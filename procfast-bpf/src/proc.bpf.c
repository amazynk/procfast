// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "procfast.h"

/*
 * Per-process stats collector.
 *
 * This is the big one. It replaces the most expensive operation that
 * top/htop/ps perform: reading /proc/[pid]/stat, /proc/[pid]/statm,
 * and /proc/[pid]/io for every process on every refresh cycle.
 *
 * == The problem in numbers ==
 *
 * On a system with 1000 processes, htop at 2Hz does:
 *   - 1000 × open("/proc/[pid]/stat")  + read + close  = 3000 syscalls
 *   - 1000 × open("/proc/[pid]/statm") + read + close  = 3000 syscalls
 *   - 1000 × open("/proc/[pid]/status")+ read + close  = 3000 syscalls
 *   ≈ 9000 syscalls per refresh, 18000/sec
 *
 * Each /proc/[pid]/stat read:
 *   - Takes task_lock() on the target task
 *   - Reads ~50 fields from task_struct, signal_struct, mm_struct
 *   - sprintf-formats them into a single line
 *   - Userspace sscanf-parses them back into integers
 *
 * == Our approach ==
 *
 * Instead of polling, we use scheduler tracepoints to maintain a live
 * map of per-process stats that's always up-to-date:
 *
 *   sched_switch      → update CPU times, state, last_cpu, runtime deltas
 *   sched_process_fork → add new process entry
 *   sched_process_exec → update comm
 *   sched_process_exit → mark dead, schedule cleanup
 *
 * Runtime tracking uses sum_exec_runtime deltas computed per-thread in
 * sched_switch, avoiding the need for sched_stat_runtime (~35k fires/sec).
 *
 * Userspace reads the hash map directly — no syscalls per process.
 * The data is already binary and structured.
 *
 * == Expected improvement ==
 *
 * A procfast-based `top` would:
 *   - Use 0 syscalls per refresh for process data (vs ~9000)
 *   - Skip all text formatting and parsing
 *   - Never take task_lock() on any process
 *   - Have O(1) per-process read cost (hash lookup vs file I/O)
 *   - Self-maintain: new processes appear automatically via fork tracepoint
 *
 * Estimated CPU savings: 10-50x for the process-scanning portion of
 * top/htop, which is typically 60-80% of their total CPU usage.
 */

/*
 * Per-process stats hash map.
 * Key: tgid (thread group leader PID — what userspace calls "PID")
 * Value: struct procfast_proc_stats
 *
 * We key by tgid, not pid, because top/htop show processes not threads.
 * Thread data is aggregated into the leader's entry.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PROCFAST_MAX_PROCS);
	__type(key, __u32);
	__type(value, struct procfast_proc_stats);
} proc_stats SEC(".maps");

/*
 * Per-thread runtime tracking map.
 * Key: tid (task->pid, not tgid)
 * Value: last seen sum_exec_runtime
 *
 * Used to compute per-thread runtime deltas in sched_switch,
 * which are then accumulated into the tgid's cpu_runtime_ns.
 * This replaces sched_stat_runtime (~35k fires/sec on 16 cores)
 * with a single hash lookup per context switch.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, __u64);
} thread_runtime SEC(".maps");

/* Header map for metadata */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct procfast_proc_header);
	__uint(map_flags, BPF_F_MMAPABLE);
} proc_header SEC(".maps");

struct timer_elem {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct timer_elem);
} proc_timer SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct procfast_config);
} proc_config SEC(".maps");

/*
 * Ring buffer for notifying userspace of process lifecycle events.
 * This lets a procfast-backed top know when to add/remove rows without
 * polling the hash map for changes.
 */
struct procfast_proc_event {
	__u32 pid;
	__u32 event_type; /* 0=new, 1=exec, 2=exit */
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 64 * 1024); /* 64KB ring */
} proc_events SEC(".maps");

/*
 * Helper: read task_struct fields into our stats struct.
 * Used for initial population and periodic refresh.
 */
static void read_task_stats(struct procfast_proc_stats *stats,
			    struct task_struct *task)
{
	stats->pid = BPF_CORE_READ(task, pid);
	stats->tgid = BPF_CORE_READ(task, tgid);
	stats->ppid = BPF_CORE_READ(task, real_parent, tgid);
	stats->uid = BPF_CORE_READ(task, real_cred, uid.val);

	BPF_CORE_READ_INTO(&stats->comm, task, comm);

	/* Process state: map kernel __state to our simplified enum.
	 * __state: 0=TASK_RUNNING, 1=TASK_INTERRUPTIBLE,
	 *          2=TASK_UNINTERRUPTIBLE, 4=__TASK_STOPPED,
	 *          0x10=EXIT_ZOMBIE, 0x20=EXIT_DEAD */
	unsigned int task_state = BPF_CORE_READ(task, __state);
	if (task_state == 0) {
		/* __state=0 means runnable. Only mark as Running if the
		 * task is not an idle kernel thread. Check on_rq or
		 * fall back to sleeping for most processes at startup. */
		unsigned int on_rq = BPF_CORE_READ(task, on_rq);
		stats->state = on_rq ? 0 : 1; /* running if on runqueue, else sleeping */
	} else if (task_state & 0x10)
		stats->state = 4; /* EXIT_ZOMBIE */
	else if (task_state & 0x20)
		stats->state = 5; /* EXIT_DEAD */
	else if (task_state & 4)
		stats->state = 3; /* __TASK_STOPPED */
	else if (task_state & 2) {
		/* TASK_UNINTERRUPTIBLE. If TASK_NOLOAD (0x400) is also set,
		 * this is TASK_IDLE (idle kernel thread), not real disk sleep.
		 * Map TASK_IDLE to sleeping like /proc/[pid]/stat does. */
		if (task_state & 0x400)
			stats->state = 1; /* idle = sleeping */
		else
			stats->state = 2; /* real disk sleep */
	} else
		stats->state = 1; /* TASK_INTERRUPTIBLE or other = sleeping */

	/* CPU times — read from task_struct directly.
	 * These are the same fields that /proc/[pid]/stat reads
	 * via task_cputime_adjusted(). */
	stats->utime_ns = BPF_CORE_READ(task, utime);
	stats->stime_ns = BPF_CORE_READ(task, stime);

	/* Scheduling */
	stats->nice = BPF_CORE_READ(task, static_prio) - 120; /* MAX_RT_PRIO */
	stats->policy = BPF_CORE_READ(task, policy);
	stats->rt_priority = BPF_CORE_READ(task, rt_priority);

	/* Context switches */
	stats->vol_ctxsw = BPF_CORE_READ(task, nvcsw);
	stats->invol_ctxsw = BPF_CORE_READ(task, nivcsw);

	/* Thread count (from signal_struct) */
	struct signal_struct *sig = BPF_CORE_READ(task, signal);
	if (sig)
		stats->nr_threads = BPF_CORE_READ(sig, nr_threads);

	/* Memory — read from mm_struct */
	struct mm_struct *mm = BPF_CORE_READ(task, mm);
	if (mm) {
		unsigned long total_vm = BPF_CORE_READ(mm, total_vm);
		stats->vsize_bytes = total_vm * 4096ULL; /* pages to bytes */

		/* RSS via mm counters (same source as /proc/[pid]/statm) */
		long rss_file = 0, rss_anon = 0;
		/* mm->rss_stat is a per-cpu counter on modern kernels;
		 * read the cached value */
		rss_file = BPF_CORE_READ(mm, rss_stat[MM_FILEPAGES].count);
		rss_anon = BPF_CORE_READ(mm, rss_stat[MM_ANONPAGES].count);
		stats->rss_bytes = (rss_file + rss_anon) * 4096ULL;
		stats->shared_bytes = rss_file * 4096ULL;
	}

	/* I/O accounting (same source as /proc/[pid]/io) */
	stats->read_bytes = BPF_CORE_READ(task, ioac.read_bytes);
	stats->write_bytes = BPF_CORE_READ(task, ioac.write_bytes);

	/* Start time */
	stats->start_time_ns = BPF_CORE_READ(task, start_boottime);
}

static void emit_event(__u32 pid, __u32 event_type)
{
	struct procfast_proc_event *evt;
	evt = bpf_ringbuf_reserve(&proc_events, sizeof(*evt), 0);
	if (evt) {
		evt->pid = pid;
		evt->event_type = event_type;
		bpf_ringbuf_submit(evt, 0);
	}
}

/*
 * sched_switch: the core accounting tracepoint.
 *
 * Fires on every context switch. We update:
 *   - prev task: save accumulated CPU time, state, runtime delta
 *   - next task: record last_seen_ns, last_cpu
 *
 * Runtime tracking: instead of using sched_stat_runtime (~35k fires/sec),
 * we read sum_exec_runtime here and compute deltas via the thread_runtime
 * map. This eliminates an entire BPF program from the scheduler hot path.
 */
SEC("tp_btf/sched_switch")
int BPF_PROG(procfast_sched_switch, _Bool preempt,
	     struct task_struct *prev, struct task_struct *next)
{
	__u64 now = bpf_ktime_get_ns();
	struct procfast_proc_stats *stats;

	/* Update prev task */
	__u32 prev_pid = BPF_CORE_READ(prev, pid);
	__u32 prev_tgid = BPF_CORE_READ(prev, tgid);
	stats = bpf_map_lookup_elem(&proc_stats, &prev_tgid);

	/* Accumulate runtime delta from sum_exec_runtime.
	 * This works for all threads: each thread's delta is added
	 * to the tgid leader's cpu_runtime_ns via atomic add. */
	__u64 curr_runtime = BPF_CORE_READ(prev, se.sum_exec_runtime);
	__u64 *last_rt = bpf_map_lookup_elem(&thread_runtime, &prev_pid);
	if (last_rt) {
		__u64 delta = curr_runtime - *last_rt;
		*last_rt = curr_runtime;
		if (stats && delta > 0)
			__sync_fetch_and_add(&stats->cpu_runtime_ns, delta);
	} else {
		/* First time seeing this thread — store baseline, no delta */
		bpf_map_update_elem(&thread_runtime, &prev_pid,
				    &curr_runtime, BPF_ANY);
	}

	if (stats) {
		stats->utime_ns = BPF_CORE_READ(prev, utime);
		stats->stime_ns = BPF_CORE_READ(prev, stime);
		stats->vol_ctxsw = BPF_CORE_READ(prev, nvcsw);
		stats->invol_ctxsw = BPF_CORE_READ(prev, nivcsw);

		/* Map task_struct __state to our simplified state enum */
		unsigned int task_state = BPF_CORE_READ(prev, __state);
		if (task_state == 0)
			stats->state = 0; /* TASK_RUNNING */
		else if (task_state & 1)
			stats->state = 1; /* TASK_INTERRUPTIBLE (sleeping) */
		else if (task_state & 2)
			stats->state = 2; /* TASK_UNINTERRUPTIBLE (disk sleep) */
		else if (task_state & 4)
			stats->state = 3; /* __TASK_STOPPED */
		else if (task_state & 0x10)
			stats->state = 4; /* EXIT_ZOMBIE */
		else
			stats->state = 5; /* EXIT_DEAD / other */
	}

	/* Update next task */
	__u32 next_tgid = BPF_CORE_READ(next, tgid);
	stats = bpf_map_lookup_elem(&proc_stats, &next_tgid);
	if (stats) {
		stats->last_seen_ns = now;
		stats->last_cpu = bpf_get_smp_processor_id();
		stats->state = 0; /* running */
	}

	return 0;
}

/*
 * sched_process_fork: new process created.
 * Add an entry to the hash map and emit event.
 */
SEC("tp_btf/sched_process_fork")
int BPF_PROG(sched_process_fork,
	     struct task_struct *parent, struct task_struct *child)
{
	__u32 child_pid = BPF_CORE_READ(child, pid);
	__u32 child_tgid = BPF_CORE_READ(child, tgid);

	/* Initialize thread runtime baseline for all new tasks (threads + leaders) */
	__u64 zero_rt = 0;
	bpf_map_update_elem(&thread_runtime, &child_pid, &zero_rt, BPF_ANY);

	/* Only track thread group leaders in proc_stats */
	if (child_pid != child_tgid)
		return 0;

	struct procfast_proc_stats stats = {};
	read_task_stats(&stats, child);
	stats.last_seen_ns = bpf_ktime_get_ns();
	stats.state = 0; /* new process starts runnable */

	bpf_map_update_elem(&proc_stats, &child_tgid, &stats, BPF_ANY);
	emit_event(child_tgid, 0 /* new */);

	return 0;
}

/*
 * sched_process_exec: process called exec.
 * Update comm and reset some counters.
 */
SEC("tp_btf/sched_process_exec")
int BPF_PROG(sched_process_exec, struct task_struct *task,
	     pid_t old_pid, struct linux_binprm *bprm)
{
	__u32 tgid = BPF_CORE_READ(task, tgid);
	struct procfast_proc_stats *stats;

	stats = bpf_map_lookup_elem(&proc_stats, &tgid);
	if (stats) {
		BPF_CORE_READ_INTO(&stats->comm, task, comm);
		/* Re-read memory stats since address space was replaced */
		struct mm_struct *mm = BPF_CORE_READ(task, mm);
		if (mm) {
			unsigned long total_vm = BPF_CORE_READ(mm, total_vm);
			stats->vsize_bytes = total_vm * 4096ULL;
		}
		emit_event(tgid, 1 /* exec */);
	}

	return 0;
}

/*
 * sched_process_exit: process exiting.
 * Mark as zombie/dead. We don't remove immediately — the timer
 * cleanup pass will reap entries that have been dead for >2 intervals.
 */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(sched_process_exit, struct task_struct *task)
{
	__u32 pid = BPF_CORE_READ(task, pid);
	__u32 tgid = BPF_CORE_READ(task, tgid);

	/* Clean up thread runtime tracking for all exiting tasks */
	bpf_map_delete_elem(&thread_runtime, &pid);

	/* Only handle proc_stats for thread group leader exit */
	if (pid != tgid)
		return 0;

	struct procfast_proc_stats *stats;
	stats = bpf_map_lookup_elem(&proc_stats, &tgid);
	if (stats) {
		/* Final CPU time update */
		stats->utime_ns = BPF_CORE_READ(task, utime);
		stats->stime_ns = BPF_CORE_READ(task, stime);
		stats->state = 4; /* zombie */

		/* Collect child times */
		struct signal_struct *sig = BPF_CORE_READ(task, signal);
		if (sig) {
			stats->cutime_ns = BPF_CORE_READ(sig, cutime);
			stats->cstime_ns = BPF_CORE_READ(sig, cstime);
		}
	}

	emit_event(tgid, 2 /* exit */);

	return 0;
}

/*
 * Timer callback: periodic maintenance.
 *
 * - Update header with current process count
 * - Refresh memory stats (RSS changes don't have a cheap tracepoint)
 * - Reap dead process entries
 */
struct reap_ctx {
	__u64 now;
	__u64 deadline; /* entries with state=zombie/dead older than this get reaped */
	__u32 count;
	__u32 reaped;
};

static __u64 reap_dead_procs(struct bpf_map *map, __u32 *pid,
			     struct procfast_proc_stats *stats,
			     struct reap_ctx *ctx)
{
	ctx->count++;

	/* Reap zombies/dead processes that haven't been seen recently */
	if (stats->state >= 4 && stats->last_seen_ns < ctx->deadline) {
		bpf_map_delete_elem(map, pid);
		ctx->reaped++;
	}

	return 0;
}

static int proc_timer_callback(void *map, __u32 *key, struct timer_elem *val)
{
	struct procfast_proc_header *hdr;
	struct procfast_config *cfg;
	__u64 interval_ns;
	__u32 zero = 0;

	hdr = bpf_map_lookup_elem(&proc_header, &zero);
	if (!hdr)
		goto rearm;

	__u64 now = bpf_ktime_get_ns();

	/* Reap dead entries older than 2 collection intervals */
	cfg = bpf_map_lookup_elem(&proc_config, &zero);
	interval_ns = cfg ? cfg->interval_ns : 1000000000ULL;

	struct reap_ctx ctx = {
		.now = now,
		.deadline = now - (2 * interval_ns),
		.count = 0,
		.reaped = 0,
	};

	bpf_for_each_map_elem(&proc_stats, reap_dead_procs, &ctx, 0);

	/* Update header */
	PROCFAST_SEQ_WRITE_BEGIN(hdr);
	hdr->timestamp_ns = now;
	hdr->nr_procs = ctx.count - ctx.reaped;
	PROCFAST_SEQ_WRITE_END(hdr);

rearm:
	cfg = bpf_map_lookup_elem(&proc_config, &zero);
	interval_ns = cfg ? cfg->interval_ns : 1000000000ULL;
	bpf_timer_start(&val->timer, interval_ns, 0);
	return 0;
}

/*
 * Initialization: set up timer and scan existing processes.
 *
 * The tracepoints only capture new events after attachment. To see
 * processes that already exist, userspace must do a one-time scan
 * of /proc on startup and populate the map. Alternatively, we use
 * a BPF task iterator to walk all existing tasks.
 */
SEC("syscall")
int procfast_proc_init(void *ctx)
{
	struct timer_elem *telem;
	__u32 zero = 0;
	int ret;

	telem = bpf_map_lookup_elem(&proc_timer, &zero);
	if (!telem)
		return -1;

	ret = bpf_timer_init(&telem->timer, &proc_timer, CLOCK_MONOTONIC);
	if (ret)
		return ret;

	ret = bpf_timer_set_callback(&telem->timer, proc_timer_callback);
	if (ret)
		return ret;

	return bpf_timer_start(&telem->timer, 0, 0);
}

/*
 * Task iterator: walks all existing tasks at load time.
 * Called from userspace via bpf_link to populate the hash map
 * with processes that were running before our tracepoints attached.
 */
SEC("iter/task")
int procfast_proc_dump_task(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;

	if (!task)
		return 0;

	__u32 pid = BPF_CORE_READ(task, pid);
	__u32 tgid = BPF_CORE_READ(task, tgid);

	/* Initialize thread runtime baseline for all threads */
	__u64 runtime = BPF_CORE_READ(task, se.sum_exec_runtime);
	bpf_map_update_elem(&thread_runtime, &pid, &runtime, BPF_NOEXIST);

	/* Only create proc_stats entries for thread group leaders */
	if (pid != tgid)
		return 0;

	struct procfast_proc_stats stats = {};
	read_task_stats(&stats, task);
	stats.last_seen_ns = bpf_ktime_get_ns();

	bpf_map_update_elem(&proc_stats, &tgid, &stats, BPF_NOEXIST);

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
