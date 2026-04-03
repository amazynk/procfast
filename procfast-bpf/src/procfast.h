/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
#ifndef __PROCFAST_H
#define __PROCFAST_H

/*
 * Shared struct definitions between BPF programs and userspace.
 * MUST match the layout in procfast-common/src/lib.rs exactly.
 */

#define PROCFAST_MAX_CPUS        256
#define PROCFAST_MAX_NET_DEVS     32
#define PROCFAST_MAX_DISKS        64
#define PROCFAST_MAX_THERMAL_ZONES 16
#define PROCFAST_MAX_IRQS        512
#define PROCFAST_MAX_PROCS       8192
#define PROCFAST_MAX_FDS        65536
#define PROCFAST_MAX_FD_PATH      256
#define PROCFAST_MAX_CGROUPS     4096

struct procfast_cpu_stats {
	__u64 user_ns;
	__u64 nice_ns;
	__u64 system_ns;
	__u64 idle_ns;
	__u64 iowait_ns;
	__u64 irq_ns;
	__u64 softirq_ns;
	__u64 steal_ns;
	__u64 guest_ns;
	__u64 guest_nice_ns;
};

struct procfast_cpu_data {
	__u64 seq;
	__u64 timestamp_ns;
	__u32 nr_cpus;
	__u32 _pad;
	struct procfast_cpu_stats total;
	struct procfast_cpu_stats per_cpu[PROCFAST_MAX_CPUS];
};

struct procfast_mem_data {
	__u64 seq;
	__u64 timestamp_ns;
	__u64 total_bytes;
	__u64 free_bytes;
	__u64 available_bytes;
	__u64 buffers_bytes;
	__u64 cached_bytes;
	__u64 swap_total_bytes;
	__u64 swap_free_bytes;
	__u64 active_bytes;
	__u64 inactive_bytes;
	__u64 slab_reclaimable_bytes;
	__u64 slab_unreclaimable_bytes;
	__u64 dirty_bytes;
	__u64 writeback_bytes;
	__u64 shmem_bytes;
};

struct procfast_net_dev_stats {
	__u64 rx_bytes;
	__u64 tx_bytes;
	__u64 rx_packets;
	__u64 tx_packets;
	__u64 rx_errors;
	__u64 tx_errors;
	__u64 rx_dropped;
	__u64 tx_dropped;
	char name[16];
};

struct procfast_net_data {
	__u64 seq;
	__u64 timestamp_ns;
	__u32 nr_devs;
	__u32 _pad;
	struct procfast_net_dev_stats devs[PROCFAST_MAX_NET_DEVS];
};

struct procfast_disk_stats {
	__u64 read_ios;
	__u64 write_ios;
	__u64 read_sectors;
	__u64 write_sectors;
	__u64 read_ns;
	__u64 write_ns;
	__u64 io_ticks_ns;
	__u32 major;
	__u32 minor;
	char name[32];
};

struct procfast_disk_data {
	__u64 seq;
	__u64 timestamp_ns;
	__u32 nr_disks;
	__u32 _pad;
	struct procfast_disk_stats disks[PROCFAST_MAX_DISKS];
};

struct procfast_thermal_zone {
	__s32 temp_millicelsius;
	__u32 _pad;
	char zone_type[20];
	char _pad2[4];
};

struct procfast_thermal_data {
	__u64 seq;
	__u64 timestamp_ns;
	__u32 nr_zones;
	__u32 _pad;
	struct procfast_thermal_zone zones[PROCFAST_MAX_THERMAL_ZONES];
};

struct procfast_irq_stats {
	__u32 irq;
	__u32 _pad;
	__u64 total_count;
	char chip_name[32];
	char action_name[64];
};

struct procfast_irq_data {
	__u64 seq;
	__u64 timestamp_ns;
	__u32 nr_irqs;
	__u32 _pad;
	struct procfast_irq_stats irqs[PROCFAST_MAX_IRQS];
};

struct procfast_proc_stats {
	__u32 pid;
	__u32 tgid;
	__u32 ppid;
	__u8  state;
	__u8  _pad1[3];
	__u32 uid;
	__u32 nr_threads;
	char  comm[16];
	__u64 utime_ns;
	__u64 stime_ns;
	__u64 cutime_ns;
	__u64 cstime_ns;
	__s32 nice;
	__u32 policy;
	__u32 last_cpu;
	__u32 rt_priority;
	__u64 last_seen_ns;
	__u64 vol_ctxsw;
	__u64 invol_ctxsw;
	__u64 rss_bytes;
	__u64 vsize_bytes;
	__u64 shared_bytes;
	__u64 read_bytes;
	__u64 write_bytes;
	__u64 cpu_runtime_ns;
	__u64 start_time_ns;
	__u64 cgroup_id;      /* cgroup v2 default hierarchy ID */
};

struct procfast_proc_header {
	__u64 seq;
	__u64 timestamp_ns;
	__u32 nr_procs;
	__u32 _pad;
};

struct procfast_config {
	__u64 interval_ns;
};

struct procfast_fd_info {
	__u32 pid;
	__u32 fd;
	__u64 open_time_ns;
	__u64 inode;
	__u32 flags;
	__u32 _pad;
	char path[PROCFAST_MAX_FD_PATH];
};

struct procfast_cgroup_stats {
	__u64 id;             /* cgroup ID (kernfs inode) */
	__u64 parent_id;      /* parent cgroup ID */
	__u32 level;          /* depth in hierarchy */
	__u32 nr_descendants; /* number of sub-cgroups */
	/* CPU */
	__u64 cpu_usage_ns;   /* total CPU (sum_exec_runtime) */
	__u64 cpu_user_ns;    /* user CPU time */
	__u64 cpu_system_ns;  /* system CPU time */
	__u64 cpu_quota_us;   /* cpu.max quota (µs per period), 0 = no limit */
	__u64 cpu_period_us;  /* cpu.max period (µs) */
	__u32 cpu_weight;     /* cpu.weight (shares) */
	__u32 nr_throttled;   /* nr times cgroup was throttled */
	__u64 throttled_ns;   /* total time throttled (ns) */
	/* Memory */
	__u64 memory_current; /* current memory usage (bytes) */
	__u64 memory_limit;   /* memory limit (bytes), 0 = no limit */
	__u64 memory_swap;    /* swap usage (bytes) */
	__u64 memory_cache;   /* file-backed pages (bytes) */
	__u64 memory_rss;     /* anonymous + mapped pages (bytes) */
	__u64 memory_slab;    /* slab reclaimable + unreclaimable (bytes) */
	__u64 memory_shmem;   /* shared memory (bytes) */
	/* PIDs */
	__u64 nr_pids;        /* current number of PIDs */
	__u64 pids_limit;     /* max PIDs, 0 = no limit */
	/* PSI — cumulative stall time (µs) */
	__u64 psi_cpu_some;   /* CPU some pressure */
	__u64 psi_cpu_full;   /* CPU full pressure */
	__u64 psi_mem_some;   /* memory some pressure */
	__u64 psi_mem_full;   /* memory full pressure */
	__u64 psi_io_some;    /* I/O some pressure */
	__u64 psi_io_full;    /* I/O full pressure */
	/* Freeze */
	__u8  frozen;         /* effective freeze state */
	__u8  _pad1[7];
	/* Name */
	char  name[64];       /* cgroup name (leaf component) */
};

/* CLOCK_MONOTONIC is a userspace constant not in vmlinux.h */
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

/* BPF_F_MMAPABLE is provided by vmlinux.h as an enum value (= 1024).
 * Do NOT redefine it — enum values are not visible to the preprocessor
 * so #ifndef would incorrectly think it's undefined. */

/* Seqlock helpers for BPF side */
#define PROCFAST_SEQ_WRITE_BEGIN(data) \
	__sync_fetch_and_add(&(data)->seq, 1)

#define PROCFAST_SEQ_WRITE_END(data) \
	__sync_fetch_and_add(&(data)->seq, 1)

#endif /* __PROCFAST_H */
