// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "procfast.h"

/*
 * CPU stats collector.
 *
 * Reads kernel_cpustat for each CPU via bpf_per_cpu_ptr() on a timer.
 * Unlike the fexit-based collectors, CPU stats need periodic sampling
 * because they are cumulative counters — consumers compute deltas
 * between samples to derive CPU utilization percentages.
 *
 * A BPF timer fires at the configured interval (default 1s) and
 * snapshots all per-CPU counters into the mmapable output map.
 */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct procfast_cpu_data);
	__uint(map_flags, BPF_F_MMAPABLE);
} cpu_data SEC(".maps");

struct timer_elem {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct timer_elem);
} cpu_timer SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct procfast_config);
} cpu_config SEC(".maps");

extern struct kernel_cpustat kernel_cpustat __ksym;

static void read_one_cpu(struct procfast_cpu_stats *out, __u32 cpu)
{
	struct kernel_cpustat *kcpu;

	kcpu = bpf_per_cpu_ptr(&kernel_cpustat, cpu);
	if (!kcpu)
		return;

	out->user_ns      = BPF_CORE_READ(kcpu, cpustat[CPUTIME_USER]);
	out->nice_ns      = BPF_CORE_READ(kcpu, cpustat[CPUTIME_NICE]);
	out->system_ns    = BPF_CORE_READ(kcpu, cpustat[CPUTIME_SYSTEM]);
	out->idle_ns      = BPF_CORE_READ(kcpu, cpustat[CPUTIME_IDLE]);
	out->iowait_ns    = BPF_CORE_READ(kcpu, cpustat[CPUTIME_IOWAIT]);
	out->irq_ns       = BPF_CORE_READ(kcpu, cpustat[CPUTIME_IRQ]);
	out->softirq_ns   = BPF_CORE_READ(kcpu, cpustat[CPUTIME_SOFTIRQ]);
	out->steal_ns     = BPF_CORE_READ(kcpu, cpustat[CPUTIME_STEAL]);
	out->guest_ns     = BPF_CORE_READ(kcpu, cpustat[CPUTIME_GUEST]);
	out->guest_nice_ns = BPF_CORE_READ(kcpu, cpustat[CPUTIME_GUEST_NICE]);
}

static void add_stats(struct procfast_cpu_stats *total,
		      const struct procfast_cpu_stats *cpu)
{
	total->user_ns      += cpu->user_ns;
	total->nice_ns      += cpu->nice_ns;
	total->system_ns    += cpu->system_ns;
	total->idle_ns      += cpu->idle_ns;
	total->iowait_ns    += cpu->iowait_ns;
	total->irq_ns       += cpu->irq_ns;
	total->softirq_ns   += cpu->softirq_ns;
	total->steal_ns     += cpu->steal_ns;
	total->guest_ns     += cpu->guest_ns;
	total->guest_nice_ns += cpu->guest_nice_ns;
}

static int collect_cpu_stats(void *map, __u32 *key, struct timer_elem *val)
{
	struct procfast_cpu_data *data;
	struct procfast_config *cfg;
	__u64 interval_ns;
	__u32 zero = 0;

	data = bpf_map_lookup_elem(&cpu_data, &zero);
	if (!data)
		goto rearm;

	PROCFAST_SEQ_WRITE_BEGIN(data);

	data->timestamp_ns = bpf_ktime_get_ns();
	__builtin_memset(&data->total, 0, sizeof(data->total));

	__u32 nr = 0;
	for (__u32 i = 0; i < PROCFAST_MAX_CPUS; i++) {
		struct procfast_cpu_stats *slot = &data->per_cpu[i];
		__builtin_memset(slot, 0, sizeof(*slot));

		read_one_cpu(slot, i);
		if (slot->user_ns || slot->system_ns || slot->idle_ns) {
			add_stats(&data->total, slot);
			nr = i + 1;
		}
	}
	data->nr_cpus = nr;

	PROCFAST_SEQ_WRITE_END(data);

rearm:
	cfg = bpf_map_lookup_elem(&cpu_config, &zero);
	interval_ns = cfg ? cfg->interval_ns : 1000000000ULL;
	bpf_timer_start(&val->timer, interval_ns, 0);

	return 0;
}

SEC("syscall")
int procfast_cpu_init(void *ctx)
{
	struct timer_elem *telem;
	__u32 zero = 0;
	int ret;

	telem = bpf_map_lookup_elem(&cpu_timer, &zero);
	if (!telem)
		return -1;

	ret = bpf_timer_init(&telem->timer, &cpu_timer, CLOCK_MONOTONIC);
	if (ret)
		return ret;

	ret = bpf_timer_set_callback(&telem->timer, collect_cpu_stats);
	if (ret)
		return ret;

	return bpf_timer_start(&telem->timer, 0, 0);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
