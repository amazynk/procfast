// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "procfast.h"

/*
 * Interrupt statistics collector.
 *
 * Counts interrupts in real-time via fentry/handle_irq_event and
 * tp_btf/softirq_entry. Clients read the percpu hash map and
 * metadata hash map directly — no periodic snapshot needed.
 */

/* Per-CPU counts. Key: IRQ number, Value: count on this CPU */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, PROCFAST_MAX_IRQS);
	__type(key, __u32);
	__type(value, __u64);
} irq_counts SEC(".maps");

/* IRQ metadata (chip + action names), populated on first encounter */
struct irq_meta {
	char chip_name[32];
	char action_name[64];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PROCFAST_MAX_IRQS);
	__type(key, __u32);
	__type(value, struct irq_meta);
} irq_metadata SEC(".maps");

#define PROCFAST_SOFTIRQ_BASE 0x80000000

/*
 * fentry/handle_irq_event: fires for every hardware interrupt.
 * Reads irq_desc for chip name and irqaction for handler name.
 */
SEC("fentry/handle_irq_event")
int BPF_PROG(fentry_handle_irq_event, struct irq_desc *desc)
{
	if (!desc)
		return 0;

	__u32 irq = BPF_CORE_READ(desc, irq_data.irq);
	__u64 *count;

	count = bpf_map_lookup_elem(&irq_counts, &irq);
	if (count) {
		(*count) += 1;
	} else {
		__u64 init_val = 1;
		bpf_map_update_elem(&irq_counts, &irq, &init_val, BPF_NOEXIST);
	}

	/* Capture metadata on first encounter */
	if (!bpf_map_lookup_elem(&irq_metadata, &irq)) {
		struct irq_meta meta = {};

		struct irq_chip *chip = BPF_CORE_READ(desc, irq_data.chip);
		if (chip) {
			const char *cname = BPF_CORE_READ(chip, name);
			if (cname)
				bpf_probe_read_kernel_str(meta.chip_name,
							  sizeof(meta.chip_name), cname);
		}

		struct irqaction *action = BPF_CORE_READ(desc, action);
		if (action) {
			const char *aname = BPF_CORE_READ(action, name);
			if (aname)
				bpf_probe_read_kernel_str(meta.action_name,
							  sizeof(meta.action_name), aname);
		}

		bpf_map_update_elem(&irq_metadata, &irq, &meta, BPF_NOEXIST);
	}

	return 0;
}

SEC("tp_btf/softirq_entry")
int BPF_PROG(softirq_entry, unsigned int vec_nr)
{
	__u32 key = PROCFAST_SOFTIRQ_BASE | vec_nr;
	__u64 *count;

	count = bpf_map_lookup_elem(&irq_counts, &key);
	if (count) {
		(*count) += 1;
	} else {
		__u64 init_val = 1;
		bpf_map_update_elem(&irq_counts, &key, &init_val, BPF_NOEXIST);

		struct irq_meta meta = {};
		static const char softirq_names[10][12] = {
			"HI", "TIMER", "NET_TX", "NET_RX", "BLOCK",
			"IRQ_POLL", "TASKLET", "SCHED", "HRTIMER", "RCU"
		};
		if (vec_nr < 10) {
			for (int i = 0; i < 11 && softirq_names[vec_nr][i]; i++)
				meta.action_name[i] = softirq_names[vec_nr][i];
		}
		bpf_map_update_elem(&irq_metadata, &key, &meta, BPF_NOEXIST);
	}

	return 0;
}

/* No-op init — no timer needed, counting is real-time */
SEC("syscall")
int procfast_irq_init(void *ctx)
{
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
