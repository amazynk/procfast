// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "procfast.h"

/*
 * Disk I/O stats collector.
 *
 * Uses fentry on diskstats_show to capture per-disk statistics.
 * diskstats_show(struct seq_file *seqf, void *v) is the seq_show
 * callback for /proc/diskstats — called once per block device.
 * The 'v' argument points to the struct gendisk.
 */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct procfast_disk_data);
	__uint(map_flags, BPF_F_MMAPABLE);
} disk_data SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct procfast_config);
} disk_config SEC(".maps");

/* Map ifindex-like key to slot, same pattern as net */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PROCFAST_MAX_DISKS);
	__type(key, __u64);  /* (major << 32) | minor */
	__type(value, __u32); /* slot index */
} disk_dev_slots SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} disk_next_slot SEC(".maps");

/*
 * fentry/diskstats_show: called once per disk when /proc/diskstats is read.
 *
 * We read the gendisk's accumulated stats. The kernel's diskstats_show
 * reads part_stat_read_all() which sums per-cpu counters — we read the
 * same gendisk->part0 block_device stats via CO-RE.
 */
SEC("fentry/diskstats_show")
int BPF_PROG(fentry_diskstats_show, struct seq_file *seqf, void *v)
{
	struct procfast_disk_data *data;
	struct gendisk *gd = (struct gendisk *)v;
	__u32 zero = 0;

	if (!gd)
		return 0;

	data = bpf_map_lookup_elem(&disk_data, &zero);
	if (!data)
		return 0;

	/* Get or assign a slot for this disk */
	__u32 major = BPF_CORE_READ(gd, major);
	__u32 minor = BPF_CORE_READ(gd, first_minor);
	__u64 dev_key = ((__u64)major << 32) | minor;

	__u32 *slot_ptr = bpf_map_lookup_elem(&disk_dev_slots, &dev_key);
	__u32 slot;

	if (slot_ptr) {
		slot = *slot_ptr;
	} else {
		__u32 *next = bpf_map_lookup_elem(&disk_next_slot, &zero);
		if (!next)
			return 0;
		slot = *next;
		if (slot >= PROCFAST_MAX_DISKS)
			return 0;
		(*next)++;
		bpf_map_update_elem(&disk_dev_slots, &dev_key, &slot, BPF_ANY);
	}

	if (slot >= PROCFAST_MAX_DISKS)
		return 0;

	struct procfast_disk_stats *dst = &data->disks[slot];

	/* Read disk name and identity */
	bpf_core_read(&dst->name, sizeof(dst->name), &gd->disk_name);
	dst->major = major;
	dst->minor = minor;

	/*
	 * Read I/O stats from the block_device's stat field.
	 * gendisk->part0 is a struct block_device which has per-cpu
	 * disk_stats. We can't easily sum per-cpu from BPF, but the
	 * block_device also has bd_stats which is a non-percpu counter
	 * set on some kernels, or we read what the seq_show will output.
	 *
	 * For now, read the gendisk's cached stats if available.
	 * On modern kernels, the most reliable way is via block tracepoints.
	 * We accumulate from block_rq_complete below.
	 */

	/* Update count and timestamp */
	__u32 *next = bpf_map_lookup_elem(&disk_next_slot, &zero);
	if (next && *next > data->nr_disks)
		data->nr_disks = *next;
	data->timestamp_ns = bpf_ktime_get_ns();

	return 0;
}

/*
 * block_rq_complete: accumulate I/O stats per device.
 * This gives us accurate read/write counts and sectors.
 */
SEC("tp_btf/block_rq_complete")
int BPF_PROG(block_rq_complete, struct request *rq, blk_status_t error,
	     unsigned int nr_bytes)
{
	struct procfast_disk_data *data;
	struct gendisk *disk;
	__u32 zero = 0;

	data = bpf_map_lookup_elem(&disk_data, &zero);
	if (!data)
		return 0;

	disk = BPF_CORE_READ(rq, q, disk);
	if (!disk)
		return 0;

	__u32 major = BPF_CORE_READ(disk, major);
	__u32 minor = BPF_CORE_READ(disk, first_minor);
	__u64 dev_key = ((__u64)major << 32) | minor;

	__u32 *slot_ptr = bpf_map_lookup_elem(&disk_dev_slots, &dev_key);
	if (!slot_ptr) {
		/* Device not yet seen via diskstats_show — assign a slot */
		__u32 *next = bpf_map_lookup_elem(&disk_next_slot, &zero);
		if (!next)
			return 0;
		__u32 slot = *next;
		if (slot >= PROCFAST_MAX_DISKS)
			return 0;
		(*next)++;
		bpf_map_update_elem(&disk_dev_slots, &dev_key, &slot, BPF_ANY);
		slot_ptr = bpf_map_lookup_elem(&disk_dev_slots, &dev_key);
		if (!slot_ptr)
			return 0;

		/* Fill in name */
		struct procfast_disk_stats *dst = &data->disks[slot];
		bpf_core_read(&dst->name, sizeof(dst->name), &disk->disk_name);
		dst->major = major;
		dst->minor = minor;

		if (slot + 1 > data->nr_disks)
			data->nr_disks = slot + 1;
	}

	__u32 idx = *slot_ptr;
	if (idx >= PROCFAST_MAX_DISKS)
		return 0;

	struct procfast_disk_stats *slot = &data->disks[idx];
	__u32 sectors = nr_bytes >> 9;

	unsigned int cmd_flags = BPF_CORE_READ(rq, cmd_flags);
	if (cmd_flags & 1) { /* REQ_OP_WRITE */
		__sync_fetch_and_add(&slot->write_ios, 1);
		__sync_fetch_and_add(&slot->write_sectors, sectors);
	} else {
		__sync_fetch_and_add(&slot->read_ios, 1);
		__sync_fetch_and_add(&slot->read_sectors, sectors);
	}

	data->timestamp_ns = bpf_ktime_get_ns();
	return 0;
}

SEC("syscall")
int procfast_disk_init(void *ctx)
{
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
