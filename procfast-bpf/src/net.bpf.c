// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "procfast.h"

/*
 * Network device stats collector.
 *
 * Uses fexit on dev_get_stats to capture per-device statistics.
 * dev_get_stats(struct net_device *dev, struct rtnl_link_stats64 *storage)
 * is called for each device when /proc/net/dev is read.
 *
 * We intercept the return to read the device name and filled stats.
 */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct procfast_net_data);
	__uint(map_flags, BPF_F_MMAPABLE);
} net_data SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct procfast_config);
} net_config SEC(".maps");

/* Track device index by name hash for updating the right slot */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PROCFAST_MAX_NET_DEVS);
	__type(key, __u32);  /* ifindex */
	__type(value, __u32); /* slot index in net_data.devs[] */
} net_dev_slots SEC(".maps");

/* Next available slot index */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} net_next_slot SEC(".maps");

/*
 * fexit/dev_get_stats: called once per device when stats are read.
 *
 * Args: struct net_device *dev, struct rtnl_link_stats64 *storage
 * Returns: struct rtnl_link_stats64 *
 */
SEC("fexit/dev_get_stats")
int BPF_PROG(fexit_dev_get_stats,
	     struct net_device *dev,
	     struct rtnl_link_stats64 *storage,
	     struct rtnl_link_stats64 *ret)
{
	struct procfast_net_data *data;
	__u32 zero = 0;

	if (!dev || !storage)
		return 0;

	data = bpf_map_lookup_elem(&net_data, &zero);
	if (!data)
		return 0;

	/* Get or assign a slot for this device */
	__u32 ifindex = BPF_CORE_READ(dev, ifindex);
	__u32 *slot_ptr = bpf_map_lookup_elem(&net_dev_slots, &ifindex);
	__u32 slot;

	if (slot_ptr) {
		slot = *slot_ptr;
	} else {
		/* Assign next available slot */
		__u32 *next = bpf_map_lookup_elem(&net_next_slot, &zero);
		if (!next)
			return 0;
		slot = *next;
		if (slot >= PROCFAST_MAX_NET_DEVS)
			return 0;
		(*next)++;
		bpf_map_update_elem(&net_dev_slots, &ifindex, &slot, BPF_ANY);
	}

	if (slot >= PROCFAST_MAX_NET_DEVS)
		return 0;

	struct procfast_net_dev_stats *dst = &data->devs[slot];

	/* Read device name */
	bpf_core_read(&dst->name, sizeof(dst->name), &dev->name);

	/* Read stats from the filled storage struct */
	dst->rx_bytes   = BPF_CORE_READ(storage, rx_bytes);
	dst->tx_bytes   = BPF_CORE_READ(storage, tx_bytes);
	dst->rx_packets = BPF_CORE_READ(storage, rx_packets);
	dst->tx_packets = BPF_CORE_READ(storage, tx_packets);
	dst->rx_errors  = BPF_CORE_READ(storage, rx_errors);
	dst->tx_errors  = BPF_CORE_READ(storage, tx_errors);
	dst->rx_dropped = BPF_CORE_READ(storage, rx_dropped);
	dst->tx_dropped = BPF_CORE_READ(storage, tx_dropped);

	/* Update device count and timestamp */
	__u32 *next = bpf_map_lookup_elem(&net_next_slot, &zero);
	if (next && *next > data->nr_devs)
		data->nr_devs = *next;
	data->timestamp_ns = bpf_ktime_get_ns();

	return 0;
}

SEC("syscall")
int procfast_net_init(void *ctx)
{
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
