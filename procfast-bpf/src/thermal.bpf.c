// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "procfast.h"

/*
 * Thermal zone stats collector.
 *
 * Uses fexit on thermal_zone_get_temp to capture zone temperatures.
 * thermal_zone_get_temp(struct thermal_zone_device *tz, int *temp)
 * is called by the thermal subsystem polling loop and by sysfs reads.
 */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct procfast_thermal_data);
	__uint(map_flags, BPF_F_MMAPABLE);
} thermal_data SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct procfast_config);
} thermal_config SEC(".maps");

/* Map zone id to slot index */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PROCFAST_MAX_THERMAL_ZONES);
	__type(key, __u32);  /* thermal zone id */
	__type(value, __u32); /* slot index */
} thermal_zone_slots SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} thermal_next_slot SEC(".maps");

/*
 * fexit/thermal_zone_get_temp: called when a zone's temperature is read.
 *
 * The thermal subsystem polls zones periodically (polling_delay), and
 * sysfs reads also trigger it. We capture the zone type, id, and
 * temperature after the kernel has read it from hardware.
 */
SEC("fexit/thermal_zone_get_temp")
int BPF_PROG(fexit_thermal_zone_get_temp,
	     struct thermal_zone_device *tz, int *temp, int ret)
{
	struct procfast_thermal_data *data;
	__u32 zero = 0;

	if (ret != 0 || !tz || !temp)
		return 0;

	data = bpf_map_lookup_elem(&thermal_data, &zero);
	if (!data)
		return 0;

	__u32 zone_id = BPF_CORE_READ(tz, id);

	/* Get or assign a slot */
	__u32 *slot_ptr = bpf_map_lookup_elem(&thermal_zone_slots, &zone_id);
	__u32 slot;

	if (slot_ptr) {
		slot = *slot_ptr;
	} else {
		__u32 *next = bpf_map_lookup_elem(&thermal_next_slot, &zero);
		if (!next)
			return 0;
		slot = *next;
		if (slot >= PROCFAST_MAX_THERMAL_ZONES)
			return 0;
		(*next)++;
		bpf_map_update_elem(&thermal_zone_slots, &zone_id, &slot, BPF_ANY);
	}

	if (slot >= PROCFAST_MAX_THERMAL_ZONES)
		return 0;

	struct procfast_thermal_zone *dst = &data->zones[slot];

	/* Read temperature (millidegrees Celsius) */
	int temp_val = 0;
	bpf_core_read(&temp_val, sizeof(temp_val), temp);
	dst->temp_millicelsius = temp_val;

	/* Read zone type string */
	bpf_core_read(&dst->zone_type, sizeof(dst->zone_type), &tz->type);

	/* Update count and timestamp */
	__u32 *next = bpf_map_lookup_elem(&thermal_next_slot, &zero);
	if (next && *next > data->nr_zones)
		data->nr_zones = *next;
	data->timestamp_ns = bpf_ktime_get_ns();

	return 0;
}

SEC("syscall")
int procfast_thermal_init(void *ctx)
{
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
