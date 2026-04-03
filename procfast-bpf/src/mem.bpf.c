// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "procfast.h"

/*
 * Memory stats collector.
 *
 * Uses fexit on si_meminfo to capture struct sysinfo after the kernel
 * populates it. This avoids the need for global variable access
 * (_totalram_pages, vm_zone_stat, etc.) which may not be in kernel BTF.
 *
 * The BPF timer periodically calls bpf_ktime_get_ns() to update the
 * timestamp, but the actual memory data comes from intercepting
 * si_meminfo calls (triggered by /proc/meminfo reads or our userspace
 * helper thread).
 */

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct procfast_mem_data);
	__uint(map_flags, BPF_F_MMAPABLE);
} mem_data SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct procfast_config);
} mem_config SEC(".maps");

/*
 * fexit hook on si_meminfo.
 *
 * si_meminfo(struct sysinfo *val) fills val with memory statistics.
 * We intercept the return and copy the results into our BPF map.
 *
 * si_meminfo is called by:
 *   - /proc/meminfo handler
 *   - OOM killer
 *   - Various kernel subsystems
 *
 * We also trigger it from userspace by reading /proc/meminfo
 * at the configured interval.
 */
SEC("fexit/si_meminfo")
int BPF_PROG(fexit_si_meminfo, struct sysinfo *info)
{
	struct procfast_mem_data *data;
	__u32 zero = 0;

	data = bpf_map_lookup_elem(&mem_data, &zero);
	if (!data)
		return 0;

	PROCFAST_SEQ_WRITE_BEGIN(data);
	data->timestamp_ns = bpf_ktime_get_ns();

	/*
	 * struct sysinfo fields (filled by si_meminfo):
	 *   totalram, freeram, sharedram, bufferram (in mem_unit-sized pages)
	 *   totalswap, freeswap
	 *   mem_unit (bytes per unit, typically PAGE_SIZE)
	 */
	__u32 mem_unit = BPF_CORE_READ(info, mem_unit);
	if (mem_unit == 0)
		mem_unit = 1;

	data->total_bytes     = (__u64)BPF_CORE_READ(info, totalram)  * mem_unit;
	data->free_bytes      = (__u64)BPF_CORE_READ(info, freeram)   * mem_unit;
	data->buffers_bytes   = (__u64)BPF_CORE_READ(info, bufferram) * mem_unit;
	data->swap_total_bytes = (__u64)BPF_CORE_READ(info, totalswap) * mem_unit;
	data->swap_free_bytes = (__u64)BPF_CORE_READ(info, freeswap)  * mem_unit;
	data->shmem_bytes     = (__u64)BPF_CORE_READ(info, sharedram) * mem_unit;

	PROCFAST_SEQ_WRITE_END(data);
	return 0;
}

/*
 * fexit hook on si_mem_available.
 *
 * si_mem_available() returns available memory in pages.
 * It accounts for watermarks, reclaimable slab, and page cache —
 * the same estimate shown as "MemAvailable" in /proc/meminfo.
 */
SEC("fexit/si_mem_available")
int BPF_PROG(fexit_si_mem_available, long ret)
{
	struct procfast_mem_data *data;
	__u32 zero = 0;

	data = bpf_map_lookup_elem(&mem_data, &zero);
	if (!data)
		return 0;

	/* ret is in pages; convert to bytes (PAGE_SIZE = 4096 on x86) */
	if (ret > 0)
		data->available_bytes = (__u64)ret * 4096;

	return 0;
}

SEC("syscall")
int procfast_mem_init(void *ctx)
{
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
