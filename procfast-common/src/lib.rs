//! Shared type definitions between BPF programs and userspace.
//!
//! These structs are `#[repr(C)]` and must exactly match the layout
//! defined in `procfast-bpf/src/procfast.h`. The BPF programs write these
//! structs into mmapable array maps, and userspace reads them via
//! zero-copy pointer casts.
//!
//! All types derive `bytemuck::Pod` and `bytemuck::Zeroable`, which
//! enables safe zero-initialization (replacing `mem::zeroed()`) and
//! safe byte-to-struct casting (replacing raw pointer casts).

#![no_std]

use bytemuck::{Pod, Zeroable};

pub const MAX_CPUS: usize = 256;
pub const MAX_NET_DEVS: usize = 32;
pub const MAX_DISKS: usize = 64;
pub const MAX_THERMAL_ZONES: usize = 16;
pub const MAX_IRQS: usize = 512;
pub const MAX_PROCS: usize = 8192;
pub const MAX_FDS: usize = 65536;
pub const MAX_FD_PATH: usize = 256;

/// Per-CPU time accounting in nanoseconds.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod, Zeroable)]
pub struct CpuStats {
    pub user_ns: u64,
    pub nice_ns: u64,
    pub system_ns: u64,
    pub idle_ns: u64,
    pub iowait_ns: u64,
    pub irq_ns: u64,
    pub softirq_ns: u64,
    pub steal_ns: u64,
    pub guest_ns: u64,
    pub guest_nice_ns: u64,
}

/// Snapshot of CPU statistics for all CPUs.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct CpuData {
    /// Seqlock counter. Odd = BPF is writing, even = consistent.
    pub seq: u64,
    /// Kernel monotonic timestamp when this snapshot was taken.
    pub timestamp_ns: u64,
    /// Number of online CPUs.
    pub nr_cpus: u32,
    pub _pad: u32,
    /// Aggregated stats across all CPUs.
    pub total: CpuStats,
    /// Per-CPU stats. Only indices `0..nr_cpus` are valid.
    pub per_cpu: [CpuStats; MAX_CPUS],
}

/// Snapshot of system memory statistics.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct MemData {
    pub seq: u64,
    pub timestamp_ns: u64,
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub available_bytes: u64,
    pub buffers_bytes: u64,
    pub cached_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_free_bytes: u64,
    pub active_bytes: u64,
    pub inactive_bytes: u64,
    pub slab_reclaimable_bytes: u64,
    pub slab_unreclaimable_bytes: u64,
    pub dirty_bytes: u64,
    pub writeback_bytes: u64,
    pub shmem_bytes: u64,
}

impl Default for MemData {
    fn default() -> Self {
        Zeroable::zeroed()
    }
}

/// Statistics for a single network device.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod, Zeroable)]
pub struct NetDevStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
    pub name: [u8; 16],
}

/// Snapshot of network device statistics.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct NetData {
    pub seq: u64,
    pub timestamp_ns: u64,
    pub nr_devs: u32,
    pub _pad: u32,
    pub devs: [NetDevStats; MAX_NET_DEVS],
}

/// Statistics for a single block device.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod, Zeroable)]
pub struct DiskStats {
    pub read_ios: u64,
    pub write_ios: u64,
    pub read_sectors: u64,
    pub write_sectors: u64,
    pub read_ns: u64,
    pub write_ns: u64,
    pub io_ticks_ns: u64,
    pub major: u32,
    pub minor: u32,
    pub name: [u8; 32],
}

/// Snapshot of block device statistics.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct DiskData {
    pub seq: u64,
    pub timestamp_ns: u64,
    pub nr_disks: u32,
    pub _pad: u32,
    pub disks: [DiskStats; MAX_DISKS],
}

/// A single thermal zone reading.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Pod, Zeroable)]
pub struct ThermalZone {
    pub temp_millicelsius: i32,
    pub _pad: u32,
    pub zone_type: [u8; 20],
    pub _pad2: [u8; 4],
}

/// Snapshot of thermal zone data.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct ThermalData {
    pub seq: u64,
    pub timestamp_ns: u64,
    pub nr_zones: u32,
    pub _pad: u32,
    pub zones: [ThermalZone; MAX_THERMAL_ZONES],
}

/// Per-IRQ counters for a single interrupt line.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct IrqStats {
    /// IRQ number (Linux IRQ, not hardware vector).
    pub irq: u32,
    pub _pad: u32,
    /// Total count across all CPUs.
    pub total_count: u64,
    /// IRQ chip name (e.g. "IO-APIC", "PCI-MSI").
    pub chip_name: [u8; 32],
    /// Action name (e.g. "ahci[0000:00:1f.2]", "eth0").
    pub action_name: [u8; 64],
}

impl Default for IrqStats {
    fn default() -> Self {
        Zeroable::zeroed()
    }
}

/// Snapshot of interrupt statistics.
///
/// This replaces `/proc/interrupts` which is one of the most expensive
/// proc files: it iterates every IRQ × every CPU, formats a massive
/// text table, and holds `sparse_irq_lock` during the walk.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct IrqData {
    pub seq: u64,
    pub timestamp_ns: u64,
    /// Number of IRQ lines with non-zero counts.
    pub nr_irqs: u32,
    pub _pad: u32,
    /// Per-IRQ statistics. Only indices `0..nr_irqs` are valid.
    pub irqs: [IrqStats; MAX_IRQS],
}

/// Per-process statistics. Replaces `/proc/[pid]/stat` + `/proc/[pid]/statm`
/// + `/proc/[pid]/io` reads.
///
/// Updated in real-time via scheduler and memory tracepoints — no polling
/// of per-PID proc files needed.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct ProcStats {
    /// Process ID.
    pub pid: u32,
    /// Thread group leader PID (== pid for main thread).
    pub tgid: u32,
    /// Parent PID.
    pub ppid: u32,
    /// Process state: 0=running, 1=sleeping, 2=disk sleep,
    /// 3=stopped, 4=zombie, 5=dead.
    pub state: u8,
    pub _pad1: [u8; 3],
    /// User ID of the process owner.
    pub uid: u32,
    /// Number of threads.
    pub nr_threads: u32,
    /// Process name (comm).
    pub comm: [u8; 16],
    /// CPU time in user mode (nanoseconds).
    pub utime_ns: u64,
    /// CPU time in kernel mode (nanoseconds).
    pub stime_ns: u64,
    /// Cumulative user time of all waited-for children.
    pub cutime_ns: u64,
    /// Cumulative system time of all waited-for children.
    pub cstime_ns: u64,
    /// Scheduler priority (nice value, -20 to 19).
    pub nice: i32,
    /// Scheduling policy (SCHED_NORMAL=0, SCHED_FIFO=1, etc.).
    pub policy: u32,
    /// CPU the process last ran on.
    pub last_cpu: u32,
    /// Real-time priority (0-99). 0 for normal (non-RT) processes.
    pub rt_priority: u32,
    /// Timestamp of last schedule-in event (for computing current CPU %).
    pub last_seen_ns: u64,
    /// Voluntary context switches.
    pub vol_ctxsw: u64,
    /// Involuntary context switches.
    pub invol_ctxsw: u64,
    /// Resident set size in bytes.
    pub rss_bytes: u64,
    /// Virtual memory size in bytes.
    pub vsize_bytes: u64,
    /// Shared memory (file-backed pages) in bytes.
    pub shared_bytes: u64,
    /// Bytes read (I/O accounting).
    pub read_bytes: u64,
    /// Bytes written (I/O accounting).
    pub write_bytes: u64,
    /// Precise cumulative CPU runtime in nanoseconds.
    /// Accumulated from sum_exec_runtime deltas in sched_switch — accurate for CPU% calculation.
    pub cpu_runtime_ns: u64,
    /// Process start time (monotonic ns since boot).
    pub start_time_ns: u64,
}

impl Default for ProcStats {
    fn default() -> Self {
        Zeroable::zeroed()
    }
}

/// Header for the process stats snapshot.
///
/// Unlike other collectors that use a fixed array, process stats use
/// a BPF hash map keyed by PID. This header provides metadata and
/// lives in a separate single-entry array map.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct ProcHeader {
    pub seq: u64,
    pub timestamp_ns: u64,
    /// Total number of tracked processes.
    pub nr_procs: u32,
    pub _pad: u32,
}

impl Default for ProcHeader {
    fn default() -> Self {
        Zeroable::zeroed()
    }
}

/// Configuration written by userspace, read by BPF programs.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct ProcfastConfig {
    /// Collection interval in nanoseconds.
    pub interval_ns: u64,
}

impl Default for ProcfastConfig {
    fn default() -> Self {
        Zeroable::zeroed()
    }
}

/// Per-file-descriptor info. Replaces `/proc/[pid]/fd/` readlink.
///
/// Tracked via openat/close hooks in the kernel. The path is whatever
/// string was passed to openat (may be relative).
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct FdInfo {
    /// Process ID (tgid).
    pub pid: u32,
    /// File descriptor number.
    pub fd: u32,
    /// Timestamp when the file was opened (monotonic ns), 0 if unknown.
    pub open_time_ns: u64,
    /// File inode number (for matching against socket map).
    pub inode: u64,
    /// Open flags (O_RDONLY, O_WRONLY, etc.).
    pub flags: u32,
    pub _pad: u32,
    /// Path string from openat (may be relative or empty for pre-existing fds).
    pub path: [u8; MAX_FD_PATH],
}

impl Default for FdInfo {
    fn default() -> Self {
        Zeroable::zeroed()
    }
}

/// Socket information from BPF socket iterators.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct SockInfo {
    pub inode: u64,
    pub family: u32,      // AF_INET=2, AF_INET6=10, AF_UNIX=1
    pub sock_type: u32,   // SOCK_STREAM=1, SOCK_DGRAM=2
    pub protocol: u8,     // IPPROTO_TCP=6, IPPROTO_UDP=17
    pub state: u8,        // TCP_ESTABLISHED=1, TCP_LISTEN=10, etc.
    pub _pad: u16,
    pub uid: u32,
    pub local_port: u32,
    pub remote_port: u32,
    pub local_addr4: u32,
    pub remote_addr4: u32,
    pub local_addr6: [u8; 16],
    pub remote_addr6: [u8; 16],
}

impl Default for SockInfo {
    fn default() -> Self {
        Zeroable::zeroed()
    }
}

impl core::fmt::Debug for FdInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let end = self.path.iter().position(|&c| c == 0).unwrap_or(self.path.len());
        f.debug_struct("FdInfo")
            .field("pid", &self.pid)
            .field("fd", &self.fd)
            .field("open_time_ns", &self.open_time_ns)
            .field("flags", &self.flags)
            .field("path", &core::str::from_utf8(&self.path[..end]).unwrap_or("?"))
            .finish()
    }
}
