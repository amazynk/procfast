//! # procfast-client — Unprivileged reader for procfast metrics
//!
//! This crate connects to BPF maps pinned by `procfastd` and provides
//! the same zero-copy read interface — but without requiring any
//! BPF capabilities. Any user who can read `/sys/fs/bpf/procfast/` can
//! use this.
//!
//! ## Architecture
//!
//! ```text
//! procfastd (root)           procfast-client (any user)
//! ┌──────────┐           ┌──────────────┐
//! │ loads BPF │  pins     │ opens pinned │
//! │ programs  │──────────>│ map by path  │
//! │ pins maps │  bpffs    │ mmaps it     │
//! └──────────┘           │ reads data   │
//!                        └──────────────┘
//! ```
//!
//! ## Usage
//!
//! ```no_run
//! use procfast_client::ProcfastClient;
//!
//! let client = ProcfastClient::connect("/sys/fs/bpf/procfast")?;
//!
//! let cpu = client.cpu()?.snapshot();
//! println!("CPUs: {}", cpu.nr_cpus);
//!
//! let mem = client.mem()?.snapshot();
//! println!("Free: {} MiB", mem.free_bytes / (1 << 20));
//!
//! let procs = client.proc_stats()?.snapshot_all()?;
//! for p in &procs {
//!     println!("{}: {}", p.pid, std::str::from_utf8(&p.comm).unwrap().trim_end_matches('\0'));
//! }
//! # Ok::<(), procfast_client::ClientError>(())
//! ```

use bytemuck::{Pod, Zeroable};
use procfast_common::*;
use libbpf_rs::{MapCore, MapFlags, MapHandle};
use memmap2::{Mmap, MmapOptions};
use std::os::fd::AsFd;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::atomic::{Ordering, fence};

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("procfastd not running: {0} not found")]
    NotRunning(String),

    #[error("failed to open pinned map {0}: {1}")]
    OpenMap(String, String),

    #[error("mmap failed: {0}")]
    Mmap(std::io::Error),

    #[error("map iteration failed: {0}")]
    Iterate(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Client handle for reading procfast metrics from pinned maps.
///
/// No BPF capabilities required — just filesystem read access to
/// the pin directory (default: `/sys/fs/bpf/procfast/`).
pub struct ProcfastClient {
    pin_dir: String,
}

impl ProcfastClient {
    /// Connect to a running procfastd instance by opening its pinned maps.
    ///
    /// Returns an error if procfastd is not running (maps not pinned).
    pub fn connect(pin_dir: &str) -> Result<Self, ClientError> {
        let dir = Path::new(pin_dir);
        if !dir.exists() {
            return Err(ClientError::NotRunning(pin_dir.to_string()));
        }
        Ok(Self {
            pin_dir: pin_dir.to_string(),
        })
    }

    /// Connect to procfastd at the default pin path (`/sys/fs/bpf/procfast`).
    pub fn connect_default() -> Result<Self, ClientError> {
        Self::connect("/sys/fs/bpf/procfast")
    }

    /// Open the CPU stats reader.
    pub fn cpu(&self) -> Result<MmapReader<CpuData>, ClientError> {
        MmapReader::open(&self.map_path("cpu_data"))
    }

    /// Open the memory stats reader.
    pub fn mem(&self) -> Result<MmapReader<MemData>, ClientError> {
        MmapReader::open(&self.map_path("mem_data"))
    }

    /// Open the network stats reader.
    pub fn net(&self) -> Result<MmapReader<NetData>, ClientError> {
        MmapReader::open(&self.map_path("net_data"))
    }

    /// Open the disk I/O stats reader.
    pub fn disk(&self) -> Result<MmapReader<DiskData>, ClientError> {
        MmapReader::open(&self.map_path("disk_data"))
    }

    /// Open the thermal stats reader.
    pub fn thermal(&self) -> Result<MmapReader<ThermalData>, ClientError> {
        MmapReader::open(&self.map_path("thermal_data"))
    }

    /// Open the interrupt stats reader — reads live from percpu + metadata maps.
    pub fn irq(&self) -> Result<IrqReader, ClientError> {
        let percpu_map = open_pinned_map(&self.map_path("irq_counts"))?;
        let metadata_map = open_pinned_map(&self.map_path("irq_metadata")).ok();
        Ok(IrqReader { percpu_map, metadata_map })
    }

    /// Open the file descriptor reader.
    pub fn fd(&self) -> Result<FdReader, ClientError> {
        let fd_map = open_pinned_map(&self.map_path("fd_entries"))?;
        Ok(FdReader { fd_map })
    }

    /// Open the socket reader.
    pub fn sock(&self) -> Result<SockReader, ClientError> {
        let sock_map = open_pinned_map(&self.map_path("sock_entries"))?;
        Ok(SockReader { sock_map })
    }

    /// Open the cgroup stats reader.
    pub fn cgroup(&self) -> Result<CgroupReader, ClientError> {
        let cgroup_map = open_pinned_map(&self.map_path("cgroup_entries"))?;
        Ok(CgroupReader { cgroup_map })
    }

    /// Open the process stats reader.
    pub fn proc_stats(&self) -> Result<ProcReader, ClientError> {
        let header = MmapReader::open(&self.map_path("proc_header"))?;
        let stats_map = open_pinned_map(&self.map_path("proc_stats"))?;
        Ok(ProcReader {
            header,
            stats_map,
        })
    }

    fn map_path(&self, name: &str) -> String {
        format!("{}/{}", self.pin_dir, name)
    }
}

/// Zero-copy reader for a single mmapable BPF array map.
///
/// Opens a pinned map file with regular `open()` (no CAP_BPF needed)
/// and mmaps it. Reads use the seqlock protocol with `bytemuck` for
/// safe byte-to-struct casting.
pub struct MmapReader<T: Pod + Copy> {
    mmap: Mmap,
    _map_handle: MapHandle,
    _marker: std::marker::PhantomData<T>,
}

// SAFETY: Mmap is Send+Sync, File is Send+Sync, T: Pod is safe to share.
unsafe impl<T: Pod + Copy> Send for MmapReader<T> {}
unsafe impl<T: Pod + Copy> Sync for MmapReader<T> {}

impl<T: Pod + Copy> MmapReader<T> {
    fn open(path: &str) -> Result<Self, ClientError> {
        let map_handle = open_pinned_map(path)?;
        let size = std::mem::size_of::<T>();

        // SAFETY: The fd refers to a BPF mmapable array map pinned by procfastd.
        let mmap = unsafe {
            MmapOptions::new()
                .len(size)
                .map(&map_handle.as_fd())
        }.map_err(ClientError::Mmap)?;

        Ok(Self {
            mmap,
            _map_handle: map_handle,
            _marker: std::marker::PhantomData,
        })
    }

    /// Read a consistent snapshot using the seqlock protocol.
    ///
    /// All operations here are safe:
    /// - Byte slice access via Mmap's Deref (safe)
    /// - Seq counter read via from_ne_bytes (safe)
    /// - Data copy via bytemuck::from_bytes (safe, checked)
    pub fn snapshot(&self) -> T {
        let bytes: &[u8] = &self.mmap;
        let size = std::mem::size_of::<T>();
        loop {
            let seq1 = read_seq(bytes);
            if seq1 & 1 != 0 {
                std::hint::spin_loop();
                continue;
            }
            fence(Ordering::Acquire);

            let mut data: T = Zeroable::zeroed();
            bytemuck::bytes_of_mut(&mut data).copy_from_slice(&bytes[..size]);

            fence(Ordering::Acquire);
            let seq2 = read_seq(bytes);

            if seq1 == seq2 {
                return data;
            }
        }
    }
}

/// Reader for per-process stats (hash map, not mmapable).
///
/// Uses `libbpf_rs::MapHandle` for safe BPF map operations — no raw
/// `libc::syscall` calls needed.
pub struct ProcReader {
    header: MmapReader<ProcHeader>,
    stats_map: MapHandle,
}

impl ProcReader {
    /// Read process count and timestamp (zero-copy).
    pub fn header(&self) -> ProcHeader {
        self.header.snapshot()
    }

    /// Read all tracked processes using batch lookup.
    pub fn snapshot_all(&self) -> Result<Vec<ProcStats>, ClientError> {
        let key_size = std::mem::size_of::<u32>();
        let val_size = std::mem::size_of::<ProcStats>();
        let batch_size: u32 = 1024;

        let mut keys = vec![0u8; batch_size as usize * key_size];
        let mut values = vec![0u8; batch_size as usize * val_size];
        let mut procs = Vec::new();

        let mut in_batch: u64 = 0;
        let mut first = true;

        let opts = libbpf_rs::libbpf_sys::bpf_map_batch_opts {
            sz: std::mem::size_of::<libbpf_rs::libbpf_sys::bpf_map_batch_opts>() as u64,
            elem_flags: 0,
            flags: 0,
        };

        let fd = self.stats_map.as_fd().as_raw_fd();

        loop {
            let mut count = batch_size;

            let in_ptr = if first {
                std::ptr::null_mut()
            } else {
                &mut in_batch as *mut u64 as *mut std::ffi::c_void
            };

            let ret = unsafe {
                libbpf_rs::libbpf_sys::bpf_map_lookup_batch(
                    fd,
                    in_ptr,
                    &mut in_batch as *mut u64 as *mut std::ffi::c_void,
                    keys.as_mut_ptr() as *mut std::ffi::c_void,
                    values.as_mut_ptr() as *mut std::ffi::c_void,
                    &mut count,
                    &opts,
                )
            };

            first = false;

            for i in 0..count as usize {
                let offset = i * val_size;
                let entry: &ProcStats = bytemuck::from_bytes(
                    &values[offset..offset + val_size],
                );
                procs.push(*entry);
            }

            if ret != 0 {
                break;
            }
        }

        Ok(procs)
    }

    /// Look up a single process by PID.
    pub fn lookup(&self, pid: u32) -> Option<ProcStats> {
        let key = pid.to_ne_bytes();
        match self.stats_map.lookup(&key, MapFlags::ANY) {
            Ok(Some(value)) if value.len() == std::mem::size_of::<ProcStats>() => {
                let stats: &ProcStats = bytemuck::from_bytes(&value);
                Some(*stats)
            }
            _ => None,
        }
    }
}

/// Reader for interrupt stats with optional per-CPU count access.
pub struct IrqReader {
    percpu_map: MapHandle,
    metadata_map: Option<MapHandle>,
}

impl IrqReader {
    /// Build a live snapshot by reading percpu counts and metadata maps.
    pub fn snapshot(&self) -> IrqData {
        let mut data: IrqData = bytemuck::Zeroable::zeroed();
        let mut idx = 0usize;

        for key in self.percpu_map.keys() {
            if idx >= MAX_IRQS || key.len() < 4 { break; }
            let irq_num = u32::from_ne_bytes(key[..4].try_into().unwrap());

            let total = self.percpu_counts(irq_num)
                .map(|c| c.iter().sum::<u64>())
                .unwrap_or(0);

            let mut entry: IrqStats = bytemuck::Zeroable::zeroed();
            entry.irq = irq_num;
            entry.total_count = total;

            if let Some(ref meta_map) = self.metadata_map {
                if let Ok(Some(meta)) = meta_map.lookup(&key, MapFlags::ANY) {
                    if meta.len() >= 96 {
                        let cl = meta[..32].iter().position(|&b| b == 0).unwrap_or(32);
                        entry.chip_name[..cl].copy_from_slice(&meta[..cl]);
                        let al = meta[32..96].iter().position(|&b| b == 0).unwrap_or(64);
                        entry.action_name[..al].copy_from_slice(&meta[32..32 + al]);
                    }
                }
            }

            data.irqs[idx] = entry;
            idx += 1;
        }
        data.nr_irqs = idx as u32;
        data
    }

    /// Read per-CPU counts for a specific IRQ number.
    pub fn percpu_counts(&self, irq: u32) -> Option<Vec<u64>> {
        let key = irq.to_ne_bytes();
        let values = self.percpu_map.lookup_percpu(&key, MapFlags::ANY).ok()??;
        Some(
            values.iter().map(|v| {
                if v.len() >= 8 {
                    u64::from_ne_bytes(v[..8].try_into().unwrap())
                } else {
                    0
                }
            }).collect()
        )
    }
}

/// Reader for file descriptor tracking (hash map).
pub struct FdReader {
    fd_map: MapHandle,
}

impl FdReader {
    /// Read all tracked file descriptors using batch lookup.
    pub fn snapshot_all(&self) -> Result<Vec<FdInfo>, ClientError> {
        let key_size = std::mem::size_of::<u64>();
        let val_size = std::mem::size_of::<FdInfo>();
        let batch_size: u32 = 1024;

        let mut keys = vec![0u8; batch_size as usize * key_size];
        let mut values = vec![0u8; batch_size as usize * val_size];
        let mut fds = Vec::new();

        let mut in_batch: u64 = 0;
        let mut first = true;

        let opts = libbpf_rs::libbpf_sys::bpf_map_batch_opts {
            sz: std::mem::size_of::<libbpf_rs::libbpf_sys::bpf_map_batch_opts>() as u64,
            elem_flags: 0,
            flags: 0,
        };

        let fd = self.fd_map.as_fd().as_raw_fd();

        loop {
            let mut count = batch_size;

            let in_ptr = if first {
                std::ptr::null_mut()
            } else {
                &mut in_batch as *mut u64 as *mut std::ffi::c_void
            };

            let ret = unsafe {
                libbpf_rs::libbpf_sys::bpf_map_lookup_batch(
                    fd,
                    in_ptr,
                    &mut in_batch as *mut u64 as *mut std::ffi::c_void,
                    keys.as_mut_ptr() as *mut std::ffi::c_void,
                    values.as_mut_ptr() as *mut std::ffi::c_void,
                    &mut count,
                    &opts,
                )
            };

            first = false;

            for i in 0..count as usize {
                let offset = i * val_size;
                let entry: &FdInfo = bytemuck::from_bytes(
                    &values[offset..offset + val_size],
                );
                fds.push(*entry);
            }

            if ret != 0 {
                break;
            }
        }

        Ok(fds)
    }

    /// Look up a single fd entry for a given pid and fd number.
    pub fn lookup(&self, pid: u32, fd_num: u32) -> Option<FdInfo> {
        let key = ((pid as u64) << 32) | (fd_num as u64);
        let key_bytes = key.to_ne_bytes();
        match self.fd_map.lookup(&key_bytes, MapFlags::ANY) {
            Ok(Some(value)) if value.len() == std::mem::size_of::<FdInfo>() => {
                let info: &FdInfo = bytemuck::from_bytes(&value);
                Some(*info)
            }
            _ => None,
        }
    }

    /// List all open fds for a single process.
    pub fn list_pid(&self, pid: u32) -> Result<Vec<FdInfo>, ClientError> {
        let all = self.snapshot_all()?;
        Ok(all.into_iter().filter(|info| info.pid == pid).collect())
    }
}

// --- helpers ---

/// Reader for socket data (hash map keyed by inode).
pub struct SockReader {
    sock_map: MapHandle,
}

impl SockReader {
    /// Look up socket info by inode.
    pub fn lookup(&self, inode: u64) -> Option<SockInfo> {
        let key = inode.to_ne_bytes();
        match self.sock_map.lookup(&key, MapFlags::ANY) {
            Ok(Some(value)) if value.len() == std::mem::size_of::<SockInfo>() => {
                let info: &SockInfo = bytemuck::from_bytes(&value);
                Some(*info)
            }
            _ => None,
        }
    }

    /// Get all sockets.
    pub fn snapshot_all(&self) -> Vec<SockInfo> {
        let val_size = std::mem::size_of::<SockInfo>();
        let mut socks = Vec::new();
        for key in self.sock_map.keys() {
            if let Ok(Some(value)) = self.sock_map.lookup(&key, MapFlags::ANY) {
                if value.len() == val_size {
                    let info: &SockInfo = bytemuck::from_bytes(&value);
                    socks.push(*info);
                }
            }
        }
        socks
    }
}

pub struct CgroupReader {
    cgroup_map: MapHandle,
}

impl CgroupReader {
    /// Get all cgroup stats.
    pub fn snapshot_all(&self) -> Vec<CgroupStats> {
        let val_size = std::mem::size_of::<CgroupStats>();
        let mut cgroups = Vec::new();
        for key in self.cgroup_map.keys() {
            if let Ok(Some(value)) = self.cgroup_map.lookup(&key, MapFlags::ANY) {
                if value.len() == val_size {
                    let info: &CgroupStats = bytemuck::from_bytes(&value);
                    cgroups.push(*info);
                }
            }
        }
        cgroups
    }
}

fn open_pinned_map(path: &str) -> Result<MapHandle, ClientError> {
    MapHandle::from_pinned_path(path)
        .map_err(|e| ClientError::OpenMap(path.to_string(), e.to_string()))
}

fn read_seq(bytes: &[u8]) -> u64 {
    let arr: [u8; 8] = bytes[..8].try_into().unwrap();
    u64::from_ne_bytes(arr)
}
