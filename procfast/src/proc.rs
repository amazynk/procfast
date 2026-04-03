use procfast_common::{ProcHeader, ProcStats};
use libbpf_rs::{MapCore, MapFlags, MapHandle};

use crate::collector::MmapReader;
use crate::error::ProcfastError;

use std::os::fd::{AsFd, AsRawFd, BorrowedFd};

/// Collector for per-process statistics.
///
/// Uses `bpf_map_lookup_batch` to read all entries in a few large
/// syscalls instead of one per process.
pub struct ProcCollector {
    header_reader: MmapReader<ProcHeader>,
    stats_map: MapHandle,
    events_fd: i32,
}

impl ProcCollector {
    pub(crate) fn new(
        header_fd: BorrowedFd<'_>,
        stats_map: MapHandle,
        events_fd: i32,
    ) -> Result<Self, ProcfastError> {
        let header_reader = MmapReader::from_fd(header_fd).map_err(ProcfastError::Mmap)?;
        Ok(Self { header_reader, stats_map, events_fd })
    }

    pub fn header(&self) -> ProcHeader {
        self.header_reader.snapshot()
    }

    /// Read all tracked processes using batch lookup.
    ///
    /// Uses `bpf_map_lookup_batch` to fetch up to 1024 entries per
    /// syscall, reducing overhead from ~1400 syscalls (2 per process)
    /// to ~2 syscalls for 700 processes.
    pub fn snapshot_all(&self) -> Result<Vec<ProcStats>, ProcfastError> {
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

            // Process returned entries
            for i in 0..count as usize {
                let offset = i * val_size;
                let entry: &ProcStats = bytemuck::from_bytes(
                    &values[offset..offset + val_size],
                );
                procs.push(*entry);
            }

            if ret != 0 {
                // ENOENT means we've read all entries (normal completion)
                // Any other error: we still got `count` valid entries above
                break;
            }
        }

        Ok(procs)
    }

    /// Look up stats for a single PID. O(1), ~200ns.
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

    pub fn events_fd(&self) -> i32 {
        self.events_fd
    }

    /// Drain pending events from the ring buffer.
    ///
    /// Returns a set of PIDs that had fork/exec/exit events since
    /// the last drain. Useful for incremental updates: only re-fetch
    /// PIDs that changed instead of scanning all processes.
    ///
    /// Event format: { pid: u32, event_type: u32 }
    /// event_type: 0=new, 1=exec, 2=exit
    pub fn drain_events(&self) -> (Vec<u32>, Vec<u32>) {
        let mut changed = Vec::new();
        let mut exited = Vec::new();

        if self.events_fd < 0 {
            return (changed, exited);
        }

        // Read raw events from the BPF ring buffer fd.
        // SAFETY: events_fd is a valid BPF ring buffer fd from skeleton load.
        // We read into a stack buffer — no ownership or lifetime concerns.
        let mut buf = [0u8; 4096];
        loop {
            let n = unsafe {
                libc::read(
                    self.events_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n <= 0 {
                break;
            }
            let n = n as usize;
            let mut off = 0;
            while off + 8 <= n {
                let pid = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap());
                let etype = u32::from_ne_bytes(buf[off + 4..off + 8].try_into().unwrap());
                if etype == 2 {
                    exited.push(pid);
                } else {
                    changed.push(pid);
                }
                off += 8;
            }
        }

        (changed, exited)
    }

    /// Refresh specific PIDs in a cache. Returns the number updated.
    pub fn refresh_pids(&self, pids: &[u32], cache: &mut std::collections::HashMap<u32, ProcStats>) -> usize {
        let mut count = 0;
        for &pid in pids {
            if let Some(stats) = self.lookup(pid) {
                cache.insert(pid, stats);
                count += 1;
            }
        }
        count
    }
}
