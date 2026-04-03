use procfast_common::FdInfo;
use libbpf_rs::{MapCore, MapFlags, MapHandle};

use crate::error::ProcfastError;

use std::os::fd::{AsFd, AsRawFd};

/// Collector for per-process file descriptor information.
///
/// Uses `bpf_map_lookup_batch` to read all entries in a few large
/// syscalls instead of iterating /proc/[pid]/fd/ for every process.
pub struct FdCollector {
    fd_map: MapHandle,
}

impl FdCollector {
    pub(crate) fn new(fd_map: MapHandle) -> Self {
        Self { fd_map }
    }

    /// Read all tracked file descriptors using batch lookup.
    pub fn snapshot_all(&self) -> Result<Vec<FdInfo>, ProcfastError> {
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
                // ENOENT means we've read all entries (normal completion)
                break;
            }
        }

        Ok(fds)
    }

    /// Look up a single fd entry for a given pid and fd number. O(1).
    pub fn lookup(&self, pid: u32, fd: u32) -> Option<FdInfo> {
        let key = ((pid as u64) << 32) | (fd as u64);
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
    ///
    /// Reads the entire map and filters by pid. For frequent per-pid
    /// queries, consider caching `snapshot_all()` results.
    pub fn list_pid(&self, pid: u32) -> Result<Vec<FdInfo>, ProcfastError> {
        let all = self.snapshot_all()?;
        Ok(all.into_iter().filter(|info| info.pid == pid).collect())
    }
}
