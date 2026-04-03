use procfast_common::SockInfo;
use libbpf_rs::{MapCore, MapFlags, MapHandle};

use std::os::fd::{AsFd, AsRawFd};

/// Collector for socket information via BPF iterators.
///
/// Stores a handle to the sock_entries hash map keyed by inode.
/// Populated by running the TCP/UDP/Unix iterators at startup.
pub struct SockCollector {
    sock_map: MapHandle,
}

impl SockCollector {
    pub(crate) fn new(sock_map: MapHandle) -> Self {
        Self { sock_map }
    }

    /// Look up socket info by inode number.
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

    /// Get all sockets using batch lookup.
    pub fn snapshot_all(&self) -> Vec<SockInfo> {
        let key_size = std::mem::size_of::<u64>();
        let val_size = std::mem::size_of::<SockInfo>();
        let batch_size: u32 = 1024;

        let mut keys = vec![0u8; batch_size as usize * key_size];
        let mut values = vec![0u8; batch_size as usize * val_size];
        let mut socks = Vec::new();

        let mut in_batch: u64 = 0;
        let mut first = true;

        let opts = libbpf_rs::libbpf_sys::bpf_map_batch_opts {
            sz: std::mem::size_of::<libbpf_rs::libbpf_sys::bpf_map_batch_opts>() as u64,
            elem_flags: 0,
            flags: 0,
        };

        let fd = self.sock_map.as_fd().as_raw_fd();

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
                let entry: &SockInfo = bytemuck::from_bytes(
                    &values[offset..offset + val_size],
                );
                socks.push(*entry);
            }

            if ret != 0 {
                break;
            }
        }

        socks
    }
}
