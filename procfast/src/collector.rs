use bytemuck::{Pod, Zeroable};
use memmap2::{Mmap, MmapOptions};
use std::os::fd::BorrowedFd;
use std::sync::atomic::{Ordering, fence};

/// Safe mmap-based reader for a BPF array map value.
///
/// Uses `memmap2::Mmap` for the mmap (RAII, safe slice access) and
/// `bytemuck` for the type cast (safe, checked). The seqlock read
/// uses byte copies and `from_bytes` — no raw pointer casts.
///
/// The only `unsafe` is in `from_fd`, where `Mmap::map()` is inherently
/// unsafe because the mapped memory is concurrently modified by the
/// kernel BPF program.
pub struct MmapReader<T: Pod + Copy> {
    mmap: Mmap,
    _marker: std::marker::PhantomData<T>,
}

// SAFETY: Mmap is Send+Sync, and T: Pod is always safe to share.
// We only read the mmap and copy bytes out.
unsafe impl<T: Pod + Copy> Send for MmapReader<T> {}
unsafe impl<T: Pod + Copy> Sync for MmapReader<T> {}

impl<T: Pod + Copy> MmapReader<T> {
    /// Create a reader by mmapping a BPF map fd.
    pub fn from_fd(fd: BorrowedFd<'_>) -> Result<Self, std::io::Error> {
        let size = std::mem::size_of::<T>();
        // BPF map fds don't report their size via fstat, so we must
        // specify the length explicitly.
        // SAFETY: The fd refers to a BPF mmapable array map. The kernel
        // guarantees the mapping is valid for the map's lifetime. Concurrent
        // writes by the BPF program are handled by the seqlock protocol.
        let mmap = unsafe {
            MmapOptions::new()
                .len(size)
                .map(&fd)?
        };
        Ok(Self {
            mmap,
            _marker: std::marker::PhantomData,
        })
    }

    /// Read a consistent snapshot using the seqlock protocol.
    ///
    /// The first 8 bytes of the mmap'd region are the sequence counter.
    /// Spins if the counter is odd (writer active), retries if it
    /// changes during the read (torn data).
    ///
    /// Uses a stack-allocated zeroed value and `copy_from_slice` to
    /// avoid heap allocation on every read.
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

            // Copy into a zeroed stack value via its byte representation.
            // bytemuck guarantees Pod types can be safely constructed
            // from any byte pattern, and Zeroable gives us a valid init.
            let mut data: T = Zeroable::zeroed();
            let dst = bytemuck::bytes_of_mut(&mut data);
            dst.copy_from_slice(&bytes[..size]);

            fence(Ordering::Acquire);
            let seq2 = read_seq(bytes);

            if seq1 == seq2 {
                return data;
            }
        }
    }
}

fn read_seq(bytes: &[u8]) -> u64 {
    let arr: [u8; 8] = bytes[..8].try_into().unwrap();
    u64::from_ne_bytes(arr)
}
