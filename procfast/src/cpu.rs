use procfast_common::CpuData;

use crate::collector::MmapReader;
use crate::error::ProcfastError;

use std::os::fd::BorrowedFd;

/// Zero-copy reader for CPU statistics collected by the BPF program.
pub struct CpuCollector {
    reader: MmapReader<CpuData>,
}

impl CpuCollector {
    pub(crate) fn from_fd(fd: BorrowedFd<'_>) -> Result<Self, ProcfastError> {
        let reader = MmapReader::from_fd(fd).map_err(ProcfastError::Mmap)?;
        Ok(Self { reader })
    }

    /// Read a consistent snapshot of CPU data.
    ///
    /// This performs a seqlocked read from the mmap'd BPF map.
    /// No syscalls are involved — just memory reads with fence instructions.
    pub fn snapshot(&self) -> CpuData {
        self.reader.snapshot()
    }
}
