use procfast_common::MemData;

use crate::collector::MmapReader;
use crate::error::ProcfastError;

use std::os::fd::BorrowedFd;

/// Zero-copy reader for memory statistics collected by the BPF program.
pub struct MemCollector {
    reader: MmapReader<MemData>,
}

impl MemCollector {
    pub(crate) fn from_fd(fd: BorrowedFd<'_>) -> Result<Self, ProcfastError> {
        let reader = MmapReader::from_fd(fd).map_err(ProcfastError::Mmap)?;
        Ok(Self { reader })
    }

    pub fn snapshot(&self) -> MemData {
        self.reader.snapshot()
    }
}
