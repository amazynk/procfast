use procfast_common::DiskData;

use crate::collector::MmapReader;
use crate::error::ProcfastError;

use std::os::fd::BorrowedFd;

/// Zero-copy reader for block device I/O statistics.
pub struct DiskCollector {
    reader: MmapReader<DiskData>,
}

impl DiskCollector {
    pub(crate) fn from_fd(fd: BorrowedFd<'_>) -> Result<Self, ProcfastError> {
        let reader = MmapReader::from_fd(fd).map_err(ProcfastError::Mmap)?;
        Ok(Self { reader })
    }

    pub fn snapshot(&self) -> DiskData {
        self.reader.snapshot()
    }
}
