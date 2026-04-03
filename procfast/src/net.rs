use procfast_common::NetData;

use crate::collector::MmapReader;
use crate::error::ProcfastError;

use std::os::fd::BorrowedFd;

/// Zero-copy reader for network device statistics.
pub struct NetCollector {
    reader: MmapReader<NetData>,
}

impl NetCollector {
    pub(crate) fn from_fd(fd: BorrowedFd<'_>) -> Result<Self, ProcfastError> {
        let reader = MmapReader::from_fd(fd).map_err(ProcfastError::Mmap)?;
        Ok(Self { reader })
    }

    pub fn snapshot(&self) -> NetData {
        self.reader.snapshot()
    }
}
