use procfast_common::ThermalData;

use crate::collector::MmapReader;
use crate::error::ProcfastError;

use std::os::fd::BorrowedFd;

/// Zero-copy reader for thermal zone data.
pub struct ThermalCollector {
    reader: MmapReader<ThermalData>,
}

impl ThermalCollector {
    pub(crate) fn from_fd(fd: BorrowedFd<'_>) -> Result<Self, ProcfastError> {
        let reader = MmapReader::from_fd(fd).map_err(ProcfastError::Mmap)?;
        Ok(Self { reader })
    }

    pub fn snapshot(&self) -> ThermalData {
        self.reader.snapshot()
    }
}
