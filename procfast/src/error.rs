use std::io;

#[derive(Debug, thiserror::Error)]
pub enum ProcfastError {
    #[error("BPF loading failed: {0}")]
    BpfLoad(String),

    #[error("BPF program run failed: {0}")]
    BpfRun(String),

    #[error("map mmap failed: {0}")]
    Mmap(io::Error),

    #[error("missing capability: {0}")]
    Permission(String),

    #[error("kernel too old: requires {required}, have {current}")]
    KernelVersion { required: String, current: String },

    #[error("collector {0} not enabled")]
    NotEnabled(&'static str),

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("map pin failed: {0}")]
    Pin(String),

    #[error("{0}")]
    Other(String),
}
