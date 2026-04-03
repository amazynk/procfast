//! Fallback implementation that reads /proc and /sys the traditional way.
//!
//! This is used when BPF is unavailable (unprivileged user, old kernel,
//! missing BTF). It provides the same data through the same types, just
//! with the usual /proc overhead.
//!
//! The fallback is intentionally minimal — the whole point of procfast is
//! to avoid this path. It exists so consumers can use procfast unconditionally
//! with `.allow_fallback(true)` and gracefully degrade.

use crate::error::ProcfastError;
use crate::{Procfast, ProcfastBuilder};

pub(crate) fn build_fallback(_builder: ProcfastBuilder) -> Result<Procfast, ProcfastError> {
    // TODO: implement /proc-based fallback collectors
    // Each collector would spawn a thread that reads /proc at the
    // configured interval and writes to an Arc<AtomicCell<T>> that
    // the snapshot() method reads from.
    Err(ProcfastError::Other(
        "fallback /proc collection not yet implemented".into(),
    ))
}
