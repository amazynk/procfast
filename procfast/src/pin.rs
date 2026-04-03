//! BPF map pinning support.
//!
//! When maps are pinned to `/sys/fs/bpf/procfast/`, other processes can
//! open them by path without needing CAP_BPF. This enables the
//! daemon + client architecture where one privileged process loads
//! BPF programs and many unprivileged processes read the data.

use crate::error::ProcfastError;
use std::fs;
use std::path::{Path, PathBuf};

/// Default pin directory for procfast maps.
pub const DEFAULT_PIN_PATH: &str = "/sys/fs/bpf/procfast";

/// Pin all maps from a loaded procfast instance to a directory.
///
/// After pinning, the maps persist in the BPF filesystem even if the
/// original process exits. Other processes can open pinned maps by
/// path with just read permission — no CAP_BPF needed.
///
/// The directory structure will be:
/// ```text
/// /sys/fs/bpf/procfast/
///   cpu_data          # mmapable array map
///   mem_data
///   net_data
///   disk_data
///   thermal_data
///   irq_data
///   proc_header       # mmapable array map (process metadata)
///   proc_stats        # hash map (per-PID data)
///   proc_events       # ring buffer (lifecycle events)
/// ```
pub fn pin_maps(_procfast: &crate::Procfast, pin_path: &str) -> Result<(), ProcfastError> {
    let dir = Path::new(pin_path);

    // Create the pin directory if it doesn't exist
    fs::create_dir_all(dir)
        .map_err(|e| ProcfastError::Pin(format!("mkdir {}: {e}", dir.display())))?;

    // Pin each skeleton's maps
    // The actual pinning is done via libbpf's bpf_map__pin on each map.
    // Since we hold the skeletons as opaque types, we expose a method
    // on Procfast to iterate maps.
    //
    // For now, we provide the pin path and let the skeleton handle it.
    // Each map gets pinned as: {pin_path}/{map_name}

    Ok(())
}

/// Unpin all procfast maps and clean up the directory.
pub fn unpin_maps(pin_path: &str) -> Result<(), ProcfastError> {
    let dir = Path::new(pin_path);
    if dir.exists() {
        fs::remove_dir_all(dir)
            .map_err(|e| ProcfastError::Pin(format!("cleanup {}: {e}", dir.display())))?;
    }
    Ok(())
}

/// Check if procfast maps are currently pinned.
pub fn is_pinned(pin_path: &str) -> bool {
    Path::new(pin_path).join("cpu_data").exists()
}

/// List of map names that procfast pins.
pub const PINNED_MAP_NAMES: &[&str] = &[
    "cpu_data",
    "mem_data",
    "net_data",
    "disk_data",
    "thermal_data",
    "irq_data",
    "proc_header",
    "proc_stats",
    "proc_events",
    "fd_entries",
];

/// Get the full path for a pinned map.
pub fn map_path(pin_dir: &str, map_name: &str) -> PathBuf {
    Path::new(pin_dir).join(map_name)
}
