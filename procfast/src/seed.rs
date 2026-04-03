//! One-time seeding of BPF maps from /proc and /sys at startup.
//!
//! The BPF tracepoints only capture events *after* attachment. This
//! module reads the current state once to populate the maps with
//! historical data, so the output is complete from the first query.

use std::fs;
use std::path::Path;

/// Seed thermal data by reading all thermal zone sysfs files once.
/// This triggers the kernel's thermal_zone_get_temp() which our
/// fexit hook intercepts.
pub fn seed_thermal() {
    let thermal_dir = Path::new("/sys/class/thermal");
    if !thermal_dir.exists() {
        return;
    }
    if let Ok(entries) = fs::read_dir(thermal_dir) {
        for entry in entries.flatten() {
            let path = entry.path().join("temp");
            if path.exists() {
                let _ = fs::read_to_string(&path);
            }
        }
    }
}

/// Seed memory data by reading /proc/meminfo once.
/// This triggers si_meminfo() + si_mem_available() which our
/// fexit hooks intercept.
pub fn seed_mem() {
    let _ = fs::read_to_string("/proc/meminfo");
}

/// Seed network data by reading /proc/net/dev once.
/// This triggers dev_get_stats() for each device which our
/// fexit hook intercepts.
pub fn seed_net() {
    let _ = fs::read_to_string("/proc/net/dev");
}

/// Seed disk data by reading /proc/diskstats once.
/// This triggers diskstats_show() for each disk which our
/// fentry hook intercepts.
pub fn seed_disk() {
    let _ = fs::read_to_string("/proc/diskstats");
}

/// Seed interrupt data by reading /proc/interrupts once.
/// The actual interrupt counts are read from the proc file and
/// don't flow through our tracepoints, but this read does NOT
/// seed our BPF maps since /proc/interrupts doesn't call
/// handle_irq_event.
///
/// Instead, we parse /proc/interrupts and write the counts
/// directly into the IRQ percpu map and metadata map via
/// BPF map update syscalls.
pub fn seed_interrupts(irq_collector: &crate::irq::IrqCollector) {
    let content = match fs::read_to_string("/proc/interrupts") {
        Ok(c) => c,
        Err(_) => return,
    };

    let mut lines = content.lines();
    // First line is CPU header — parse to get CPU count
    let header = match lines.next() {
        Some(h) => h,
        None => return,
    };
    let nr_cpus = header.split_whitespace().count();

    for line in lines {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < nr_cpus + 1 {
            continue;
        }

        // First field is "NNN:" or "ABC:" (IRQ number or arch label)
        let irq_label = parts[0].trim_end_matches(':');

        // Parse IRQ number — skip arch-specific labels (NMI, LOC, etc.)
        // since we can't track those via handle_irq_event anyway
        let irq_num: u32 = match irq_label.parse() {
            Ok(n) => n,
            Err(_) => continue, // arch-specific, skip
        };

        // Parse per-CPU counts
        let mut per_cpu_counts = Vec::with_capacity(nr_cpus);
        for i in 1..=nr_cpus {
            let count: u64 = parts.get(i).and_then(|s| s.parse().ok()).unwrap_or(0);
            per_cpu_counts.push(count);
        }

        // After the CPU columns: chip_name [hwirq_info] action_name
        // e.g. "IR-IO-APIC    2-edge      timer"
        // or   "PCI-MSI-0000:00:00.2    0-edge      AMD-Vi"
        // Chip is the first token, action is the last token.
        let extra = &parts[nr_cpus + 1..];
        let chip = extra.first().unwrap_or(&"");
        let action = if extra.len() >= 3 {
            extra.last().unwrap_or(&"")
        } else if extra.len() == 2 {
            extra.last().unwrap_or(&"")
        } else {
            &""
        };

        irq_collector.seed_irq(irq_num, &per_cpu_counts, chip, action);
    }
}
