use bytemuck::Zeroable;
use procfast_common::{IrqData, IrqStats, MAX_IRQS};
use libbpf_rs::{MapCore, MapHandle};


/// Reader for interrupt statistics.
///
/// Reads directly from the percpu hash map (live counts) and metadata
/// hash map (chip/action names). No mmapable snapshot — data is always
/// real-time.
pub struct IrqCollector {
    percpu_map: MapHandle,
    metadata_map: MapHandle,
}

impl IrqCollector {
    pub(crate) fn new(percpu_map: MapHandle, metadata_map: MapHandle) -> Self {
        Self { percpu_map, metadata_map }
    }

    /// Build an IrqData snapshot by reading the percpu and metadata maps.
    /// This is live data — no staleness from periodic snapshots.
    pub fn snapshot(&self) -> IrqData {
        let mut data: IrqData = Zeroable::zeroed();
        let mut idx = 0usize;

        for key in self.percpu_map.keys() {
            if idx >= MAX_IRQS { break; }
            if key.len() < 4 { continue; }

            let irq_num = u32::from_ne_bytes(key[..4].try_into().unwrap());

            // Sum per-CPU counts for total
            let total = self.percpu_counts(irq_num)
                .map(|counts| counts.iter().sum::<u64>())
                .unwrap_or(0);

            let mut entry: IrqStats = Zeroable::zeroed();
            entry.irq = irq_num;
            entry.total_count = total;

            // Read metadata (chip + action names)
            if let Ok(Some(meta)) = self.metadata_map.lookup(&key, libbpf_rs::MapFlags::ANY) {
                if meta.len() >= 96 {
                    let chip_end = meta[..32].iter().position(|&b| b == 0).unwrap_or(32);
                    entry.chip_name[..chip_end].copy_from_slice(&meta[..chip_end]);
                    let action_end = meta[32..96].iter().position(|&b| b == 0).unwrap_or(64);
                    entry.action_name[..action_end].copy_from_slice(&meta[32..32 + action_end]);
                }
            }

            data.irqs[idx] = entry;
            idx += 1;
        }

        data.nr_irqs = idx as u32;
        data.timestamp_ns = 0; // no BPF timestamp available without mmap
        data
    }

    /// Read per-CPU counts for a specific IRQ number.
    pub fn percpu_counts(&self, irq: u32) -> Option<Vec<u64>> {
        let key = irq.to_ne_bytes();
        let values = self.percpu_map.lookup_percpu(&key, libbpf_rs::MapFlags::ANY).ok()??;
        Some(
            values
                .iter()
                .map(|v| {
                    if v.len() >= 8 {
                        u64::from_ne_bytes(v[..8].try_into().unwrap())
                    } else {
                        0
                    }
                })
                .collect()
        )
    }

    /// Number of CPUs tracked by the percpu map.
    pub fn nr_cpus(&self) -> usize {
        for key in self.percpu_map.keys() {
            if key.len() >= 4 {
                let irq = u32::from_ne_bytes(key[..4].try_into().unwrap());
                if let Some(counts) = self.percpu_counts(irq) {
                    return counts.len();
                }
            }
        }
        num_possible_cpus()
    }

    /// Seed an IRQ entry from /proc/interrupts data at startup.
    pub fn seed_irq(&self, irq: u32, per_cpu: &[u64], chip: &str, action: &str) {
        let key = irq.to_ne_bytes();
        let nr_cpus = num_possible_cpus();

        let values: Vec<Vec<u8>> = (0..nr_cpus)
            .map(|i| {
                let count = per_cpu.get(i).copied().unwrap_or(0);
                count.to_ne_bytes().to_vec()
            })
            .collect();
        let _ = self.percpu_map.update_percpu(&key, &values, libbpf_rs::MapFlags::NO_EXIST);

        let mut meta = [0u8; 96];
        let chip_bytes = chip.as_bytes();
        let action_bytes = action.as_bytes();
        let chip_len = chip_bytes.len().min(31);
        let action_len = action_bytes.len().min(63);
        meta[..chip_len].copy_from_slice(&chip_bytes[..chip_len]);
        meta[32..32 + action_len].copy_from_slice(&action_bytes[..action_len]);
        let _ = self.metadata_map.update(&key, &meta, libbpf_rs::MapFlags::NO_EXIST);
    }
}

pub const SOFTIRQ_BASE: u32 = 0x80000000;

pub fn is_softirq(irq: u32) -> bool {
    irq & SOFTIRQ_BASE != 0
}

pub fn softirq_vec(irq: u32) -> Option<u32> {
    if is_softirq(irq) {
        Some(irq & !SOFTIRQ_BASE)
    } else {
        None
    }
}

fn num_possible_cpus() -> usize {
    std::fs::read_to_string("/sys/devices/system/cpu/possible")
        .ok()
        .and_then(|s| {
            let last = s.trim().rsplit('-').next()?;
            last.parse::<usize>().ok().map(|n| n + 1)
        })
        .unwrap_or(16)
}
