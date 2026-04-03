use procfast::{Procfast, ProcfastBuilder};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build procfast with just CPU and memory collection at 500ms intervals
    let procfast = ProcfastBuilder::new()
        .cpu(true)
        .mem(true)
        .net(false)
        .disk(false)
        .thermal(false)
        .interval_ms(500)
        .build()?;

    // Wait for first collection
    std::thread::sleep(Duration::from_millis(600));

    // Read CPU stats — this is just a pointer dereference, no syscall
    if let Some(cpu) = procfast.cpu() {
        let snap = cpu.snapshot();
        println!("CPU snapshot (ts={}ns):", snap.timestamp_ns);
        println!("  Online CPUs: {}", snap.nr_cpus);
        println!("  Total user:   {} ns", snap.total.user_ns);
        println!("  Total system: {} ns", snap.total.system_ns);
        println!("  Total idle:   {} ns", snap.total.idle_ns);

        // Per-CPU breakdown
        for i in 0..snap.nr_cpus.min(4) as usize {
            let c = &snap.per_cpu[i];
            println!(
                "  CPU{}: user={} sys={} idle={}",
                i, c.user_ns, c.system_ns, c.idle_ns
            );
        }
        if snap.nr_cpus > 4 {
            println!("  ... and {} more CPUs", snap.nr_cpus - 4);
        }
    }

    // Read memory stats
    if let Some(mem) = procfast.mem() {
        let snap = mem.snapshot();
        println!("\nMemory snapshot (ts={}ns):", snap.timestamp_ns);
        println!("  Total:     {} MiB", snap.total_bytes / (1 << 20));
        println!("  Free:      {} MiB", snap.free_bytes / (1 << 20));
        println!("  Available: {} MiB", snap.available_bytes / (1 << 20));
        println!("  Cached:    {} MiB", snap.cached_bytes / (1 << 20));
    }

    Ok(())
}
