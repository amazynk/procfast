use std::fs;
use std::time::{Duration, Instant};

fn bench_proc(path: &str, n: usize) -> Duration {
    let start = Instant::now();
    for _ in 0..n {
        let data = fs::read_to_string(path).unwrap();
        std::hint::black_box(&data);
    }
    start.elapsed()
}

fn bench_proc_pid_all(n: usize) -> (Duration, usize) {
    let pids: Vec<_> = fs::read_dir("/proc")
        .unwrap()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .collect();
    let start = Instant::now();
    for _ in 0..n {
        for pid in &pids {
            let _ = fs::read_to_string(format!("/proc/{pid}/stat"));
        }
    }
    (start.elapsed(), pids.len())
}

fn bench_proc_fd_all(n: usize) -> (Duration, usize) {
    let pids: Vec<_> = fs::read_dir("/proc")
        .unwrap()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .collect();
    let mut total_fds = 0usize;
    let start = Instant::now();
    for _ in 0..n {
        for pid in &pids {
            let fd_dir = format!("/proc/{pid}/fd");
            if let Ok(entries) = fs::read_dir(&fd_dir) {
                for entry in entries.flatten() {
                    let _ = fs::read_link(entry.path());
                    total_fds += 1;
                }
            }
        }
    }
    let fds_per_iter = if n > 0 { total_fds / n } else { 0 };
    (start.elapsed(), fds_per_iter)
}

fn bench_proc_sock(n: usize) -> Duration {
    let start = Instant::now();
    for _ in 0..n {
        let _ = fs::read_to_string("/proc/net/tcp");
        let _ = fs::read_to_string("/proc/net/udp");
        let _ = fs::read_to_string("/proc/net/unix");
    }
    start.elapsed()
}

fn bench<F: Fn()>(f: F, n: usize) -> Duration {
    let start = Instant::now();
    for _ in 0..n {
        f();
        std::hint::black_box(());
    }
    start.elapsed()
}

fn report(label: &str, d: Duration, n: usize) {
    let us = d.as_nanos() as f64 / n as f64 / 1000.0;
    println!("  {label:<20} {:>8.2} us/read  ({:.1} ms total)", us, d.as_millis());
}

fn speedup(label: &str, proc_d: Duration, procfast_d: Option<Duration>) {
    if let Some(kd) = procfast_d {
        let s = proc_d.as_nanos() as f64 / kd.as_nanos().max(1) as f64;
        println!("  {label:<20} {:>6.0}x faster", s);
    } else {
        println!("  {label:<20}    n/a");
    }
}

const ALL: &[&str] = &["cpu", "mem", "net", "disk", "irq", "thermal", "proc", "fd", "sock"];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut parts: Vec<String> = Vec::new();
    let mut iterations: usize = 10_000;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-n" | "--iterations" => {
                i += 1;
                iterations = args.get(i).and_then(|s| s.parse().ok()).unwrap_or_else(|| {
                    eprintln!("error: -n requires a number");
                    std::process::exit(1);
                });
            }
            "-h" | "--help" => {
                println!("procfast-bench — benchmark procfast vs /proc");
                println!();
                println!("USAGE:");
                println!("  procfast-bench [OPTIONS] [PARTS...]");
                println!();
                println!("PARTS (default: all):");
                println!("  cpu mem net disk irq thermal proc fd sock");
                println!();
                println!("OPTIONS:");
                println!("  -n, --iterations N   Number of iterations (default: 10000)");
                println!();
                println!("EXAMPLES:");
                println!("  procfast-bench                    # benchmark everything, 10k iterations");
                println!("  procfast-bench cpu mem             # only CPU and memory");
                println!("  procfast-bench -n 100000 cpu       # 100k iterations, CPU only");
                println!("  procfast-bench -n 1000 proc        # 1k iterations, process stats");
                return;
            }
            s => parts.push(s.to_string()),
        }
        i += 1;
    }

    if parts.is_empty() {
        parts = ALL.iter().map(|s| s.to_string()).collect();
    }

    let want = |name: &str| parts.iter().any(|p| p == name);

    println!("procfast benchmark: {iterations} iterations\n");

    // /proc baselines
    println!("=== /proc reads ===");
    let mut proc_cpu = None;
    let mut proc_mem = None;
    let mut proc_net = None;
    let mut proc_disk = None;
    let mut proc_irq = None;
    let mut proc_thermal = None;
    let mut proc_pid_time = None;
    let mut _proc_pid_count = 0;
    let mut proc_fd_time = None;
    let mut _proc_fd_count = 0;
    let mut proc_fd_iters = 0;
    let mut proc_sock = None;

    if want("cpu") {
        let d = bench_proc("/proc/stat", iterations);
        report("/proc/stat", d, iterations);
        proc_cpu = Some(d);
    }
    if want("mem") {
        let d = bench_proc("/proc/meminfo", iterations);
        report("/proc/meminfo", d, iterations);
        proc_mem = Some(d);
    }
    if want("net") {
        let d = bench_proc("/proc/net/dev", iterations);
        report("/proc/net/dev", d, iterations);
        proc_net = Some(d);
    }
    if want("disk") {
        let d = bench_proc("/proc/diskstats", iterations);
        report("/proc/diskstats", d, iterations);
        proc_disk = Some(d);
    }
    if want("irq") {
        let d = bench_proc("/proc/interrupts", iterations);
        report("/proc/interrupts", d, iterations);
        proc_irq = Some(d);
    }
    if want("thermal") {
        if std::path::Path::new("/sys/class/thermal/thermal_zone0/temp").exists() {
            let d = bench_proc("/sys/class/thermal/thermal_zone0/temp", iterations);
            report("thermal_zone0/temp", d, iterations);
            proc_thermal = Some(d);
        } else {
            println!("  thermal              (no zones)");
        }
    }
    if want("proc") {
        let proc_iters = iterations.min(100); // /proc/[pid]/stat is slow; cap iterations
        let (d, n) = bench_proc_pid_all(proc_iters);
        let total_reads = n * proc_iters;
        let us = d.as_nanos() as f64 / total_reads as f64 / 1000.0;
        println!("  {:<20} {:>8.2} us/read  ({:.1} ms, {} procs x {})",
            "/proc/[pid]/stat", us, d.as_millis(), n, proc_iters);
        proc_pid_time = Some(d);
        _proc_pid_count = n;
    }
    if want("fd") {
        let fd_iters = iterations.min(10); // readlink on every fd is very slow; cap iterations
        let (d, n) = bench_proc_fd_all(fd_iters);
        let us_per_scan = d.as_nanos() as f64 / fd_iters as f64 / 1000.0;
        println!("  {:<20} {:>8.0} us/scan  ({:.1} ms, {} fds x {})",
            "/proc/[pid]/fd/*", us_per_scan, d.as_millis(), n, fd_iters);
        proc_fd_time = Some(d);
        _proc_fd_count = n;
        proc_fd_iters = fd_iters;
    }
    if want("sock") {
        let d = bench_proc_sock(iterations);
        let us = d.as_nanos() as f64 / iterations as f64 / 1000.0;
        println!("  {:<20} {:>8.2} us/read  ({:.1} ms total)",
            "/proc/net/tcp+udp+unix", us, d.as_millis());
        proc_sock = Some(d);
    }

    // procfast reads
    println!("\n=== procfast reads ===");

    let need_fd = want("fd") || want("sock");
    let procfast = match procfast::ProcfastBuilder::new().fd(need_fd).build() {
        Ok(k) => k,
        Err(e) => {
            println!("  (skipped — BPF unavailable: {e})");
            println!("  Run with CAP_BPF + CAP_PERFMON.");
            return;
        }
    };

    std::thread::sleep(Duration::from_millis(200));

    let mut kd_cpu = None;
    let mut kd_mem = None;
    let mut kd_net = None;
    let mut kd_disk = None;
    let mut kd_irq = None;
    let mut kd_thermal = None;
    let mut kd_proc = None;
    let mut procfast_proc_n = 0;
    let mut kd_fd = None;
    let mut procfast_fd_n = 0;
    let mut kd_sock = None;

    if want("cpu") {
        if let Some(c) = procfast.cpu() {
            let d = bench(|| { c.snapshot(); }, iterations);
            report("procfast cpu", d, iterations);
            kd_cpu = Some(d);
        } else { println!("  procfast cpu             (not loaded)"); }
    }
    if want("mem") {
        if let Some(c) = procfast.mem() {
            let d = bench(|| { c.snapshot(); }, iterations);
            report("procfast mem", d, iterations);
            kd_mem = Some(d);
        } else { println!("  procfast mem             (not loaded)"); }
    }
    if want("net") {
        if let Some(c) = procfast.net() {
            let d = bench(|| { c.snapshot(); }, iterations);
            report("procfast net", d, iterations);
            kd_net = Some(d);
        } else { println!("  procfast net             (not loaded)"); }
    }
    if want("disk") {
        if let Some(c) = procfast.disk() {
            let d = bench(|| { c.snapshot(); }, iterations);
            report("procfast disk", d, iterations);
            kd_disk = Some(d);
        } else { println!("  procfast disk            (not loaded)"); }
    }
    if want("irq") {
        if let Some(c) = procfast.irq() {
            let d = bench(|| { c.snapshot(); }, iterations);
            report("procfast irq", d, iterations);
            kd_irq = Some(d);
        } else { println!("  procfast irq             (not loaded)"); }
    }
    if want("thermal") {
        if let Some(c) = procfast.thermal() {
            let d = bench(|| { c.snapshot(); }, iterations);
            report("procfast thermal", d, iterations);
            kd_thermal = Some(d);
        } else { println!("  procfast thermal         (not loaded)"); }
    }
    if want("proc") {
        if let Some(c) = procfast.proc_stats() {
            procfast_proc_n = c.header().nr_procs.max(1) as usize;
            let d = bench(|| { let _ = c.snapshot_all(); }, iterations);
            report("procfast proc (all)", d, iterations);
            kd_proc = Some(d);
        } else { println!("  procfast proc            (not loaded)"); }
    }
    if want("fd") {
        if let Some(c) = procfast.fd() {
            let snap = c.snapshot_all().unwrap_or_default();
            procfast_fd_n = snap.len();
            let d = bench(|| { let _ = c.snapshot_all(); }, iterations);
            report("procfast fd (all)", d, iterations);
            kd_fd = Some(d);
        } else { println!("  procfast fd              (not loaded — run with fd(true))"); }
    }
    if want("sock") {
        if let Some(c) = procfast.sock() {
            let d = bench(|| { let _ = c.snapshot_all(); }, iterations);
            report("procfast sock (all)", d, iterations);
            kd_sock = Some(d);
        } else { println!("  procfast sock            (not loaded — run with fd(true))"); }
    }

    // Speedup summary
    println!("\n=== Speedup ===");

    if let Some(pd) = proc_cpu { speedup("CPU", pd, kd_cpu); }
    if let Some(pd) = proc_mem { speedup("Memory", pd, kd_mem); }
    if let Some(pd) = proc_net { speedup("Network", pd, kd_net); }
    if let Some(pd) = proc_disk { speedup("Disk", pd, kd_disk); }
    if let Some(pd) = proc_irq { speedup("Interrupts", pd, kd_irq); }
    if let Some(pd) = proc_thermal { speedup("Thermal", pd, kd_thermal); }
    if let (Some(pt), Some(kd)) = (proc_pid_time, kd_proc) {
        // proc_pid_time = time for (proc_pid_count * min(iterations,100)) reads
        // kd = time for iterations snapshot_all calls
        let proc_per_scan = pt.as_nanos() as f64 / iterations.min(100) as f64;
        let procfast_per_scan = kd.as_nanos() as f64 / iterations as f64;
        let s = proc_per_scan / procfast_per_scan.max(1.0);
        println!("  {:<20} {:>6.0}x faster ({} processes)", "Processes", s, procfast_proc_n);
    }
    if let (Some(pt), Some(kd)) = (proc_fd_time, kd_fd) {
        let proc_per_scan = pt.as_nanos() as f64 / proc_fd_iters.max(1) as f64;
        let procfast_per_scan = kd.as_nanos() as f64 / iterations as f64;
        let s = proc_per_scan / procfast_per_scan.max(1.0);
        println!("  {:<20} {:>6.0}x faster ({} fds)", "File descriptors", s, procfast_fd_n);
    }
    if let Some(pd) = proc_sock { speedup("Sockets", pd, kd_sock); }
}
