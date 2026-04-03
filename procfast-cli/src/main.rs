//! procfast CLI — query system metrics from procfastd.
//!
//! No root or capabilities required. Connects to pinned BPF maps
//! published by procfastd.
//!
//! Usage:
//!   procfast cpu               # CPU stats (like /proc/stat)
//!   procfast mem               # memory stats (like /proc/meminfo)
//!   procfast net               # network stats (like /proc/net/dev)
//!   procfast disk              # disk I/O stats (like /proc/diskstats)
//!   procfast irq               # interrupt counts (like /proc/interrupts)
//!   procfast thermal           # thermal zones (like /sys/class/thermal)
//!   procfast fd                # open file descriptors (like lsof)
//!   procfast fd <pid>          # open files for one process
//!   procfast ps                # process list (like ps aux)
//!   procfast top               # live process view (like top)
//!   procfast pid <pid>         # single process details
//!   procfast status            # check if procfastd is running
//!   procfast json <metric>     # output as JSON for scripting (cpu, mem, net, disk, irq, thermal, fd, ps)

use procfast_client::{ProcfastClient, ClientError};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        std::process::exit(1);
    }

    let client = match ProcfastClient::connect_default() {
        Ok(c) => c,
        Err(ClientError::NotRunning(_)) => {
            eprintln!("error: procfastd is not running.");
            eprintln!("Start it with: sudo procfastd");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };

    match args[1].as_str() {
        "cpu" => cmd_cpu(&client),
        "mem" => cmd_mem(&client),
        "net" => cmd_net(&client),
        "disk" => cmd_disk(&client),
        "irq" => cmd_irq(&client),
        "thermal" => cmd_thermal(&client),
        "fd" => {
            let pid = if args.len() >= 3 {
                Some(args[2].parse::<u32>().unwrap_or_else(|_| {
                    eprintln!("error: invalid PID");
                    std::process::exit(1);
                }))
            } else {
                None
            };
            cmd_fd(&client, pid);
        }
        "sock" => cmd_sock(&client),
        "cgroup" => cmd_cgroup(&client),
        "ps" => cmd_ps(&client),
        "top" => {
            let delay = if args.len() >= 3 {
                parse_delay(&args[2])
            } else {
                std::time::Duration::from_secs(1)
            };
            cmd_top(&client, delay);
        }
        "pid" => {
            if args.len() < 3 {
                eprintln!("usage: procfast pid <pid>");
                std::process::exit(1);
            }
            let pid: u32 = args[2].parse().unwrap_or_else(|_| {
                eprintln!("error: invalid PID");
                std::process::exit(1);
            });
            cmd_pid(&client, pid);
        }
        "status" => cmd_status(&client),
        "json" => {
            if args.len() < 3 {
                eprintln!("usage: procfast json <cpu|mem|net|disk|irq|thermal|fd|ps|status>");
                std::process::exit(1);
            }
            cmd_json(&client, &args[2]);
        }
        "--help" | "-h" | "help" => print_usage(),
        other => {
            eprintln!("error: unknown command '{other}'");
            print_usage();
            std::process::exit(1);
        }
    }
}

fn print_usage() {
    println!("procfast — fast system metrics via eBPF");
    println!();
    println!("USAGE:");
    println!("  procfast <command> [args]");
    println!();
    println!("COMMANDS:");
    println!("  cpu             CPU time breakdown per core");
    println!("  mem             Memory usage summary");
    println!("  net             Network device statistics");
    println!("  disk            Block device I/O statistics");
    println!("  irq             Interrupt counts");
    println!("  thermal         Thermal zone temperatures");
    println!("  fd [pid]        Open file descriptors (like lsof)");
    println!("  sock            TCP/UDP sockets (like ss)");
    println!("  cgroup          Cgroup CPU and memory stats");
    println!("  ps              Process list (snapshot)");
    println!("  top [delay]     Live process view (delay: 1, 0.5, 200ms)");
    println!("  pid <pid>       Single process details");
    println!("  status          Check if procfastd is running");
    println!("  json <cmd>      JSON output (cpu, mem, net, disk, irq, thermal, ps, status)");
    println!();
    println!("Requires procfastd to be running (sudo procfastd).");
    println!("Queries require root or sudo (BPF map access).");
}

fn cmd_cpu(client: &ProcfastClient) {
    let cpu = client.cpu().unwrap_or_else(|e| die(&e));
    let snap = cpu.snapshot();

    println!("CPU Statistics ({} CPUs)", snap.nr_cpus);
    println!("{:>6} {:>12} {:>12} {:>12} {:>12} {:>12} {:>12}",
        "CPU", "user%", "sys%", "idle%", "iowait%", "irq%", "softirq%");
    println!("{}", "-".repeat(78));

    print_cpu_row("total", &snap.total);

    for i in 0..snap.nr_cpus as usize {
        if i >= procfast_common::MAX_CPUS { break; }
        print_cpu_row(&format!("{i}"), &snap.per_cpu[i]);
    }
}

fn print_cpu_row(label: &str, s: &procfast_common::CpuStats) {
    let total = s.user_ns + s.nice_ns + s.system_ns + s.idle_ns
        + s.iowait_ns + s.irq_ns + s.softirq_ns + s.steal_ns;
    if total == 0 { return; }
    let t = total as f64;
    println!("{:>6} {:>11.1}% {:>11.1}% {:>11.1}% {:>11.1}% {:>11.1}% {:>11.1}%",
        label,
        (s.user_ns + s.nice_ns) as f64 / t * 100.0,
        s.system_ns as f64 / t * 100.0,
        s.idle_ns as f64 / t * 100.0,
        s.iowait_ns as f64 / t * 100.0,
        s.irq_ns as f64 / t * 100.0,
        s.softirq_ns as f64 / t * 100.0,
    );
}

fn cmd_mem(client: &ProcfastClient) {
    let mem = client.mem().unwrap_or_else(|e| die(&e));
    let snap = mem.snapshot();
    let mb = |b: u64| format!("{:>10.1} MiB", b as f64 / (1024.0 * 1024.0));
    let mb_or_na = |b: u64| {
        if b > 0 { mb(b) } else { "       n/a".to_string() }
    };

    // Used = Total - Free - Buffers (approximation matching htop)
    let used = snap.total_bytes
        .saturating_sub(snap.free_bytes)
        .saturating_sub(snap.buffers_bytes);

    println!("Memory Statistics");
    println!("  Total:         {}", mb(snap.total_bytes));
    println!("  Used:          {}", mb(used));
    println!("  Free:          {}", mb(snap.free_bytes));
    println!("  Available:     {}", mb_or_na(snap.available_bytes));
    println!("  Shared:        {}", mb_or_na(snap.shmem_bytes));
    println!("  Buffers:       {}", mb(snap.buffers_bytes));
    println!("  Cached:        {}", mb_or_na(snap.cached_bytes));
    println!("  Swap total:    {}", mb(snap.swap_total_bytes));
    println!("  Swap free:     {}", mb(snap.swap_free_bytes));
}

fn cmd_net(client: &ProcfastClient) {
    let net = client.net().unwrap_or_else(|e| die(&e));
    let snap = net.snapshot();

    println!("{:<16} {:>14} {:>14} {:>12} {:>12}",
        "Interface", "RX bytes", "TX bytes", "RX pkts", "TX pkts");
    println!("{}", "-".repeat(70));

    for i in 0..snap.nr_devs as usize {
        if i >= procfast_common::MAX_NET_DEVS { break; }
        let dev = &snap.devs[i];
        let name = bytes_to_str(&dev.name);
        println!("{:<16} {:>14} {:>14} {:>12} {:>12}",
            name, dev.rx_bytes, dev.tx_bytes, dev.rx_packets, dev.tx_packets);
    }
}

fn cmd_disk(client: &ProcfastClient) {
    let disk = client.disk().unwrap_or_else(|e| die(&e));
    let snap = disk.snapshot();

    println!("{:<16} {:>10} {:>10} {:>14} {:>14}",
        "Device", "Read IOs", "Write IOs", "Read sect", "Write sect");
    println!("{}", "-".repeat(66));

    for i in 0..snap.nr_disks as usize {
        if i >= procfast_common::MAX_DISKS { break; }
        let d = &snap.disks[i];
        let name = bytes_to_str(&d.name);
        println!("{:<16} {:>10} {:>10} {:>14} {:>14}",
            name, d.read_ios, d.write_ios, d.read_sectors, d.write_sectors);
    }
}

fn cmd_irq(client: &ProcfastClient) {
    let reader = client.irq().unwrap_or_else(|e| die(&e));
    let snap = reader.snapshot();

    if snap.nr_irqs == 0 {
        println!("No interrupt data yet.");
        return;
    }

    // Detect number of CPUs from first IRQ's percpu data
    let nr_cpus = snap.irqs.iter()
        .take(snap.nr_irqs as usize)
        .find_map(|irq| reader.percpu_counts(irq.irq))
        .map(|v| v.len())
        .unwrap_or(0);

    // Collect entries and sort: hardirqs by number, then softirqs
    let mut hw_irqs: Vec<_> = (0..snap.nr_irqs as usize)
        .filter(|&i| i < procfast_common::MAX_IRQS && snap.irqs[i].irq & 0x80000000 == 0)
        .collect();
    hw_irqs.sort_by_key(|&i| snap.irqs[i].irq);

    let mut sw_irqs: Vec<_> = (0..snap.nr_irqs as usize)
        .filter(|&i| i < procfast_common::MAX_IRQS && snap.irqs[i].irq & 0x80000000 != 0)
        .collect();
    sw_irqs.sort_by_key(|&i| snap.irqs[i].irq);

    // Print header with CPU columns
    print!("{:>8}", "");
    for cpu in 0..nr_cpus {
        print!("{:>11}", format!("CPU{cpu}"));
    }
    println!();

    // Print hardware IRQs
    for &i in &hw_irqs {
        let irq = &snap.irqs[i];
        let chip = bytes_to_str(&irq.chip_name);
        let action = bytes_to_str(&irq.action_name);

        print!("{:>8}:", irq.irq);
        if let Some(counts) = reader.percpu_counts(irq.irq) {
            for c in &counts {
                print!("{:>11}", c);
            }
        }
        println!("   {:<24}{}", chip, action);
    }

    // Print softirqs
    let softirq_names = ["HI", "TIMER", "NET_TX", "NET_RX", "BLOCK",
                          "IRQ_POLL", "TASKLET", "SCHED", "HRTIMER", "RCU"];
    for &i in &sw_irqs {
        let irq = &snap.irqs[i];
        let vec = irq.irq & !0x80000000;
        let label = softirq_names.get(vec as usize).unwrap_or(&"?");

        print!("{:>8}:", label);
        if let Some(counts) = reader.percpu_counts(irq.irq) {
            for c in &counts {
                print!("{:>11}", c);
            }
        }
        println!();
    }
}

fn cmd_thermal(client: &ProcfastClient) {
    let thermal = client.thermal().unwrap_or_else(|e| die(&e));
    let snap = thermal.snapshot();

    if snap.nr_zones == 0 {
        println!("No thermal data yet.");
        println!("Data appears when the kernel or a tool reads thermal zones.");
        println!("Try: cat /sys/class/thermal/thermal_zone*/temp");
        return;
    }

    println!("{:<20} {:>10}",
        "Zone", "Temp");
    println!("{}", "-".repeat(32));

    for i in 0..snap.nr_zones as usize {
        if i >= procfast_common::MAX_THERMAL_ZONES { break; }
        let z = &snap.zones[i];
        let name = bytes_to_str(&z.zone_type);
        let temp_c = z.temp_millicelsius as f64 / 1000.0;
        println!("{:<20} {:>8.1}\u{00b0}C", name, temp_c);
    }
}

fn format_ipv4(addr: u32) -> String {
    let b = addr.to_ne_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn tcp_state_str(state: u8) -> &'static str {
    match state {
        1 => "ESTABLISHED",
        2 => "SYN_SENT",
        3 => "SYN_RECV",
        4 => "FIN_WAIT1",
        5 => "FIN_WAIT2",
        6 => "TIME_WAIT",
        7 => "CLOSE",
        8 => "CLOSE_WAIT",
        9 => "LAST_ACK",
        10 => "LISTEN",
        11 => "CLOSING",
        _ => "UNKNOWN",
    }
}

fn cmd_sock(client: &ProcfastClient) {
    let reader = client.sock().unwrap_or_else(|e| die(&e));
    let socks = reader.snapshot_all();

    if socks.is_empty() {
        println!("No socket data. Run procfastd with --fd to enable socket tracking.");
        return;
    }

    // Build inode → (pid, process name) map from fd entries.
    // FdInfo now has an inode field populated by BPF — no /proc reads needed.
    let mut inode_to_proc: std::collections::HashMap<u64, (u32, String)> = std::collections::HashMap::new();
    if let (Ok(fd_reader), Ok(proc_reader)) = (client.fd(), client.proc_stats()) {
        let proc_names: std::collections::HashMap<u32, String> = proc_reader.snapshot_all()
            .unwrap_or_default()
            .into_iter()
            .map(|p| (p.pid, bytes_to_str(&p.comm).to_string()))
            .collect();

        if let Ok(fds) = fd_reader.snapshot_all() {
            for fd in &fds {
                if fd.inode > 0 {
                    let name = proc_names.get(&fd.pid).cloned().unwrap_or_default();
                    inode_to_proc.entry(fd.inode).or_insert((fd.pid, name));
                }
            }
        }
    }

    println!("{:<6} {:<12} {:<24} {:<24} {:>7} {:<16} {:<}",
        "Proto", "State", "Local Address", "Remote Address", "PID", "COMMAND", "Inode");
    println!("{}", "-".repeat(105));

    let mut sorted = socks;
    sorted.sort_by_key(|s| (s.protocol, s.state));

    for s in &sorted {
        let proto = match s.protocol {
            6 => "tcp",
            17 => "udp",
            _ => "???",
        };

        let (local, remote) = if s.family == 2 {
            (
                format!("{}:{}", format_ipv4(s.local_addr4), s.local_port),
                format!("{}:{}", format_ipv4(s.remote_addr4), s.remote_port),
            )
        } else if s.family == 10 {
            (
                format!("[::]:{}", s.local_port),
                format!("[::]:{}", s.remote_port),
            )
        } else {
            ("?".to_string(), "?".to_string())
        };

        let state = if s.protocol == 6 {
            tcp_state_str(s.state)
        } else {
            ""
        };

        let proto_str = if s.family == 10 {
            format!("{}6", proto)
        } else {
            proto.to_string()
        };

        println!("{:<6} {:<12} {:<24} {:<24} {:>7} {:<16} {}",
            proto_str, state, local, remote,
            inode_to_proc.get(&s.inode).map(|(pid, _)| *pid as i64).unwrap_or(-1),
            inode_to_proc.get(&s.inode).map(|(_, name)| name.as_str()).unwrap_or("-"),
            s.inode);
    }
}

fn cmd_cgroup(client: &ProcfastClient) {
    let reader = client.cgroup().unwrap_or_else(|e| die(&e));
    let mut cgroups = reader.snapshot_all();

    if cgroups.is_empty() {
        println!("No cgroup data. Run procfastd with --cgroup to enable cgroup tracking.");
        return;
    }

    // Build path map from id/parent_id hierarchy
    let name_map: std::collections::HashMap<u64, String> = cgroups.iter()
        .map(|cg| (cg.id, bytes_to_str(&cg.name).to_string()))
        .collect();
    let parent_map: std::collections::HashMap<u64, u64> = cgroups.iter()
        .map(|cg| (cg.id, cg.parent_id))
        .collect();

    let build_path = |id: u64| -> String {
        let mut parts = Vec::new();
        let mut cur = id;
        for _ in 0..10 {
            if let Some(name) = name_map.get(&cur) {
                if name.is_empty() { break; }
                parts.push(name.clone());
            } else {
                break;
            }
            if let Some(&pid) = parent_map.get(&cur) {
                if pid == 0 || pid == cur { break; }
                cur = pid;
            } else {
                break;
            }
        }
        parts.reverse();
        if parts.is_empty() { "/".to_string() } else { format!("/{}", parts.join("/")) }
    };

    // Aggregate per-process RSS/shared by cgroup_id from proc stats.
    // This gives accurate memory breakdown since per-process mm counters
    // are always up to date (unlike memcg vmstats which need rstat flush).
    let mut cg_rss: std::collections::HashMap<u64, (u64, u64)> = std::collections::HashMap::new();
    if let Ok(proc_reader) = client.proc_stats() {
        if let Ok(procs) = proc_reader.snapshot_all() {
            for p in &procs {
                if p.cgroup_id > 0 {
                    let entry = cg_rss.entry(p.cgroup_id).or_insert((0, 0));
                    entry.0 += p.rss_bytes;    // total RSS (anon + file)
                    entry.1 += p.shared_bytes;  // file-backed (cache)
                }
            }
        }
    }

    // Sort by memory usage descending
    cgroups.sort_by(|a, b| b.memory_current.cmp(&a.memory_current));

    println!("{:<50} {:>10} {:>10} {:>10} {:>8} {:>8} {:>6}",
        "Path", "Memory", "Cache", "RSS", "CPU", "PIDs", "Throt");
    println!("{}", "-".repeat(108));

    for cg in &cgroups {
        let full_path = build_path(cg.id);
        let path_str = if full_path.len() > 48 {
            &full_path[full_path.len()-48..]
        } else {
            full_path.as_str()
        };

        let mem = if cg.memory_current > 0 { format_bytes(cg.memory_current) } else { "-".into() };
        // Use per-process aggregated RSS (always accurate) over BPF vmstats
        let (proc_rss, proc_shared) = cg_rss.get(&cg.id).copied().unwrap_or((0, 0));
        let cache = if proc_shared > 0 { format_bytes(proc_shared) } else { "-".into() };
        let rss = if proc_rss > proc_shared { format_bytes(proc_rss - proc_shared) } else if proc_rss > 0 { format_bytes(proc_rss) } else { "-".into() };
        let cpu = format_duration_ns(cg.cpu_usage_ns);
        let pids = if cg.nr_pids > 0 { format!("{}", cg.nr_pids) } else { "-".into() };
        let throt = if cg.nr_throttled > 0 { format!("{}", cg.nr_throttled) } else { "-".into() };

        println!("{:<50} {:>10} {:>10} {:>10} {:>8} {:>8} {:>6}",
            path_str, mem, cache, rss, cpu, pids, throt);
    }

    // Summary
    println!();
    let total = cgroups.len();
    let mem_limited = cgroups.iter().filter(|c| c.memory_limit > 0).count();
    let cpu_limited = cgroups.iter().filter(|c| c.cpu_quota_us > 0).count();
    let throttled = cgroups.iter().filter(|c| c.nr_throttled > 0).count();
    let frozen = cgroups.iter().filter(|c| c.frozen > 0).count();
    let has_psi = cgroups.iter().any(|c| c.psi_cpu_some > 0 || c.psi_mem_some > 0 || c.psi_io_some > 0);

    println!("{total} cgroups: {mem_limited} memory-limited, {cpu_limited} cpu-limited, {throttled} throttled{}",
        if frozen > 0 { format!(", {frozen} frozen") } else { String::new() });

    if has_psi {
        // Show top PSI offenders
        let mut psi_sorted = cgroups.clone();
        psi_sorted.sort_by(|a, b| {
            let a_total = a.psi_cpu_some + a.psi_mem_some + a.psi_io_some;
            let b_total = b.psi_cpu_some + b.psi_mem_some + b.psi_io_some;
            b_total.cmp(&a_total)
        });
        let top_psi: Vec<_> = psi_sorted.iter()
            .filter(|c| c.psi_cpu_some > 0 || c.psi_mem_some > 0 || c.psi_io_some > 0)
            .take(5)
            .collect();

        if !top_psi.is_empty() {
            println!();
            println!("Top pressure (PSI some µs — cpu/mem/io):");
            for cg in &top_psi {
                let p = build_path(cg.id);
                let display = if p.len() > 48 { &p[p.len()-48..] } else { p.as_str() };
                println!("  {:<50} cpu:{:>12} mem:{:>12} io:{:>12}",
                    display,
                    cg.psi_cpu_some,
                    cg.psi_mem_some,
                    cg.psi_io_some);
            }
        }
    }
}

fn format_duration_ns(ns: u64) -> String {
    if ns == 0 {
        return "-".to_string();
    }
    let secs = ns / 1_000_000_000;
    if secs >= 3600 {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m{:.1}s", secs / 60, (ns % 60_000_000_000) as f64 / 1e9)
    } else {
        format!("{:.2}s", ns as f64 / 1e9)
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

fn cmd_fd(client: &ProcfastClient, pid_filter: Option<u32>) {
    let fd_reader = client.fd().unwrap_or_else(|e| die(&e));

    let mut entries = if let Some(pid) = pid_filter {
        fd_reader.list_pid(pid).unwrap_or_else(|e| {
            eprintln!("error: {e}");
            std::process::exit(1);
        })
    } else {
        fd_reader.snapshot_all().unwrap_or_else(|e| {
            eprintln!("error: {e}");
            std::process::exit(1);
        })
    };

    // Sort by pid, then by fd number
    entries.sort_by(|a, b| a.pid.cmp(&b.pid).then(a.fd.cmp(&b.fd)));

    // Try to resolve process names from the proc collector
    let proc_reader = client.proc_stats().ok();
    let proc_map: std::collections::HashMap<u32, String> = proc_reader
        .as_ref()
        .and_then(|p| p.snapshot_all().ok())
        .unwrap_or_default()
        .into_iter()
        .map(|p| (p.pid, bytes_to_str(&p.comm).to_string()))
        .collect();

    println!("{:<12} {:>7} {:>4}  {:<}", "COMMAND", "PID", "FD", "PATH");
    println!("{}", "-".repeat(72));

    for entry in &entries {
        let path = bytes_to_str(&entry.path);
        let comm = proc_map.get(&entry.pid)
            .map(|s| s.as_str())
            .unwrap_or("?");
        println!("{:<12} {:>7} {:>4}  {:<}", comm, entry.pid, entry.fd, path);
    }

    println!();
    println!("{} open file descriptors", entries.len());
}

fn cmd_ps(client: &ProcfastClient) {
    let procs = client.proc_stats().unwrap_or_else(|e| die(&e));
    let mut all = procs.snapshot_all().unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1);
    });

    // Filter out dead/zombie processes and sort by CPU time descending
    all.retain(|p| p.state < 4); // 4=zombie, 5=dead
    all.sort_by(|a, b| {
        let a_total = a.utime_ns + a.stime_ns;
        let b_total = b.utime_ns + b.stime_ns;
        b_total.cmp(&a_total)
    });

    let hdr = procs.header();
    println!("Processes: {} tracked (ts={})", hdr.nr_procs, hdr.timestamp_ns);
    println!();
    println!("{:>7} {:>7} {:1} {:>6} {:>10} {:>10} {:>8} {:>8} {:<}",
        "PID", "PPID", "S", "CPU", "RSS MiB", "VIRT MiB", "VolCSW", "InvCSW", "COMMAND");
    println!("{}", "-".repeat(80));

    for p in &all {
        let comm = bytes_to_str(&p.comm);
        let state = match p.state {
            0 => "R",
            1 => "S",
            2 => "D",
            3 => "T",
            4 => "Z",
            _ => "X",
        };
        println!("{:>7} {:>7} {:1} {:>6} {:>10.1} {:>10.1} {:>8} {:>8} {:<}",
            p.pid,
            p.ppid,
            state,
            p.last_cpu,
            p.rss_bytes as f64 / (1024.0 * 1024.0),
            p.vsize_bytes as f64 / (1024.0 * 1024.0),
            p.vol_ctxsw,
            p.invol_ctxsw,
            comm,
        );
    }
}

fn terminal_rows() -> usize {
    // Read from LINES env var, or fall back to 40
    std::env::var("LINES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(40)
}

/// Parse a delay string like "1", "0.5", "200ms", "1.5s".
/// Default unit is seconds.
fn parse_delay(s: &str) -> std::time::Duration {
    if let Some(ms_str) = s.strip_suffix("ms") {
        let ms: f64 = ms_str.parse().unwrap_or_else(|_| {
            eprintln!("error: invalid delay '{s}' (examples: 1, 0.5, 200ms)");
            std::process::exit(1);
        });
        std::time::Duration::from_micros((ms * 1000.0) as u64)
    } else {
        let secs_str = s.strip_suffix('s').unwrap_or(s);
        let secs: f64 = secs_str.parse().unwrap_or_else(|_| {
            eprintln!("error: invalid delay '{s}' (examples: 1, 0.5, 200ms)");
            std::process::exit(1);
        });
        std::time::Duration::from_micros((secs * 1_000_000.0) as u64)
    }
}

fn cmd_top(client: &ProcfastClient, delay: std::time::Duration) {
    let procs = client.proc_stats().unwrap_or_else(|e| die(&e));
    let cpu_reader = client.cpu().unwrap_or_else(|e| die(&e));
    let mem_reader = client.mem().unwrap_or_else(|e| die(&e));

    // Take initial snapshot
    let mut prev_snap = procs.snapshot_all().unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1);
    });
    let mut prev_cpu = cpu_reader.snapshot();

    loop {
        std::thread::sleep(delay);

        let snap = match procs.snapshot_all() {
            Ok(s) => s,
            Err(_) => continue,
        };
        let cpu = cpu_reader.snapshot();
        let mem = mem_reader.snapshot();

        // Build PID -> previous stats
        let prev: std::collections::HashMap<u32, &procfast_common::ProcStats> =
            prev_snap.iter().map(|p| (p.pid, p)).collect();

        // Wall clock from CPU timestamps
        let wall_ns = if cpu.timestamp_ns > prev_cpu.timestamp_ns {
            (cpu.timestamp_ns - prev_cpu.timestamp_ns) as f64
        } else {
            1_000_000_000.0
        };

        struct ProcDelta {
            proc: procfast_common::ProcStats,
            cpu_pct: f64,
        }

        let mut deltas: Vec<ProcDelta> = snap
            .iter()
            .filter(|p| p.state < 4) // skip zombie/dead
            .map(|p| {
                let cpu_pct = if let Some(old) = prev.get(&p.pid) {
                    let delta = p.cpu_runtime_ns.saturating_sub(old.cpu_runtime_ns) as f64;
                    if wall_ns > 0.0 { (delta / wall_ns) * 100.0 } else { 0.0 }
                } else {
                    0.0
                };
                ProcDelta { proc: *p, cpu_pct }
            })
            .collect();

        deltas.sort_by(|a, b| b.cpu_pct.partial_cmp(&a.cpu_pct).unwrap());

        // Overall CPU busy %
        let cpu_busy = {
            let sum = |c: &procfast_common::CpuStats| {
                c.user_ns + c.system_ns + c.idle_ns
                    + c.iowait_ns + c.irq_ns + c.softirq_ns
            };
            let total_delta = (sum(&cpu.total) - sum(&prev_cpu.total)) as f64;
            let idle_delta = (cpu.total.idle_ns - prev_cpu.total.idle_ns) as f64;
            if total_delta > 0.0 { (1.0 - idle_delta / total_delta) * 100.0 } else { 0.0 }
        };

        let total_mem = mem.total_bytes as f64 / (1024.0 * 1024.0);
        let used_mem = (mem.total_bytes - mem.free_bytes) as f64 / (1024.0 * 1024.0);

        // Clear screen and move cursor to top
        print!("\x1b[2J\x1b[H");

        println!("procfast top — {} processes, {:.1}% CPU, {:.0}/{:.0} MiB mem",
            deltas.len(), cpu_busy, used_mem, total_mem);
        println!();
        println!("{:>7} {:>6} {:1} {:>10} {:>10} {:<}",
            "PID", "%CPU", "S", "RSS MiB", "VIRT MiB", "COMMAND");
        println!("{}", "-".repeat(60));

        // Fill remaining terminal rows (header uses 4 lines)
        let max_rows = terminal_rows().saturating_sub(4);
        for d in deltas.iter().take(max_rows) {
            let p = &d.proc;
            let comm = bytes_to_str(&p.comm);
            let state = match p.state {
                0 => "R", 1 => "S", 2 => "D", 3 => "T", 4 => "Z", _ => "X",
            };
            println!("{:>7} {:>5.1}% {:1} {:>10.1} {:>10.1} {:<}",
                p.pid,
                d.cpu_pct,
                state,
                p.rss_bytes as f64 / (1024.0 * 1024.0),
                p.vsize_bytes as f64 / (1024.0 * 1024.0),
                comm,
            );
        }

        // Save for next delta
        prev_snap = snap;
        prev_cpu = cpu;
    }
}

fn cmd_pid(client: &ProcfastClient, pid: u32) {
    let procs = client.proc_stats().unwrap_or_else(|e| die(&e));

    match procs.lookup(pid) {
        Some(p) => {
            let comm = bytes_to_str(&p.comm);
            let state = match p.state {
                0 => "Running",
                1 => "Sleeping",
                2 => "Disk sleep",
                3 => "Stopped",
                4 => "Zombie",
                _ => "Dead",
            };
            println!("Process {} ({})", pid, comm);
            println!("  State:         {state}");
            println!("  PPID:          {}", p.ppid);
            println!("  UID:           {}", p.uid);
            println!("  Threads:       {}", p.nr_threads);
            println!("  Nice:          {}", p.nice);
            println!("  Last CPU:      {}", p.last_cpu);
            println!("  User time:     {:.3}s", p.utime_ns as f64 / 1e9);
            println!("  System time:   {:.3}s", p.stime_ns as f64 / 1e9);
            println!("  RSS:           {:.1} MiB", p.rss_bytes as f64 / (1024.0 * 1024.0));
            println!("  Virtual:       {:.1} MiB", p.vsize_bytes as f64 / (1024.0 * 1024.0));
            println!("  Shared:        {:.1} MiB", p.shared_bytes as f64 / (1024.0 * 1024.0));
            println!("  Read I/O:      {:.1} MiB", p.read_bytes as f64 / (1024.0 * 1024.0));
            println!("  Write I/O:     {:.1} MiB", p.write_bytes as f64 / (1024.0 * 1024.0));
            println!("  Vol CSW:       {}", p.vol_ctxsw);
            println!("  Invol CSW:     {}", p.invol_ctxsw);
        }
        None => {
            eprintln!("error: process {pid} not found");
            std::process::exit(1);
        }
    }
}

fn cmd_status(client: &ProcfastClient) {
    // If we got here, the client connected successfully
    let cpu = client.cpu().unwrap_or_else(|e| die(&e));
    let snap = cpu.snapshot();
    println!("procfastd is running");
    println!("  Pin path:    /sys/fs/bpf/procfast");
    println!("  CPUs:        {}", snap.nr_cpus);
    println!("  Last update: {}ns (monotonic)", snap.timestamp_ns);
}

fn cmd_json(client: &ProcfastClient, subcmd: &str) {
    use serde_json::json;

    let output = match subcmd {
        "cpu" => {
            let cpu = client.cpu().unwrap_or_else(|e| die(&e));
            let s = cpu.snapshot();
            let per_cpu: Vec<_> = (0..s.nr_cpus as usize)
                .filter(|&i| i < procfast_common::MAX_CPUS)
                .map(|i| {
                    let c = &s.per_cpu[i];
                    json!({
                        "cpu": i,
                        "user_ns": c.user_ns, "nice_ns": c.nice_ns,
                        "system_ns": c.system_ns, "idle_ns": c.idle_ns,
                        "iowait_ns": c.iowait_ns, "irq_ns": c.irq_ns,
                        "softirq_ns": c.softirq_ns, "steal_ns": c.steal_ns,
                    })
                }).collect();
            json!({
                "timestamp_ns": s.timestamp_ns, "nr_cpus": s.nr_cpus,
                "total": {
                    "user_ns": s.total.user_ns, "nice_ns": s.total.nice_ns,
                    "system_ns": s.total.system_ns, "idle_ns": s.total.idle_ns,
                    "iowait_ns": s.total.iowait_ns, "irq_ns": s.total.irq_ns,
                    "softirq_ns": s.total.softirq_ns, "steal_ns": s.total.steal_ns,
                },
                "per_cpu": per_cpu,
            })
        }
        "mem" => {
            let mem = client.mem().unwrap_or_else(|e| die(&e));
            let s = mem.snapshot();
            json!({
                "timestamp_ns": s.timestamp_ns,
                "total_bytes": s.total_bytes, "free_bytes": s.free_bytes,
                "available_bytes": s.available_bytes, "buffers_bytes": s.buffers_bytes,
                "cached_bytes": s.cached_bytes, "shmem_bytes": s.shmem_bytes,
                "swap_total_bytes": s.swap_total_bytes, "swap_free_bytes": s.swap_free_bytes,
                "active_bytes": s.active_bytes, "inactive_bytes": s.inactive_bytes,
                "dirty_bytes": s.dirty_bytes,
            })
        }
        "net" => {
            let net = client.net().unwrap_or_else(|e| die(&e));
            let s = net.snapshot();
            let devs: Vec<_> = (0..s.nr_devs as usize)
                .filter(|&i| i < procfast_common::MAX_NET_DEVS)
                .map(|i| {
                    let d = &s.devs[i];
                    json!({
                        "name": bytes_to_str(&d.name),
                        "rx_bytes": d.rx_bytes, "tx_bytes": d.tx_bytes,
                        "rx_packets": d.rx_packets, "tx_packets": d.tx_packets,
                        "rx_errors": d.rx_errors, "tx_errors": d.tx_errors,
                        "rx_dropped": d.rx_dropped, "tx_dropped": d.tx_dropped,
                    })
                }).collect();
            json!({ "timestamp_ns": s.timestamp_ns, "devices": devs })
        }
        "disk" => {
            let disk = client.disk().unwrap_or_else(|e| die(&e));
            let s = disk.snapshot();
            let disks: Vec<_> = (0..s.nr_disks as usize)
                .filter(|&i| i < procfast_common::MAX_DISKS)
                .map(|i| {
                    let d = &s.disks[i];
                    json!({
                        "name": bytes_to_str(&d.name), "major": d.major, "minor": d.minor,
                        "read_ios": d.read_ios, "write_ios": d.write_ios,
                        "read_sectors": d.read_sectors, "write_sectors": d.write_sectors,
                    })
                }).collect();
            json!({ "timestamp_ns": s.timestamp_ns, "disks": disks })
        }
        "irq" => {
            let reader = client.irq().unwrap_or_else(|e| die(&e));
            let s = reader.snapshot();
            let irqs: Vec<_> = (0..s.nr_irqs as usize)
                .filter(|&i| i < procfast_common::MAX_IRQS)
                .map(|i| {
                    let irq = &s.irqs[i];
                    let percpu = reader.percpu_counts(irq.irq);
                    json!({
                        "irq": irq.irq,
                        "is_softirq": irq.irq & 0x80000000 != 0,
                        "total_count": irq.total_count,
                        "chip": bytes_to_str(&irq.chip_name),
                        "action": bytes_to_str(&irq.action_name),
                        "per_cpu": percpu,
                    })
                }).collect();
            json!({ "timestamp_ns": s.timestamp_ns, "interrupts": irqs })
        }
        "thermal" => {
            let thermal = client.thermal().unwrap_or_else(|e| die(&e));
            let s = thermal.snapshot();
            let zones: Vec<_> = (0..s.nr_zones as usize)
                .filter(|&i| i < procfast_common::MAX_THERMAL_ZONES)
                .map(|i| {
                    let z = &s.zones[i];
                    json!({
                        "type": bytes_to_str(&z.zone_type),
                        "temp_millicelsius": z.temp_millicelsius,
                    })
                }).collect();
            json!({ "timestamp_ns": s.timestamp_ns, "zones": zones })
        }
        "fd" => {
            let fd_reader = client.fd().unwrap_or_else(|e| die(&e));
            let all = fd_reader.snapshot_all().unwrap_or_else(|e| {
                eprintln!("error: {e}");
                std::process::exit(1);
            });
            let list: Vec<_> = all.iter().map(|f| {
                json!({
                    "pid": f.pid, "fd": f.fd,
                    "open_time_ns": f.open_time_ns,
                    "flags": f.flags,
                    "path": bytes_to_str(&f.path),
                })
            }).collect();
            json!({ "fds": list, "count": list.len() })
        }
        "sock" => {
            let reader = client.sock().unwrap_or_else(|e| die(&e));
            let socks = reader.snapshot_all();
            let list: Vec<_> = socks.iter().map(|s| {
                json!({
                    "inode": s.inode,
                    "family": s.family,
                    "protocol": s.protocol,
                    "state": s.state,
                    "uid": s.uid,
                    "local_port": s.local_port,
                    "remote_port": s.remote_port,
                    "local_addr": if s.family == 2 { format_ipv4(s.local_addr4) } else { "[::]".to_string() },
                    "remote_addr": if s.family == 2 { format_ipv4(s.remote_addr4) } else { "[::]".to_string() },
                })
            }).collect();
            json!({ "sockets": list, "count": list.len() })
        }
        "ps" => {
            let procs = client.proc_stats().unwrap_or_else(|e| die(&e));
            let all = procs.snapshot_all().unwrap_or_else(|e| {
                eprintln!("error: {e}");
                std::process::exit(1);
            });
            let list: Vec<_> = all.iter().filter(|p| p.state < 4).map(|p| {
                json!({
                    "pid": p.pid, "ppid": p.ppid, "uid": p.uid,
                    "state": p.state, "comm": bytes_to_str(&p.comm),
                    "nr_threads": p.nr_threads, "nice": p.nice,
                    "last_cpu": p.last_cpu,
                    "utime_ns": p.utime_ns, "stime_ns": p.stime_ns,
                    "cpu_runtime_ns": p.cpu_runtime_ns,
                    "rss_bytes": p.rss_bytes, "vsize_bytes": p.vsize_bytes,
                    "shared_bytes": p.shared_bytes,
                    "read_bytes": p.read_bytes, "write_bytes": p.write_bytes,
                    "vol_ctxsw": p.vol_ctxsw, "invol_ctxsw": p.invol_ctxsw,
                    "start_time_ns": p.start_time_ns,
                })
            }).collect();
            json!({ "processes": list, "count": list.len() })
        }
        "cgroup" => {
            let reader = client.cgroup().unwrap_or_else(|e| die(&e));
            let cgroups = reader.snapshot_all();
            let list: Vec<_> = cgroups.iter().map(|cg| {
                json!({
                    "id": cg.id, "parent_id": cg.parent_id,
                    "name": bytes_to_str(&cg.name),
                    "level": cg.level, "nr_descendants": cg.nr_descendants,
                    "cpu_usage_ns": cg.cpu_usage_ns,
                    "cpu_user_ns": cg.cpu_user_ns,
                    "cpu_system_ns": cg.cpu_system_ns,
                    "cpu_quota_us": cg.cpu_quota_us,
                    "cpu_period_us": cg.cpu_period_us,
                    "cpu_weight": cg.cpu_weight,
                    "nr_throttled": cg.nr_throttled,
                    "throttled_ns": cg.throttled_ns,
                    "memory_current": cg.memory_current,
                    "memory_limit": cg.memory_limit,
                    "memory_swap": cg.memory_swap,
                    "nr_pids": cg.nr_pids,
                    "pids_limit": cg.pids_limit,
                    "psi_cpu_some": cg.psi_cpu_some,
                    "psi_cpu_full": cg.psi_cpu_full,
                    "psi_mem_some": cg.psi_mem_some,
                    "psi_mem_full": cg.psi_mem_full,
                    "psi_io_some": cg.psi_io_some,
                    "psi_io_full": cg.psi_io_full,
                    "frozen": cg.frozen != 0,
                })
            }).collect();
            json!({ "cgroups": list, "count": list.len() })
        }
        "status" => {
            let cpu = client.cpu().unwrap_or_else(|e| die(&e));
            let s = cpu.snapshot();
            json!({
                "running": true, "nr_cpus": s.nr_cpus,
                "timestamp_ns": s.timestamp_ns,
                "pin_path": "/sys/fs/bpf/procfast",
            })
        }
        other => {
            eprintln!("error: unknown json subcommand '{other}'");
            eprintln!("usage: procfast json <cpu|mem|net|disk|irq|thermal|ps|cgroup|status>");
            std::process::exit(1);
        }
    };

    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}

fn bytes_to_str(b: &[u8]) -> &str {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    std::str::from_utf8(&b[..end]).unwrap_or("?")
}

fn die(e: &dyn std::fmt::Display) -> ! {
    let msg = e.to_string();
    if msg.contains("No such file or directory") {
        // The map file doesn't exist. Check if it's because the collector
        // failed to load (other maps exist) vs procfastd not running at all.
        let dir = std::path::Path::new("/sys/fs/bpf/procfast");
        if dir.exists() {
            eprintln!("error: this collector is not available on the current kernel.");
            eprintln!("procfastd is running but skipped this collector (check procfastd logs).");
        } else {
            eprintln!("error: procfastd is not running. Start it with: sudo procfastd");
        }
    } else if msg.contains("Permission denied") || msg.contains("Operation not permitted") {
        eprintln!("error: permission denied.");
        eprintln!("Run as root, or grant BPF capability:");
        eprintln!("  sudo setcap cap_bpf+ep $(which procfast)");
    } else {
        eprintln!("error: {msg}");
    }
    std::process::exit(1);
}
