//! procfast-exporter — Prometheus exporter for procfast system metrics.
//!
//! Loads BPF programs directly and serves metrics on HTTP.
//!
//! Usage:
//!   sudo procfast-exporter                    # listen on :9099
//!   sudo procfast-exporter --port 9100        # custom port
//!   sudo procfast-exporter --interval 500     # 500ms BPF collection interval
//!
//! Metrics endpoint: http://localhost:9099/metrics

use procfast::{Procfast, ProcfastBuilder};
use procfast_common::*;
use std::io::Write;

fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    ).init();

    let args = parse_args();

    log::info!("Loading BPF programs...");
    let procfast = ProcfastBuilder::new()
        .interval_ms(args.interval_ms)
        .build()
        .unwrap_or_else(|e| {
            eprintln!("error: {e}");
            eprintln!("Requires CAP_BPF + CAP_PERFMON (or root).");
            std::process::exit(1);
        });

    let addr = format!("0.0.0.0:{}", args.port);
    log::info!("Listening on http://{addr}/metrics");

    let server = tiny_http::Server::http(&addr).unwrap_or_else(|e| {
        eprintln!("error: failed to bind {addr}: {e}");
        std::process::exit(1);
    });

    for request in server.incoming_requests() {
        let url = request.url().to_string();
        match url.as_str() {
            "/metrics" => {
                let body = render_metrics(&procfast);
                let response = tiny_http::Response::from_string(&body)
                    .with_header(
                        "Content-Type: text/plain; version=0.0.4; charset=utf-8"
                            .parse::<tiny_http::Header>().unwrap()
                    );
                let _ = request.respond(response);
            }
            "/" => {
                let body = "<html><body><a href=\"/metrics\">Metrics</a></body></html>";
                let response = tiny_http::Response::from_string(body)
                    .with_header("Content-Type: text/html".parse::<tiny_http::Header>().unwrap());
                let _ = request.respond(response);
            }
            _ => {
                let response = tiny_http::Response::from_string("Not Found\n")
                    .with_status_code(404);
                let _ = request.respond(response);
            }
        }
    }
}

fn render_metrics(procfast: &Procfast) -> String {
    let mut out = Vec::with_capacity(8192);

    render_cpu(procfast, &mut out);
    render_mem(procfast, &mut out);
    render_net(procfast, &mut out);
    render_disk(procfast, &mut out);
    render_irq(procfast, &mut out);
    render_thermal(procfast, &mut out);
    render_proc(procfast, &mut out);

    String::from_utf8(out).unwrap_or_default()
}

fn render_cpu(procfast: &Procfast, out: &mut Vec<u8>) {
    let cpu = match procfast.cpu() {
        Some(c) => c,
        None => return,
    };
    let snap = cpu.snapshot();

    writeln!(out, "# HELP procfast_cpu_seconds_total CPU time in seconds per mode per CPU.").unwrap();
    writeln!(out, "# TYPE procfast_cpu_seconds_total counter").unwrap();

    for i in 0..snap.nr_cpus as usize {
        if i >= MAX_CPUS { break; }
        let c = &snap.per_cpu[i];
        let cpu_label = format!("cpu=\"{i}\"");
        let ns_to_s = |ns: u64| ns as f64 / 1e9;
        writeln!(out, "procfast_cpu_seconds_total{{{cpu_label},mode=\"user\"}} {:.6}", ns_to_s(c.user_ns)).unwrap();
        writeln!(out, "procfast_cpu_seconds_total{{{cpu_label},mode=\"nice\"}} {:.6}", ns_to_s(c.nice_ns)).unwrap();
        writeln!(out, "procfast_cpu_seconds_total{{{cpu_label},mode=\"system\"}} {:.6}", ns_to_s(c.system_ns)).unwrap();
        writeln!(out, "procfast_cpu_seconds_total{{{cpu_label},mode=\"idle\"}} {:.6}", ns_to_s(c.idle_ns)).unwrap();
        writeln!(out, "procfast_cpu_seconds_total{{{cpu_label},mode=\"iowait\"}} {:.6}", ns_to_s(c.iowait_ns)).unwrap();
        writeln!(out, "procfast_cpu_seconds_total{{{cpu_label},mode=\"irq\"}} {:.6}", ns_to_s(c.irq_ns)).unwrap();
        writeln!(out, "procfast_cpu_seconds_total{{{cpu_label},mode=\"softirq\"}} {:.6}", ns_to_s(c.softirq_ns)).unwrap();
        writeln!(out, "procfast_cpu_seconds_total{{{cpu_label},mode=\"steal\"}} {:.6}", ns_to_s(c.steal_ns)).unwrap();
    }
}

fn render_mem(procfast: &Procfast, out: &mut Vec<u8>) {
    let mem = match procfast.mem() {
        Some(m) => m,
        None => return,
    };
    let s = mem.snapshot();

    writeln!(out, "# HELP procfast_memory_bytes Memory statistics in bytes.").unwrap();
    writeln!(out, "# TYPE procfast_memory_bytes gauge").unwrap();
    writeln!(out, "procfast_memory_bytes{{type=\"total\"}} {}", s.total_bytes).unwrap();
    writeln!(out, "procfast_memory_bytes{{type=\"free\"}} {}", s.free_bytes).unwrap();
    writeln!(out, "procfast_memory_bytes{{type=\"available\"}} {}", s.available_bytes).unwrap();
    writeln!(out, "procfast_memory_bytes{{type=\"buffers\"}} {}", s.buffers_bytes).unwrap();
    writeln!(out, "procfast_memory_bytes{{type=\"shared\"}} {}", s.shmem_bytes).unwrap();
    writeln!(out, "procfast_memory_bytes{{type=\"swap_total\"}} {}", s.swap_total_bytes).unwrap();
    writeln!(out, "procfast_memory_bytes{{type=\"swap_free\"}} {}", s.swap_free_bytes).unwrap();
}

fn render_net(procfast: &Procfast, out: &mut Vec<u8>) {
    let net = match procfast.net() {
        Some(n) => n,
        None => return,
    };
    let s = net.snapshot();

    writeln!(out, "# HELP procfast_net_rx_bytes_total Network receive bytes.").unwrap();
    writeln!(out, "# TYPE procfast_net_rx_bytes_total counter").unwrap();
    writeln!(out, "# HELP procfast_net_tx_bytes_total Network transmit bytes.").unwrap();
    writeln!(out, "# TYPE procfast_net_tx_bytes_total counter").unwrap();
    writeln!(out, "# HELP procfast_net_rx_packets_total Network receive packets.").unwrap();
    writeln!(out, "# TYPE procfast_net_rx_packets_total counter").unwrap();
    writeln!(out, "# HELP procfast_net_tx_packets_total Network transmit packets.").unwrap();
    writeln!(out, "# TYPE procfast_net_tx_packets_total counter").unwrap();
    writeln!(out, "# HELP procfast_net_rx_errors_total Network receive errors.").unwrap();
    writeln!(out, "# TYPE procfast_net_rx_errors_total counter").unwrap();
    writeln!(out, "# HELP procfast_net_tx_errors_total Network transmit errors.").unwrap();
    writeln!(out, "# TYPE procfast_net_tx_errors_total counter").unwrap();

    for i in 0..s.nr_devs as usize {
        if i >= MAX_NET_DEVS { break; }
        let d = &s.devs[i];
        let name = bytes_to_str(&d.name);
        let dev = format!("device=\"{name}\"");
        writeln!(out, "procfast_net_rx_bytes_total{{{dev}}} {}", d.rx_bytes).unwrap();
        writeln!(out, "procfast_net_tx_bytes_total{{{dev}}} {}", d.tx_bytes).unwrap();
        writeln!(out, "procfast_net_rx_packets_total{{{dev}}} {}", d.rx_packets).unwrap();
        writeln!(out, "procfast_net_tx_packets_total{{{dev}}} {}", d.tx_packets).unwrap();
        writeln!(out, "procfast_net_rx_errors_total{{{dev}}} {}", d.rx_errors).unwrap();
        writeln!(out, "procfast_net_tx_errors_total{{{dev}}} {}", d.tx_errors).unwrap();
    }
}

fn render_disk(procfast: &Procfast, out: &mut Vec<u8>) {
    let disk = match procfast.disk() {
        Some(d) => d,
        None => return,
    };
    let s = disk.snapshot();

    writeln!(out, "# HELP procfast_disk_read_ios_total Disk read operations.").unwrap();
    writeln!(out, "# TYPE procfast_disk_read_ios_total counter").unwrap();
    writeln!(out, "# HELP procfast_disk_write_ios_total Disk write operations.").unwrap();
    writeln!(out, "# TYPE procfast_disk_write_ios_total counter").unwrap();
    writeln!(out, "# HELP procfast_disk_read_sectors_total Disk sectors read.").unwrap();
    writeln!(out, "# TYPE procfast_disk_read_sectors_total counter").unwrap();
    writeln!(out, "# HELP procfast_disk_write_sectors_total Disk sectors written.").unwrap();
    writeln!(out, "# TYPE procfast_disk_write_sectors_total counter").unwrap();

    for i in 0..s.nr_disks as usize {
        if i >= MAX_DISKS { break; }
        let d = &s.disks[i];
        let name = bytes_to_str(&d.name);
        let dev = format!("device=\"{name}\"");
        writeln!(out, "procfast_disk_read_ios_total{{{dev}}} {}", d.read_ios).unwrap();
        writeln!(out, "procfast_disk_write_ios_total{{{dev}}} {}", d.write_ios).unwrap();
        writeln!(out, "procfast_disk_read_sectors_total{{{dev}}} {}", d.read_sectors).unwrap();
        writeln!(out, "procfast_disk_write_sectors_total{{{dev}}} {}", d.write_sectors).unwrap();
    }
}

fn render_irq(procfast: &Procfast, out: &mut Vec<u8>) {
    let irq = match procfast.irq() {
        Some(i) => i,
        None => return,
    };
    let s = irq.snapshot();

    writeln!(out, "# HELP procfast_interrupts_total Interrupt count per IRQ.").unwrap();
    writeln!(out, "# TYPE procfast_interrupts_total counter").unwrap();

    for i in 0..s.nr_irqs as usize {
        if i >= MAX_IRQS { break; }
        let irq = &s.irqs[i];
        let action = bytes_to_str(&irq.action_name);
        let chip = bytes_to_str(&irq.chip_name);
        let irq_type = if irq.irq & 0x80000000 != 0 { "softirq" } else { "hardirq" };
        let irq_label = if irq.irq & 0x80000000 != 0 {
            action.to_string()
        } else {
            format!("{}", irq.irq)
        };
        writeln!(out,
            "procfast_interrupts_total{{irq=\"{irq_label}\",type=\"{irq_type}\",chip=\"{chip}\",action=\"{action}\"}} {}",
            irq.total_count
        ).unwrap();
    }
}

fn render_thermal(procfast: &Procfast, out: &mut Vec<u8>) {
    let thermal = match procfast.thermal() {
        Some(t) => t,
        None => return,
    };
    let s = thermal.snapshot();

    writeln!(out, "# HELP procfast_thermal_celsius Thermal zone temperature in Celsius.").unwrap();
    writeln!(out, "# TYPE procfast_thermal_celsius gauge").unwrap();

    for i in 0..s.nr_zones as usize {
        if i >= MAX_THERMAL_ZONES { break; }
        let z = &s.zones[i];
        let zone_type = bytes_to_str(&z.zone_type);
        writeln!(out,
            "procfast_thermal_celsius{{zone=\"{zone_type}\"}} {:.1}",
            z.temp_millicelsius as f64 / 1000.0
        ).unwrap();
    }
}

fn render_proc(procfast: &Procfast, out: &mut Vec<u8>) {
    let procs = match procfast.proc_stats() {
        Some(p) => p,
        None => return,
    };
    let hdr = procs.header();

    writeln!(out, "# HELP procfast_process_count Number of tracked processes.").unwrap();
    writeln!(out, "# TYPE procfast_process_count gauge").unwrap();
    writeln!(out, "procfast_process_count {}", hdr.nr_procs).unwrap();

    // Emit per-process metrics for top consumers only (avoids cardinality explosion).
    // Scrape the full list, sort by runtime, export top 50.
    let all = match procs.snapshot_all() {
        Ok(a) => a,
        Err(_) => return,
    };

    let mut active: Vec<&ProcStats> = all.iter().filter(|p| p.state < 4).collect();
    active.sort_by(|a, b| b.cpu_runtime_ns.cmp(&a.cpu_runtime_ns));

    writeln!(out, "# HELP procfast_process_cpu_seconds_total Process CPU runtime in seconds.").unwrap();
    writeln!(out, "# TYPE procfast_process_cpu_seconds_total counter").unwrap();
    writeln!(out, "# HELP procfast_process_rss_bytes Process resident set size in bytes.").unwrap();
    writeln!(out, "# TYPE procfast_process_rss_bytes gauge").unwrap();

    for p in active.iter().take(50) {
        let comm = bytes_to_str(&p.comm);
        let labels = format!("pid=\"{}\",comm=\"{comm}\"", p.pid);
        writeln!(out,
            "procfast_process_cpu_seconds_total{{{labels}}} {:.6}",
            p.cpu_runtime_ns as f64 / 1e9
        ).unwrap();
        writeln!(out,
            "procfast_process_rss_bytes{{{labels}}} {}",
            p.rss_bytes
        ).unwrap();
    }
}

fn bytes_to_str(b: &[u8]) -> &str {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    std::str::from_utf8(&b[..end]).unwrap_or("?")
}

struct Args {
    port: u16,
    interval_ms: u64,
}

fn parse_args() -> Args {
    let mut args = Args { port: 9099, interval_ms: 1000 };
    let argv: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--port" | "-p" => {
                i += 1;
                args.port = argv.get(i).and_then(|s| s.parse().ok()).unwrap_or(9099);
            }
            "--interval" | "-i" => {
                i += 1;
                args.interval_ms = argv.get(i).and_then(|s| s.parse().ok()).unwrap_or(1000);
            }
            "-h" | "--help" => {
                println!("procfast-exporter — Prometheus exporter for procfast metrics");
                println!();
                println!("USAGE:");
                println!("  sudo procfast-exporter [OPTIONS]");
                println!();
                println!("OPTIONS:");
                println!("  -p, --port <port>      HTTP port (default: 9099)");
                println!("  -i, --interval <ms>    BPF collection interval (default: 1000)");
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }
    args
}
