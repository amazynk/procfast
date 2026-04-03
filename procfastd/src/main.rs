//! procfastd — daemon that loads procfast BPF programs and pins maps for shared access.
//!
//! Usage:
//!   sudo procfastd                          # start with defaults
//!   sudo procfastd --interval 500           # 500ms collection interval
//!   sudo procfastd --pin-path /sys/fs/bpf/procfast  # custom pin path
//!   sudo procfastd --no-proc               # disable process tracking
//!
//! Once running, any user can read metrics via procfast-client or procfast-cli:
//!   procfast query cpu
//!   procfast top

use procfast::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    let args = parse_args();

    // Clean up stale pins from a previous run
    if pin::is_pinned(&args.pin_path) {
        log::info!("Cleaning up stale pinned maps at {}", args.pin_path);
        if let Err(e) = pin::unpin_maps(&args.pin_path) {
            log::warn!("Failed to clean up: {e}");
        }
    }

    // Build procfast with all configured collectors
    log::info!("Loading BPF programs and pinning maps to {}...", args.pin_path);
    let _procfast = procfast::ProcfastBuilder::new()
        .interval_ms(args.interval_ms)
        .proc_stats(args.enable_proc)
        .fd(args.enable_fd)
        .cgroup(args.enable_cgroup)
        .pin_path(&args.pin_path)
        .public(args.public)
        .build()
        .unwrap_or_else(|e| {
            eprintln!("error: failed to initialize procfast: {e}");
            eprintln!();
            eprintln!("Requirements:");
            eprintln!("  - Linux kernel 5.15+");
            eprintln!("  - CAP_BPF + CAP_PERFMON capabilities (or root)");
            eprintln!("  - CONFIG_DEBUG_INFO_BTF=y in kernel config");
            std::process::exit(1);
        });

    // Set up signal handlers for clean shutdown using signal-hook.
    // This is safe — no libc::signal or extern "C" fn needed.
    let shutdown = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&shutdown))
        .expect("failed to register SIGINT handler");
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&shutdown))
        .expect("failed to register SIGTERM handler");

    log::info!("procfastd ready. Clients can connect via: {}", args.pin_path);
    log::info!("Collectors: cpu, mem, net, disk, thermal, irq{}{}",
        if args.enable_proc { ", proc" } else { "" },
        if args.enable_cgroup { ", cgroup" } else { "" });
    log::info!("Interval: {}ms", args.interval_ms);

    // Notify systemd we're ready (if running as a systemd service)
    notify_systemd_ready();

    // Main loop — just keep the process alive so BPF programs stay loaded.
    // The BPF timers do all the work autonomously in-kernel.
    while !shutdown.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    // Cleanup
    log::info!("Shutting down...");
    if let Err(e) = pin::unpin_maps(&args.pin_path) {
        log::warn!("Failed to unpin maps: {e}");
    }
    log::info!("procfastd stopped.");
}

struct Args {
    interval_ms: u64,
    pin_path: String,
    enable_proc: bool,
    enable_fd: bool,
    enable_cgroup: bool,
    public: bool,
}

fn parse_args() -> Args {
    let mut args = Args {
        interval_ms: 100,
        pin_path: pin::DEFAULT_PIN_PATH.to_string(),
        enable_proc: true,
        enable_fd: false,
        enable_cgroup: false,
        public: true,
    };

    let argv: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "--interval" | "-i" => {
                i += 1;
                args.interval_ms = argv[i].parse().unwrap_or_else(|_| {
                    eprintln!("error: --interval requires a number (milliseconds)");
                    std::process::exit(1);
                });
            }
            "--pin-path" | "-p" => {
                i += 1;
                args.pin_path = argv[i].clone();
            }
            "--no-proc" => {
                args.enable_proc = false;
            }
            "--fd" => {
                args.enable_fd = true;
            }
            "--cgroup" => {
                args.enable_cgroup = true;
            }
            "--no-public" => {
                args.public = false;
            }
            "--help" | "-h" => {
                println!("procfastd — procfast metrics daemon");
                println!();
                println!("Loads eBPF programs that collect system metrics and pins the");
                println!("resulting maps to bpffs. Other tools read these maps for fast,");
                println!("zero-copy access to CPU, memory, network, disk, interrupt,");
                println!("thermal, process, and file descriptor data.");
                println!();
                println!("USAGE:");
                println!("  sudo procfastd [OPTIONS]");
                println!();
                println!("OPTIONS:");
                println!("  -i, --interval <ms>    CPU sample / proc reaper interval (default: 100)");
                println!("  -p, --pin-path <path>  BPF map pin directory (default: {0})", pin::DEFAULT_PIN_PATH);
                println!("      --no-proc          Disable per-process tracking (most expensive collector)");
                println!("      --fd               Enable fd + socket tracking (for lsof/ss)");
                println!("      --cgroup           Enable cgroup stats (CPU + memory per cgroup)");
                println!("      --no-public        Restrict map access to root only");
                println!("  -h, --help             Show this help");
                println!();
                println!("COLLECTORS:");
                println!("  cpu       Per-CPU time counters (timer-based, always on)");
                println!("  mem       Memory stats via fexit/si_meminfo");
                println!("  net       Network device stats via fexit/dev_get_stats");
                println!("  disk      Block I/O via fentry/diskstats_show + tracepoint");
                println!("  irq       Interrupt counts via fentry/handle_irq_event");
                println!("  thermal   Zone temperatures via fexit/thermal_zone_get_temp");
                println!("  proc      Process stats via scheduler tracepoints (disable: --no-proc)");
                println!("  fd        File descriptors via openat/close hooks (enable: --fd)");
                println!("  sock      TCP/UDP/Unix sockets via BPF iterators (with --fd)");
                println!("  cgroup    Cgroup CPU + memory stats via BPF iterator (enable: --cgroup)");
                println!();
                println!("EXAMPLES:");
                println!("  sudo procfastd                    # start with defaults");
                println!("  sudo procfastd --fd               # also track open files + sockets");
                println!("  sudo procfastd -i 50              # 50ms CPU sample interval");
                println!("  sudo procfastd --no-proc --fd     # only system metrics + fd/sockets");
                println!();
                println!("REQUIREMENTS:");
                println!("  Linux 5.15+, CONFIG_DEBUG_INFO_BTF=y, CAP_BPF + CAP_PERFMON");
                std::process::exit(0);
            }
            other => {
                eprintln!("error: unknown argument: {other}");
                eprintln!("Try 'procfastd --help' for usage.");
                std::process::exit(1);
            }
        }
        i += 1;
    }

    args
}

fn notify_systemd_ready() {
    // sd_notify(0, "READY=1") — notify systemd we're initialized
    if let Ok(path) = std::env::var("NOTIFY_SOCKET") {
        let addr = if path.starts_with('@') {
            // Abstract socket
            format!("\0{}", &path[1..])
        } else {
            path
        };
        // Best-effort; don't fail if this doesn't work
        let _ = std::os::unix::net::UnixDatagram::unbound()
            .and_then(|sock| {
                sock.send_to(b"READY=1", &addr)
            });
    }
}
