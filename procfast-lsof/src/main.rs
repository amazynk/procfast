//! procfast-lsof — Fast lsof replacement powered by eBPF.
//!
//! Lists open file descriptors for all processes or a specific PID,
//! using procfast's BPF-based fd tracking instead of walking /proc/[pid]/fd/.
//!
//! Usage:
//!   sudo procfast-lsof                  # list all open files
//!   sudo procfast-lsof -p 1234         # files for PID 1234
//!   sudo procfast-lsof -c firefox      # files for processes named "firefox"
//!   sudo procfast-lsof -u root         # files for user root
//!   sudo procfast-lsof /var/log/syslog # files matching path
//!   sudo procfast-lsof -J              # JSON output
//!   sudo procfast-lsof +D /tmp         # files under directory

use procfast::{Procfast, ProcfastBuilder};
use procfast_common::{FdInfo, ProcStats};
use std::collections::HashMap;

fn main() {
    let args = parse_args();

    let procfast = ProcfastBuilder::new()
        .fd(true)
        .proc_stats(true)
        .cpu(false).mem(false).net(false).disk(false)
        .thermal(false).irq(false)
        .build()
        .unwrap_or_else(|e| {
            eprintln!("error: {e}");
            eprintln!("Requires root or CAP_BPF+CAP_PERFMON.");
            std::process::exit(1);
        });

    let fd_collector = procfast.fd().unwrap_or_else(|| {
        eprintln!("error: fd collector not available");
        std::process::exit(1);
    });

    // Build pid->comm map for display
    let proc_map = build_proc_map(&procfast);

    let fds = fd_collector.snapshot_all().unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1);
    });

    // Apply filters
    let filtered: Vec<&FdInfo> = fds.iter().filter(|fd| {
        if let Some(pid) = args.pid {
            if fd.pid != pid { return false; }
        }
        if let Some(ref name) = args.command {
            let comm = proc_comm(&proc_map, fd.pid);
            if !comm.contains(name.as_str()) { return false; }
        }
        if let Some(ref user) = args.user {
            if let Some(ps) = proc_map.get(&fd.pid) {
                let uid_match = user.parse::<u32>().map(|u| ps.uid == u).unwrap_or(false);
                if !uid_match {
                    // Try matching username via /etc/passwd
                    let uname = uid_to_name(ps.uid);
                    if uname != *user { return false; }
                }
            } else {
                return false;
            }
        }
        if let Some(ref path_filter) = args.path {
            let path = bytes_to_str(&fd.path);
            if !path.contains(path_filter.as_str()) { return false; }
        }
        if let Some(ref dir) = args.dir {
            let path = bytes_to_str(&fd.path);
            if !path.starts_with(dir.as_str()) { return false; }
        }
        true
    }).collect();

    if args.json {
        print_json(&filtered, &proc_map);
    } else {
        print_table(&filtered, &proc_map);
    }
}

fn print_table(fds: &[&FdInfo], proc_map: &HashMap<u32, ProcStats>) {
    println!("{:<16} {:>7} {:>5}  {}", "COMMAND", "PID", "FD", "NAME");
    for fd in fds {
        let comm = proc_comm(proc_map, fd.pid);
        let path = bytes_to_str(&fd.path);
        println!("{:<16} {:>7} {:>5}  {}", comm, fd.pid, fd.fd, path);
    }
}

fn print_json(fds: &[&FdInfo], proc_map: &HashMap<u32, ProcStats>) {
    let entries: Vec<serde_json::Value> = fds.iter().map(|fd| {
        serde_json::json!({
            "command": proc_comm(proc_map, fd.pid),
            "pid": fd.pid,
            "fd": fd.fd,
            "path": bytes_to_str(&fd.path),
            "flags": fd.flags,
        })
    }).collect();
    println!("{}", serde_json::to_string_pretty(&entries).unwrap());
}

fn build_proc_map(procfast: &Procfast) -> HashMap<u32, ProcStats> {
    procfast.proc_stats()
        .and_then(|p| p.snapshot_all().ok())
        .unwrap_or_default()
        .into_iter()
        .map(|p| (p.pid, p))
        .collect()
}

fn proc_comm(map: &HashMap<u32, ProcStats>, pid: u32) -> &str {
    map.get(&pid)
        .map(|p| bytes_to_str(&p.comm))
        .unwrap_or("?")
}

fn bytes_to_str(b: &[u8]) -> &str {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    std::str::from_utf8(&b[..end]).unwrap_or("?")
}

fn uid_to_name(uid: u32) -> String {
    std::fs::read_to_string("/etc/passwd")
        .unwrap_or_default()
        .lines()
        .find(|line| {
            let mut parts = line.split(':');
            parts.next(); // name
            parts.next(); // x
            parts.next().and_then(|u| u.parse::<u32>().ok()) == Some(uid)
        })
        .and_then(|line| line.split(':').next())
        .unwrap_or("?")
        .to_string()
}

struct Args {
    pid: Option<u32>,
    command: Option<String>,
    user: Option<String>,
    path: Option<String>,
    dir: Option<String>,
    json: bool,
}

fn parse_args() -> Args {
    let mut args = Args {
        pid: None, command: None, user: None,
        path: None, dir: None, json: false,
    };

    let argv: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < argv.len() {
        match argv[i].as_str() {
            "-p" => { i += 1; args.pid = argv.get(i).and_then(|s| s.parse().ok()); }
            "-c" => { i += 1; args.command = argv.get(i).cloned(); }
            "-u" => { i += 1; args.user = argv.get(i).cloned(); }
            "+D" => { i += 1; args.dir = argv.get(i).cloned(); }
            "-J" | "--json" => { args.json = true; }
            "-h" | "--help" => {
                println!("procfast-lsof — fast lsof replacement powered by eBPF");
                println!();
                println!("USAGE:");
                println!("  sudo procfast-lsof [OPTIONS] [PATH]");
                println!();
                println!("OPTIONS:");
                println!("  -p PID        Show only files for PID");
                println!("  -c NAME       Show only files for command NAME");
                println!("  -u USER       Show only files for USER (name or UID)");
                println!("  +D DIR        Show only files under directory DIR");
                println!("  -J, --json    Output as JSON");
                println!("  -h, --help    Show this help");
                println!();
                println!("EXAMPLES:");
                println!("  procfast-lsof                  List all open files");
                println!("  procfast-lsof -p 1             Files for PID 1");
                println!("  procfast-lsof -c firefox        Files for firefox processes");
                println!("  procfast-lsof /var/log          Files matching /var/log");
                println!("  procfast-lsof +D /tmp           Files under /tmp/");
                std::process::exit(0);
            }
            s if !s.starts_with('-') && !s.starts_with('+') => {
                args.path = Some(s.to_string());
            }
            _ => {
                eprintln!("unknown option: {}", argv[i]);
                std::process::exit(1);
            }
        }
        i += 1;
    }
    args
}
