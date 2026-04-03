//! # procfast — High-performance Linux system metrics via eBPF
//!
//! procfast replaces expensive `/proc` and `/sys` file reads with eBPF-based
//! data collection. Instead of repeated open/read/close syscalls and
//! text parsing, metrics are collected by BPF programs running inside
//! the kernel and exposed to userspace via zero-copy mmap'd BPF maps.
//!
//! ## Requirements
//!
//! - Linux kernel 5.15+ (for bpf_timer)
//! - `CAP_BPF` and `CAP_PERFMON` capabilities (or root)
//! - BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`)

pub mod collector;
pub mod cpu;
pub mod disk;
pub mod error;
pub mod fd;
pub mod sock;
pub mod irq;
pub mod mem;
pub mod pin;
pub mod proc;
pub mod net;
pub mod thermal;

mod fallback;
pub mod seed;

pub use cpu::CpuCollector;
pub use disk::DiskCollector;
pub use error::ProcfastError;
pub use fd::FdCollector;
pub use sock::SockCollector;
pub use irq::IrqCollector;
pub use procfast_common::*;
pub use proc::ProcCollector;
pub use mem::MemCollector;
pub use net::NetCollector;
pub use thermal::ThermalCollector;

// Include generated BPF skeletons (produced by build.rs).
// Each skeleton is in its own submodule to avoid `mod imp` name collisions.
#[allow(non_upper_case_globals, non_snake_case, non_camel_case_types, dead_code, ambiguous_glob_reexports)]
mod skel {
    pub mod cpu {
        include!(concat!(env!("OUT_DIR"), "/skel/cpu.skel.rs"));
    }
    pub mod mem {
        include!(concat!(env!("OUT_DIR"), "/skel/mem.skel.rs"));
    }
    pub mod net {
        include!(concat!(env!("OUT_DIR"), "/skel/net.skel.rs"));
    }
    pub mod disk {
        include!(concat!(env!("OUT_DIR"), "/skel/disk.skel.rs"));
    }
    pub mod thermal {
        include!(concat!(env!("OUT_DIR"), "/skel/thermal.skel.rs"));
    }
    pub mod irq {
        include!(concat!(env!("OUT_DIR"), "/skel/irq.skel.rs"));
    }
    pub mod proc {
        include!(concat!(env!("OUT_DIR"), "/skel/proc.skel.rs"));
    }
    pub mod fd {
        include!(concat!(env!("OUT_DIR"), "/skel/fd.skel.rs"));
    }
    pub mod sock {
        include!(concat!(env!("OUT_DIR"), "/skel/sock.skel.rs"));
    }
}

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, MapHandle, ProgramInput};
use std::io::Read;
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::os::unix::io::{AsRawFd, FromRawFd};

/// Main handle for procfast system metrics collection.
pub struct Procfast {
    cpu: Option<CpuCollector>,
    mem: Option<MemCollector>,
    net: Option<NetCollector>,
    disk: Option<DiskCollector>,
    thermal: Option<ThermalCollector>,
    irq: Option<IrqCollector>,
    proc: Option<ProcCollector>,
    fd: Option<FdCollector>,
    sock: Option<SockCollector>,
    // Box the storage so it has a stable address and lives as long as Procfast.
    _storage: Box<SkelStorage>,
    // BPF program attachment links. Dropping a Link detaches the program,
    // so we must keep them alive for the lifetime of the Procfast handle.
    _links: Vec<libbpf_rs::Link>,
}

/// Holds the MaybeUninit storage and loaded skeletons.
/// The skeleton types contain self-referential borrows, so we box this
/// and never move it.
struct SkelStorage {
    _cpu_obj: MaybeUninit<libbpf_rs::OpenObject>,
    _mem_obj: MaybeUninit<libbpf_rs::OpenObject>,
    _net_obj: MaybeUninit<libbpf_rs::OpenObject>,
    _disk_obj: MaybeUninit<libbpf_rs::OpenObject>,
    _thermal_obj: MaybeUninit<libbpf_rs::OpenObject>,
    _irq_obj: MaybeUninit<libbpf_rs::OpenObject>,
    _proc_obj: MaybeUninit<libbpf_rs::OpenObject>,
    _fd_obj: MaybeUninit<libbpf_rs::OpenObject>,
    _sock_obj: MaybeUninit<libbpf_rs::OpenObject>,
}

impl Procfast {
    pub fn cpu(&self) -> Option<&CpuCollector> { self.cpu.as_ref() }
    pub fn mem(&self) -> Option<&MemCollector> { self.mem.as_ref() }
    pub fn net(&self) -> Option<&NetCollector> { self.net.as_ref() }
    pub fn disk(&self) -> Option<&DiskCollector> { self.disk.as_ref() }
    pub fn thermal(&self) -> Option<&ThermalCollector> { self.thermal.as_ref() }
    pub fn irq(&self) -> Option<&IrqCollector> { self.irq.as_ref() }
    pub fn proc_stats(&self) -> Option<&ProcCollector> { self.proc.as_ref() }
    pub fn fd(&self) -> Option<&FdCollector> { self.fd.as_ref() }
    pub fn sock(&self) -> Option<&SockCollector> { self.sock.as_ref() }
}

/// Builder for configuring which metrics to collect and at what interval.
#[derive(Clone)]
pub struct ProcfastBuilder {
    enable_cpu: bool,
    enable_mem: bool,
    enable_net: bool,
    enable_disk: bool,
    enable_thermal: bool,
    enable_irq: bool,
    enable_proc: bool,
    enable_fd: bool,
    interval_ms: u64,
    allow_fallback: bool,
    pin_path: Option<String>,
    public: bool,
}

impl Default for ProcfastBuilder {
    fn default() -> Self { Self::new() }
}

impl ProcfastBuilder {
    pub fn new() -> Self {
        Self {
            enable_cpu: true,
            enable_mem: true,
            enable_net: true,
            enable_disk: true,
            enable_thermal: true,
            enable_irq: true,
            enable_proc: true,
            enable_fd: false,
            interval_ms: 100,
            allow_fallback: false,
            pin_path: None,
            public: true,
        }
    }

    pub fn cpu(mut self, enable: bool) -> Self { self.enable_cpu = enable; self }
    pub fn mem(mut self, enable: bool) -> Self { self.enable_mem = enable; self }
    pub fn net(mut self, enable: bool) -> Self { self.enable_net = enable; self }
    pub fn disk(mut self, enable: bool) -> Self { self.enable_disk = enable; self }
    pub fn thermal(mut self, enable: bool) -> Self { self.enable_thermal = enable; self }
    pub fn irq(mut self, enable: bool) -> Self { self.enable_irq = enable; self }
    pub fn proc_stats(mut self, enable: bool) -> Self { self.enable_proc = enable; self }
    pub fn fd(mut self, enable: bool) -> Self { self.enable_fd = enable; self }
    pub fn interval_ms(mut self, ms: u64) -> Self { self.interval_ms = ms; self }
    pub fn allow_fallback(mut self, allow: bool) -> Self { self.allow_fallback = allow; self }

    /// Pin BPF maps to a bpffs directory so clients can read them
    /// without CAP_BPF. Maps are pinned as `{path}/{map_name}`.
    pub fn pin_path(mut self, path: &str) -> Self { self.pin_path = Some(path.to_string()); self }

    /// Allow non-root users to read pinned maps (default: true).
    /// When false, only root can access the maps.
    pub fn public(mut self, public: bool) -> Self { self.public = public; self }

    pub fn build(self) -> Result<Procfast, ProcfastError> {
        let builder = self.clone();
        match self.try_build_bpf() {
            Ok(procfast) => Ok(procfast),
            Err(e) if builder.allow_fallback => {
                log::warn!("BPF unavailable ({e}), falling back to /proc");
                fallback::build_fallback(builder)
            }
            Err(e) => Err(e),
        }
    }

    fn try_build_bpf(self) -> Result<Procfast, ProcfastError> {
        let interval_ns = self.interval_ms * 1_000_000;
        let config = procfast_common::ProcfastConfig { interval_ns };

        // Create pin directory if requested
        if let Some(ref pin_dir) = self.pin_path {
            std::fs::create_dir_all(pin_dir)
                .map_err(|e| ProcfastError::Pin(format!("mkdir {pin_dir}: {e}")))?;
        }

        let mut storage = Box::new(SkelStorage {
            _cpu_obj: MaybeUninit::uninit(),
            _mem_obj: MaybeUninit::uninit(),
            _net_obj: MaybeUninit::uninit(),
            _disk_obj: MaybeUninit::uninit(),
            _thermal_obj: MaybeUninit::uninit(),
            _irq_obj: MaybeUninit::uninit(),
            _proc_obj: MaybeUninit::uninit(),
            _fd_obj: MaybeUninit::uninit(),
            _sock_obj: MaybeUninit::uninit(),
        });

        let mut cpu_collector = None;
        let mut mem_collector = None;
        let mut net_collector = None;
        let mut disk_collector = None;
        let mut thermal_collector = None;
        let mut irq_collector = None;
        let mut proc_collector = None;
        let mut fd_collector = None;
        let mut sock_collector = None;
        let mut links: Vec<libbpf_rs::Link> = Vec::new();

        if self.enable_cpu {
            let builder = skel::cpu::CpuSkelBuilder::default();
            let open = builder.open(&mut storage._cpu_obj)
                .map_err(|e| ProcfastError::BpfLoad(e.to_string()))?;
            let mut skel = open.load()
                .map_err(|e| ProcfastError::BpfLoad(e.to_string()))?;

            write_config(&skel.maps.cpu_config, &config)?;
            cpu_collector = Some(CpuCollector::from_fd(skel.maps.cpu_data.as_fd())?);
            if let Some(ref dir) = self.pin_path {
                pin_map(&mut skel.maps.cpu_data, dir, "cpu_data")?;
            }
            run_init_prog(&skel.progs.procfast_cpu_init)?;
            std::mem::forget(skel);
        }

        if self.enable_mem {
            match (|| -> Result<_, ProcfastError> {
                let builder = skel::mem::MemSkelBuilder::default();
                let open = builder.open(&mut storage._mem_obj)
                    .map_err(|e| ProcfastError::BpfLoad(e.to_string()))?;
                let mut skel = open.load()
                    .map_err(|e| ProcfastError::BpfLoad(e.to_string()))?;
                write_config(&skel.maps.mem_config, &config)?;
                let c = MemCollector::from_fd(skel.maps.mem_data.as_fd())?;
                if let Some(ref dir) = self.pin_path {
                    pin_map(&mut skel.maps.mem_data, dir, "mem_data")?;
                }
                // Attach fexit hooks
                links.push(skel.progs.fexit_si_meminfo.attach()
                    .map_err(|e| ProcfastError::BpfLoad(format!("attach fexit/si_meminfo: {e}")))?);
                links.push(skel.progs.fexit_si_mem_available.attach()
                    .map_err(|e| ProcfastError::BpfLoad(format!("attach fexit/si_mem_available: {e}")))?);
                run_init_prog(&skel.progs.procfast_mem_init)?;
                std::mem::forget(skel);
                Ok(c)
            })() {
                Ok(c) => mem_collector = Some(c),
                Err(e) => log::warn!("mem collector unavailable: {e}"),
            }
        }

        if self.enable_net {
            match (|| -> Result<_, ProcfastError> {
                let builder = skel::net::NetSkelBuilder::default();
                let open = builder.open(&mut storage._net_obj)
                    .map_err(|e| ProcfastError::BpfLoad(e.to_string()))?;
                let mut skel = open.load()
                    .map_err(|e| ProcfastError::BpfLoad(e.to_string()))?;
                write_config(&skel.maps.net_config, &config)?;
                let c = NetCollector::from_fd(skel.maps.net_data.as_fd())?;
                if let Some(ref dir) = self.pin_path {
                    pin_map(&mut skel.maps.net_data, dir, "net_data")?;
                }
                links.push(skel.progs.fexit_dev_get_stats.attach()
                    .map_err(|e| ProcfastError::BpfLoad(format!("attach fexit/dev_get_stats: {e}")))?);
                run_init_prog(&skel.progs.procfast_net_init)?;
                std::mem::forget(skel);
                Ok(c)
            })() {
                Ok(c) => net_collector = Some(c),
                Err(e) => log::warn!("net collector unavailable: {e}"),
            }
        }

        if self.enable_disk {
            match (|| -> Result<_, ProcfastError> {
                let builder = skel::disk::DiskSkelBuilder::default();
                let open = builder.open(&mut storage._disk_obj)
                    .map_err(|e| ProcfastError::BpfLoad(e.to_string()))?;
                let mut skel = open.load()
                    .map_err(|e| ProcfastError::BpfLoad(e.to_string()))?;
                write_config(&skel.maps.disk_config, &config)?;
                let c = DiskCollector::from_fd(skel.maps.disk_data.as_fd())?;
                if let Some(ref dir) = self.pin_path {
                    pin_map(&mut skel.maps.disk_data, dir, "disk_data")?;
                }
                links.push(skel.progs.fentry_diskstats_show.attach()
                    .map_err(|e| ProcfastError::BpfLoad(format!("attach fentry/diskstats_show: {e}")))?);
                links.push(skel.progs.block_rq_complete.attach()
                    .map_err(|e| ProcfastError::BpfLoad(format!("attach block_rq_complete: {e}")))?);
                run_init_prog(&skel.progs.procfast_disk_init)?;
                std::mem::forget(skel);
                Ok(c)
            })() {
                Ok(c) => disk_collector = Some(c),
                Err(e) => log::warn!("disk collector unavailable: {e}"),
            }
        }

        if self.enable_thermal {
            match (|| -> Result<_, ProcfastError> {
                let builder = skel::thermal::ThermalSkelBuilder::default();
                let open = builder.open(&mut storage._thermal_obj)
                    .map_err(|e| ProcfastError::BpfLoad(e.to_string()))?;
                let mut skel = open.load()
                    .map_err(|e| ProcfastError::BpfLoad(e.to_string()))?;
                write_config(&skel.maps.thermal_config, &config)?;
                let c = ThermalCollector::from_fd(skel.maps.thermal_data.as_fd())?;
                if let Some(ref dir) = self.pin_path {
                    pin_map(&mut skel.maps.thermal_data, dir, "thermal_data")?;
                }
                links.push(skel.progs.fexit_thermal_zone_get_temp.attach()
                    .map_err(|e| ProcfastError::BpfLoad(format!("attach fexit/thermal_zone_get_temp: {e}")))?);
                run_init_prog(&skel.progs.procfast_thermal_init)?;
                std::mem::forget(skel);
                Ok(c)
            })() {
                Ok(c) => thermal_collector = Some(c),
                Err(e) => log::warn!("thermal collector unavailable: {e}"),
            }
        }

        if self.enable_irq {
            match (|| -> Result<_, ProcfastError> {
                let builder = skel::irq::IrqSkelBuilder::default();
                let open = builder.open(&mut storage._irq_obj)
                    .map_err(|e| ProcfastError::BpfLoad(e.to_string()))?;
                let mut skel = open.load()
                    .map_err(|e| ProcfastError::BpfLoad(e.to_string()))?;
                let percpu_handle = MapHandle::try_from(&skel.maps.irq_counts)
                    .map_err(|e| ProcfastError::BpfLoad(format!("MapHandle for irq_counts: {e}")))?;
                let metadata_handle = MapHandle::try_from(&skel.maps.irq_metadata)
                    .map_err(|e| ProcfastError::BpfLoad(format!("MapHandle for irq_metadata: {e}")))?;
                let c = IrqCollector::new(percpu_handle, metadata_handle);
                if let Some(ref dir) = self.pin_path {
                    pin_map(&mut skel.maps.irq_counts, dir, "irq_counts")?;
                    pin_map(&mut skel.maps.irq_metadata, dir, "irq_metadata")?;
                }
                links.push(skel.progs.fentry_handle_irq_event.attach()
                    .map_err(|e| ProcfastError::BpfLoad(format!("attach fentry/handle_irq_event: {e}")))?);
                links.push(skel.progs.softirq_entry.attach()
                    .map_err(|e| ProcfastError::BpfLoad(format!("attach softirq_entry: {e}")))?);
                run_init_prog(&skel.progs.procfast_irq_init)?;
                std::mem::forget(skel);
                Ok(c)
            })() {
                Ok(c) => irq_collector = Some(c),
                Err(e) => log::warn!("irq collector unavailable: {e}"),
            }
        }

        if self.enable_proc {
            match (|| -> Result<_, ProcfastError> {
                let builder = skel::proc::ProcSkelBuilder::default();
                let open = builder.open(&mut storage._proc_obj)
                    .map_err(|e| ProcfastError::BpfLoad(e.to_string()))?;
                let mut skel = open.load()
                    .map_err(|e| ProcfastError::BpfLoad(e.to_string()))?;
                write_config(&skel.maps.proc_config, &config)?;
                if let Some(ref dir) = self.pin_path {
                    pin_map(&mut skel.maps.proc_header, dir, "proc_header")?;
                    pin_map(&mut skel.maps.proc_stats, dir, "proc_stats")?;
                    pin_map(&mut skel.maps.proc_events, dir, "proc_events")?;
                }
                let header_fd = skel.maps.proc_header.as_fd();
                let stats_handle = MapHandle::try_from(&skel.maps.proc_stats)
                    .map_err(|e| ProcfastError::BpfLoad(format!("MapHandle for proc_stats: {e}")))?;
                let events_fd = skel.maps.proc_events.as_fd().as_raw_fd();
                let c = ProcCollector::new(header_fd, stats_handle, events_fd)?;
                links.push(skel.progs.procfast_sched_switch.attach()
                    .map_err(|e| ProcfastError::BpfLoad(format!("attach sched_switch: {e}")))?);
                links.push(skel.progs.sched_process_fork.attach()
                    .map_err(|e| ProcfastError::BpfLoad(format!("attach sched_process_fork: {e}")))?);
                links.push(skel.progs.sched_process_exec.attach()
                    .map_err(|e| ProcfastError::BpfLoad(format!("attach sched_process_exec: {e}")))?);
                links.push(skel.progs.sched_process_exit.attach()
                    .map_err(|e| ProcfastError::BpfLoad(format!("attach sched_process_exit: {e}")))?);

                // Run task iterator to populate existing processes.
                // BPF iterators require creating a separate read fd via
                // bpf_link__create_iter (not reading the link fd directly).
                let link = skel.progs.procfast_proc_dump_task.attach()
                    .map_err(|e| ProcfastError::BpfLoad(format!("attach task iter: {e}")))?;

                // Create an iterator fd from the link
                let link_fd = link.as_fd().as_raw_fd();
                let iter_fd = unsafe {
                    libbpf_rs::libbpf_sys::bpf_iter_create(link_fd)
                };
                if iter_fd >= 0 {
                    let mut iter_file = unsafe { std::fs::File::from_raw_fd(iter_fd) };
                    let mut buf = [0u8; 4096];
                    loop {
                        match iter_file.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(_) => continue,
                        }
                    }
                    // iter_file will be dropped and closed here (we own this fd)
                } else {
                    log::warn!("failed to create task iterator fd: {}", std::io::Error::last_os_error());
                }

                run_init_prog(&skel.progs.procfast_proc_init)?;
                std::mem::forget(skel);
                Ok(c)
            })() {
                Ok(c) => proc_collector = Some(c),
                Err(e) => log::warn!("proc collector unavailable: {e}"),
            }
        }

        if self.enable_fd {
            match (|| -> Result<_, ProcfastError> {
                let builder = skel::fd::FdSkelBuilder::default();
                let open = builder.open(&mut storage._fd_obj)
                    .map_err(|e| ProcfastError::BpfLoad(e.to_string()))?;
                let mut skel = open.load()
                    .map_err(|e| ProcfastError::BpfLoad(e.to_string()))?;

                if let Some(ref dir) = self.pin_path {
                    pin_map(&mut skel.maps.fd_entries, dir, "fd_entries")?;
                }

                let fd_handle = MapHandle::try_from(&skel.maps.fd_entries)
                    .map_err(|e| ProcfastError::BpfLoad(format!("MapHandle for fd_entries: {e}")))?;
                let c = FdCollector::new(fd_handle);

                // Attach openat and close hooks
                links.push(skel.progs.procfast_fexit_openat2.attach()
                    .map_err(|e| ProcfastError::BpfLoad(format!("attach fexit/do_sys_openat2: {e}")))?);
                links.push(skel.progs.procfast_fentry_close_fd.attach()
                    .map_err(|e| ProcfastError::BpfLoad(format!("attach fentry/close_fd: {e}")))?);

                // Run task_file iterator to populate existing fds
                let link = skel.progs.procfast_fd_dump_task_file.attach()
                    .map_err(|e| ProcfastError::BpfLoad(format!("attach task_file iter: {e}")))?;
                let link_fd = link.as_fd().as_raw_fd();
                let iter_fd = unsafe {
                    libbpf_rs::libbpf_sys::bpf_iter_create(link_fd)
                };
                if iter_fd >= 0 {
                    let mut iter_file = unsafe { std::fs::File::from_raw_fd(iter_fd) };
                    let mut buf = [0u8; 4096];
                    loop {
                        match iter_file.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(_) => continue,
                        }
                    }
                } else {
                    log::warn!("failed to create task_file iterator fd: {}", std::io::Error::last_os_error());
                }

                std::mem::forget(skel);
                Ok(c)
            })() {
                Ok(c) => fd_collector = Some(c),
                Err(e) => log::warn!("fd collector unavailable: {e}"),
            }
        }

        // Socket iterator — enumerate all TCP/UDP sockets
        if self.enable_fd {
            match (|| -> Result<_, ProcfastError> {
                let builder = skel::sock::SockSkelBuilder::default();
                let open = builder.open(&mut storage._sock_obj)
                    .map_err(|e| ProcfastError::BpfLoad(e.to_string()))?;
                let mut skel = open.load()
                    .map_err(|e| ProcfastError::BpfLoad(e.to_string()))?;

                let sock_handle = MapHandle::try_from(&skel.maps.sock_entries)
                    .map_err(|e| ProcfastError::BpfLoad(format!("MapHandle for sock_entries: {e}")))?;

                // Run TCP iterator to populate socket map
                let tcp_link = skel.progs.procfast_iter_tcp.attach()
                    .map_err(|e| ProcfastError::BpfLoad(format!("attach iter/tcp: {e}")))?;
                let tcp_iter_fd = unsafe { libbpf_rs::libbpf_sys::bpf_iter_create(tcp_link.as_fd().as_raw_fd()) };
                if tcp_iter_fd >= 0 {
                    let mut f = unsafe { std::fs::File::from_raw_fd(tcp_iter_fd) };
                    let mut buf = [0u8; 4096];
                    loop { match f.read(&mut buf) { Ok(0) | Err(_) => break, _ => {} } }
                }

                // Run UDP iterator
                let udp_link = skel.progs.procfast_iter_udp.attach()
                    .map_err(|e| ProcfastError::BpfLoad(format!("attach iter/udp: {e}")))?;
                let udp_iter_fd = unsafe { libbpf_rs::libbpf_sys::bpf_iter_create(udp_link.as_fd().as_raw_fd()) };
                if udp_iter_fd >= 0 {
                    let mut f = unsafe { std::fs::File::from_raw_fd(udp_iter_fd) };
                    let mut buf = [0u8; 4096];
                    loop { match f.read(&mut buf) { Ok(0) | Err(_) => break, _ => {} } }
                }

                // Run Unix iterator
                let unix_link = skel.progs.procfast_iter_unix.attach()
                    .map_err(|e| ProcfastError::BpfLoad(format!("attach iter/unix: {e}")))?;
                let unix_iter_fd = unsafe { libbpf_rs::libbpf_sys::bpf_iter_create(unix_link.as_fd().as_raw_fd()) };
                if unix_iter_fd >= 0 {
                    let mut f = unsafe { std::fs::File::from_raw_fd(unix_iter_fd) };
                    let mut buf = [0u8; 4096];
                    loop { match f.read(&mut buf) { Ok(0) | Err(_) => break, _ => {} } }
                }

                let c = SockCollector::new(sock_handle);
                if let Some(ref dir) = self.pin_path {
                    pin_map(&mut skel.maps.sock_entries, dir, "sock_entries")?;
                }
                std::mem::forget(skel);
                Ok(c)
            })() {
                Ok(c) => sock_collector = Some(c),
                Err(e) => log::warn!("sock collector unavailable: {e}"),
            }
        }

        // Seed collectors by reading /proc and /sys once to populate
        // BPF maps with existing data. Tracepoints then keep them updated.
        if mem_collector.is_some() { seed::seed_mem(); }
        if net_collector.is_some() { seed::seed_net(); }
        if disk_collector.is_some() { seed::seed_disk(); }
        if thermal_collector.is_some() { seed::seed_thermal(); }
        if let Some(ref irq) = irq_collector { seed::seed_interrupts(irq); }

        // Make pinned maps readable by non-root users
        if self.public {
            if let Some(ref dir) = self.pin_path {
                make_public(dir);
            }
        }

        // Give the BPF timer a moment to snapshot the seeded data
        std::thread::sleep(std::time::Duration::from_millis(100));

        Ok(Procfast {
            cpu: cpu_collector,
            mem: mem_collector,
            net: net_collector,
            disk: disk_collector,
            thermal: thermal_collector,
            irq: irq_collector,
            proc: proc_collector,
            fd: fd_collector,
            sock: sock_collector,
            _storage: storage,
            _links: links,
        })
    }
}

fn write_config(map: &libbpf_rs::Map, config: &procfast_common::ProcfastConfig) -> Result<(), ProcfastError> {
    let key = 0u32.to_ne_bytes();
    let value = bytemuck::bytes_of(config);
    map.update(&key, value, libbpf_rs::MapFlags::ANY)
        .map_err(|e| ProcfastError::BpfRun(format!("config update: {e}")))
}

fn run_init_prog(prog: &libbpf_rs::ProgramMut) -> Result<(), ProcfastError> {
    prog.test_run(ProgramInput::default())
        .map_err(|e| ProcfastError::BpfRun(format!("init prog_test_run: {e}")))?;
    Ok(())
}

fn make_public(dir: &str) {
    use std::os::unix::fs::PermissionsExt;
    // Ensure parent directory (e.g. /sys/fs/bpf) is traversable
    if let Some(parent) = std::path::Path::new(dir).parent() {
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755));
    }
    // Set our directory to 0o755 (rwxr-xr-x)
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));
    // Set each pinned map file to 0o644 (rw-r--r--)
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let _ = std::fs::set_permissions(
                entry.path(),
                std::fs::Permissions::from_mode(0o644),
            );
        }
    }
}

fn pin_map(map: &mut libbpf_rs::MapMut, dir: &str, name: &str) -> Result<(), ProcfastError> {
    let path = format!("{dir}/{name}");
    // Remove stale pin if it exists from a previous run
    let _ = std::fs::remove_file(&path);
    map.pin(&path)
        .map_err(|e| ProcfastError::Pin(format!("pin {name}: {e}")))
}
