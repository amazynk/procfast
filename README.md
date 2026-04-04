# procfast — fast /proc and /sys replacement via eBPF

Meta recently submitted a kernel patch improving `/proc/interrupts` performance by 29% on high core count machines. That's a meaningful improvement at the kernel level. But we thought: what if we could skip `/proc` entirely? We solved that problem — reading interrupt data went from 118 µs to 2.9 µs, a 41x improvement. Then we kept going.

Ever wondered why `top` appears in `top`? It shouldn't have to. A tool that shows you what's using CPU shouldn't itself be one of the things using CPU. We fixed that — patched `top` uses literally no CPU to gather data (it's just reading memory), and only a tiny bit to actually display it. It no longer registers in its own output. Then we did the same for `htop`, `btop`, and `lsof`.

## The problem

Reading `/proc` and `/sys` on Linux can be expensive. Every read involves open/read/close syscalls, kernel-side text formatting (sprintf), and userspace text parsing (sscanf). On a 256-CPU machine, a single read of `/proc/interrupts` generates over 100KB of text and takes hundreds of microseconds. `/proc/stat`, `/proc/meminfo`, `/proc/net/dev` — all the same story, and if you want it at a higher resolution, the overhead becomes significant.

Tools like `top`, `htop`, `btop`, and `lsof` read these files thousands of times per second. On a standard desktop with ~700 processes, `htop` performs over 250,000 syscalls per refresh cycle. `lsof` is worse — it does a `readlink()` on every file descriptor of every process, routinely taking 50+ seconds to complete — and now taking under a second with procfast. Things are much worse on a loaded server with thousands of processes and tens of thousands of open file descriptors.

## The approach

procfast uses eBPF to read the same kernel data structures that `/proc` and `/sys` expose, but without the VFS overhead:

- **No syscalls per metric read.** Data lands in BPF maps, readable via mmap — a pointer dereference, not a syscall.
- **No text serialization.** Structured binary data, not sprintf/sscanf round trips.
- **No per-file locks.** BPF reads atomic counters directly.
- **Batch collection.** One BPF timer or tracepoint captures dozens of metrics atomically.

The BPF programs attach to kernel functions (`fexit/si_meminfo`, `fexit/dev_get_stats`, `fentry/handle_irq_event`, scheduler tracepoints, etc.) and write structured data into mmapable BPF maps. Userspace reads them with zero-copy mmap access protected by a seqlock.

## What we built

A daemon (`procfastd`) that loads 8 BPF programs covering CPU, memory, network, disk, interrupts, thermal, per-process stats, and open file descriptors. A CLI (`procfast`) for querying metrics. A Prometheus exporter. A standalone `procfast-lsof`. A C client library (`procfast_client.h`) that any project can drop in. And patches for `top`, `htop`, `btop`, and `lsof`.

### Benchmark results

Measured on a 16-core AMD system with ~700 processes, 10,000 iterations:

| Metric | /proc | procfast | Speedup |
|---|---|---|---|
| CPU stats | 25.5 µs | 0.72 µs | **35x** |
| Memory stats | 9.9 µs | 0.01 µs | **1,500x** |
| Network stats | 58.6 µs | 0.07 µs | **850x** |
| Disk stats | 95.7 µs | 0.15 µs | **625x** |
| Interrupts | 118 µs | 2.9 µs | **41x** |
| Thermal | 641 µs | 0.02 µs | **26,000x** |
| Process list (700 procs) | 4.5 ms | 0.13 ms | **35x** |
| File descriptors (22k fds) | 57 ms | 4.9 ms | **12x** |
| Sockets (2,300 sockets) | 2.5 ms | 0.34 ms | **7x** |
| Cgroups (295 cgroups) | 3.4 ms | 0.05 ms | **67x** |

Socket speedup scales with connection count — `/proc/net/tcp` walks the entire kernel hash table and formats each entry as text. On a loaded server with 50,000+ connections, this becomes a significant bottleneck.

### Tool patches

| Tool | Flag | Effect |
|---|---|---|
| **top** (procps-ng) | `--procfast` | /proc opens drop from 1,370 to 15 per refresh. All per-PID file reads eliminated. |
| **htop** | `--procfast` | 57x less CPU, 43x fewer syscalls. Process data from one BPF batch read. |
| **btop** | `--procfast` | CPU, memory, and process data from BPF maps. No /proc/stat or /proc/meminfo reads. |
| **lsof** | `-B` | 85x faster (0.6s vs 54s). Full output with cwd/rtd/txt/mem entries. |

The patched tools produce output matching their normal mode. `top --procfast` shows the same PRI, NI, VIRT, RES, SHR, %CPU, %MEM columns. `lsof -B` shows the same TYPE, DEVICE, SIZE/OFF, NODE, NAME columns. The difference is what happens underneath.

An [LD_PRELOAD library](procfast-preload/README.md) is also available for testing with unmodified binaries (`LD_PRELOAD=libprocfast_preload.so top`). It intercepts `/proc` reads and serves data from BPF maps, eliminating 99.6% of syscalls. However, it must format binary data back into `/proc`-compatible text, which the tool then parses back into numbers — a round trip that limits the speedup to ~10%. The native patches avoid this entirely by reading binary data directly, which is why they're 3-5x faster. The preload is useful mainly for testing and for tools that can't be patched.

### Architecture

```
procfastd (root)               procfast CLI / patched tools (any user with CAP_BPF)
┌──────────────────┐           ┌──────────────────────┐
│ 8 BPF programs   │  pins     │ opens pinned maps    │
│ attached to      │──────────>│ mmap for zero-copy   │
│ kernel functions │  bpffs    │ batch read for procs │
│                  │           │ readlink/stat for    │
│ writes to BPF    │           │ enrichment           │
│ maps via timers  │           └──────────────────────┘
│ and tracepoints  │
└──────────────────┘
```

### Data sources

| Collector | Kernel hook | Replaces |
|---|---|---|
| CPU | `bpf_per_cpu_ptr(kernel_cpustat)` + timer | `/proc/stat` |
| Memory | `fexit/si_meminfo` + `fexit/si_mem_available` | `/proc/meminfo` |
| Network | `fexit/dev_get_stats` | `/proc/net/dev` |
| Disk | `fentry/diskstats_show` + `tp_btf/block_rq_complete` | `/proc/diskstats` |
| Interrupts | `fentry/handle_irq_event` + `tp_btf/softirq_entry` | `/proc/interrupts` |
| Thermal | `fexit/thermal_zone_get_temp` | `/sys/class/thermal/*/temp` |
| Processes | scheduler tracepoints + task iterator | `/proc/[pid]/stat` |
| File descriptors | `fexit/do_sys_openat2` + `fentry/close_fd` + task_file iterator | `/proc/[pid]/fd/*` |
| Sockets | `iter/tcp` + `iter/udp` + `iter/unix` BPF iterators | `/proc/net/tcp`, `/proc/net/udp`, `/proc/net/unix` |
| Cgroups | `iter/cgroup` BPF iterator | `/sys/fs/cgroup/*/cpu.stat`, `memory.current` |

### Cgroup support

The cgroup collector (enabled with `procfastd --cgroup`) walks the entire cgroup v2 hierarchy via `iter/cgroup` and reads stats directly from kernel data structures. Per cgroup, it provides:

- **CPU**: total/user/system usage, weight (shares), quota/period, throttle count and time
- **Memory**: current usage, limit, swap usage
- **PIDs**: current count and limit
- **PSI**: cpu/memory/io pressure (some + full), cumulative microseconds
- **Freeze**: effective frozen state
- **Hierarchy**: id, parent id, name, level, descendant count (paths reconstructed in userspace)

On a system with 295 cgroups, reading all stats takes 52 µs vs 3.4 ms via sysfs (67x faster). On a Kubernetes node with thousands of cgroups, the improvement is larger — each sysfs read involves a VFS open/read/close cycle plus text formatting.

**Memory breakdown:** Per-cgroup cache and RSS are derived by aggregating per-process `mm->rss_stat` counters (which are always accurate) grouped by each process's `cgroup_id`. This works well for leaf cgroups where processes run. For parent cgroups, `memory.current` (from `page_counter.usage`, an atomic counter) shows the accurate hierarchical total. The kernel's `memcg_vmstats->state[]` breakdown (used by `memory.stat`) requires `cgroup_rstat_flush()` to aggregate percpu deltas, which BPF cannot trigger — see the Future hope section.

### Requirements

- Linux 5.15+ (for `bpf_timer`)
- `CONFIG_DEBUG_INFO_BTF=y`
- `CAP_BPF` + `CAP_PERFMON` (or root)

### Quick start

```bash
# Build
bpftool btf dump file /sys/kernel/btf/vmlinux format c > procfast-bpf/src/vmlinux.h
cargo build --release

# Run daemon
sudo ./target/release/procfastd          # basic metrics
sudo ./target/release/procfastd --fd     # also track open files + sockets
sudo ./target/release/procfastd --cgroup # also track cgroup stats

# Query
sudo ./target/release/procfast cpu       # per-CPU time breakdown
sudo ./target/release/procfast mem       # memory stats
sudo ./target/release/procfast net       # network interface stats
sudo ./target/release/procfast irq       # interrupt counts (per-CPU)
sudo ./target/release/procfast top       # live process view
sudo ./target/release/procfast ps        # process list snapshot
sudo ./target/release/procfast fd        # open file descriptors (needs --fd)
sudo ./target/release/procfast sock      # TCP/UDP/Unix sockets (needs --fd)
sudo ./target/release/procfast cgroup    # cgroup CPU/memory/PIDs (needs --cgroup)
sudo ./target/release/procfast json cpu  # JSON output for scripting

# Patched tools (after applying patches)
sudo top --procfast
sudo htop --procfast
sudo btop --procfast
sudo lsof -B

# Run integration tests
sudo ./tests/integration.sh
```

### Project structure

| Crate | Purpose |
|---|---|
| `procfast-common` | Shared `#[repr(C)]` types (Rust + C layout match) |
| `procfast` | Core library — loads BPF, manages collectors |
| `procfast-client` | Reads pinned maps (for daemon+client mode) |
| `procfast-cli` | `procfast` command-line tool |
| `procfastd` | Daemon — loads BPF programs, pins maps |
| `procfast-bench` | Benchmarks vs /proc |
| `procfast-exporter` | Prometheus metrics exporter |
| `procfast-lsof` | Standalone fast lsof replacement |
| `procfast-native` | Single-header C client library |
| `procfast-preload` | LD_PRELOAD library for unmodified binaries ([docs](procfast-preload/README.md)) |
| `patches/` | Patches for top, htop, btop, lsof |

### Beyond top and lsof

We started with `top`, `htop`, `btop`, and `lsof`, but the same approach applies to anything that polls `/proc` or `/sys`:

- **Monitoring agents** (Prometheus node_exporter, Datadog, Telegraf, collectd, Netdata) — the single largest consumer of `/proc` reads on most servers. A node_exporter scrape on a 5,000-process server does 20,000+ file reads per cycle. With procfast, that drops to a handful of mmap reads.
- **Container infrastructure** (cAdvisor, kubelet, containerd) — reads cgroup stats and per-container process data every collection cycle. On a busy Kubernetes node this is a meaningful fraction of CPU overhead.
- **Socket statistics** (`ss`, `nethogs`) — `/proc/net/tcp` iterates the entire kernel socket hash table as text. A BPF socket iterator would return the same data instantly.
- **Process accounting** (`atop`, `sysstat`/`sar`, `pidstat`, `iotop`) — same pattern as top, same fix.
- **Shell scripts and cron jobs** — the thousands of scripts that call `ps`, `pgrep`, `pidof`, or parse `/proc` directly.

The pattern is always the same: open a text file in `/proc`, read it, parse it, close it, repeat. procfast replaces that with: mmap a binary map, read structured data.

### Future hope

procfast works today, but it's more complex than it needs to be. Much of that complexity exists to work around kernel limitations rather than solve the actual problem. A handful of kernel changes would make projects like this dramatically simpler:

- **Kernel-maintained mmapable stats maps.** The kernel already has CPU counters, memory counters, and per-device network stats in memory. `/proc` just formats them as text. If the kernel exposed these as read-only mmapable BPF maps directly, the entire class of "hook a function, copy data to a map, read via mmap" would collapse to "create map, mmap it, read." All our fexit hooks, BPF timers, and seqlock protocols would become unnecessary.

- **A path for read-only access to pinned BPF maps.** Currently, reading a pinned BPF map requires `CAP_BPF` regardless of filesystem permissions. We understand the security rationale — BPF maps can contain sensitive data. But for maps explicitly pinned and chmod'd for sharing (like system-wide CPU or memory counters), a mechanism for read-only access without full BPF capabilities would let monitoring tools run unprivileged. Perhaps a per-map opt-in flag set at creation time.

- **BTF visibility for key globals.** Variables like `vm_zone_stat`, `vm_node_stat`, and `_totalram_pages` aren't exported via BTF on many kernels, forcing us to use indirect fexit hooks instead of reading the counters directly.

- **BPF iterators that write to maps directly.** Every BPF iterator that populates a map currently goes through a seq_file read dance — attach, create fd, read in a loop, discard output. The actual work happens in the callback. Letting iterators target maps directly would eliminate this overhead.

- **Mmapable hash maps.** Only array maps support `BPF_F_MMAPABLE` today. Process and file descriptor data lives in hash maps, requiring batch syscalls instead of zero-copy mmap reads.

- **BPF access to flushed cgroup memory stats.** Per-cgroup memory breakdown (`memory.stat` values like cache, RSS, slab) lives in `memcg_vmstats->state[]`, but this array only reflects data from the last `cgroup_rstat_flush()`. BPF programs cannot trigger this flush, and `bpf_per_cpu_ptr()` is rejected by the verifier on `memcg_vmstats_percpu` pointers, preventing direct percpu aggregation. A BPF helper like `bpf_cgroup_rstat_flush()` or allowing `bpf_per_cpu_ptr()` on memory cgroup percpu stats would let BPF programs read accurate per-cgroup memory breakdowns. Today, only `page_counter.usage` (the total) is always accurate from BPF — the detailed breakdown requires reading the text files.

With these changes, procfast could shrink from eight BPF programs and several thousand lines of workaround code to something closer to: create a few kernel-provided maps, mmap them, read structured data. We'd welcome any of them.

### Thank you

- **Claude** — You're the best.

### License

MIT OR Apache-2.0
