/*
 * procfast_client.h — Single-header C library for reading procfast metrics.
 *
 * Drop this file into any C/C++ project. No external dependencies
 * beyond Linux headers. Reads data from procfast's pinned BPF maps.
 *
 * Usage:
 *   struct procfast_handle *procfast = procfast_open("/sys/fs/bpf/procfast");
 *   if (!procfast) { ... procfast not running ... }
 *
 *   struct procfast_cpu_data cpu;
 *   procfast_read_cpu(procfast, &cpu);
 *   printf("CPUs: %u\n", cpu.nr_cpus);
 *
 *   struct procfast_proc_stats *procs;
 *   int n = procfast_read_procs(procfast, &procs);
 *   for (int i = 0; i < n; i++)
 *       printf("%d %s\n", procs[i].pid, procs[i].comm);
 *   free(procs);
 *
 *   procfast_close(procfast);
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */

#ifndef PROCFAST_CLIENT_H
#define PROCFAST_CLIENT_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <linux/bpf.h>
#include <sys/syscall.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Data structures (must match procfast-common/src/lib.rs) ---- */

#define PROCFAST_MAX_CPUS         256
#define PROCFAST_MAX_NET_DEVS      32
#define PROCFAST_MAX_DISKS         64
#define PROCFAST_MAX_THERMAL_ZONES 16
#define PROCFAST_MAX_IRQS         512
#define PROCFAST_MAX_FDS        65536
#define PROCFAST_MAX_FD_PATH      256

struct procfast_cpu_stats {
    uint64_t user_ns, nice_ns, system_ns, idle_ns;
    uint64_t iowait_ns, irq_ns, softirq_ns, steal_ns;
    uint64_t guest_ns, guest_nice_ns;
};

struct procfast_cpu_data {
    uint64_t seq;
    uint64_t timestamp_ns;
    uint32_t nr_cpus;
    uint32_t _pad;
    struct procfast_cpu_stats total;
    struct procfast_cpu_stats per_cpu[PROCFAST_MAX_CPUS];
};

struct procfast_mem_data {
    uint64_t seq;
    uint64_t timestamp_ns;
    uint64_t total_bytes, free_bytes, available_bytes;
    uint64_t buffers_bytes, cached_bytes;
    uint64_t swap_total_bytes, swap_free_bytes;
    uint64_t active_bytes, inactive_bytes;
    uint64_t slab_reclaimable_bytes, slab_unreclaimable_bytes;
    uint64_t dirty_bytes, writeback_bytes, shmem_bytes;
};

struct procfast_net_dev_stats {
    uint64_t rx_bytes, tx_bytes, rx_packets, tx_packets;
    uint64_t rx_errors, tx_errors, rx_dropped, tx_dropped;
    char name[16];
};

struct procfast_net_data {
    uint64_t seq;
    uint64_t timestamp_ns;
    uint32_t nr_devs;
    uint32_t _pad;
    struct procfast_net_dev_stats devs[PROCFAST_MAX_NET_DEVS];
};

struct procfast_proc_stats {
    uint32_t pid, tgid, ppid;
    uint8_t  state;
    uint8_t  _pad1[3];
    uint32_t uid, nr_threads;
    char     comm[16];
    uint64_t utime_ns, stime_ns, cutime_ns, cstime_ns;
    int32_t  nice;
    uint32_t policy, last_cpu, rt_priority;
    uint64_t last_seen_ns, vol_ctxsw, invol_ctxsw;
    uint64_t rss_bytes, vsize_bytes, shared_bytes;
    uint64_t read_bytes, write_bytes;
    uint64_t cpu_runtime_ns;
    uint64_t start_time_ns;
    uint64_t cgroup_id;
};

struct procfast_cgroup_stats {
    uint64_t id;
    uint64_t parent_id;
    uint32_t level;
    uint32_t nr_descendants;
    uint64_t cpu_usage_ns;
    uint64_t cpu_user_ns;
    uint64_t cpu_system_ns;
    uint64_t cpu_quota_us;
    uint64_t cpu_period_us;
    uint32_t cpu_weight;
    uint32_t nr_throttled;
    uint64_t throttled_ns;
    uint64_t memory_current;
    uint64_t memory_limit;
    uint64_t memory_swap;
    uint64_t memory_cache;
    uint64_t memory_rss;
    uint64_t memory_slab;
    uint64_t memory_shmem;
    uint64_t nr_pids;
    uint64_t pids_limit;
    uint64_t psi_cpu_some;
    uint64_t psi_cpu_full;
    uint64_t psi_mem_some;
    uint64_t psi_mem_full;
    uint64_t psi_io_some;
    uint64_t psi_io_full;
    uint8_t  frozen;
    uint8_t  _pad1[7];
    char     name[64];
};

struct procfast_proc_header {
    uint64_t seq;
    uint64_t timestamp_ns;
    uint32_t nr_procs;
    uint32_t _pad;
};

struct procfast_sock_info {
    uint64_t inode;
    uint32_t family;      /* AF_INET=2, AF_INET6=10, AF_UNIX=1 */
    uint32_t sock_type;   /* SOCK_STREAM=1, SOCK_DGRAM=2 */
    uint8_t  protocol;    /* IPPROTO_TCP=6, IPPROTO_UDP=17 */
    uint8_t  state;       /* TCP_ESTABLISHED=1, TCP_LISTEN=10, etc. */
    uint16_t _pad;
    uint32_t uid;
    uint32_t local_port;
    uint32_t remote_port;
    uint32_t local_addr4;
    uint32_t remote_addr4;
    uint8_t  local_addr6[16];
    uint8_t  remote_addr6[16];
};

struct procfast_fd_info {
    uint32_t pid;
    uint32_t fd;
    uint64_t open_time_ns;
    uint64_t inode;
    uint32_t flags;
    uint32_t _pad;
    char path[PROCFAST_MAX_FD_PATH];
};

/* ---- Handle ---- */

struct procfast_mmap {
    void   *addr;
    size_t  len;
    int     fd;
};

struct procfast_handle {
    struct procfast_mmap cpu;
    struct procfast_mmap mem;
    struct procfast_mmap net;
    struct procfast_mmap proc_header;
    int proc_stats_fd;
    int fd_entries_fd;
    int sock_entries_fd;
    int cgroup_entries_fd;
    int available;  /* bitmask: 1=cpu, 2=mem, 4=net, 8=proc, 16=fd, 32=sock, 64=cgroup */
};

#define PROCFAST_HAS_CPU    1
#define PROCFAST_HAS_MEM    2
#define PROCFAST_HAS_NET    4
#define PROCFAST_HAS_PROC   8
#define PROCFAST_HAS_FD    16
#define PROCFAST_HAS_SOCK  32
#define PROCFAST_HAS_CGROUP 64

/* ---- Internal helpers ---- */

static inline int procfast__bpf_obj_get(const char *path) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.pathname = (uint64_t)(unsigned long)path;
    return (int)syscall(SYS_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
}

static inline int procfast__open_map(const char *dir, const char *name,
                                  struct procfast_mmap *mm, size_t value_size) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", dir, name);

    int fd = procfast__bpf_obj_get(path);
    if (fd < 0) return -1;

    void *addr = mmap(NULL, value_size, PROT_READ, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        close(fd);
        return -1;
    }

    mm->addr = addr;
    mm->len = value_size;
    mm->fd = fd;
    return 0;
}

static inline void procfast__close_map(struct procfast_mmap *mm) {
    if (mm->addr && mm->addr != MAP_FAILED) {
        munmap(mm->addr, mm->len);
        mm->addr = NULL;
    }
    if (mm->fd >= 0) {
        close(mm->fd);
        mm->fd = -1;
    }
}

/* Seqlock read: copy data while sequence counter is stable */
static inline void procfast__seqlock_read(const void *src, void *dst, size_t len) {
    const volatile uint64_t *seq = (const volatile uint64_t *)src;
    for (;;) {
        uint64_t s1 = *seq;
        if (s1 & 1) { /* writer active */
            __asm__ __volatile__("pause" ::: "memory");
            continue;
        }
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        memcpy(dst, (const void *)src, len);
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        uint64_t s2 = *seq;
        if (s1 == s2) return;
    }
}

/* ---- Public API ---- */

/**
 * Open a connection to procfast's pinned maps.
 * Returns NULL if procfast daemon is not running.
 */
static inline struct procfast_handle *procfast_open(const char *pin_dir) {
    if (!pin_dir) pin_dir = "/sys/fs/bpf/procfast";

    struct stat st;
    if (stat(pin_dir, &st) != 0) return NULL;

    struct procfast_handle *h = (struct procfast_handle *)calloc(1, sizeof(*h));
    if (!h) return NULL;

    h->proc_stats_fd = -1;
    h->fd_entries_fd = -1;
    h->sock_entries_fd = -1;
    h->cgroup_entries_fd = -1;
    h->available = 0;

    if (procfast__open_map(pin_dir, "cpu_data", &h->cpu,
                       sizeof(struct procfast_cpu_data)) == 0)
        h->available |= PROCFAST_HAS_CPU;

    if (procfast__open_map(pin_dir, "mem_data", &h->mem,
                       sizeof(struct procfast_mem_data)) == 0)
        h->available |= PROCFAST_HAS_MEM;

    if (procfast__open_map(pin_dir, "net_data", &h->net,
                       sizeof(struct procfast_net_data)) == 0)
        h->available |= PROCFAST_HAS_NET;

    if (procfast__open_map(pin_dir, "proc_header", &h->proc_header,
                       sizeof(struct procfast_proc_header)) == 0) {
        char path[256];
        snprintf(path, sizeof(path), "%s/proc_stats", pin_dir);
        h->proc_stats_fd = procfast__bpf_obj_get(path);
        if (h->proc_stats_fd >= 0)
            h->available |= PROCFAST_HAS_PROC;
    }

    {
        char path[256];
        snprintf(path, sizeof(path), "%s/fd_entries", pin_dir);
        h->fd_entries_fd = procfast__bpf_obj_get(path);
        if (h->fd_entries_fd >= 0)
            h->available |= PROCFAST_HAS_FD;
    }

    {
        char path[256];
        snprintf(path, sizeof(path), "%s/sock_entries", pin_dir);
        h->sock_entries_fd = procfast__bpf_obj_get(path);
        if (h->sock_entries_fd >= 0)
            h->available |= PROCFAST_HAS_SOCK;
    }

    {
        char path[256];
        snprintf(path, sizeof(path), "%s/cgroup_entries", pin_dir);
        h->cgroup_entries_fd = procfast__bpf_obj_get(path);
        if (h->cgroup_entries_fd >= 0)
            h->available |= PROCFAST_HAS_CGROUP;
    }

    if (h->available == 0) {
        free(h);
        return NULL;
    }

    return h;
}

/** Close handle and free resources. */
static inline void procfast_close(struct procfast_handle *h) {
    if (!h) return;
    procfast__close_map(&h->cpu);
    procfast__close_map(&h->mem);
    procfast__close_map(&h->net);
    procfast__close_map(&h->proc_header);
    if (h->proc_stats_fd >= 0) close(h->proc_stats_fd);
    if (h->fd_entries_fd >= 0) close(h->fd_entries_fd);
    if (h->sock_entries_fd >= 0) close(h->sock_entries_fd);
    if (h->cgroup_entries_fd >= 0) close(h->cgroup_entries_fd);
    free(h);
}

/** Check if a specific data source is available. */
static inline int procfast_has(struct procfast_handle *h, int flag) {
    return h && (h->available & flag);
}

/** Read CPU stats (zero-copy via seqlock). Returns 0 on success. */
static inline int procfast_read_cpu(struct procfast_handle *h, struct procfast_cpu_data *out) {
    if (!procfast_has(h, PROCFAST_HAS_CPU)) return -1;
    procfast__seqlock_read(h->cpu.addr, out, sizeof(*out));
    return 0;
}

/** Read memory stats. Returns 0 on success. */
static inline int procfast_read_mem(struct procfast_handle *h, struct procfast_mem_data *out) {
    if (!procfast_has(h, PROCFAST_HAS_MEM)) return -1;
    procfast__seqlock_read(h->mem.addr, out, sizeof(*out));
    return 0;
}

/** Read network stats. Returns 0 on success. */
static inline int procfast_read_net(struct procfast_handle *h, struct procfast_net_data *out) {
    if (!procfast_has(h, PROCFAST_HAS_NET)) return -1;
    procfast__seqlock_read(h->net.addr, out, sizeof(*out));
    return 0;
}

/**
 * Read all tracked processes via batch lookup.
 * Allocates *out_procs (caller must free). Returns count, or -1 on error.
 */
static inline int procfast_read_procs(struct procfast_handle *h,
                                   struct procfast_proc_stats **out_procs) {
    if (!procfast_has(h, PROCFAST_HAS_PROC)) return -1;

    struct procfast_proc_header hdr;
    procfast__seqlock_read(h->proc_header.addr, &hdr, sizeof(hdr));

    size_t capacity = hdr.nr_procs > 0 ? hdr.nr_procs + 64 : 1024;
    struct procfast_proc_stats *procs = (struct procfast_proc_stats *)
        malloc(capacity * sizeof(struct procfast_proc_stats));
    if (!procs) return -1;

    int fd = h->proc_stats_fd;
    uint32_t key_size = sizeof(uint32_t);
    uint32_t val_size = sizeof(struct procfast_proc_stats);
    uint32_t batch = 512;

    uint32_t *keys = (uint32_t *)malloc(batch * key_size);
    struct procfast_proc_stats *vals = (struct procfast_proc_stats *)
        malloc(batch * val_size);
    if (!keys || !vals) {
        free(keys); free(vals); free(procs);
        return -1;
    }

    int total = 0;
    uint64_t in_batch = 0, out_batch = 0;
    int first = 1;

    struct { uint64_t sz, elem_flags, flags; } opts = {
        .sz = sizeof(opts), .elem_flags = 0, .flags = 0
    };

    for (;;) {
        uint32_t count = batch;

        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.batch.map_fd = fd;
        attr.batch.in_batch = first ? 0 : (uint64_t)(unsigned long)&in_batch;
        attr.batch.out_batch = (uint64_t)(unsigned long)&out_batch;
        attr.batch.keys = (uint64_t)(unsigned long)keys;
        attr.batch.values = (uint64_t)(unsigned long)vals;
        attr.batch.count = count;

        int ret = (int)syscall(SYS_bpf, BPF_MAP_LOOKUP_BATCH,
                               &attr, sizeof(attr));
        count = attr.batch.count;
        first = 0;

        for (uint32_t i = 0; i < count; i++) {
            if ((size_t)total >= capacity) {
                capacity *= 2;
                procs = (struct procfast_proc_stats *)
                    realloc(procs, capacity * sizeof(*procs));
                if (!procs) { free(keys); free(vals); return -1; }
            }
            procs[total++] = vals[i];
        }

        in_batch = out_batch;
        if (ret != 0) break; /* ENOENT = done */
    }

    free(keys);
    free(vals);
    *out_procs = procs;
    return total;
}

/**
 * Look up a single process by PID. Returns 0 on success, -1 if not found.
 */
static inline int procfast_read_proc(struct procfast_handle *h, uint32_t pid,
                                  struct procfast_proc_stats *out) {
    if (!procfast_has(h, PROCFAST_HAS_PROC)) return -1;

    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = h->proc_stats_fd;
    attr.key = (uint64_t)(unsigned long)&pid;
    attr.value = (uint64_t)(unsigned long)out;

    return (int)syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

/**
 * Read all tracked file descriptors via batch lookup.
 * Allocates *out_fds (caller must free). Returns count, or -1 on error.
 */
static inline int procfast_read_fds(struct procfast_handle *h,
                                 struct procfast_fd_info **out_fds) {
    if (!procfast_has(h, PROCFAST_HAS_FD)) return -1;

    size_t capacity = 4096;
    struct procfast_fd_info *fds = (struct procfast_fd_info *)
        malloc(capacity * sizeof(struct procfast_fd_info));
    if (!fds) return -1;

    int fd = h->fd_entries_fd;
    uint32_t batch = 512;

    uint64_t *keys = (uint64_t *)malloc(batch * sizeof(uint64_t));
    struct procfast_fd_info *vals = (struct procfast_fd_info *)
        malloc(batch * sizeof(struct procfast_fd_info));
    if (!keys || !vals) {
        free(keys); free(vals); free(fds);
        return -1;
    }

    int total = 0;
    uint64_t in_batch = 0, out_batch = 0;
    int first = 1;

    for (;;) {
        uint32_t count = batch;

        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.batch.map_fd = fd;
        attr.batch.in_batch = first ? 0 : (uint64_t)(unsigned long)&in_batch;
        attr.batch.out_batch = (uint64_t)(unsigned long)&out_batch;
        attr.batch.keys = (uint64_t)(unsigned long)keys;
        attr.batch.values = (uint64_t)(unsigned long)vals;
        attr.batch.count = count;

        int ret = (int)syscall(SYS_bpf, BPF_MAP_LOOKUP_BATCH,
                               &attr, sizeof(attr));
        count = attr.batch.count;
        first = 0;

        for (uint32_t i = 0; i < count; i++) {
            if ((size_t)total >= capacity) {
                capacity *= 2;
                fds = (struct procfast_fd_info *)
                    realloc(fds, capacity * sizeof(*fds));
                if (!fds) { free(keys); free(vals); return -1; }
            }
            fds[total++] = vals[i];
        }

        in_batch = out_batch;
        if (ret != 0) break; /* ENOENT = done */
    }

    free(keys);
    free(vals);
    *out_fds = fds;
    return total;
}

/**
 * Look up a single file descriptor by PID + fd number.
 * Returns 0 on success, -1 if not found.
 */
static inline int procfast_read_fd(struct procfast_handle *h, uint32_t pid,
                                uint32_t fd_num, struct procfast_fd_info *out) {
    if (!procfast_has(h, PROCFAST_HAS_FD)) return -1;

    uint64_t key = ((uint64_t)pid << 32) | fd_num;

    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = h->fd_entries_fd;
    attr.key = (uint64_t)(unsigned long)&key;
    attr.value = (uint64_t)(unsigned long)out;

    return (int)syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

/**
 * Look up socket info by inode number.
 * Returns 0 on success, -1 if not found.
 */
static inline int procfast_read_sock(struct procfast_handle *h, uint64_t inode,
                                      struct procfast_sock_info *out) {
    if (!procfast_has(h, PROCFAST_HAS_SOCK)) return -1;

    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = h->sock_entries_fd;
    attr.key = (uint64_t)(unsigned long)&inode;
    attr.value = (uint64_t)(unsigned long)out;

    return (int)syscall(SYS_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

/**
 * Read all cgroup stats via batch lookup.
 * Allocates *out_cgroups (caller must free). Returns count, or -1 on error.
 */
static inline int procfast_read_cgroups(struct procfast_handle *h,
                                        struct procfast_cgroup_stats **out_cgroups) {
    if (!procfast_has(h, PROCFAST_HAS_CGROUP)) return -1;

    size_t capacity = 512;
    struct procfast_cgroup_stats *cgroups = (struct procfast_cgroup_stats *)
        malloc(capacity * sizeof(struct procfast_cgroup_stats));
    if (!cgroups) return -1;

    int fd = h->cgroup_entries_fd;
    uint32_t batch = 256;

    uint64_t *keys = (uint64_t *)malloc(batch * sizeof(uint64_t));
    struct procfast_cgroup_stats *vals = (struct procfast_cgroup_stats *)
        malloc(batch * sizeof(struct procfast_cgroup_stats));
    if (!keys || !vals) {
        free(keys); free(vals); free(cgroups);
        return -1;
    }

    int total = 0;
    uint64_t in_batch = 0, out_batch = 0;
    int first = 1;

    for (;;) {
        uint32_t count = batch;

        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.batch.map_fd = fd;
        attr.batch.in_batch = first ? 0 : (uint64_t)(unsigned long)&in_batch;
        attr.batch.out_batch = (uint64_t)(unsigned long)&out_batch;
        attr.batch.keys = (uint64_t)(unsigned long)keys;
        attr.batch.values = (uint64_t)(unsigned long)vals;
        attr.batch.count = count;

        int ret = (int)syscall(SYS_bpf, BPF_MAP_LOOKUP_BATCH,
                               &attr, sizeof(attr));
        count = attr.batch.count;
        first = 0;

        for (uint32_t i = 0; i < count; i++) {
            if ((size_t)total >= capacity) {
                capacity *= 2;
                cgroups = (struct procfast_cgroup_stats *)
                    realloc(cgroups, capacity * sizeof(*cgroups));
                if (!cgroups) { free(keys); free(vals); return -1; }
            }
            cgroups[total++] = vals[i];
        }

        in_batch = out_batch;
        if (ret != 0) break;
    }

    free(keys);
    free(vals);
    *out_cgroups = cgroups;
    return total;
}

#ifdef __cplusplus
}
#endif

#endif /* PROCFAST_CLIENT_H */
