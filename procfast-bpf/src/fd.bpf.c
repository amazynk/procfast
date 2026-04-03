// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "procfast.h"

/*
 * File descriptor tracker.
 *
 * Replaces the expensive /proc/[pid]/fd/ readlink approach used by lsof.
 * Instead of iterating every process's fd directory (which requires
 * opendir + readlink per fd per process), we hook openat/close in the
 * kernel and maintain a live hash map of (pid, fd) -> file info.
 *
 * == The problem ==
 *
 * lsof on a system with 1000 processes, each with 50 open files:
 *   - 1000 opendir("/proc/[pid]/fd")
 *   - 50000 readlink("/proc/[pid]/fd/N")
 *   - 1000 closedir
 *   = ~52000 syscalls, each requiring VFS path resolution
 *
 * == Our approach ==
 *
 *   fexit/do_sys_openat2  -> capture file opens, store path + metadata
 *   fentry/close_fd       -> remove entry on close
 *   iter/task_file         -> populate existing fds at startup
 *
 * Userspace reads the hash map directly -- zero syscalls per query.
 */

/*
 * FD info hash map.
 * Key: u64 = (tgid << 32) | fd
 * Value: struct procfast_fd_info
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PROCFAST_MAX_FDS);
	__type(key, __u64);
	__type(value, struct procfast_fd_info);
} fd_entries SEC(".maps");

/*
 * fexit/do_sys_openat2: capture successful file opens.
 *
 * do_sys_openat2(int dfd, const char __user *filename, struct open_how *how)
 * returns long (the new fd on success, negative errno on failure).
 */
SEC("fexit/do_sys_openat2")
int BPF_PROG(procfast_fexit_openat2, int dfd, const char *filename,
	     struct open_how *how, long ret)
{
	/* Only track successful opens */
	if (ret < 0)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	__u32 fd = (__u32)ret;

	__u64 key = ((__u64)tgid << 32) | fd;

	struct procfast_fd_info info = {};
	info.pid = tgid;
	info.fd = fd;
	info.open_time_ns = bpf_ktime_get_ns();

	/* Read open flags from the open_how struct */
	if (how)
		info.flags = (__u32)BPF_CORE_READ(how, flags);

	/* Read the filename from userspace */
	if (filename)
		bpf_probe_read_user_str(info.path, sizeof(info.path), filename);

	/* Read inode from the newly opened file:
	 * current->files->fdt->fd[ret_fd]->f_inode->i_ino */
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (task) {
		struct file **fdt_fd = BPF_CORE_READ(task, files, fdt, fd);
		if (fdt_fd) {
			struct file *filp = NULL;
			bpf_core_read(&filp, sizeof(filp), &fdt_fd[fd]);
			if (filp) {
				struct inode *inode = BPF_CORE_READ(filp, f_inode);
				if (inode)
					info.inode = BPF_CORE_READ(inode, i_ino);
			}
		}
	}

	bpf_map_update_elem(&fd_entries, &key, &info, BPF_ANY);

	return 0;
}

/*
 * fentry/close_fd: capture file closes.
 *
 * close_fd(unsigned int fd) -- called when a process closes a file descriptor.
 * We remove the corresponding entry from our hash map.
 */
SEC("fentry/close_fd")
int BPF_PROG(procfast_fentry_close_fd, unsigned int fd)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;

	__u64 key = ((__u64)tgid << 32) | fd;
	bpf_map_delete_elem(&fd_entries, &key);

	return 0;
}

/*
 * Task-file iterator: walks all existing open files at load time.
 *
 * Called from userspace via bpf_link to populate the hash map with
 * files opened before the BPF program loaded. For existing files we
 * cannot recover the original path string passed to openat, so path
 * is left empty. The fd number, pid, and open flags are still useful.
 */
SEC("iter/task_file")
int procfast_fd_dump_task_file(struct bpf_iter__task_file *ctx)
{
	struct task_struct *task = ctx->task;
	struct file *file = ctx->file;
	__u32 fd = ctx->fd;

	if (!task || !file)
		return 0;

	__u32 pid = BPF_CORE_READ(task, pid);
	__u32 tgid = BPF_CORE_READ(task, tgid);

	/* Only track thread group leaders */
	if (pid != tgid)
		return 0;

	__u64 key = ((__u64)tgid << 32) | fd;

	struct procfast_fd_info info = {};
	info.pid = tgid;
	info.fd = fd;
	info.open_time_ns = 0; /* unknown for pre-existing files */
	info.flags = BPF_CORE_READ(file, f_flags);

	/* Read inode number */
	struct inode *inode = BPF_CORE_READ(file, f_inode);
	if (inode)
		info.inode = BPF_CORE_READ(inode, i_ino);

	/* Try to read the path from the file's dentry name.
	 * This gives us the filename component (not full path). */
	struct dentry *dentry = BPF_CORE_READ(file, __f_path.dentry);
	if (dentry) {
		const unsigned char *dname = BPF_CORE_READ(dentry, d_name.name);
		if (dname)
			bpf_probe_read_kernel_str(info.path, sizeof(info.path), dname);
	}

	bpf_map_update_elem(&fd_entries, &key, &info, BPF_NOEXIST);

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
