// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "procfast.h"

/*
 * Socket iterator — enumerates all TCP/UDP/Unix sockets.
 * Replaces reading /proc/net/tcp, /proc/net/udp, /proc/net/unix.
 *
 * Each iterator walks the kernel's socket hash table and writes
 * structured binary data into a BPF hash map keyed by inode number.
 * The lsof patch matches socket inodes from fd entries against this map.
 */

struct procfast_sock_info {
	__u64 inode;
	__u32 family;     /* AF_INET=2, AF_INET6=10, AF_UNIX=1 */
	__u32 sock_type;  /* SOCK_STREAM=1, SOCK_DGRAM=2 */
	__u8  protocol;   /* IPPROTO_TCP=6, IPPROTO_UDP=17 */
	__u8  state;      /* TCP_ESTABLISHED=1, TCP_LISTEN=10, etc. */
	__u16 _pad;
	__u32 uid;
	__u32 local_port;
	__u32 remote_port;
	__u32 local_addr4;
	__u32 remote_addr4;
	__u8  local_addr6[16];
	__u8  remote_addr6[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);   /* inode number */
	__type(value, struct procfast_sock_info);
} sock_entries SEC(".maps");

/*
 * TCP iterator: walks all TCP sockets (established, listen, time-wait, etc.)
 */
SEC("iter/tcp")
int procfast_iter_tcp(struct bpf_iter__tcp *ctx)
{
	struct sock_common *sk_common = ctx->sk_common;
	if (!sk_common)
		return 0;

	struct sock *sk = (struct sock *)sk_common;
	struct procfast_sock_info info = {};

	info.family = BPF_CORE_READ(sk_common, skc_family);
	info.state = BPF_CORE_READ(sk_common, skc_state);
	info.protocol = 6; /* IPPROTO_TCP */
	info.sock_type = 1; /* SOCK_STREAM */
	info.uid = ctx->uid;

	/* Get inode from sock -> sk_socket -> sock_inode_cachep */
	struct socket *socket = BPF_CORE_READ(sk, sk_socket);
	if (!socket)
		return 0;

	__u64 ino = 0;
	struct file *filp = BPF_CORE_READ(socket, file);
	if (filp) {
		struct inode *inode_ptr = BPF_CORE_READ(filp, f_inode);
		if (inode_ptr)
			ino = BPF_CORE_READ(inode_ptr, i_ino);
	}
	if (ino == 0)
		return 0;

	info.inode = ino;

	/* Addresses and ports */
	if (info.family == 2) { /* AF_INET */
		/* For IPv4, addresses are in skc_daddr/skc_rcv_saddr via union */
		info.local_addr4 = BPF_CORE_READ(sk_common, skc_rcv_saddr);
		info.remote_addr4 = BPF_CORE_READ(sk_common, skc_daddr);
	} else if (info.family == 10) { /* AF_INET6 */
		BPF_CORE_READ_INTO(&info.local_addr6, sk_common, skc_v6_rcv_saddr);
		BPF_CORE_READ_INTO(&info.remote_addr6, sk_common, skc_v6_daddr);
	}

	/* Ports from inet_sock */
	struct inet_sock *inet = (struct inet_sock *)sk;
	info.local_port = (unsigned int)bpf_ntohs(BPF_CORE_READ(inet, inet_sport));
	info.remote_port = (unsigned int)bpf_ntohs(BPF_CORE_READ(sk_common, skc_dport));

	bpf_map_update_elem(&sock_entries, &ino, &info, BPF_ANY);
	return 0;
}

/*
 * UDP iterator: walks all UDP sockets.
 */
SEC("iter/udp")
int procfast_iter_udp(struct bpf_iter__udp *ctx)
{
	struct udp_sock *udp_sk = ctx->udp_sk;
	if (!udp_sk)
		return 0;

	struct sock *sk = (struct sock *)udp_sk;
	struct sock_common *sk_common = &sk->__sk_common;
	struct procfast_sock_info info = {};

	info.family = BPF_CORE_READ(sk_common, skc_family);
	info.state = BPF_CORE_READ(sk_common, skc_state);
	info.protocol = 17; /* IPPROTO_UDP */
	info.sock_type = 2; /* SOCK_DGRAM */
	info.uid = ctx->uid;

	struct socket *socket = BPF_CORE_READ(sk, sk_socket);
	if (!socket)
		return 0;
	struct file *filp = BPF_CORE_READ(socket, file);
	if (!filp)
		return 0;
	struct inode *inode_ptr2 = BPF_CORE_READ(filp, f_inode);
	__u64 ino = inode_ptr2 ? BPF_CORE_READ(inode_ptr2, i_ino) : 0;
	if (ino == 0)
		return 0;

	info.inode = ino;

	if (info.family == 2) {
		info.local_addr4 = BPF_CORE_READ(sk_common, skc_rcv_saddr);
		info.remote_addr4 = BPF_CORE_READ(sk_common, skc_daddr);
	} else if (info.family == 10) {
		BPF_CORE_READ_INTO(&info.local_addr6, sk_common, skc_v6_rcv_saddr);
		BPF_CORE_READ_INTO(&info.remote_addr6, sk_common, skc_v6_daddr);
	}

	struct inet_sock *inet = (struct inet_sock *)sk;
	info.local_port = (unsigned int)bpf_ntohs(BPF_CORE_READ(inet, inet_sport));
	info.remote_port = (unsigned int)bpf_ntohs(BPF_CORE_READ(sk_common, skc_dport));

	bpf_map_update_elem(&sock_entries, &ino, &info, BPF_ANY);
	return 0;
}

/*
 * Unix socket iterator: walks all AF_UNIX sockets.
 */
SEC("iter/unix")
int procfast_iter_unix(struct bpf_iter__unix *ctx)
{
	struct unix_sock *unix_sk = ctx->unix_sk;
	if (!unix_sk)
		return 0;

	struct sock *sk = (struct sock *)unix_sk;
	struct sock_common *sk_common = &sk->__sk_common;
	struct procfast_sock_info info = {};

	info.family = 1; /* AF_UNIX */
	info.state = BPF_CORE_READ(sk_common, skc_state);
	info.protocol = 0;
	info.sock_type = BPF_CORE_READ(sk, sk_type);
	info.uid = ctx->uid;

	struct socket *socket = BPF_CORE_READ(sk, sk_socket);
	if (!socket)
		return 0;
	struct file *filp = BPF_CORE_READ(socket, file);
	if (!filp)
		return 0;
	struct inode *inode_ptr = BPF_CORE_READ(filp, f_inode);
	__u64 ino = inode_ptr ? BPF_CORE_READ(inode_ptr, i_ino) : 0;
	if (ino == 0)
		return 0;

	info.inode = ino;

	bpf_map_update_elem(&sock_entries, &ino, &info, BPF_ANY);
	return 0;
}

/* No-op init */
SEC("syscall")
int procfast_sock_init(void *ctx)
{
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
