#include "spdk/stdinc.h"

#if defined(__FreeBSD__)
#include <sys/event.h>
#define SPDK_KEVENT
#else
#define SPDK_EPOLL
#endif


#ifdef SPDK_CONFIG_EBPF
#include "ebpf/reuseport_loader.h"
#endif


#include "spdk/env.h"
#include "spdk/log.h"
#include "spdk/pipe.h"
#include "spdk/sock.h"
#include "spdk/util.h"
#include "spdk/string.h"
#include "spdk/net.h"
#include "spdk/log.h"
#include "spdk_internal/sock_module.h"

/* UDP-specific helper functions (copied from sock.c to avoid modifying shared code) */
static struct addrinfo *
udp_getaddrinfo(const char *ip, int port)
{
	struct addrinfo hints, *res;
	char service[32];
	int rc;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;     /* UDP */
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_NUMERICSERV | AI_PASSIVE | AI_NUMERICHOST;


	snprintf(service, sizeof(service), "%d", port);

	/* Handle IPv6 addresses in brackets */
	if (ip != NULL && ip[0] == '[') {
		char *tmp = strdup(ip + 1);
		if (tmp == NULL) {
			return NULL;
		}
		char *end = strchr(tmp, ']');
		if (end != NULL) {
			*end = '\0';
		}
		rc = getaddrinfo(tmp, service, &hints, &res);
		free(tmp);
	} else {
		rc = getaddrinfo(ip, service, &hints, &res);
	}

	if (rc != 0) {
		return NULL;
	}

	return res;
}

#define MAX_TMPBUF 1024
#define IOV_BATCH_SIZE 64
#define MAX_EVENTS_PER_POLL 32
#define DEFAULT_SO_RCVBUF_SIZE (256 * 1024 * 1024)  /* 256 MB - matches kernel net.core.rmem_max */
#define DEFAULT_SO_SNDBUF_SIZE (256 * 1024 * 1024)  /* 256 MB - matches kernel net.core.wmem_max */
#define MIN_SO_RCVBUF_SIZE (256 * 1024)
#define MIN_SO_SNDBUF_SIZE (256 * 1024)

/* recvmmsg() batch receive: drain up to 64 UDP datagrams per syscall */
#define UDP_RECV_BATCH_SIZE     64
#define UDP_RECV_BATCH_BUF_SIZE 65536  /* Support full UDP GRO super-segment (64 KB coalesced packets) */

struct  spdk_udp_sock {
	struct spdk_sock	base;
	int			fd;

	/* Local address cached once at socket creation to avoid getsockname() on every packet */
	struct sockaddr_storage	cached_local_addr;
	socklen_t		cached_local_addr_len;

	/* Remote address for connected UDP sockets */
	struct sockaddr_storage	remote_addr;
	socklen_t		remote_addr_len;
	bool			is_connected;
	bool			zcopy;
	bool			ready;

	int			placement_id;

	TAILQ_ENTRY(spdk_udp_sock)	link;
	
	char			interface_name[IFNAMSIZ];
};

struct spdk_udp_sock_group_impl {
	struct spdk_sock_group_impl	base;
	int				fd;
	struct spdk_interrupt		*intr;
	int				placement_id;
};


static struct spdk_sock_impl_opts g_udp_impl_opts = {
	.recv_buf_size = DEFAULT_SO_RCVBUF_SIZE,
	.send_buf_size = DEFAULT_SO_SNDBUF_SIZE,
	.enable_recv_pipe = false,		/* UDP doesn't need pipe buffering */
	.enable_quickack = false,		/* Not applicable for UDP */
	.enable_placement_id = PLACEMENT_NONE,
	.enable_zerocopy_send_server = false,	/* Typically not used for UDP */
	.enable_zerocopy_send_client = false,
	.zerocopy_threshold = 0,
	.tls_version = 0,
	.enable_ktls = false,
};

/* Forward declaration */
static int _sock_flush(struct spdk_sock *sock);
static struct spdk_sock_map g_map = {
	.entries = STAILQ_HEAD_INITIALIZER(g_map.entries),
	.mtx = PTHREAD_MUTEX_INITIALIZER
};

__attribute((destructor)) static void
udp_sock_map_cleanup(void)
{
	spdk_sock_map_cleanup(&g_map);
}

#define __udp_sock(sock) (struct spdk_udp_sock *)sock
#define __udp_group_impl(group) (struct spdk_udp_sock_group_impl *)group

#ifdef __linux__
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef UDP_GRO
#define UDP_GRO 104
#endif
#ifndef SOL_UDP
#define SOL_UDP 17
#endif
#endif /* __linux__ */

#ifdef SPDK_CONFIG_EBPF
#ifndef SO_ATTACH_REUSEPORT_EBPF
#define SO_ATTACH_REUSEPORT_EBPF 51
#endif
#endif

static int
udp_sock_getaddr(struct spdk_sock *_sock, char *saddr, int slen, uint16_t *sport,
		 char *caddr, int clen, uint16_t *cport)
{
	struct spdk_udp_sock *sock = __udp_sock(_sock);
	struct sockaddr_storage local_addr;
	socklen_t local_len = sizeof(local_addr);
	int rc;

	/* Use cached local address — populated once at socket creation */
	if (saddr != NULL || sport != NULL) {
		const struct sockaddr_storage *la;

		if (sock->cached_local_addr.ss_family != 0) {
			la = &sock->cached_local_addr;
		} else {
			/* Fallback: cache was not populated at alloc time (shouldn't happen) */
			rc = getsockname(sock->fd, (struct sockaddr *)&local_addr, &local_len);
			if (rc != 0) {
				return -1;
			}
			/* Populate cache for future calls */
			sock->cached_local_addr = local_addr;
			sock->cached_local_addr_len = local_len;
			la = &sock->cached_local_addr;
		}

		if (saddr != NULL) {
			if (la->ss_family == AF_INET) {
				const struct sockaddr_in *addr_in = (const struct sockaddr_in *)la;
				inet_ntop(AF_INET, &addr_in->sin_addr, saddr, slen);
			} else if (la->ss_family == AF_INET6) {
				const struct sockaddr_in6 *addr_in6 = (const struct sockaddr_in6 *)la;
				inet_ntop(AF_INET6, &addr_in6->sin6_addr, saddr, slen);
			}
		}

		if (sport != NULL) {
			if (la->ss_family == AF_INET) {
				const struct sockaddr_in *addr_in = (const struct sockaddr_in *)la;
				*sport = ntohs(addr_in->sin_port);
				SPDK_DEBUGLOG(sock_udp, "UDP cached local port %u for fd %d\n", *sport, sock->fd);
			} else if (la->ss_family == AF_INET6) {
				const struct sockaddr_in6 *addr_in6 = (const struct sockaddr_in6 *)la;
				*sport = ntohs(addr_in6->sin6_port);
				SPDK_DEBUGLOG(sock_udp, "UDP cached local port %u for fd %d\n", *sport, sock->fd);
			}
		}
	}

	/* Get remote address from stored value (populated by recvmsg) */
	if (caddr != NULL || cport != NULL) {
		/* Check if we have a valid remote address */
		if (sock->remote_addr.ss_family == 0) {
			/* No remote address available yet */
			if (sock->is_connected) {
				/* Connected socket - use getpeername */
				struct sockaddr_storage remote;
				socklen_t remote_len = sizeof(remote);
				rc = getpeername(sock->fd, (struct sockaddr *)&remote, &remote_len);
				if (rc != 0) {
					return -1;
				}

				if (caddr != NULL) {
					if (remote.ss_family == AF_INET) {
						struct sockaddr_in *addr_in = (struct sockaddr_in *)&remote;
						inet_ntop(AF_INET, &addr_in->sin_addr, caddr, clen);
					} else if (remote.ss_family == AF_INET6) {
						struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&remote;
						inet_ntop(AF_INET6, &addr_in6->sin6_addr, caddr, clen);
					}
				}

				if (cport != NULL) {
					if (remote.ss_family == AF_INET) {
						struct sockaddr_in *addr_in = (struct sockaddr_in *)&remote;
						*cport = ntohs(addr_in->sin_port);
						SPDK_DEBUGLOG(sock_udp, "UDP getpeername returned port %u for fd %d\n", *cport, sock->fd);
					} else if (remote.ss_family == AF_INET6) {
						struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&remote;
						*cport = ntohs(addr_in6->sin6_port);
					}
				}
			} else {
				/* Unconnected socket with no data received yet */
				return -1;
			}
		} else {
			/* Use stored remote address from last recvmsg */
			if (caddr != NULL) {
				if (sock->remote_addr.ss_family == AF_INET) {
					struct sockaddr_in *addr_in = (struct sockaddr_in *)&sock->remote_addr;
					inet_ntop(AF_INET, &addr_in->sin_addr, caddr, clen);
				} else if (sock->remote_addr.ss_family == AF_INET6) {
					struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&sock->remote_addr;
					inet_ntop(AF_INET6, &addr_in6->sin6_addr, caddr, clen);
				}
			}

			if (cport != NULL) {
				if (sock->remote_addr.ss_family == AF_INET) {
					struct sockaddr_in *addr_in = (struct sockaddr_in *)&sock->remote_addr;
					*cport = ntohs(addr_in->sin_port);
				} else if (sock->remote_addr.ss_family == AF_INET6) {
					struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&sock->remote_addr;
					*cport = ntohs(addr_in6->sin6_port);
				}
			}
		}
	}

	// SPDK_ERRLOG("udp_sock_getaddr() end \n");

	return 0;
}

static const char *
udp_sock_get_interface_name(struct spdk_sock *_sock)
{
	struct spdk_udp_sock *sock = __udp_sock(_sock);
	char saddr[64];
	int rc;

	rc = spdk_net_getaddr(sock->fd, saddr, sizeof(saddr), NULL, NULL, 0, NULL);
	if (rc != 0) {
		return NULL;
	}

	rc = spdk_net_get_interface_name(saddr, sock->interface_name,
					 sizeof(sock->interface_name));
	if (rc != 0) {
		return NULL;
	}

	return sock->interface_name;
}

static int32_t
udp_sock_get_numa_id(struct spdk_sock *sock)
{
	const char *interface_name;
	uint32_t numa_id;
	int rc;

	interface_name = udp_sock_get_interface_name(sock);
	if (interface_name == NULL) {
		return SPDK_ENV_NUMA_ID_ANY;
	}

	rc = spdk_read_sysfs_attribute_uint32(&numa_id,
					      "/sys/class/net/%s/device/numa_node", interface_name);
	if (rc == 0 && numa_id <= INT32_MAX) {
		return (int32_t)numa_id;
	} else {
		return SPDK_ENV_NUMA_ID_ANY;
	}
}

static int
udp_sock_set_recvbuf(struct spdk_sock *_sock, int sz)
{
	struct spdk_udp_sock *sock = __udp_sock(_sock);
	int rc;

	if (sz < MIN_SO_RCVBUF_SIZE) {
		sz = MIN_SO_RCVBUF_SIZE;
	}

	rc = setsockopt(sock->fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
	if (rc < 0) {
		return rc;
	}

	return 0;
}

static int
udp_sock_set_sendbuf(struct spdk_sock *_sock, int sz)
{
	struct spdk_udp_sock *sock = __udp_sock(_sock);
	int rc;

	if (sz < MIN_SO_SNDBUF_SIZE) {
		sz = MIN_SO_SNDBUF_SIZE;
	}

	rc = setsockopt(sock->fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
	if (rc < 0) {
		return rc;
	}

	return 0;
}

static struct spdk_udp_sock *
udp_sock_alloc(int fd, struct spdk_sock_impl_opts *impl_opts)
{
	struct spdk_udp_sock *sock;

	sock = calloc(1, sizeof(*sock));
	if (sock == NULL) {
		SPDK_ERRLOG("sock allocation failed\n");
		return NULL;
	}

	sock->fd = fd;
	memcpy(&sock->base.impl_opts, impl_opts, sizeof(*impl_opts));

	/* Cache local address once — avoids getsockname() on every recvmsg/getaddr call */
	sock->cached_local_addr_len = sizeof(sock->cached_local_addr);
	if (getsockname(fd, (struct sockaddr *)&sock->cached_local_addr,
			&sock->cached_local_addr_len) != 0) {
		/* Non-fatal: zero out so udp_sock_getaddr falls back to live call */
		memset(&sock->cached_local_addr, 0, sizeof(sock->cached_local_addr));
		sock->cached_local_addr_len = 0;
	}

#if defined(__linux__)
	spdk_sock_get_placement_id(sock->fd, sock->base.impl_opts.enable_placement_id,
				   &sock->placement_id);
#elif defined(__FreeBSD__)
	spdk_sock_get_placement_id(sock->fd, sock->base.impl_opts.enable_placement_id,
				   &sock->placement_id);
#endif

	return sock;
}

/* Create UDP socket and bind to address */
static struct spdk_sock *
udp_sock_listen(const char *ip, int port, struct spdk_sock_opts *opts)
{
	struct spdk_sock_impl_opts impl_opts;
	struct spdk_udp_sock *sock;
	struct addrinfo *res, *res0;
	int fd = -1, rc;
	int val = 1;

	if (opts->impl_opts != NULL && opts->impl_opts_size > 0) {
		memcpy(&impl_opts, &g_udp_impl_opts, sizeof(impl_opts));
		memcpy(&impl_opts, opts->impl_opts,
		       spdk_min(sizeof(impl_opts), opts->impl_opts_size));
	} else {
		impl_opts = g_udp_impl_opts;
	}

	res0 = udp_getaddrinfo(ip, port);
	if (!res0) {
		return NULL;
	}

	/* Try to bind to the first address that works */
	for (res = res0; res != NULL; res = res->ai_next) {
		fd = socket(res->ai_family, SOCK_DGRAM, IPPROTO_UDP);
		if (fd < 0) {
			continue;
		}

		/* for server side core affinity */
		rc = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val));
		if(rc != 0) {
			close(fd);
			fd = -1;
			continue;
		}

		/* Set socket buffers */
		rc = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &impl_opts.recv_buf_size,
				sizeof(impl_opts.recv_buf_size));
		if (rc != 0) {
			close(fd);
			fd = -1;
			continue;
		}

		rc = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &impl_opts.send_buf_size,
				sizeof(impl_opts.send_buf_size));
		if (rc != 0) {
			close(fd);
			fd = -1;
			continue;
		}

		rc = setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &val, sizeof(val));
		if (rc != 0) {
			SPDK_ERRLOG("setsockopt(IP_PKTINFO) failed: errno=%d (%s)\n", errno, strerror(errno));
			close(fd);
			fd = -1;
			continue;
		}

#ifdef UDP_GRO
		/* Enable UDP GRO so the kernel coalesces equal-size incoming datagrams
		 * into a super-segment before delivery, matching TCP GRO behavior. */
		val = 1;
		rc = setsockopt(fd, SOL_UDP, UDP_GRO, &val, sizeof(val));
		if (rc != 0) {
			SPDK_WARNLOG("setsockopt(UDP_GRO) failed: errno=%d (%s) — GRO disabled\n",
				     errno, strerror(errno));
		}
#endif
		rc = bind(fd, res->ai_addr, res->ai_addrlen);
		if (rc != 0) {
			SPDK_ERRLOG("bind() failed: errno=%d (%s)\n", errno, strerror(errno));
			close(fd);
			fd = -1;
			continue;
		}

#ifdef SPDK_CONFIG_EBPF
		/* Each reactor: write own fd directly to map, attach prog (idempotent), update config */
		if (impl_opts.ebpf_prog_fd >= 0) {
			__u32 key = (__u32)impl_opts.ebpf_socket_index;

			rc = bpf_map_update_elem(impl_opts.ebpf_map_fd, &key, &fd, 0);
			if (rc != 0) {
				SPDK_ERRLOG("eBPF: map[%u]=%d update failed: errno=%d\n", key, fd, errno);
			}
			rc = setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF,
					&impl_opts.ebpf_prog_fd, sizeof(impl_opts.ebpf_prog_fd));
			if (rc != 0) {
				SPDK_ERRLOG("eBPF: SO_ATTACH_REUSEPORT_EBPF failed: errno=%d (%s)\n",
					    errno, strerror(errno));
			}
			SPDK_NOTICELOG("reuseport_array[%u] = fd %d (reactor=%d cpu=%d)\n",
                       key, fd, (int)impl_opts.ebpf_socket_index,
                       (int)spdk_env_get_current_core());
			if (impl_opts.ebpf_config_map_fd >= 0) {
				__u32 cfg_key = 0;
				__u32 num = (__u32)impl_opts.ebpf_num_sockets;
				rc = bpf_map_update_elem(impl_opts.ebpf_config_map_fd, &cfg_key, &num, 0);
			}
		}
#endif
		if (spdk_fd_set_nonblock(fd)) {
			close(fd);
			fd = -1;
			continue;
		}
		break;
	}

	freeaddrinfo(res0);

	if (fd < 0) {
		return NULL;
	}

	sock = udp_sock_alloc(fd, &impl_opts);
	if (sock == NULL) {
		close(fd);
		return NULL;
	}

	return &sock->base;
}

/* Create UDP socket and optionally "connect" it (for filtering) */
static struct spdk_sock *
udp_sock_connect(const char *ip, int port, struct spdk_sock_opts *opts)
{
	struct spdk_sock_impl_opts impl_opts;
	struct spdk_udp_sock *sock;
	struct addrinfo *res, *res0;
	int fd = -1, rc;
	int val = 1;

	if (opts->impl_opts != NULL && opts->impl_opts_size > 0) {
		memcpy(&impl_opts, &g_udp_impl_opts, sizeof(impl_opts));
		memcpy(&impl_opts, opts->impl_opts,
		       spdk_min(sizeof(impl_opts), opts->impl_opts_size));
	} else {
		impl_opts = g_udp_impl_opts;
	}

	res0 = udp_getaddrinfo(ip, port);
	if (!res0) {
		return NULL;
	}

	/* Try to create and connect */
	for (res = res0; res != NULL; res = res->ai_next) {
		fd = socket(res->ai_family, SOCK_DGRAM, IPPROTO_UDP);
		if (fd < 0) {
			continue;
		}

		/* Set socket buffers */
		rc = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &impl_opts.recv_buf_size,
				sizeof(impl_opts.recv_buf_size));
		if (rc != 0) {
			close(fd);
			fd = -1;
			continue;
		}

		rc = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &impl_opts.send_buf_size,
				sizeof(impl_opts.send_buf_size));
		if (rc != 0) {
			close(fd);
			fd = -1;
			continue;
		}

#ifdef UDP_GRO
		/* Enable UDP GRO so the kernel coalesces equal-size incoming datagrams
		 * into a super-segment before delivery, matching TCP GRO behavior. */
		val = 1;
		rc = setsockopt(fd, SOL_UDP, UDP_GRO, &val, sizeof(val));
		if (rc != 0) {
			SPDK_WARNLOG("setsockopt(UDP_GRO) failed: errno=%d (%s) — GRO disabled\n",
				     errno, strerror(errno));
		}
#endif

		/* Optional: bind to source address if specified */
		if (opts->src_addr != NULL || opts->src_port != 0) {
			struct addrinfo *src_res = NULL;
			src_res = udp_getaddrinfo(opts->src_addr ? opts->src_addr : "0.0.0.0",
						  opts->src_port);
			if (src_res) {
				bind(fd, src_res->ai_addr, src_res->ai_addrlen);
				freeaddrinfo(src_res);
			}
		}

		/* UDP "connect" - sets default destination and filters incoming packets */
		rc = connect(fd, res->ai_addr, res->ai_addrlen);
		if (rc != 0) {
			close(fd);
			fd = -1;
			continue;
		}

		if (spdk_fd_set_nonblock(fd)) {
			close(fd);
			fd = -1;
			continue;
		}

		break;
	}

	freeaddrinfo(res0);

	if (fd < 0) {
		return NULL;
	}

	sock = udp_sock_alloc(fd, &impl_opts);
	if (sock == NULL) {
		close(fd);
		return NULL;
	}

	sock->is_connected = true;

	return &sock->base;
}

/* UDP doesn't have accept - return NULL */
static struct spdk_sock *
udp_sock_accept(struct spdk_sock *_sock)
{
	return NULL;
}

static int
udp_sock_close(struct spdk_sock *_sock)
{
	struct spdk_udp_sock *sock = __udp_sock(_sock);

	if (sock->fd != -1) {
		close(sock->fd);
	}

	free(sock);
	return 0;
}

static ssize_t
udp_sock_recv(struct spdk_sock *_sock, void *buf, size_t len)
{
	struct spdk_udp_sock *sock = __udp_sock(_sock);
	struct msghdr msg = {};
	struct iovec iov;
	ssize_t rc;

	iov.iov_base = buf;
	iov.iov_len = len;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (!sock->is_connected) {
		/* Need to receive source address */
		msg.msg_name = &sock->remote_addr;
		msg.msg_namelen = sizeof(sock->remote_addr);
	}

	// SPDK_ERRLOG("udp_sock_recv() start \n");
	rc = recvmsg(sock->fd, &msg, MSG_DONTWAIT);
	if (rc < 0) { 
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}
		return -1;
	}

	if (rc > 0) {
		SPDK_DEBUGLOG(sock_udp, "udp_sock_recv() received %zd bytes\n", rc);
	}

	if (!sock->is_connected) {
		sock->remote_addr_len = msg.msg_namelen;
	}

	return rc;
}


static ssize_t
udp_sock_readv(struct spdk_sock *_sock, struct iovec *iov, int iovcnt)
{
	struct spdk_udp_sock *sock = __udp_sock(_sock);
	struct msghdr msg = {};
	ssize_t rc;

	msg.msg_iov = iov;
	msg.msg_iovlen = iovcnt;

	rc = recvmsg(sock->fd, &msg, MSG_DONTWAIT);
	if (rc < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}
		return -1;
	}

	if(rc > 0) {
		SPDK_DEBUGLOG(sock_udp, "udp_sock_readv() received %zd bytes \n", rc);
	}

	return rc;
}

static ssize_t
udp_sock_writev(struct spdk_sock *_sock, struct iovec *iov, int iovcnt)
{
	struct spdk_udp_sock *sock = __udp_sock(_sock);
	struct msghdr msg = {};
	ssize_t rc;

	msg.msg_iov = iov;
	msg.msg_iovlen = iovcnt;

	if (!sock->is_connected && sock->remote_addr_len > 0) {
		/* Send to last known remote address */
		msg.msg_name = &sock->remote_addr;
		msg.msg_namelen = sock->remote_addr_len;
		SPDK_DEBUGLOG(sock_udp, "udp_sock_writev: using remote_addr, len=%u\n", sock->remote_addr_len);
	} else if (!sock->is_connected) {
		SPDK_DEBUGLOG(sock_udp, "udp_sock_writev: NOT CONNECTED and no remote_addr! is_connected=%d, remote_addr_len=%u\n",
		           sock->is_connected, sock->remote_addr_len);
	} else {
		SPDK_DEBUGLOG(sock_udp, "udp_sock_writev: socket is connected, fd=%d\n", sock->fd);
	}

	rc = sendmsg(sock->fd, &msg, MSG_DONTWAIT | MSG_NOSIGNAL);
	if (rc < 0) {
		SPDK_DEBUGLOG(sock_udp, "sendmsg failed: rc=%ld, errno=%d (%s), fd=%d, iovcnt=%d, total_len=%zu\n",
		           rc, errno, strerror(errno), sock->fd, iovcnt,
		           iovcnt > 0 ? iov[0].iov_len : 0);
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}
		return -1;
	}

	return rc;
}

static void
udp_sock_writev_async(struct spdk_sock *sock, struct spdk_sock_request *req)
{
	int rc;

	spdk_sock_request_queue(sock, req);

	if(sock->queued_iovcnt >= IOV_BATCH_SIZE) {
		rc = _sock_flush(sock);
		if (rc > 0) {
			spdk_sock_request_complete(sock, req, rc);
		}
	}
}

static int
udp_sock_set_recvlowat(struct spdk_sock *_sock, int nbytes)
{
	/* Not particularly useful for UDP, but implement for compatibility */
	struct spdk_udp_sock *sock = __udp_sock(_sock);
	int val = nbytes;
	int rc;

	rc = setsockopt(sock->fd, SOL_SOCKET, SO_RCVLOWAT, &val, sizeof(val));
	if (rc < 0) {
		return -1;
	}

	return 0;
}

static bool
udp_sock_is_ipv6(struct spdk_sock *_sock)
{
	struct spdk_udp_sock *sock = __udp_sock(_sock);
	struct sockaddr_storage sa;
	socklen_t salen;
	int rc;

	memset(&sa, 0, sizeof sa);
	salen = sizeof sa;
	rc = getsockname(sock->fd, (struct sockaddr *)&sa, &salen);
	if (rc != 0) {
		return false;
	}

	return (sa.ss_family == AF_INET6);
}

static bool
udp_sock_is_ipv4(struct spdk_sock *_sock)
{
	struct spdk_udp_sock *sock = __udp_sock(_sock);
	struct sockaddr_storage sa;
	socklen_t salen;
	int rc;

	memset(&sa, 0, sizeof sa);
	salen = sizeof sa;
	rc = getsockname(sock->fd, (struct sockaddr *)&sa, &salen);
	if (rc != 0) {
		return false;
	}

	return (sa.ss_family == AF_INET);
}

static bool
udp_sock_is_connected(struct spdk_sock *_sock)
{
	struct spdk_udp_sock *sock = __udp_sock(_sock);
	return sock->is_connected;
}

static struct spdk_sock_group_impl *
udp_sock_group_impl_get_optimal(struct spdk_sock *_sock, struct spdk_sock_group_impl *hint)
{
	struct spdk_udp_sock *sock = __udp_sock(_sock);
	struct spdk_sock_group_impl *group_impl;

	if (sock->placement_id != -1) {
		spdk_sock_map_lookup(&g_map, sock->placement_id, &group_impl, hint);
		return group_impl;
	}

	return NULL;
}

static int
udp_sock_alloc_pipe(struct spdk_udp_sock *sock __attribute__((unused)), int sz __attribute__((unused)))
{
	return 0;
}

#if 0
static int
udp_sock_alloc_pipe_unused(struct spdk_udp_sock *sock, int sz)
{
	uint8_t *new_buf, *old_buf;
	struct spdk_pipe *new_pipe;
	struct iovec siov[2];
	struct iovec diov[2];
	int sbytes;
	ssize_t bytes;
	int rc;

	if (sock->recv_buf_sz == sz) {
		return 0;
	}

	/* If the new size is 0, just free the pipe */
	if (sz == 0) {
		old_buf = spdk_pipe_destroy(sock->recv_pipe);
		free(old_buf);
		sock->recv_pipe = NULL;
		return 0;
	} else if (sz < MIN_SOCK_PIPE_SIZE) {
		SPDK_ERRLOG("The size of the pipe must be larger than %d\n", MIN_SOCK_PIPE_SIZE);
		return -1;
	}

	/* Round up to next 64 byte multiple */
	rc = posix_memalign((void **)&new_buf, 64, sz);
	if (rc != 0) {
		SPDK_ERRLOG("socket recv buf allocation failed\n");
		return -ENOMEM;
	}
	memset(new_buf, 0, sz);

	new_pipe = spdk_pipe_create(new_buf, sz);
	if (new_pipe == NULL) {
		SPDK_ERRLOG("socket pipe allocation failed\n");
		free(new_buf);
		return -ENOMEM;
	}

	if (sock->recv_pipe != NULL) {
		/* Pull all of the data out of the old pipe */
		sbytes = spdk_pipe_reader_get_buffer(sock->recv_pipe, sock->recv_buf_sz, siov);
		if (sbytes > sz) {
			/* Too much data to fit into the new pipe size */
			old_buf = spdk_pipe_destroy(new_pipe);
			free(old_buf);
			return -EINVAL;
		}

		sbytes = spdk_pipe_writer_get_buffer(new_pipe, sz, diov);
		assert(sbytes == sz);

		bytes = spdk_iovcpy(siov, 2, diov, 2);
		spdk_pipe_writer_advance(new_pipe, bytes);

		old_buf = spdk_pipe_destroy(sock->recv_pipe);
		free(old_buf);
	}

	sock->recv_buf_sz = sz;
	sock->recv_pipe = new_pipe;

	if (sock->base.group_impl) {
		struct spdk_udp_sock_group_impl *group;

		group = __udp_group_impl(sock->base.group_impl);
		spdk_pipe_group_add(group->pipe_group, sock->recv_pipe);
	}

	return 0;
}
#endif



static struct spdk_sock_group_impl *
udp_sock_group_impl_create(void)
{
	struct spdk_udp_sock_group_impl *group_impl;
	int fd;

#if defined(SPDK_EPOLL)
	fd = epoll_create1(0);
#elif defined(SPDK_KEVENT)
	fd = kqueue();
#endif
	if (fd == -1) {
		return NULL;
	}

	group_impl = calloc(1, sizeof(*group_impl));
	if (group_impl == NULL) {
		SPDK_ERRLOG("group_impl allocation failed\n");
		close(fd);
		return NULL;
	}


	group_impl->fd = fd;
	group_impl->placement_id = -1;

	if (g_udp_impl_opts.enable_placement_id == PLACEMENT_CPU) {
		spdk_sock_map_insert(&g_map, spdk_env_get_current_core(), &group_impl->base);
		group_impl->placement_id = spdk_env_get_current_core();
	}

	return &group_impl->base;
}




static void
udp_sock_mark(struct spdk_udp_sock_group_impl *group, struct spdk_udp_sock *sock,
		int placement_id)
{
#if defined(SO_MARK)
	int rc;

	rc = setsockopt(sock->fd, SOL_SOCKET, SO_MARK,
			&placement_id, sizeof(placement_id));
	if (rc != 0) {
		/* Not fatal */
		SPDK_ERRLOG("Error setting SO_MARK\n");
		return;
	}

	rc = spdk_sock_map_insert(&g_map, placement_id, &group->base);
	if (rc != 0) {
		/* Not fatal */
		SPDK_ERRLOG("Failed to insert sock group into map: %d\n", rc);
		return;
	}

	sock->placement_id = placement_id;
#endif
}


static void
udp_sock_update_mark(struct spdk_sock_group_impl *_group, struct spdk_sock *_sock)
{
	struct spdk_udp_sock_group_impl *group = __udp_group_impl(_group);

	if (group->placement_id == -1) {
		group->placement_id = spdk_sock_map_find_free(&g_map);

		/* If a free placement id is found, update existing sockets in this group */
		if (group->placement_id != -1) {
			struct spdk_sock  *sock, *tmp;

			TAILQ_FOREACH_SAFE(sock, &_group->socks, link, tmp) {
				udp_sock_mark(group, __udp_sock(sock), group->placement_id);
			}
		}
	}

	if (group->placement_id != -1) {
		/*
		 * group placement id is already determined for this poll group.
		 * Mark socket with group's placement id.
		 */
		udp_sock_mark(group, __udp_sock(_sock), group->placement_id);
	}
}



static int
udp_sock_group_impl_add_sock(struct spdk_sock_group_impl *_group, struct spdk_sock *_sock)
{
	struct spdk_udp_sock_group_impl *group = __udp_group_impl(_group);
	struct spdk_udp_sock *sock = __udp_sock(_sock);
	int rc;

	SPDK_DEBUGLOG(sock,"UDP: Adding sock fd=%d to epoll group fd=%d\n", sock->fd, group->fd);

#if defined(SPDK_EPOLL)
	struct epoll_event event;

	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN;
	event.data.ptr = sock;

	rc = epoll_ctl(group->fd, EPOLL_CTL_ADD, sock->fd, &event);
	SPDK_DEBUGLOG(sock,"UDP: epoll_ctl ADD result: rc=%d (errno=%d)\n", rc, errno);
#elif defined(SPDK_KEVENT)
	struct kevent event;
	struct timespec ts = {0};

	EV_SET(&event, sock->fd, EVFILT_READ, EV_ADD, 0, 0, sock);

	rc = kevent(group->fd, &event, 1, NULL, 0, &ts);
#endif

	if (rc < 0) {
		return -1;
	}

	if (_sock->impl_opts.enable_placement_id == PLACEMENT_MARK) {
		udp_sock_update_mark(_group, _sock);
	} else if (sock->placement_id != -1) {
		rc = spdk_sock_map_insert(&g_map, sock->placement_id, &group->base);
		if (rc != 0) {
			SPDK_ERRLOG("Failed to insert sock group into map: %d\n", rc);
			/* Do not treat this as an error. The system will continue running. */
		}
	}

	return rc;
}

static int
udp_sock_group_impl_remove_sock(struct spdk_sock_group_impl *_group, struct spdk_sock *_sock)
{
	struct spdk_udp_sock_group_impl *group = __udp_group_impl(_group);
	struct spdk_udp_sock *sock = __udp_sock(_sock);
	int rc;

	spdk_sock_map_release(&g_map, sock->placement_id);

#if defined(SPDK_EPOLL)
	struct epoll_event event;

	memset(&event, 0, sizeof(event));
	rc = epoll_ctl(group->fd, EPOLL_CTL_DEL, sock->fd, &event);
#elif defined(SPDK_KEVENT)
	struct kevent event;
	struct timespec ts = {0};

	EV_SET(&event, sock->fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);

	rc = kevent(group->fd, &event, 1, NULL, 0, &ts);
#endif

	if (rc < 0) {
		return -1;
	}

	return 0;
}

static int
udp_sock_group_impl_poll(struct spdk_sock_group_impl *_group, int max_events,
			   struct spdk_sock **socks)
{
	struct spdk_udp_sock_group_impl *group = __udp_group_impl(_group);
	struct spdk_sock *sock;
	struct spdk_udp_sock *usock;
	int num_events, ready, i;
#if defined(SPDK_EPOLL)
	struct epoll_event events[MAX_EVENTS_PER_POLL];
#elif defined(SPDK_KEVENT)
	struct kevent events[MAX_EVENTS_PER_POLL];
	struct timespec ts = {0};
#endif

assert(max_events > 0);

#if defined(SPDK_EPOLL)
	num_events = epoll_wait(group->fd, events, max_events, 0);
#elif defined(SPDK_KEVENT)
	num_events = kevent(group->fd, NULL, 0, events, max_events, &ts);
#endif

	if (num_events == -1) {
		return -1;
	}

	ready = 0;

	if (num_events == 0 && !TAILQ_EMPTY(&_group->socks)) {
		sock = TAILQ_FIRST(&_group->socks);
		usock = __udp_sock(sock);
		if (sock->opts.priority) {
			/* Hardware busy-poll path: kick the NIC queue */
			struct pollfd pfd = {0, 0, 0};

			pfd.fd = usock->fd;
			pfd.events = POLLIN | POLLERR;
			poll(&pfd, 1, 0);
		}
	}

	for (i = 0; i < num_events; i++) {
#if defined(SPDK_EPOLL)
		sock = events[i].data.ptr;
		usock = __udp_sock(sock);

#ifdef SPDK_ZEROCOPY
		if (events[i].events & EPOLLERR) {
			int rc = _sock_check_zcopy(sock);
			/* If the socket was closed or removed from
			 * the group in response to a send ack, don't
			 * add it to the array here. */
			if (rc || sock->cb_fn == NULL) {
				continue;
			}
		}
#endif
		SPDK_DEBUGLOG(sock,"UDP: epoll event[%d] flags=0x%x (EPOLLIN=0x%x, EPOLLOUT=0x%x, EPOLLERR=0x%x, EPOLLHUP=0x%x) fd=%d\n",
			       i, events[i].events, EPOLLIN, EPOLLOUT, EPOLLERR, EPOLLHUP, usock->fd);
		if ((events[i].events & EPOLLIN) == 0) {
			continue;
		}

#elif defined(SPDK_KEVENT)
		sock = events[i].udata;
		usock = __udp_sock(sock);
#endif

		if (spdk_unlikely(sock->cb_fn == NULL)) {
			continue;
		}

		socks[ready++] = sock;
	}

	return ready;
}

static int
udp_sock_group_impl_close(struct spdk_sock_group_impl *_group)
{
	struct spdk_udp_sock_group_impl *group = __udp_group_impl(_group);

	close(group->fd);
	free(group);

	return 0;
}

static int
udp_sock_impl_get_opts(struct spdk_sock_impl_opts *opts, size_t *len)
{
	if (!opts || !len) {
		errno = EINVAL;
		return -1;
	}

	memset(opts, 0, *len);
	memcpy(opts, &g_udp_impl_opts, spdk_min(*len, sizeof(g_udp_impl_opts)));
	*len = spdk_min(*len, sizeof(g_udp_impl_opts));

	return 0;
}

static int
udp_sock_impl_set_opts(const struct spdk_sock_impl_opts *opts, size_t len)
{
	if (!opts) {
		errno = EINVAL;
		return -1;
	}

	memcpy(&g_udp_impl_opts, opts, spdk_min(len, sizeof(g_udp_impl_opts)));

	return 0;
}

static int
_sock_flush(struct spdk_sock *sock)
{
	struct spdk_udp_sock *usock = __udp_sock(sock);
	struct msghdr msg = {};
	struct iovec iovs[IOV_BATCH_SIZE];
	int iovcnt;
	struct spdk_sock_request *req;
	ssize_t rc;
	unsigned int offset;
	size_t len;
	int flags = MSG_DONTWAIT | MSG_NOSIGNAL;

	/* Can't flush from within a callback or we end up with recursive calls */
	if (sock->cb_cnt > 0) {
		errno = EAGAIN;
		return -1;
	}

	/* Prepare iovecs from queued requests */
	iovcnt = spdk_sock_prep_reqs(sock, iovs, 0, NULL, &flags);
	if (iovcnt == 0) {
		return 0;
	}

	/* Perform the vectored write */
	msg.msg_iov = iovs;
	msg.msg_iovlen = iovcnt;

	/* Set destination address if not connected */
	if (!usock->is_connected && usock->remote_addr_len > 0) {
		msg.msg_name = &usock->remote_addr;
		msg.msg_namelen = usock->remote_addr_len;
	}

	rc = sendmsg(usock->fd, &msg, flags);
	if (rc <= 0) {
		if (rc == 0 || errno == EAGAIN || errno == EWOULDBLOCK) {
			errno = EAGAIN;
		}
		return -1;
	}

	/* Consume the requests that were actually written */
	req = TAILQ_FIRST(&sock->queued_reqs);
	while (req) {
		offset = req->internal.offset;

		for (int i = 0; i < req->iovcnt; i++) {
			len = SPDK_SOCK_REQUEST_IOV(req, i)->iov_len;

			/* Advance by the offset first */
			if (offset >= len) {
				offset -= len;
				continue;
			}

			/* Calculate consumed bytes in this iovec */
			len -= offset;

			if (len > (size_t)rc) {
				/* Partially consumed this iov */
				req->internal.offset += rc;
				return 0;
			}

			offset = 0;
			req->internal.offset += len;
			rc -= len;
		}

		/* Fully consumed this request - move to pending and complete it */
		spdk_sock_request_pend(sock, req);
		
		/* For UDP, we send complete datagrams, so report full size */
		if (spdk_sock_request_put(sock, req, 0) != 0) {
			return -1;
		}

		if (rc == 0) {
			break;
		}

		req = TAILQ_FIRST(&sock->queued_reqs);
	}

	return 0;
}

static int
udp_sock_flush(struct spdk_sock *sock)
{
	return _sock_flush(sock);
}

int
spdk_sock_get_remote_addr(struct spdk_sock *_sock, struct sockaddr_storage *addr, socklen_t *addrlen)
{
	const char *impl_name;
	struct spdk_udp_sock *sock;

	if (_sock == NULL || addr == NULL || addrlen == NULL) {
		return -1;
	}

	/* Only works for UDP sockets */
	impl_name = spdk_sock_get_impl_name(_sock);
	if (impl_name == NULL || strcmp(impl_name, "udp") != 0) {
		return -1;
	}

	sock = __udp_sock(_sock);

	/* Check if we have a valid remote address */
	if (sock->remote_addr.ss_family == 0) {
		return -1;
	}

	memcpy(addr, &sock->remote_addr, sizeof(sock->remote_addr));
	if (sock->remote_addr_len > 0) {
		*addrlen = sock->remote_addr_len;
	} else {
		*addrlen = sizeof(sock->remote_addr);
	}

	return 0;
}

static int
udp_sock_writev_direct(struct spdk_sock *_sock, struct iovec *iov, int iovcnt, struct sockaddr *da, socklen_t dalen)
{
	struct spdk_udp_sock *sock = __udp_sock(_sock);
	struct msghdr msg = {};
	ssize_t rc;

	msg.msg_iov = iov;
	msg.msg_iovlen = iovcnt;

	/* Set destination address */
	msg.msg_name = da;
	msg.msg_namelen = dalen;

	rc = sendmsg(sock->fd, &msg, MSG_DONTWAIT | MSG_NOSIGNAL);
	if (rc < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}
		return -1;
	}

	return rc;
}

static int
udp_sock_recv_with_msghdr(struct spdk_sock *_sock, struct mmsghdr *msgs, int vlen)
{
	struct spdk_udp_sock *sock = __udp_sock(_sock);
	int n;

	n = recvmmsg(sock->fd, msgs, vlen, MSG_DONTWAIT, NULL);
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}
		return -1;
	}
	return n;
}



static int
udp_sock_writev_direct_batch(struct spdk_sock *_sock, struct mmsghdr *msgs, int n)
{
	struct spdk_udp_sock *sock = __udp_sock(_sock);
	int rc;

	rc = sendmmsg(sock->fd, msgs, n, MSG_DONTWAIT | MSG_NOSIGNAL);
	if (rc < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}
		return -1;
	}
	return rc;
}

#ifdef __linux__
static int
udp_sock_writev_direct_gso(struct spdk_sock *_sock, struct iovec *iov, size_t segment_size,
			   struct sockaddr *addr, socklen_t addrlen)
{
	struct spdk_udp_sock *sock = __udp_sock(_sock);
	char cmsgbuf[CMSG_SPACE(sizeof(uint16_t))] = {};
	struct msghdr msg = {
		.msg_name    = addr,
		.msg_namelen = addrlen,
		.msg_iov     = iov,
		.msg_iovlen  = 1,
		.msg_control = cmsgbuf,
	};
	ssize_t rc;

	/* Set UDP_SEGMENT only when there are multiple segments */
	if (segment_size > 0 && iov->iov_len > segment_size) {
		/* Directly cast cmsgbuf — CMSG_FIRSTHDR() returns NULL when msg_controllen==0 */
		struct cmsghdr *cmsg = (struct cmsghdr *)cmsgbuf;
		cmsg->cmsg_level = SOL_UDP;
		cmsg->cmsg_type  = UDP_SEGMENT;
		cmsg->cmsg_len   = CMSG_LEN(sizeof(uint16_t));
		*(uint16_t *)CMSG_DATA(cmsg) = (uint16_t)segment_size;
		msg.msg_controllen = CMSG_SPACE(sizeof(uint16_t));
	} else {
		msg.msg_control    = NULL;
		msg.msg_controllen = 0;
	}

	rc = sendmsg(sock->fd, &msg, MSG_DONTWAIT | MSG_NOSIGNAL);
	if (rc < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}
		return -1;
	}
	return (int)rc;
}
#else
static int
udp_sock_writev_direct_gso(struct spdk_sock *_sock, struct iovec *iov, size_t segment_size,
			   struct sockaddr *addr, socklen_t addrlen)
{
	/* GSO not supported on this platform — fall back to plain sendmsg */
	return udp_sock_writev_direct(_sock, iov, 1, addr, addrlen);
}
#endif

static struct spdk_net_impl g_udp_net_impl = {
	.name		= "udp",
	.getaddr	= udp_sock_getaddr,
	.connect	= udp_sock_connect,
	.listen		= udp_sock_listen,
	.accept		= udp_sock_accept,
	.close		= udp_sock_close,
	.recv		= udp_sock_recv,
	.readv		= udp_sock_readv,
	.writev		= udp_sock_writev,
	.writev_async	= udp_sock_writev_async,
	.flush		= udp_sock_flush,
	.set_recvlowat	= udp_sock_set_recvlowat,
	.set_recvbuf	= udp_sock_set_recvbuf,
	.set_sendbuf	= udp_sock_set_sendbuf,
	.is_ipv6	= udp_sock_is_ipv6,
	.is_ipv4	= udp_sock_is_ipv4,
	.is_connected	= udp_sock_is_connected,
	.get_numa_id	= udp_sock_get_numa_id,
	.get_interface_name = udp_sock_get_interface_name,
	.group_impl_get_optimal	= udp_sock_group_impl_get_optimal,
	.group_impl_create	= udp_sock_group_impl_create,
	.group_impl_add_sock	= udp_sock_group_impl_add_sock,
	.group_impl_remove_sock = udp_sock_group_impl_remove_sock,
	.group_impl_poll	= udp_sock_group_impl_poll,
	.group_impl_close	= udp_sock_group_impl_close,
	.get_opts		= udp_sock_impl_get_opts,
	.set_opts		= udp_sock_impl_set_opts,
	.writev_direct = udp_sock_writev_direct,
	.writev_direct_batch = udp_sock_writev_direct_batch,
	.writev_direct_gso = udp_sock_writev_direct_gso,
	.recv_with_msghdr = udp_sock_recv_with_msghdr,
};

SPDK_NET_IMPL_REGISTER_DEFAULT(udp, &g_udp_net_impl);

SPDK_LOG_REGISTER_COMPONENT(sock_udp)
