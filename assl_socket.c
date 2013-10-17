/*
 * Copyright (c) 2011 Conformal Systems LLC <info@conformal.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#include "assl.h"
#include "assl_internal.h"

int
assl_initialize_sockets()
{
	/* Nothing to do. */
	return (0);
}

int
assl_shutdown_sockets()
{
	/* Nothing to do. */
	return (0);
}

int
assl_close_socket(int s)
{
	return close(s);
}

int
assl_get_ssl_error(const SSL *ssl, int ret)
{
	return SSL_get_error(ssl, ret);
}

void
assl_get_socket_error(int err, char *outstr, int len)
{
	strlcpy(outstr, strerror(err), len);
}

BIO *
assl_bio_new_socket(int sock, int close_flag)
{
	return BIO_new_socket(sock, close_flag);
}

int
assl_is_nonblock(int s)
{
	int	r, rv = -1;

	r = fcntl(s, F_GETFL, 0);
	if (r < 0)
		ERROR_OUT(ERR_SOCKET, done);

	rv = 0;
	if (r & O_NONBLOCK)
		rv = 1;
done:
	return (rv);
}

int
assl_set_nonblock(int fd)
{
	int			val, rv = 1;

	val = fcntl(fd, F_GETFL, 0);
	if (val < 0)
		goto done;

	if (val & O_NONBLOCK)
		return (0);

	val |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, val) == -1)
		goto done;

	rv = 0;
done:
	return (rv);
}

int
assl_set_keepalive(int fd)
{
	int			val = 1;

	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, sizeof(val)) == -1)
		return (-1);

	return (0);
}

void
assl_set_tos(int fd, int family, int flags)
{
	int	level, optname, tos;

	if (family == AF_INET) {
		level = IPPROTO_IP;
		optname = IP_TOS;
#ifdef IPV6_TCLASS
	} else if (family == AF_INET6) {
		level = IPPROTO_IPV6;
		optname = IPV6_TCLASS;
#endif
	} else
		return;

	if (flags & ASSL_F_LOWDELAY) {
		tos = IPTOS_LOWDELAY;
		setsockopt(fd, level, optname, &tos, sizeof(tos));
	}
	if (flags & ASSL_F_THROUGHPUT) {
		tos = IPTOS_THROUGHPUT;
		setsockopt(fd, level, optname, &tos, sizeof(tos));
	}
}

void
assl_set_recvbuf(int fd, int bufsize)
{
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
}

void
assl_set_sendbuf(int fd, int bufsize)
{
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
}

int
assl_get_recvtimeo(int fd, struct timeval *t)
{
	socklen_t		sz = sizeof *t;

	if (getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, t, &sz) == -1)
		return (-1);

	return (0);
}

int
assl_set_recvtimeo(int fd, struct timeval *t)
{
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, t, sizeof *t) == -1)
		return (-1);

	return (0);
}
int
assl_fd(struct assl_context *c)
{
        return c->as_sock;
}

