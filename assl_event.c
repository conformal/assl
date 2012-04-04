/*
 * Copyright (c) 2010 Conformal Systems LLC <info@conformal.com>
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

#include <event2/event.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/queue.h>
#include <sys/time.h>

#include <netdb.h>

#include "assl.h"
#include "assl_internal.h"

struct assl_serve_ctx {
	void		(*cb_fn)(int, short, void *);
	void		*cb_arg;
	int		flags;
	struct event	*ev[2];
	int		fd[2];
};

/*
 * assl_event_cb
 *
 * Internal function used to service listen socket before invoking
 * user's callback.
 */
void
assl_event_cb(evutil_socket_t fd, short event, void *arg)
{
	int s;
	struct assl_serve_ctx *ctx = arg;

	/* XXX ERR, HUP, NVAL? */

	if ((s = accept(fd, 0, 0)) == -1)
		assl_fatalx("accept failed");

	ctx->cb_fn(s, event, ctx->cb_arg);

	if (ctx->flags & ASSL_F_CLOSE_SOCKET)
		close(s);
}

struct assl_serve_ctx *
assl_event_serve(const char *listen_ip, const char *listen_port, int flags,
    struct event_base *ev_base, void (*cb_fn)(int, short, void *),
    void *cb_arg)
{
	struct addrinfo		hints, *res, *ai;
	int			s = -1, on = 1, i;
	int			nfd = -1;
	int			fds[2];
	struct assl_serve_ctx	*ctx = NULL;
	short			event_type;

	if (listen_port == NULL)
		listen_port = ASSL_DEFAULT_PORT;

	bzero(&hints, sizeof hints);
	hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if ((i = getaddrinfo(listen_ip, listen_port, &hints, &res))) {
		assl_err_own("%s", gai_strerror(i));
		ERROR_OUT(ERR_OWN, done);
	}

	bzero(fds, sizeof fds);
	for (ai = res, i = 0; ai && i < 2; ai = ai->ai_next, i++) {
		if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
		    continue;
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (s < 0)
			continue;

		if (flags & ASSL_F_NONBLOCK)
			if (assl_set_nonblock(s)) {
				close(s);
				ERROR_OUT(ERR_LIBC, done);
			}

		setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

		if (bind(s, ai->ai_addr, ai->ai_addrlen) < 0) {
			close(s);
			continue;
		}

		if (listen(s, /* XXX */ 10) < 0) {
			close(s);
			continue;
		}

		fds[i] = s;
		nfd = i + 1;
	}
	freeaddrinfo(res);

	if (nfd == -1 || nfd == 0)
		goto done;

	ctx = calloc(1, sizeof(*ctx));

	ctx->fd[1] = -1; /* init, in case nfd == 1 */

	event_type = EV_READ|EV_PERSIST;
	if (nfd == 2) {
		ctx->fd[1] = fds[1];
		ctx->ev[1] = event_new(ev_base, fds[1], event_type,
		    assl_event_cb, ctx);
		/* XXX alloc failure? */
		event_add(ctx->ev[1], NULL);
	}
	ctx->fd[0] = fds[0];
	ctx->ev[0] = event_new(ev_base, fds[0], event_type, assl_event_cb, ctx);
	/* XXX alloc failure? */
	event_add(ctx->ev[0], NULL);

	ctx->flags = flags;
	ctx->cb_fn = cb_fn;
	ctx->cb_arg= cb_arg;

done:
	return (ctx);
}

/*
 * close the listening socket
 */
void
assl_event_serve_stop(struct assl_serve_ctx *ctx)
{
	if (ctx->fd[0] != -1) {
		event_del(ctx->ev[0]);
		free(ctx->ev[0]);
		ctx->ev[0] = NULL;
		close(ctx->fd[0]);
		ctx->fd[0] = -1;
	}

	if (ctx->fd[1] != -1) {
		event_del(ctx->ev[1]);
		free(ctx->ev[1]);
		ctx->ev[1] = NULL;
		close(ctx->fd[1]);
		ctx->fd[1] = -1;
	}
}

int
assl_event_accept(struct assl_context *ctx, struct event_base *ev_base, int s,
    void (*rd_cb)(evutil_socket_t, short, void *),
    void (*wr_cb)(evutil_socket_t, short, void *),
    void *arg)
{
	int rv;

	rv = assl_accept(ctx, s);
	if (rv)
		return rv;

	ctx->as_ev_rd = event_new(ev_base, ctx->as_sock, EV_READ|EV_PERSIST,
	    rd_cb, arg);
	if (ctx->as_ev_rd == NULL)
		goto fail;
	ctx->as_ev_wr = event_new(ev_base, ctx->as_sock, EV_WRITE|EV_PERSIST,
	    wr_cb, arg);
	if (ctx->as_ev_wr == NULL)
		goto fail;

	event_add(ctx->as_ev_rd, NULL);

	return (rv);
fail:
	if (ctx->as_ev_rd) {
		event_free(ctx->as_ev_rd);
		ctx->as_ev_rd = NULL;
	}
	if (ctx->as_ev_wr) {
		event_free(ctx->as_ev_wr);
		ctx->as_ev_wr = NULL;
	}
	/* XXX what about accepted socket? */

	return -1;
}


void
assl_event_enable_write(struct assl_context *ctx)
{
	event_add(ctx->as_ev_wr, NULL);
}
void
assl_event_disable_write(struct assl_context *ctx)
{
	if (ctx->as_ev_wr)
		event_del(ctx->as_ev_wr);
}

int
assl_event_connect(struct assl_context *c, const char *host, const char *port,
    int flags, struct event_base *ev_base,
    void (*rd_cb)(evutil_socket_t, short, void *),
    void (*wr_cb)(evutil_socket_t, short, void *), void *arg)
{
	int	rv;

	rv = assl_connect(c, host, port, flags);

	if (rv)
		return rv;

	c->as_ev_rd = event_new(ev_base, c->as_sock, EV_READ|EV_PERSIST,
	    rd_cb, arg);
	if (c->as_ev_rd == NULL)
		goto fail;
	c->as_ev_wr = event_new(ev_base, c->as_sock, EV_WRITE|EV_PERSIST,
	    wr_cb, arg);
	if (c->as_ev_wr == NULL)
		goto fail;
	event_add(c->as_ev_rd, NULL);

	return rv;
fail:
	if (c->as_ev_rd) {
		event_free(c->as_ev_rd);
		c->as_ev_rd = NULL;
	}
	if (c->as_ev_wr) {
		event_free(c->as_ev_wr);
		c->as_ev_wr = NULL;
	}
	/* XXX what about connected socket? */

	return 1;
}

int
assl_event_close(struct assl_context *c)
{
	if (c->as_ev_rd) {
		event_del(c->as_ev_rd);
		free(c->as_ev_rd);
		c->as_ev_rd = NULL;
	}
	if (c->as_ev_wr) {
		event_del(c->as_ev_wr);
		free(c->as_ev_wr);
		c->as_ev_wr = NULL;
	}
	return assl_close(c);
}
