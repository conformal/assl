/*
 * Copyright (c) 2009 Marco Peereboom <marco@peereboom.us>
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
#include <event.h>
#include "assl.h"

struct workctx {
	struct event		*ev;
	struct assl_context	*c;
	char			*b;
	ssize_t 		tot;
	int			s;		/* not really needed? */
	char			buf[65536 * 10];
};

void			serve_callback(int s, short event, void *arg);
void			serve_rd_worker(evutil_socket_t fd, short event,
			    void *arg);
void			serve_wr_worker(evutil_socket_t fd, short event,
			    void *arg);

void
serve_callback(int s, short event, void *arg)
{
	struct assl_context	*c;
	struct workctx		*wctx;

	printf("callback running\n");
	wctx = calloc(1, sizeof(*wctx));
	if (wctx == NULL)
		assl_fatalx("assl_alloc_context");

	wctx->b = wctx->buf;
	wctx->tot = sizeof wctx->buf;

	c = assl_alloc_context(ASSL_M_ALL, 0);
	if (c == NULL)
		assl_fatalx("assl_alloc_context");
	wctx->c = c;

	if (assl_load_file_certs(c, "../ca/ca.crt", "server/server.crt",
	    "server/private/server.key"))
		assl_fatalx("assl_load_file_certs");

	if (assl_event_accept(c, s, serve_rd_worker, serve_wr_worker, wctx))
		assl_fatalx("assl_accept");
}


void
serve_rd_worker(evutil_socket_t fd, short event, void *arg)
{
	struct workctx		*wctx = arg;
	int			close = 0;
	ssize_t			rd;

	rd = assl_read(wctx->c, wctx->b, wctx->tot);

	//printf("read %zd\n", rd);
	if (rd == -1) {
		return;
	} else if (rd == 0 && wctx->tot != 0) {
		/* socket closed */
		close = 1;
	}  else {
		wctx->tot -= rd;
		wctx->b += rd;
	}

	if (wctx->tot == 0 || close == 1) {
		assl_event_close(wctx->c);
		free(wctx);
	}
}

void
serve_wr_worker(evutil_socket_t fd, short event, void *arg)
{
}

int
main(int argc, char *argv[])
{
	struct assl_serve_ctx	*assl_lctx;

	assl_initialize();

	event_init();

	assl_lctx = assl_event_serve(NULL, ASSL_DEFAULT_PORT, ASSL_F_NONBLOCK,
	    serve_callback, NULL);

	event_dispatch();

	return (0);
}
