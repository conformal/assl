/* $assl$ */
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
#include <signal.h>
#include "assl.h"

#define USE_MEM_CERTS
void serve_rd_worker(int fd, short event, void *arg);
void serve_wr_worker(int fd, short event, void *arg);
void serve_open_writer(int fd, short event, void *arg);
void serve_stop(int fd, short event, void *arg);

struct event			sigterm_ev;
struct event			prd_ev;
int 				cnt = 0;
int				stop = 0;
int				pfd[2];


struct wrctx {
	struct assl_context	*c;
	char			*b;
	ssize_t			tot;
	char			buf[65536 * 10];
};

int
main(int argc, char *argv[])
{
	assl_initialize();

	event_init();

#ifdef USE_MEM_CERTS
	if (assl_load_file_certs_to_mem("../ca/ca.crt", "client/client.crt",
	    "client/private/client.key"))
		assl_fatalx("assl_load_file_certs");
#endif

	if (pipe(pfd) == -1) {
		assl_fatalx("pipe failed");
	}

	cnt = 0;

	signal_set(&sigterm_ev, SIGINT, serve_stop, NULL);
	signal_add(&sigterm_ev, NULL);
	signal_set(&sigterm_ev, SIGTERM, serve_stop, NULL);
	signal_add(&sigterm_ev, NULL);

	event_set(&prd_ev, pfd[0], EV_READ|EV_PERSIST, serve_open_writer, NULL);
	event_add(&prd_ev, NULL);

	write(pfd[1], "a", 1);
	//serve_open_writer(0, 0, NULL);
	event_dispatch();
	exit(1);
}

void
serve_stop(int fd, short event, void *arg)
{
	stop = 1;
	printf("stop\n");
}

void
serve_open_writer(int fd, short event, void *arg)
{
	struct wrctx		*wctx;
	char			buf[20];

	read(pfd[0], buf, sizeof(buf));

	wctx = calloc(1, sizeof *wctx);
	if (wctx == NULL)
		assl_fatalx("unable to allocate context");

	wctx->c = assl_alloc_context(ASSL_M_TLSV1_CLIENT, 0);
	if (wctx->c == NULL)
		assl_fatalx("assl_alloc_context");

#ifdef USE_MEM_CERTS
	if (assl_use_mem_certs(wctx->c))
		assl_fatalx("assl_use_mem_certs");
#else
	if (assl_load_file_certs(wctx->c, "../ca/ca.crt", "client/client.crt",
	    "client/private/client.key"))
		assl_fatalx("assl_load_certs");
#endif
	memset(wctx->buf, 'M', sizeof(wctx->buf));
	wctx->tot = sizeof(wctx->buf);
	wctx->b = wctx->buf;

	if (assl_event_connect(wctx->c, "localhost", ASSL_DEFAULT_PORT,
	    ASSL_F_NONBLOCK, serve_rd_worker, serve_wr_worker, wctx))
		assl_fatalx("assl_connect");

	printf("try%d\n", cnt);
	assl_event_enable_write(wctx->c);
}



void
serve_rd_worker(int fd, short event, void *arg)
{
	printf("rd shouldn't be called\n");
}

void
serve_wr_worker(int fd, short event, void *arg)
{
	struct wrctx		*wctx = arg;
	int			close = 0;
	ssize_t			wr;

	printf("serve_wr_worker\n");

	wr = assl_write(wctx->c, wctx->b, wctx->tot);

	if (wr == -1) {
		/* unable write anything just return; */
		return;
	} else if (wr == 0 && wctx->tot != 0) {
		/* other end closed socket */
		close = 1;
	} else { 
		wctx->tot -= wr;
		wctx->b += wr;
	}

	if (wctx->tot == 0 || close == 1) {
		assl_event_close(wctx->c);
		free(wctx);
		cnt++;
		if (stop == 0)
			write(pfd[1], "a", 1);
		else
			event_loopexit(NULL);
	}
}
