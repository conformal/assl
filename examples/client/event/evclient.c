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

#include "assl.h"
#include <event.h>

#define USE_MEM_CERTS

struct workctx {
	struct assl_context	*c;
	char			*b;
	ssize_t			tot;
	char			buf[65536 * 10];
};

void
rd_callback(int s, short event, void *arg)
{
	printf("rd_callback called, not expected");
	exit(2);
}

void
wr_callback(int s, short event, void *arg)
{
	struct workctx		*wctx = arg;
	int			close = 0;
	ssize_t			wr;

	wr = assl_write(wctx->c, wctx->b, wctx->tot);

	if (wr == -1) {
		return; /* pipe full */
	} else if (wr == 0 && wctx->tot != 0) {
		close = 1;
	} else {
		wctx->tot -= wr;
		wctx->b += wr;
	}

	if (wctx->tot == 0 || close == 1) {
		assl_event_close(wctx->c);
		free(wctx);
		event_loopbreak();
	}
}

int
main(int argc, char *argv[])
{
	struct assl_context	*c;
	int			i;
	void			*t;
	struct workctx          *wctx;

	event_init();
	assl_initialize();

#ifdef USE_MEM_CERTS
	if ((t = assl_load_file_certs_to_mem("../ca/ca.crt", "client/client.crt",
	    "client/private/client.key")) == NULL)
		assl_fatalx("assl_load_file_certs");
#endif

	for (i = 0;;i++) {
		c = assl_alloc_context(ASSL_M_TLSV1_CLIENT, 0);
		if (c == NULL)
			assl_fatalx("assl_alloc_context");

#ifdef USE_MEM_CERTS
		if (assl_use_mem_certs(c, t))
			assl_fatalx("assl_use_mem_certs");
#else
		if (assl_load_file_certs(c, "../ca/ca.crt", "client/client.crt",
		    "client/private/client.key"))
			assl_fatalx("assl_load_certs");
#endif

		wctx = calloc(1, sizeof(*wctx));
		memset(wctx->buf, 'M', sizeof wctx->buf);
		wctx->c = c;
		wctx->b = wctx->buf;
		wctx->tot = sizeof wctx->buf;

		if (assl_event_connect(c, "localhost", ASSL_DEFAULT_PORT,
		    ASSL_F_NONBLOCK, rd_callback, wr_callback, wctx))
			assl_fatalx("server connect failed");
		
		assl_event_enable_write(wctx->c);

		event_dispatch();
		printf("try%d\n", i);
	}

	return (0);
}
