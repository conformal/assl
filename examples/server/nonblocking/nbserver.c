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
#include <errno.h>
#include <poll.h>

#include "assl.h"

void			serve_callback(int);

void
serve_callback(int s)
{
	struct assl_context	*c;
	char			buf[65536 * 10], *b;
	ssize_t			rd, tot;

	c = assl_alloc_context(ASSL_M_TLSV1_2, 0);
	if (c == NULL)
		assl_fatalx("assl_alloc_context");

	if (assl_load_file_certs(c, "../ca/ca.crt", "server/server.crt",
	    "server/private/server.key"))
		assl_fatalx("assl_load_file_certs");

	if (assl_accept(c, s))
		assl_fatalx("assl_accept");
	printf("CIPHER: %s\n", c->as_protocol);

	for (tot = sizeof buf, b = buf; tot > 0; ) {
		rd = assl_read(c, b, tot);
		if (rd == -1) {
			if (errno == EAGAIN) {
				if (assl_poll(c, 10 * 1000, POLLIN, NULL) <= 0)
					assl_fatalx("assl_poll");
				continue;
			}
			goto done;
		}
		tot -= rd;
		b += rd;
	}
done:
	if (assl_close(c)) {
		c = NULL;
		assl_fatalx("assl_disconnect");
	}
}

int
main(int argc, char *argv[])
{
	assl_initialize();

	assl_serve(NULL, ASSL_DEFAULT_PORT, ASSL_F_NONBLOCK, serve_callback,
	    NULL);

	return (0);
}
