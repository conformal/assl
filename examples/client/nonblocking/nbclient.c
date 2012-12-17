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

#define USE_MEM_CERTS

int
main(int argc, char *argv[])
{
	struct assl_context	*c;
	int			i;
	char			buf[65536 * 10], *b;
	ssize_t			wr, tot;
	void			*t;

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
		if (assl_connect(c, "localhost", ASSL_DEFAULT_PORT, ASSL_F_NONBLOCK))
			assl_fatalx("assl_connect");
		printf("cipher: %s\n", c->as_protocol);

		memset(buf, 'M', sizeof buf);
		for (tot = sizeof buf, b = buf; tot > 0;) {
			wr = assl_write(c, b, tot);
			if (wr == -1) {
				if (errno == EAGAIN) {
					printf("polling\n");
					if (assl_poll(c, 10 * 1000, POLLOUT, NULL) <= 0)
						assl_fatalx("assl_poll");
					continue;
				}
				printf("failed write\n");
				goto done;
			}
			tot -= wr;
			b += wr;
		}
done:
		if (assl_close(c)) {
			c = NULL;
			assl_fatalx("assl_disconnect");
		}
		printf("try%d\n", i);
	}

	return (0);
}
