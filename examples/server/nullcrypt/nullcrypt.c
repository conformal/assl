/*
 * Copyright (c) 2010 Marco Peereboom <marco@peereboom.us>
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

void			serve_callback(int);

void
serve_callback(int s)
{
	struct assl_context	*c;
	char			buf[65536 * 10];
	ssize_t			rd;

	/* anonymous connection */
	/*
	c = assl_alloc_context(ASSL_M_TLSV1_SERVER, ASSL_F_DONT_ENCRYPT | ASSL_F_DONT_VERIFY);
	*/

	/* authenticated connections */
	//c = assl_alloc_context(ASSL_M_TLSV1_SERVER, ASSL_F_DONT_ENCRYPT);
	char			*argv[] = { ASSL_ARG_NAMEDCURVE "prime256v1", NULL };
	c = assl_alloc_context_v2(ASSL_F_TLS1_2 | ASSL_F_DONT_ENCRYPT, argv);
	if (c == NULL)
		assl_fatalx("assl_alloc_context");

	if (assl_load_file_certs(c, "../ca/ca.crt", "server/server.crt",
	    "server/private/server.key"))
		assl_fatalx("assl_load_file_certs");

	if (assl_accept(c, s))
		assl_fatalx("assl_accept");
	printf("CIPHER: %s\n", c->as_protocol);

	rd = assl_read(c, buf, sizeof buf);
	if (rd == -1)
		assl_fatalx("assl_read");

	if (assl_close(c)) {
		c = NULL;
		assl_fatalx("assl_disconnect");
	}
}

int
main(int argc, char *argv[])
{
	assl_initialize();

	assl_serve(NULL, ASSL_DEFAULT_PORT, ASSL_F_BLOCK, serve_callback, NULL);

	return (0);
}

