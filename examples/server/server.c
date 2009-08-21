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

void			serve_callback(int);

void
serve_callback(int s)
{
	struct assl_context	*c;

	c = assl_alloc_context(ASSL_M_ALL_SERVER);
	if (c == NULL)
		errx(1, "assl_alloc_context");

	if (assl_load_file_certs(c, "../ca/ca.crt", "server/server.crt",
	    "server/private/server.key"))
		errx(1, "assl_load_certs");

	if (assl_accept(c, s))
		errx(1, "assl_accept");

	errx(1, "do something!");
}

int
main(int argc, char *argv[])
{
	assl_initialize();

	assl_serve(NULL, ASSL_DEFAULT_PORT, serve_callback);
	
	return (0);
}