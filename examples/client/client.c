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

int
main(int argc, char *argv[])
{
	struct assl_context	*c;

	assl_initialize();

	c = assl_alloc_context(ASSL_M_TLSV1_CLIENT);
	if (c == NULL)
		errx(1, "assl_alloc_context");

	if (assl_load_file_certs(c, "../ca/ca.crt", "client/client.crt",
	    "client/private/client.key"))
		errx(1, "assl_load_certs");

	if (assl_connect(c, "localhost", ASSL_DEFAULT_PORT))
		errx(1, "assl_connect");

	return (0);
}
