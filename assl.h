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

#ifndef AGGLOMERATEDSSL_H
#define AGGLOMERATEDSSL_H

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <netinet/in.h>
#include <netdb.h>

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#define ASSL_DEFAULT_PORT	"4433"
#define ASSL_F_NONBLOCK		(1<<0)
#define ASSL_F_CLOSE_SOCKET	(1<<1)
#define ASSL_F_BLOCK		(0)

enum assl_method {
	ASSL_M_ALL,
	ASSL_M_ALL_CLIENT,
	ASSL_M_ALL_SERVER,
	ASSL_M_SSLV2,
	ASSL_M_SSLV2_CLIENT,
	ASSL_M_SSLV2_SERVER,
	ASSL_M_SSLV3,
	ASSL_M_SSLV3_CLIENT,
	ASSL_M_SSLV3_SERVER,
	ASSL_M_TLSV1,
	ASSL_M_TLSV1_CLIENT,
	ASSL_M_TLSV1_SERVER
};

struct assl_context {
	/* generic */
	int			as_nonblock;	/* 1 when non-block */
	int			as_server;	/* 1 if server mode */
	SSL			*as_ssl;
	int			as_sock;
	BIO			*as_sbio;

	/* openssl */
	SSL_METHOD		*as_method;
	SSL_CTX			*as_ctx;
	X509			*as_ca;
	X509			*as_cert;
	EVP_PKEY		*as_key;
	int			as_verify_mode;
	int			as_verify_depth;
};

void			assl_initialize(void);
struct assl_context	*assl_alloc_context(enum assl_method);
int			assl_load_file_certs(struct assl_context *, char *,
			    char *, char *);
int			assl_connect(struct assl_context *, char *, char *,
			    int);
int			assl_serve(char *, char *, int, void (*)(int));
int			assl_accept(struct assl_context *, int);
void			assl_fatalx(char *);
ssize_t			assl_read(struct assl_context *, void *, size_t);
ssize_t			assl_write(struct assl_context *, void *, size_t);
int			assl_close(struct assl_context *);
int			assl_poll(struct assl_context *, int, short);
#endif /* AGGLOMERATEDSSL_H */
