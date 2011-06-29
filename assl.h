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

#ifdef NEED_LIBCLENS
#include <clens.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/queue.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netdb.h>

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/engine.h"

/* versioning */
#define ASSL_VERSION_MAJOR	0
#define ASSL_VERSION_MINOR	9
#define ASSL_VERSION_PATCH	8
#define ASSL_VERSION		"0.9.8"

void	assl_version(int *major, int *minor, int *patch);

#define ASSL_DEFAULT_PORT	"4433"

#define ASSL_F_NONBLOCK		(1<<0)
#define ASSL_F_CLOSE_SOCKET	(1<<1)
#define ASSL_F_CHILD		(1<<2)
#define ASSL_F_DONT_VERIFY	(1<<3)
#define ASSL_F_DONT_ENCRYPT	(1<<4)
#define ASSL_F_KEEPALIVE	(1<<5)
#define ASSL_F_LOWDELAY		(1<<6)
#define ASSL_F_THROUGHPUT	(1<<7)
#define ASSL_F_BLOCK		(0)

#define ASSL_GF_IGNORE_SELF_SIGNED	(1<<0)
#define ASSL_GF_IGNORE_EXPIRED		(1<<1)

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
	SSL_SESSION		*as_ssl_session;
	int			as_sock;
	BIO			*as_sbio;

	/* memory certificates */
	void			*as_token;

	/* openssl */
	const SSL_METHOD	*as_method;
	SSL_CTX			*as_ctx;
	int			as_verify_mode;
	int			as_verify_depth;

	/* protocol defs */
	X509			*as_peer;
	int			as_bits;	/* -1 invalid */
	char			as_protocol[128];

	/* event */
	struct event		*as_ev_rd;
	struct event		*as_ev_wr;

	/* peer IP */
	char			*as_peername;
};

/* contents of this structure are private */
struct assl_serve_ctx;

void			assl_initialize(void);
struct assl_context	*assl_alloc_context(enum assl_method, int);
void			assl_set_cert_flags(int);
int			assl_load_file_certs(struct assl_context *,
			    const char *, const char *, const char *);
int			assl_connect(struct assl_context *, const char *,
				const char *, int);
int			assl_event_connect(struct assl_context *, const char *,
			    const char *, int,
			    void (*rd_cb)(int, short, void *),
			    void (*wr_cb)(int, short, void *), void *);
int			assl_serve(const char *, const char *, int,
			    void (*)(int), void (*)(void));
struct assl_serve_ctx	*assl_event_serve(const char *, const char *, int flags,
			    void (*)(int, short, void *), void *);
void			assl_event_serve_stop(struct assl_serve_ctx *);
int			assl_accept(struct assl_context *, int);
int			assl_event_accept(struct assl_context *, int,
			    void (*)(int, short, void *),
			    void (*)(int, short, void *),
			    void *);
void			assl_fatalx(const char *, ...);
void			assl_warnx(const char *, ...);
ssize_t			assl_read(struct assl_context *, void *, size_t);
ssize_t			assl_write(struct assl_context *, void *, size_t);
int			assl_close(struct assl_context *);
int			assl_event_close(struct assl_context *);
int			assl_poll(struct assl_context *, int, short, short *);
ssize_t			assl_read_timeout(struct assl_context *, void *, size_t,
			    unsigned);
ssize_t			assl_write_timeout(struct assl_context *, void *,
			    size_t, unsigned);
ssize_t			assl_gets(struct assl_context *, char *, int);
ssize_t			assl_puts(struct assl_context *, char *, int);

void			*assl_load_file_certs_to_mem(const char *, const char *,
			    const char *);
int			assl_use_mem_certs(struct assl_context *, void *);
int			assl_destroy_mem_certs(void *);
void			assl_event_enable_write(struct assl_context *);
void			assl_event_disable_write(struct assl_context *);

#ifdef __linux__
#define INFTIM		(-1)
#endif

#endif /* AGGLOMERATEDSSL_H */
