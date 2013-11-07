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

#include <assl_socket.h>

/* versioning */
#define ASSL_STRINGIFY(x)	#x
#define ASSL_STR(x)		ASSL_STRINGIFY(x)
#define ASSL_VERSION_MAJOR	1
#define ASSL_VERSION_MINOR	5
#define ASSL_VERSION_PATCH	0
#define ASSL_VERSION		ASSL_STR(ASSL_VERSION_MAJOR) "." \
				ASSL_STR(ASSL_VERSION_MINOR) "." \
				ASSL_STR(ASSL_VERSION_PATCH)

const char	*assl_verstring(void);
void		 assl_version(int *major, int *minor, int *patch);

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
/* assl_alloc_context_v2 only flags */
#define ASSL_F_TLS1_2		(1<<28)
#define ASSL_F_TLS1_1		(1<<29)
#define ASSL_F_TLS1		(1<<30)
#define ASSL_F_SSLV3		(1<<31)

#define ASSL_GF_IGNORE_SELF_SIGNED	(1<<0)
#define ASSL_GF_IGNORE_EXPIRED		(1<<1)

/* Logging constants */
#define	ASSL_LOG_MSG		(1)
#define	ASSL_LOG_WARN		(2)
#define	ASSL_LOG_ERR		(3)

enum assl_method {
	ASSL_M_ALL,
	ASSL_M_ALL_CLIENT,
	ASSL_M_ALL_SERVER,
	ASSL_M_SSLV2_DEPRECATED,
	ASSL_M_SSLV2_CLIENT_DEPRECATED,
	ASSL_M_SSLV2_SERVER_DEPRECATED,
	ASSL_M_SSLV3,
	ASSL_M_SSLV3_CLIENT,
	ASSL_M_SSLV3_SERVER,
	ASSL_M_TLSV1,
	ASSL_M_TLSV1_CLIENT,
	ASSL_M_TLSV1_SERVER,
	ASSL_M_TLSV1_1,
	ASSL_M_TLSV1_1_CLIENT,
	ASSL_M_TLSV1_1_SERVER,
	ASSL_M_TLSV1_2,
	ASSL_M_TLSV1_2_CLIENT,
	ASSL_M_TLSV1_2_SERVER,
};

struct assl_context {
	/* generic */
	int			as_nonblock;	/* 1 when non-block */
	int			as_server;	/* 1 if server mode */
	int			as_keepalive;	/* 1 when keepalive is set */
	SSL			*as_ssl;
	SSL_SESSION		*as_ssl_session;
	int			as_sock;
	BIO			*as_sbio;
	DH			*as_dh;		/* dh param */

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
	int			as_curve;	/* named curve */

	/* peer IP */
	char			*as_peername;
	int			 as_ignore_expired_cert;
	int			 as_ignore_self_signed_cert;
};

struct assl_connect_opts {
	int		aco_rcvbuf; /* receive buffer size, 0 is unchanged. */
	int		aco_sndbuf; /* send buffer size, 0 is unchanged. */
	int		aco_flags; /* takes ASSL_F flags. */
};

/* contents of this structure are private */
struct assl_serve_ctx;

void			assl_initialize(void);
struct assl_context	*assl_alloc_context(enum assl_method, int);
void			assl_set_cert_flags(struct assl_context *, int);
int			assl_load_file_certs(struct assl_context *,
			    const char *, const char *, const char *);
int			assl_connect_opts(struct assl_context *, const char *,
				const char *, struct assl_connect_opts *);
int			assl_connect(struct assl_context *, const char *,
				const char *, int);
int			assl_serve_opts(const char *, const char *,
			    struct assl_connect_opts *,
			    void (*)(int), void (*)(void));
int			assl_serve(const char *, const char *, int,
			    void (*)(int), void (*)(void));
int			assl_accept(struct assl_context *, int);
__dead void		assl_fatalx(const char *, ...);
void			assl_warnx(const char *, ...);
ssize_t			assl_read(struct assl_context *, void *, size_t);
ssize_t			assl_write(struct assl_context *, void *, size_t);
int			assl_close(struct assl_context *);
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
void			assl_set_log_callback(void (*)(int, const char *));
int			assl_fd(struct assl_context *);

/* new api */
#define ASSL_ARG_NAMEDCURVE	"named_curve="
struct assl_context	*assl_alloc_context_v2(int, char *[]);

#ifndef INFTIM
#define INFTIM		(-1)
#endif

#endif /* AGGLOMERATEDSSL_H */
