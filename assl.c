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
#include "ssl_privsep.h"

static const char *cvstag = "$assl$";
static const char *version = "Release: "ASSL_VERSION;

/*
 * XXX todo:
 * XDR read/write
 * LDAP integration for certs
 * create CA certificate
 * create machine certificates
 * sign machine certificates
 * keep stats on read/write performance and connection overhead
 * come up with a scheme to deal with errors, < 0 for ssl and  > 0 libc
 * write proper regress tests
 */

#define ASSL_VERIFY_DEPTH	(1)

#include "assl_internal.h"

/* error handling */

#ifndef ASSL_NO_FANCY_ERRORS
void
assl_fatalx(const char *errstr)
{
	fprintf(stderr, "%s\n", errstr);
	exit(1);
}

void
assl_warnx(const char *errstr)
{
	fprintf(stderr, "%s\n", errstr);
}
#else
SLIST_HEAD(assl_error_stack, assl_error);

/* XXX NOT concurrency safe! */
char			assl_last_error[1024];
struct assl_error_stack	aes;

/* set to stop assl_serve */
volatile sig_atomic_t	assl_stop_serving;

/* set to indicate this is a child process */
pid_t			assl_child;

/* XXX these have to be global because openssl is retarded */
int			assl_ignore_self_signed_cert;
int			assl_ignore_expired_cert;

/* pre-loaded certificates */
void			*assl_mem_ca;
off_t			assl_mem_ca_len;
void			*assl_mem_cert;
off_t			assl_mem_cert_len;
void			*assl_mem_key;
off_t			assl_mem_key_len;

char *
assl_geterror(int et)
{
	char			*es;

	switch (et) {
	case ERR_LIBC:
		strlcpy(assl_last_error, strerror(errno), sizeof assl_last_error);
		break;
	case ERR_SSL:
		es = (char *)ERR_lib_error_string(ERR_get_error());
		if (es)
			strlcpy(assl_last_error, es, sizeof assl_last_error);
		else
			strlcpy(assl_last_error, "unknown SSL error",
			    sizeof assl_last_error);
		break;
	default:
		strlcpy(assl_last_error, "unknown error",
		    sizeof assl_last_error);
		/* FALLTHROUGH */
	case ERR_OWN:
		break;
	}

	return (assl_last_error);
}

void
assl_push_error(const char *file, const char *func, int line, int et)
{
	struct assl_error	*ce;

	if ((ce = calloc(1, sizeof *ce)) == NULL)
		exit(ENOMEM);
	if ((ce->file = strdup(file)) == NULL)
		exit(ENOMEM);
	if ((ce->func = strdup(func)) == NULL)
		exit(ENOMEM);
	if ((ce->errstr = strdup(assl_geterror(et))) == NULL)
		exit(ENOMEM);
	ce->line = line;

	SLIST_INSERT_HEAD(&aes, ce, link);
}

void
assl_err_stack_unwind(void)
{
	struct assl_error	*ce;

	while(!SLIST_EMPTY(&aes)) {
		ce = SLIST_FIRST(&aes);
		SLIST_REMOVE_HEAD(&aes, link);
		free(ce->file);
		free(ce->func);
		free(ce->errstr);
		free(ce);
	}
	SLIST_INIT(&aes);
}

void
assl_err_own(char *s, ...)
{
	va_list			ap;

	va_start(ap, s);
	vsnprintf(assl_last_error, sizeof assl_last_error, s, ap);
	va_end(ap);
}
void
assl_fatalx(const char *errstr)
{
	struct assl_error	*ce;

	fprintf(stderr, "%s\n\n", errstr);
	fprintf(stderr, "ASSL Fatal Error\n");

	SLIST_FOREACH(ce, &aes, link) {
		fprintf(stderr,
		    "\tfile:\t%s\n"
		    "\tfunct:\t%s\n"
		    "\tline:\t%d\n"
		    "\terror:\t%s\n\n",
		    ce->file,
		    ce->func,
		    ce->line,
		    ce->errstr);
	}

	if (assl_child)
		_exit(1);
	exit(1);
}

void
assl_warnx(const char *errstr)
{
	struct assl_error	*ce;

	fprintf(stderr, "%s\n\n", errstr);
	fprintf(stderr, "ASSL Warning\n");

	SLIST_FOREACH(ce, &aes, link) {
		fprintf(stderr,
		    "\tfile:\t%s\n"
		    "\tfunct:\t%s\n"
		    "\tline:\t%d\n"
		    "\terror:\t%s\n\n",
		    ce->file,
		    ce->func,
		    ce->line,
		    ce->errstr);
	}
}
#endif /* ASSL_NO_FANCY_ERRORS */

/* utility functions */
int
assl_set_nonblock(int fd)
{
	int			val, rv = 1;

	val = fcntl(fd, F_GETFL, 0);
	if (val < 0)
		goto done;

	if (val & O_NONBLOCK)
		return (0);

	val |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, val) == -1)
		goto done;

	rv = 0;
done:
	return (rv);
}

void
assl_initialize(void)
{
	/* shut gcc up */
	cvstag = cvstag;
	version = version;

	SSL_library_init();
	SSL_load_error_strings();

	/* Init hardware crypto engines. */
	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();

	OpenSSL_add_ssl_algorithms();

	assl_err_stack_unwind();
}

/* XXX this function has got to go, can't have globals like this */
void
assl_set_cert_flags(int flags)
{
	if (flags & ASSL_GF_IGNORE_EXPIRED)
		assl_ignore_expired_cert = 1;
	if (flags & ASSL_GF_IGNORE_SELF_SIGNED)
		assl_ignore_self_signed_cert = 1;
}

int
assl_verify_callback(int rv, X509_STORE_CTX *ctx)
{
	/* openssl is retarded that it doesn't pass in a void * for params */
	/*
	fprintf(stderr, "assl_verify_callback: ctx->error %d\n", ctx->error);
	*/
	rv = 0; /* fail */

	/* override expired and self signed certs */
	switch (ctx->error)
	{
		case X509_V_OK:
			rv = 1;
			break;
		case X509_V_ERR_CERT_HAS_EXPIRED:
			if (assl_ignore_expired_cert) {
				rv = 1;
				ctx->error = X509_V_OK;
				/*
				fprintf(stderr, "ignoring expired\n");
				*/
			}
			break;
		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
			if (assl_ignore_self_signed_cert) {
				rv = 1;
				ctx->error = X509_V_OK;
				/*
				fprintf(stderr, "ignoring self signed\n");
				*/
			}
			break;
		case X509_V_ERR_CERT_UNTRUSTED:
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
			rv = 1;
			ctx->error = X509_V_OK;
			/*
			fprintf(stderr, "ignoring %d\n", ctx->error);
			*/
			break;
	}

	/*
	fprintf(stderr, "assl_verify_callback: %s  rv %d error %d\n",
	   rv == 0 ? "failed" : "success", rv, ctx->error);
	*/

	return (rv);
}

void
assl_destroy_mem_certs(void)
{
	if (assl_mem_ca) {
		bzero(assl_mem_ca, assl_mem_ca_len);
		free(assl_mem_ca);
		assl_mem_ca = NULL;
		assl_mem_ca_len = 0;
	}
	if (assl_mem_cert) {
		bzero(assl_mem_cert, assl_mem_cert_len);
		free(assl_mem_cert);
		assl_mem_cert = NULL;
		assl_mem_cert_len = 0;
	}
	if (assl_mem_key) {
		bzero(assl_mem_key, assl_mem_key_len);
		free(assl_mem_key);
		assl_mem_key = NULL;
		assl_mem_key_len = 0;
	}
}

int
assl_load(const char *filename, void **buf, off_t *len)
{
	int			f = -1, rv = 1;
	struct stat		sb;

	assl_err_stack_unwind();

	if (filename == NULL || buf == NULL || len == NULL) {
		assl_err_own("no context, buffer or len");
		ERROR_OUT(ERR_OWN, done);
	}

	if ((f = open(filename, O_RDONLY)) == -1)
		ERROR_OUT(ERR_LIBC, done);
	if (fstat(f, &sb))
		ERROR_OUT(ERR_LIBC, done);

	if (*buf) {
		free(*buf);
		*buf = NULL;
	}

	*buf = malloc(sb.st_size + 1);
	if (*buf == NULL)
		ERROR_OUT(ERR_LIBC, done);

	if (read(f, *buf, sb.st_size) != sb.st_size)
		ERROR_OUT(ERR_LIBC, done);

	*len = sb.st_size + 1;

	rv = 0;
done:
	if (f != -1)
		close(f);

	return (rv);
}

int
assl_load_file_certs_to_mem(const char *ca, const char *cert, const char *key)
{
	int			rv = 1;

	assl_err_stack_unwind();

	if (ca && assl_load(ca, &assl_mem_ca, &assl_mem_ca_len)) {
		assl_err_own("assl_load ca failed");
		ERROR_OUT(ERR_OWN, done);
	}

	if (cert && assl_load(cert, &assl_mem_cert, &assl_mem_cert_len)) {
		assl_err_own("assl_load cert failed");
		ERROR_OUT(ERR_OWN, done);
	}

	if (key && assl_load(key, &assl_mem_key, &assl_mem_key_len)) {
		assl_err_own("assl_load key failed");
		ERROR_OUT(ERR_OWN, done);
	}

	rv = 0;
done:
	if (rv)
		assl_destroy_mem_certs();
	return (rv);
}

int
assl_use_mem_certs(struct assl_context *c)
{
	int			rv = 1;

	assl_err_stack_unwind();

	if (c == NULL) {
		assl_err_own("no context");
		ERROR_OUT(ERR_OWN, done);
	}

	if (c->as_server) {
		/* server requires all the goodies */
		if (assl_mem_ca == NULL || assl_mem_cert == NULL ||
		    assl_mem_key == NULL) {
			if (assl_mem_ca == NULL)
				assl_err_own("no ca");
			else if (assl_mem_cert == NULL)
				assl_err_own("no cert");
			else if (assl_mem_key == NULL)
				assl_err_own("no key");
			ERROR_OUT(ERR_OWN, done);
		}
	}

	c->as_mem_ca = assl_mem_ca;
	c->as_mem_ca_len = assl_mem_ca_len;
	c->as_mem_cert = assl_mem_cert;
	c->as_mem_cert_len = assl_mem_cert_len;
	c->as_mem_key = assl_mem_key;
	c->as_mem_key_len = assl_mem_key_len;

	/* use certs */
	if (!ssl_ctx_load_verify_memory(c->as_ctx, c->as_mem_ca,
	    c->as_mem_ca_len))
		ERROR_OUT(ERR_SSL, done);
	if (!ssl_ctx_use_certificate_chain(c->as_ctx, c->as_mem_cert,
	   c->as_mem_cert_len))
		ERROR_OUT(ERR_SSL, done);
	if (!ssl_ctx_use_private_key(c->as_ctx, c->as_mem_key,
	    c->as_mem_key_len))
		ERROR_OUT(ERR_SSL, done);
	if (!SSL_CTX_check_private_key(c->as_ctx))
		ERROR_OUT(ERR_SSL, done);

	rv = 0;
done:
	return (rv);
}

int
assl_load_file_certs(struct assl_context *c, const char *ca, const char *cert,
		const char *key)
{
	int			rv = 1;
	SSL_CTX			*ctx;

	assl_err_stack_unwind();

	if (c == NULL) {
		assl_err_own("no context");
		ERROR_OUT(ERR_OWN, done);
	}
	ctx = c->as_ctx;

	if (c->as_server) {
		/* server requires all the goodies */
		if (ca == NULL || cert == NULL || key == NULL) {
			if (ca == NULL)
				assl_err_own("no ca");
			else if (cert == NULL)
				assl_err_own("no cert");
			else if (key == NULL)
				assl_err_own("no key");
			ERROR_OUT(ERR_OWN, done);
		}
	}

	if (ca && !SSL_CTX_load_verify_locations(ctx, ca, NULL))
		ERROR_OUT(ERR_SSL, done);
	if (cert && !SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM))
		ERROR_OUT(ERR_SSL, done);
	if (key && !SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM))
		ERROR_OUT(ERR_SSL, done);
	if (key && !SSL_CTX_check_private_key(ctx))
		ERROR_OUT(ERR_SSL, done);
	if (c->as_server)
		SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(ca));

	/* use callback to ignore some errors such as expired cert */
	SSL_CTX_set_verify(c->as_ctx, c->as_verify_mode, assl_verify_callback);
	SSL_CTX_set_mode(c->as_ctx, SSL_MODE_AUTO_RETRY);
	SSL_CTX_set_verify_depth(c->as_ctx, c->as_verify_depth);

	rv = 0;
done:
	return (rv);
}

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#define SSL_METHOD_CONST const
#else
#define SSL_METHOD_CONST
#endif

struct assl_context *
assl_alloc_context(enum assl_method m, int flags)
{
	struct assl_context	*c = NULL;
	int			server = 0;
	SSL_METHOD_CONST SSL_METHOD	*meth;

	assl_err_stack_unwind();

	if (flags & ASSL_F_CHILD)
		assl_child = getpid();

	switch (m) {
	case ASSL_M_ALL:
		meth = SSLv23_method();
		server = 1;
		break;
	case ASSL_M_ALL_CLIENT:
		meth = SSLv23_client_method();
		break;
	case ASSL_M_ALL_SERVER:
		meth = SSLv23_server_method();
		server = 1;
		break;
	case ASSL_M_SSLV2:
		meth = SSLv2_method();
		server = 1;
		break;
	case ASSL_M_SSLV2_CLIENT:
		meth = SSLv2_client_method();
		break;
	case ASSL_M_SSLV2_SERVER:
		meth = SSLv2_server_method();
		server = 1;
		break;
	case ASSL_M_SSLV3:
		meth = SSLv3_method();
		server = 1;
		break;
	case ASSL_M_SSLV3_CLIENT:
		meth = SSLv3_client_method();
		break;
	case ASSL_M_SSLV3_SERVER:
		meth = SSLv3_server_method();
		server = 1;
		break;
	case ASSL_M_TLSV1:
		meth = TLSv1_method();
		server = 1;
		break;
	case ASSL_M_TLSV1_CLIENT:
		meth = TLSv1_client_method();
		break;
	case ASSL_M_TLSV1_SERVER:
		meth = TLSv1_server_method();
		server = 1;
		break;
	default:
		assl_err_own("invalid method %d", m);
		ERROR_OUT(ERR_OWN, unwind);
	}

	c = calloc(1, sizeof *c);
	if (c == NULL)
		ERROR_OUT(ERR_LIBC, unwind);

	/* set some sane values */
	c->as_sock = -1;
	c->as_server = server;
	c->as_method = meth;
	c->as_ctx = SSL_CTX_new(meth);
	if (c->as_ctx == NULL)
		ERROR_OUT(ERR_SSL, unwind);

	/* allow all buggy implementations to play */
	SSL_CTX_set_options(c->as_ctx, SSL_OP_ALL);

	if (server)
		SSL_CTX_set_options(c->as_ctx,
		    SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

	/*
	 * Assume we want to verify client and server certificates
	 * client ignores SSL_VERIFY_FAIL_IF_NO_PEER_CERT so just set it
	 *
	 * This needs to be set for anonymous connections
	 */
	if (flags & ASSL_F_DONT_VERIFY)
		c->as_verify_mode = SSL_VERIFY_NONE;
	else
		c->as_verify_mode = SSL_VERIFY_FAIL_IF_NO_PEER_CERT |
		    SSL_VERIFY_PEER;

	/* do not encrypt transport */
	if (flags & ASSL_F_DONT_ENCRYPT)
		if (!SSL_CTX_set_cipher_list(c->as_ctx, "NULL-SHA"))
			ERROR_OUT(ERR_SSL, unwind);

	c->as_verify_depth = ASSL_VERIFY_DEPTH;

	return (c);
unwind:
	if (c)
		free(c);

	return (NULL);
}

int
assl_poll(struct assl_context *c, int mseconds, short event, short *revents)
{
	struct pollfd		fds[1];
	int			nfds, rv = -1;

	assl_err_stack_unwind();

	if (c == NULL) {
		assl_err_own("no context");
		ERROR_OUT(ERR_OWN, done);
	}

	errno = 0;
	fds[0].fd = c->as_sock;
	fds[0].events = event;
	nfds = poll(fds, 1, mseconds);
	if (nfds == 0) {
		rv = 0;
		assl_err_own("poll timeout");
		ERROR_OUT(ERR_OWN, done);
	} else if (nfds == -1 || (fds[0].revents & (POLLERR|POLLHUP|POLLNVAL)))
		ERROR_OUT(ERR_LIBC, done);

	rv = 1;
	if (revents)
		*revents = fds[0].revents;
done:
	return (rv);
}

int
assl_negotiate_nonblock(struct assl_context *c)
{
	int			r, rv = 1, p;

	assl_err_stack_unwind();

	if (c == NULL) {
		assl_err_own("no context");
		ERROR_OUT(ERR_OWN, done);
	}

	for (;;) {
		if (c->as_server)
			r = SSL_accept(c->as_ssl);
		else
			r = SSL_connect(c->as_ssl);

		switch (SSL_get_error(c->as_ssl, r)) {
		case SSL_ERROR_NONE:
			rv = 0;
			goto done;
		case SSL_ERROR_WANT_READ:
			p = assl_poll(c, 10 * 1000, POLLIN, NULL);
			if (p == -1) {
				if (errno == EINTR)
					continue;
				ERROR_OUT(ERR_LIBC, done);
			}
			break;
		case SSL_ERROR_SYSCALL:
			rv = -1;
			ERROR_OUT(ERR_LIBC, done);
			break;
		case SSL_ERROR_ZERO_RETURN:
			/* connection hung up on the other side */
			rv = -1;
			assl_err_own("connection closed by peer");
			ERROR_OUT(ERR_OWN, done);
			break;
		default:
			rv = -1;
			/* XXX we want this additional information */
			/*
			ERR_print_errors_fp(stderr);
			*/
			ERROR_OUT(ERR_SSL, done);
		}
	}
done:
	return (rv);
}

int
assl_connect(struct assl_context *c, const char *host, const char *port,
		int flags)
{
	struct addrinfo		hints, *res = NULL, *ai;
	int			p, s = -1, on = 1, rv = 1, retries;

	assl_err_stack_unwind();

	if (c == NULL || host == NULL) {
		if (c == NULL)
			assl_err_own("no context");
		else if (host == NULL)
			assl_err_own("no host");
		ERROR_OUT(ERR_OWN, done);
	}

	p = atoi(port);
	if (p <= 0 || p > 65535) {
		assl_err_own("invalid port %d", p);
		ERROR_OUT(ERR_OWN, done);
	}

	bzero(&hints, sizeof(struct addrinfo));
	hints.ai_flags = AI_CANONNAME;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(host, port, &hints, &res))
		ERROR_OUT(ERR_LIBC, done);

	for (ai = res; ai; ai = ai->ai_next) {
		retries = 0;
		if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
		    continue;
retry:
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (s < 0)
			ERROR_OUT(ERR_LIBC, done);
		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on,
		    sizeof(on)) == -1) {
			close(s);
			ERROR_OUT(ERR_LIBC, done);
		}

		if (connect(s, ai->ai_addr, ai->ai_addrlen) < 0) {
			close(s);
			/*
			 * required for unit test
			 * without this quick connections will eventually
			 * fail with a "Address already in use" error
			 */
			if (errno == EADDRINUSE) {
				if (retries > 5)
					ERROR_OUT(ERR_LIBC, done);
				retries++;
				goto retry;
			}

			ERROR_OUT(ERR_LIBC, done);
		}

		c->as_sock = s;
		if (flags & ASSL_F_NONBLOCK) {
			if (assl_set_nonblock(s))
				ERROR_OUT(ERR_LIBC, done);
			c->as_nonblock = 1;
		}

		rv = -1; /* negative for ssl errors */

		/* go do ssl magic */
		c->as_ssl = SSL_new(c->as_ctx);
		c->as_sbio = BIO_new_socket(c->as_sock, BIO_CLOSE);
		SSL_set_bio(c->as_ssl, c->as_sbio, c->as_sbio);
		SSL_set_connect_state(c->as_ssl);

		if (assl_negotiate_nonblock(c)) {
			assl_err_own("SSL/TLS connect failed");
			ERROR_OUT(ERR_OWN, done);
		}

		if (c->as_verify_mode == SSL_VERIFY_NONE)
			break;

		if (SSL_get_verify_result(c->as_ssl) != X509_V_OK)
			ERROR_OUT(ERR_SSL, done);

		/* all done */
		break;
	}

	c->as_ssl_session = SSL_get_session(c->as_ssl);

	rv = 0;
done:
	if (res)
		freeaddrinfo(res);
	return (rv);
}

int
assl_accept(struct assl_context *c, int s)
{
	int			r, rv = 1;

	assl_err_stack_unwind();

	if (c == NULL) {
		assl_err_own("no context");
		ERROR_OUT(ERR_OWN, done);
	}
	c->as_sock = s;

	/* figure out if context is non-blocking */
	r = fcntl(s, F_GETFL, 0);
	if (r < 0)
		ERROR_OUT(ERR_LIBC, done);
	c->as_nonblock = r & O_NONBLOCK ? 1 : 0;

	c->as_ssl = SSL_new(c->as_ctx);
	c->as_sbio = BIO_new_socket(c->as_sock, BIO_CLOSE);
	SSL_set_bio(c->as_ssl, c->as_sbio, c->as_sbio);
	SSL_set_accept_state(c->as_ssl);

	if (assl_negotiate_nonblock(c)) {
		assl_err_own("SSL/TLS accept failed");
		ERROR_OUT(ERR_OWN, done);
	}

	c->as_ssl_session = SSL_get_session(c->as_ssl);

	rv = 0;
done:
	return (rv);
}

int
assl_serve(const char *listen_ip, const char *listen_port, int flags,
		void (*cb)(int), void (*intr_cb)(void))
{
	struct addrinfo		hints, *res, *ai;
	int			s = -1, on = 1, i, nfds, x, c;
	struct pollfd		fds[2];

	assl_err_stack_unwind();

	if (cb == NULL) {
		assl_err_own("no callback");
		ERROR_OUT(ERR_OWN, done);
	}

	if (listen_port == NULL)
		listen_port = ASSL_DEFAULT_PORT;

	bzero(&hints, sizeof hints);
	hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if ((i = getaddrinfo(listen_ip, listen_port, &hints, &res))) {
		assl_err_own("%s", gai_strerror(i));
		ERROR_OUT(ERR_OWN, done);
	}

	bzero(fds, sizeof fds);
	for (ai = res, i = 0; ai && i < 2; ai = ai->ai_next, i++) {
		if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
		    continue;
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (s < 0)
			continue;

		if (flags & ASSL_F_NONBLOCK)
			if (assl_set_nonblock(s)) {
				close(s);
				ERROR_OUT(ERR_LIBC, done);
			}

		setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

		if (bind(s, ai->ai_addr, ai->ai_addrlen) < 0) {
			close(s);
			continue;
		}

		if (listen(s, /* XXX */ 10) < 0) {
			close(s);
			continue;
		}

		fds[i].fd = s;
		fds[i].events = POLLIN;
	}
	freeaddrinfo(res);

	for (;assl_stop_serving == 0;) {
		nfds = poll(fds, i, INFTIM);
		if (nfds == -1) {
			if (errno != EINTR)
				ERROR_OUT(ERR_LIBC, done);
			if (intr_cb)
				intr_cb();
			continue;
		}

		for (x = 0, c = 0; x < i && c < nfds; x++) {
			if (fds[x].revents & (POLLERR | POLLHUP | POLLNVAL))
				ERROR_OUT(ERR_LIBC, done);
			if (!(fds[x].revents & POLLIN))
				continue;

			c++;
			if ((s = accept(fds[x].fd, 0, 0)) == -1)
				ERROR_OUT(ERR_LIBC, done);

			/* hand off to caller */
			cb(s);
			if (flags & ASSL_F_CLOSE_SOCKET)
				close(s);
		}
	}

	/* NOTREACHED */
done:
	return (1);
}

ssize_t
assl_read_write(struct assl_context *c, void *buf, size_t nbytes, int rd)
{
	int			r, sz;
	uint8_t			*b;
	ssize_t			tot = 0;

	assl_err_stack_unwind();

	if (c == NULL) {
		assl_err_own("no context");
		ERROR_OUT(ERR_OWN, done);
	}

	for (b = buf, sz = nbytes; sz > 0;) {
		if (rd)
			r = SSL_read(c->as_ssl, b, sz);
		else
			r = SSL_write(c->as_ssl, b, sz);

		if (r == 0) {
			/* dirty hang up on the other side */
			tot = 0;
			goto done;
		}

		switch (SSL_get_error(c->as_ssl, r)) {
		case SSL_ERROR_NONE:
			tot += r;
			b += r;
			sz -= r;
			if (c->as_nonblock) {
				errno = EAGAIN;
				goto done;
			}
			break;
		case SSL_ERROR_WANT_READ:
			if (c->as_nonblock) {
				tot = -1;
				errno = EAGAIN;
				goto done;
			}
			errx(1, "assl_read_write read assert"); /* XXX delete */
			break;
		case SSL_ERROR_WANT_WRITE:
			if (c->as_nonblock) {
				tot = -1;
				errno = EAGAIN;
				goto done;
			}
			errx(1, "assl_read_write write assert"); /* XXX delete */
			break;
		case SSL_ERROR_SYSCALL:
			/* reuse errno */
			tot = -1;
			ERROR_OUT(ERR_LIBC, done);
			break;
		case SSL_ERROR_ZERO_RETURN:
			/* clean hang up on the other side */
			tot = 0;
			goto done;
		default:
			tot = -1;
			ERROR_OUT(ERR_SSL, done);
		}
	}

done:
	return (tot);
}

ssize_t
assl_read(struct assl_context *c, void *buf, size_t nbytes)
{
	return (assl_read_write(c, buf, nbytes, 1));
}

ssize_t
assl_write(struct assl_context *c, void *buf, size_t nbytes)
{
	return (assl_read_write(c, buf, nbytes, 0));
}

int
assl_close(struct assl_context *c)
{
	assl_err_stack_unwind();

	if (c == NULL) {
		assl_err_own("no context");
		ERROR_OUT(ERR_OWN, done);
	}
	if (c->as_ssl) {
		SSL_shutdown(c->as_ssl);
		SSL_free(c->as_ssl);
		c->as_ssl = NULL;
	}
	if (c->as_sock != -1) {
		close(c->as_sock);
		c->as_sock = -1;
	}
	if (c->as_ctx) {
		SSL_CTX_free(c->as_ctx);
		c->as_ctx = NULL;
	}

	free(c);
done:
	return (0);
}

ssize_t
assl_read_write_timeout(struct assl_context *c, void *buf, size_t nbytes,
    unsigned to, int rw)
{
	int			rv = -1, timeout, pr, retval, pd;
	ssize_t			tot, bufsz;
	struct timeval		start, end, elapsed;
	void			*b;

	if (c == NULL) {
		assl_err_own("no context");
		ERROR_OUT(ERR_OWN, done);
	}
	if (c->as_nonblock != 1) {
		assl_err_own("must be in non-blocking mode");
		ERROR_OUT(ERR_OWN, done);
	}
	if (to < 2) {
		assl_err_own("invalid timeout");
		ERROR_OUT(ERR_OWN, done);
	}

	if (gettimeofday(&start, NULL) == -1) {
		assl_err_own("start gettimeofday failed");
		ERROR_OUT(ERR_OWN, done);
	}

	pd = rw == 1 ? POLLIN : POLLOUT;
	for (tot = nbytes, bufsz = 0, b = buf; tot > 0; ) {
		if (gettimeofday(&end, NULL)) {
			assl_err_own("end gettimeofday failed");
			ERROR_OUT(ERR_OWN, done);
		}
		timersub(&end, &start, &elapsed);
		timeout = to - elapsed.tv_sec;
		if (elapsed.tv_sec > to || timeout <= 0) {
			assl_err_own("timeout");
			ERROR_OUT(ERR_OWN, done);
		}

		if ((pr = assl_poll(c, timeout * 1000, pd, NULL)) == -1) {
			if (errno == EINTR)
				continue; /* signal */
			assl_err_own("assl_poll");
			ERROR_OUT(ERR_OWN, done);
		}
		if (pr == 0)
			continue; /* poll timeout */

		if (rw == 1)
			retval = assl_read(c, b, tot);
		else
			retval = assl_write(c, b, tot);

		if (retval == 0)
			break;
		if (retval == -1) {
			if (errno == EAGAIN || errno == EINTR)
				continue; /* signal or nothing to read/write */
			assl_err_own("assl_read/assl_write");
			ERROR_OUT(ERR_OWN, done);
		}

		tot -= retval;
		b += retval;
		bufsz += retval;
	}

	rv = bufsz;
done:
	return (rv);
}

ssize_t
assl_read_timeout(struct assl_context *c, void *buf, size_t n, unsigned to)
{
	return (assl_read_write_timeout(c, buf, n, to, 1));
}

ssize_t
assl_write_timeout(struct assl_context *c, void *buf, size_t n, unsigned to)
{
	return (assl_read_write_timeout(c, buf, n, to, 0));
}

ssize_t
assl_gets(struct assl_context *c, char *s, int size)
{
	int			r, quit;
	ssize_t			tot = 0;

	/*
	 * this is a low speed interface to facilitate \r\n type protocols
	 *
	 * XXX it might be an idea to buffer the input instead of doing a read
	 * with length = 1
	 */

	if (c == NULL) {
		assl_err_own("no context");
		ERROR_OUT(ERR_OWN, bad);
	}
	if (s == NULL) {
		assl_err_own("invalid buffer");
		ERROR_OUT(ERR_OWN, bad);
	}

	for (quit = 0; size > 1 && quit == 0;) {
		r = assl_read(c, s, 1);
		if (r == 0)
			return (0);
		if (r == -1) {
			if (errno == EAGAIN || errno == EINTR)
				if (tot)
					return (tot);
			ERROR_OUT(ERR_LIBC, bad); /* XXX probably LIBC */
		}

		*(s + 1) = '\0';
		if (*s == '\n')
			quit = 1;

		s += r;
		size -= r;
		tot += r;

	}

	/* return bytes read - NUL */
	return (tot);
bad:
	return (-1);
}

ssize_t
assl_puts(struct assl_context *c, char *s, int send_nul)
{
	ssize_t			tot = 0;
	size_t			len;

	if (c == NULL) {
		assl_err_own("no context");
		ERROR_OUT(ERR_OWN, bad);
	}
	if (s == NULL) {
		assl_err_own("invalid buffer");
		ERROR_OUT(ERR_OWN, bad);
	}

	len = strlen(s);
	if (len == 0 || (len == 1 && send_nul == 0)) {
		errno = EINVAL;
		assl_err_own("invalid length");
		ERROR_OUT(ERR_OWN, bad);
	}
	if (send_nul)
		len += 1;

	tot = assl_write(c, s, len);
	if (tot == 0)
		return (0);
	if (tot == -1) {
		if (errno == EAGAIN || errno == EINTR)
			if (tot)
				return (tot);
		ERROR_OUT(ERR_LIBC, bad); /* XXX probably LIBC */
	}

	return (tot);
bad:
	return (-1);
}
