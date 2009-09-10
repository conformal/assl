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

static const char *cvstag = "$assl$";
static const char *version = "Release: "ASSL_VERSION;

/*
 * XXX todo:
 * fgets/fputs blocking
 * fgets/fputs non-blocking
 * XDR read/write
 * LDAP integration for certs
 * create CA certificate
 * create machine certificates
 * sign machine certificates
 * keep stats on read/write performance and connection overhead
 * come up with a scheme to deal with errors, < 0 for ssl and  > 0 libc
 * add reconnect code
 * write proper regress tests
 */

/* error handling */
#define ASSL_NO_FANCY_ERRORS

#ifndef ASSL_NO_FANCY_ERRORS
#define ERROR_OUT(e, g) do { goto g; } while (0)
#define assl_err_stack_unwind() do { } while (0)
#define assl_err_own(s, ...) do { } while (0)

void
assl_fatalx(char *errstr)
{
	fprintf(stderr, "%s\n", errstr);
	exit(1);
}
#else
#define ERR_LIBC	(0)
#define ERR_SSL		(1)
#define ERR_OWN		(2)

#define ERROR_OUT(e, g)	do { assl_push_error(__FILE__, __FUNCTION__, __LINE__, e); goto g; } while(0)

struct assl_error {
	SLIST_ENTRY(assl_error)	link;

	char			*file;
	char			*func;
	int			line;
	char			*errstr;
};
SLIST_HEAD(assl_error_stack, assl_error);

/* XXX NOT concurrency safe! */
char			assl_last_error[1024];
struct assl_error_stack	aes;

/* set to stop assl_serve */
volatile sig_atomic_t	assl_stop_serving;

/* set to indicate this is a child process */
pid_t			assl_child;

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
assl_push_error(char *file, char *func, int line, int et)
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
	struct assl_error	*ce, *next;

	for (ce = SLIST_FIRST(&aes); ce != SLIST_END(&aes); ce = next) {
		next = SLIST_NEXT(ce, link);
		free(ce->file);
		free(ce->func);
		free(ce->errstr);
		free(ce);
		SLIST_REMOVE(&aes, ce, assl_error, link);
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
assl_fatalx(char *errstr)
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

/* tiny ssl functions */
void
assl_initialize(void)
{
	/* shut gcc up */
	cvstag = cvstag;
	version = version;

	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

	assl_err_stack_unwind();
}

int
assl_load_file_certs(struct assl_context *c, char *ca, char *cert, char *key)
{
	int			rv = 1;
	SSL_CTX			*ctx;

	assl_err_stack_unwind();

	if (c == NULL) {
		assl_err_own("no context");
		ERROR_OUT(ERR_OWN, done);
	}
	ctx = c->as_ctx;

	/* XXX CA might not be required for clients */
	if (ca == NULL || cert == NULL || key == NULL) {
		if (ca == NULL)
			assl_err_own("no ca");
		else if (cert == NULL)
			assl_err_own("no cert");
		else if (key == NULL)
			assl_err_own("no key");
		ERROR_OUT(ERR_OWN, done);
	}

	if (!SSL_CTX_load_verify_locations(ctx, ca, NULL))
		ERROR_OUT(ERR_SSL, done);
	if (!SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM))
		ERROR_OUT(ERR_SSL, done);
	if (!SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM))
		ERROR_OUT(ERR_SSL, done);
	if (!SSL_CTX_check_private_key(ctx))
		ERROR_OUT(ERR_SSL, done);
	if (c->as_server)
		SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(ca));

	rv = 0;
done:
	return (rv);
}

void
assl_setup_ssl(struct assl_context *c)
{
	int			x;
	assl_err_stack_unwind();

	if (c == NULL) {
		assl_err_own("no context");
		ERROR_OUT(ERR_OWN, done);
	}

	SSL_CTX_set_mode(c->as_ctx, SSL_MODE_AUTO_RETRY);
	SSL_CTX_set_verify(c->as_ctx, c->as_verify_mode, NULL);
	SSL_CTX_set_verify_depth(c->as_ctx, c->as_verify_depth);
done:
	x = x; /* shut gcc up */
}

struct assl_context *
assl_alloc_context(enum assl_method m, int flags)
{
	struct assl_context	*c = NULL;
	SSL_METHOD		*meth;
	int			server = 0;

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

	/*
	 * Assume we want to verify client and server certificates
	 * client ignores SSL_VERIFY_FAIL_IF_NO_PEER_CER so just set it
	 */
	c->as_verify_mode = SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_PEER;
	c->as_verify_depth = 1;

	return (c);
unwind:
	if (c)
		free(c);

	return (NULL);
}

int
assl_poll(struct assl_context *c, int mseconds, short event)
{
	struct pollfd		fds[1];
	int			nfds, rv = -1;

	assl_err_stack_unwind();

	if (c == NULL) {
		assl_err_own("no context");
		ERROR_OUT(ERR_OWN, done);
	}

	fds[0].fd = c->as_sock;
	fds[0].events = event;
	nfds = poll(fds, 1, mseconds);
	if (nfds == 0) {
		rv = 0;
		assl_err_own("poll timeout");
		ERROR_OUT(ERR_OWN, done);
	} else if (nfds == -1)
		ERROR_OUT(ERR_LIBC, done);

	if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL))
		ERROR_OUT(ERR_LIBC, done);
	if (!(fds[0].revents & event)) {
		assl_err_own("poll didn't return %s",
		    event == POLLIN ? "POLLIN" : "POLLOUT");
		ERROR_OUT(ERR_OWN, done);
	}

	rv = 1;
done:
	return (rv);
}

int
assl_negotiate_nonblock(struct assl_context *c)
{
	int			r, rv = 1;

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
			if (assl_poll(c, 10 * 1000, POLLIN) <= 0)
				ERROR_OUT(ERR_LIBC, done);
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
			ERROR_OUT(ERR_SSL, done);
		}
	}
done:
	return (rv);
}

int
assl_connect(struct assl_context *c, char *host, char *port, int flags)
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

	/* prepare ssl connection parameters */
	assl_setup_ssl(c);

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

		if (assl_negotiate_nonblock(c)) {
			assl_err_own("SSL/TLS connect failed");
			ERROR_OUT(ERR_OWN, done);
		}

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

	/* prepare ssl connection parameters */
	assl_setup_ssl(c);

	c->as_ssl = SSL_new(c->as_ctx);
	c->as_sbio = BIO_new_socket(c->as_sock, BIO_CLOSE);
	SSL_set_bio(c->as_ssl, c->as_sbio, c->as_sbio);

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
assl_serve(char *listen_ip, char *listen_port, int flags, void (*cb)(int))
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
		if (nfds == -1 && errno != EINTR)
			ERROR_OUT(ERR_LIBC, done);
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
	u_int8_t		*b;
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
			tot = -1;
			ERROR_OUT(ERR_LIBC, done);
			break;
		case SSL_ERROR_ZERO_RETURN:
			/* connection hung up on the other side */
			tot = -1;
			assl_err_own("connection closed by peer");
			ERROR_OUT(ERR_OWN, done);
			break;
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
