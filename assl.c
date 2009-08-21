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

/* XXX todo:
 * read/write blocking
 * read/write non-blocking
 * session teardown
 * LDAP integration for certs
 * create CA certificate
 * create machine cerrtificates
 * sign machine certificates
 * sane error logging
 *
 * man page:
 * add all connection methods to the man page
 */

/* utility functions */
int
assl_set_nonblock(int fd)
{
	int			val;

	val = fcntl(fd, F_GETFL, 0);
	if (val < 0)
		return (1);

	if (val & O_NONBLOCK)
		return (0);

	val |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, val) == -1)
		return (1);

	return (0);
}

/* tiny ssl functions */
void
assl_initialize(void)
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

int
assl_load_file_certs(struct assl_context *c, char *ca, char *cert, char *key)
{
	int			rv = 1;
	SSL_CTX			*ctx;

	if (c == NULL)
		goto done;
	ctx = c->as_ctx;

	if (ca == NULL || cert == NULL || key == NULL)
		goto done;

	if (!SSL_CTX_load_verify_locations(ctx, ca, NULL))
		goto done;
	if (!SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM))
		goto done;
	if (!SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM))
		goto done;
	if (!SSL_CTX_check_private_key(ctx))
		goto done;
	if (c->as_server)
		SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(ca));

	rv = 0;
done:
	return (rv);
}

void
assl_setup_ssl(struct assl_context *c)
{
	if (c == NULL)
		return;

	SSL_CTX_set_mode(c->as_ctx, SSL_MODE_AUTO_RETRY);
	SSL_CTX_set_verify(c->as_ctx, c->as_verify_mode, NULL);
	SSL_CTX_set_verify_depth(c->as_ctx, c->as_verify_depth);
}

struct assl_context *
assl_alloc_context(enum assl_method m)
{
	struct assl_context	*c = NULL;
	SSL_METHOD		*meth;
	int			server = 0;

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
		return (NULL);
	}

	c = calloc(1, sizeof *c);
	if (c == NULL)
		return (NULL);

	/* set some sane values */
	c->as_server = server;
	c->as_method = meth;
	c->as_ctx = SSL_CTX_new(meth);
	if (c->as_ctx == NULL)
		goto unwind;

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
assl_connect(struct assl_context *c, char *host, char *port)
{
	int			p, rv = -1;

	if (c == NULL || host == NULL)
		goto done;

	p = atoi(port);
	if (p <= 0 || p > 65535)
		goto done;

	/* prepare ssl connection parameters */
	assl_setup_ssl(c);

	/* setup socket */
	if ((c->as_raddr = gethostbyname(host)) == NULL)
		goto done;

	bzero(&c->as_addr, sizeof c->as_addr);
	c->as_addr.sin_addr = *(struct in_addr *)c->as_raddr->h_addr_list[0];
	c->as_addr.sin_family = AF_INET;
	c->as_addr.sin_port = htons(p);

	if ((c->as_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		goto done;
	if (connect(c->as_sock, (struct sockaddr *)&c->as_addr,
	    sizeof c->as_addr) == -1)
		goto done;

	rv = 1; /* positive for ssl errors */

	/* go do ssl magic */
	c->as_ssl = SSL_new(c->as_ctx);
	c->as_sbio = BIO_new_socket(c->as_sock, BIO_NOCLOSE);
	SSL_set_bio(c->as_ssl, c->as_sbio, c->as_sbio);

	if (SSL_connect(c->as_ssl) <= 0)
		goto done;

	if (SSL_get_verify_result(c->as_ssl) != X509_V_OK)
		goto done;

	rv = 0;
done:
	return(rv);
}

int
assl_accept(struct assl_context *c, int s)
{
	int			r, serr;

	if (c == NULL)
		return (1);

	c->as_sock = s;

	/* seup ssl connection */
	assl_setup_ssl(c);

	c->as_ssl = SSL_new(c->as_ctx);
	c->as_sbio = BIO_new_socket(c->as_sock, BIO_NOCLOSE);
	SSL_set_bio(c->as_ssl, c->as_sbio, c->as_sbio);
	for (;;) {
		r = SSL_accept(c->as_ssl);
		if (r == 1)
			break;
		else if (r == 2) {
			/* XXX close ssl */
			close(c->as_sock);
			return (1);
		}
		/* deal with connetcions that were opened but send no data */
		/* poll for an x amount of time */
		serr = SSL_get_error(c->as_ssl, r);
		if (serr == SSL_ERROR_WANT_READ || serr == SSL_ERROR_WANT_WRITE) {
			errx(1, "fix assl_accept");
			continue;
		}

		return (1);
	}

	return (0);
}

int
assl_serve(char *listen_ip, char *listen_port, void (*cb)(int))
{
	struct addrinfo		hints, *res, *ai;
	int			s = -1, on = 1, i, nfds, x, c;
	struct pollfd		fds[2];

	if (cb == NULL)
		return (1);

	if (listen_port == NULL)
		listen_port = ASSL_DEFAULT_PORT;

	bzero(&hints, sizeof hints);
	hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if ((i = getaddrinfo(listen_ip, listen_port, &hints, &res)))
		errx(1, "%d %s", i, gai_strerror(i));

	bzero(fds, sizeof fds);
	for (ai = res, i = 0; ai && i < 2; ai = ai->ai_next, i++) {
		if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
		    continue;
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (s < 0)
			continue;
		if (assl_set_nonblock(s) == -1) {
			close(s);
			continue;
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

	for (;;) {
		nfds = poll(fds, i, INFTIM);
		if (nfds == -1)
			return (1);
		for (x = 0, c = 0; x < i && c < nfds; x++) {
			if (fds[x].revents & (POLLERR | POLLHUP | POLLNVAL))
			 	return (1);
			if (!(fds[x].revents & POLLIN))
				continue;

			c++;
			if ((s = accept(fds[x].fd, 0, 0)) == -1)
				return (1);

			/* hand off to caller */
			cb(s);
		}
	}

	/* NOTREACHED */

	return (1);
}
