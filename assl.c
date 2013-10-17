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

#include <stdlib.h>
#include <err.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>

#include <sys/stat.h>

#include <netdb.h>

#include <openssl/engine.h>

#include "assl.h"
#include "ssl_privsep.h"

#ifdef BUILDSTR
static const char *vertag = ASSL_VERSION " " BUILDSTR;
#else
static const char *vertag = ASSL_VERSION;
#endif

/* borrowed from openssl the tool */
static unsigned char	assl_dh512_p[] = {
	0xDA, 0x58, 0x3C, 0x16, 0xD9, 0x85, 0x22, 0x89, 0xD0, 0xE4, 0xAF, 0x75,
	0x6F, 0x4C, 0xCA, 0x92, 0xDD, 0x4B, 0xE5, 0x33, 0xB8, 0x04, 0xFB, 0x0F,
	0xED, 0x94, 0xEF, 0x9C, 0x8A, 0x44, 0x03, 0xED, 0x57, 0x46, 0x50, 0xD3,
	0x69, 0x99, 0xDB, 0x29, 0xD7, 0x76, 0x27, 0x6B, 0xA2, 0xD3, 0xD4, 0x12,
	0xE2, 0x18, 0xF4, 0xDD, 0x1E, 0x08, 0x4C, 0xF6, 0xD8, 0x00, 0x3E, 0x7C,
	0x47, 0x74, 0xE8, 0x33,
};
static unsigned char	assl_dh512_g[] = {
	0x02,
};

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

/* set to stop assl_serve */
volatile sig_atomic_t	assl_stop_serving;

/* set to indicate this is a child process */
pid_t			assl_child;

static int		assl_init;
static int		assl_ctx_idx;

const char *
assl_verstring(void)
{
	return vertag;
}

void
assl_version(int *major, int *minor, int *patch)
{
	*major = ASSL_VERSION_MAJOR;
	*minor = ASSL_VERSION_MINOR;
	*patch = ASSL_VERSION_PATCH;
}

static void	(*assl_log_fn)(int severity, const char *message) = NULL;

void
assl_set_log_callback(void (*cb)(int, const char *))
{
	assl_log_fn = cb;
}

/* error handling */
#ifdef ASSL_NO_FANCY_ERRORS
__dead void
assl_fatalx(const char *s, ...)
{
	char			errmsg[1024];
	va_list			ap;

	va_start(ap, s);
	vsnprintf(errmsg, sizeof(errmsg), s, ap);
	va_end(ap);
	strlcat(errmsg, "\n", sizeof(errmsg));

	if (assl_log_fn) {
		(*assl_log_fn)(ASSL_LOG_WARN, errmsg);
	} else {
		fprintf(stderr, "%s", errmsg);
	}

	exit(1);
}

void
assl_warnx(const char *s, ...)
{
	char			errmsg[1024];
	va_list			ap;

	va_start(ap, s);
	snprintf(errmsg, sizeof(errmsg), s, ap);
	va_end(ap);

	if (assl_log_fn) {
		(*assl_log_fn)(ASSL_LOG_ERR, errmsg);
	} else {
		fprintf(stderr, "%s\n", errmsg);
	}
}
#else
SLIST_HEAD(assl_error_stack, assl_error);

/* XXX NOT concurrency safe! */
char			assl_last_error[1024];
struct assl_error_stack	aes = SLIST_HEAD_INITIALIZER(aes);

char *
assl_geterror(int et)
{
	char			*es;

	switch (et) {
	case ERR_LIBC:
		strlcpy(assl_last_error, strerror(errno), sizeof
		    assl_last_error);
		break;
	case ERR_SSL:
		es = (char *)ERR_lib_error_string(ERR_get_error());
		if (es)
			strlcpy(assl_last_error, es, sizeof assl_last_error);
		else
			strlcpy(assl_last_error, "unknown SSL error",
			    sizeof assl_last_error);
		break;
	case ERR_SOCKET:
		assl_get_socket_error(errno, assl_last_error,
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
		return;
	if ((ce->errstr = strdup(assl_geterror(et))) == NULL) {
		free(ce);
		return;
	}
	ce->file = file;
	ce->func = func;
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
assl_log(int severity, const char *s, va_list ap)
{
	struct assl_error	*ce;
	const char		*prefix;
	char			*output = NULL;
	size_t			 maxsz = 0, sz;
	va_list			 cap;

	/* We need to back this up since we process it twice */
	va_copy(cap, ap);
again:
	sz = 0;
	sz = vsnprintf(output,  (output ? (maxsz - sz) : 0), s, ap);
	sz += snprintf(output + sz,  (output ? (maxsz - sz) : 0), "\n\n");
	/* XXX only if going to stderr? */
	switch (severity) {
	case ASSL_LOG_MSG:
		prefix = "ASSL Info\n";
		break;
	case ASSL_LOG_WARN:
		prefix = "ASSL Warning\n";
		break;
	case ASSL_LOG_ERR:
		prefix = "ASSL Fatal Error\n";
		break;
	default:
		prefix = "ASSL Unknown Error\n";
	}
	sz += snprintf(output + sz, (output ? (maxsz - sz) : 0), "%s", prefix);

	SLIST_FOREACH(ce, &aes, link) {
		sz += snprintf(output + sz, (output ? (maxsz - sz) : 0),
		    "\tfile:\t%s\n"
		    "\tfunct:\t%s\n"
		    "\tline:\t%d\n"
		    "\terror:\t%s\n\n",
		    ce->file,
		    ce->func,
		    ce->line,
		    ce->errstr);
	}

	if (maxsz == 0) {
		sz++; /* for NUL */
		maxsz = sz;
		if ((output = calloc(maxsz, 1)) == NULL) {
			if (assl_log_fn) {
				(*assl_log_fn)(ASSL_LOG_WARN, "can't allocate "
				    "memory for warning buffer");
			} else {
				fprintf(stderr, "can't allocate memory for "
				    "warning buffer\n");
			}
			return;
		}
		va_copy(ap, cap);

		goto again;
	}

	if (assl_log_fn) {
		(*assl_log_fn)(severity, output);
	} else {
		fprintf(stderr, "%s", output);
	}
	free(output);
}

__dead void
assl_fatalx(const char *s, ...)
{
	va_list			ap;

	va_start(ap, s);
	assl_log(ASSL_LOG_ERR, s, ap);
	va_end(ap);

	if (assl_child)
		_exit(1);
	exit(1);
}

void
assl_warnx(const char *s, ...)
{
	va_list			ap;

	va_start(ap, s);
	assl_log(ASSL_LOG_WARN, s, ap);
	va_end(ap);
}
#endif /* ASSL_NO_FANCY_ERRORS */

void
assl_initialize(void)
{
	if (assl_init)
		return;
	assl_init = 1;

	if (assl_initialize_sockets())
		assl_fatalx("socket initialization failed");

	SSL_library_init();
	SSL_load_error_strings();

	/* Init hardware crypto engines. */
	ENGINE_load_builtin_engines();
	ENGINE_register_all_complete();

	OpenSSL_add_ssl_algorithms();

	assl_err_stack_unwind();
	assl_ctx_idx = SSL_get_ex_new_index(0, "assl context", NULL,
	    NULL, NULL);

}

void
assl_set_cert_flags(struct assl_context *c, int flags)
{
	if (flags & ASSL_GF_IGNORE_EXPIRED)
		c->as_ignore_expired_cert = 1;
	if (flags & ASSL_GF_IGNORE_SELF_SIGNED)
		c->as_ignore_self_signed_cert = 1;
}

int
assl_verify_callback(int rv, X509_STORE_CTX *ctx)
{
	struct assl_context	*c;
	SSL			*ssl;

	ssl = X509_STORE_CTX_get_ex_data(ctx,
	    SSL_get_ex_data_X509_STORE_CTX_idx());
	c = SSL_get_ex_data(ssl, assl_ctx_idx);
	/*
	fprintf(stderr, "assl_verify_callback: ctx->error %d\n", ctx->error);
	*/
	rv = 0; /* fail */

	/* override expired and self signed certs */
	switch (ctx->error) {
	case X509_V_OK:
		rv = 1;
		break;
	case X509_V_ERR_CERT_HAS_EXPIRED:
		if (c->as_ignore_expired_cert) {
			rv = 1;
			ctx->error = X509_V_OK;
			/*
			fprintf(stderr, "ignoring expired\n");
			 */
		}
		break;
	case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
	case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
		if (c->as_ignore_self_signed_cert) {
			rv = 1;
			ctx->error = X509_V_OK;
			/*
			fprintf(stderr, "ignoring self signed\n");
			 */
		}
		break;
	}

	/*
	fprintf(stderr, "assl_verify_callback: %s  rv %d error %d\n",
	   rv == 0 ? "failed" : "success", rv, ctx->error);
	*/

	return (rv);
}

void
assl_setup_verify(struct assl_context *c)
{
	/* use callback to ignore some errors such as expired cert */
	SSL_CTX_set_verify(c->as_ctx, c->as_verify_mode, assl_verify_callback);
	SSL_CTX_set_mode(c->as_ctx, SSL_MODE_AUTO_RETRY);
	SSL_CTX_set_verify_depth(c->as_ctx, c->as_verify_depth);
}

DH *
assl_load_dh_params(const char *cert)
{
	BIO		*bio;
	DH		*dh = NULL;

	if ((bio = BIO_new_file(cert,"r")) == NULL)
		ERROR_OUT(ERR_SSL, done);

	dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
	if (dh == NULL) {
		/* try defaults */
		if ((dh = DH_new()) == NULL)
			ERROR_OUT(ERR_SSL, done);

		dh->p = BN_bin2bn(assl_dh512_p, sizeof(assl_dh512_p), NULL);
		dh->g = BN_bin2bn(assl_dh512_g, sizeof(assl_dh512_g), NULL);
		if ((dh->p == NULL) || (dh->g == NULL)) {
			assl_err_own("BN_bin2bn failed in assl_load_dh_params");
			ERROR_OUT(ERR_OWN, done);
		}
	}

done:
	if (bio != NULL)
		BIO_free(bio);

	return (dh);
}

void
assl_free_mem_cert(struct assl_mem_cert* mc)
{
	if (mc->assl_mem_ca) {
		bzero(mc->assl_mem_ca, mc->assl_mem_ca_len);
		free(mc->assl_mem_ca);
		mc->assl_mem_ca = NULL;
		mc->assl_mem_ca_len = 0;
	}
	if (mc->assl_mem_cert) {
		bzero(mc->assl_mem_cert, mc->assl_mem_cert_len);
		free(mc->assl_mem_cert);
		mc->assl_mem_cert = NULL;
		mc->assl_mem_cert_len = 0;
	}
	if (mc->assl_mem_key) {
		bzero(mc->assl_mem_key, mc->assl_mem_key_len);
		free(mc->assl_mem_key);
		mc->assl_mem_key = NULL;
		mc->assl_mem_key_len = 0;
	}

	/* DH params */
	if (mc->assl_mem_dh) {
		DH_free(mc->assl_mem_dh);
		mc->assl_mem_dh = NULL;
	}

	bzero(mc, sizeof *mc);
	free(mc);
}

int
assl_destroy_mem_certs(void *token)
{
	struct assl_mem_cert	*mc = token;

	if (mc == NULL)
		return (1);

	assl_free_mem_cert(mc);

	return (0);
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

void *
assl_load_file_certs_to_mem(const char *ca, const char *cert, const char *key)
{
	struct assl_mem_cert	*mc = NULL;

	assl_err_stack_unwind();

	mc = calloc(1, sizeof *mc);
	if (mc == NULL)
		ERROR_OUT(ERR_LIBC, done);

	if (ca && assl_load(ca, &mc->assl_mem_ca, &mc->assl_mem_ca_len)) {
		assl_err_own("assl_load ca failed");
		ERROR_OUT(ERR_OWN, done);
	}
	if (cert && assl_load(cert, &mc->assl_mem_cert, &mc->assl_mem_cert_len)) {
		assl_err_own("assl_load cert failed");
		ERROR_OUT(ERR_OWN, done);
	}
	if (key && assl_load(key, &mc->assl_mem_key, &mc->assl_mem_key_len)) {
		assl_err_own("assl_load key failed");
		ERROR_OUT(ERR_OWN, done);
	}

	/* DH params */
	if (cert) {
		mc->assl_mem_dh = assl_load_dh_params(cert);
		if (mc->assl_mem_dh == NULL)
			goto done;
	}

	return (mc);
done:
	if (mc)
		assl_free_mem_cert(mc);
	return (NULL);
}

int
assl_use_mem_certs(struct assl_context *c, void *token)
{
	int			rv = 1;
	struct assl_mem_cert	*mc = token;

	assl_err_stack_unwind();

	if (c == NULL) {
		assl_err_own("no context");
		ERROR_OUT(ERR_OWN, done);
	}
	if (mc == NULL) {
		assl_err_own("no token");
		ERROR_OUT(ERR_OWN, done);
	}

	if (c->as_server) {
		/* server requires all the goodies */
		if (mc->assl_mem_ca == NULL || mc->assl_mem_cert == NULL ||
		    mc->assl_mem_key == NULL) {
			if (mc->assl_mem_ca == NULL)
				assl_err_own("no ca");
			else if (mc->assl_mem_cert == NULL)
				assl_err_own("no cert");
			else if (mc->assl_mem_key == NULL)
				assl_err_own("no key");
			ERROR_OUT(ERR_OWN, done);
		}
	}

	c->as_token = token;

	/* use certs */
	if (!ssl_ctx_load_verify_memory(c->as_ctx, mc->assl_mem_ca,
	    mc->assl_mem_ca_len))
		ERROR_OUT(ERR_SSL, done);
	if (!ssl_ctx_use_certificate_chain(c->as_ctx, mc->assl_mem_cert,
	   mc->assl_mem_cert_len))
		ERROR_OUT(ERR_SSL, done);
	if (!ssl_ctx_use_private_key(c->as_ctx, mc->assl_mem_key,
	    mc->assl_mem_key_len))
		ERROR_OUT(ERR_SSL, done);
	if (!SSL_CTX_check_private_key(c->as_ctx))
		ERROR_OUT(ERR_SSL, done);

	assl_setup_verify(c);

	/* DH params */
	if (mc->assl_mem_dh)
		c->as_dh = DHparams_dup(mc->assl_mem_dh);

	rv = 0;
done:
	return (rv);
}

int
assl_load_file_certs(struct assl_context *c, const char *ca, const char *cert,
		const char *key)
{
	int			rv = 1;
	struct stat		sb;
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

	if (ca && lstat(ca, &sb) != 0) {
		assl_err_own("unable to load ca \"%s\": %s", ca,
		    strerror(errno));
		ERROR_OUT(ERR_OWN, done);
	}
	if (cert && lstat(cert, &sb) != 0) {
		assl_err_own("unable to load cert \"%s\": %s", cert,
		    strerror(errno));
		ERROR_OUT(ERR_OWN, done);
	}
	if (key && lstat(key, &sb) != 0) {
		assl_err_own("unable to load key \"%s\": %s", key,
		    strerror(errno));
		ERROR_OUT(ERR_OWN, done);
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

	assl_setup_verify(c);

	if (cert) {
		c->as_dh = assl_load_dh_params(cert);
		if (c->as_dh == NULL)
			goto done;
	}

	rv = 0;
done:
	return (rv);
}

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#define SSL_METHOD_CONST const
#else
#define SSL_METHOD_CONST
#endif

/* older openssl does not support TLS > 1.0 */
#if OPENSSL_VERSION_NUMBER < 0x10001000L
#define TLSv1_1_method          TLSv1_method
#define TLSv1_1_client_method   TLSv1_client_method
#define TLSv1_1_server_method   TLSv1_server_method
#define TLSv1_2_method          TLSv1_method
#define TLSv1_2_client_method   TLSv1_client_method
#define TLSv1_2_server_method   TLSv1_server_method
#define SSL_OP_NO_TLSv1_1       SSL_OP_NO_TLSv1
#define SSL_OP_NO_TLSv1_2       SSL_OP_NO_TLSv1
/* #warning "Installed OpenSSL version does not support TLS > 1.0, falling back to 1.0" */
#endif

struct assl_context *
assl_internal_alloc_context(SSL_METHOD_CONST SSL_METHOD *meth, int flags, int server)
{
	struct assl_context	*c = NULL;

	c = calloc(1, sizeof *c);
	if (c == NULL)
		ERROR_OUT(ERR_LIBC, unwind);

	/* set some sane values */
	c->as_sock = -1;
	c->as_method = meth;
	c->as_server = server;
	c->as_ctx = SSL_CTX_new(meth);
	if (c->as_ctx == NULL)
		ERROR_OUT(ERR_SSL, unwind);

	/* allow all buggy implementations to play */
	SSL_CTX_set_options(c->as_ctx, SSL_OP_ALL);

	if (c->as_server)
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
		if (!SSL_CTX_set_cipher_list(c->as_ctx, "eNULL"))
			ERROR_OUT(ERR_SSL, unwind);

	c->as_verify_depth = ASSL_VERIFY_DEPTH;

	/* set defaults */
	c->as_curve = NID_secp521r1;

	return (c);
unwind:
	if (c)
		free(c);

	return (NULL);
}

struct assl_context *
assl_alloc_context(enum assl_method m, int flags)
{
	int				server = 0;
	SSL_METHOD_CONST SSL_METHOD	*meth;

	assl_err_stack_unwind();

	assl_initialize_sockets();

	if (flags & ASSL_F_CHILD)
		assl_child = getpid();

	switch (m) {
	/* ALL versions */
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
	/* SSL v3 */
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
	/* TLS 1.0 */
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
	/* TLS 1.1 */
	case ASSL_M_TLSV1_1:
		meth = TLSv1_1_method();
		server = 1;
		break;
	case ASSL_M_TLSV1_1_CLIENT:
		meth = TLSv1_1_client_method();
		break;
	case ASSL_M_TLSV1_1_SERVER:
		meth = TLSv1_1_server_method();
		server = 1;
		break;
	/* TLS 1.2 */
	case ASSL_M_TLSV1_2:
		meth = TLSv1_2_method();
		server = 1;
		break;
	case ASSL_M_TLSV1_2_CLIENT:
		meth = TLSv1_2_client_method();
		break;
	case ASSL_M_TLSV1_2_SERVER:
		meth = TLSv1_2_server_method();
		server = 1;
		break;
	default:
		assl_err_own("invalid method %d", m);
		ERROR_OUT(ERR_OWN, unwind);
	}

	return (assl_internal_alloc_context(meth, flags, server));
unwind:
	return (NULL);
}

struct assl_context *
assl_alloc_context_v2(int flags, char *argv[])
{
	struct assl_context		*c = NULL;
	SSL_METHOD_CONST SSL_METHOD	*meth;
	char				*named_curve = NULL;
	int				i;

	meth = SSLv23_method();
	if ((c = assl_internal_alloc_context(meth, flags, 1)) == NULL)
		goto unwind;

	SSL_CTX_set_options(c->as_ctx, SSL_OP_NO_SSLv2); /* disallow SSL v2 */

	if (!(flags & ASSL_F_SSLV3))
		SSL_CTX_set_options(c->as_ctx, SSL_OP_NO_SSLv3);
	if (!(flags & ASSL_F_TLS1))
		SSL_CTX_set_options(c->as_ctx, SSL_OP_NO_TLSv1);
	if (!(flags & ASSL_F_TLS1_1))
		SSL_CTX_set_options(c->as_ctx, SSL_OP_NO_TLSv1_1);
	if (!(flags & ASSL_F_TLS1_2))
		SSL_CTX_set_options(c->as_ctx, SSL_OP_NO_TLSv1_2);

	if (argv == NULL)
		goto done;

	for (i = 0; argv[i] != NULL; i++) {
		if (!strncmp(argv[i], ASSL_ARG_NAMEDCURVE,
		    strlen(ASSL_ARG_NAMEDCURVE))) {
			named_curve = argv[i] + strlen(ASSL_ARG_NAMEDCURVE);
			c->as_curve = OBJ_sn2nid(named_curve);
			if (c->as_curve == 0) {
				assl_err_own("invalid curve %s", named_curve);
				ERROR_OUT(ERR_OWN, unwind);
			}
		} else {
			assl_err_own("invalid argument %s", argv[i]);
			ERROR_OUT(ERR_OWN, unwind);
		}
	}
done:
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
	int			r, rv = 1, p, timo;
	struct timeval		tval, told;
	struct timeval		now, end, trem;
	struct sockaddr_storage	ss;
	socklen_t		len;
	char			peer[NI_MAXHOST];

	assl_err_stack_unwind();

	if (c == NULL) {
		assl_err_own("no context");
		ERROR_OUT(ERR_OWN, bad);
	}

	len = sizeof(ss);
	if (getpeername(c->as_sock, (struct sockaddr *)&ss, &len) != -1 &&
		getnameinfo((struct sockaddr *)&ss, len,
			peer, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == 0)
		c->as_peername = strdup(peer);

	if (assl_get_recvtimeo(c->as_sock, &told))
		ERROR_OUT(ERR_SOCKET, bad);

	tval.tv_sec = 1;
	tval.tv_usec = 0;
	if (assl_set_recvtimeo(c->as_sock, &tval))
		ERROR_OUT(ERR_SOCKET, done);

	if (gettimeofday(&now, NULL) == -1) {
		assl_err_own("can't obtain time");
		ERROR_OUT(ERR_OWN, done);
	}
	trem.tv_sec = 10;
	trem.tv_usec = 0;
	timeradd(&now, &trem, &end);

	for (;;) {
		if (c->as_server)
			r = SSL_accept(c->as_ssl);
		else
			r = SSL_connect(c->as_ssl);

		if (gettimeofday(&now, NULL) == -1) {
			assl_err_own("can't obtain time");
			ERROR_OUT(ERR_OWN, done);
		}
		if (timercmp(&now, &end, >=)) {
			assl_err_own("SSL negotiation timeout");
			ERROR_OUT(ERR_OWN, done);
		}

		switch (assl_get_ssl_error(c->as_ssl, r)) {
		case SSL_ERROR_NONE:
			rv = 0;
			goto done;
		case SSL_ERROR_WANT_READ:
			timersub(&end, &now, &trem);
			timo = (trem.tv_sec * 1000) + (trem.tv_usec / 1000);
			p = assl_poll(c, timo, POLLIN, NULL);
			if (p == -1) {
				if (errno == EINTR)
					continue;
				ERROR_OUT(ERR_SOCKET, done);
			}
			break;
		case SSL_ERROR_SYSCALL:
			rv = -1;
			ERROR_OUT(ERR_SOCKET, done);
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
	assl_set_recvtimeo(c->as_sock, &told);
bad:
	return (rv);
}

void
assl_get_parameters(struct assl_context *c)
{
	const SSL_CIPHER	*ci;
	EVP_PKEY		*pktmp;
	char			*s;

	c->as_bits = -1;

	c->as_peer = SSL_get_peer_certificate(c->as_ssl);
	if (c->as_peer) {
		pktmp = X509_get_pubkey(c->as_peer);
		if (pktmp) {
			c->as_bits = EVP_PKEY_bits(pktmp);
			EVP_PKEY_free(pktmp);
		}
	}

	ci = SSL_get_current_cipher(c->as_ssl);
	if (ci) {
		SSL_CIPHER_description(ci, c->as_protocol,
		    sizeof c->as_protocol);
		s = c->as_protocol;
		strsep(&s, "\n");
	}
}

int
assl_connect(struct assl_context *c, const char *host, const char *port,
    int flags)
{
	struct assl_connect_opts aco = {
		.aco_flags = flags,
	};

	return (assl_connect_opts(c, host, port, &aco));
}

int
assl_connect_opts(struct assl_context *c, const char *host, const char *port,
    struct assl_connect_opts *aco)
{
	struct addrinfo		hints, *res = NULL, *ai;
	int			p, s = -1, on = 1, rv = 1, retries;
	int			gairv;

	assl_err_stack_unwind();

	if (c == NULL || host == NULL || port == NULL || aco == NULL) {
		if (c == NULL)
			assl_err_own("no context");
		else if (host == NULL)
			assl_err_own("no host");
		else if (port == NULL)
			assl_err_own("no port");
		else if (aco == NULL)
			assl_err_own("no aco");
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

	if ((gairv = getaddrinfo(host, port, &hints, &res))) {
		assl_err_own("%s", gai_strerror(gairv));
		ERROR_OUT(ERR_OWN, done);
	}

	for (ai = res; ai; ai = ai->ai_next) {
		if (s != -1) {
			close(s);
			s = -1;
		}

		retries = 0;
		if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
		    continue;
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (s == -1)
			continue;
		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on,
		    sizeof(on)) == -1)
			continue;
		if (aco->aco_flags & ASSL_F_LOWDELAY ||
		    aco->aco_flags & ASSL_F_THROUGHPUT)
			assl_set_tos(s, ai->ai_family, aco->aco_flags);
		if (aco->aco_flags & ASSL_F_KEEPALIVE) {
			if (assl_set_keepalive(s))
				c->as_keepalive = 0;
			else
				c->as_keepalive = 1;
		}
		if (connect(s, ai->ai_addr, ai->ai_addrlen) == 0)
			break;

		/*
		 * required for unit test
		 * without this quick connections will eventually
		 * fail with a "Address already in use" error
		 */
		if (errno == EADDRINUSE) {
			if (retries > 5)
				ERROR_OUT(ERR_SOCKET, done);
			retries++;
			usleep(500000);
		}
	}
	if (s == -1)
		ERROR_OUT(ERR_SOCKET, done);

	if (aco->aco_flags & ASSL_F_NONBLOCK) {
		if (assl_set_nonblock(s)) {
			close(s);
			s = -1;
			ERROR_OUT(ERR_SOCKET, done);
		}
		c->as_nonblock = 1;
	}

	if (aco->aco_rcvbuf != 0) {
		assl_set_recvbuf(s, aco->aco_rcvbuf);
	}

	if (aco->aco_sndbuf != 0) {
		assl_set_sendbuf(s, aco->aco_sndbuf);
	}

	c->as_sock = s;

	rv = -1; /* negative for ssl errors */

	/* go do ssl magic */
	c->as_ssl = SSL_new(c->as_ctx);
	SSL_set_ex_data(c->as_ssl, assl_ctx_idx, c);
	c->as_sbio = assl_bio_new_socket(c->as_sock, BIO_CLOSE);


	SSL_set_bio(c->as_ssl, c->as_sbio, c->as_sbio);
	SSL_set_connect_state(c->as_ssl);

	if (assl_negotiate_nonblock(c)) {
		assl_err_own("SSL/TLS connect failed");
		ERROR_OUT(ERR_OWN, done);
	}

	c->as_ssl_session = SSL_get_session(c->as_ssl);
	assl_get_parameters(c);

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
	EC_KEY			*ecdh = NULL;

	assl_err_stack_unwind();

	if (c == NULL) {
		assl_err_own("no context");
		ERROR_OUT(ERR_OWN, done);
	}
	c->as_sock = s;

	/* figure out if socket is non-blocking */
	r = assl_is_nonblock(s);
	if (r < 0)
		ERROR_OUT(ERR_SOCKET, done);
	c->as_nonblock = r;

	/* set up DH */
	if (c->as_dh)
		SSL_CTX_set_tmp_dh(c->as_ctx, c->as_dh);

	/* set up ECDHE */
	ecdh = EC_KEY_new_by_curve_name(c->as_curve);
	if (ecdh == NULL)
		ERROR_OUT(ERR_SSL, done);
	SSL_CTX_set_tmp_ecdh(c->as_ctx, ecdh);
	EC_KEY_free(ecdh);

	/* now that all the poopage has been setup get SSL going */
	c->as_ssl = SSL_new(c->as_ctx);
	SSL_set_ex_data(c->as_ssl, assl_ctx_idx, c);
	c->as_sbio = assl_bio_new_socket(c->as_sock, BIO_CLOSE);
	SSL_set_bio(c->as_ssl, c->as_sbio, c->as_sbio);
	SSL_set_accept_state(c->as_ssl);

	if (assl_negotiate_nonblock(c)) {
		assl_err_own("SSL/TLS accept failed");
		ERROR_OUT(ERR_OWN, done);
	}

	c->as_ssl_session = SSL_get_session(c->as_ssl);
	assl_get_parameters(c);

	rv = 0;
done:
	return (rv);
}

int
assl_serve(const char *listen_ip, const char *listen_port, int flags,
		void (*cb)(int), void (*intr_cb)(void))
{
	struct assl_connect_opts aco = {
		.aco_flags = flags,
	};

	return (assl_serve_opts(listen_ip, listen_port, &aco, cb, intr_cb));
}

int
assl_serve_opts(const char *listen_ip, const char *listen_port,
    struct assl_connect_opts *aco, void (*cb)(int), void (*intr_cb)(void))
{
	struct addrinfo		hints, *res, *ai;
	int			s = -1, on = 1, i, nfds, x, c;
	struct pollfd		fds[2];

	assl_err_stack_unwind();

	if (cb == NULL) {
		assl_err_own("no callback");
		ERROR_OUT(ERR_OWN, done);
	}
	if (aco == NULL) {
		assl_err_own("no aco");
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

		if (aco->aco_flags & ASSL_F_NONBLOCK)
			if (assl_set_nonblock(s)) {
				assl_close_socket(s);
				ERROR_OUT(ERR_SOCKET, done);
			}

		if (aco->aco_flags & ASSL_F_KEEPALIVE)
			if (assl_set_keepalive(s)) {
				assl_close_socket(s);
				ERROR_OUT(ERR_SOCKET, done);
			}

		if (aco->aco_flags & ASSL_F_LOWDELAY ||
		    aco->aco_flags & ASSL_F_THROUGHPUT)
			assl_set_tos(s, ai->ai_family, aco->aco_flags);

		if (aco->aco_rcvbuf != 0) {
			assl_set_recvbuf(s, aco->aco_rcvbuf);
		}

		if (aco->aco_sndbuf != 0) {
			assl_set_sendbuf(s, aco->aco_rcvbuf);
		}

		setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

		if (bind(s, ai->ai_addr, ai->ai_addrlen) < 0) {
			assl_close_socket(s);
			continue;
		}

		if (listen(s, /* XXX */ 10) < 0) {
			assl_close_socket(s);
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
			if (aco->aco_flags & ASSL_F_CLOSE_SOCKET)
				assl_close_socket(s);
		}
	}
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

		switch (assl_get_ssl_error(c->as_ssl, r)) {
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
			ERROR_OUT(ERR_SOCKET, done);
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
	if (c->as_peer)
		X509_free(c->as_peer);
	if (c->as_ssl) {
		SSL_shutdown(c->as_ssl);
		SSL_free(c->as_ssl);
		c->as_ssl = NULL;
	}
	if (c->as_sock != -1) {
		assl_close_socket(c->as_sock);
		c->as_sock = -1;
	}
	if (c->as_ctx) {
		SSL_CTX_free(c->as_ctx);
		c->as_ctx = NULL;
	}
	if (c->as_peername) {
		free(c->as_peername);
		c->as_peername = NULL;
	}
	if (c->as_dh) {
		DH_free(c->as_dh);
		c->as_dh = NULL;
	}

	free(c);
	if (assl_shutdown_sockets())
		return (1);

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
			ERROR_OUT(ERR_SOCKET, bad); /* XXX probably socket */
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
		ERROR_OUT(ERR_SOCKET, bad); /* XXX probably socket */
	}

	return (tot);
bad:
	return (-1);
}
