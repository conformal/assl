#ifndef ASSL_SSL_PRIVSEP_H
int			ssl_ctx_load_verify_memory(SSL_CTX *, char *, off_t);
int			ssl_ctx_use_certificate_chain(SSL_CTX *, char *, off_t);
int			ssl_ctx_use_private_key(SSL_CTX *, char *, off_t);
#endif /* ASSL_SSL_PRIVSEP_H */
