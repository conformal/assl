int assl_set_nonblock(int fd);
void assl_fatalx(char *errstr);

/* error handling */
#define ASSL_NO_FANCY_ERRORS

#ifndef ASSL_NO_FANCY_ERRORS
#define ERROR_OUT(e, g) do { goto g; } while (0)
#define assl_err_stack_unwind() do { } while (0)
#define assl_err_own(s, ...) do { } while (0)

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
extern char			assl_last_error[1024];
extern struct assl_error_stack	aes;

/* set to indicate this is a child process */
extern pid_t			assl_child;
extern int		assl_ignore_self_signed_cert;
extern int		assl_ignore_expired_cert;
extern void		*assl_mem_ca;
extern off_t		assl_mem_ca_len;
extern void		*assl_mem_cert;
extern off_t		assl_mem_cert_len;
extern void		*assl_mem_key;
extern off_t		assl_mem_key_len;
char * assl_geterror(int et);
void assl_push_error(const char *file, const char *func, int line, int et);
void assl_err_stack_unwind(void);
void assl_err_own(char *s, ...);
#endif
