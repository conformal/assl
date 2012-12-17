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
#include <err.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/wait.h>

#include "assl.h"

void			serve_callback(int);

void				*token;
pid_t				child;
extern volatile sig_atomic_t	assl_stop_serving;

#define USE_MEM_CERTS

void
sighdlr(int sig)
{
	int			saved_errno, status;
	pid_t			pid;

	saved_errno = errno;

	switch (sig) {
	case SIGINT:
	case SIGTERM:
	case SIGHUP:
		assl_stop_serving = 1;
		/*
		fprintf(stderr, "stoppping in %d child %d\n", getpid(), child);
		*/
		if (child)
			_exit(0);
		else
			exit(0);
		break;
	case SIGCHLD:
		while ((pid = waitpid(WAIT_ANY, &status, WNOHANG)) != 0) {
			if (pid == -1) {
				if (errno == EINTR)
					continue;
				if (errno != ECHILD) {
					/*
					fprintf(stderrr, "sigchild: waitpid:");
					*/
				}
				break;
			}

			if (WIFEXITED(status)) {
				if (WEXITSTATUS(status) != 0) {
					/*
					fprintf(stderr, "sigchild: child exit "
					    "status: %d", WEXITSTATUS(status));
					*/
				}
			} else {
				/*
				fprintf(stderr, "sigchild: child is terminated abnormally");
				*/
			}
		}
		break;
	}

	errno = saved_errno;
}

void
serve_callback(int s)
{
	struct assl_context	*c;
	char			buf[65536 * 10], *b;
	ssize_t			rd, tot;

	switch (fork()) {
	case 0:
		signal(SIGCHLD, SIG_DFL);
		child = getpid();
		fprintf(stderr, "child: %d parent: %d\n", getpid(), getppid());
		break;
	case -1:
		err(1, "fork");
		/* NOTREACHED */
	default:
		fprintf(stderr, "parent: %d parent's parent: %d\n",
		    getpid(), getppid());
		return;
	}

	c = assl_alloc_context(ASSL_M_TLSV1_2, ASSL_F_CHILD);
	if (c == NULL)
		assl_fatalx("assl_alloc_context");

#ifdef USE_MEM_CERTS
	if (assl_use_mem_certs(c, token))
		assl_fatalx("assl_use_mem_certs");
#else
	if (assl_load_file_certs(c, "../ca/ca.crt", "server/server.crt",
	    "server/private/server.key"))
		assl_fatalx("assl_load_file_certs");
#endif
	if (assl_accept(c, s))
		assl_fatalx("assl_accept");
	printf("CIPHER: %s\n", c->as_protocol);
	for (tot = sizeof buf, b = buf; tot > 0; ) {
		rd = assl_read(c, b, tot);
		if (rd == -1) {
			if (errno == EAGAIN) {
				if (assl_poll(c, 10 * 1000, POLLIN, NULL) <= 0)
					assl_fatalx("assl_poll");
				continue;
			}
			goto done;
		}
		tot -= rd;
		b += rd;
	}
done:
	if (assl_close(c)) {
		c = NULL;
		assl_fatalx("assl_disconnect");
	}

	_exit(0);
}

int
main(int argc, char *argv[])
{
	struct sigaction	sact;

	assl_initialize();

	/* signaling */
        bzero(&sact, sizeof(sact));
	sigemptyset(&sact.sa_mask);
	sact.sa_flags = 0;
	sact.sa_handler = sighdlr;
	sigaction(SIGINT, &sact, NULL);
	sigaction(SIGQUIT, &sact, NULL);
	sigaction(SIGTERM, &sact, NULL);
	sigaction(SIGHUP, &sact, NULL);

	sact.sa_handler = sighdlr;
	sact.sa_flags = SA_NOCLDSTOP;
	sigaction(SIGCHLD, &sact, NULL);

#ifdef USE_MEM_CERTS
	if ((token = assl_load_file_certs_to_mem("../ca/ca.crt",
	    "server/server.crt", "server/private/server.key")) == NULL)
		assl_fatalx("assl_load_file_certs");
#endif
	assl_serve(NULL, ASSL_DEFAULT_PORT,
	    ASSL_F_NONBLOCK | ASSL_F_CLOSE_SOCKET, serve_callback, NULL);

	return (0);
}
