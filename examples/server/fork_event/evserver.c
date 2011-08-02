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
#include <errno.h>
#include <event.h>
#include <signal.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/wait.h>

#include "assl.h"

struct workctx {
	struct event		*ev;
	struct assl_context	*c;
	char			*b;
	ssize_t 		tot;
	int			s;		/* not really needed? */
	char			buf[65536 * 10];
};

int child = 0;

void			serve_callback(int s, short event, void *arg);
void			serve_rd_worker(int fd, short event, void *arg);
void			serve_wr_worker(int fd, short event, void *arg);

void			sighdlr(int sig);

void
serve_callback(int s, short event, void *arg)
{
	struct assl_context	*c;
	struct workctx		*wctx;
	pid_t			child;


	/*
	 * If child and parent were going to talk over a pipe, that pipe
	 * would be created here.
	 */
	child = fork();

	switch(child) {
	case -1:
		printf("fork failed %d %s\n", errno, strerror(errno));
		assl_fatalx("");
		break;
	case 0:
		/* child */
		child = getpid();
		break;
	default:
		/* parent */
		return;
	}

	printf("running in child\n");

	/* reinit libevent, we do not want to handle events of the parent */
	event_init();

	wctx = calloc(1, sizeof(*wctx));
	if (wctx == NULL)
		assl_fatalx("assl_alloc_context");

	wctx->b = wctx->buf;
	wctx->tot = sizeof wctx->buf;

	c = assl_alloc_context(ASSL_M_ALL, 0);
	if (c == NULL)
		assl_fatalx("assl_alloc_context");
	wctx->c = c;

	if (assl_load_file_certs(c, "../ca/ca.crt", "server/server.crt",
	    "server/private/server.key"))
		assl_fatalx("assl_load_file_certs");

	if (assl_event_accept(c, s, serve_rd_worker, serve_wr_worker, wctx))
		assl_fatalx("assl_accept");

	event_dispatch();
}


void
serve_rd_worker(int fd, short event, void *arg)
{
	struct workctx		*wctx = arg;
	int			close = 0;
	ssize_t			rd;

	rd = assl_read(wctx->c, wctx->b, wctx->tot);

	//printf("read %zd\n", rd);
	if (rd == -1) {
		return;
	} else if (rd == 0 && wctx->tot != 0) {
		/* socket closed */
		close = 1;
	}  else {
		wctx->tot -= rd;
		wctx->b += rd;
	}

	if (wctx->tot == 0 || close == 1) {
		printf("receive finished\n");
		assl_close(wctx->c);
		free(wctx);
		_exit(0);
	}
}

void
serve_wr_worker(int fd, short event, void *arg)
{
}

struct assl_serve_ctx	*assl_lctx = NULL;

int
main(int argc, char *argv[])
{
	struct sigaction	sact;

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

	assl_initialize();

	event_init();

	assl_lctx = assl_event_serve(NULL, ASSL_DEFAULT_PORT,
	    ASSL_F_NONBLOCK|ASSL_F_CLOSE_SOCKET, serve_callback, NULL);

	event_dispatch();

	return (0);
}

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
		if (assl_lctx)
		    assl_event_serve_stop(assl_lctx);
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
