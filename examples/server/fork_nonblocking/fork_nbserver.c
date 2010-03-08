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

void			serve_callback(int);

pid_t			child;

void
sighdlr(int sig)
{
	pid_t			pid;
	extern volatile sig_atomic_t	assl_stop_serving;

	switch (sig) {
	case SIGINT:
	case SIGTERM:
	case SIGHUP:
		assl_stop_serving = 1;
		fprintf(stderr, "stoppping in %d child %d\n", getpid(), child);
		if (child)
			_exit(0);
		else
			exit(0);
		break;
	case SIGCHLD:
		/* sig safe */
		while ((pid = waitpid(WAIT_ANY, NULL, WNOHANG)) != -1) {
			if (pid == 0)
				abort();
			fprintf(stderr, "reaping: %d\n", pid);
		}
		break;
	}
}

void
installsignal(int sig, char *name)
{
	struct sigaction	sa;
	char			msg[80];

	sa.sa_handler = sighdlr;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(sig, &sa, NULL) == -1) {
		snprintf(msg, sizeof msg, "could not install %s handler", name);
		err(1, msg);
	}
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

	c = assl_alloc_context(ASSL_M_ALL, ASSL_F_CHILD);
	if (c == NULL)
		assl_fatalx("assl_alloc_context");

	if (assl_load_file_certs(c, "../ca/ca.crt", "server/server.crt",
	    "server/private/server.key"))
		assl_fatalx("assl_load_file_certs");

	if (assl_accept(c, s))
		assl_fatalx("assl_accept");

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
	/* signaling */
	installsignal(SIGTERM, "TERM");
	installsignal(SIGINT, "INT");
	installsignal(SIGHUP, "HUP");
	installsignal(SIGCHLD, "CHLD");

	assl_initialize();

	assl_serve(NULL, ASSL_DEFAULT_PORT,
	    ASSL_F_NONBLOCK | ASSL_F_CLOSE_SOCKET, serve_callback);
	
	return (0);
}
