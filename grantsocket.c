#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

#include "arg.h"

#define BACKLOG 128

char *argv0;

static void
die(const char *fmt, ...)
{
	va_list ap;
	int err = errno;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (*fmt && fmt[strlen(fmt)-1] == ':') {
		fputc(' ', stderr);
		fputs(strerror(err), stderr);
	}
	fputc('\n', stderr);
	exit(1);
}

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-d fdnum] [-s user:group] host:port cmd ...\n", argv0);
}

static char *
split_arg(char *arg)
{
	char *pivot = strrchr(arg, ':');
	if (!pivot) {
		usage();
		exit(1);
	}
	*pivot = 0;
	return pivot + 1;
}

static int
open_socket(const char *host, const char *port)
{
	struct addrinfo hints = {
		.ai_flags    = AI_NUMERICSERV,
		.ai_family   = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
	};
	struct addrinfo *ai, *p;
	int err = getaddrinfo(host, port, &hints, &ai);
	if (err) die("getaddrinfo: %s", gai_strerror(err));

	int fd;
	for (p = ai; p; p = p->ai_next) {
		fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (fd < 0) continue;

		const int yes = 1;
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof (int));
		
		if (bind(fd, p->ai_addr, p->ai_addrlen) < 0) {
			close(fd);
			continue;
		}

		break;
	}
	if (!p) die("unable to open socket.");

	int flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	if (listen(fd, BACKLOG) < 0) die("listen:");

	freeaddrinfo(ai);
	return fd;
}

int
main(int argc, char **argv)
{
	argv0 = argv[0];

	int fd = 3;
	char *user = NULL, *group = NULL;
	ARGBEGIN {
	case 'h':
		usage();
		exit(0);
	case 'd':
		fd = atoi(EARGF(usage()));
		break;
	case 's':
		user = EARGF(usage());
		group = split_arg(user);
		break;
	default:
		usage();
		exit(1);
	} ARGEND

	if (argc < 2) {
		usage();
		exit(1);
	}

	char *host = *argv++;
	char *port = split_arg(host);

	int sock = open_socket(host, port);
	if (dup2(sock, fd) < 0) die("dup2:");
	if (sock != fd) close(sock);

	if (user) {
		errno = 0;
		struct passwd *pwd = getpwnam(user);
		if (!pwd) die("getpwnam:");

		errno = 0;
		struct group *grp = getgrnam(group);
		if (!grp) die("getgrnam:");

		if (setgroups(1, &grp->gr_gid) < 0) die("setgroups:");
		if (setgid(grp->gr_gid) < 0) die("setgid:");
		if (setuid(pwd->pw_uid) < 0) die("setuid:");
	}

	execvp(*argv, argv);
	die("execvp:");
}

