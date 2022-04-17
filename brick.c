#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <errno.h>
#include <tls.h>

#define NUM_PORTALS 1
#define MAX_CONNS   2
#define BACKLOG     128

enum phase {
	REQUEST, RESPONSE, PAYLOAD
};

/* Connection Control Block */
struct ccb {
	struct sockaddr_storage addr;
	socklen_t addrlen;
	struct tls *tls;
	enum phase phase;
	size_t progress;
};

static int nconns;
static struct pollfd pfds[NUM_PORTALS + MAX_CONNS];
static struct ccb ccbs[MAX_CONNS];

static void
usage(void)
{
	printf("usage: brick [host] [port]\n");
}

static int
open_portal(const char *host, const char *port)
{
	struct addrinfo hints = {
		.ai_flags    = AI_NUMERICSERV,
		.ai_family   = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
	};
	struct addrinfo *ai, *p;
	int err = getaddrinfo(host, port, &hints, &ai);
	if (err) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
		exit(1);
	}

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

	if (!p) {
		fprintf(stderr, "unable to open port\n");
		exit(1);
	}

	if (listen(fd, BACKLOG) < 0) {
		fprintf(stderr, "listen: %s\n", strerror(errno));
		exit(1);
	}

	freeaddrinfo(ai);
	return fd;
}

static void
add_conn(int fd, struct sockaddr_storage *addr, socklen_t addrlen)
{
	if (nconns >= MAX_CONNS) {
		printf("Rejecting a connection.\n");
		close(fd);
		return;
	}

	printf("Accepted a new connection.\n");

	fcntl(fd, F_SETFL, O_NONBLOCK);

	int idx = nconns++;
	memcpy(&ccbs[idx].addr, addr, addrlen);
	ccbs[idx].addrlen = addrlen;
	ccbs[idx].phase = REQUEST;
	ccbs[idx].progress = 0;
	pfds[NUM_PORTALS + idx].fd = fd;
	pfds[NUM_PORTALS + idx].events = POLLIN;
}

static void
del_conn(int idx)
{
	printf("Closing a connection.\n");

	close(pfds[NUM_PORTALS + idx].fd);
	
	nconns--;
	pfds[NUM_PORTALS + idx] = pfds[NUM_PORTALS + nconns];
	struct ccb tmp = ccbs[idx];
	ccbs[idx] = ccbs[nconns];
	ccbs[nconns] = tmp;
}

#if 0
static bool
parse_http(const char *buf, const HTTP_Field *fields)
{
	const char *p, *q;
	size_t n;
	const HTTP_Field *field;
	for (field = fields; field->key; ++field) {
		field->value[0] = 0;
	}
	p = buf;
	/* Ensure the used method is GET. */
	if (strncmp(p, "GET ", 4)) return false;
	p += 4;
	/* Parse the target path. */
	if (!(q = strchr(p, ' '))) return false;
	if (p == q) return false;
	n = MIN((size_t) (q-p), field->max-1);
	memcpy(field->value, p, n);
	field->value[n] = 0;
	p = q + 1;
	/* Parse the HTTP version & end of line. Must be HTTP/1.1. */
	if (strncmp(p, "HTTP/1.1\r\n", 10)) return false;
	p += 10;
	/* Assume each line corresponds to a header field. */
	while (*p) {
		/* Use linear search to identify the given header field. */
		for (field = fields; field->key; ++field) {
			n = strlen(field->key);
			if (!strncasecmp(p, field->key, n)) {
				p += n;
				break;
			}
		}
		/* If we don't recognize the header field, we silently ignore it. */
		if (!field->key) {
			if (!(q = strstr(p, "\r\n"))) return false;
			p = q + 2;
			continue;
		}
		/* Enforce the colon after the field name & skip whitespace. */
		if (*p != ':') return false;
		++p;
		while (*p == ' ' || *p == '\t') ++p;
		/* Copy the field's value and advance. */
		if (!(q = strstr(p, "\r\n"))) return false;
		n = MIN((size_t) (q-p), field->max-1);
		memcpy(field->value, p, n);
		field->value[n] = 0;
		p = q + 2;
	}
	return true;
}
#endif

static void
teardown(void)
{
	for (int i = 0; i < NUM_PORTALS + nconns; i++) {
		close(pfds[i].fd);
	}
}

int
main(int argc, const char *argv[])
{
	if (argc != 3) {
		usage();
		exit(1);
	}

	pfds[0].fd     = open_portal(argv[1], argv[2]);
	pfds[0].events = POLLIN;

	for (;;) {
		int n = poll(pfds, NUM_PORTALS + nconns, -1);
		if (n < 0) continue;

		for (int i = 0; i < NUM_PORTALS; i++) {
			if (pfds[i].revents & POLLIN) {
				struct sockaddr_storage addr;
				socklen_t addrlen;
				int fd = accept(pfds[i].fd, (void *) &addr, &addrlen);
				add_conn(fd, &addr, addrlen);
			}
		}

		for (int i = 0; i < nconns; i++) {
			if (pfds[NUM_PORTALS + i].revents) {
				printf("fd event: %hd\n", pfds[NUM_PORTALS + i].revents);
				if (pfds[NUM_PORTALS + i].revents & POLLERR) {
					del_conn(i);
					i--;
					continue;
				}
				if (pfds[NUM_PORTALS + i].revents & POLLIN) {
					char buf[1000];
					int ret = recv(pfds[NUM_PORTALS + i].fd, buf, 1000, 0);
					if (!ret) {
						del_conn(i);
						i--;
						continue;
					}
					if (ret < 0) {
						switch (errno) {
#if EAGAIN != EWOULDBLOCK
						case EAGAIN:
#endif
						case EWOULDBLOCK:
							break;
						default:
							del_conn(i);
							i--;
							continue;
						}
					}
				}
			}
		}
	}

	teardown();
	return 0;
}

