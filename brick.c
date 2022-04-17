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

#define SWAP(t,a,b) do { t _tv=(a); (a)=(b); (b)=_tv; } while (0)

#define NUM_PORTALS 1
#define MAX_CONNS   2
#define BACKLOG     128
#define SCRATCH     2048

enum phase {
	REQUEST, RESPONSE, PAYLOAD
};

struct conn {
	char *scratch;
	struct sockaddr_storage addr;
	socklen_t addrlen;
	size_t progress;
	enum phase phase;
	int sock;
};

static int nconns;

static struct pollfd  all_pfds[NUM_PORTALS + MAX_CONNS];
static struct conn    conns[MAX_CONNS];
static struct pollfd *conn_pfds = all_pfds + NUM_PORTALS;

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
	struct conn *conn = &conns[idx];

	memcpy(&conn->addr, addr, addrlen);
	conn->addrlen = addrlen;
	conn->sock = fd;

	conn_pfds[idx].fd = fd;
	conn_pfds[idx].events = POLLIN;
}

static void
del_conn(int idx)
{
	printf("Closing a connection.\n");

	struct conn *conn = &conns[idx];
	char *scratch = conn->scratch;
	close(conn->sock);
	
	nconns--;
	conns[idx] = conns[nconns];
	conn_pfds[idx] = conn_pfds[nconns];

	memset(&conns[nconns], 0, sizeof (struct conn));
	conns[nconns].scratch = scratch;
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

static int
process_conn(int idx, int revents)
{
	struct conn *conn = &conns[idx];
	int ret;

	printf("fd event: %hd\n", revents);
	if (revents & POLLERR) return -1;

	switch (conn->phase) {
	case REQUEST:
		if (!(revents & POLLIN)) return 0;
		if (conn->progress >= SCRATCH) return -1;
retry_recv:
		ret = recv(conn->sock, conn->scratch, SCRATCH - conn->progress, 0);
		if (!ret) return -1;
		if (ret < 0) {
			switch (errno) {
			case EINTR:
				goto retry_recv;
#if EAGAIN != EWOULDBLOCK
			case EAGAIN:
#endif
			case EWOULDBLOCK:
				return 0;
			default:
				return -1;
			}
		}
		conn->progress += ret;

		if (conn->progress < 4) return 0;
		if (memcmp(conn->scratch + conn->progress - 4, "\r\n\r\n", 4)) return 0;

		

		return 0;

	case RESPONSE:
		return 0;

	case PAYLOAD:
		return 0;

	default:
		return -1;
	}
}

static void
teardown(void)
{
	for (int i = 0; i < NUM_PORTALS; i++) {
		close(all_pfds[i].fd);
	}
	for (int i = 0; i < nconns; i++) {
		close(conns[i].sock);
	}
	for (int i = 0; i < MAX_CONNS; i++) {
		free(conns[i].scratch);
	}
}

int
main(int argc, const char *argv[])
{
	if (argc != 3) {
		usage();
		exit(1);
	}

	all_pfds[0].fd     = open_portal(argv[1], argv[2]);
	all_pfds[0].events = POLLIN;

	for (int i = 0; i < MAX_CONNS; i++) {
		conns[i].scratch = malloc(SCRATCH);
		if (!conns[i].scratch) {
			fprintf(stderr, "malloc: %s\n", strerror(errno));
			exit(1);
		}
	}

	for (;;) {
		int n = poll(all_pfds, NUM_PORTALS + nconns, -1);
		if (n < 0) continue;

		for (int i = 0; i < NUM_PORTALS; i++) {
			if (all_pfds[i].revents & POLLIN) {
				struct sockaddr_storage addr;
				socklen_t addrlen;
				int fd = accept(all_pfds[i].fd, (void *) &addr, &addrlen);
				add_conn(fd, &addr, addrlen);
			}
		}

		for (int i = 0; i < nconns; i++) {
			if (conn_pfds[i].revents) {
				if (process_conn(i, conn_pfds[i].revents) < 0) {
					del_conn(i);
					i--;
					continue;
				}
			}
		}
	}

	teardown();
	return 0;
}

