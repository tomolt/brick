#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <errno.h>
#include <tls.h>

#define MIN(a,b) ((a)<(b)?(a):(b))
#define SWAP(t,a,b) do { t _tv=(a); (a)=(b); (b)=_tv; } while (0)

#define NUM_PORTALS 1
#define MAX_CONNS   2
#define BACKLOG     128
#define SCRATCH     2048
#define MAX_PATH    200
#define MAX_HEADER  200

enum phase {
	REQUEST, RESPONSE, PAYLOAD
};

struct conn {
	char *scratch;
	struct sockaddr_storage addr;
	socklen_t addrlen;
	size_t offset;
	size_t length;
	size_t content_length;
	enum phase phase;
	int sock;
	int src;
};

static int nconns;

static struct pollfd  all_pfds[NUM_PORTALS + MAX_CONNS];
static struct conn    conns[MAX_CONNS];
static struct pollfd *conn_pfds = all_pfds + NUM_PORTALS;

static const char *req_keys[] = {
	"Connection",
	NULL
};

static char req_headers[sizeof req_keys / sizeof *req_keys - 1][MAX_HEADER];
static char req_path[MAX_PATH];

static const char *mime_types[] = {
	".html", "text/html",
	".htm", "text/html",
	NULL
};

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

static int
read_some(int fd, char *buf, size_t *len, size_t max)
{
	if (*len == max) return -1;
	for (;;) {
		ssize_t n = read(fd, buf + *len, max - *len);
		if (!n) return -1;
		if (n > 0) {
			*len += n;
			return 0;
		}
		switch (errno) {
		case EINTR: continue;
#if EAGAIN != EWOULDBLOCK
		case EAGAIN:
#endif
		case EWOULDBLOCK: return 0;
		default: return -1;
		}
	}
}

static int
write_some(int fd, const char *buf, size_t *off, size_t len)
{
	for (;;) {
		ssize_t n = write(fd, buf + *off, len - *off);
		if (n >= 0) {
			*off += n;
			return 0;
		}
		switch (errno) {
		case EINTR: continue;
#if EAGAIN != EWOULDBLOCK
		case EAGAIN:
#endif
		case EWOULDBLOCK: return 0;
		default: return -1;
		}
	}
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
	conn->src = -1;

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
	if (!(conn->src < 0)) close(conn->src);
	
	nconns--;
	conns[idx] = conns[nconns];
	conn_pfds[idx] = conn_pfds[nconns];

	memset(&conns[nconns], 0, sizeof (struct conn));
	conns[nconns].scratch = scratch;
}

static void
switch_phase(int idx, enum phase phase)
{
	struct conn *conn = &conns[idx];
	conn->phase  = phase;
	conn->offset = 0;
	conn->length = 0;
	conn_pfds[idx].events = phase == REQUEST ? POLLIN : POLLOUT;
}

static int
parse_http(const char *buf, const char **keys, char (*values)[MAX_HEADER], char *path)
{
	const char *p, *q;
	size_t n;
	int i;

	for (i = 0; keys[i]; i++) {
		values[i][0] = 0;
	}
	path[0] = 0;
	p = buf;
	
	/* Ensure the used method is GET. */
	if (strncmp(p, "GET ", 4)) return -1;
	p += 4;
	
	/* Parse the target path. */
	if (!(q = strchr(p, ' '))) return -1;
	if (p == q) return -1;
	n = MIN((size_t) (q-p), MAX_PATH-1);
	memcpy(path, p, n);
	path[n] = 0;
	p = q + 1;
	
	/* Parse the HTTP version & end of line. Must be HTTP/1.1. */
	if (strncmp(p, "HTTP/1.1\r\n", 10)) return -1;
	p += 10;
	
	/* Assume each line corresponds to a header field. */
	while (*p) {
		/* Use linear search to identify the given header field. */
		for (i = 0; keys[i]; i++) {
			if (!strcasecmp(p, keys[i])) {
				p += strlen(keys[i]);
				break;
			}
		}

		/* If we don't recognize the header field, we silently ignore it. */
		if (!keys[i]) {
			if (!(q = strstr(p, "\r\n"))) return -1;
			p = q + 2;
			continue;
		}

		/* Enforce the colon after the field name & skip whitespace. */
		if (*p != ':') return -1;
		p++;
		while (*p == ' ' || *p == '\t') p++;

		/* Copy the field's value and advance. */
		if (!(q = strstr(p, "\r\n"))) return -1;
		n = MIN((size_t) (q-p), MAX_HEADER-1);
		memcpy(values[i], p, n);
		values[i][n] = 0;
		p = q + 2;
	}
	return 0;
}

static int
process_request(int idx)
{
	struct conn *conn = &conns[idx];
	conn->content_length = 0;

	if (parse_http(conn->scratch, req_keys, req_headers, req_path) < 0) return -1;
	printf("Requested path: %s\n", req_path);

	conn->src = open(req_path, O_RDONLY);
	if (conn->src < 0) {
		conn->length = snprintf(conn->scratch, SCRATCH,
			"HTTP/1.1 404 Not Found\r\n"
			"Server: brick\r\n"
			"Content-Type: text/html;charset=UTF-8\r\n"
			"Content-Length: 13\r\n"
			"\r\n"
			"404 Not Found");
		return 0;
	}

	struct stat meta;
	fstat(conn->src, &meta);
	// TODO err check
	conn->content_length = meta.st_size;

	const char *mime = "text/plain";
	size_t pathlen = strlen(req_path);
	for (int i = 0; mime_types[i]; i += 2) {
		size_t len = strlen(mime_types[i]);
		if (pathlen < len) continue;
		if (!strcmp(req_path + pathlen - len, mime_types[i])) {
			mime = mime_types[i+1];
			break;
		}
	}

	conn->length = snprintf(conn->scratch, SCRATCH,
		"HTTP/1.1 200 OK\r\n"
		"Server: brick\r\n"
		"Content-Type: %s\r\n"
		"Content-Length: %llu\r\n"
		"\r\n", mime, (long long unsigned) conn->content_length);
	return 0;
}

static int
process_conn(int idx, int revents)
{
	if (revents & POLLERR) return -1;

	struct conn *conn = &conns[idx];
	switch (conn->phase) {
	case REQUEST:
		if (!(revents & POLLIN)) return 0;
		if (read_some(conn->sock, conn->scratch, &conn->length, SCRATCH) < 0) return -1;

		if (conn->length >= 4 && !memcmp(conn->scratch + conn->length - 4, "\r\n\r\n", 4)) {
			conn->scratch[conn->length - 2] = 0;
			printf("Received a request.\n");
			switch_phase(idx, RESPONSE);
			return process_request(idx);
		}
		return 0;

	case RESPONSE:
		if (!(revents & POLLOUT)) return 0;
		if (write_some(conn->sock, conn->scratch, &conn->offset, conn->length) < 0) return -1;

		if (conn->offset == conn->length) {
			printf("Sent a response.\n");
			switch_phase(idx, conn->content_length ? PAYLOAD : REQUEST);
		}
		return 0;

	case PAYLOAD:
		if (!(revents & POLLOUT)) return 0;

		if (conn->offset == conn->length) {
			conn->offset = 0;
			conn->length = 0;
			if (read_some(conn->src, conn->scratch, &conn->length, SCRATCH) < 0) return -1;
			conn->content_length -= conn->length;
		}

		if (write_some(conn->sock, conn->scratch, &conn->offset, conn->length) < 0) return -1;

		if (conn->offset == conn->length && !conn->content_length) {
			printf("Sent the payload.\n");
			switch_phase(idx, REQUEST);
			close(conn->src);
		}
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
		if (!(conns[i].src < 0)) close(conns[i].src);
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
				socklen_t addrlen = sizeof addr;
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

