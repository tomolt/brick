#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <locale.h>
#include <time.h>
#include <errno.h>

#if BRICK_TLS
# include <tls.h>
# define NUM_ARGS 6
#else
# define NUM_ARGS 3
#endif

#define MIN(a,b) ((a)<(b)?(a):(b))

#define NUM_PORTALS 1
#define MAX_CONNS   1000
#define BACKLOG     128
#define SCRATCH     2048
#define MAX_PATH    200
#define MAX_HEADER  200

#define SHUTDOWN    0x1
#define RECONFIGURE 0x2

enum phase { REQUEST, RESPONSE, PAYLOAD };

struct conn {
	char *scratch;
#if BRICK_TLS
	struct tls *tls;
#endif
	struct sockaddr_storage addr;
	size_t offset;
	size_t length;
	size_t content_length;
	enum phase phase;
	int sock;
	int src;
};

static const char **args;
static volatile int global_flags;
static int nconns;

static struct pollfd  all_pfds[NUM_PORTALS + MAX_CONNS];
static struct conn    conns[MAX_CONNS];
static struct pollfd *conn_pfds = all_pfds + NUM_PORTALS;
#if BRICK_TLS
static struct tls    *portal_tls;
#endif

static const char *req_keys[] = {
	"Host",
	NULL
};

static char req_headers[sizeof req_keys / sizeof *req_keys - 1][MAX_HEADER];
static char req_path[MAX_PATH];

static const char *mime_types[] = {
        ".xml",   "application/xml; charset=utf-8",
        ".xhtml", "application/xhtml+xml; charset=utf-8",
        ".html",  "text/html; charset=utf-8",
        ".htm",   "text/html; charset=utf-8",
        ".css",   "text/css; charset=utf-8",
        ".txt",   "text/plain; charset=utf-8",
        ".md",    "text/plain; charset=utf-8",
        ".c",     "text/plain; charset=utf-8",
        ".h",     "text/plain; charset=utf-8",
        ".gz",    "application/x-gtar",
        ".tar",   "application/tar",
        ".pdf",   "application/x-pdf",
        ".png",   "image/png",
        ".gif",   "image/gif",
        ".jpeg",  "image/jpg",
        ".jpg",   "image/jpg",
        ".iso",   "application/x-iso9660-image",
        ".webp",  "image/webp",
        ".svg",   "image/svg+xml; charset=utf-8",
        ".flac",  "audio/flac",
        ".mp3",   "audio/mpeg",
        ".ogg",   "audio/ogg",
        ".mp4",   "video/mp4",
        ".ogv",   "video/ogg",
        ".webm",  "video/webm",
	NULL
};

static void
usage(void)
{
	printf("usage: %s [host] [port]"
#if BRICK_TLS
		" [ca-file] [cert-file] [key-file]"
#endif
		"\n", args[0]);
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

	int flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	if (listen(fd, BACKLOG) < 0) {
		fprintf(stderr, "listen: %s\n", strerror(errno));
		exit(1);
	}

	freeaddrinfo(ai);
	return fd;
}

static int
same_addr(const struct sockaddr_storage *a, const struct sockaddr_storage *b)
{
	if (a->ss_family != b->ss_family) return 0;
	switch (a->ss_family) {
	case AF_INET:
		return ((struct sockaddr_in *) a)->sin_addr.s_addr ==
			((struct sockaddr_in *) b)->sin_addr.s_addr;
	default: /* AF_INET6 */
		return memcmp(((struct sockaddr_in6 *) a)->sin6_addr.s6_addr,
			((struct sockaddr_in6 *) b)->sin6_addr.s6_addr,
			sizeof (((struct sockaddr_in6 *) a)->sin6_addr.s6_addr)) == 0;
	}
}

static int
evict(void)
{
	int evicted = -1;
	int maxcnt = 0;
	for (int i = 0; i < nconns; i++) {
		int sel = i, cnt = 0;
		for (int j = 0; j < nconns; j++) {
			if (!same_addr(&conns[sel].addr, &conns[j].addr)) continue;
			cnt++;
			if (conns[j].phase < conns[sel].phase) {
				sel = j;
			} else if (conns[j].phase == conns[sel].phase) {
				int swap = 0;
				switch (conns[sel].phase) {
				case REQUEST:
					swap = conns[j].length < conns[sel].length;
					break;
				case RESPONSE:
					/* TODO prioritize status 200 responses */
					swap = (conns[j].length - conns[j].offset) >
						(conns[sel].length - conns[sel].offset);
					break;
				case PAYLOAD:
					swap = conns[j].content_length > conns[sel].content_length;
					break;
				}
				if (swap) sel = j;
			}
		}
		if (cnt > maxcnt) {
			evicted = sel;
			maxcnt = cnt;
		}
	}
	return evicted;
}

static void
clr_conn(int idx)
{
	struct conn *conn = &conns[idx];
	close(conn->sock);
	if (!(conn->src < 0)) close(conn->src);
#if BRICK_TLS
	tls_free(conn->tls);
#endif
}

static void
del_conn(int idx)
{
	printf("Closing a connection.\n");

	char *scratch = conns[idx].scratch;
	clr_conn(idx);
	
	nconns--;
	conns[idx] = conns[nconns];
	conn_pfds[idx] = conn_pfds[nconns];

	memset(&conns[nconns], 0, sizeof (struct conn));
	conns[nconns].scratch = scratch;
}

static int
set_conn(int idx, int fd, const struct sockaddr_storage *addr, socklen_t addrlen)
{
	struct conn *conn = &conns[idx];

	int flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#if BRICK_TLS
	if (tls_accept_socket(portal_tls, &conn->tls, fd) < 0) {
		fprintf(stderr, "tls_accept: %s (non-fatal)\n", tls_error(portal_tls));
		close(fd);
		return -1;
	}
#endif

	memcpy(&conn->addr, addr, addrlen);
	conn->sock = fd;
	conn->src = -1;

	conn_pfds[idx].fd      = fd;
	conn_pfds[idx].events  = POLLIN;
	conn_pfds[idx].revents = 0;
	
	return 0;
}

static void
add_conn(int fd, struct sockaddr_storage *addr, socklen_t addrlen)
{
	printf("Accepted a new connection.\n");
	if (nconns >= MAX_CONNS) {
		del_conn(evict());
	}
	if (set_conn(nconns, fd, addr, addrlen) < 0) return;
	nconns++;
}

static int
conn_read(int idx)
{
	struct conn *conn = &conns[idx];
	if (conn->length == SCRATCH) return -1;
#if BRICK_TLS
	ssize_t n = tls_read(conn->tls, conn->scratch + conn->length, SCRATCH - conn->length);
	switch (n) {
	case -1: fprintf(stderr, "tls_read: %s (non-fatal)\n", tls_error(conn->tls)); return -1;
	case TLS_WANT_POLLIN:  conn_pfds[idx].events = POLLIN;  break;
	case TLS_WANT_POLLOUT: conn_pfds[idx].events = POLLOUT; break;
	default: conn->length += n;
	}
	return 0;
#else
	for (;;) {
		ssize_t n = read(conn->sock, conn->scratch + conn->length, SCRATCH - conn->length);
		if (!n) return -1;
		if (n > 0) {
			conn->length += n;
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
#endif
}

static int
conn_write(int idx)
{
	struct conn *conn = &conns[idx];
#if BRICK_TLS
	ssize_t n = tls_write(conn->tls, conn->scratch + conn->offset, conn->length - conn->offset);
	switch (n) {
	case -1: fprintf(stderr, "tls_write: %s (non-fatal)\n", tls_error(conn->tls)); return -1;
	case TLS_WANT_POLLIN:  conn_pfds[idx].events = POLLIN;  break;
	case TLS_WANT_POLLOUT: conn_pfds[idx].events = POLLOUT; break;
	default: conn->offset += n;
	}
	return 0;
#else
	for (;;) {
		ssize_t n = write(conn->sock, conn->scratch + conn->offset, conn->length - conn->offset);
		if (n >= 0) {
			conn->offset += n;
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
#endif
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
	
	/* Parse the HTTP version & end of line. */
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
sanitize_path(char *path)
{
	char *r = path, *w = path;
	if (*r != '/') return -1;
	for (;;) {
		while (*r == '/') r++;
		if (*r == '.') return -1;
		char *d = strchr(r, '/');
		if (!d) break;
		size_t l = d - r + 1;
		memmove(w, r, l);
		w += l;
		r = d;
	}
	size_t l = strlen(r);
	memmove(w, r, l);
	w += l;
	*w = 0;
	return 0;
}

static const char *
name_of_code(int code)
{
	switch (code) {
	case 200: return "OK";
	case 400: return "Bad Request";
	case 404: return "File Not Found";
	default:  return "";
	}
}

static int
load_content(int idx, const char **mime)
{
	struct conn *conn = &conns[idx];
	conn->content_length = 0;
	*mime = "text/plain";

	if (parse_http(conn->scratch, req_keys, req_headers, req_path) < 0) return -1;
	printf("Requested path: %s\n", req_path);

	if (sanitize_path(req_path) < 0) return 400;
	printf("Sanitized path: %s\n", req_path);

	conn->src = open(req_path, O_RDONLY);
	if (conn->src < 0) return 404;

	*mime = "application/octet-stream";
	size_t pathlen = strlen(req_path);
	for (int i = 0; mime_types[i]; i += 2) {
		size_t len = strlen(mime_types[i]);
		if (pathlen < len) continue;
		if (!strcmp(req_path + pathlen - len, mime_types[i])) {
			*mime = mime_types[i+1];
			break;
		}
	}

	struct stat meta;
	fstat(conn->src, &meta);
	// TODO err check
	if (S_ISDIR(meta.st_mode)) {
		int fd = openat(conn->src, "index.html", O_RDONLY);
		close(conn->src);
		conn->src = fd;
		if (conn->src < 0) return 404;
		fstat(conn->src, &meta);
		*mime = "text/html;charset=UTF-8";
	}
	conn->content_length = meta.st_size;

	return 200;
}

static int
process_request(int idx)
{
	const char *mime;
	int code = load_content(idx, &mime);
	if (code < 0) return -1;

	char date[50];
	time_t t = time(NULL);
	struct tm tm;
	gmtime_r(&t, &tm);
	strftime(date, sizeof date, "%a, %d %b %Y %T GMT", &tm);

	struct conn *conn = &conns[idx];
	conn->length = snprintf(conn->scratch, SCRATCH,
		"HTTP/1.1 %03d %s\r\n"
		"Server: brick\r\n"
		"Date: %s\r\n"
		"Content-Type: %s\r\n",
		code, name_of_code(code), date, mime);

	if (code == 200) {
		conn->length += snprintf(conn->scratch + conn->length, SCRATCH - conn->length,
			"Content-Length: %llu\r\n"
			"\r\n",
			(long long unsigned) conn->content_length);
	} else {
		const char *msg = name_of_code(code);
		conn->length += snprintf(conn->scratch + conn->length, SCRATCH - conn->length,
			"Content-Length: %llu\r\n"
			"\r\n"
			"%03d %s",
			(long long unsigned) (4 + strlen(msg)), code, msg);
	}

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
		if (conn_read(idx) < 0) return -1;

		if (conn->length >= 4 && !memcmp(conn->scratch + conn->length - 4, "\r\n\r\n", 4)) {
			conn->scratch[conn->length - 2] = 0;
			printf("Received a request.\n");
			switch_phase(idx, RESPONSE);
			return process_request(idx);
		}
		return 0;

	case RESPONSE:
		if (!(revents & POLLOUT)) return 0;
		if (conn_write(idx) < 0) return -1;

		if (conn->offset == conn->length) {
			printf("Sent a response.\n");
			switch_phase(idx, conn->content_length ? PAYLOAD : REQUEST);
		}
		return 0;

	case PAYLOAD:
		if (!(revents & POLLOUT)) return 0;

		if (conn->offset == conn->length) {
			conn->offset = 0;
			for (;;) {
				ssize_t n = read(conn->src, conn->scratch, SCRATCH);
				if (!n) return -1;
				if (n > 0) {
					conn->length = n;
					break;
				}
				switch (errno) {
				case EINTR: continue;
				default: return -1;
				}
			}
			conn->content_length -= conn->length;
		}

		if (conn_write(idx) < 0) return -1;

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
signal_handler(int sig)
{
	switch (sig) {
	case SIGINT:
	case SIGTERM: global_flags |= SHUTDOWN; break;
	case SIGUSR1: global_flags |= RECONFIGURE; break;
	}
}

static void
reconfigure(void)
{
#if BRICK_TLS
	if (portal_tls) tls_reset(portal_tls);
	else portal_tls = tls_server();
	struct tls_config *tls_cfg = tls_config_new();
	if (tls_config_set_ca_file(tls_cfg, args[3]) < 0 ||
		tls_config_set_cert_file(tls_cfg, args[4]) < 0 ||
		tls_config_set_key_file (tls_cfg, args[5]) < 0) {
		fprintf(stderr, "tls configuration: %s (non-fatal)\n", tls_config_error(tls_cfg));
		tls_config_free(tls_cfg);
		return;
	}
	if (tls_configure(portal_tls, tls_cfg) < 0) {
		fprintf(stderr, "tls_configure: %s (non-fatal)\n", tls_error(portal_tls));
	}
	tls_config_free(tls_cfg);
#endif
}

static void
teardown(void)
{
	close(all_pfds[0].fd);
#if BRICK_TLS
	tls_free(portal_tls);
#endif
	for (int i = nconns; i--;) del_conn(i);
	for (int i = 0; i < MAX_CONNS; i++) free(conns[i].scratch);
}

int
main(int argc, const char **argv)
{
	setlocale(LC_ALL, "C");

	args = argv;
	if (argc != NUM_ARGS) {
		usage();
		exit(1);
	}

	reconfigure();
	all_pfds[0].fd     = open_portal(argv[1], argv[2]);
	all_pfds[0].events = POLLIN;

	struct sigaction sa = { 0 };
	sa.sa_handler = signal_handler;
	sigaction(SIGINT,  &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);

	for (int i = 0; i < MAX_CONNS; i++) {
		conns[i].scratch = malloc(SCRATCH);
		if (!conns[i].scratch) {
			fprintf(stderr, "malloc: %s\n", strerror(errno));
			exit(1);
		}
	}

	for (;;) {
		int n = poll(all_pfds, NUM_PORTALS + nconns, -1);

		if (global_flags & SHUTDOWN) {
			printf("Shutting down.\n");
			teardown();
			exit(0);
		}
		if (global_flags & RECONFIGURE) {
			printf("Reconfiguring.\n");
			reconfigure();
			global_flags &= ~RECONFIGURE;
		}

		if (n < 0) continue;

		if (all_pfds[0].revents & POLLIN) {
			for (;;) {
				struct sockaddr_storage addr;
				socklen_t addrlen = sizeof addr;
				int fd = accept(all_pfds[0].fd, (void *) &addr, &addrlen);
				if (fd < 0) break;
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
}

