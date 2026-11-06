/*
 * THE BRIDGE: a bearer on one side and a host's UDP port on the other, project.md
 * sec 912. For a device with no IP, which reaches its gateway through whatever
 * radio or serial line is plugged into a machine beside it.
 *
 *     fuzznet-bridge --unit=N --udp=HOST:PORT [--serial=PATH]
 *
 * A byte stream (`--serial`, stdin and stdout when not given) carries units as
 * SLIP, each a piece of a frame (`net/bearer.h`). A frame joined whole goes to
 * the host as one datagram, and each datagram the host sends back goes out as
 * pieces.
 *
 * IT HOLDS NO KEY AND CHECKS NOTHING. A sealed frame says who sent it, and the
 * host judges that, so a bridge is the unprivileged carrier sec 3 describes:
 * taking it over lets you drop frames and no more, as owning the radio does.
 * All devices share one socket: a host answers the frame's sender under its
 * session, and on a radio everyone hears the answer and only one can open it.
 *
 * STOPS when the stream ends, or at SIGINT or SIGTERM. Holds nothing that
 * grows: its slots are a fixed few, an oldest frame giving way to a newer.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>

#include "bearer.h"
#include "udp.h"

/* DEVICES PART WAY AT ONCE. One radio carries one transmission at a time, so
 * this only has to outlast a frame's pieces being interleaved. */
#define BRIDGE_SLOTS 8u

static volatile sig_atomic_t stopping;

static void on_stop(int signum)
{
	(void)signum;
	stopping = 1;
}

static int stream_out = -1;

static int write_all(int fd, const uint8_t *bytes, size_t len)
{
	while (len) {
		ssize_t n = write(fd, bytes, len);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return 0;
		bytes += n;
		len -= (size_t)n;
	}
	return 1;
}

static int send_unit(void *ctx, const uint8_t *bytes, size_t len)
{
	static uint8_t coded[2u * FZN_BEARER_UNIT_MAX + 2u];
	size_t n = fzn_slip_encode(bytes, len, coded, sizeof(coded));

	(void)ctx;
	return n && write_all(stream_out, coded, n);
}

/* A TTY'S BYTES AS THEY COME: no echo, no line discipline. A pipe has none. */
static int make_raw(int fd)
{
	struct termios t;

	if (!isatty(fd))
		return 1;
	if (tcgetattr(fd, &t) != 0)
		return 0;
	t.c_iflag &= ~(tcflag_t)(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
	t.c_oflag &= ~(tcflag_t)OPOST;
	t.c_lflag &= ~(tcflag_t)(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
	t.c_cflag &= ~(tcflag_t)(CSIZE | PARENB);
	t.c_cflag |= CS8;
	t.c_cc[VMIN] = 1;
	t.c_cc[VTIME] = 0;
	return tcsetattr(fd, TCSANOW, &t) == 0;
}

static void usage(const char *prog)
{
	fprintf(stderr, "usage: %s --unit=N --udp=HOST:PORT [--serial=PATH]\n", prog);
}

int main(int argc, char **argv)
{
	static fzn_bearer_slot_t slots[BRIDGE_SLOTS];
	static uint8_t unit_in[FZN_BEARER_UNIT_MAX], datagram[FZN_UDP_DATAGRAM_MAX];
	static char host[64];
	fzn_slip_reader_t reader;
	fzn_bearer_join_t join;
	fzn_bearer_t bearer;
	fzn_udp_addr_t to;
	struct sigaction stop;
	struct pollfd fds[2];
	const char *serial = NULL, *udp = NULL;
	unsigned long unit = 0, port = 0;
	uint16_t link_id = 0;
	int in_fd = 0, udp_fd = -1, i;
	char *colon;

	for (i = 1; i < argc; i++) {
		if (!strncmp(argv[i], "--unit=", 7))
			unit = strtoul(argv[i] + 7, NULL, 10);
		else if (!strncmp(argv[i], "--udp=", 6))
			udp = argv[i] + 6;
		else if (!strncmp(argv[i], "--serial=", 9))
			serial = argv[i] + 9;
		else {
			usage(argv[0]);
			return 2;
		}
	}
	if (!udp || unit < FZN_BEARER_UNIT_MIN || unit > FZN_BEARER_UNIT_MAX
	    || strlen(udp) >= sizeof(host) || !(colon = strrchr(strcpy(host, udp), ':'))) {
		usage(argv[0]);
		return 2;
	}
	*colon = '\0';
	port = strtoul(colon + 1, NULL, 10);
	if (port == 0u || port > 65535u
	    || fzn_udp_resolve(AF_INET, host, (uint16_t)port, &to) != FZN_UDP_OK
	    || fzn_udp_bind(AF_INET, NULL, 0, &udp_fd) != FZN_UDP_OK) {
		fprintf(stderr, "fuzznet-bridge: could not reach for %s\n", udp);
		return 1;
	}
	stream_out = 1;
	if (serial) {
		in_fd = open(serial, O_RDWR | O_NOCTTY);
		if (in_fd < 0 || !make_raw(in_fd)) {
			fprintf(stderr, "fuzznet-bridge: %s: %s\n", serial, strerror(errno));
			return 1;
		}
		stream_out = in_fd;
	}
	memset(&stop, 0, sizeof(stop));
	stop.sa_handler = on_stop;
	(void)sigaction(SIGINT, &stop, NULL);
	(void)sigaction(SIGTERM, &stop, NULL);
	(void)signal(SIGPIPE, SIG_IGN);

	memset(&reader, 0, sizeof(reader));
	reader.buffer = unit_in;
	reader.cap = sizeof(unit_in);
	memset(&join, 0, sizeof(join));
	join.held = slots;
	join.n_held = BRIDGE_SLOTS;
	join.unit = unit;
	memset(&bearer, 0, sizeof(bearer));
	bearer.unit = unit;
	bearer.send = send_unit;

	fds[0].fd = in_fd;
	fds[0].events = POLLIN;
	fds[1].fd = udp_fd;
	fds[1].events = POLLIN;
	while (!stopping) {
		if (poll(fds, 2u, -1) < 0) {
			if (errno == EINTR)
				continue;
			return 1;
		}
		if (fds[0].revents) {
			uint8_t bytes[256];
			ssize_t n = read(in_fd, bytes, sizeof(bytes));
			ssize_t k;

			if (n == 0 || (n < 0 && errno != EINTR))
				break;
			for (k = 0; k < n; k++) {
				const uint8_t *frame = NULL;
				size_t len, whole;

				if (!(len = fzn_slip_feed(&reader, bytes[k])))
					continue;
				whole = fzn_bearer_take(&join, unit_in, len, &frame);
				if (whole)
					(void)fzn_udp_send(udp_fd, &to, frame, whole);
			}
		}
		if (fds[1].revents) {
			size_t len = 0;

			if (fzn_udp_recv(udp_fd, datagram, sizeof(datagram), &len, NULL) == FZN_UDP_OK
			    && len)
				(void)fzn_bearer_send(&bearer, link_id++, datagram, len);
		}
	}
	close(udp_fd);
	return 0;
}
