/* The local path end to end, in the order sec 4.8c states.
 *
 * Every piece of `local/` has its own test and none of them crosses a seam.
 * This one drives all four over a real socket -- accept, credentials, framing,
 * vocabulary -- because the failures worth catching here are the ones that
 * live between modules rather than inside one.
 *
 * THE ONE THAT MATTERS is the fail-closed path across the accept/vocabulary
 * seam. `fzn_socket_accept` fills an `fzn_peer_t`; `fzn_vocabulary_admit`
 * reads it. If the supplementary group list could not be read, accept leaves
 * `groups_known` clear and admit must answer UNKNOWN rather than a definite
 * anything. Each module asserts its own half; nothing asserted that the halves
 * meet, and a struct filled by one and misread by the other would pass both
 * suites.
 *
 * Bounded and self-contained: one directory under TMPDIR, one process, no
 * fork, both ends of every connection owned here.
 */

#if defined(__linux__)
#define _GNU_SOURCE
#endif

#include "../line.h"
#include "../socket.h"
#include "../vocabulary.h"

#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int failures;
static int checks;

static void check(int ok, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL: %s\n", what);
	}
}

static int dial(const char *path)
{
	struct sockaddr_un addr;
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);

	if (fd < 0)
		return -1;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1u);
	if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static fzn_socket_err_t wait_accept(int listen_fd, int *out_fd, fzn_peer_t *peer)
{
	struct pollfd pfd = { listen_fd, POLLIN, 0 };

	if (poll(&pfd, 1, 2000) != 1)
		return FZN_SOCKET_ERR_AGAIN;
	return fzn_socket_accept(listen_fd, out_fd, peer);
}

static const uint8_t STATUS[] = "status";
static const uint8_t DESTROY[] = "destroy";

int main(void)
{
	char dir[] = "/tmp/fzn_admit_test_XXXXXX";
	char path[256];
	int listen_fd = -1, client = -1, served = -1;
	fzn_peer_t peer;
	fzn_line_t reader;
	uint8_t line_buf[64];
	const uint8_t *line;
	size_t line_len;
	gid_t mine[64];
	int n;
	uint32_t held_gid;

	if (!mkdtemp(dir)) {
		printf("  FAIL: could not make a temporary directory\n");
		return 1;
	}
	snprintf(path, sizeof(path), "%s/sock", dir);

	check(fzn_socket_listen(path, 0660u, 4, &listen_fd) == FZN_SOCKET_OK, "listen refused");
	check(fcntl(listen_fd, F_SETFL, O_NONBLOCK) == 0, "could not set non-blocking");

	/* STEP 1: accept, which cannot be done without credentials. */
	client = dial(path);
	check(client >= 0, "could not connect");
	check(wait_accept(listen_fd, &served, &peer) == FZN_SOCKET_OK, "accept failed");
	check(peer.pid == (int64_t)getpid(), "the credentials are not this process's");
	check(peer.groups_known == 1, "groups were not established over a real socket");

	/* A group this process genuinely holds, from the kernel rather than
	 * from the parser, so the table below gates on something real. */
	n = getgroups((int)(sizeof(mine) / sizeof(mine[0])), mine);
	check(n >= 0, "getgroups failed");
	held_gid = (n > 0) ? (uint32_t)mine[0] : peer.primary_gid;

	{
		const fzn_verb_rule_t rules[] = {
			{ held_gid, STATUS, sizeof(STATUS) - 1u },
			{ 0x7ffffffeu, DESTROY, sizeof(DESTROY) - 1u },
		};

		/* STEP 2: the group, before a byte of the peer's input is read.
		 * Asserted here as an ordering statement: the verdict is
		 * available from the accept alone. */
		check(fzn_peer_group_verdict(&peer, held_gid) == FZN_PEER_MEMBER,
		      "a group the kernel reports was not a member");

		/* STEP 3: framing, bounded. */
		check(fzn_line_init(&reader, line_buf, sizeof(line_buf)) == FZN_LINE_OK,
		      "line init refused");
		check(write(client, "status\n", 7) == 7, "writing a request failed");
		{
			uint8_t got[64];
			ssize_t r = read(served, got, sizeof(got));

			check(r > 0, "reading the request failed");
			check(fzn_line_push(&reader, got, (size_t)r) == FZN_LINE_OK,
			      "the request was refused by the framing bound");
		}
		check(fzn_line_next(&reader, &line, &line_len) == 1, "no complete line");

		/* STEP 4: the verb, against the peer that sent it. */
		check(fzn_vocabulary_admit(&peer, line, line_len, rules, 2) == FZN_PEER_MEMBER,
		      "a verb this peer's group may ask for was refused end to end");

		/* A verb reserved to a group nobody holds. Same peer, same
		 * connection, different verb -- which is raidcfgd's whole
		 * point: the connection being admitted is not the question. */
		check(fzn_vocabulary_admit(&peer, DESTROY, sizeof(DESTROY) - 1u, rules, 2) ==
		              FZN_PEER_NOT_MEMBER,
		      "a verb reserved to another group was admitted on an admitted "
		      "connection");

		/* THE SEAM. A peer whose supplementary list could not be read
		 * is what accept produces when /proc is unreadable, and the
		 * vocabulary must answer UNKNOWN rather than definitely. The
		 * state is set by hand because /proc cannot be made to fail
		 * from here -- the same reason peer_linux.c's I/O branches are
		 * unexercised -- but the seam is the point, not the cause. */
		{
			fzn_peer_t blind = peer;

			blind.groups_known = 0;
			blind.group_count = 0;
			blind.primary_gid = 0x7ffffffdu; /* not a gid any rule names */
			check(fzn_vocabulary_admit(&blind, line, line_len, rules, 2) ==
			              FZN_PEER_UNKNOWN,
			      "a peer whose groups accept could not read got a definite "
			      "answer about a verb some group may ask for");
			check(fzn_vocabulary_admit(&blind, line, line_len, rules, 2) !=
			              FZN_PEER_MEMBER,
			      "an unreadable group list admitted a verb, turning a failed "
			      "/proc read into an allow");
		}

		/* AN OVER-LONG REQUEST YIELDS NO VERB AT ALL, so nothing
		 * downstream is asked to judge one. The connection is finished
		 * whatever the peer's groups say. */
		{
			fzn_line_t small_reader;
			uint8_t small_buf[8];

			check(fzn_line_init(&small_reader, small_buf, sizeof(small_buf)) ==
			              FZN_LINE_OK,
			      "init refused");
			check(fzn_line_push(&small_reader, (const uint8_t *)"aaaaaaaaaaaa\n",
			                    13) == FZN_LINE_ERR_OVERLONG,
			      "an over-long request was accepted");
			check(fzn_line_next(&small_reader, &line, &line_len) == 0,
			      "an over-long request still produced a verb to judge");
		}
	}

	close(client);
	close(served);
	fzn_socket_close(listen_fd, path);
	(void)rmdir(dir);

	printf("admit_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
