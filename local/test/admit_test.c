/* Credentials and the vocabulary bound, across the seam between them.
 *
 * Each module tests its own half and neither crosses to the other.
 * `fzn_peer_from_fd` fills an `fzn_peer_t` from a real socket;
 * `fzn_vocabulary_admit` reads that struct. A struct written by one and
 * misread by the other would pass both suites and fail only in a daemon.
 *
 * A SOCKETPAIR RATHER THAN A LISTENER, since `local/socket.c` moved to
 * raidcfgd on 2026-08-18 -- see sec 2, where the reason is that a listener
 * chooses a transport and this library does not define the local hop. Both
 * ends of a socketpair are in this process, so `SO_PEERCRED` reports our own
 * credentials and nothing needs forking; `local/test/peer_linux_test.c`
 * makes the same observation at more length.
 *
 * THE ASSERTION THAT EARNS THE FILE is the fail-closed path across that seam.
 * A peer whose supplementary list could not be read is what `fzn_peer_from_fd`
 * produces when /proc is unreadable, and the vocabulary must answer UNKNOWN --
 * not a definite no, and certainly not an allow.
 */

#if defined(__linux__)
#define _GNU_SOURCE
#endif

#include "../peer.h"
#include "../vocabulary.h"

#include <grp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int failures;
static int checks;

static void check(int ok, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		fprintf(stderr, "  FAIL: %s\n", what);
	}
}

static const uint8_t STATUS[] = "status";
static const uint8_t DESTROY[] = "destroy";

int main(void)
{
	int sv[2];
	fzn_peer_t peer;
	gid_t mine[64];
	int n;
	uint32_t held_gid;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		fprintf(stderr, "  FAIL: socketpair\n");
		return 1;
	}

	memset(&peer, 0, sizeof(peer));
	check(fzn_peer_from_fd(sv[0], &peer) == 0, "reading the peer of a socketpair failed");
	check(peer.pid == (int64_t)getpid(), "the credentials are not this process's");
	check(peer.groups_known == 1, "groups were not established from a readable /proc");

	/* A group this process genuinely holds, from the kernel rather than
	 * from the parser, so the table gates on something real. */
	n = getgroups((int)(sizeof(mine) / sizeof(mine[0])), mine);
	check(n >= 0, "getgroups failed");
	held_gid = (n > 0) ? (uint32_t)mine[0] : peer.primary_gid;

	{
		const fzn_verb_rule_t rules[] = {
			{ held_gid, STATUS, sizeof(STATUS) - 1u },
			{ 0x7ffffffeu, DESTROY, sizeof(DESTROY) - 1u },
		};

		check(fzn_peer_group_verdict(&peer, held_gid) == FZN_PEER_MEMBER,
		      "a group the kernel reports was not a member");
		check(fzn_vocabulary_admit(&peer, STATUS, sizeof(STATUS) - 1u, rules, 2) ==
		              FZN_PEER_MEMBER,
		      "a verb this peer's group may ask for was refused across the seam");

		/* Same peer, same connection, different verb -- which is
		 * raidcfgd's whole point: the connection being admitted is not
		 * the question. */
		check(fzn_vocabulary_admit(&peer, DESTROY, sizeof(DESTROY) - 1u, rules, 2) ==
		              FZN_PEER_NOT_MEMBER,
		      "a verb reserved to another group was admitted for an identified peer");

		/* THE SEAM. The state is set by hand because /proc cannot be
		 * made to fail from here -- the same reason peer_linux.c's I/O
		 * branches are unexercised -- but the seam is the point rather
		 * than the cause. */
		{
			fzn_peer_t blind = peer;

			blind.groups_known = 0;
			blind.group_count = 0;
			blind.primary_gid = 0x7ffffffdu; /* no rule names it */
			check(fzn_vocabulary_admit(&blind, STATUS, sizeof(STATUS) - 1u, rules,
			                           2) == FZN_PEER_UNKNOWN,
			      "a peer whose groups could not be read got a definite answer "
			      "about a verb some group may ask for");
			check(fzn_vocabulary_admit(&blind, STATUS, sizeof(STATUS) - 1u, rules,
			                           2) != FZN_PEER_MEMBER,
			      "an unreadable group list admitted a verb, turning a failed "
			      "/proc read into an allow");
		}
	}

	close(sv[0]);
	close(sv[1]);

	printf("admit_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
