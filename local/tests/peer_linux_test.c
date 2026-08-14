/* A test for the system half, which project.md sec 14 recorded as
 * untestable and is not.
 *
 * That entry said `peer_linux.c` needs "a socket and a cooperating
 * process". The socket is right and the cooperating process is wrong: an
 * `AF_UNIX` socketpair has both ends in THIS process, so `SO_PEERCRED` on
 * one of them reports our own credentials and `/proc/<pid>/status` is our
 * own. Nothing needs to be forked, waited for, or cleaned up.
 *
 * WHAT MAKES IT WORTH HAVING is that the answer can be checked against a
 * source that is not this library. `getgroups()` and `getuid()` are the
 * kernel's answer to the same question `fzn_peer_from_fd` gets by parsing
 * text out of /proc, so the two agreeing is real corroboration rather than
 * the file agreeing with itself. A parser that dropped every other entry
 * would satisfy a self-consistency test and fails this one.
 *
 * The claim being checked is `peer.h`'s: that this file holds no decisions.
 * An assertion about a file nothing exercises is worth exactly nothing, and
 * that is what sec 14 said about this one until now.
 */

#include "../peer.h"

#include <grp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
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

static int holds(const fzn_peer_t *p, uint32_t gid)
{
	for (size_t i = 0; i < p->group_count; i++) {
		if (p->groups[i] == gid)
			return 1;
	}
	return 0;
}

int main(void)
{
	int sv[2];
	fzn_peer_t p;
	gid_t mine[256];
	int n;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
		printf("  FAIL: socketpair\n");
		return 1;
	}

	memset(&p, 0, sizeof(p));
	check(fzn_peer_from_fd(sv[0], &p) == 0, "reading the peer of a socketpair failed");

	/* Against the kernel rather than against ourselves. */
	check(p.pid == (int64_t)getpid(), "pid is not this process");
	check(p.uid == (uint32_t)getuid(), "uid is not this user");
	/* THIS CHECK CANNOT DISCRIMINATE ON THIS MACHINE, and saying so is
	 * more useful than the check is.
	 *
	 * A Debian-style user has uid == gid == 1000, their own group, which
	 * is the same fact that makes `SO_PEERCRED`'s primary gid useless for
	 * gating and is why this module exists. It also means filling
	 * `primary_gid` from `cred.uid` instead of `cred.gid` produces
	 * identical output here: a deliberate sabotage of exactly that was
	 * NOT caught, and no test written here could catch it.
	 *
	 * The check stays because it discriminates wherever the two differ --
	 * a system account, a shared-group setup, a container. But it must
	 * not be counted as evidence on a machine where they are equal, and a
	 * sabotage run that reports "all caught" without this note would be
	 * claiming coverage it does not have. */
	check(p.primary_gid == (uint32_t)getgid(), "primary gid is not this process's");
	if (getuid() == (uid_t)getgid())
		printf("  note: uid == gid here, so the primary-gid check above is "
		       "non-discriminating on this machine\n");

	check(p.groups_known == 1,
	      "supplementary groups were not established from a readable /proc");

	n = getgroups((int)(sizeof(mine) / sizeof(mine[0])), mine);
	check(n >= 0, "getgroups failed");

	if (n >= 0 && p.groups_known) {
		int agreed = 1;

		/* Every group the kernel reports must be one the parser found.
		 * The reverse is not asserted: /proc's Groups: line and
		 * getgroups() need not be ordered alike, and the parser also
		 * has no reason to invent one, so containment in this
		 * direction is the property with teeth. */
		for (int i = 0; i < n; i++) {
			if (!holds(&p, (uint32_t)mine[i])) {
				printf("  FAIL: getgroups reports %u and the parser did not\n",
				       (unsigned)mine[i]);
				agreed = 0;
				failures++;
			}
			checks++;
		}
		check(agreed, "the parsed list and getgroups disagree");

		/* And a count that matches, so a parser that found every real
		 * group plus some invented ones is caught too. */
		check(p.group_count == (size_t)n,
		      "the parsed count and getgroups' count differ");
	}

	/* The verdict functions, against the same independent source. */
	if (n > 0) {
		check(fzn_peer_group_verdict(&p, (uint32_t)mine[0]) == FZN_PEER_MEMBER,
		      "a group getgroups reports was not a member");
		check(fzn_peer_is_member(&p, (uint32_t)mine[0]) == 1,
		      "is_member disagreed about a real group");
	}

	/* A gid nobody could hold. Chosen high rather than low because a low
	 * one might be a real group on somebody's machine, and a test that
	 * depends on which groups exist is a test that fails on a stranger's
	 * laptop for no reason. */
	check(fzn_peer_group_verdict(&p, 0x7ffffffeu) == FZN_PEER_NOT_MEMBER,
	      "membership of an impossible gid was reported");

	/* Errors: peer.h says only a failure to get credentials at all is one. */
	check(fzn_peer_from_fd(-1, &p) != 0, "a negative fd was accepted");
	check(fzn_peer_from_fd(sv[0], NULL) != 0, "a null peer was accepted");
	{
		int devnull = -1;
		/* A file descriptor that is not a socket: getsockopt must
		 * refuse, and this must be an error rather than a peer with
		 * zeroes in it. */
		devnull = dup(STDERR_FILENO);
		if (devnull >= 0) {
			check(fzn_peer_from_fd(devnull, &p) != 0,
			      "a non-socket fd produced a peer");
			close(devnull);
		}
	}

	close(sv[0]);
	close(sv[1]);

	printf("peer_linux_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
