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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
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
		fprintf(stderr, "  FAIL: socketpair\n");
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
				fprintf(stderr, "  FAIL: getgroups reports %u and the parser did not\n",
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

	/* A DATAGRAM SOCKET WITH NO PEER, which is the case that returned
	 * success having learned nothing.
	 *
	 * `getsockopt(SO_PEERCRED)` RETURNS 0 here and reports pid 0 with uid
	 * and gid both (uid_t)-1 -- so a check on the status and the length
	 * alone passes, and `peer->uid` comes back as 4294967295. It failed
	 * closed only because /proc/0/status cannot be opened, which left the
	 * groups unknown; a consumer gating on `uid` got a definite wrong
	 * answer instead.
	 *
	 * This is the shape a consumer reading commands off a socket is
	 * likeliest to hold, which is why it matters more than the
	 * not-a-socket case above. */
	{
		int dgram = socket(AF_UNIX, SOCK_DGRAM, 0);

		if (dgram >= 0) {
			struct fzn_peer q;

			memset(&q, 0xAA, sizeof(q));
			check(fzn_peer_from_fd(dgram, &q) != 0,
			      "an unconnected datagram socket reported a peer");
			close(dgram);
		}
	}
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

	/* THE PEER THAT NO LONGER EXISTS, which is the one path in this file
	 * that needs a second process after all.
	 *
	 * `SO_PEERCRED` is captured at connect time and does not change when
	 * the peer dies, so an accepted socket keeps naming a pid that has
	 * been reaped. `/proc/<pid>/status` then cannot be opened, and
	 * peer.h's promise is that this is NOT an error: the credentials are
	 * known and the groups are not, which is a state a caller acts on.
	 * Any other answer -- refusing, or reporting groups it never read --
	 * would collapse the tri-state this module exists for.
	 *
	 * A socketpair cannot reach it. Both ends live in this process, so
	 * the pid is our own and /proc always opens; the header above is
	 * right about that for every other case and wrong for this one.
	 *
	 * IT TERMINATES because the child does nothing but connect and
	 * _exit, `waitpid` is not WNOHANG so it returns once that has
	 * happened, and `alarm` bounds the whole block if a connect ever
	 * blocks. The socket path is unlinked on every exit from the block,
	 * including the ones that skip the checks. */
	{
		char path[108];
		struct sockaddr_un addr;
		int srv, conn;
		pid_t kid;
		int st;

		(void)snprintf(path, sizeof(path), "/tmp/fzn-peer-linux-%ld.sock",
		               (long)getpid());
		(void)unlink(path);

		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;
		(void)snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

		srv = socket(AF_UNIX, SOCK_STREAM, 0);
		if (srv >= 0 && bind(srv, (struct sockaddr *)&addr, sizeof(addr)) == 0
		    && listen(srv, 1) == 0) {
			alarm(30);
			kid = fork();
			if (kid == 0) {
				int c = socket(AF_UNIX, SOCK_STREAM, 0);

				if (c >= 0)
					(void)connect(c, (struct sockaddr *)&addr,
					              sizeof(addr));
				_exit(0);
			}
			if (kid > 0) {
				conn = accept(srv, NULL, NULL);
				(void)waitpid(kid, &st, 0);
				if (conn >= 0) {
					struct fzn_peer dead;

					memset(&dead, 0xBB, sizeof(dead));
					check(fzn_peer_from_fd(conn, &dead) == 0,
					      "a peer that has exited was reported as an "
					      "error rather than as known-without-groups");
					check(dead.pid == (int64_t)kid,
					      "the socket stopped naming the pid it was "
					      "connected by once that pid was reaped");
					check(dead.uid == (uint32_t)getuid(),
					      "the dead peer's uid was not the one that "
					      "connected");
					check(dead.groups_known == 0,
					      "groups were reported for a process whose "
					      "/proc entry could not be opened");
					check(dead.group_count == 0,
					      "a group was recorded from a /proc entry "
					      "that was never read");
					close(conn);
				}
			}
			alarm(0);
		}
		if (srv >= 0)
			close(srv);
		(void)unlink(path);
	}

	close(sv[0]);
	close(sv[1]);

	printf("peer_linux_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
