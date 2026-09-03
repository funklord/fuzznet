/* The system half of peer.h: SO_PEERCRED and /proc/<pid>/status.
 *
 * A file of its own so that peer.c -- which holds every decision -- links
 * with no platform dependency at all and its tests need no socket, no
 * process and no /proc. Everything here is plumbing: it reads, it fills,
 * and it decides nothing.
 *
 * Linux only, and not pretended otherwise. SO_PEERCRED's struct and
 * /proc/<pid>/status are both Linux's; project.md sec 2 has this module
 * optional and last, so a port is a later problem and a stub that returned
 * plausible values would be worse than an absence.
 */

#if defined(__linux__)
/* `struct ucred` and `SO_PEERCRED` are guarded behind _GNU_SOURCE, and
 * -std=c11 asks glibc for strict ISO, which hides them. Defined here rather
 * than in the Makefile so that the one file needing an extension is the one
 * declaring it, and the rest of the library keeps compiling as plain C11.
 * It must precede every include, which is why it is above peer.h. */
#define _GNU_SOURCE
#endif

#include "peer.h"

#if defined(__linux__)

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int fzn_peer_from_fd(int fd, fzn_peer_t *peer)
{
	struct ucred cred;
	socklen_t len = sizeof(cred);
	char path[64];
	char status[8192];
	FILE *f;
	size_t got;

	if (!peer || fd < 0)
		return -1;

	memset(peer, 0, sizeof(*peer));

	/* The credentials are the part that must succeed. Without them we do
	 * not know who this is at all, which is a different thing from not
	 * knowing their groups. */
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0)
		return -1;
	if (len != sizeof(cred))
		return -1;
	/* AND THE KERNEL MUST ACTUALLY HAVE ANSWERED, which the return value
	 * does not tell us.
	 *
	 * On a datagram socket with no peer -- an `AF_UNIX` `SOCK_DGRAM`
	 * receiver, which is what a consumer reading commands off a socket is
	 * likeliest to hold -- `getsockopt` RETURNS 0 and reports `pid = 0`
	 * with `uid` and `gid` both `(uid_t)-1`. Measured, not inferred.
	 *
	 * Checking only the status and the length therefore reported SUCCESS
	 * having learned nothing, and filled `uid` with 4294967295. It failed
	 * closed only by luck: `/proc/0/status` cannot be opened, so
	 * `groups_known` stayed clear and any group gate answered UNKNOWN.
	 * A consumer gating on `uid` got a definite wrong answer, which is
	 * exactly the state `peer.h` distinguishes UNKNOWN from.
	 *
	 * pid 0 is not a process a peer can be, and `(uid_t)-1` is the value
	 * the kernel uses for "nobody", so both are unambiguous. */
	if (cred.pid == 0 || cred.uid == (uid_t)-1)
		return -1;

	peer->pid = (int64_t)cred.pid;
	peer->uid = (uint32_t)cred.uid;
	peer->primary_gid = (uint32_t)cred.gid;

	/* From here on, failure is not an error: peer.h promises that "we
	 * know who they are and not what groups they hold" is a state a
	 * caller can act on, and every path below leaves groups_known clear
	 * rather than returning. */
	if (snprintf(path, sizeof(path), "/proc/%lld/status", (long long)peer->pid) < 0)
		return 0;

	f = fopen(path, "re");
	if (!f)
		return 0;

	got = fread(status, 1, sizeof(status), f);
	/* A short read is not distinguished from a whole one on purpose: the
	 * parser is handed what was read and answers "could not tell" if the
	 * Groups: line was not in it, which is the correct answer for a
	 * truncated read and needs no separate path to get wrong. */
	if (ferror(f))
		got = 0;
	/* A READ THAT FILLED THE BUFFER MAY HAVE STOPPED MID-LINE, and the
	 * paragraph above is only true once that line is dropped.
	 *
	 * `fzn_peer_groups_parse` requires whole lines -- peer.h says so -- and
	 * cannot check it, because `len` alone does not say whether it means
	 * "the whole file" or "as much as fitted". THIS is the caller that
	 * knows, so this is where it is answered.
	 *
	 * A SHORT READ IS NOT A FAILED READ and `ferror` sees nothing here. A
	 * status file longer than this buffer comes back full and clean. The
	 * Groups: line is early in the file but it is also the LONGEST line in
	 * it -- a process in a few hundred supplementary groups runs it into
	 * the kilobytes -- so the many-groups case is exactly the one where
	 * the cut lands inside it. Handed on uncut, every gid before the cut
	 * parses, `groups_known` comes back 1, and the number AT the cut may
	 * be half a number: 250 read as 25, which is not a missing entry but a
	 * wrong one no caller can tell from a real 25. A definite
	 * FZN_PEER_NOT_MEMBER for a real member, which is what peer.h's
	 * tri-state exists to prevent.
	 *
	 * Trimming to the last newline rather than discarding the read, so a
	 * large status file whose Groups: line arrived whole is still
	 * answered. If nothing survives, `got` is 0 and the parser says
	 * "could not tell", which is the honest answer and the one this
	 * function already gives for a file it could not open. */
	else if (got == sizeof(status)) {
		while (got > 0 && status[got - 1] != '\n')
			got--;
	}
	fclose(f);

	(void)fzn_peer_groups_parse(status, got, peer);

	return 0;
}

#else

int fzn_peer_from_fd(int fd, fzn_peer_t *peer)
{
	(void)fd;
	/* Not implemented rather than faked. A stub that filled plausible
	 * credentials would be a gate that admits whoever it was told to. */
	if (peer)
		memset(peer, 0, sizeof(*peer));
	return -1;
}

#endif
