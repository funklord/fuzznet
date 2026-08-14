/* Who is on the other end of a local socket, and whether we could tell.
 *
 * project.md sec 2 is the requirement and it is stated there because it was
 * got wrong first: a root daemon serving a group needs the peer's
 * SUPPLEMENTARY groups, and `SO_PEERCRED` does not carry them.
 *
 * `SO_PEERCRED` reports pid, uid and the PRIMARY gid. A user's primary
 * group is normally their own, so a gate comparing a `disk`- or `raid`-style
 * group against it denies nearly everybody it was written to admit while
 * reading as correctly configured. Measured on the machine this family is
 * developed on: primary gid 1000 is the owner's own group, and `netdev`,
 * `cdrom` and `sudo` are supplementary only. netcfgd hit this first and
 * carries the warning in its own `peer.rs`.
 *
 * THE TRI-STATE IS THE WHOLE POINT. sec 2: an empty group list means
 * "could not tell", not "none". The two are safe to conflate only because
 * both deny, and flattening a failed read into an empty list in the
 * PERMISSIVE direction turns a read that failed into an allow -- on a
 * socket whose group is root for that group, which is the hazard raidcfgd
 * raised arriving through the back door. So membership is three-valued and
 * a caller cannot accidentally treat "unknown" as "no": the enum has no
 * boolean reading.
 *
 * THE POLICY IS PURE AND THE I/O IS THIN, which is the division every
 * module here uses -- chain.h takes a signed region it did not read,
 * freshness.h takes a clock it did not call. Everything that decides
 * anything operates on a `fzn_peer_t` the caller filled, and can be tested
 * exhaustively without a socket, a process, or /proc. `fzn_peer_from_fd` is
 * the only function here that touches the system, and it does no deciding.
 */

#ifndef FZN_PEER_H
#define FZN_PEER_H

#include <stddef.h>
#include <stdint.h>

/* How many supplementary groups a peer may have before this gives up.
 *
 * A process can hold far more than this -- Linux allows thousands -- so the
 * bound will be reached by something eventually. What matters is what
 * happens then, and it is NOT truncation: a truncated list that reports
 * "not a member" is a wrong DEFINITE answer, and definite wrong answers are
 * exactly what the tri-state exists to prevent. Overflow marks the list
 * unknown instead, which denies while staying honest about why. */
#define FZN_PEER_MAX_GROUPS 64

typedef struct fzn_peer {
	int64_t pid;
	uint32_t uid;
	/* From SO_PEERCRED. Kept because it is real information, and named
	 * `primary_gid` rather than `gid` so that nobody gates on it by
	 * reaching for the obvious field name. */
	uint32_t primary_gid;
	uint32_t groups[FZN_PEER_MAX_GROUPS];
	size_t group_count;
	/* Zero when the supplementary list could not be established -- the
	 * read failed, the format was not understood, or there were more
	 * groups than FZN_PEER_MAX_GROUPS. `group_count` is then meaningless
	 * and must not be read. */
	int groups_known;
} fzn_peer_t;

/* Three values, and deliberately not a bool or an errno.
 *
 * The numbering is chosen so that a caller who writes
 * `if (fzn_peer_in_group(...))` -- the mistake this type exists to make
 * hard -- gets a TRUE for UNKNOWN as well as for MEMBER and will see it in
 * their first test rather than in production. There is no assignment of
 * values to these three that makes the careless reading safe; making it
 * loudly wrong is the next best thing. */
typedef enum fzn_peer_verdict {
	FZN_PEER_NOT_MEMBER = 0,
	FZN_PEER_MEMBER = 1,
	FZN_PEER_UNKNOWN = 2,
} fzn_peer_verdict_t;

/* Parse the supplementary groups out of the text of `/proc/<pid>/status`.
 *
 * Pure, and separate from reading the file, because this is where every
 * decision about a malformed or surprising line gets made and it should be
 * testable without a process to point at. `text` need not be
 * null-terminated; `len` bounds it.
 *
 * Fills `groups`, `group_count` and `groups_known`, leaving the rest of
 * `peer` alone. On anything it does not understand it sets `groups_known`
 * to 0 and returns 0 -- there is no partial success, because a partial
 * group list is the wrong definite answer described above.
 *
 * A `Groups:` line with no entries is a REAL empty membership and sets
 * `groups_known` to 1 with a count of 0. A missing `Groups:` line is not:
 * that is "could not tell". Those two look identical in a naive parser and
 * are the reason this function exists rather than a sscanf at the call
 * site. */
int fzn_peer_groups_parse(const char *text, size_t len, fzn_peer_t *peer);

/* What do we know about this peer's membership of `gid`? Checks the
 * supplementary list AND the primary gid, because a group can legitimately
 * be somebody's primary one and refusing that would be the mirror of the
 * bug this module is about.
 *
 * Returns FZN_PEER_UNKNOWN when the supplementary list is not known and the
 * primary gid does not match -- because the answer genuinely is not known,
 * not because it is no.
 *
 * NAMED `verdict` RATHER THAN `in_group`, WHICH IS WHAT IT WAS. The
 * numbering above makes the careless `if (...)` loudly wrong, but raidcfgd
 * pointed out that this is an argument against relying on the numbering:
 * if no ordering makes the boolean reading safe, the ordering is not the
 * lever. **The name was.** `in_group` reads as a predicate while returning
 * a verdict, so `if (fzn_peer_in_group(...))` was not carelessness -- it
 * was the name being taken at its word. `verdict` does not read that way,
 * so the mistake looks wrong at the call site rather than only in a test. */
fzn_peer_verdict_t fzn_peer_group_verdict(const fzn_peer_t *peer, uint32_t gid);

/* The honestly boolean one, for the caller who was going to write `if`
 * anyway: 1 for MEMBER, 0 for NOT_MEMBER and 0 for UNKNOWN.
 *
 * It exists because the shortcut will be taken, and the useful response is
 * to put the SAFE default behind the name that invites it rather than to
 * forbid it. Deny-on-unknown is not always the right policy -- a caller who
 * must tell "could not tell" from "not a member", to log it or to retry,
 * is by definition thinking about it and will reach for the verdict.
 *
 * raidcfgd's suggestion, and a better answer than the numbering trick it
 * replaces: this one cannot be misread, because there is nothing to
 * misread. */
int fzn_peer_is_member(const fzn_peer_t *peer, uint32_t gid);

/* Fill a peer from a connected `AF_UNIX` socket: `SO_PEERCRED` for pid, uid
 * and primary gid, then `/proc/<pid>/status` for the supplementary list.
 *
 * The only function here that touches the system, and it decides nothing.
 * Returns 0 on success. A failure to read the supplementary list is NOT a
 * failure of this call -- it succeeds with `groups_known` clear, because
 * "we know who they are and not what groups they hold" is a real state a
 * caller must be able to act on. Only a failure to get the credentials at
 * all is an error.
 *
 * Declared here and compiled only on Linux, since `SO_PEERCRED` and
 * `/proc/<pid>/status` are both Linux's. sec 2 has this module optional and
 * last; a port is somebody's later problem and is not pretended at here. */
int fzn_peer_from_fd(int fd, fzn_peer_t *peer);

#endif /* FZN_PEER_H */
