/* The AF_UNIX listener -- the last piece of sec 10 step 7.
 *
 * WHAT THIS DOES NOT DO, and the omission is the design. It does not own an
 * accept loop, a thread, a poll set or a timeout. netcfgd, raidcfgd and
 * fuzzypickles each have an event loop already -- two of them Qt's -- and a
 * library that brought its own would be choosing their IO model for them,
 * which is precisely the "absorbing one consumer's application" that sec 5
 * exists to refuse. A caller polls the listening descriptor however it
 * already polls anything, and calls accept when it is readable.
 *
 * TWO THINGS IT DOES OWN, because both are easy to get wrong and expensive to
 * get wrong quietly:
 *
 *   - **The mode on the path.** An AF_UNIX socket is gated by filesystem
 *     permissions, and `bind` applies the process umask -- so a daemon that
 *     binds and then chmods has a window in which the socket is reachable by
 *     whoever the umask allowed. This binds to an unpredictable temporary
 *     name in the same directory, sets the mode there, and renames it over
 *     the target. The rename is atomic, so the path a client connects to
 *     never exists with the wrong mode.
 *
 *   - **Credentials, inseparably from the connection.** `fzn_socket_accept`
 *     hands back a descriptor and its peer's credentials together, and there
 *     is no call here that returns one without the other. raidcfgd's
 *     requirement starts with a gid check on the connection; a caller cannot
 *     forget a step it was never offered separately.
 *
 * A LIVENESS PROBE IS A CONNECTION, and a running daemon sees it. There is no
 * way to tell a live socket from a stale one without connecting, so every
 * failed `fzn_socket_listen` against a running instance leaves one connection
 * in that instance's backlog which closes immediately. A caller's accept loop
 * must tolerate a peer that opens and closes without sending anything --
 * which it must anyway, since any client can do that -- but it is worth
 * knowing that starting a second instance is what produces one. Found by a
 * test accepting the probe's connection instead of its own.
 *
 * A STALE SOCKET IS NOT UNLINKED BLINDLY. A path left behind by a crash and a
 * path held by a running instance look identical on disk, so this connects to
 * it first: a refused connection means nobody is listening and the entry may
 * be replaced, and a successful one means another instance owns it and this
 * call fails. Unlinking without asking is how a second daemon silently takes
 * a socket from the first, and the failure is invisible until something
 * reconnects.
 *
 * Linux only, like local/peer_linux.c, and refusing rather than pretending
 * elsewhere.
 */

#ifndef FZN_SOCKET_H
#define FZN_SOCKET_H

#include "peer.h"

typedef enum fzn_socket_err {
	FZN_SOCKET_OK = 0,
	FZN_SOCKET_ERR_MALFORMED = -1,
	/* The path is longer than sun_path, or not absolute. Refused rather
	 * than truncated: a truncated path is a different socket, and one an
	 * attacker may be able to create. */
	FZN_SOCKET_ERR_PATH = -2,
	/* Something in the system call sequence failed; errno is the
	 * caller's to read, and is left as the failing call set it. */
	FZN_SOCKET_ERR_SYSTEM = -3,
	/* Another instance is listening on that path. */
	FZN_SOCKET_ERR_IN_USE = -4,
	/* Not built for this platform. */
	FZN_SOCKET_ERR_UNSUPPORTED = -5,
	/* No connection was waiting. Only from a non-blocking descriptor, and
	 * distinct from an error so a polled caller can tell a spurious wakeup
	 * from a broken socket. */
	FZN_SOCKET_ERR_AGAIN = -6,
} fzn_socket_err_t;

/* Create, bind and listen. `mode` is the permission bits the socket path ends
 * up with -- the caller's, because only it knows which group it is admitting,
 * and 0660 with a group-owned directory is the shape raidcfgd describes.
 *
 * `backlog` is passed to listen(2) unchanged.
 *
 * The descriptor is blocking and has no close-on-exec disposition beyond
 * SOCK_CLOEXEC, which is set: a listener leaking into a child is a listener
 * somebody else can accept on. */
fzn_socket_err_t fzn_socket_listen(const char *path, unsigned int mode, int backlog,
                                    int *out_fd);

/* Accept one connection and read its peer's credentials.
 *
 * On success `*out_fd` is a connected descriptor and `*out_peer` describes who
 * opened it -- including the supplementary groups, with `groups_known` clear
 * if they could not be read, which denies. See peer.h.
 *
 * A connection whose credentials cannot be read at all is CLOSED and refused
 * rather than returned: there is nothing a caller could safely do with a
 * descriptor whose peer is unknown, and handing one back would invite it to
 * try. */
fzn_socket_err_t fzn_socket_accept(int listen_fd, int *out_fd, fzn_peer_t *out_peer);

/* Close a listener and remove its path. Safe to call with a negative fd, so a
 * caller's cleanup path does not need to know how far setup got. */
void fzn_socket_close(int fd, const char *path);

#endif /* FZN_SOCKET_H */
