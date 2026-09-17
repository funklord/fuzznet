/* The remote hop's datagram transport: one fuzznet frame per UDP datagram.
 *
 * This is FZN_ORIGIN_REMOTE's carrier -- the socket sec 1 has always named
 * ("over UDP"), and sec 298 puts in this library rather than in each
 * consumer. It is deliberately thin. Everything that makes a frame
 * trustworthy sits above it and is already built: the seal (wire/seal.h)
 * authenticates and decrypts, the chunker (chunk/split.h, chunk/reassembly.h)
 * fits a large message into frame-sized pieces and puts them back, freshness
 * and the replay window (frame/freshness.h) reject the stale and the
 * repeated, and the capability chain (chain/authz.h) decides what a sender
 * may ask for. This module moves bytes and nothing else.
 *
 * WHAT IT DOES NOT DO, and the omissions are the design, the same way
 * local/socket.h states its own:
 *
 *   - No recv loop, no thread, no poll set. A node polls the descriptor
 *     however it already polls anything and calls fzn_udp_recv when it is
 *     readable -- exactly as a caller drives local/socket.h's listener.
 *     sec 298 puts owning a loop in scope for a shared daemon that would
 *     otherwise make consumers write one each; a transport primitive is not
 *     that case.
 *
 *   - No name resolution and no discovery. fzn_udp_resolve takes a NUMERIC
 *     address through inet_pton, never a hostname through DNS. The remote hop
 *     is pointed at an address a person configured; a resolver would be both
 *     a network dependency and a discovery channel, and raidcfgd's brief asks
 *     for neither.
 *
 *   - No dual-stack magic. A socket is one address family. A node wanting
 *     both v4 and v6 opens one of each and polls both -- the composition
 *     local/socket.h leaves to its caller -- and an AF_INET6 socket here sets
 *     IPV6_V6ONLY so the two do not overlap through v4-mapped addresses.
 *
 * ONE FRAME PER DATAGRAM, and the size is not this module's to choose. A
 * sealed frame is at most SITU_FZN_FRAME_SIZE_MAX (1168) bytes, a bound
 * sec 10 step 2 set so a frame fits the IPv6 minimum-MTU UDP payload (1232)
 * with 64 bytes to spare -- so a frame never has to be IP-fragmented, and
 * fragmented UDP is widely dropped. fzn_udp_send REFUSES a frame larger than
 * FZN_UDP_DATAGRAM_MAX rather than letting IP fragment it, and fzn_udp_recv
 * REFUSES a datagram larger than the buffer rather than handing back a
 * truncated one, because a truncated frame is a different frame and one an
 * attacker can arrange.
 *
 * POSIX sockets, so it builds anywhere Berkeley sockets do -- unlike
 * local/socket.h, which is Linux-only for its credential call. Truncation
 * detection uses MSG_TRUNC's datagram semantics, which are Linux's; where
 * they are absent the caller's frame-sized buffer means no legitimate frame
 * truncates anyway.
 */

#ifndef FZN_UDP_H
#define FZN_UDP_H

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_udp_err {
	FZN_UDP_OK = 0,
	/* A null pointer, or a family that is neither AF_INET nor AF_INET6. */
	FZN_UDP_ERR_MALFORMED = -1,
	/* An address or host string inet_pton would not parse. A hostname
	 * lands here: this transport resolves nothing. */
	FZN_UDP_ERR_ADDR = -2,
	/* A frame larger than one datagram may carry without fragmenting. */
	FZN_UDP_ERR_OVERSIZED = -3,
	/* A received datagram larger than the buffer: a different frame. */
	FZN_UDP_ERR_TRUNCATED = -4,
	/* A system call failed; errno holds why. */
	FZN_UDP_ERR_SYSTEM = -5,
	/* Non-blocking, and nothing was ready. */
	FZN_UDP_ERR_AGAIN = -6,
	/* Built where this cannot run. */
	FZN_UDP_ERR_UNSUPPORTED = -7
} fzn_udp_err_t;

/* The transport's own name for the sealed-frame maximum. Equal to the
 * generated SITU_FZN_FRAME_SIZE_MAX, and net/test/udp_test.c pins the two
 * together with a static assertion so they cannot drift. */
#define FZN_UDP_DATAGRAM_MAX 1168u

/* A peer's address, opaque to the caller: room for a v4 or v6 sockaddr,
 * carried back by fzn_udp_recv so a node can reply to whoever sent. It is
 * exactly a sockaddr_storage; udp.c refuses to build if the platform's is
 * larger rather than truncate one silently. */
typedef struct fzn_udp_addr {
	unsigned char storage[128];
	unsigned int len;
} fzn_udp_addr_t;

/* Bind a datagram socket to (family, port). `addr` NULL binds every local
 * address of that family; otherwise it is a numeric address to bind. The
 * descriptor comes back in *out_fd; a node polls it and calls fzn_udp_recv. */
fzn_udp_err_t fzn_udp_bind(int family, const char *addr, uint16_t port,
                           int *out_fd);

/* Resolve a NUMERIC (host, port) to an address for fzn_udp_send. No DNS. */
fzn_udp_err_t fzn_udp_resolve(int family, const char *host, uint16_t port,
                              fzn_udp_addr_t *out);

/* Send one frame as one datagram to `to`. Refuses a zero-length frame and one
 * larger than FZN_UDP_DATAGRAM_MAX -- it does not fragment. */
fzn_udp_err_t fzn_udp_send(int fd, const fzn_udp_addr_t *to,
                           const uint8_t *frame, size_t len);

/* Receive one datagram into buf[cap], setting *len. If `from` is non-NULL it
 * receives the sender's address. A datagram larger than cap is refused as
 * FZN_UDP_ERR_TRUNCATED, not copied as a short frame. */
fzn_udp_err_t fzn_udp_recv(int fd, uint8_t *buf, size_t cap, size_t *len,
                           fzn_udp_addr_t *from);

void fzn_udp_close(int fd);

#endif
