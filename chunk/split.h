/* Splitting a message into datagrams -- the sending half of sec 4.4.
 *
 * The mirror of chunk/reassembly.h, and it exists because the receiver's
 * rules are only half a contract. A reassembler that requires a uniform
 * stride is no use unless something produces one, and the two agreeing is a
 * property worth testing rather than asserting: split_test round-trips a
 * payload through both, in order and out of order, and compares bytes.
 *
 * PURE ARITHMETIC. Nothing here holds a buffer, copies a payload, or knows
 * what a datagram looks like -- it answers "how many pieces, and which
 * bytes are piece N" and leaves the caller to cut them. That keeps it
 * independent of wire/frame.situ, which is what makes it buildable while
 * sec 10 step 2 is blocked, and it means a sender can plan a message before
 * deciding whether it will send one at all.
 *
 * NOT a transmission schedule. Nothing here decides when to send, what to
 * resend, or how fast -- sec 10 names a hand-written retransmission state
 * machine as the thing to refuse, and situ generates one at rung 6.
 */

#ifndef FZN_SPLIT_H
#define FZN_SPLIT_H

#include <stddef.h>
#include <stdint.h>

#include "reassembly.h" /* FZN_REASM_MAX_CHUNKS, and the stride rule */

typedef enum fzn_split_err {
	FZN_SPLIT_OK = 0,
	FZN_SPLIT_ERR_MALFORMED = -1,
	/* The message would need more pieces than a receiver will track.
	 * Refused here rather than discovered at the far end, because the
	 * sender is the one who can do something about it -- send less, or
	 * raise the per-datagram payload. */
	FZN_SPLIT_ERR_TOO_LARGE = -2,
} fzn_split_err_t;

/* How a message is cut. Every piece but the last is exactly `chunk_size`;
 * the last is `total - chunk_size * (chunks - 1)` and may be shorter.
 *
 * The uniform stride is not tidiness, it is what makes out-of-order
 * arrival addressable: without it a receiver cannot place piece 7 until it
 * has seen 0 through 6, which defeats the point of carrying an index. */
typedef struct fzn_split {
	size_t total;
	size_t chunk_size;
	uint16_t chunks;
	/* What a receiver must have room for, which is the stride times the
	 * count rather than `total`. Exposed because it is the number a
	 * sender would otherwise get wrong: the last piece being short does
	 * not shrink the buffer the pieces before it are placed in. */
	size_t buffer_needed;
} fzn_split_t;

/* Plan the cut. `max_payload` is what one datagram can carry -- the
 * caller's, since it depends on the MTU and on the frame overhead
 * (wire/frame.situ's 96 bytes today, which sec 13 is still arguing about).
 *
 * A zero-length message is refused: reassembly rejects an empty piece, so
 * producing one here would build something the other half will not take. */
fzn_split_err_t fzn_split_plan(size_t total, size_t max_payload, fzn_split_t *out);

/* Where piece `index` starts and how long it is. */
fzn_split_err_t fzn_split_at(const fzn_split_t *plan, uint16_t index, size_t *offset,
                              size_t *len);

#endif /* FZN_SPLIT_H */
