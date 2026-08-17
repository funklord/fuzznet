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

/* The largest payload a frame can carry, and the one number here that is
 * not this module's own.
 *
 * `wire/frame.situ` declares `u16 length [max = 1024]`, so a piece bigger
 * than this cannot be framed at all -- `situ_fzn_frame_validate` refuses it.
 * Planning a stride above it produces a plan whose every datagram is
 * unsendable, and nothing on the send path would have said so: this library
 * has no encoder yet, so `fzn_split_plan` is the only thing between a
 * caller's arithmetic and an invalid frame.
 *
 * IT IS REPEATED HERE RATHER THAN INCLUDED, deliberately. This module is
 * pure arithmetic and independent of the schema -- that is what makes it
 * buildable while sec 10 step 2 is blocked -- so it cannot see
 * `SITU_FZN_FRAME_SIZE_MAX`. The copy is tethered instead:
 * `chunk/tests/agreement_test.c` static-asserts this against the generated
 * header, which is the only place both numbers are visible.
 *
 * So the tether is `make test`, not `make`. Putting it in the default build
 * would mean a library source including a generated header, which would cost
 * the independence above for a constant that changes about once. Worth
 * knowing that the schema's number is a placeholder its own comment says
 * wants measuring: when it is measured, the assert is what refuses the
 * half-done change. */
#define FZN_SPLIT_MAX_PAYLOAD 1024u

typedef enum fzn_split_err {
	FZN_SPLIT_OK = 0,
	FZN_SPLIT_ERR_MALFORMED = -1,
	/* The message would need more pieces than a receiver will track.
	 * Refused here rather than discovered at the far end, because the
	 * sender is the one who can do something about it -- send less, or
	 * raise the per-datagram payload as far as FZN_SPLIT_MAX_PAYLOAD.
	 *
	 * That ceiling is why the two errors are distinct. Between them they
	 * bound a message at FZN_SPLIT_MAX_PAYLOAD * FZN_REASM_MAX_CHUNKS,
	 * and a caller that hits this one has already spent whatever raising
	 * the stride was going to buy. */
	FZN_SPLIT_ERR_TOO_LARGE = -2,
	/* `max_payload` exceeds what a frame can carry. Refused rather than
	 * clamped: clamping would leave the caller cutting their buffer with
	 * their number while the plan used a smaller one, which is a
	 * disagreement about the stride and the one thing this module exists
	 * to prevent. */
	FZN_SPLIT_ERR_PAYLOAD_TOO_LARGE = -3,
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
 * caller's, since it depends on the MTU, capped at FZN_SPLIT_MAX_PAYLOAD.
 *
 * THE OBVIOUS CALCULATION OVERSHOOTS, which is why the cap is checked and
 * not merely documented. A caller sizing from Ethernet gets 1500 - 28 for
 * IP and UDP - 144 of frame overhead = 1328, comfortably above the 1024 a
 * frame's `length` field will accept, and every datagram of that plan would
 * have failed validation at the far end.
 *
 * The overhead figure here said 96 until this was checked, and 96 is the
 * plaintext prefix alone -- it counts hop and header while omitting the
 * sealed `capability` and the tag, which cost 48 between them. It was stale
 * in the direction that makes the miscalculation worse, so this comment was
 * instructing a caller into the bug the paragraph above describes. Read the
 * real one off `SITU_FZN_FRAME_SIZE_MIN` rather than from prose.
 *
 * A zero-length message is refused: reassembly rejects an empty piece, so
 * producing one here would build something the other half will not take. */
fzn_split_err_t fzn_split_plan(size_t total, size_t max_payload, fzn_split_t *out);

/* Where piece `index` starts and how long it is. */
fzn_split_err_t fzn_split_at(const fzn_split_t *plan, uint16_t index, size_t *offset,
                              size_t *len);

#endif /* FZN_SPLIT_H */
