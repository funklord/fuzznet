/* The four things two hosts say to each other about a blob, and their bytes.
 *
 * project.md sec 102 measured what a filestore needs and named this row as
 * the one most likely to carry a consumer's peer model across. It is the
 * vocabulary fuzzypickles has as `encode_want`, `have`, `have_query` and
 * `data`; this is the same conversation with their estate taken out of it.
 *
 * THIS IS PAYLOAD, NOT A FRAME KIND. Sec 96 closed the kind set -- nop,
 * unit, chunk, ack -- and a filestore message is not a fifth. These encode
 * INTO the sealed payload of a `chunk` or a `unit`, which is where sec 96
 * put fuzzypickles' command vocabulary back when it was theirs. What has
 * changed since is who owns the vocabulary, not where it rides.
 *
 * THE HAVE-SET ON THE WIRE IS RANGES, NOT A BITMAP, and that is the one
 * design decision here a reader would most likely get backwards -- because
 * `spool/` stores a bitmap and the obvious move is to send it.
 *
 * A 4 GiB blob is 2^22 leaves and a 512 KiB bitmap. That does not fit a
 * frame, so sending it means fragmenting half a megabyte to answer "what do
 * you have", which is the amplifier sec 25 spent three rules closing. The
 * same fact as ranges is `fzn_spool_range_t`, the type BOTH planners already
 * speak, and `fzn_spool_plan_offer` already produces exactly this message's
 * body -- so the encoder has nothing to compute.
 *
 * And the compression is guaranteed rather than hoped for. Sec 102 records
 * that assignment is sequential, lowest leaves first, precisely so a
 * partially fetched blob stays contiguous; a contiguous prefix is ONE range,
 * 16 bytes, whatever the blob's size. The bitmap is the right shape for a
 * store answering "is leaf 91,000 present" and the wrong shape for a peer
 * answering "how far have you got".
 *
 * THE COOKIE IS SIXTEEN OPAQUE BYTES AND THIS LIBRARY NEVER READS THEM.
 * That is the neutrality this row exists to keep. fuzzypickles binds their
 * cookie to a source address string; netcfgd's peers are not addressed that
 * way, and sec 102 lists their peer model first among the three things that
 * must not travel. A host cannot bind a cookie to a peer without knowing
 * what a peer IS, and that is exactly the question this library declines --
 * so it carries the field and the host decides what goes in it.
 *
 * `wire/` states the same split from the other side: the field is schema,
 * the policy is ours. Here the field is ours and the policy is the host's.
 *
 * IT IS ANTI-REFLECTION AND IT IS NOT A RATE LIMIT. A 70-byte WANT answered
 * with a 64 KiB span is a ~900x amplifier, and a spoofer never sees the HAVE
 * that carried the cookie, so echoing one is proof of nothing except that
 * the sender receives at the address it claims. It bounds WHOM to answer.
 * Sec 25's planners bound WHAT to answer, which is the other half and does
 * not substitute -- naming what this is not is what stops it being
 * "improved" into a rate limiter with the property quietly removed.
 *
 * THE TRANSFER ID IS FOR DEMULTIPLEXING, and the reason it came with is not
 * the reason it stays. fuzzypickles hold that it "keeps the server stateless
 * and avoids a 32-byte root per DATA frame", and sec 102 recorded the
 * property as worth keeping while its encoding was not. Checked here, the
 * second half of their reason does not arise: a fuzznet DATA carries a whole
 * span and `chunk/` fragments it, so the 28 bytes saved are once per 64 KiB
 * message rather than once per frame -- 0.04%, which buys nothing.
 *
 * What it does buy is that a requester with several spans of one blob in
 * flight to one peer can match an answer to its question without reparsing,
 * and can recognise an answer to a request it has already retired. The
 * stateless half is real and is kept: the responder echoes what it was
 * given and remembers nothing, so the id costs it no table.
 *
 * A MESSAGE NAMING NOTHING GETS NOTHING, inherited from sec 25 rather than
 * re-argued: a WANT of zero leaves and a HAVE of zero ranges are refused as
 * FZN_MSG_ERR_EMPTY, because the cheapest message a stranger can forge must
 * not be the one that buys the most work.
 *
 * THE TYPE BYTE IS DOMAIN SEPARATION AND IT MATTERS INSIDE THE SEAL.
 * `wire/bytes.h` records what it cost fuzzypickles to learn that two record
 * types of the same length can have one signature that verifies as both.
 * Nothing here is signed -- the frame's seal authenticates all four -- but a
 * peer legitimately sends every one of these under the same key, so a seal
 * proves only that the peer wrote the bytes and not which question they
 * answer. The version and type bytes lead every message for that reason.
 *
 * AN ASYMMETRY WORTH KNOWING: `record/sync.h` deliberately does NOT encode.
 * It says "how it is encoded is the consumer's", and that was right when the
 * consumer owned the transport. Sec 101 moved the transport here, so sync's
 * reason has expired without sync noticing -- the same conversation about
 * records still has no bytes while this one now does. That is a finding
 * about `record/sync.h`, not a defect in this file, and project.md carries
 * it rather than this header resolving it in passing.
 */

#ifndef FZN_MESSAGE_H
#define FZN_MESSAGE_H

#include "plan.h"
#include "spool.h"

/* The vocabulary's own version, separate from FZN_SIGNED_VERSION because
 * these are not signed objects and a shared number would tie two families
 * that move for different reasons. */
#define FZN_MSG_VERSION 1u

typedef enum fzn_msg_type {
	/* "Do you have this blob?" -- a root and nothing else. */
	FZN_MSG_HAVE_QUERY = 1,
	/* "This much of it, and here is a cookie to quote back." */
	FZN_MSG_HAVE = 2,
	/* "Send me this span; here is your cookie." */
	FZN_MSG_WANT = 3,
	/* "That span, under one proof." */
	FZN_MSG_DATA = 4,
} fzn_msg_type_t;

typedef enum fzn_msg_err {
	FZN_MSG_OK = 0,
	/* Short, over-long, wrong version, unknown type, or a field a decoder
	 * cannot make sense of. A stranger's bytes, and the ordinary answer. */
	FZN_MSG_ERR_MALFORMED,
	/* A count past a ceiling, or an answer that does not fit the caller's
	 * buffer. Separate from MALFORMED because the bytes may be perfectly
	 * well formed and simply larger than this host will handle. */
	FZN_MSG_ERR_TOO_LARGE,
	/* A message naming nothing: an empty want, a have with no ranges. */
	FZN_MSG_ERR_EMPTY,
} fzn_msg_err_t;

const char *fzn_msg_err_str(fzn_msg_err_t err);

/* Sixteen bytes, chosen so a truncated MAC fits without a host having to
 * think about it, and small enough that carrying one per HAVE is free. */
#define FZN_MSG_COOKIE_LEN 16u

/* Ranges one HAVE may carry. The same ceiling as a want plan, because the
 * plan is what fills it and a bound that differed from the producer's would
 * be a truncation nobody chose. */
#define FZN_MSG_MAX_RANGES FZN_SPOOL_MAX_WANT

/* Leaves one DATA may carry. `spool/spool.h` already caps a span at this for
 * the same reason -- the count comes from a peer, and an uncapped one is a
 * stack frame a stranger chooses. */
#define FZN_MSG_MAX_SPAN 64u

/* Proof siblings a DATA may carry.
 *
 * DERIVED, NOT CHOSEN, and it was chosen for about an hour first. This read
 * `64u` with a comment observing that a span over 2^22 leaves needs at most
 * one sibling per level -- a true sentence with a round number sitting on top
 * of it, above both the depth it cited and the 40 `blob/` actually permits.
 *
 * A canonical span's proof is the path from its subtree node to the root, so
 * the count IS the depth and `blob/` already names the maximum; every proof
 * buffer in the tree is sized by it. Measured to confirm rather than assumed:
 * a 4096-leaf tree at one leaf per request costs 12 siblings a proof, which
 * is its depth exactly (project.md sec 106 has the sweep).
 *
 * Found by the lens sec 106 came out of -- a constant justified by a quantity
 * that only pushes one way is unjustified, and reads as justified because a
 * real measurement is attached. Here the measurement was real, said "at
 * most", and stopped one step short of a bound this tree already had. */
#define FZN_MSG_MAX_PROOF FZN_BLOB_MAX_DEPTH

/* THE LAYOUTS. Big-endian, fixed width, no padding, fixed fields first --
 * the same rules as the hop and the revocation, for the same reason.
 *
 *   HAVE_QUERY                     HAVE
 *     0   1  version                 0   1  version
 *     1   1  type (= 1)              1   1  type (= 2)
 *     2  32  root                    2  32  root
 *    ----------------- 34           34   8  leaf_count
 *                                   42  16  cookie
 *   WANT                            58   2  range_count
 *     0   1  version                60  16  range[0] .. range[n-1]
 *     1   1  type (= 3)             -----------------  60 + 16n
 *     2   4  transfer
 *     6  16  cookie                DATA
 *    22  32  root                    0   1  version
 *    54   8  first                   1   1  type (= 4)
 *    62   8  count                   2   4  transfer
 *   ----------------- 70             6   8  first
 *                                   14   8  count
 *                                   22   1  proof_count
 *                                   23  32  sibling[0] .. sibling[p-1]
 *                                     +  4  leaf_len[0] .. leaf_len[n-1]
 *                                     +     the sealed leaves
 */
#define FZN_MSG_OFF_VERSION 0u
#define FZN_MSG_OFF_TYPE 1u

#define FZN_MSG_HAVE_QUERY_LEN 34u

#define FZN_MSG_HAVE_OFF_ROOT 2u
#define FZN_MSG_HAVE_OFF_LEAF_COUNT 34u
#define FZN_MSG_HAVE_OFF_COOKIE 42u
#define FZN_MSG_HAVE_OFF_RANGE_COUNT 58u
#define FZN_MSG_HAVE_OFF_RANGES 60u
#define FZN_MSG_RANGE_LEN 16u
#define FZN_MSG_HAVE_LEN(ranges) (FZN_MSG_HAVE_OFF_RANGES + (size_t)(ranges)*FZN_MSG_RANGE_LEN)

#define FZN_MSG_WANT_OFF_TRANSFER 2u
#define FZN_MSG_WANT_OFF_COOKIE 6u
#define FZN_MSG_WANT_OFF_ROOT 22u
#define FZN_MSG_WANT_OFF_FIRST 54u
#define FZN_MSG_WANT_OFF_COUNT 62u
#define FZN_MSG_WANT_LEN 70u

#define FZN_MSG_DATA_OFF_TRANSFER 2u
#define FZN_MSG_DATA_OFF_FIRST 6u
#define FZN_MSG_DATA_OFF_COUNT 14u
#define FZN_MSG_DATA_OFF_PROOF_COUNT 22u
#define FZN_MSG_DATA_OFF_PROOF 23u

/*
 * Reads the type byte without decoding anything else.
 *
 * A receiver has one buffer and four shapes, so it must dispatch before it
 * can parse -- and the alternative, trying each parser in turn, makes a
 * malformed message of one type indistinguishable from a well-formed message
 * of another. The version is checked here so a future version is refused
 * once rather than four times.
 */
fzn_msg_err_t fzn_msg_peek(const uint8_t *bytes, size_t len, fzn_msg_type_t *out_type);

fzn_msg_err_t fzn_msg_have_query_encode(const uint8_t root[FZN_BLOB_HASH_LEN], uint8_t *out,
                                        size_t out_cap, size_t *out_len);
fzn_msg_err_t fzn_msg_have_query_parse(const uint8_t *bytes, size_t len,
                                       uint8_t out_root[FZN_BLOB_HASH_LEN]);

/*
 * Encodes what this host holds of a blob.
 *
 * `ranges` is what `fzn_spool_plan_offer` produced, unmodified: this
 * function does not decide what to disclose, it writes down an answer
 * somebody else planned.
 */
fzn_msg_err_t fzn_msg_have_encode(const uint8_t root[FZN_BLOB_HASH_LEN], uint64_t leaf_count,
                                  const uint8_t cookie[FZN_MSG_COOKIE_LEN],
                                  const fzn_spool_range_t *ranges, size_t range_count,
                                  uint8_t *out, size_t out_cap, size_t *out_len);

/*
 * `out_ranges` receives at most `cap` ranges and `out_count` says how many
 * the message held. A message carrying more than `cap` is TOO_LARGE rather
 * than truncated: a partial have-set read as a whole one is a peer reported
 * as holding less than it does, which schedules a re-fetch of leaves that
 * were already available.
 */
fzn_msg_err_t fzn_msg_have_parse(const uint8_t *bytes, size_t len,
                                 uint8_t out_root[FZN_BLOB_HASH_LEN], uint64_t *out_leaf_count,
                                 uint8_t out_cookie[FZN_MSG_COOKIE_LEN],
                                 fzn_spool_range_t *out_ranges, size_t cap, size_t *out_count);

fzn_msg_err_t fzn_msg_want_encode(uint32_t transfer, const uint8_t cookie[FZN_MSG_COOKIE_LEN],
                                  const uint8_t root[FZN_BLOB_HASH_LEN], uint64_t first,
                                  uint64_t count, uint8_t *out, size_t out_cap, size_t *out_len);
fzn_msg_err_t fzn_msg_want_parse(const uint8_t *bytes, size_t len, uint32_t *out_transfer,
                                 uint8_t out_cookie[FZN_MSG_COOKIE_LEN],
                                 uint8_t out_root[FZN_BLOB_HASH_LEN], uint64_t *out_first,
                                 uint64_t *out_count);

/*
 * Encodes a span and the one proof that covers it.
 *
 * `sealed` and `sealed_len` are the same pair `fzn_spool_place_span` takes,
 * in the same order, so a relay can decode a DATA and hand the arrays
 * straight to a store without copying or reordering them.
 */
fzn_msg_err_t fzn_msg_data_encode(uint32_t transfer, uint64_t first, uint64_t count,
                                  const uint8_t *proof, unsigned proof_count,
                                  const uint8_t *const *sealed, const size_t *sealed_len,
                                  uint8_t *out, size_t out_cap, size_t *out_len);

/*
 * Parses a span WITHOUT COPYING THE LEAVES: `out_sealed` receives pointers
 * into `bytes`, which must outlive them.
 *
 * A 64 KiB span copied into a caller's buffer would double the cost of every
 * transfer for nothing -- the bytes are already contiguous and already
 * verified by whoever holds the proof. `out_proof` points into `bytes` for
 * the same reason, and both arrays are sized by the caller so this module
 * still allocates nothing.
 */
fzn_msg_err_t fzn_msg_data_parse(const uint8_t *bytes, size_t len, uint32_t *out_transfer,
                                 uint64_t *out_first, uint64_t *out_count,
                                 const uint8_t **out_proof, unsigned *out_proof_count,
                                 const uint8_t **out_sealed, size_t *out_sealed_len, size_t cap);

#endif /* FZN_MESSAGE_H */
