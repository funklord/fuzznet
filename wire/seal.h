/* Opening and sealing a frame -- sec 10 step 2, and the first code here that
 * reads the wire.
 *
 * WHAT SITU CONTRIBUTES, and it is not what this library expected. The record
 * said this waited on "situ's sealed-region ABI" and that the calling
 * convention was still a guess. It is neither, and the convention is smaller
 * than the guess: the generated code never calls a codec at all. It gives
 *
 *   - `situ_fzn_frame_tag_covered()` -- the exact span the tag authenticates,
 *     computed from the layout rather than restated here;
 *   - `situ_fzn_frame_sealed_open(view, verified, &gate)` -- which refuses to
 *     produce an interior view unless `verified` is true, and every accessor
 *     for the capability and payload takes that gate as its argument.
 *
 * So the discipline situ enforces is ORDER: nothing can address the plaintext
 * before something has said the tag verified. This file is what says it, and
 * it is deliberately the only place in the library that may.
 *
 * THE ONE MODULE THAT DEPENDS ON THE GENERATED CODE. Every other source here
 * takes decoded fields from a caller and never sees a frame -- which is what
 * keeps them buildable, and shippable, without situ. That property is worth
 * more than the symmetry, so the dependency is confined to this file rather
 * than spread by having reassembly or freshness learn the layout.
 */

#ifndef FZN_SEAL_H
#define FZN_SEAL_H

#include "../session/aead.h"
#include "../session/commitment.h"
#include "../session/random.h"

/* For FZN_RELAY_MAX_HOPS. A sender now states a hop budget and this library
 * refuses one larger than it would itself forward -- see `fzn_send.hops`. */
#include "relay.h"

#include <stddef.h>
#include <stdint.h>

/* Bytes a frame costs before any payload. Stated here so a sender can size a
 * buffer without reading the schema, and checked against the generated layout
 * in wire/test/constants_test.c rather than trusted. */
#define FZN_SEAL_OVERHEAD 144u

typedef enum fzn_seal_err {
	FZN_SEAL_OK = 0,
	/* An argument this library cannot act on: a null pointer where one is
	 * required, a payload pointer absent with a non-zero length, or a hop
	 * budget past FZN_RELAY_MAX_HOPS. Distinct from ERR_SHAPE, which is
	 * about the bytes of a frame rather than about what a caller asked
	 * for. */
	FZN_SEAL_ERR_MALFORMED = -1,
	/* The frame is not the shape the schema describes -- too short, a bad
	 * version, an index past its own chunk count, or LONGER than the frame
	 * it contains. Refused before any cryptography, because a frame that is
	 * not a frame is not worth a decryption.
	 *
	 * SHORT AND OVER-LONG ARE ONE CODE AND NOT ONE FAULT, which is worth
	 * knowing when one of them is being diagnosed. A short buffer is a
	 * TRUNCATED datagram: bytes the sender wrote that did not arrive, which
	 * a network does by itself and which every check below notices because
	 * the missing bytes were authenticated. An over-long buffer is bytes
	 * the sender did NOT write and somebody else appended: the frame inside
	 * it is intact and its tag verifies, because the tag covers `head` and
	 * the sealed region and stops there, so no amount of cryptography would
	 * ever object to a suffix.
	 *
	 * `wire/frame.situ` says `require canonical(fzn_frame)`, which situc
	 * checks at codegen time and which never reached this C. Until this
	 * check existed a valid 168-byte frame handed in as 232 bytes -- and at
	 * every size up to 168 + 4096 -- returned FZN_SEAL_OK with
	 * `payload_len` unchanged. Anything keyed on the DATAGRAM rather than
	 * on the frame inside it -- a dedup cache, a forwarding relay, one
	 * capture compared against another -- then sees a single frame wearing
	 * as many identities as an attacker cares to append, at no cost and
	 * with no key. */
	FZN_SEAL_ERR_SHAPE = -2,
	/* The tag did not verify. Says nothing about who sent it or why: a
	 * forgery and a corrupted datagram are the same answer here. */
	FZN_SEAL_ERR_TAG = -3,
	/* The key-commitment in the header is not the one this key derives.
	 * DISTINCT FROM A BAD TAG on purpose, and A VERDICT AN ATTACKER MAY
	 * CHOOSE -- fzn_seal_open() states both halves, and the second one
	 * governs what a consumer may do about it. */
	FZN_SEAL_ERR_COMMITMENT = -4,
	/* No nonce could be drawn. A refusal rather than a frame sealed under
	 * something predictable -- see session/random.h. */
	FZN_SEAL_ERR_NO_NONCE = -5,
	/* The caller's buffer is too small for the frame it asked for. */
	FZN_SEAL_ERR_CAPACITY = -6,
} fzn_seal_err_t;

/* What opening a frame yields: pointers into the caller's own buffer, which
 * this library does not own and does not copy. Valid only while that buffer
 * is, and only after FZN_SEAL_OK. */
typedef struct fzn_opened {
	const uint8_t *capability; /* FZN_CAP_ID_LEN bytes */
	const uint8_t *payload;
	size_t payload_len;
	/* Decoded header fields the rest of the library takes as arguments,
	 * so that a caller need not learn the accessors to use them. */
	const uint8_t *sender; /* 32 bytes */
	const uint8_t *nonce;  /* FZN_AEAD_NONCE_LEN bytes */
	uint64_t expires_at;
	uint32_t msg;
	uint16_t index;
	uint16_t chunks;
	uint8_t kind;
} fzn_opened_t;

/* Open a frame in place. `frame` is decrypted where it lies, so the buffer
 * must be writable and the caller must treat it as consumed.
 *
 * THE ORDER IS THE POINT, and it is checked rather than described:
 *
 *   1. shape, from the schema's own validator;
 *   2. the commitment, against the key -- before a decryption is spent;
 *   3. the tag, over exactly the span situ says it covers;
 *   4. only then the gate, and only then any plaintext.
 *
 * Step 2 is why `commitment` is in the authenticated header rather than
 * inside the seal, and why its failure is a DIFFERENT error from a bad tag:
 * with K candidate keys it turns K tag verifications into K compares and one
 * verification, which is what makes `wire/relay.h`'s addressing-by-decryption
 * affordable at all.
 *
 * WHAT FZN_SEAL_ERR_COMMITMENT DOES NOT MEAN, AND THIS HEADER USED TO SAY THE
 * OPPOSITE. It said the difference was "between rotating a key and hunting an
 * attacker", which reads as an instruction to rotate. It is not one, and the
 * reason is the order above rather than anything about key management:
 * `commitment` is a PLAINTEXT header field compared BEFORE the AEAD runs, so
 * the verdict is reached entirely from bytes anybody on the path may rewrite.
 * Measured here with a call-counting stub: flipping one byte at frame offset
 * 0x49 turns FZN_SEAL_OK into this error with the AEAD never called.
 *
 * A consumer acting on a single one of these has therefore handed a stranger
 * a remote control -- one flipped byte per datagram and a healthy receiver
 * concludes its own key is wrong. project.md sec 4.7 states the corollary in
 * general, and it governs every pre-tag verdict rather than only this one:
 *
 *   - COUNT IT IN AGGREGATE AND ACT ON THE RATE, which is the only form the
 *     honest signal survives in. Mismatch on every frame from a peer means
 *     the key really has moved. Mismatch on one frame in a thousand means
 *     somebody is flipping bits, and no single frame can tell the two apart.
 *   - NEVER let one on its own trigger a rekey, evict a peer, or reach a
 *     sentence that names an identity. A verdict reached before the tag names
 *     nobody, because nothing it was reached from was authenticated.
 *
 * THE ORDER IS NOT WHAT WAS WRONG and does not move. Checking the commitment
 * first is what saves the decryptions; putting it below the tag would cost
 * exactly what it was put there to buy. What was wrong was the advice about
 * the answer.
 *
 * `frame_len` MUST BE THE FRAME EXACTLY. A buffer longer than the frame it
 * holds is refused as FZN_SEAL_ERR_SHAPE, and it has to be refused HERE
 * because nothing else can: the tag covers `head` and the sealed region and
 * stops there, so a suffix after the tag changes nothing any check below
 * looks at. See FZN_SEAL_ERR_SHAPE for what an appended suffix buys an
 * attacker, and for why an over-long buffer is a different fault from a short
 * one even though it is the same code.
 */
fzn_seal_err_t fzn_seal_open(uint8_t *frame, size_t frame_len,
                              const uint8_t key[FZN_AEAD_KEY_LEN],
                              const uint8_t commitment[FZN_COMMITMENT_LEN],
                              const fzn_aead_ops_t *aead, fzn_opened_t *out);

/* What a sender is putting into one frame. Everything here is the caller's
 * except the nonce, which is deliberately absent: `fzn_seal_build` draws it
 * from the entropy seam and refuses if it cannot, because a nonce a caller
 * supplied is a nonce a caller can repeat. See `session/random.h` for what
 * repeating one costs. */
typedef struct fzn_send {
	const uint8_t *sender;     /* 32 bytes */
	const uint8_t *capability; /* FZN_CAP_ID_LEN, sealed rather than sent clear */
	const uint8_t *payload;
	size_t payload_len;
	uint64_t expires_at;
	uint32_t msg;
	uint16_t index;
	uint16_t chunks;
	uint8_t kind;
	/* THE HOP BUDGET, and the first thing on the send path that has ever
	 * written one.
	 *
	 * `fzn_hop.hops_left` has been in every frame since the schema existed
	 * and until this field nothing in this library set it. `fzn_seal_build`
	 * memset the frame and wrote only `version`, so EVERY frame this
	 * library could build carried a budget of zero: `fzn_relay_budget`
	 * answered 0 and `fzn_relay_spend` answered FZN_RELAY_ERR_EXHAUSTED,
	 * for every frame, always. A consumer wanting a relayable frame had to
	 * poke `frame[1]` by hand -- exactly the raw-offset knowledge this
	 * header exists to spare it. It is also the mechanical reason the
	 * seal -> relay -> open round trip had never been written: it could
	 * not be written against the public API.
	 *
	 * ZERO MEANS THIS FRAME IS NOT OFFERED FOR RELAYING. The first host to
	 * receive it does not forward it. That is what a `memset` to zero
	 * leaves behind, and the coincidence is deliberate rather than
	 * convenient: relaying is opted INTO. A zero meaning FZN_RELAY_MAX_HOPS
	 * would turn every consumer written before this field existed into a
	 * traffic source without one of them changing a line, and it would do
	 * it by making the safest-looking initialisation the most expansive
	 * one.
	 *
	 * REFUSED ABOVE FZN_RELAY_MAX_HOPS, with FZN_SEAL_ERR_MALFORMED, before
	 * the buffer is touched. A frame claiming more hops than this library
	 * will forward states a reach the same library refuses on receipt --
	 * `fzn_relay_budget` clamps it at the first honest host -- so accepting
	 * it would leave the caller believing in a reach it does not have.
	 * Refused rather than clamped, on `chunk/split.c`'s argument for the
	 * same decision: clamping leaves a caller believing something was sent.
	 *
	 * AND IT IS A REQUEST RATHER THAN A GUARANTEE. The byte sits before the
	 * authenticated region, necessarily, because a relay decrements it --
	 * so anyone on the path may rewrite it, and `wire/relay.h` says what
	 * does and does not follow from that. A sender states a budget; it does
	 * not set one. */
	uint8_t hops;
} fzn_send_t;

/* Build one frame and seal it, which is the send path's whole order in one
 * call.
 *
 * THE ORDER IS HERE RATHER THAN IN A DOCUMENT, and that is the point. sec 4.7
 * states what a receiver must do and `frame/test/receive_fuzz.c` runs it;
 * the sender's order was never written down at all, and it has traps that a
 * consumer would meet one at a time:
 *
 *   1. **A fresh nonce per frame**, from the entropy seam, refusing if none
 *      can be had. Not per message -- per FRAME. Two chunks of one message
 *      sealed under one nonce is the same key-and-nonce reuse as two
 *      unrelated frames, and this is the trap a caller is likeliest to walk
 *      into, because "one message, one nonce" reads as tidy.
 *   2. **Every authenticated byte final before the tag.** The header is the
 *      AEAD's associated data, so a field written after sealing is a field
 *      the tag does not cover; `length` is worse still, since the sealed
 *      region's extent is computed from it and writing it late moves the
 *      span the tag was taken over.
 *   3. **The capability and the payload inside the seal**, written as
 *      plaintext and encrypted in place by the same call.
 *   4. **The hop budget, from `what->hops`**, which is the one header field
 *      the tag deliberately does NOT cover -- see `fzn_send.hops` and
 *      `wire/relay.h`. Written before the seal here, though nothing requires
 *      it to be: the whole point of the field's position is that changing it
 *      neither invalidates nor needs the tag. `wire/test/seal_test.c` asserts
 *      that property directly rather than restating it, by spending the
 *      entire budget between build and open and requiring the frame to still
 *      open with its payload and capability byte-identical.
 *
 * `frame` receives the whole datagram and `*frame_len` its length. The buffer
 * must have room for FZN_SEAL_OVERHEAD + `payload_len`.
 */
fzn_seal_err_t fzn_seal_build(uint8_t *frame, size_t frame_cap, size_t *frame_len,
                               const fzn_send_t *what, const uint8_t key[FZN_AEAD_KEY_LEN],
                               const uint8_t commitment[FZN_COMMITMENT_LEN],
                               const fzn_random_ops_t *rng, const fzn_aead_ops_t *aead);

/* Seal a frame whose header and plaintext a caller has already written.
 * Encrypts the sealed region in place and writes the tag where the layout
 * puts it, which is not immediately after the ciphertext. */
fzn_seal_err_t fzn_seal_close(uint8_t *frame, size_t frame_len,
                               const uint8_t key[FZN_AEAD_KEY_LEN],
                               const fzn_aead_ops_t *aead);

/* A short name for `fzn_seal_err_t`, for a log line or a message to a user.
 *
 * NEVER NULL, including for a value that is not one of the enumerators, so
 * that a caller may pass the result straight to a printf without a check.
 * An unrecognised value renders as "unknown", which is deliberately not any
 * real code's text -- a caller that cannot tell "we do not know" from a
 * genuine answer is the failure this whole library is careful about
 * elsewhere.
 *
 * The strings are lowercase, carry no trailing punctuation and name the
 * condition rather than restating the constant, on the same reasoning as
 * strerror: the caller supplies the sentence, this supplies the noun. */
const char *fzn_seal_err_str(fzn_seal_err_t err);

#endif /* FZN_SEAL_H */
