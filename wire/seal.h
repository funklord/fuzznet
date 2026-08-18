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

#include <stddef.h>
#include <stdint.h>

/* Bytes a frame costs before any payload. Stated here so a sender can size a
 * buffer without reading the schema, and checked against the generated layout
 * in wire/tests/constants_test.c rather than trusted. */
#define FZN_SEAL_OVERHEAD 144u

typedef enum fzn_seal_err {
	FZN_SEAL_OK = 0,
	FZN_SEAL_ERR_MALFORMED = -1,
	/* The frame is not the shape the schema describes -- too short, a bad
	 * version, an index past its own chunk count. Refused before any
	 * cryptography, because a frame that is not a frame is not worth a
	 * decryption. */
	FZN_SEAL_ERR_SHAPE = -2,
	/* The tag did not verify. Says nothing about who sent it or why: a
	 * forgery and a corrupted datagram are the same answer here. */
	FZN_SEAL_ERR_TAG = -3,
	/* The key-commitment in the header is not the one this key derives.
	 * DISTINCT FROM A BAD TAG on purpose -- see fzn_seal_open(). */
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
 * inside the seal, and why its failure is a DIFFERENT error from a bad tag. A
 * receiver holding the wrong key learns that it holds the wrong key, rather
 * than that somebody sent it rubbish -- which is the difference between
 * rotating a key and hunting an attacker.
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
} fzn_send_t;

/* Build one frame and seal it, which is the send path's whole order in one
 * call.
 *
 * THE ORDER IS HERE RATHER THAN IN A DOCUMENT, and that is the point. sec 4.7
 * states what a receiver must do and `frame/tests/receive_fuzz.c` runs it;
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

#endif /* FZN_SEAL_H */
