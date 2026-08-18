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

#include <stddef.h>
#include <stdint.h>

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

/* Seal a frame whose header and plaintext a caller has already written.
 * Encrypts the sealed region in place and writes the tag where the layout
 * puts it, which is not immediately after the ciphertext. */
fzn_seal_err_t fzn_seal_close(uint8_t *frame, size_t frame_len,
                               const uint8_t key[FZN_AEAD_KEY_LEN],
                               const fzn_aead_ops_t *aead);

#endif /* FZN_SEAL_H */
