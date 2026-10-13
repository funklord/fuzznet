/*
 * A SEALED BOX TO A PREKEY, project.md sec 618: the first-contact sealed
 * box fuzzypickles built (`pairing_crypto`), brought into fuzznet for
 * step 3b of sec 608. What a stranger sends a host it has no session with:
 * a pairing request, sealed to the host's prekey from its contact card.
 *
 *     mark 0xFB | version 1 | ephemeral public key [32] | text | tag [16]
 *
 * The key is the hash of a label, the ephemeral public key, the recipient's
 * prekey and their X25519 agreement; one ephemeral key per box, so the nonce
 * is zero and the key is never used twice. The head is the AEAD's
 * associated data.
 *
 * CONFIDENTIALITY ONLY, DELIBERATELY. The box says nothing about who sent
 * it -- anybody holding the card can seal one -- and fuzzypickles chose
 * that on purpose: authenticity is the payload's own signature, checked
 * after opening against a key the payload proves. A caller that acts on a
 * box's contents before checking that signature has authenticated nothing.
 *
 * NOT A FRAME. A frame's first byte is its version, 1 (`wire/frame.situ`);
 * a box's is FZN_BOX_MARK, so a datagram that is one can never read as the
 * other, and the closed set of frame kinds is not touched.
 */
#ifndef FZN_BOX_H
#define FZN_BOX_H

#include <stddef.h>
#include <stdint.h>

#include "aead.h"
#include "agree.h"
#include "commitment.h"
#include "random.h"

#define FZN_BOX_MARK 0xFBu
#define FZN_BOX_VERSION 1u
#define FZN_BOX_HEAD_LEN (2u + FZN_AGREE_PUBLIC_LEN)
#define FZN_BOX_OVERHEAD (FZN_BOX_HEAD_LEN + FZN_AEAD_TAG_LEN)

typedef enum fzn_box_err {
	FZN_BOX_OK = 0,
	FZN_BOX_ERR_MALFORMED = -1, /* a null, or no room */
	FZN_BOX_ERR_SHAPE = -2,     /* bytes that are not a box */
	FZN_BOX_ERR_OPEN = -3,      /* not sealed to this key, or altered */
	FZN_BOX_ERR_OPS = -4        /* the randomness or the agreement refused */
} fzn_box_err_t;

const char *fzn_box_err_str(fzn_box_err_t err);

/* Whether `bytes` begin as a box does: what a datagram handler asks before
 * spending an agreement on it. */
int fzn_box_is(const uint8_t *bytes, size_t len);

/* SEAL `payload` (`len` bytes) to `recipient`, a prekey: `out`, of
 * FZN_BOX_OVERHEAD + `len`, `*out_len` bytes. */
fzn_box_err_t fzn_box_seal(const fzn_agree_ops_t *agree, const fzn_hash_ops_t *hash,
                           const fzn_aead_ops_t *aead, const fzn_random_ops_t *rng,
                           const uint8_t recipient[FZN_AGREE_PUBLIC_LEN], const uint8_t *payload,
                           size_t len, uint8_t *out, size_t cap, size_t *out_len);

/* OPEN a box sealed to `secret`'s public half: its payload into `out`,
 * `*out_len` bytes. OPEN for one sealed to another key, or altered. */
fzn_box_err_t fzn_box_open(const fzn_agree_secret_t *secret, const fzn_agree_ops_t *agree,
                           const fzn_hash_ops_t *hash, const fzn_aead_ops_t *aead,
                           const uint8_t *box, size_t len, uint8_t *out, size_t cap,
                           size_t *out_len);

#endif /* FZN_BOX_H */
