#ifndef FZN_PREKEY_H
#define FZN_PREKEY_H

/*
 * A prekey record, and the act of pinning one.
 *
 * THE TWO ARE ONE FEATURE AND ARE DELIBERATELY NOT SEPARATED. This library
 * asked fuzzypickles whether prekey distribution or contact management was
 * the blocking row, and the answer was that the question had the wrong shape:
 * in their tree the contact record is MADE FROM the prekey record at add
 * time, so there is no separate distribution mechanism. The record is the
 * thing that travels, verifying it is what an add does, and pinning it IS the
 * trust-on-first-use act. A record with no pinning act is a blob nobody
 * adopts -- half of one thing rather than one of two.
 *
 * What is NOT here, and is the application-shaped half that can follow: the
 * peer's address, its realm, per-peer opt-in state, and a store holding many
 * of them. This module produces a pinned peer; keeping a table of them is a
 * consumer's business, as it must be in a library that does not allocate.
 *
 * WHAT VERIFYING ONE PROVES, AND WHAT IT DOES NOT. The record is SELF-SIGNED:
 * the host signs its own prekey under its own long-term key. So a valid
 * signature proves that whoever holds `host`'s secret key made this record,
 * and proves NOTHING about whether `host` is the party the user meant. That
 * is not a weakness to be fixed here -- it is what trust on first use is, and
 * `trust/trust.h` says at length that a consumer using it owes its user a way
 * to check the anchor out of band. The same debt is owed here.
 */

#include <stddef.h>
#include <stdint.h>

#include "../chain/chain.h" /* fzn_sign_ops_t, FZN_PUBKEY_LEN, FZN_SIG_LEN */
#include "../trust/trust.h"

/* An X25519 public key is 32 bytes, as is an Ed25519 one. Named separately
 * from FZN_PUBKEY_LEN because they are different keys with different jobs --
 * the long-term identity signs, the prekey agrees -- and a future that
 * changes one must not silently change the other. */
#define FZN_PREKEY_LEN 32u

#define FZN_PREKEY_OFF_VERSION    0u
#define FZN_PREKEY_OFF_OBJECT     (FZN_PREKEY_OFF_VERSION + 1u)
#define FZN_PREKEY_OFF_HOST       (FZN_PREKEY_OFF_OBJECT + 1u)
#define FZN_PREKEY_OFF_PREKEY     (FZN_PREKEY_OFF_HOST + FZN_PUBKEY_LEN)
#define FZN_PREKEY_OFF_CREATED_AT (FZN_PREKEY_OFF_PREKEY + FZN_PREKEY_LEN)
#define FZN_PREKEY_OFF_SIGNATURE  (FZN_PREKEY_OFF_CREATED_AT + 8u)

/* The bytes the signature covers: everything before it. */
#define FZN_PREKEY_BODY_LEN FZN_PREKEY_OFF_SIGNATURE
#define FZN_PREKEY_LEN_TOTAL (FZN_PREKEY_BODY_LEN + FZN_SIG_LEN)

typedef enum fzn_prekey_err {
	FZN_PREKEY_OK = 0,
	/* The caller's bug: a null, a buffer too small. */
	FZN_PREKEY_ERR_MALFORMED,
	/* A peer's bytes are not this shape: a wrong length, a version or an
	 * object tag that is not ours. */
	FZN_PREKEY_ERR_SHAPE,
	/* The self-signature does not verify under the host key the record
	 * names. */
	FZN_PREKEY_ERR_SIGNATURE,
	/* A signer or verifier refused, or was absent. */
	FZN_PREKEY_ERR_SIGNER,
	/*
	 * A record for a host already pinned, offering a DIFFERENT prekey and
	 * not newer.
	 *
	 * THE ROLLBACK CASE, and it has its own code because it is the one an
	 * operator has to see. A stranger who replays a host's older, real,
	 * correctly-signed record is offering a key the host has moved on
	 * from -- and if that key has since leaked, accepting it is the whole
	 * attack. Nothing about the bytes is wrong, which is why the
	 * signature cannot catch it.
	 */
	FZN_PREKEY_ERR_ROLLBACK,
	/*
	 * A record naming a host that is NOT the one pinned.
	 *
	 * Distinct from a rollback because it is a distinct event: not this
	 * peer rotating a key, but a different peer entirely arriving under
	 * the same slot. `fzn_trust_adopt` refuses in the same shape and for
	 * the same reason.
	 */
	FZN_PREKEY_ERR_WRONG_HOST,
} fzn_prekey_err_t;

const char *fzn_prekey_err_str(fzn_prekey_err_t err);

/* A record, as a view over bytes the caller owns. Nothing is copied and
 * nothing is decoded twice: `fzn_prekey_open` checks the shape and hands back
 * pointers into the caller's buffer, so the bytes verified are the bytes
 * stored -- the same discipline `chain/` and `record/` use, and the reason
 * neither has a second transcript implementation to drift. */
typedef struct fzn_prekey_record {
	const uint8_t *bytes;
	const uint8_t *host;
	const uint8_t *prekey;
	uint64_t created_at;
} fzn_prekey_record_t;

/*
 * The canonical encoding, signed by the host over its own record.
 *
 * `created_at` is the host's clock and is NOT trusted for anything except
 * ordering two records from the SAME host. project.md sec 13b settled that a
 * clock does not gate admission here; what it does is let a receiver refuse a
 * replayed older prekey, which is a comparison between two of one host's own
 * statements rather than a judgement about freshness.
 */
fzn_prekey_err_t fzn_prekey_issue(const uint8_t host[FZN_PUBKEY_LEN],
                                   const uint8_t prekey[FZN_PREKEY_LEN], uint64_t created_at,
                                   const fzn_sign_ops_t *signer,
                                   uint8_t out[FZN_PREKEY_LEN_TOTAL]);

/* Shape only: length, version, object tag. No key is touched, so a
 * misaddressed or truncated blob is refused before any verification is
 * attempted -- which is what keeps a stranger's garbage cheap. */
fzn_prekey_err_t fzn_prekey_open(const uint8_t *bytes, size_t len, fzn_prekey_record_t *out);

/* The self-signature, under the host key the record itself names. See the
 * header comment: this proves authorship and not identity. */
fzn_prekey_err_t fzn_prekey_verify(fzn_prekey_record_t record, const fzn_sign_ops_t *verifier);

/*
 * A pinned peer: what a consumer keeps.
 *
 * `trust` carries the host key and how it arrived, so the anchor and its
 * provenance stay in the one type that already knows about both rather than
 * being copied into a second place that can disagree with it.
 */
typedef struct fzn_prekey_peer {
	fzn_trust_t trust;
	uint8_t prekey[FZN_PREKEY_LEN];
	uint64_t created_at;
} fzn_prekey_peer_t;

void fzn_prekey_peer_init(fzn_prekey_peer_t *peer);

/*
 * THE ACT. Verifies a record and pins it, or refuses.
 *
 * On an EMPTY peer this is first use: the record's host becomes the anchor,
 * with `source` recording whether the caller had confirmed the key out of
 * band (`FZN_TRUST_PINNED`) or is taking it on faith (`FZN_TRUST_ADOPTED`).
 * The distinction is not decoration -- it is the thing a consumer shows a
 * user who asks how this peer came to be trusted, and `trust/trust.h` exists
 * to keep it.
 *
 * On a peer ALREADY PINNED, exactly three outcomes and they are separate
 * codes because they are separate events:
 *
 *   - the same host offering a NEWER prekey: a rotation, accepted, and the
 *     stored prekey moves. `source` is not changed -- a rotation is not a new
 *     first use, and letting it upgrade an ADOPTED anchor to PINNED would let
 *     a peer launder its own provenance.
 *   - the same host offering the SAME prekey: FZN_PREKEY_OK and nothing
 *     moves, because a re-delivery of a record already held is ordinary and
 *     is not an event.
 *   - the same host offering a DIFFERENT prekey that is not newer:
 *     FZN_PREKEY_ERR_ROLLBACK. A real, correctly signed, older record replayed
 *     by anyone who saw it -- and if that prekey has since leaked, accepting
 *     it is the attack.
 *   - a DIFFERENT host: FZN_PREKEY_ERR_WRONG_HOST.
 *
 * REFUSED MEANS UNTOUCHED. A peer is not written at all unless the call
 * succeeds, so a caller that ignores the return value cannot end up half
 * re-pinned.
 */
fzn_prekey_err_t fzn_prekey_pin(fzn_prekey_peer_t *peer, fzn_prekey_record_t record,
                                 const fzn_sign_ops_t *verifier, fzn_trust_source_t source,
                                 uint64_t now);

#endif /* FZN_PREKEY_H */
