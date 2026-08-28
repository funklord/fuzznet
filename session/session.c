/* See session.h. */

#include "session.h"

#include "../constant_time/constant_time.h"

#include <string.h>

/*
 * Domain separation, sixteen bytes like every other label here, and distinct
 * from the KDF's own so that no input to one derivation can equal an input to
 * the other. `session/commitment.c` prepends its root label to whatever it is
 * handed, so a transcript beginning with this one can never collide with a
 * caller's transcript beginning with something else -- but only if this
 * differs, which is what the assertion in that file's spirit asks for here.
 */
static const char FZN_SESSION_LABEL[16] = "fuzznet-sess-v1\0";

/*
 * The directed label.
 *
 * DISTINCT FROM THE TRANSCRIPT'S, AND NOT LOAD-BEARING BY THE LIBRARY'S OWN
 * PATH -- which is worth saying, because a mutation swapping this for
 * FZN_SESSION_LABEL fails nothing and a reader who found that would
 * reasonably delete one of the two.
 *
 * The reason it fails nothing is an OUTER label nobody remembers:
 * `fzn_commitment_derive_root` prepends its own `fuzznet-kdf-v2` to whatever
 * it is handed, so a transcript reaching the hash always begins with that,
 * while `chain_for` below calls the hash directly. The two inputs differ in
 * their first sixteen bytes whatever this constant says.
 *
 * WHERE IT DOES MATTER is the path this header advertises: a caller may build
 * a transcript with `fzn_session_transcript` and hash it itself, for its own
 * reasons, without going through the KDF. Then the transcript begins with
 * FZN_SESSION_LABEL and a chain input begins with this one, and the two are
 * separated by exactly this difference and nothing else.
 *
 * So it is conditional defence for a supported composition rather than a
 * property of the code as it stands. Recorded that way because the general
 * shape has bitten this file twice today: A DOMAIN-SEPARATION CLAIM MUST SAY
 * AT WHICH BOUNDARY IT HOLDS, since an outer label upstream can be doing the
 * work the inner one is being credited with.
 */
static const char FZN_SESSION_DIR_LABEL[16] = "fuzznet-dir-v1\0\0";

_Static_assert(sizeof(FZN_SESSION_LABEL) == 16,
               "the session label must be the fixed width the layout assumes");
_Static_assert(sizeof(FZN_SESSION_DIR_LABEL) == sizeof(FZN_SESSION_LABEL),
               "the two labels must be one length, or their inputs can overlap");
_Static_assert(FZN_SESSION_TRANSCRIPT_LEN == 177u,
               "the transcript's length has moved; every peer that derives a root must agree");

fzn_session_err_t fzn_session_transcript(const uint8_t self_identity[FZN_SESSION_IDENTITY_LEN],
                                         const uint8_t self_prekey[FZN_AGREE_PUBLIC_LEN],
                                         const uint8_t peer_identity[FZN_SESSION_IDENTITY_LEN],
                                         const uint8_t peer_prekey[FZN_AGREE_PUBLIC_LEN],
                                         const uint8_t shared[FZN_AGREE_SHARED_LEN],
                                         uint8_t out[FZN_SESSION_TRANSCRIPT_LEN])
{
	const uint8_t *first_id;
	const uint8_t *first_pk;
	const uint8_t *second_id;
	const uint8_t *second_pk;
	int order;
	size_t at = 0;

	if (!self_identity || !self_prekey || !peer_identity || !peer_prekey || !shared || !out)
		return FZN_SESSION_ERR_MALFORMED;

	/*
	 * THE CANONICAL ORDER, and it is a plain memcmp rather than a
	 * constant-time compare on purpose.
	 *
	 * Both identities are public keys that travel in the clear, so there
	 * is no secret in the comparison and nothing for a timing channel to
	 * carry. `constant_time.h` argues that reaching for the careful thing
	 * everywhere is how it stops being possible to see which uses matter;
	 * this is one of the uses that does not.
	 *
	 * The result decides the LAYOUT, not an accept or a reject, which is
	 * the other half of why it is not a security comparison.
	 */
	order = memcmp(self_identity, peer_identity, FZN_SESSION_IDENTITY_LEN);
	if (order == 0)
		return FZN_SESSION_ERR_SELF;

	if (order < 0) {
		first_id = self_identity;
		first_pk = self_prekey;
		second_id = peer_identity;
		second_pk = peer_prekey;
	} else {
		first_id = peer_identity;
		first_pk = peer_prekey;
		second_id = self_identity;
		second_pk = self_prekey;
	}

	memcpy(out + at, FZN_SESSION_LABEL, sizeof(FZN_SESSION_LABEL));
	at += sizeof(FZN_SESSION_LABEL);
	out[at++] = (uint8_t)FZN_SESSION_TRANSCRIPT_VERSION;

	/* Each identity immediately followed by its own prekey.
	 *
	 * READABILITY, NOT SECURITY, AND THE FIRST DRAFT CLAIMED OTHERWISE.
	 * It said the interleaving stops a transcript being reassembled by
	 * pairing one host's identity with the other's key. A mutation
	 * regrouping this as identity|identity|prekey|prekey failed nothing,
	 * and it should not have: the CANONICAL ORDER above is what makes the
	 * assignment unambiguous, since `first_*` is always the lower identity
	 * and its prekey whichever order the four fields are laid down in.
	 * Interleaved because it reads as two hosts rather than two lists;
	 * kept, and no longer credited with a property the sort provides. */
	memcpy(out + at, first_id, FZN_SESSION_IDENTITY_LEN);
	at += FZN_SESSION_IDENTITY_LEN;
	memcpy(out + at, first_pk, FZN_AGREE_PUBLIC_LEN);
	at += FZN_AGREE_PUBLIC_LEN;
	memcpy(out + at, second_id, FZN_SESSION_IDENTITY_LEN);
	at += FZN_SESSION_IDENTITY_LEN;
	memcpy(out + at, second_pk, FZN_AGREE_PUBLIC_LEN);
	at += FZN_AGREE_PUBLIC_LEN;

	memcpy(out + at, shared, FZN_AGREE_SHARED_LEN);
	at += FZN_AGREE_SHARED_LEN;

	/* The one place a layout error would be silent: a transcript short by
	 * a field still hashes, and both peers making the same mistake still
	 * agree. The count is what turns that into a build-time or a
	 * test-time failure rather than a protocol nobody can change later. */
	return (at == FZN_SESSION_TRANSCRIPT_LEN) ? FZN_SESSION_OK : FZN_SESSION_ERR_MALFORMED;
}

fzn_session_err_t fzn_session_establish(const fzn_agree_secret_t *self_prekey,
                                        const fzn_agree_ops_t *agree,
                                        const fzn_hash_ops_t *hash,
                                        const uint8_t self_identity[FZN_SESSION_IDENTITY_LEN],
                                        const uint8_t peer_identity[FZN_SESSION_IDENTITY_LEN],
                                        const uint8_t peer_prekey[FZN_AGREE_PUBLIC_LEN],
                                        uint8_t key_out[FZN_AEAD_KEY_LEN],
                                        uint8_t commitment_key_out[FZN_COMMITMENT_KEY_LEN])
{
	uint8_t shared[FZN_AGREE_SHARED_LEN];
	uint8_t transcript[FZN_SESSION_TRANSCRIPT_LEN];
	const uint8_t *self_pk;
	fzn_session_err_t err = FZN_SESSION_OK;
	fzn_agree_err_t aerr;

	if (!self_prekey || !self_identity || !peer_identity || !peer_prekey || !key_out
	    || !commitment_key_out)
		return FZN_SESSION_ERR_MALFORMED;

	/* The caller's own prekey public comes from the secret rather than
	 * from an argument, so a host cannot hash a public key that does not
	 * belong to the secret it is agreeing with -- which would derive a
	 * root the peer cannot reach and present as a peer that went silent. */
	self_pk = fzn_agree_secret_public(self_prekey);
	if (!self_pk)
		return FZN_SESSION_ERR_AGREE;

	aerr = fzn_agree_shared(self_prekey, agree, peer_prekey, shared);
	if (aerr != FZN_AGREE_OK)
		return FZN_SESSION_ERR_AGREE;

	err = fzn_session_transcript(self_identity, self_pk, peer_identity, peer_prekey, shared,
	                             transcript);
	if (err != FZN_SESSION_OK)
		goto out;

	if (fzn_commitment_derive_root(hash, transcript, sizeof(transcript), key_out,
	                               commitment_key_out) != FZN_COMMITMENT_OK) {
		err = FZN_SESSION_ERR_HASH;
		goto out;
	}

out:
	/* BOTH ARE WIPED ON EVERY PATH. The shared secret and the transcript
	 * are the two things an attacker most wants and a caller has least
	 * reason to keep: the transcript contains the shared secret, so
	 * forgetting one and not the other forgets neither.
	 *
	 * NOT OBSERVABLE THROUGH THIS API, and known to be so -- both are
	 * locals, so a mutation deleting either fails nothing. What they
	 * defend against is the stack being read afterwards: a later call
	 * reusing the frame, a core dump, a debugger. Recorded as
	 * construction-guaranteed-unobservable rather than left looking
	 * tested, which is the third such line found in this session and the
	 * third time the honest answer was to say so rather than to invent a
	 * test that would only assert the compiler's layout. */
	fzn_wipe(shared, sizeof(shared));
	fzn_wipe(transcript, sizeof(transcript));
	return err;
}

/* One direction's chain key: label | from | to | root. Static because the
 * only thing that may call it is the function below, which calls it twice
 * with the identities swapped -- and that swap is the whole mechanism. */
static fzn_session_err_t chain_for(const fzn_hash_ops_t *hash,
                                    const uint8_t key[FZN_AEAD_KEY_LEN],
                                    const uint8_t from[FZN_SESSION_IDENTITY_LEN],
                                    const uint8_t to[FZN_SESSION_IDENTITY_LEN],
                                    uint8_t out[FZN_CHAIN_KEY_LEN])
{
	uint8_t input[sizeof(FZN_SESSION_DIR_LABEL) + (2u * FZN_SESSION_IDENTITY_LEN)
	              + FZN_AEAD_KEY_LEN];
	size_t at = 0;
	fzn_session_err_t err = FZN_SESSION_OK;

	memcpy(input + at, FZN_SESSION_DIR_LABEL, sizeof(FZN_SESSION_DIR_LABEL));
	at += sizeof(FZN_SESSION_DIR_LABEL);
	memcpy(input + at, from, FZN_SESSION_IDENTITY_LEN);
	at += FZN_SESSION_IDENTITY_LEN;
	memcpy(input + at, to, FZN_SESSION_IDENTITY_LEN);
	at += FZN_SESSION_IDENTITY_LEN;
	memcpy(input + at, key, FZN_AEAD_KEY_LEN);
	at += FZN_AEAD_KEY_LEN;

	if (!hash->hash(hash->ctx, out, FZN_CHAIN_KEY_LEN, input, at)) {
		fzn_wipe(out, FZN_CHAIN_KEY_LEN);
		err = FZN_SESSION_ERR_HASH;
	}

	/* The input holds the session root and is wiped whichever way this
	 * went. A caller that got a refusal must not be able to find the root
	 * on the stack behind it. */
	fzn_wipe(input, sizeof(input));
	return err;
}

fzn_session_err_t fzn_session_chains(const fzn_hash_ops_t *hash,
                                     const uint8_t key[FZN_AEAD_KEY_LEN],
                                     const uint8_t self_identity[FZN_SESSION_IDENTITY_LEN],
                                     const uint8_t peer_identity[FZN_SESSION_IDENTITY_LEN],
                                     uint8_t send_chain_out[FZN_CHAIN_KEY_LEN],
                                     uint8_t recv_chain_out[FZN_CHAIN_KEY_LEN])
{
	fzn_session_err_t err;

	if (!key || !self_identity || !peer_identity || !send_chain_out || !recv_chain_out)
		return FZN_SESSION_ERR_MALFORMED;
	if (!hash || !hash->hash)
		return FZN_SESSION_ERR_HASH;
	/* Refused for the same reason the transcript refuses it: a host has
	 * no direction to itself, and the two chains below would be one. */
	if (memcmp(self_identity, peer_identity, FZN_SESSION_IDENTITY_LEN) == 0)
		return FZN_SESSION_ERR_SELF;

	/* SEND IS (self -> peer) AND RECEIVE IS (peer -> self), which is what
	 * makes the two sides agree without saying which they are: this
	 * host's send chain and the other host's receive chain are both keyed
	 * (self, peer) and are therefore the same key. */
	err = chain_for(hash, key, self_identity, peer_identity, send_chain_out);
	if (err != FZN_SESSION_OK)
		return err;
	err = chain_for(hash, key, peer_identity, self_identity, recv_chain_out);
	if (err != FZN_SESSION_OK) {
		/* One of the two failed, so neither is usable: a caller left
		 * holding a send chain and no receive chain would ratchet
		 * forward into a conversation it cannot hear. */
		fzn_wipe(send_chain_out, FZN_CHAIN_KEY_LEN);
		return err;
	}

	return FZN_SESSION_OK;
}

/* See session.h. No `default:`, so -Wswitch names a code added and not
 * rendered here. */
const char *fzn_session_err_str(fzn_session_err_t err)
{
	switch (err) {
	case FZN_SESSION_OK:
		return "ok";
	case FZN_SESSION_ERR_MALFORMED:
		return "malformed argument";
	case FZN_SESSION_ERR_SELF:
		return "both identities are the same key";
	case FZN_SESSION_ERR_AGREE:
		return "key agreement refused or unavailable";
	case FZN_SESSION_ERR_HASH:
		return "hash refused or absent";
	}

	return "unknown";
}
