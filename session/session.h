#ifndef FZN_SESSION_H
#define FZN_SESSION_H

/*
 * The session transcript: what two hosts hash to agree on a root key.
 *
 * `session/commitment.h` derives an AEAD key and a commitment key from a
 * transcript and deliberately declines to say what the transcript holds --
 * "a protocol decision that depends on the session model". This file is that
 * decision, made, for the model project.md sec 4.5 settled.
 *
 * WHY IT IS A FUNCTION AND NOT A PARAGRAPH. Two peers who disagree about the
 * transcript derive different keys and fail to talk. That is the correct
 * failure and it is also an expensive one to debug, and it is entirely
 * avoidable: if both sides call the same builder, there is no layout for
 * them to disagree about. `commitment.h`'s boundary is unchanged -- the
 * primitive still hashes what it is handed -- and this is a named model
 * beside it rather than a restriction on it.
 *
 * THE MODEL: TWO ROTATING PREKEYS. Each host publishes a signed prekey
 * (`prekey/prekey.h`) and keeps its secret across restarts. A session's
 * agreement is between those two prekeys, and the root is a hash over both
 * identities, both prekeys and the shared secret.
 *
 * WHAT THAT BUYS, AND WHAT IT DOES NOT:
 *
 *   - Forward secrecy at ROTATION granularity, from either side. Once either
 *     host rotates and destroys its old prekey secret, every session root
 *     derived from it is unrecoverable -- including by an attacker who later
 *     obtains both identity keys. That is the property the whole design
 *     exists for, and it is exactly as strong as `fzn_agree_secret_install`
 *     actually destroying what it replaces.
 *   - Reboot survivability. A prekey secret is persisted on purpose, so a
 *     host that restarts can still open traffic sealed to it while it was
 *     away. That is what ruled out a per-session ephemeral as the ONLY
 *     deletable material: an ephemeral vanishes with the process, and the
 *     messages queued for a host that rebooted vanish with it.
 *   - NOT per-message forward secrecy, which is `ratchet/`'s, seeded from
 *     the root this produces. The two compose: rotation bounds what a
 *     compromise reaches back to, and the ratchet bounds what it reaches
 *     back to within that.
 *   - NOT protection against a compromise BEFORE the next rotation. Traffic
 *     since the last rotation is readable to whoever takes the prekey
 *     secret. Rotation cadence is the knob and it is the consumer's.
 *
 * THE EPHEMERAL VARIANT IS BELOW, and it needs no wire change. See
 * `fzn_session_establish_initiator`.
 *
 * (Historical note, kept because the reasoning was wrong in a useful way.)
 * NO SENDER EPHEMERAL, and it is a live question rather than a closed one.
 * An initiator contributing a per-session ephemeral would protect against
 * ITS OWN later compromise immediately rather than at the next rotation, and
 * would cost nothing in reboot terms because the sender can always
 * re-handshake. It needs the ephemeral public key on the wire and this
 * library has no handshake message to carry one. Raised in sec 20 rather
 * than assumed either way; adding it later changes the transcript, which
 * changes every root, which is why the version byte below exists.
 */

#include <stddef.h>
#include <stdint.h>

#include "agree.h"
#include "commitment.h"
#include "../ratchet/ratchet.h" /* FZN_CHAIN_KEY_LEN */

/*
 * A long-term identity key, as this module sees it.
 *
 * REPEATED RATHER THAN INCLUDED FROM `chain/chain.h`, which is where
 * FZN_PUBKEY_LEN lives. `session/` includes nothing from `chain/` today and
 * that independence is the point: `record.h` separates authenticity from
 * authorisation because "a consumer that authorises by capability chain and
 * one that authorises by local uid both need the first and neither needs the
 * other's answer". A session module that dragged in the capability layer to
 * learn what 32 means would undo that for a number.
 *
 * The tether is `session/test/session_test.c`, which asserts the two agree.
 * Same arrangement `chain/test/manifest_test.c` uses for
 * FZN_MANIFEST_MAX_PAIRS: the check is `make test`, not `make`.
 */
#define FZN_SESSION_IDENTITY_LEN 32u

/*
 * The transcript's own version, INSIDE the transcript.
 *
 * Not the library's version and not a wire field -- it is hashed, so two
 * peers built against different transcript layouts derive different roots
 * and fail to talk, rather than appearing to agree. That is the same
 * argument `session/commitment.c`'s labels make, and it is why adding a
 * sender ephemeral later is safe to do: bump this, and old and new peers
 * stop agreeing loudly instead of quietly.
 */
#define FZN_SESSION_TRANSCRIPT_VERSION 1u

/* label | version | identity | ITS prekey | identity | ITS prekey | shared,
 * the two hosts ordered canonically -- see `fzn_session_transcript` below.
 *
 * THIS LINE READ `identity | identity | prekey | prekey` UNTIL 2026-09-01,
 * which is not what the code writes and never was: it is the REGROUPING that
 * session.c names as the rejected alternative. It mattered because this is
 * the header a consumer implements interop FROM, and a peer building a
 * transcript in that order derives a different root and simply cannot talk --
 * the exact outcome the preamble above warns about. Nothing executable had
 * ever read it; `session/test/session_kat_test.c` does now. */
#define FZN_SESSION_TRANSCRIPT_LEN                                            \
	(16u + 1u + (2u * FZN_SESSION_IDENTITY_LEN) + (2u * FZN_AGREE_PUBLIC_LEN) \
	 + FZN_AGREE_SHARED_LEN)

typedef enum fzn_session_err {
	FZN_SESSION_OK = 0,
	FZN_SESSION_ERR_MALFORMED,
	/*
	 * The two identities are the same key.
	 *
	 * ITS OWN CODE BECAUSE IT IS ITS OWN MISTAKE, and because refusing it
	 * is what keeps the ordering below total. A host establishing a
	 * session with itself has nothing to agree about, and the canonical
	 * order has no tie-break, so this is refused rather than resolved.
	 */
	FZN_SESSION_ERR_SELF,
	/* The agreement or hash seam refused, or was absent. Carried out
	 * rather than folded into MALFORMED, because a caller must be able to
	 * tell a peer offering a degenerate key from its own bug. */
	FZN_SESSION_ERR_AGREE,
	FZN_SESSION_ERR_HASH,
} fzn_session_err_t;

const char *fzn_session_err_str(fzn_session_err_t err);

/*
 * Builds the transcript.
 *
 * ORDERED CANONICALLY BY IDENTITY, not by role, BECAUSE THIS RELATIONSHIP IS
 * SYMMETRIC. The two hosts sort their identity keys and lay the pairs down in
 * that order, so both build byte-identical transcripts without negotiating
 * who is the initiator.
 *
 * THE QUALIFIER MATTERS AND THE FIRST DRAFT LEFT IT OUT, which fuzzypickles
 * caught by contrasting their two transcripts. The rule is not "order
 * canonically". It is:
 *
 *   - canonically, when the relationship is SYMMETRIC and has no roles at
 *     derivation time -- as here, where a role nobody signed would be a thing
 *     an attacker can flip, and where two sides ordering differently derive
 *     different keys and simply cannot talk;
 *   - BY ROLE, when the roles are real, asymmetric, and covered by what is
 *     signed -- a directed message, where sender-then-recipient is the point
 *     and flipping them must change the key.
 *
 * Their `prekey_channel.c` is the first kind and sorts, as this does; their
 * `crypto_msg.c` is the second and does not, correctly. `fzn_session_chains`
 * below is the second kind inside this very file, which is why the
 * distinction is stated here rather than left as a preference.
 *
 * `self_*` and `peer_*` are named from the caller's point of view precisely
 * because the OUTPUT does not depend on which is which -- that is the
 * property, and naming them "first" and "second" would invite a caller to
 * supply them already ordered and get it wrong.
 *
 * The prekeys travel WITH their identities rather than in a block of their
 * own. READABILITY, NOT SECURITY -- and this paragraph claimed otherwise until
 * 2026-09-01, after session.c had already retracted it. What stops a
 * transcript being reassembled by pairing one host's identity with the other's
 * prekey is the CANONICAL ORDER above: `first` is the lower identity and its
 * own prekey whichever order the four fields are laid down in. A mutation
 * regrouping them failed nothing at the time, and it should not have.
 *
 * It fails now, for a different reason worth keeping separate: the layout is
 * PROTOCOL, so session_kat_test refuses any change to it whether or not the
 * change costs a security property. A correction made in one file and not in
 * the header beside it is how a retracted claim outlives its retraction.
 *
 * `created_at` from the prekey record is deliberately NOT included. A
 * rotation changes the prekey's public bytes, which already changes the
 * transcript and therefore the root; adding a timestamp would bind two
 * clocks together for no property the key does not already give.
 */
fzn_session_err_t fzn_session_transcript(const uint8_t self_identity[FZN_SESSION_IDENTITY_LEN],
                                         const uint8_t self_prekey[FZN_AGREE_PUBLIC_LEN],
                                         const uint8_t peer_identity[FZN_SESSION_IDENTITY_LEN],
                                         const uint8_t peer_prekey[FZN_AGREE_PUBLIC_LEN],
                                         const uint8_t shared[FZN_AGREE_SHARED_LEN],
                                         uint8_t out[FZN_SESSION_TRANSCRIPT_LEN]);

/*
 * Agrees, builds the transcript, derives the root, and forgets everything in
 * between.
 *
 * THE WHOLE POINT IS THE FORGETTING. The shared secret and the transcript
 * are the two things an attacker most wants and the two a caller has least
 * reason to keep, so this exists so that a consumer never holds either. A
 * caller that wants the transcript for its own reasons can build it above;
 * a caller that just wants a session should not have to know the shape of
 * what it must not retain.
 *
 * The prekey secret stays inside `fzn_agree_secret_t` throughout and is
 * never copied out.
 *
 * THIS IS THE VARIANT WITHOUT A SENDER EPHEMERAL, AND THE NAME DOES NOT SAY
 * SO. `fzn_session_establish_initiator` and `_responder` below are the pair
 * that adds one, and a caller wanting the stronger property has to know they
 * exist to reach them -- this function is the obvious name and is the weaker
 * protocol.
 *
 * WHAT THE DIFFERENCE IS, so the choice is made rather than defaulted: both
 * derive a real AEAD key and a real commitment key, and nothing fails if this
 * one is used. What the ephemeral buys is that a compromise of the
 * initiator's own long-term material stops opening recorded traffic
 * IMMEDIATELY rather than at the next prekey rotation. With this function the
 * window is a rotation interval; with the pair below it is one session.
 *
 * Written here rather than only at the transcript above, where it was, because
 * a caller choosing an entry point is looking at this line and not at a
 * paragraph a hundred and fifty lines earlier. Found when a consumer began
 * building a key schedule against this header.
 */
fzn_session_err_t fzn_session_establish(const fzn_agree_secret_t *self_prekey,
                                        const fzn_agree_ops_t *agree,
                                        const fzn_hash_ops_t *hash,
                                        const uint8_t self_identity[FZN_SESSION_IDENTITY_LEN],
                                        const uint8_t peer_identity[FZN_SESSION_IDENTITY_LEN],
                                        const uint8_t peer_prekey[FZN_AGREE_PUBLIC_LEN],
                                        uint8_t key_out[FZN_AEAD_KEY_LEN],
                                        uint8_t commitment_key_out[FZN_COMMITMENT_KEY_LEN]);

/*
 * The two ratchet chain keys a session seeds, one per DIRECTION.
 *
 * WHY THIS EXISTS: THE RATCHET WAS UNWIRED. `ratchet/ratchet.h` is a
 * symmetric key chain that takes a seed from its caller, and until this
 * function nothing in this library gave it one -- measured, not assumed:
 * outside its own tests, `fzn_ratchet_init` had no callers at all. So the
 * library had rotation-granularity forward secrecy from the session root and
 * per-message forward secrecy from the ratchet, and no path between them.
 *
 * DIRECTED, NOT CANONICAL, WHICH IS THE OPPOSITE OF THE TRANSCRIPT ABOVE AND
 * IS THE SAME RULE. A message goes one way. A-to-B and B-to-A must not share
 * a chain, or a message replayed back at its sender decrypts under the key
 * the sender is expecting to receive under -- and the direction IS a real
 * role, agreed by both sides from the frame, so ordering by it is correct
 * where ordering the transcript by it would not have been.
 *
 * Both sides compute both keys and agree on them: A's send chain is keyed
 * (A, B) and B's receive chain is keyed (A, B) too, so they match without
 * either side having to say which it is.
 *
 * SEEDS, NOT STATE. What comes back is two chain keys for the caller to hand
 * to `fzn_ratchet_init`. This module holds no ratchet and no sequence
 * numbers, because a chain's position is exactly the state `ratchet/` says
 * belongs to the caller -- and a session that owned it would have to be
 * persisted, which is the storage this library does not do.
 */
fzn_session_err_t fzn_session_chains(const fzn_hash_ops_t *hash,
                                     const uint8_t key[FZN_AEAD_KEY_LEN],
                                     const uint8_t self_identity[FZN_SESSION_IDENTITY_LEN],
                                     const uint8_t peer_identity[FZN_SESSION_IDENTITY_LEN],
                                     uint8_t send_chain_out[FZN_CHAIN_KEY_LEN],
                                     uint8_t recv_chain_out[FZN_CHAIN_KEY_LEN]);

/*
 * ---- the ephemeral variant ---------------------------------------------
 *
 * A session that ALSO mixes in a per-session key the initiator throws away.
 *
 * WHAT IT ADDS. The base session above is bounded by rotation: a compromise
 * of either host discloses everything back to its last prekey rotation. With
 * an ephemeral, an initiator's later compromise discloses nothing at all
 * about a session it has finished, because the material is gone the moment
 * the handshake completes. The responder's exposure is unchanged and still
 * bounded by rotation, since its prekey is the thing that must survive a
 * reboot.
 *
 * IT NEEDS NO WIRE CHANGE, WHICH IS WHY IT IS HERE AND NOT WAITING. The
 * ephemeral public key cannot travel in a frame head -- the head is a fixed
 * 91 bytes generated from `wire/frame.situ` -- and it cannot take a new
 * `fzn_kind`, because that enum is a CLOSED SET OF FOUR settled by the
 * copyright holder 2026-08-26, where "adding to it is a conversation rather
 * than an edit". It does not need either: a consumer establishes the base
 * session first, which both sides can derive from published prekeys alone,
 * and sends the ephemeral inside a SEALED PAYLOAD, where `frame.situ` says
 * this library never looks. Delivery is the consumer's; the derivation is
 * ours.
 *
 * ROLE-ORDERED, DELIBERATELY, WHICH IS THE OPPOSITE OF THE BASE TRANSCRIPT.
 * There is a real asymmetry here -- one host owns the ephemeral and the other
 * does not -- so by the rule stated above, ordering by role is correct where
 * ordering the base transcript by role would not have been. It is spelled as
 * two functions rather than one with a flag, so that a caller states which it
 * is rather than passing a boolean it can get backwards.
 *
 * VERSION 2 IN THE TRANSCRIPT. A host doing the ephemeral exchange and one
 * doing the base exchange derive different roots and fail to talk, loudly,
 * rather than one of them silently getting less than it thought. That is what
 * the version byte was put there for.
 */
#define FZN_SESSION_TRANSCRIPT_V2 2u

/* label | version | initiator id | initiator prekey | responder id |
 * responder prekey | ephemeral public | prekey shared | ephemeral shared */
#define FZN_SESSION_TRANSCRIPT_V2_LEN                                              \
	(16u + 1u + (2u * FZN_SESSION_IDENTITY_LEN) + (3u * FZN_AGREE_PUBLIC_LEN) \
	 + (2u * FZN_AGREE_SHARED_LEN))

/*
 * The initiator's half.
 *
 * `ephemeral` is a secret this host has just minted and MUST DESTROY once
 * the session is established -- that destruction is the entire property, and
 * this function cannot do it because the caller may still need the public
 * half to send. `fzn_agree_secret_wipe` is the call, and a caller that skips
 * it has the base session's guarantees and a longer transcript.
 *
 * The public half the peer must receive is `fzn_agree_secret_public` of that
 * same secret. It is not returned here, because a caller that has to ask for
 * it is a caller that has it.
 */
fzn_session_err_t fzn_session_establish_initiator(
        const fzn_agree_secret_t *self_prekey, const fzn_agree_secret_t *ephemeral,
        const fzn_agree_ops_t *agree, const fzn_hash_ops_t *hash,
        const uint8_t self_identity[FZN_SESSION_IDENTITY_LEN],
        const uint8_t peer_identity[FZN_SESSION_IDENTITY_LEN],
        const uint8_t peer_prekey[FZN_AGREE_PUBLIC_LEN], uint8_t key_out[FZN_AEAD_KEY_LEN],
        uint8_t commitment_key_out[FZN_COMMITMENT_KEY_LEN]);

/*
 * The responder's half. `peer_ephemeral` is the public key that arrived; this
 * host mixes it with its own prekey secret, which is why the responder needs
 * no ephemeral of its own and why a reboot does not lose the session.
 */
/* A REFUSAL WRITES NOTHING INTO `key_out` OR `commitment_key_out`, at all
 * three entry points. Measured 2026-09-02 while testing that a refused key
 * agreement stops establishment: on refusal both buffers hold exactly what
 * the caller left in them.
 *
 * It is written down because it is a security property and the alternative
 * looks equally reasonable. A WIPED buffer is all-zero, which looks like a
 * key; an untouched one looks like whatever the caller had, so a caller that
 * ignores the return code cannot mistake a refusal for a session. Nothing
 * partially derived is ever left behind either way. */
fzn_session_err_t fzn_session_establish_responder(
        const fzn_agree_secret_t *self_prekey, const fzn_agree_ops_t *agree,
        const fzn_hash_ops_t *hash, const uint8_t self_identity[FZN_SESSION_IDENTITY_LEN],
        const uint8_t peer_identity[FZN_SESSION_IDENTITY_LEN],
        const uint8_t peer_prekey[FZN_AGREE_PUBLIC_LEN],
        const uint8_t peer_ephemeral[FZN_AGREE_PUBLIC_LEN],
        uint8_t key_out[FZN_AEAD_KEY_LEN], uint8_t commitment_key_out[FZN_COMMITMENT_KEY_LEN]);

#endif /* FZN_SESSION_H */
