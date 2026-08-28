/* See ratchet.h. */

#include "ratchet.h"

#include "../constant_time/constant_time.h"

#include <string.h>

/*
 * Domain separation. Sixteen bytes, like every other label in this library,
 * and prepended to a fixed-length input so nothing else here can produce the
 * same bytes.
 *
 * The version digit is in the label for the reason session/commitment.c
 * gives: if the step's shape ever changes, changing the label makes old and
 * new peers derive different keys and fail to talk, which is the correct
 * failure. Two peers agreeing on a key by hashing different things is the
 * one that is found months later.
 */
static const char FZN_RATCHET_LABEL[16] = "fuzznet-ratchet1";

_Static_assert(sizeof(FZN_RATCHET_LABEL) == 16,
               "the ratchet label must be the fixed width the derivation assumes");

/* Both halves out of one hash. */
#define FZN_RATCHET_DERIVED_LEN (FZN_MESSAGE_KEY_LEN + FZN_CHAIN_KEY_LEN)

fzn_ratchet_err_t fzn_ratchet_derive(const fzn_hash_ops_t *hash,
                                      const uint8_t chain_key[FZN_CHAIN_KEY_LEN],
                                      uint8_t message_key_out[FZN_MESSAGE_KEY_LEN],
                                      uint8_t next_chain_key_out[FZN_CHAIN_KEY_LEN])
{
	uint8_t input[sizeof(FZN_RATCHET_LABEL) + FZN_CHAIN_KEY_LEN];
	uint8_t derived[FZN_RATCHET_DERIVED_LEN];
	fzn_ratchet_err_t err = FZN_RATCHET_OK;

	if (!hash || !hash->hash || !chain_key || !message_key_out || !next_chain_key_out)
		return FZN_RATCHET_ERR_MALFORMED;

	memcpy(input, FZN_RATCHET_LABEL, sizeof(FZN_RATCHET_LABEL));
	memcpy(input + sizeof(FZN_RATCHET_LABEL), chain_key, FZN_CHAIN_KEY_LEN);

	if (!hash->hash(hash->ctx, derived, sizeof(derived), input, sizeof(input))) {
		err = FZN_RATCHET_ERR_HASH;
		goto out;
	}

	/* BOTH OUTPUTS COMPUTED BEFORE EITHER IS WRITTEN, which is what makes
	 * `derive(k, mk, k)` and `derive(k, k, next)` correct. The input has
	 * already been copied out of `chain_key` above, so writing either
	 * output cannot disturb the other or the source. Without this the
	 * in-place form -- the natural way to spell "advance this chain" in a
	 * library whose state the caller owns -- would corrupt its own input
	 * and surface as a decryption failure a long way from here. */
	memcpy(message_key_out, derived, FZN_MESSAGE_KEY_LEN);
	memcpy(next_chain_key_out, derived + FZN_MESSAGE_KEY_LEN, FZN_CHAIN_KEY_LEN);

out:
	fzn_wipe(derived, sizeof(derived));
	fzn_wipe(input, sizeof(input));
	return err;
}

void fzn_ratchet_init(fzn_ratchet_chain_t *chain, const uint8_t key[FZN_CHAIN_KEY_LEN],
                      uint64_t seq)
{
	if (!chain)
		return;
	memset(chain, 0, sizeof(*chain));
	if (key)
		memcpy(chain->key, key, FZN_CHAIN_KEY_LEN);
	chain->seq = seq;
}

void fzn_ratchet_wipe(fzn_ratchet_chain_t *chain)
{
	if (!chain)
		return;
	fzn_wipe(chain->key, sizeof(chain->key));
	chain->seq = 0;
}

fzn_ratchet_err_t fzn_ratchet_advance(const fzn_hash_ops_t *hash,
                                       const fzn_ratchet_chain_t *from, uint64_t target_seq,
                                       uint8_t message_key_out[FZN_MESSAGE_KEY_LEN],
                                       fzn_ratchet_chain_t *to, uint8_t *skipped_out,
                                       size_t skipped_cap, size_t *skipped_count,
                                       size_t *dropped)
{
	/* WORKED ON A COPY AND WRITTEN OUT AT THE END, so `to` is untouched
	 * unless the whole call succeeds. A caller left holding a position
	 * that is neither the old one nor a usable new one has no way back:
	 * the peer's position has not moved and this one's is a number no
	 * message will ever name. */
	fzn_ratchet_chain_t work;
	uint8_t message_key[FZN_MESSAGE_KEY_LEN];
	uint64_t jump;
	uint64_t i;
	size_t kept = 0;
	size_t lost = 0;
	fzn_ratchet_err_t err = FZN_RATCHET_OK;

	if (!hash || !from || !to || !message_key_out)
		return FZN_RATCHET_ERR_MALFORMED;
	/* THE REFUSAL THAT IS THE WHOLE DESIGN. Advancing a live chain in one
	 * step is how a forged frame permanently ends a sender's delivery --
	 * ratchet.h has the trace. Refused rather than documented against,
	 * because a rule that says "verify before you commit" holds until
	 * somebody writes the caller that does not. */
	if (to == from)
		return FZN_RATCHET_ERR_IN_PLACE;
	if (skipped_cap > 0u && !skipped_out)
		return FZN_RATCHET_ERR_MALFORMED;
	if (!skipped_count != !skipped_out)
		return FZN_RATCHET_ERR_MALFORMED;
	if (skipped_out && !dropped)
		return FZN_RATCHET_ERR_MALFORMED;

	/* BEHIND IS ITS OWN ANSWER AND IS NOT AN ERROR IN THE ORDINARY SENSE.
	 * A chain moves one way, so this is what a duplicate or a replay looks
	 * like from inside -- ordinary weather on a datagram transport, and a
	 * caller that treats it as an intrusion will alarm on it hourly. */
	if (target_seq < from->seq)
		return FZN_RATCHET_ERR_BEHIND;

	jump = target_seq - from->seq;
	/* THE SAFETY VALVE. The number of derivations below is whatever
	 * sequence number a stranger wrote in a header, so without this a
	 * ~40-byte message buys an unbounded loop. Refused rather than
	 * clamped, so a caller can see the size of what it declined. */
	if (jump > (uint64_t)FZN_RATCHET_MAX_ADVANCE)
		return FZN_RATCHET_ERR_TOO_FAR;

	work = *from;

	/* The keys for the sequence numbers being jumped over. Handed back
	 * rather than discarded, because a message that arrives after the
	 * chain has passed it can never be opened again and "late" is not
	 * exceptional on this transport. */
	for (i = 0; i < jump; i++) {
		err = fzn_ratchet_derive(hash, work.key, message_key, work.key);
		if (err != FZN_RATCHET_OK)
			goto out;
		if (skipped_out) {
			if (kept < skipped_cap) {
				memcpy(skipped_out + (kept * FZN_MESSAGE_KEY_LEN), message_key,
				       FZN_MESSAGE_KEY_LEN);
				kept++;
			} else {
				lost++;
			}
		}
		work.seq++;
	}

	err = fzn_ratchet_derive(hash, work.key, message_key, work.key);
	if (err != FZN_RATCHET_OK)
		goto out;
	work.seq++;

	memcpy(message_key_out, message_key, FZN_MESSAGE_KEY_LEN);
	*to = work;
	if (skipped_count)
		*skipped_count = kept;
	if (dropped)
		*dropped = lost;

out:
	/* `work` holds a chain key on every path, including the failing one,
	 * and it is a live secret rather than an intermediate. `message_key`
	 * likewise: on success a copy has gone to the caller, and the copy
	 * here is one more place it lives than it needs to. */
	fzn_wipe(message_key, sizeof(message_key));
	fzn_wipe(work.key, sizeof(work.key));
	return err;
}

/* See ratchet.h. No `default:`, so -Wswitch names a code added and not
 * rendered; the fallback after the switch catches a value that is not an
 * enumerator at all. */
const char *fzn_ratchet_err_str(fzn_ratchet_err_t err)
{
	switch (err) {
	case FZN_RATCHET_OK:
		return "ok";
	case FZN_RATCHET_ERR_MALFORMED:
		return "malformed argument";
	case FZN_RATCHET_ERR_HASH:
		return "hash refused or absent";
	case FZN_RATCHET_ERR_BEHIND:
		return "target is behind the chain, so a duplicate or a replay";
	case FZN_RATCHET_ERR_TOO_FAR:
		return "jump exceeds the fast-forward bound";
	case FZN_RATCHET_ERR_IN_PLACE:
		return "advanced a live chain in place: derive, verify, then commit";
	}

	return "unknown";
}
