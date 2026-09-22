/* See admit.h. */

#include "admit.h"

#include <string.h>

const char *fzn_admit_vocab_str(fzn_admit_vocab_t vocab)
{
	switch (vocab) {
	case FZN_ADMIT_VOCAB_NONE:           return "none";
	case FZN_ADMIT_VOCAB_SEAL:           return "seal";
	case FZN_ADMIT_VOCAB_COMMITMENT:     return "commitment";
	case FZN_ADMIT_VOCAB_FRESH:          return "freshness";
	case FZN_ADMIT_VOCAB_CHAIN:          return "chain";
	case FZN_ADMIT_VOCAB_REASM:          return "reassembly";
	case FZN_ADMIT_VOCAB_UNKNOWN_SENDER: return "unknown-sender";
	case FZN_ADMIT_VOCAB_NO_CHAIN:       return "no-chain";
	}
	return "unknown";
}

const char *fzn_admit_step_str(fzn_admit_step_t step)
{
	switch (step) {
	case FZN_ADMIT_ADMITTED:   return "admitted";
	case FZN_ADMIT_SHAPE:      return "shape";
	case FZN_ADMIT_KEY_SELECT: return "key-select";
	case FZN_ADMIT_COMMITMENT: return "commitment";
	case FZN_ADMIT_TAG:        return "tag";
	case FZN_ADMIT_FRESHNESS:  return "freshness";
	case FZN_ADMIT_REPLAY:     return "replay";
	case FZN_ADMIT_CHAIN:      return "chain";
	case FZN_ADMIT_REASSEMBLY: return "reassembly";
	}
	return "unknown";
}

static void refuse(fzn_admit_result_t *out, fzn_admit_step_t step,
                   fzn_admit_vocab_t vocab, int err)
{
	out->step = step;
	out->vocab = vocab;
	out->err = err;
}

void fzn_admit(uint8_t *frame, size_t frame_len, uint64_t now,
               const fzn_admit_env_t *env, fzn_admit_key_t *candidates,
               size_t candidate_cap, fzn_admit_result_t *out)
{
	fzn_peek_t peek;
	fzn_seal_err_t sr;
	size_t n, i, chosen = candidate_cap;
	fzn_expiry_rule_t rule;
	fzn_fresh_err_t fr;
	uint8_t root[FZN_PUBKEY_LEN];
	const uint8_t *chain_bytes = NULL;
	size_t chain_len = 0;
	fzn_chain_hop_t hops[FZN_CHAIN_MAX_HOPS];
	size_t hop_count = 0;
	fzn_chain_t verdict;
	fzn_chain_err_t cr;
	fzn_cap_id_t cap;

	if (!out)
		return;
	memset(out, 0, sizeof(*out));
	if (!frame || !env || !env->ops || !env->ops->keys
	    || !env->ops->expiry_rule || !env->ops->root_for || !env->hash
	    || !env->aead || !env->sign || !env->replay || !env->chains
	    || (candidate_cap != 0 && !candidates)) {
		refuse(out, FZN_ADMIT_SHAPE, FZN_ADMIT_VOCAB_SEAL,
		       (int)FZN_SEAL_ERR_MALFORMED);
		return;
	}

	/* 1. SHAPE. situ's layout check, and the no-trailing-bytes rule with
	 * it -- the only thing between a stranger and the AEAD. */
	sr = fzn_seal_peek(frame, frame_len, &peek);
	if (sr != FZN_SEAL_OK) {
		refuse(out, FZN_ADMIT_SHAPE, FZN_ADMIT_VOCAB_SEAL, (int)sr);
		return;
	}

	/* 2. KEY SELECT, on the CLAIMED sender. An unknown sender is a DROP
	 * and nothing is created for it -- no record, no pending entry, no
	 * negative cache, every one of which would be an unauthenticated
	 * write. Nothing here is remembered, so there is nothing to write. */
	n = env->ops->keys(env->ops->ctx, peek.sender, candidates,
	                   candidate_cap);
	if (n == 0 || n > candidate_cap) {
		refuse(out, FZN_ADMIT_KEY_SELECT, FZN_ADMIT_VOCAB_UNKNOWN_SENDER, 0);
		return;
	}

	/* 3. COMMITMENT. Pure, and the one discretionary pre-tag step: with K
	 * candidates it turns K tag verifications into K derivations plus K
	 * compares, which is measured at 2.1x to 3.6x rather than the order of
	 * magnitude "K compares" once implied. */
	for (i = 0; i < n; i++) {
		uint8_t derived[FZN_COMMITMENT_LEN];
		fzn_commitment_err_t er;

		er = fzn_commitment_for_nonce(env->hash, candidates[i].commitment,
		                              peek.nonce, derived);
		if (er != FZN_COMMITMENT_OK) {
			refuse(out, FZN_ADMIT_COMMITMENT, FZN_ADMIT_VOCAB_COMMITMENT,
			       (int)er);
			return;
		}
		if (fzn_commitment_check(derived, peek.commitment)
		    == FZN_COMMITMENT_OK) {
			chosen = i;
			break;
		}
	}
	if (chosen == candidate_cap) {
		/* No candidate addresses this frame. Not an error in any
		 * module's vocabulary -- the frame was not for us. */
		refuse(out, FZN_ADMIT_COMMITMENT, FZN_ADMIT_VOCAB_COMMITMENT,
		       (int)FZN_COMMITMENT_ERR_MISMATCH);
		return;
	}

	/* 4. TAG. THE PIVOT. Nothing above this line changed anything the next
	 * datagram can observe; nothing below it runs on a stranger's say-so.
	 * The frame is decrypted in place. */
	sr = fzn_seal_open(frame, frame_len, candidates[chosen].aead,
	                   candidates[chosen].commitment, env->hash, env->aead,
	                   &out->opened);
	if (sr != FZN_SEAL_OK) {
		memset(&out->opened, 0, sizeof(out->opened));
		refuse(out, FZN_ADMIT_TAG, FZN_ADMIT_VOCAB_SEAL, (int)sr);
		return;
	}

	/* 5. FRESHNESS, below the tag, where sec 4.7b moved it: the reason
	 * given for putting it above -- not spending a signature verification
	 * on something already dead -- argues for freshness before the CHAIN,
	 * and never asked for freshness before the TAG. The verdict is now
	 * authentic enough to name a peer. */
	rule = env->ops->expiry_rule(env->ops->ctx, out->opened.kind);
	fr = fzn_freshness_check(out->opened.expires_at, rule, now,
	                         env->max_ahead);
	if (fr != FZN_FRESH_OK) {
		refuse(out, FZN_ADMIT_FRESHNESS, FZN_ADMIT_VOCAB_FRESH, (int)fr);
		return;
	}

	/* 6. REPLAY. THE FIRST MUTATION, and the first thing on this path that
	 * a refusal could have cost -- which is why every refusal above
	 * returned before reaching it. */
	fr = fzn_replay_admit(env->replay, out->opened.nonce,
	                      out->opened.expires_at, rule, now);
	if (fr != FZN_FRESH_OK) {
		refuse(out, FZN_ADMIT_REPLAY, FZN_ADMIT_VOCAB_FRESH, (int)fr);
		return;
	}

	/* 7. CHAIN, after replay rather than before, which is where
	 * "predicates before mutations" yields to measurement: chain-first
	 * pays an Ed25519 verification on every duplicate and retransmission
	 * of a lossy link, where the window catches them for 77 ns. */
	if (!env->ops->root_for(env->ops->ctx, out->opened.sender, root)) {
		/* No root anchors this sender. The chain module is not reached,
		 * so there is no chain error to give -- see NO_CHAIN. */
		refuse(out, FZN_ADMIT_CHAIN, FZN_ADMIT_VOCAB_NO_CHAIN, 0);
		return;
	}
	memcpy(cap.b, out->opened.capability, FZN_CAP_ID_LEN);
	/* sec 4.7c's memo, asked here and nowhere earlier: the sender it keys
	 * on became authentic at step 4. A hit skips the lookup, the open and
	 * the Ed25519 -- which is the 51 to 487 ms a chunked message otherwise
	 * spends reaching one answer 256 times. */
	if (env->memo
	    && fzn_chain_memo_allows(env->memo, root, out->opened.sender, &cap,
	                             fzn_revocation_generation(env->revocations),
	                             now))
		goto reassemble;
	if (!fzn_chain_store_lookup(env->chains, root, &cap, out->opened.sender,
	                            now, &chain_bytes, &chain_len)) {
		/* Fail closed: a capability this host cannot prove is one it
		 * does not act on. An ABSENCE, not a chain error. */
		refuse(out, FZN_ADMIT_CHAIN, FZN_ADMIT_VOCAB_NO_CHAIN, 0);
		return;
	}
	cr = fzn_chain_open(chain_bytes, chain_len, hops, &hop_count);
	if (cr != FZN_CHAIN_OK) {
		refuse(out, FZN_ADMIT_CHAIN, FZN_ADMIT_VOCAB_CHAIN, (int)cr);
		return;
	}
	cr = fzn_chain_verify(hops, hop_count, root, &cap, now, env->sign,
	                      env->revocations, env->manifest, &verdict);
	if (cr != FZN_CHAIN_OK) {
		refuse(out, FZN_ADMIT_CHAIN, FZN_ADMIT_VOCAB_CHAIN, (int)cr);
		return;
	}
	/* Only the affirmative, and the generation read AFTER the
	 * verification: a revocation landing while it ran must invalidate
	 * this, and the earlier number would hide it. */
	if (env->memo)
		(void)fzn_chain_memo_record(env->memo, &verdict,
		                            fzn_revocation_generation(env->revocations));

reassemble:

	/* 8. REASSEMBLY, last: the largest and longest-lived mutation in the
	 * path, and every step above exists so that its memory bound protects
	 * a table no stranger can reach. Optional, because a consumer that
	 * does not chunk needs no table and a default one would be a memory
	 * bound this library invented for it. */
	if (env->reassembly) {
		fzn_reasm_err_t rr;

		rr = fzn_reasm_accept(env->reassembly, out->opened.sender,
		                      out->opened.msg, out->opened.index,
		                      out->opened.chunks, out->opened.payload,
		                      out->opened.payload_len,
		                      out->opened.expires_at, now,
		                      &out->message);
		if (rr != FZN_REASM_OK) {
			out->message = NULL;
			refuse(out, FZN_ADMIT_REASSEMBLY, FZN_ADMIT_VOCAB_REASM, (int)rr);
			return;
		}
	}

	out->step = FZN_ADMIT_ADMITTED;
	out->vocab = FZN_ADMIT_VOCAB_NONE;
	out->err = 0;
}
