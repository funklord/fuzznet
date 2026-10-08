/* See apply.h. */

#include "apply.h"
#include "roots.h"
#include "settings.h"

#include "../constant_time/constant_time.h"

#include <string.h>

/* What applying one object came to. FULL is a store with no room: the object
 * is not marked applied, since the next round may have room, and nothing
 * after it is asked this round, since it would meet the same store. */
enum outcome { APPLIED, REFUSED, WAIT, NOT_SAVED, FULL };

static int is_root(const fzn_node_apply_t *ap, const uint8_t key[FZN_PUBKEY_LEN])
{
	if (fzn_ct_memeq(key, ap->root, FZN_PUBKEY_LEN))
		return 1;
	return ap->roots && ap->roots->ops.member && ap->roots->ops.member(ap->roots->ops.ctx, key);
}

int fzn_node_apply_chain(const fzn_node_apply_t *ap, const uint8_t key[FZN_PUBKEY_LEN],
                         const fzn_cap_id_t *capability,
                         uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN], size_t *hop_count)
{
	uint8_t walked[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	const uint8_t *at = key;
	size_t depth = 0, i;

	if (!ap || !key || !capability || !hops || !hop_count)
		return 0;
	/* UP FROM THE SIGNER, a grant at a time, until a root granted. A chain
	 * may carry FZN_CHAIN_MAX_HOPS - 1 hops when offered beside a vote. */
	while (!is_root(ap, at)) {
		const fzn_node_grant_t *g = NULL;

		if (depth + 1u >= FZN_CHAIN_MAX_HOPS)
			return 0;
		for (i = 0; i < ap->grants_used && !g; i++)
			if (fzn_ct_memeq(ap->grants[i].grantee, at, FZN_PUBKEY_LEN)
			    && fzn_ct_memeq(ap->grants[i].capability.b, capability->b, FZN_CAP_ID_LEN))
				g = &ap->grants[i];
		if (!g)
			return 0;
		memcpy(walked[depth++], g->hop, FZN_HOP_LEN);
		at = g->grantor;
	}
	/* ROOT FIRST, as a chain is read. */
	for (i = 0; i < depth; i++)
		memcpy(hops[i], walked[depth - 1u - i], FZN_HOP_LEN);
	*hop_count = depth;
	return 1;
}

static enum outcome index_grant(fzn_node_apply_t *ap, const uint8_t *body, size_t len,
                                fzn_node_apply_tally_t *tally)
{
	fzn_chain_hop_t hop;
	fzn_node_grant_t *g;
	size_t i;

	if (len != FZN_HOP_LEN || fzn_hop_open(body, len, &hop) != FZN_CHAIN_OK)
		return REFUSED;
	for (i = 0; i < ap->grants_used; i++)
		if (memcmp(ap->grants[i].hop, body, FZN_HOP_LEN) == 0)
			return APPLIED;
	/* A FULL INDEX REFUSES rather than evicting: a grant forgotten is a
	 * chain nothing can rebuild, and every vote under it would wait. */
	if (ap->grants_used >= FZN_NODE_APPLY_GRANTS_MAX)
		return REFUSED;
	g = &ap->grants[ap->grants_used++];
	memcpy(g->hop, body, FZN_HOP_LEN);
	memcpy(g->grantor, fzn_hop_grantor(hop), FZN_PUBKEY_LEN);
	memcpy(g->grantee, fzn_hop_grantee(hop), FZN_PUBKEY_LEN);
	g->capability = *fzn_hop_capability(hop);
	tally->grants++;
	return APPLIED;
}

/* An object through the vote stream's admission, under `signer`'s chain --
 * as a member, then as an admin -- or none for a root. */
static enum outcome take(fzn_node_apply_t *ap, char item, const uint8_t *body, size_t len,
                         const uint8_t signer[FZN_PUBKEY_LEN])
{
	static fzn_node_vote_pull_t pull;
	uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	const fzn_cap_id_t *caps[2];
	size_t n = 0, c, tried = 0;
	fzn_node_pull_err_t err;

	memset(&pull, 0, sizeof(pull));
	pull.roots = ap->roots;
	pull.roster = ap->roster;
	pull.successions = ap->successions;
	if (is_root(ap, signer)) {
		err = fzn_node_votes_take(&pull, item, body, len, NULL, 0u, ap->root, ap->sign,
		                          ap->hash, ap->revocations, ap->store);
		if (err == FZN_NODE_PULL_NOT_SAVED)
			return NOT_SAVED;
		if (err == FZN_NODE_PULL_REFUSED)
			return FULL;
		return pull.learned ? APPLIED : REFUSED;
	}
	caps[0] = ap->capability;
	caps[1] = ap->admin_capability;
	for (c = 0; c < 2u; c++) {
		if (!caps[c] || !fzn_node_apply_chain(ap, signer, caps[c], hops, &n))
			continue;
		tried++;
		pull.learned = 0;
		err = fzn_node_votes_take(&pull, item, body, len, (const uint8_t (*)[FZN_HOP_LEN])hops,
		                          n, ap->root, ap->sign, ap->hash, ap->revocations, ap->store);
		if (err == FZN_NODE_PULL_NOT_SAVED)
			return NOT_SAVED;
		if (err == FZN_NODE_PULL_REFUSED)
			return FULL;
		if (pull.learned)
			return APPLIED;
	}
	/* NO CHAIN YET: a grant in another stream may still arrive. */
	return tried ? REFUSED : WAIT;
}

/* Whether `hops` (`n` of them, from the index) grant `capability` to `key`
 * from a root, verified now. */
static int chain_proves(const fzn_node_apply_t *ap, const uint8_t key[FZN_PUBKEY_LEN],
                        const uint8_t (*hops)[FZN_HOP_LEN], size_t n,
                        const fzn_cap_id_t *capability)
{
	fzn_chain_hop_t opened[FZN_CHAIN_MAX_HOPS];
	fzn_chain_t verdict;
	size_t i;

	if (n == 0u || n > FZN_CHAIN_MAX_HOPS)
		return 0;
	for (i = 0; i < n; i++)
		if (fzn_hop_open(hops[i], FZN_HOP_LEN, &opened[i]) != FZN_CHAIN_OK)
			return 0;
	/* THE CHAIN'S OWN ROOT, which must be one: the pinned root or a member
	 * of the set. */
	return is_root(ap, fzn_hop_grantor(opened[0]))
	       && fzn_chain_verify(opened, n, fzn_hop_grantor(opened[0]), capability,
	                           ap->now ? ap->now() : 0u, ap->sign, ap->revocations, NULL,
	                           &verdict)
	                  == FZN_CHAIN_OK
	       && fzn_ct_memeq(verdict.grantee, key, FZN_PUBKEY_LEN);
}

int fzn_node_apply_rank(const fzn_node_apply_t *ap, const uint8_t key[FZN_PUBKEY_LEN],
                        fzn_scope_t scope, const uint8_t about[FZN_SUBJECT_LEN],
                        fzn_setting_rank_t *rank)
{
	uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	fzn_chain_hop_t opened[FZN_CHAIN_MAX_HOPS];
	size_t n = 0, i;
	int found = 0;

	if (!ap || !key || !about || !rank || !ap->root || !ap->sign)
		return -1;
	if (is_root(ap, key)) {
		*rank = FZN_SETTING_RANK_ROOT;
		return 1;
	}
	/* AN ADMIN BY THE STANDING A RETENTION SETTING TAKES (sec 479): the
	 * chain admitted by the revocation store, confirmations and all. */
	if (ap->admin_capability && ap->revocations
	    && fzn_node_apply_chain(ap, key, ap->admin_capability, hops, &n) && n) {
		found = 1;
		for (i = 0; i < n; i++)
			if (fzn_hop_open(hops[i], FZN_HOP_LEN, &opened[i]) != FZN_CHAIN_OK)
				break;
		if (i == n
		    && fzn_revocation_admin_admit(ap->revocations, key, opened, n, ap->root, ap->sign)
		               == FZN_CHAIN_OK) {
			*rank = FZN_SETTING_RANK_ADMIN;
			return 1;
		}
	}
	/* THE HOST ITSELF, for its own host-scoped cells alone. */
	if (scope == FZN_SCOPE_HOST && fzn_ct_memeq(about, key, FZN_PUBKEY_LEN) && ap->capability
	    && fzn_node_apply_chain(ap, key, ap->capability, hops, &n) && n) {
		found = 1;
		if (chain_proves(ap, key, (const uint8_t (*)[FZN_HOP_LEN])hops, n, ap->capability)) {
			*rank = FZN_SETTING_RANK_HOST;
			return 1;
		}
	}
	/* A MEMBER WITH NO STANDING FOR THIS CELL IS REFUSED, not left to wait:
	 * its chain is here, so nothing still to arrive would change the
	 * answer, and a setting that waits stops its setter's whole stream. */
	if (!found && ap->capability && fzn_node_apply_chain(ap, key, ap->capability, hops, &n) && n)
		found = 1;
	return found ? -1 : 0;
}

/* A SETTING, sec 540: judged by its setter's standing, then kept at that
 * rank. Its setter must be the record's signer: no setting rides another
 * key's stream. */
static enum outcome take_setting(fzn_node_apply_t *ap, const uint8_t *body, size_t len,
                                 const uint8_t *signer)
{
	fzn_node_settings_err_t err;
	fzn_setting_rank_t rank;
	fzn_setting_t s;
	int judged;

	if (!ap->settings || fzn_setting_open(body, len, ap->sign, &s) != FZN_SETTING_OK
	    || !fzn_ct_memeq(s.setter, signer, FZN_PUBKEY_LEN))
		return REFUSED;
	judged = fzn_node_apply_rank(ap, signer, s.scope, s.about, &rank);
	if (judged == 0)
		return WAIT;
	if (judged < 0)
		return REFUSED;
	err = fzn_node_settings_learn(ap->settings, body, len, rank);
	if (err == FZN_NODE_SETTINGS_BACKEND)
		return NOT_SAVED;
	/* STALE IS APPLIED: an older setting met a newer one standing, which is
	 * the order a journal may hand them in. */
	return err == FZN_NODE_SETTINGS_OK || err == FZN_NODE_SETTINGS_STALE ? APPLIED : REFUSED;
}

static enum outcome apply_one(fzn_node_apply_t *ap, fzn_record_t rec,
                              fzn_node_apply_tally_t *tally)
{
	const uint8_t *body = fzn_record_body(rec), *signer = fzn_record_issuer(rec);
	size_t len = fzn_record_body_len(rec);
	uint32_t kind = fzn_record_kind(rec);
	fzn_node_roots_err_t rerr;

	/* THE BODY IS THE OBJECT ITS KIND NAMES, sec 502: a record whose body's
	 * tag disagrees with its kind is refused before anything reads it. */
	if (len < 2u || body[1] != (uint8_t)kind)
		return REFUSED;
	switch (kind) {
	case FZN_OBJECT_HOP:
		return index_grant(ap, body, len, tally);
	case FZN_OBJECT_ROOT_ADD:
	case FZN_OBJECT_ROOT_REMOVE:
	case FZN_OBJECT_QUORUM_SET:
		if (!ap->roots)
			return REFUSED;
		rerr = fzn_node_roots_learn(ap->roots, ap->store, body, len);
		return rerr == FZN_NODE_ROOTS_OK ? APPLIED
		       : rerr == FZN_NODE_ROOTS_NOT_SAVED ? NOT_SAVED
		                                          : REFUSED;
	case FZN_OBJECT_RETENTION_SET:
		/* A ROOT'S SETTING TO THE ROOTS, an admin's through its chain. */
		if (ap->roots && is_root(ap, signer)) {
			rerr = fzn_node_roots_learn(ap->roots, ap->store, body, len);
			return rerr == FZN_NODE_ROOTS_OK ? APPLIED
			       : rerr == FZN_NODE_ROOTS_NOT_SAVED ? NOT_SAVED
			                                          : REFUSED;
		}
		return take(ap, 't', body, len, signer);
	case FZN_OBJECT_REVOCATION:
	case FZN_OBJECT_WITHDRAWAL:
		return take(ap, 'r', body, len, signer);
	case FZN_OBJECT_ADMIN_CONFIRM:
		return take(ap, 'c', body, len, signer);
	case FZN_OBJECT_ROSTER_ADD:
	case FZN_OBJECT_ROSTER_REMOVE:
	case FZN_OBJECT_ROSTER_SET:
		return take(ap, 'o', body, len, signer);
	case FZN_OBJECT_SUCCESSION:
		return take(ap, 's', body, len, signer);
	case FZN_OBJECT_SETTING:
		return take_setting(ap, body, len, signer);
	default:
		return REFUSED;
	}
}

fzn_node_pull_err_t fzn_node_apply_round(fzn_node_apply_t *ap, fzn_node_apply_tally_t *tally)
{
	static uint8_t buf[FZN_RECORD_MAX_LEN];
	size_t pass, e;
	int progress = 1;

	if (!ap || !tally || !ap->journal || !ap->store || !ap->store->save || !ap->revocations
	    || !ap->root || !ap->capability || !ap->sign || !ap->hash || !ap->hash->hash)
		return FZN_NODE_PULL_MALFORMED;
	memset(tally, 0, sizeof(*tally));
	for (pass = 0; pass < FZN_NODE_APPLY_PASSES && progress; pass++) {
		progress = 0;
		tally->waiting = 0;
		for (e = 0; e < ap->journal->journal.used; e++) {
			fzn_journal_entry_t *entry = &ap->journal->entries[e];
			uint64_t seq;

			if (entry->stream != FZN_NODE_JOURNAL_STREAM)
				continue;
			for (seq = entry->applied + 1u; seq <= entry->received; seq++) {
				fzn_record_t rec;
				enum outcome out;

				if (fzn_record_store_get(&ap->journal->store, entry->issuer,
				                         FZN_NODE_JOURNAL_STREAM, seq, buf, sizeof(buf), &rec)
				    != FZN_RECORD_STORE_OK)
					break;
				out = apply_one(ap, rec, tally);
				if (out == NOT_SAVED)
					return FZN_NODE_PULL_NOT_SAVED;
				/* A FULL STORE STOPS THE ROUND with the object unmarked:
				 * marked, it would be skipped for ever, and a vote lost
				 * to a full table is a revocation never in force. */
				if (out == FULL)
					return FZN_NODE_PULL_REFUSED;
				if (out == WAIT) {
					tally->waiting++;
					break;
				}
				if (out == APPLIED && fzn_record_kind(rec) != (uint32_t)FZN_OBJECT_HOP)
					tally->applied++;
				if (out == REFUSED)
					tally->refused++;
				(void)fzn_journal_confirm(&ap->journal->journal, entry->issuer,
				                          FZN_NODE_JOURNAL_STREAM, seq);
				progress = 1;
			}
		}
	}
	return FZN_NODE_PULL_OK;
}
