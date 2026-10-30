/* See apply.h. */

#include "apply.h"
#include "roots.h"
#include "settings.h"
#include "siblings.h"

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

/* EVER A ROOT HERE, sec 700: the standing a root record's signer, and a
 * grantor, needs when the record arrives. Removed since is still standing
 * enough: whether the act counts is the cut's question, asked when read. */
static int ever_root(const fzn_node_apply_t *ap, const uint8_t key[FZN_PUBKEY_LEN])
{
	return fzn_ct_memeq(key, ap->root, FZN_PUBKEY_LEN)
	       || (ap->roots && fzn_node_roots_known(ap->roots, key));
}

/* A WALK UP FROM A KEY, which tries each grant naming it until one reaches a
 * root, sec 700. Taking the first grant found, and giving up when its grantor
 * reached no root, let a stranger's grant naming a member -- signed by the
 * stranger, which is all a grant needs to be indexed -- hide that member's
 * real chain: every act of the member then waited for ever, and an admin
 * shadowed so could no longer vote. A key found to reach no root with so
 * many hops left is not walked again with as many or fewer, so the walk
 * stays polynomial in the grants however many a liar adds.
 *
 * THE MEMO IS KEPT ON THE GRANTS, sec 704, each naming the key as its
 * grantee and marked with the walk: a key no grant names is walked at no
 * depth, so it needs none, and the memo is as large as the index however
 * large that grows. It was a table of its own, bounded as the index was. */
struct chain_walk {
	const fzn_node_apply_t *ap;
	const fzn_cap_id_t *capability;
	uint8_t walked[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	uint32_t walk;
};

static int dead_at(const struct chain_walk *w, const uint8_t *key, size_t left)
{
	size_t i;

	for (i = 0; i < w->ap->grants_used; i++)
		if (w->ap->grants[i].dead_walk == w->walk && w->ap->grants[i].dead_left >= left
		    && fzn_ct_memeq(w->ap->grants[i].grantee, key, FZN_PUBKEY_LEN))
			return 1;
	return 0;
}

static void mark_dead(struct chain_walk *w, const uint8_t *key, size_t left)
{
	size_t i;

	for (i = 0; i < w->ap->grants_used; i++) {
		fzn_node_grant_t *g = &w->ap->grants[i];

		if (!fzn_ct_memeq(g->grantee, key, FZN_PUBKEY_LEN))
			continue;
		if (g->dead_walk != w->walk || g->dead_left < left)
			g->dead_left = left;
		g->dead_walk = w->walk;
	}
}

/* From `at`, `depth` hops walked: 1 with the chain in `walked` and its length
 * in `*depth_out`. A GRANT THAT MAY BE PASSED ON FIRST, sec 579: a member
 * holds its join grant, delegable, and since siblings pair one another a
 * grant from each sibling as well, which is not; walking up through a
 * sibling's would judge the member on that sibling's standing, and a revoked
 * sibling would take the member's records with it. */
static int walk_up(struct chain_walk *w, const uint8_t *at, size_t depth, size_t *depth_out)
{
	const fzn_node_apply_t *ap = w->ap;
	size_t pass, i;

	if (is_root(ap, at)) {
		*depth_out = depth;
		return 1;
	}
	/* A chain may carry FZN_CHAIN_MAX_HOPS - 1 hops when offered beside a
	 * vote. */
	if (depth + 1u >= FZN_CHAIN_MAX_HOPS || dead_at(w, at, FZN_CHAIN_MAX_HOPS - depth))
		return 0;
	for (pass = 0; pass < 2u; pass++)
		for (i = 0; i < ap->grants_used; i++) {
			const fzn_node_grant_t *g = &ap->grants[i];

			if ((g->hop[FZN_HOP_OFF_DELEGABLE] == 1u) != (pass == 0u)
			    || !fzn_ct_memeq(g->grantee, at, FZN_PUBKEY_LEN)
			    || !fzn_ct_memeq(g->capability.b, w->capability->b, FZN_CAP_ID_LEN))
				continue;
			memcpy(w->walked[depth], g->hop, FZN_HOP_LEN);
			if (walk_up(w, g->grantor, depth + 1u, depth_out))
				return 1;
		}
	mark_dead(w, at, FZN_CHAIN_MAX_HOPS - depth);
	return 0;
}

int fzn_node_apply_chain(const fzn_node_apply_t *ap, const uint8_t key[FZN_PUBKEY_LEN],
                         const fzn_cap_id_t *capability,
                         uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN], size_t *hop_count)
{
	static struct chain_walk w;
	static uint32_t walks;
	size_t depth = 0, i;

	if (!ap || !key || !capability || !hops || !hop_count)
		return 0;
	/* UP FROM THE SIGNER, a grant at a time, until a root granted. A walk
	 * of its own number, never 0, which a fresh grant holds. */
	w.ap = ap;
	w.capability = capability;
	if (++walks == 0u)
		walks = 1u;
	w.walk = walks;
	if (!walk_up(&w, key, 0, &depth))
		return 0;
	/* ROOT FIRST, as a chain is read. */
	for (i = 0; i < depth; i++)
		memcpy(hops[i], w.walked[depth - 1u - i], FZN_HOP_LEN);
	*hop_count = depth;
	return 1;
}

/* A grant's row in FZN_PERSIST_GRANT: a hash of the hop's bytes. */
static int grant_row(const fzn_node_apply_t *ap, const uint8_t *hop, uint8_t row[FZN_PUBKEY_LEN])
{
	return ap->hash->hash(ap->hash->ctx, row, FZN_PUBKEY_LEN, hop, FZN_HOP_LEN);
}

/* THE INDEX'S ROOM: its own until it is given more. */
static void index_room(fzn_node_apply_t *ap)
{
	if (!ap->grants) {
		ap->grants = ap->grants_own;
		ap->grants_cap = FZN_NODE_APPLY_GRANTS_MAX;
	}
}

int fzn_node_apply_use_grants(fzn_node_apply_t *ap, fzn_node_grant_t *grants, size_t capacity)
{
	if (!ap || !grants || capacity == 0u || capacity < ap->grants_used)
		return 0;
	index_room(ap);
	if (grants != ap->grants && ap->grants_used)
		memmove(grants, ap->grants, ap->grants_used * sizeof(*grants));
	ap->grants = grants;
	ap->grants_cap = capacity;
	ap->grants_wanted = 0;
	return 1;
}

/* Add `body` (a hop) to the in-memory index: 1 added, 0 held already, -1
 * not a hop, -2 no room. */
static int index_add(fzn_node_apply_t *ap, const uint8_t *body, size_t len)
{
	fzn_chain_hop_t hop;
	fzn_node_grant_t *g;
	size_t i;

	if (len != FZN_HOP_LEN || fzn_hop_open(body, len, &hop) != FZN_CHAIN_OK)
		return -1;
	index_room(ap);
	for (i = 0; i < ap->grants_used; i++)
		if (memcmp(ap->grants[i].hop, body, FZN_HOP_LEN) == 0)
			return 0;
	/* A FULL INDEX WAITS FOR ROOM rather than evicting or refusing: a grant
	 * forgotten is a chain nothing can rebuild, and every vote under it
	 * would wait; refused, it was marked applied and lost. sec 704. */
	if (ap->grants_used >= ap->grants_cap) {
		ap->grants_wanted = ap->grants_used + 1u;
		return -2;
	}
	g = &ap->grants[ap->grants_used++];
	memset(g, 0, sizeof(*g));
	memcpy(g->hop, body, FZN_HOP_LEN);
	memcpy(g->grantor, fzn_hop_grantor(hop), FZN_PUBKEY_LEN);
	memcpy(g->grantee, fzn_hop_grantee(hop), FZN_PUBKEY_LEN);
	g->capability = *fzn_hop_capability(hop);
	return 1;
}

static enum outcome index_grant(fzn_node_apply_t *ap, const uint8_t *body, size_t len,
                                const uint8_t *signer, fzn_node_apply_tally_t *tally)
{
	uint8_t row[FZN_PUBKEY_LEN];
	fzn_chain_hop_t hop;
	const uint8_t *msg;
	size_t msg_len;
	int added;

	/* SIGNED BY ITS GRANTOR, AND THE GRANTOR THE SIGNER, sec 700: a grant is
	 * its grantor's act, in its grantor's stream (sec 497), so a record of
	 * anybody else's carrying one is no grant of theirs. The journal's
	 * record vouched only for its issuer: indexed on that, one member's
	 * stream could carry hops in any root's name -- each failing when a
	 * chain through it was verified, but standing in the index meanwhile. */
	if (fzn_hop_open(body, len, &hop) != FZN_CHAIN_OK
	    || !fzn_ct_memeq(fzn_hop_grantor(hop), signer, FZN_PUBKEY_LEN))
		return REFUSED;
	fzn_hop_signed_bytes(hop, &msg, &msg_len);
	if (!ap->sign->verify
	    || !ap->sign->verify(ap->sign->ctx, fzn_hop_grantor(hop), msg, msg_len,
	                         fzn_hop_signature(hop)))
		return REFUSED;
	/* AND ITS GRANTOR STANDING, sec 700, the holder's of 2026-10-23: a root,
	 * or itself granted from one. A grant from a key with no chain here
	 * waits, as an act whose chain has not arrived does, rather than taking
	 * a place in the index -- kept and judged on read, a stranger's grants
	 * filled the index and every genuine grant after them was refused. */
	if (!ever_root(ap, fzn_hop_grantor(hop))) {
		uint8_t walked[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
		size_t n = 0;

		if (!fzn_node_apply_chain(ap, fzn_hop_grantor(hop), fzn_hop_capability(hop), walked, &n)
		    && !fzn_node_apply_chain(ap, fzn_hop_grantor(hop), ap->capability, walked, &n)
		    && !(ap->admin_capability
		         && fzn_node_apply_chain(ap, fzn_hop_grantor(hop), ap->admin_capability, walked,
		                                 &n)))
			return WAIT;
	}
	added = index_add(ap, body, len);

	if (added == -2)
		return FULL;
	if (added < 0)
		return REFUSED;
	/* KEPT AS WELL AS INDEXED, sec 545, so the chain outlives the journal
	 * that carried it: a grant not kept is not applied, and is asked again
	 * next round. */
	if (!grant_row(ap, body, row)
	    || !ap->store->save(ap->store->ctx, FZN_PERSIST_GRANT, row, body, FZN_HOP_LEN)) {
		if (added)
			ap->grants_used--;
		return NOT_SAVED;
	}
	if (added)
		tally->grants++;
	return APPLIED;
}

/* ONE GRANT ROW AT LOAD: what it says it is, under its own place -- a hop
 * filed under another's hash is not that grant. sec 545, walked since 704. */
struct grants_walk {
	fzn_node_apply_t *ap;
	size_t *loaded;
	int failed;
};

static int grant_walked(void *arg, const uint8_t row[FZN_PUBKEY_LEN])
{
	struct grants_walk *w = arg;
	uint8_t hop[FZN_HOP_LEN], again[FZN_PUBKEY_LEN];
	size_t len = 0;
	int added;

	if (!w->ap->store->load(w->ap->store->ctx, FZN_PERSIST_GRANT, row, hop, sizeof(hop), &len)
	    || len != FZN_HOP_LEN || !grant_row(w->ap, hop, again)
	    || memcmp(again, row, FZN_PUBKEY_LEN) != 0) {
		w->failed = 1;
		return 0;
	}
	added = index_add(w->ap, hop, len);
	if (added < 0) {
		w->failed = 1;
		return 0;
	}
	*w->loaded += (size_t)added;
	return 1;
}

int fzn_node_apply_load_grants(fzn_node_apply_t *ap, size_t *loaded)
{
	struct grants_walk w;

	if (!loaded)
		return 0;
	*loaded = 0;
	if (!ap || !ap->store || (!ap->store->list && !ap->store->each) || !ap->store->load
	    || !ap->hash || !ap->hash->hash)
		return 0;
	w.ap = ap;
	w.loaded = loaded;
	w.failed = 0;
	return fzn_persist_each(ap->store, FZN_PERSIST_GRANT, grant_walked, &w) && !w.failed;
}

/* Set while parked objects are judged again, so one refused again is not
 * parked a second time. */
static int judging_parked;

/* An object through the vote stream's admission, under `signer`'s chain --
 * as an admin, then as a member -- or none for a root. */
static enum outcome take(fzn_node_apply_t *ap, char item, const uint8_t *body, size_t len,
                         const uint8_t signer[FZN_PUBKEY_LEN])
{
	static fzn_node_vote_pull_t pull;
	uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	const fzn_cap_id_t *caps[2];
	size_t n = 0, c, tried = 0;
	int admin_absent = 0;
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
	/* AS AN ADMIN FIRST, sec 781: a vote is kept with the chain it was
	 * admitted under, and admitted under a delegable member chain an
	 * admin's vote is a member's -- one that revokes only what its signer
	 * granted -- so a device another admitted was never revoked at the root,
	 * nor at a contact handed the vote. */
	caps[0] = ap->admin_capability;
	caps[1] = ap->capability;
	for (c = 0; c < 2u; c++) {
		if (!caps[c] || !fzn_node_apply_chain(ap, signer, caps[c], hops, &n)) {
			if (c == 0u && caps[c])
				admin_absent = 1;
			continue;
		}
		tried++;
		pull.learned = 0;
		err = fzn_node_votes_take(&pull, item, body, len, (const uint8_t (*)[FZN_HOP_LEN])hops,
		                          n, ap->root, ap->sign, ap->hash, ap->revocations, ap->store);
		if (err == FZN_NODE_PULL_NOT_SAVED)
			return NOT_SAVED;
		if (err == FZN_NODE_PULL_REFUSED)
			return FULL;
		/* A MEMBER'S, ITS SIGNER NO ADMIN YET: parked as well, sec 781, so
		 * that once the grant making it one is indexed the vote is admitted
		 * again under that chain -- held, not lost, while it waits. Measured
		 * at a root whose own admin grant was indexed a round after the
		 * admin's vote arrived: the vote stayed a member's for good. */
		if (pull.learned) {
			if (c == 1u && admin_absent && item == 'r' && ap->settings && !judging_parked)
				(void)fzn_node_settings_park(ap->settings, body, len);
			/* JUDGED AGAIN AND STILL A MEMBER'S: kept parked, admitted again
			 * each round, which admission makes free, until an admin grant
			 * comes -- or for good, for a member that is never one. */
			if (c == 1u && admin_absent && item == 'r' && judging_parked)
				return WAIT;
			return APPLIED;
		}
	}
	/* A VOTE REFUSED FOR WANT OF AN ADMIN CHAIN IS PARKED, sec 737: the
	 * grant that makes its voter an admin may come later, and a vote judged
	 * once and confirmed never counted then -- the estate journey's lost
	 * vote at 20% loss. Kept with sec 728's parked settings and judged
	 * again at each round's end; WAIT instead would stop the voter's whole
	 * stream on a member who is never made admin. */
	if (tried && admin_absent && (item == 'r') && ap->settings && !judging_parked)
		(void)fzn_node_settings_park(ap->settings, body, len);
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

int fzn_node_apply_holds(const fzn_node_apply_t *ap, const uint8_t key[FZN_PUBKEY_LEN],
                         const fzn_cap_id_t *capability)
{
	uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	size_t n = 0;

	if (!ap || !key || !capability || !ap->root || !ap->sign)
		return 0;
	return is_root(ap, key)
	       || (fzn_node_apply_chain(ap, key, capability, hops, &n)
	           && chain_proves(ap, key, (const uint8_t (*)[FZN_HOP_LEN])hops, n, capability));
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

/* AN ACT UNDER ITS SIGNER'S CUT, sec 706: what the roster asks of its
 * writers (`roster/roster.c`), asked of any act a rank was judged for when
 * it arrived. A root's counts as the root set says of it; any other's
 * stands while no hop of its chain is revoked, and past a revocation only
 * where each revoked hop's cut still covers the act below it. */
int fzn_node_apply_act_stands(const fzn_node_apply_t *ap, const uint8_t key[FZN_PUBKEY_LEN],
                              fzn_setting_rank_t rank, const uint8_t act[FZN_SUBJECT_LEN])
{
	uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	uint8_t grantors[FZN_CHAIN_MAX_HOPS][FZN_PUBKEY_LEN], grantees[FZN_CHAIN_MAX_HOPS][FZN_PUBKEY_LEN];
	uint8_t hop_act[FZN_CHAIN_MAX_HOPS][FZN_SUBJECT_LEN], revoked[FZN_CHAIN_MAX_HOPS];
	const fzn_root_ops_t *set;
	const fzn_cap_id_t *capability;
	fzn_chain_hop_t hop;
	size_t n = 0, i;

	if (!ap || !key || !act || !ap->revocations)
		return 1;
	set = ap->revocations->roots;
	if (rank == FZN_SETTING_RANK_ROOT)
		return !set || set->counts(set->ctx, key, act);
	capability = rank == FZN_SETTING_RANK_ADMIN ? ap->admin_capability : ap->capability;
	/* NO CHAIN HERE NOW is no revocation: judged as it was on arrival. */
	if (!capability || !fzn_node_apply_chain(ap, key, capability, hops, &n) || n == 0u)
		return 1;
	for (i = 0; i < n; i++) {
		if (fzn_hop_open(hops[i], FZN_HOP_LEN, &hop) != FZN_CHAIN_OK
		    || !ap->hash->hash(ap->hash->ctx, hop_act[i], FZN_SUBJECT_LEN, hops[i], FZN_HOP_LEN))
			return 0;
		memcpy(grantors[i], fzn_hop_grantor(hop), FZN_PUBKEY_LEN);
		memcpy(grantees[i], fzn_hop_grantee(hop), FZN_PUBKEY_LEN);
	}
	if (set && !set->counts(set->ctx, grantors[0], hop_act[0]))
		return 0;
	fzn_revocation_covers_links(ap->revocations, (const uint8_t (*)[FZN_PUBKEY_LEN])grantors,
	                            (const uint8_t (*)[FZN_PUBKEY_LEN])grantees, n, capability,
	                            revoked);
	for (i = 0; i < n; i++)
		if (revoked[i]
		    && !fzn_revocation_act_stands(ap->revocations,
		                                  (const uint8_t (*)[FZN_PUBKEY_LEN])grantors,
		                                  (const uint8_t (*)[FZN_PUBKEY_LEN])grantees, n,
		                                  capability, i, i + 1u < n ? hop_act[i + 1u] : act))
			return 0;
	return 1;
}

/* WHETHER `signer` HELD THE RANK ITS SETTING STATES, as far as this node can
 * tell now, `judged` being what it holds today, sec 728:
 * - root: ever standing as one -- whether this act still counts is its
 *   cut's question, asked when read (sec 700);
 * - admin: an admin today, or one whose admin chain this node holds,
 *   revoked or not -- a revocation is the read's to weigh, by its cut;
 * - the host's own: always, since a judged setting is at least that.
 * A stated rank below what the setter holds now was written before it
 * rose, and is taken as stated. */
static int stated_holds(const fzn_node_apply_t *ap, const uint8_t *signer,
                        fzn_setting_rank_t stated, fzn_setting_rank_t judged)
{
	uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	size_t n = 0;

	if (stated == FZN_SETTING_RANK_ROOT)
		return ever_root(ap, signer);
	if (stated == FZN_SETTING_RANK_ADMIN)
		return judged >= FZN_SETTING_RANK_ADMIN
		       || (ap->admin_capability
		           && fzn_node_apply_chain(ap, signer, ap->admin_capability, hops, &n) && n);
	return 1;
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
	/* A CELL BEYOND WHAT THIS NODE KNOWS OF ITS SETTER, stating a rank that
	 * would reach it, is parked rather than refused (sec 728): an admin's
	 * estate setting arriving before its admin chain was otherwise lost
	 * for good -- E's case one rank down. Judged again each round. */
	if (judged < 0)
		return s.rank > (int)FZN_SETTING_RANK_HOST
		               ? fzn_node_settings_park(ap->settings, body, len) == FZN_NODE_SETTINGS_OK
		                         ? APPLIED
		                         : NOT_SAVED
		               : REFUSED;
	/* THE RANK ITS SETTER STATES, sec 728, taken once this node confirms
	 * the setter held it (`stated_holds`). One claimed beyond what this
	 * node knows is PARKED, not waited on and not filed at what this node
	 * knew on arrival: a root's add arriving after left a setting a rank
	 * low for good, and a wait held the setter's whole stream for a
	 * standing that may never come -- a device that was its own root
	 * before it joined states root on what it wrote then, and its every
	 * later record stopped behind it. A parked setting is judged again
	 * each round (`fzn_node_apply_round`). */
	if (s.rank >= 0) {
		fzn_setting_rank_t stated = (fzn_setting_rank_t)s.rank;

		/* ITS OWN HOST CELL needs no more than the host's own standing,
		 * which `judged` already found: a device that was its own root
		 * before it joined wrote its address at root rank, and parked, the
		 * address never reached the estate's other hosts or its contacts. */
		if (!stated_holds(ap, signer, stated, rank)) {
			if (s.scope == FZN_SCOPE_HOST && fzn_ct_memeq(s.about, signer, FZN_PUBKEY_LEN))
				stated = rank;
			else
				return fzn_node_settings_park(ap->settings, body, len)
				               == FZN_NODE_SETTINGS_OK
				               ? APPLIED
				               : NOT_SAVED;
		}
		rank = stated;
	}
	err = fzn_node_settings_learn(ap->settings, body, len, rank);
	if (err == FZN_NODE_SETTINGS_BACKEND)
		return NOT_SAVED;
	/* STALE IS APPLIED: an older setting met a newer one standing, which is
	 * the order a journal may hand them in. */
	return err == FZN_NODE_SETTINGS_OK || err == FZN_NODE_SETTINGS_STALE ? APPLIED : REFUSED;
}

/* A SIBLING'S PREKEY, sec 579: kept when its carrier is its host and a
 * member -- judged as the member setting its own host cell would be, so a
 * key with no chain yet waits, and one with a chain granting nothing is
 * refused. An older record than the one kept is applied and changes
 * nothing, as a journal may hand them in any order. */
static enum outcome take_prekey(fzn_node_apply_t *ap, const uint8_t *body, size_t len,
                                const uint8_t *signer)
{
	fzn_node_siblings_err_t err;
	fzn_setting_rank_t rank;
	int judged = fzn_node_apply_rank(ap, signer, FZN_SCOPE_HOST, signer, &rank);

	if (judged == 0)
		return WAIT;
	if (judged < 0)
		return REFUSED;
	err = fzn_node_siblings_learn(ap->store, ap->sign, body, len, signer);
	if (err == FZN_NODE_SIBLINGS_BACKEND)
		return NOT_SAVED;
	return err == FZN_NODE_SIBLINGS_OK || err == FZN_NODE_SIBLINGS_STALE ? APPLIED : REFUSED;
}

/* WHAT THE ROOTS' ANSWER COMES TO. A FULL TABLE LEAVES THE RECORD FOR THE
 * NEXT ROUND, sec 703, as a full revocation store does: refused, it would
 * be marked applied and skipped for good, the estate's change lost on this
 * node. */
static enum outcome roots_outcome(fzn_node_roots_err_t rerr)
{
	return rerr == FZN_NODE_ROOTS_OK ? APPLIED
	       : rerr == FZN_NODE_ROOTS_NOT_SAVED ? NOT_SAVED
	       : rerr == FZN_NODE_ROOTS_FULL ? FULL
	                                     : REFUSED;
}

/* ONE OBJECT of `kind`, signed by `signer`: the journal's record issuer, or
 * the object's own signer when it came alone (sec 550). */
static enum outcome apply_body(fzn_node_apply_t *ap, uint32_t kind, const uint8_t *body,
                               size_t len, const uint8_t *signer, fzn_node_apply_tally_t *tally)
{
	/* THE BODY IS THE OBJECT ITS KIND NAMES, sec 502: a record whose body's
	 * tag disagrees with its kind is refused before anything reads it. */
	if (len < 2u || body[1] != (uint8_t)kind)
		return REFUSED;
	switch (kind) {
	case FZN_OBJECT_HOP:
		return index_grant(ap, body, len, signer, tally);
	case FZN_OBJECT_ROOT_ADD:
	case FZN_OBJECT_ROOT_REMOVE:
	case FZN_OBJECT_QUORUM_SET:
		if (!ap->roots)
			return REFUSED;
		/* ITS SIGNER'S, and ITS SIGNER EVER A ROOT, sec 700: byte 2 is each
		 * of these records' signer. One from a key not yet a root here waits
		 * for the add that makes it one, rather than taking one of the root
		 * log's fixed places. */
		if (len < 2u + FZN_PUBKEY_LEN || !fzn_ct_memeq(body + 2, signer, FZN_PUBKEY_LEN))
			return REFUSED;
		if (!ever_root(ap, signer))
			return WAIT;
		return roots_outcome(fzn_node_roots_learn(ap->roots, ap->store, body, len));
	case FZN_OBJECT_RETENTION_SET:
		/* A ROOT'S SETTING TO THE ROOTS, an admin's through its chain. */
		if (ap->roots && is_root(ap, signer)) {
			return roots_outcome(fzn_node_roots_learn(ap->roots, ap->store, body, len));
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
	case FZN_OBJECT_PREKEY:
		return take_prekey(ap, body, len, signer);
	default:
		/* AN EXTENSION'S KIND, sec 675: the consumer half, its to judge. */
		if (ap->extension && kind != 0u && !FZN_OBJECT_IS_LIBRARY(kind) && kind < 256u) {
			int took = ap->extension(ap->extension_ctx, kind, body, len, signer);

			return took > 0 ? APPLIED : took < 0 ? WAIT : REFUSED;
		}
		return REFUSED;
	}
}

static enum outcome apply_one(fzn_node_apply_t *ap, fzn_record_t rec,
                              fzn_node_apply_tally_t *tally)
{
	return apply_body(ap, fzn_record_kind(rec), fzn_record_body(rec), fzn_record_body_len(rec),
	                  fzn_record_issuer(rec), tally);
}

fzn_node_apply_outcome_t fzn_node_apply_object(fzn_node_apply_t *ap, const uint8_t *object,
                                               size_t len, fzn_node_apply_tally_t *tally)
{
	size_t at = 2u;

	if (!ap || !object || !tally || !ap->store || !ap->store->save || !ap->revocations
	    || !ap->root || !ap->capability || !ap->sign || !ap->hash || !ap->hash->hash)
		return FZN_NODE_APPLY_REFUSED;
	if (len < 2u || object[0] != (uint8_t)FZN_SIGNED_VERSION)
		return FZN_NODE_APPLY_REFUSED;
	/* THE SIGNER IS THE OBJECT'S OWN: byte 2 of every library object but a
	 * revocation's, whose issuer follows its capability and grantee. */
	if (object[1] == (uint8_t)FZN_OBJECT_REVOCATION
	    || object[1] == (uint8_t)FZN_OBJECT_WITHDRAWAL)
		at = FZN_REV_OFF_ISSUER;
	if (len < at + FZN_PUBKEY_LEN)
		return FZN_NODE_APPLY_REFUSED;
	/* A GRANT IS SIGNED BY ITS GRANTOR, checked where every grant is
	 * indexed (`index_grant`): indexed unchecked, one peer could fill the
	 * index and every digest with hops nobody signed. */
	switch (apply_body(ap, object[1], object, len, object + at, tally)) {
	case APPLIED:
		return FZN_NODE_APPLY_APPLIED;
	case WAIT:
		return FZN_NODE_APPLY_WAITING;
	case NOT_SAVED:
	case FULL:
		return FZN_NODE_APPLY_NOT_SAVED;
	case REFUSED:
		break;
	}
	return FZN_NODE_APPLY_REFUSED;
}

/* A PARKED SETTING JUDGED AGAIN, sec 728: taken at its stated rank once its
 * setter's standing has arrived; dropped when it does not open; kept
 * otherwise -- a setter judged to have no standing for the cell is what a
 * claim beyond what this node knows looks like until the grant arrives, so
 * that is kept too. The first version dropped it, and threw away the very
 * case it was parked for at the first round. */
static int unpark_judged(void *ctx, const uint8_t *bytes, size_t len)
{
	fzn_node_apply_t *ap = ctx;
	fzn_setting_rank_t rank;
	fzn_setting_t s;
	fzn_node_settings_err_t err;
	int judged;

	/* A PARKED VOTE, sec 737: taken now its voter's chain counts, kept
	 * while it does not. */
	if (len > FZN_REV_OFF_ISSUER + FZN_PUBKEY_LEN
	    && (bytes[1] == (uint8_t)FZN_OBJECT_REVOCATION
	        || bytes[1] == (uint8_t)FZN_OBJECT_WITHDRAWAL)) {
		enum outcome out;

		judging_parked = 1;
		out = take(ap, 'r', bytes, len, bytes + FZN_REV_OFF_ISSUER);
		judging_parked = 0;
		return out == APPLIED ? 1 : 0;
	}

	if (fzn_setting_open(bytes, len, ap->sign, &s) != FZN_SETTING_OK || s.rank < 0)
		return -1;
	judged = fzn_node_apply_rank(ap, s.setter, s.scope, s.about, &rank);
	if (judged <= 0 || !stated_holds(ap, s.setter, (fzn_setting_rank_t)s.rank, rank))
		return 0;
	err = fzn_node_settings_learn(ap->settings, bytes, len, (fzn_setting_rank_t)s.rank);
	if (err == FZN_NODE_SETTINGS_BACKEND)
		return 0;
	return 1;
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
			fzn_journal_entry_t *entry = &ap->journal->journal.entries[e];
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
	/* AND WHAT WAS PARKED, sec 728, judged again once this round's
	 * standings are in: a root's add arriving after the setting it raised
	 * is what takes the setting at its stated rank. */
	if (ap->settings) {
		size_t taken = 0;

		if (fzn_node_settings_unpark(ap->settings, unpark_judged, ap, &taken)
		    == FZN_NODE_SETTINGS_BACKEND)
			return FZN_NODE_PULL_NOT_SAVED;
		tally->applied += taken;
	}
	return FZN_NODE_PULL_OK;
}
