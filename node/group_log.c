/* A group's log: project.md sec 626, and the header. */
#include "group_log.h"

#include <string.h>

#include "../wire/bytes.h"

const char *fzn_group_log_err_str(fzn_group_log_err_t err)
{
	switch (err) {
	case FZN_GROUP_LOG_OK:
		return "ok";
	case FZN_GROUP_LOG_ERR_MALFORMED:
		return "malformed";
	case FZN_GROUP_LOG_ERR_REFUSED:
		return "not an act, or its signature does not hold";
	case FZN_GROUP_LOG_ERR_NOT_NEXT:
		return "it does not follow the log";
	case FZN_GROUP_LOG_ERR_DENIED:
		return "its signer may not make it";
	case FZN_GROUP_LOG_ERR_MOOT:
		return "it changes nothing";
	case FZN_GROUP_LOG_ERR_FULL:
		return "full";
	case FZN_GROUP_LOG_ERR_ABSENT:
		return "no such group or act";
	case FZN_GROUP_LOG_ERR_GAP:
		return "acts before it are missing";
	case FZN_GROUP_LOG_ERR_BACKEND:
		return "the store refused";
	}
	return "unknown";
}

/* ---- the group an act log says ------------------------------------------ */

static size_t find(const uint8_t (*keys)[FZN_PUBKEY_LEN], size_t n, const uint8_t *key)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (memcmp(keys[i], key, FZN_PUBKEY_LEN) == 0)
			return i;
	return n;
}

static void drop_at(uint8_t (*keys)[FZN_PUBKEY_LEN], size_t *n, size_t i)
{
	memmove(keys[i], keys[i + 1u], (*n - i - 1u) * FZN_PUBKEY_LEN);
	(*n)--;
}

int fzn_group_is_member(const fzn_group_t *g, const uint8_t root[FZN_PUBKEY_LEN])
{
	return g && root
	       && find((const uint8_t (*)[FZN_PUBKEY_LEN])g->members, g->n_members, root)
	                  < g->n_members;
}

int fzn_group_is_admin(const fzn_group_t *g, const uint8_t root[FZN_PUBKEY_LEN])
{
	return g && root
	       && find((const uint8_t (*)[FZN_PUBKEY_LEN])g->admins, g->n_admins, root)
	                  < g->n_admins;
}

const fzn_group_host_t *fzn_group_host(const fzn_group_t *g, const uint8_t key[FZN_PUBKEY_LEN])
{
	size_t i;

	if (!g || !key)
		return NULL;
	for (i = 0; i < g->n_hosts; i++)
		if (memcmp(g->hosts[i].key, key, FZN_PUBKEY_LEN) == 0)
			return &g->hosts[i];
	return NULL;
}

const uint8_t *fzn_group_commit(const fzn_group_t *g, uint32_t epoch)
{
	const fzn_group_commit_t *c;

	if (!g || epoch == 0u)
		return NULL;
	c = &g->commits[epoch % FZN_GROUP_EPOCHS_KEPT];
	return c->epoch == epoch ? c->commit : NULL;
}

int fzn_group_epoch_commit(const fzn_hash_ops_t *hash, const uint8_t id[FZN_GROUP_ID_LEN],
                           uint32_t epoch, const uint8_t secret[FZN_GROUP_SECRET_LEN],
                           uint8_t out[32])
{
	static const char label[] = "fuzznet group epoch";
	uint8_t in[sizeof(label) - 1u + FZN_GROUP_ID_LEN + 4u + FZN_GROUP_SECRET_LEN];
	int ok;

	if (!hash || !hash->hash || !id || !secret || !out)
		return 0;
	memcpy(in, label, sizeof(label) - 1u);
	memcpy(in + sizeof(label) - 1u, id, FZN_GROUP_ID_LEN);
	fzn_put_be32(in + sizeof(label) - 1u + FZN_GROUP_ID_LEN, epoch);
	memcpy(in + sizeof(label) - 1u + FZN_GROUP_ID_LEN + 4u, secret, FZN_GROUP_SECRET_LEN);
	ok = hash->hash(hash->ctx, out, 32u, in, sizeof(in));
	memset(in, 0, sizeof(in));
	return ok;
}

/* A MEMBER'S HOSTS GO WITH THEM: removed or left, none is sealed another
 * epoch. */
static void drop_hosts_of(fzn_group_t *g, const uint8_t *owner)
{
	size_t i = 0;

	while (i < g->n_hosts) {
		if (memcmp(g->hosts[i].owner, owner, FZN_PUBKEY_LEN) != 0) {
			i++;
			continue;
		}
		memmove(&g->hosts[i], &g->hosts[i + 1u], (g->n_hosts - i - 1u) * sizeof(g->hosts[0]));
		g->n_hosts--;
	}
}

static fzn_group_log_err_t add_host(fzn_group_t *g, const uint8_t *owner, const uint8_t *key,
                                    uint32_t seq)
{
	fzn_group_host_t *h;

	if (fzn_group_host(g, key))
		return FZN_GROUP_LOG_ERR_MOOT;
	if (g->n_hosts == FZN_GROUP_HOSTS_MAX)
		return FZN_GROUP_LOG_ERR_FULL;
	h = &g->hosts[g->n_hosts++];
	memcpy(h->owner, owner, FZN_PUBKEY_LEN);
	memcpy(h->key, key, FZN_PUBKEY_LEN);
	h->seq = seq;
	h->joined_epoch = g->epoch;
	h->keyed_epoch = 0u;
	h->backfilled_to = g->epoch;
	return FZN_GROUP_LOG_OK;
}

/* AN EPOCH'S SECRET SEALED TO HOSTS, sec 627. The first KEYS act for the
 * current epoch fixes its commitment; every later one, for that epoch or a
 * kept older one, must carry the same. Each box is for a listed host: for
 * the current epoch one not yet given it, for an older one a host that
 * joined after it, and only while the group backfills. */
static fzn_group_log_err_t keys(fzn_group_t *g, const fzn_group_act_t *a)
{
	uint32_t e = (uint32_t)a->value;
	const uint8_t *commit = fzn_group_commit(g, e);
	size_t n = a->payload_len / FZN_GROUP_KEY_ENTRY_LEN, i, fresh = 0;
	fzn_group_host_t *h;

	if (!fzn_group_is_member(g, a->signer.owner)
	    || !fzn_group_host(g, fzn_contact_device_key(&a->signer)))
		return FZN_GROUP_LOG_ERR_DENIED;
	if (a->value == 0u || a->value > g->epoch || n == 0u || n > FZN_GROUP_KEYS_PER_ACT
	    || a->payload_len % FZN_GROUP_KEY_ENTRY_LEN != 0u)
		return FZN_GROUP_LOG_ERR_MALFORMED;
	if (commit ? memcmp(commit, a->subject, 32u) != 0 : e != g->epoch)
		return FZN_GROUP_LOG_ERR_DENIED;
	if (e < g->epoch && !g->backfill)
		return FZN_GROUP_LOG_ERR_DENIED;
	for (i = 0; i < n; i++) {
		h = (fzn_group_host_t *)fzn_group_host(g, a->payload + i * FZN_GROUP_KEY_ENTRY_LEN);
		if (!h)
			return FZN_GROUP_LOG_ERR_DENIED;
		if (e == g->epoch && h->keyed_epoch != e) {
			h->keyed_epoch = e;
			fresh++;
		} else if (e < g->epoch) {
			/* NEWEST FIRST, one epoch at a time: an epoch it holds is
			 * moot, one skipped is refused. */
			if (e >= h->backfilled_to)
				return FZN_GROUP_LOG_ERR_MOOT;
			if (e + 1u != h->backfilled_to)
				return FZN_GROUP_LOG_ERR_DENIED;
			h->backfilled_to = e;
			fresh++;
		}
	}
	if (!commit) {
		g->commits[e % FZN_GROUP_EPOCHS_KEPT].epoch = e;
		memcpy(g->commits[e % FZN_GROUP_EPOCHS_KEPT].commit, a->subject, 32u);
		fresh++;
	}
	return !fresh ? FZN_GROUP_LOG_ERR_MOOT : FZN_GROUP_LOG_OK;
}

/* MORE THAN HALF of the admins: 1 of 1, 2 of 2, 2 of 3, 3 of 4. */
static size_t majority(const fzn_group_t *g)
{
	return g->n_admins / 2u + 1u;
}

/* A PROPOSAL CARRIED: the admin set changed -- if its subject still fits --
 * and every open proposal ended. */
static void enact(fzn_group_t *g, const fzn_group_proposal_t *p)
{
	size_t i = find((const uint8_t (*)[FZN_PUBKEY_LEN])g->admins, g->n_admins, p->subject);

	if (p->kind == FZN_GROUP_ACT_ADMIN_ADD) {
		if (i == g->n_admins && fzn_group_is_member(g, p->subject)
		    && g->n_admins < FZN_GROUP_ADMINS_MAX)
			memcpy(g->admins[g->n_admins++], p->subject, FZN_PUBKEY_LEN);
	} else if (i < g->n_admins && g->n_admins > 1u) {
		drop_at(g->admins, &g->n_admins, i);
	}
	g->n_proposals = 0;
}

/* AN APPROVAL BY `who` of proposal `k`, carried when it reaches a
 * majority. */
static fzn_group_log_err_t approve(fzn_group_t *g, size_t k, const uint8_t *who)
{
	fzn_group_proposal_t *p = &g->proposals[k];

	if (find((const uint8_t (*)[FZN_PUBKEY_LEN])p->approvals, p->n_approvals, who)
	    < p->n_approvals)
		return FZN_GROUP_LOG_ERR_MOOT;
	memcpy(p->approvals[p->n_approvals++], who, FZN_PUBKEY_LEN);
	if (p->n_approvals >= majority(g)) {
		fzn_group_proposal_t carried = *p;

		enact(g, &carried);
	}
	return FZN_GROUP_LOG_OK;
}

static fzn_group_log_err_t judge(fzn_group_t *g, const fzn_group_act_t *a, const uint8_t *hash)
{
	const uint8_t *by = a->signer.owner;
	size_t i, k;

	switch (a->kind) {
	case FZN_GROUP_ACT_ADD:
		if (!fzn_group_is_admin(g, by))
			return FZN_GROUP_LOG_ERR_DENIED;
		if (fzn_group_is_member(g, a->subject))
			return FZN_GROUP_LOG_ERR_MOOT;
		if (g->n_members == FZN_GROUP_MEMBERS_MAX)
			return FZN_GROUP_LOG_ERR_FULL;
		memcpy(g->members[g->n_members++], a->subject, FZN_PUBKEY_LEN);
		g->epoch++;
		return FZN_GROUP_LOG_OK;
	case FZN_GROUP_ACT_REMOVE:
	case FZN_GROUP_ACT_LEAVE:
		if (a->kind == FZN_GROUP_ACT_REMOVE ? !fzn_group_is_admin(g, by)
		                                    : memcmp(by, a->subject, FZN_PUBKEY_LEN) != 0)
			return FZN_GROUP_LOG_ERR_DENIED;
		i = find((const uint8_t (*)[FZN_PUBKEY_LEN])g->members, g->n_members, a->subject);
		if (i == g->n_members)
			return FZN_GROUP_LOG_ERR_MOOT;
		if (fzn_group_is_admin(g, a->subject)) {
			/* AN ADMIN is removed as an admin first, by a majority; and
			 * the last one may not leave. */
			if (a->kind == FZN_GROUP_ACT_REMOVE || g->n_admins == 1u)
				return FZN_GROUP_LOG_ERR_DENIED;
			drop_at(g->admins, &g->n_admins,
			        find((const uint8_t (*)[FZN_PUBKEY_LEN])g->admins, g->n_admins,
			             a->subject));
			g->n_proposals = 0;
		}
		drop_at(g->members, &g->n_members, i);
		drop_hosts_of(g, a->subject);
		g->epoch++;
		return FZN_GROUP_LOG_OK;
	case FZN_GROUP_ACT_ADMIN_ADD:
	case FZN_GROUP_ACT_ADMIN_REMOVE:
		if (!fzn_group_is_admin(g, by))
			return FZN_GROUP_LOG_ERR_DENIED;
		if (a->kind == FZN_GROUP_ACT_ADMIN_ADD
		            ? !fzn_group_is_member(g, a->subject) || fzn_group_is_admin(g, a->subject)
		            : !fzn_group_is_admin(g, a->subject) || g->n_admins == 1u)
			return FZN_GROUP_LOG_ERR_MOOT;
		/* THE SAME CHANGE PROPOSED AGAIN is an approval of the first. */
		for (k = 0; k < g->n_proposals; k++)
			if (g->proposals[k].kind == a->kind
			    && memcmp(g->proposals[k].subject, a->subject, FZN_PUBKEY_LEN) == 0)
				return approve(g, k, by);
		if (a->kind == FZN_GROUP_ACT_ADMIN_ADD && g->n_admins == FZN_GROUP_ADMINS_MAX)
			return FZN_GROUP_LOG_ERR_FULL;
		if (g->n_proposals == FZN_GROUP_PROPOSALS_MAX)
			return FZN_GROUP_LOG_ERR_FULL;
		k = g->n_proposals++;
		memset(&g->proposals[k], 0, sizeof(g->proposals[k]));
		memcpy(g->proposals[k].hash, hash, 32u);
		g->proposals[k].kind = a->kind;
		memcpy(g->proposals[k].subject, a->subject, FZN_PUBKEY_LEN);
		return approve(g, k, by);
	case FZN_GROUP_ACT_APPROVE:
		if (!fzn_group_is_admin(g, by))
			return FZN_GROUP_LOG_ERR_DENIED;
		for (k = 0; k < g->n_proposals; k++)
			if (memcmp(g->proposals[k].hash, a->subject, 32u) == 0)
				return approve(g, k, by);
		return FZN_GROUP_LOG_ERR_MOOT;
	case FZN_GROUP_ACT_SET:
		if (!fzn_group_is_admin(g, by))
			return FZN_GROUP_LOG_ERR_DENIED;
		if (a->setting != FZN_GROUP_SETTING_BACKFILL || a->value > 1u)
			return FZN_GROUP_LOG_ERR_MALFORMED;
		if (g->backfill == (uint8_t)a->value)
			return FZN_GROUP_LOG_ERR_MOOT;
		g->backfill = (uint8_t)a->value;
		return FZN_GROUP_LOG_OK;
	case FZN_GROUP_ACT_HOST:
		if (!fzn_group_is_member(g, by))
			return FZN_GROUP_LOG_ERR_DENIED;
		return add_host(g, by, fzn_contact_device_key(&a->signer), a->seq);
	case FZN_GROUP_ACT_KEYS:
		return keys(g, a);
	}
	return FZN_GROUP_LOG_ERR_MALFORMED;
}

fzn_group_log_err_t fzn_group_apply(fzn_group_t *g, const fzn_group_act_t *a,
                                    const uint8_t hash[32])
{
	static fzn_group_t next;
	static const uint8_t zero[32];
	fzn_group_log_err_t err;

	if (!g || !a || !hash)
		return FZN_GROUP_LOG_ERR_MALFORMED;
	if (a->kind == FZN_GROUP_ACT_CREATE) {
		if (a->seq != 0u || memcmp(a->group, zero, 32u) != 0 || memcmp(a->prev, zero, 32u) != 0)
			return FZN_GROUP_LOG_ERR_NOT_NEXT;
		memset(g, 0, sizeof(*g));
		memcpy(g->id, hash, FZN_GROUP_ID_LEN);
		memcpy(g->head, hash, 32u);
		g->seq = 1u;
		g->epoch = 1u;
		g->backfill = 1u;
		memcpy(g->members[0], a->signer.owner, FZN_PUBKEY_LEN);
		memcpy(g->admins[0], a->signer.owner, FZN_PUBKEY_LEN);
		g->n_members = g->n_admins = 1u;
		/* ITS MAKER'S HOST is its first host. */
		return add_host(g, a->signer.owner, fzn_contact_device_key(&a->signer), 0u);
	}
	if (g->seq == 0u || a->seq != g->seq || memcmp(a->group, g->id, FZN_GROUP_ID_LEN) != 0
	    || memcmp(a->prev, g->head, 32u) != 0)
		return FZN_GROUP_LOG_ERR_NOT_NEXT;
	next = *g;
	err = judge(&next, a, hash);
	if (err != FZN_GROUP_LOG_OK)
		return err;
	memcpy(next.head, hash, 32u);
	next.seq++;
	*g = next;
	return FZN_GROUP_LOG_OK;
}

/* ---- the group, as the store keeps it ----------------------------------- */

#define GROUP_VERSION 2u
#define HOST_LEN (2u * FZN_PUBKEY_LEN + 4u * 4u)
#define PROPOSAL_LEN (32u + 1u + FZN_PUBKEY_LEN + 1u + FZN_GROUP_ADMINS_MAX * FZN_PUBKEY_LEN)
#define GROUP_BYTES_MAX                                                                    \
	(1u + FZN_GROUP_ID_LEN + 4u + 32u + 4u + 1u + 2u + FZN_GROUP_MEMBERS_MAX * FZN_PUBKEY_LEN \
	 + 1u + FZN_GROUP_ADMINS_MAX * FZN_PUBKEY_LEN + 1u + FZN_GROUP_PROPOSALS_MAX * PROPOSAL_LEN \
	 + 2u + FZN_GROUP_HOSTS_MAX * HOST_LEN + 1u + FZN_GROUP_EPOCHS_KEPT * (4u + 32u))

static size_t group_encode(const fzn_group_t *g, uint8_t *out)
{
	size_t at = 0, k, n;

	out[at++] = GROUP_VERSION;
	memcpy(out + at, g->id, FZN_GROUP_ID_LEN);
	at += FZN_GROUP_ID_LEN;
	fzn_put_be32(out + at, g->seq);
	at += 4u;
	memcpy(out + at, g->head, 32u);
	at += 32u;
	fzn_put_be32(out + at, g->epoch);
	at += 4u;
	out[at++] = g->backfill;
	fzn_put_be16(out + at, (uint16_t)g->n_members);
	at += 2u;
	memcpy(out + at, g->members, g->n_members * FZN_PUBKEY_LEN);
	at += g->n_members * FZN_PUBKEY_LEN;
	out[at++] = (uint8_t)g->n_admins;
	memcpy(out + at, g->admins, g->n_admins * FZN_PUBKEY_LEN);
	at += g->n_admins * FZN_PUBKEY_LEN;
	out[at++] = (uint8_t)g->n_proposals;
	for (k = 0; k < g->n_proposals; k++) {
		const fzn_group_proposal_t *p = &g->proposals[k];

		memcpy(out + at, p->hash, 32u);
		at += 32u;
		out[at++] = p->kind;
		memcpy(out + at, p->subject, FZN_PUBKEY_LEN);
		at += FZN_PUBKEY_LEN;
		out[at++] = (uint8_t)p->n_approvals;
		memcpy(out + at, p->approvals, p->n_approvals * FZN_PUBKEY_LEN);
		at += p->n_approvals * FZN_PUBKEY_LEN;
	}
	fzn_put_be16(out + at, (uint16_t)g->n_hosts);
	at += 2u;
	for (k = 0; k < g->n_hosts; k++) {
		memcpy(out + at, g->hosts[k].owner, FZN_PUBKEY_LEN);
		memcpy(out + at + FZN_PUBKEY_LEN, g->hosts[k].key, FZN_PUBKEY_LEN);
		fzn_put_be32(out + at + 2u * FZN_PUBKEY_LEN, g->hosts[k].seq);
		fzn_put_be32(out + at + 2u * FZN_PUBKEY_LEN + 4u, g->hosts[k].joined_epoch);
		fzn_put_be32(out + at + 2u * FZN_PUBKEY_LEN + 8u, g->hosts[k].keyed_epoch);
		fzn_put_be32(out + at + 2u * FZN_PUBKEY_LEN + 12u, g->hosts[k].backfilled_to);
		at += HOST_LEN;
	}
	/* ONLY THE SLOTS IN USE: a new group has one. */
	n = 0;
	for (k = 0; k < FZN_GROUP_EPOCHS_KEPT; k++)
		n += g->commits[k].epoch != 0u;
	out[at++] = (uint8_t)n;
	for (k = 0; k < FZN_GROUP_EPOCHS_KEPT; k++)
		if (g->commits[k].epoch) {
			fzn_put_be32(out + at, g->commits[k].epoch);
			memcpy(out + at + 4u, g->commits[k].commit, 32u);
			at += 4u + 32u;
		}
	return at;
}

static int group_decode(const uint8_t *in, size_t len, fzn_group_t *g)
{
	size_t at = 0, k, n;

	memset(g, 0, sizeof(*g));
#define NEED(x)                         \
	do {                            \
		if (len - at < (size_t)(x)) \
			return 0;       \
	} while (0)
	NEED(1u + FZN_GROUP_ID_LEN + 4u + 32u + 4u + 1u + 2u);
	if (in[at++] != GROUP_VERSION)
		return 0;
	memcpy(g->id, in + at, FZN_GROUP_ID_LEN);
	at += FZN_GROUP_ID_LEN;
	g->seq = fzn_get_be32(in + at);
	at += 4u;
	memcpy(g->head, in + at, 32u);
	at += 32u;
	g->epoch = fzn_get_be32(in + at);
	at += 4u;
	g->backfill = in[at++];
	n = fzn_get_be16(in + at);
	at += 2u;
	if (n > FZN_GROUP_MEMBERS_MAX)
		return 0;
	NEED(n * FZN_PUBKEY_LEN + 1u);
	memcpy(g->members, in + at, n * FZN_PUBKEY_LEN);
	g->n_members = n;
	at += n * FZN_PUBKEY_LEN;
	n = in[at++];
	if (n > FZN_GROUP_ADMINS_MAX)
		return 0;
	NEED(n * FZN_PUBKEY_LEN + 1u);
	memcpy(g->admins, in + at, n * FZN_PUBKEY_LEN);
	g->n_admins = n;
	at += n * FZN_PUBKEY_LEN;
	g->n_proposals = in[at++];
	if (g->n_proposals > FZN_GROUP_PROPOSALS_MAX)
		return 0;
	for (k = 0; k < g->n_proposals; k++) {
		fzn_group_proposal_t *p = &g->proposals[k];

		NEED(32u + 1u + FZN_PUBKEY_LEN + 1u);
		memcpy(p->hash, in + at, 32u);
		at += 32u;
		p->kind = in[at++];
		memcpy(p->subject, in + at, FZN_PUBKEY_LEN);
		at += FZN_PUBKEY_LEN;
		n = in[at++];
		if (n > FZN_GROUP_ADMINS_MAX)
			return 0;
		NEED(n * FZN_PUBKEY_LEN);
		memcpy(p->approvals, in + at, n * FZN_PUBKEY_LEN);
		p->n_approvals = n;
		at += n * FZN_PUBKEY_LEN;
	}
	NEED(2u);
	n = fzn_get_be16(in + at);
	at += 2u;
	if (n > FZN_GROUP_HOSTS_MAX)
		return 0;
	NEED(n * HOST_LEN + 1u);
	for (k = 0; k < n; k++) {
		memcpy(g->hosts[k].owner, in + at, FZN_PUBKEY_LEN);
		memcpy(g->hosts[k].key, in + at + FZN_PUBKEY_LEN, FZN_PUBKEY_LEN);
		g->hosts[k].seq = fzn_get_be32(in + at + 2u * FZN_PUBKEY_LEN);
		g->hosts[k].joined_epoch = fzn_get_be32(in + at + 2u * FZN_PUBKEY_LEN + 4u);
		g->hosts[k].keyed_epoch = fzn_get_be32(in + at + 2u * FZN_PUBKEY_LEN + 8u);
		g->hosts[k].backfilled_to = fzn_get_be32(in + at + 2u * FZN_PUBKEY_LEN + 12u);
		at += HOST_LEN;
	}
	g->n_hosts = n;
	n = in[at++];
	if (n > FZN_GROUP_EPOCHS_KEPT)
		return 0;
	NEED(n * (4u + 32u));
	for (k = 0; k < n; k++) {
		uint32_t e = fzn_get_be32(in + at);
		fzn_group_commit_t *c = &g->commits[e % FZN_GROUP_EPOCHS_KEPT];

		if (e == 0u || c->epoch != 0u)
			return 0;
		c->epoch = e;
		memcpy(c->commit, in + at + 4u, 32u);
		at += 4u + 32u;
	}
#undef NEED
	return at == len;
}

static fzn_group_log_err_t group_save(const fzn_persist_ops_t *store, const fzn_group_t *g)
{
	static uint8_t bytes[GROUP_BYTES_MAX];
	size_t n = group_encode(g, bytes);

	return store->save(store->ctx, FZN_PERSIST_GROUP, g->id, bytes, n) ? FZN_GROUP_LOG_OK
	                                                                    : FZN_GROUP_LOG_ERR_BACKEND;
}

fzn_group_log_err_t fzn_group_log_put(const fzn_persist_ops_t *store, const fzn_group_t *g)
{
	if (!store || !store->save || !g || g->n_members > FZN_GROUP_MEMBERS_MAX
	    || g->n_admins > FZN_GROUP_ADMINS_MAX || g->n_proposals > FZN_GROUP_PROPOSALS_MAX
	    || g->n_hosts > FZN_GROUP_HOSTS_MAX)
		return FZN_GROUP_LOG_ERR_MALFORMED;
	return group_save(store, g);
}

fzn_group_log_err_t fzn_group_log_get(const fzn_persist_ops_t *store,
                                      const uint8_t id[FZN_GROUP_ID_LEN], fzn_group_t *out)
{
	static uint8_t bytes[GROUP_BYTES_MAX];
	size_t n = 0;

	if (!store || !store->load || !id || !out)
		return FZN_GROUP_LOG_ERR_MALFORMED;
	if (!store->load(store->ctx, FZN_PERSIST_GROUP, id, bytes, sizeof(bytes), &n))
		return FZN_GROUP_LOG_ERR_ABSENT;
	return group_decode(bytes, n, out) ? FZN_GROUP_LOG_OK : FZN_GROUP_LOG_ERR_BACKEND;
}

fzn_group_log_err_t fzn_group_log_list(const fzn_persist_ops_t *store,
                                       uint8_t (*ids)[FZN_GROUP_ID_LEN], size_t cap,
                                       size_t *count)
{
	if (!store || !ids || !count)
		return FZN_GROUP_LOG_ERR_MALFORMED;
	*count = 0;
	if (!store->list)
		return FZN_GROUP_LOG_ERR_BACKEND;
	return store->list(store->ctx, FZN_PERSIST_GROUP, (uint8_t *)ids, cap, count)
	               ? FZN_GROUP_LOG_OK
	               : FZN_GROUP_LOG_ERR_BACKEND;
}

/* ---- the acts, as the store keeps them ---------------------------------- */

/* WHERE AN ACT IS FILED: the hash of its group's id and its place, so a
 * log is walked forward with nothing but the group. */
static int act_subject(const fzn_group_log_ops_t *ops, const uint8_t *id, uint32_t seq,
                       uint8_t out[FZN_PUBKEY_LEN])
{
	uint8_t in[FZN_GROUP_ID_LEN + 4u];

	memcpy(in, id, FZN_GROUP_ID_LEN);
	fzn_put_be32(in + FZN_GROUP_ID_LEN, seq);
	return ops->hash->hash(ops->hash->ctx, out, FZN_PUBKEY_LEN, in, sizeof(in));
}

fzn_group_log_err_t fzn_group_log_act(const fzn_group_log_ops_t *ops,
                                      const uint8_t id[FZN_GROUP_ID_LEN], uint32_t seq,
                                      uint8_t *out, size_t cap, size_t *len)
{
	uint8_t subject[FZN_PUBKEY_LEN];

	if (!ops || !ops->store || !ops->store->load || !ops->hash || !id || !out || !len)
		return FZN_GROUP_LOG_ERR_MALFORMED;
	if (!act_subject(ops, id, seq, subject))
		return FZN_GROUP_LOG_ERR_BACKEND;
	return ops->store->load(ops->store->ctx, FZN_PERSIST_GROUP_ACT, subject, out, cap, len)
	               ? FZN_GROUP_LOG_OK
	               : FZN_GROUP_LOG_ERR_ABSENT;
}

static fzn_group_log_err_t act_save(const fzn_group_log_ops_t *ops, const uint8_t *id,
                                    uint32_t seq, const uint8_t *bytes, size_t len)
{
	uint8_t subject[FZN_PUBKEY_LEN];

	if (!act_subject(ops, id, seq, subject)
	    || !ops->store->save(ops->store->ctx, FZN_PERSIST_GROUP_ACT, subject, bytes, len))
		return FZN_GROUP_LOG_ERR_BACKEND;
	return FZN_GROUP_LOG_OK;
}

/* THE GROUP AS ITS FIRST `upto` ACTS SAY, replayed from the store: what a
 * fork is judged against. */
static fzn_group_log_err_t replay(const fzn_group_log_ops_t *ops, const uint8_t *id,
                                  uint32_t upto, fzn_group_t *g)
{
	static uint8_t bytes[FZN_GROUP_ACT_MAX];
	static fzn_group_act_t a;
	uint8_t hash[32];
	size_t n = 0;
	uint32_t s;

	memset(g, 0, sizeof(*g));
	for (s = 0; s < upto; s++)
		if (fzn_group_log_act(ops, id, s, bytes, sizeof(bytes), &n) != FZN_GROUP_LOG_OK
		    || fzn_group_act_decode(bytes, n, &a) != FZN_GROUP_ACT_OK
		    || fzn_group_act_hash(&a, ops->hash, hash) != FZN_GROUP_ACT_OK
		    || fzn_group_apply(g, &a, hash) != FZN_GROUP_LOG_OK)
			return FZN_GROUP_LOG_ERR_BACKEND;
	return FZN_GROUP_LOG_OK;
}

fzn_group_log_err_t fzn_group_log_offer(const fzn_group_log_ops_t *ops, const uint8_t *bytes,
                                        size_t len, fzn_group_offer_t *did, size_t *dropped)
{
	static fzn_group_act_t a, there;
	static fzn_group_t g, before;
	static uint8_t held[FZN_GROUP_ACT_MAX];
	uint8_t hash[32], held_hash[32], subject[FZN_PUBKEY_LEN];
	size_t n = 0;
	uint32_t s;
	fzn_group_log_err_t err;

	if (!ops || !ops->store || !ops->store->load || !ops->store->save || !ops->hash
	    || !ops->sign || !ops->member || !bytes || !did || !dropped)
		return FZN_GROUP_LOG_ERR_MALFORMED;
	*dropped = 0;
	if (fzn_group_act_decode(bytes, len, &a) != FZN_GROUP_ACT_OK
	    || fzn_group_act_verify(&a, ops->sign, ops->member) != FZN_GROUP_ACT_OK
	    || fzn_group_act_hash(&a, ops->hash, hash) != FZN_GROUP_ACT_OK)
		return FZN_GROUP_LOG_ERR_REFUSED;
	if (a.kind == FZN_GROUP_ACT_CREATE) {
		if (fzn_group_log_get(ops->store, hash, &g) == FZN_GROUP_LOG_OK) {
			*did = FZN_GROUP_OFFER_HELD;
			return FZN_GROUP_LOG_OK;
		}
		err = fzn_group_apply(&g, &a, hash);
		if (err == FZN_GROUP_LOG_OK)
			err = act_save(ops, g.id, 0u, bytes, len);
		if (err == FZN_GROUP_LOG_OK)
			err = group_save(ops->store, &g);
		if (err == FZN_GROUP_LOG_OK)
			*did = FZN_GROUP_OFFER_TAKEN;
		return err;
	}
	err = fzn_group_log_get(ops->store, a.group, &g);
	if (err != FZN_GROUP_LOG_OK)
		return err;
	if (a.seq > g.seq)
		return FZN_GROUP_LOG_ERR_GAP;
	if (a.seq == g.seq) {
		err = fzn_group_apply(&g, &a, hash);
		if (err == FZN_GROUP_LOG_OK)
			err = act_save(ops, g.id, a.seq, bytes, len);
		if (err == FZN_GROUP_LOG_OK)
			err = group_save(ops->store, &g);
		if (err == FZN_GROUP_LOG_OK)
			*did = FZN_GROUP_OFFER_TAKEN;
		return err;
	}
	/* AT A PLACE ALREADY FILLED: the same act, or a fork. */
	if (a.seq == 0u
	    || fzn_group_log_act(ops, a.group, a.seq, held, sizeof(held), &n) != FZN_GROUP_LOG_OK
	    || fzn_group_act_decode(held, n, &there) != FZN_GROUP_ACT_OK
	    || fzn_group_act_hash(&there, ops->hash, held_hash) != FZN_GROUP_ACT_OK)
		return FZN_GROUP_LOG_ERR_BACKEND;
	if (memcmp(hash, held_hash, 32u) == 0) {
		*did = FZN_GROUP_OFFER_HELD;
		return FZN_GROUP_LOG_OK;
	}
	err = replay(ops, a.group, a.seq, &before);
	if (err != FZN_GROUP_LOG_OK)
		return err;
	err = fzn_group_apply(&before, &a, hash);
	if (err != FZN_GROUP_LOG_OK)
		return err;
	/* THE LOWER HASH STANDS, wherever it arrived first. */
	if (memcmp(held_hash, hash, 32u) < 0) {
		*did = FZN_GROUP_OFFER_LOST;
		return FZN_GROUP_LOG_OK;
	}
	/* THE KEPT ACT AND THE GROUP IT SAYS FIRST, then the lost tail: an act
	 * past the head is never read, and is overwritten when its place is
	 * filled again, so a removal that fails leaves nothing wrong. */
	err = act_save(ops, a.group, a.seq, bytes, len);
	if (err == FZN_GROUP_LOG_OK)
		err = group_save(ops->store, &before);
	if (err != FZN_GROUP_LOG_OK)
		return err;
	*dropped = g.seq - a.seq;
	if (ops->dropped)
		ops->dropped(ops->dropped_ctx, held, n);
	for (s = a.seq + 1u; s < g.seq; s++) {
		if (ops->dropped
		    && fzn_group_log_act(ops, a.group, s, held, sizeof(held), &n) == FZN_GROUP_LOG_OK)
			ops->dropped(ops->dropped_ctx, held, n);
		if (ops->store->remove && act_subject(ops, a.group, s, subject))
			(void)ops->store->remove(ops->store->ctx, FZN_PERSIST_GROUP_ACT, subject);
	}
	*did = FZN_GROUP_OFFER_REPLACED;
	return FZN_GROUP_LOG_OK;
}
