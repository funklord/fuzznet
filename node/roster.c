/* See roster.h. */

#include "roster.h"

#include "../contact/contact.h"

#include <stdio.h>
#include <string.h>

/* A record's blob: the record, its chain's hop count, its hops. Only adds
 * and removals are written or learned -- settings are refused by admission
 * (`roster.h`) -- so the record is always FZN_ROSTER_MIN_LEN. */
#define BODY(hops) ((size_t)FZN_ROSTER_MIN_LEN + 1u + ((size_t)(hops) * (size_t)FZN_HOP_LEN))
#define BLOB_MAX ((size_t)FZN_PERSIST_HEAD_LEN + BODY(FZN_CHAIN_MAX_HOPS))

const char *fzn_node_roster_err_str(fzn_node_roster_err_t err)
{
	switch (err) {
	case FZN_NODE_ROSTER_OK:
		return "ok";
	case FZN_NODE_ROSTER_MALFORMED:
		return "malformed";
	case FZN_NODE_ROSTER_NO_STANDING:
		return "this node is not the root and holds no chain to write contacts with";
	case FZN_NODE_ROSTER_REFUSED:
		return "the contact record would not admit";
	case FZN_NODE_ROSTER_NOT_SAVED:
		return "the contact record is in force and not saved";
	case FZN_NODE_ROSTER_ABSENT:
		return "no active contact with that key";
	case FZN_NODE_ROSTER_STORE:
		return "the contact records would not read";
	case FZN_NODE_ROSTER_NOT_LOGGED:
		return "written, and not in this root's log: it would fall at this root's removal";
	case FZN_NODE_ROSTER_FULL:
		return "a table of the roster is full; the node must be given a larger one";
	}
	return "unknown";
}

fzn_node_roster_err_t fzn_node_roster_init(fzn_node_roster_t *nr,
                                           const uint8_t root[FZN_PUBKEY_LEN],
                                           const fzn_cap_id_t *capability,
                                           const fzn_sign_ops_t *sign,
                                           const fzn_root_ops_t *roots,
                                           const fzn_hash_ops_t *hash)
{
	if (!nr || !root || !capability || !sign || !hash || !hash->hash)
		return FZN_NODE_ROSTER_MALFORMED;
	memset(nr, 0, sizeof(*nr));
	if (fzn_roster_init(&nr->roster, nr->entries, FZN_NODE_ROSTER_ENTRIES, nr->writers,
	                    FZN_NODE_ROSTER_WRITERS)
	    != FZN_ROSTER_OK)
		return FZN_NODE_ROSTER_MALFORMED;
	memcpy(nr->root, root, FZN_PUBKEY_LEN);
	nr->capability = *capability;
	nr->authority.root = nr->root;
	nr->authority.capability = &nr->capability;
	nr->authority.sign = sign;
	/* THE SET, OR THE PINNED ROOT ALONE; AND THE HASH ALWAYS, sec 497: a
	 * revoked member's records are judged by its log's cut whether the
	 * estate has one root or several, and with no hash nothing it wrote
	 * could be shown to lie before the line. */
	nr->authority.roots = roots;
	nr->authority.hash = hash;
	nr->hash = hash;
	return FZN_NODE_ROSTER_OK;
}

/* The hash a record is filed under, which is also the act a root logs. */
static int record_id(const fzn_hash_ops_t *hash, const uint8_t *record,
                     uint8_t id[FZN_PUBKEY_LEN])
{
	return hash && hash->hash
	       && hash->hash(hash->ctx, id, FZN_PUBKEY_LEN, record, FZN_ROSTER_MIN_LEN);
}

static fzn_node_roster_err_t admit(fzn_node_roster_t *nr, const uint8_t *record,
                                   size_t record_len, const uint8_t (*hops)[FZN_HOP_LEN],
                                   size_t hop_count)
{
	fzn_chain_hop_t opened[FZN_CHAIN_MAX_HOPS];
	fzn_roster_record_t rec;
	size_t i;

	if (record_len != FZN_ROSTER_MIN_LEN || hop_count > FZN_CHAIN_MAX_HOPS
	    || (hop_count && !hops))
		return FZN_NODE_ROSTER_MALFORMED;
	for (i = 0; i < hop_count; i++)
		if (fzn_hop_open(hops[i], FZN_HOP_LEN, &opened[i]) != FZN_CHAIN_OK)
			return FZN_NODE_ROSTER_REFUSED;
	if (fzn_roster_open(record, record_len, &rec) != FZN_ROSTER_OK)
		return FZN_NODE_ROSTER_REFUSED;
	switch (fzn_roster_admit(&nr->roster, rec, opened, hop_count, &nr->authority)) {
	case FZN_ROSTER_OK:
		return FZN_NODE_ROSTER_OK;
	case FZN_ROSTER_ERR_FULL:
		/* WHICH TABLE, sec 704: a full one is given room, and the record
		 * taken then; a third FULL, an incarnation's removers, is the
		 * quorum's size and truly few. */
		if (nr->roster.used >= nr->roster.capacity) {
			nr->entries_wanted = nr->roster.used + 1u;
			return FZN_NODE_ROSTER_FULL;
		}
		if (nr->roster.writers_used >= nr->roster.writer_capacity) {
			nr->writers_wanted = nr->roster.writers_used + 1u;
			return FZN_NODE_ROSTER_FULL;
		}
		return FZN_NODE_ROSTER_REFUSED;
	default:
		return FZN_NODE_ROSTER_REFUSED;
	}
}

static fzn_node_roster_err_t save(const fzn_persist_ops_t *store, const fzn_hash_ops_t *hash,
                                  const uint8_t *record, const uint8_t (*hops)[FZN_HOP_LEN],
                                  size_t hop_count)
{
	static uint8_t blob[BLOB_MAX];
	uint8_t id[FZN_PUBKEY_LEN];
	uint8_t *body = blob + FZN_PERSIST_HEAD_LEN;
	size_t i;

	if (!store->save || !record_id(hash, record, id)
	    || fzn_persist_head_write(blob, sizeof(blob), BODY(hop_count), FZN_PERSIST_BLOB_ROSTER)
	               != FZN_PERSIST_OK)
		return FZN_NODE_ROSTER_NOT_SAVED;
	memcpy(body, record, FZN_ROSTER_MIN_LEN);
	body[FZN_ROSTER_MIN_LEN] = (uint8_t)hop_count;
	for (i = 0; i < hop_count; i++)
		memcpy(body + FZN_ROSTER_MIN_LEN + 1u + (i * (size_t)FZN_HOP_LEN), hops[i],
		       FZN_HOP_LEN);
	if (!store->save(store->ctx, FZN_PERSIST_ROSTER, id, blob,
	                 FZN_PERSIST_HEAD_LEN + BODY(hop_count)))
		return FZN_NODE_ROSTER_NOT_SAVED;
	return FZN_NODE_ROSTER_OK;
}

int fzn_node_roster_get(const fzn_persist_ops_t *store, const uint8_t id[FZN_PUBKEY_LEN],
                        uint8_t record[FZN_ROSTER_MIN_LEN], uint8_t (*hops)[FZN_HOP_LEN],
                        size_t *hop_count)
{
	static uint8_t blob[BLOB_MAX];
	const uint8_t *body = blob + FZN_PERSIST_HEAD_LEN;
	size_t len = 0, n, i;

	if (!store || !store->load || !id || !record || !hops || !hop_count
	    || !store->load(store->ctx, FZN_PERSIST_ROSTER, id, blob, sizeof(blob), &len)
	    || len < FZN_PERSIST_HEAD_LEN + BODY(0))
		return 0;
	n = body[FZN_ROSTER_MIN_LEN];
	if (n > FZN_CHAIN_MAX_HOPS
	    || fzn_persist_head_check(blob, len, BODY(n), FZN_PERSIST_BLOB_ROSTER) != FZN_PERSIST_OK)
		return 0;
	memcpy(record, body, FZN_ROSTER_MIN_LEN);
	for (i = 0; i < n; i++)
		memcpy(hops[i], body + FZN_ROSTER_MIN_LEN + 1u + (i * (size_t)FZN_HOP_LEN),
		       FZN_HOP_LEN);
	*hop_count = n;
	return 1;
}

/* ONE RECORD, walked at load: admitted, or skipped when it will not admit --
 * one written under a root this node has since left, say -- but a table
 * found full stops the load, so the caller can give room and load again. */
struct roster_walk {
	fzn_node_roster_t *nr;
	const fzn_persist_ops_t *store;
	size_t *count;
	fzn_node_roster_err_t err;
};

static int roster_walked(void *arg, const uint8_t id[FZN_PUBKEY_LEN])
{
	static uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
	struct roster_walk *w = arg;
	uint8_t record[FZN_ROSTER_MIN_LEN];
	size_t n = 0;
	fzn_node_roster_err_t err;

	if (!fzn_node_roster_get(w->store, id, record, hops, &n)) {
		w->err = FZN_NODE_ROSTER_STORE;
		return 0;
	}
	err = admit(w->nr, record, sizeof(record), (const uint8_t (*)[FZN_HOP_LEN])hops, n);
	if (err == FZN_NODE_ROSTER_FULL) {
		w->err = err;
		return 0;
	}
	if (err == FZN_NODE_ROSTER_OK)
		(*w->count)++;
	return 1;
}

fzn_node_roster_err_t fzn_node_roster_load(fzn_node_roster_t *nr,
                                           const fzn_persist_ops_t *store, size_t *count)
{
	struct roster_walk w;

	if (!nr || !store || (!store->list && !store->each) || !count)
		return FZN_NODE_ROSTER_MALFORMED;
	*count = 0;
	w.nr = nr;
	w.store = store;
	w.count = count;
	w.err = FZN_NODE_ROSTER_OK;
	if (!fzn_persist_each(store, FZN_PERSIST_ROSTER, roster_walked, &w))
		return FZN_NODE_ROSTER_STORE;
	return w.err;
}

fzn_node_roster_err_t fzn_node_roster_use(fzn_node_roster_t *nr, fzn_roster_entry_t *entries,
                                          size_t capacity, fzn_roster_writer_t *writers,
                                          size_t writer_capacity)
{
	if (!nr || !entries || !writers || capacity < nr->roster.used || capacity == 0u
	    || writer_capacity < nr->roster.writers_used || writer_capacity == 0u)
		return FZN_NODE_ROSTER_MALFORMED;
	if (entries != nr->roster.entries)
		memmove(entries, nr->roster.entries, nr->roster.used * sizeof(*entries));
	if (writers != nr->roster.writers)
		memmove(writers, nr->roster.writers, nr->roster.writers_used * sizeof(*writers));
	nr->roster.entries = entries;
	nr->roster.capacity = capacity;
	nr->roster.writers = writers;
	nr->roster.writer_capacity = writer_capacity;
	nr->entries_wanted = nr->writers_wanted = 0;
	return FZN_NODE_ROSTER_OK;
}

int fzn_node_roster_wants(const fzn_node_roster_t *nr, size_t *entries, size_t *writers)
{
	if (!nr || !entries || !writers || (!nr->entries_wanted && !nr->writers_wanted))
		return 0;
	*entries = nr->entries_wanted > nr->roster.capacity ? nr->entries_wanted
	                                                     : nr->roster.capacity;
	*writers = nr->writers_wanted > nr->roster.writer_capacity ? nr->writers_wanted
	                                                            : nr->roster.writer_capacity;
	return 1;
}

fzn_node_roster_err_t fzn_node_roster_learn(fzn_node_roster_t *nr,
                                            const fzn_persist_ops_t *store,
                                            const uint8_t *record, size_t record_len,
                                            const uint8_t (*hops)[FZN_HOP_LEN],
                                            size_t hop_count)
{
	fzn_node_roster_err_t err;

	if (!nr || !store || !record)
		return FZN_NODE_ROSTER_MALFORMED;
	err = admit(nr, record, record_len, hops, hop_count);
	if (err != FZN_NODE_ROSTER_OK)
		return err;
	return save(store, nr->hash, record, hops, hop_count);
}

/* An incarnation of `subject` held here, any state. */
static int held(const fzn_node_roster_t *nr, const uint8_t subject[FZN_PUBKEY_LEN])
{
	size_t i;

	for (i = 0; i < nr->roster.used; i++)
		if (memcmp(nr->roster.entries[i].subject, subject, FZN_PUBKEY_LEN) == 0)
			return 1;
	return 0;
}

/* THE INCARNATION A REMOVAL BY `writer` IS ABOUT: the active one, or --
 * since a second member confirming is that member removing the same
 * incarnation (`roster.h`) -- one already SUSPENDED that `writer` has not
 * removed. 0 when there is neither. */
static int removable(const fzn_node_roster_t *nr, const uint8_t subject[FZN_PUBKEY_LEN],
                     const uint8_t writer[FZN_PUBKEY_LEN],
                     const fzn_revocation_store_t *revocations, size_t k,
                     uint8_t incarnation[FZN_ROSTER_INCARNATION_LEN])
{
	size_t i, j;

	if (fzn_roster_active(&nr->roster, subject, revocations, k, incarnation))
		return 1;
	for (i = 0; i < nr->roster.used; i++) {
		const fzn_roster_entry_t *e = &nr->roster.entries[i];
		int mine = 0;

		if (memcmp(e->subject, subject, FZN_PUBKEY_LEN) != 0
		    || fzn_roster_state(&nr->roster, subject, e->incarnation, revocations, k)
		               != FZN_ROSTER_SUSPENDED)
			continue;
		for (j = 0; j < e->remover_count; j++)
			if (memcmp(nr->writers[e->remover[j]].key, writer, FZN_PUBKEY_LEN) == 0)
				mine = 1;
		if (!mine) {
			memcpy(incarnation, e->incarnation, FZN_ROSTER_INCARNATION_LEN);
			return 1;
		}
	}
	return 0;
}

fzn_node_roster_err_t fzn_node_roster_write(fzn_node_roster_t *nr,
                                            const fzn_persist_ops_t *store,
                                            const fzn_node_identity_t *id,
                                            const fzn_node_authority_t *authority,
                                            const fzn_random_ops_t *rng,
                                            const uint8_t subject[FZN_PUBKEY_LEN], int add,
                                            const fzn_revocation_store_t *revocations,
                                            size_t k)
{
	uint8_t incarnation[FZN_ROSTER_INCARNATION_LEN];
	uint8_t record[FZN_ROSTER_MIN_LEN];
	fzn_chain_hop_t opened[FZN_CHAIN_MAX_HOPS];
	size_t len = 0, hop_count = 0, i;
	const uint8_t (*hops)[FZN_HOP_LEN] = NULL;
	fzn_roster_err_t rerr;
	fzn_node_roster_err_t err;

	if (!nr || !store || !id || !id->sign || !subject || (add && (!rng || !rng->fill)))
		return FZN_NODE_ROSTER_MALFORMED;
	/* STANDING FIRST: the root alone, or a chain naming this node as its
	 * last grantee for the capability. Admission would refuse anything
	 * else; asking first says why. */
	if (authority && authority->hop_count) {
		if (authority->hop_count > FZN_CHAIN_MAX_HOPS || !authority->hops)
			return FZN_NODE_ROSTER_NO_STANDING;
		for (i = 0; i < authority->hop_count; i++)
			if (fzn_hop_open(authority->hops[i], FZN_HOP_LEN, &opened[i]) != FZN_CHAIN_OK)
				return FZN_NODE_ROSTER_NO_STANDING;
		if (memcmp(fzn_hop_grantee(opened[authority->hop_count - 1u]), id->pubkey,
		           FZN_PUBKEY_LEN) != 0
		    || memcmp(fzn_hop_capability(opened[authority->hop_count - 1u]), &nr->capability,
		              sizeof(nr->capability)) != 0)
			return FZN_NODE_ROSTER_NO_STANDING;
		hops = authority->hops;
		hop_count = authority->hop_count;
	} else if (memcmp(id->pubkey, nr->root, FZN_PUBKEY_LEN) != 0
	           && !(nr->authority.roots
	                && nr->authority.roots->member(nr->authority.roots->ctx, id->pubkey))) {
		return FZN_NODE_ROSTER_NO_STANDING;
	}
	if (add) {
		/* AN ADD OF WHAT IS ACTIVE writes nothing: a second incarnation of
		 * a live contact would only race the first. */
		if (fzn_roster_active(&nr->roster, subject, revocations, k, incarnation))
			return FZN_NODE_ROSTER_OK;
		/* A FRESH INCARNATION, never all zero, which issue refuses. */
		do {
			if (!rng->fill(rng->ctx, incarnation, sizeof(incarnation)))
				return FZN_NODE_ROSTER_MALFORMED;
			for (i = 0; i < sizeof(incarnation) && !incarnation[i]; i++)
				;
		} while (i == sizeof(incarnation));
		rerr = fzn_roster_issue_add(id->pubkey, subject, incarnation, nr->roster.seq_seen + 1u,
		                            id->sign, record, sizeof(record), &len);
	} else {
		if (!removable(nr, subject, id->pubkey, revocations, k, incarnation))
			return FZN_NODE_ROSTER_ABSENT;
		rerr = fzn_roster_issue_remove(id->pubkey, subject, incarnation,
		                               nr->roster.seq_seen + 1u, id->sign, record,
		                               sizeof(record), &len);
	}
	if (rerr != FZN_ROSTER_OK || len != sizeof(record))
		return FZN_NODE_ROSTER_REFUSED;
	/* IN FORCE FIRST, SAVED SECOND, as a revocation is: a removal unsaved
	 * is a smaller failure than one saved and not in force. */
	err = admit(nr, record, len, hops, hop_count);
	if (err != FZN_NODE_ROSTER_OK)
		return err;
	err = save(store, nr->hash, record, hops, hop_count);
	if (err != FZN_NODE_ROSTER_OK)
		return err;
	if (nr->wrote && !nr->wrote(nr->wrote_ctx, record, len))
		return FZN_NODE_ROSTER_NOT_LOGGED;
	return FZN_NODE_ROSTER_OK;
}

fzn_roster_state_t fzn_node_roster_standing(const fzn_node_roster_t *nr,
                                            const uint8_t subject[FZN_PUBKEY_LEN],
                                            const fzn_revocation_store_t *revocations,
                                            size_t k)
{
	uint8_t incarnation[FZN_ROSTER_INCARNATION_LEN];
	fzn_roster_state_t best = FZN_ROSTER_ABSENT;
	size_t i;

	if (!nr || !subject)
		return FZN_ROSTER_ABSENT;
	if (fzn_roster_active(&nr->roster, subject, revocations, k, incarnation))
		return FZN_ROSTER_ACTIVE;
	for (i = 0; i < nr->roster.used; i++) {
		fzn_roster_state_t s;

		if (memcmp(nr->roster.entries[i].subject, subject, FZN_PUBKEY_LEN) != 0)
			continue;
		s = fzn_roster_state(&nr->roster, subject, nr->roster.entries[i].incarnation, revocations, k);
		if (s == FZN_ROSTER_RETIRED || (s == FZN_ROSTER_SUSPENDED && best == FZN_ROSTER_ABSENT))
			best = s;
	}
	return best;
}

size_t fzn_node_roster_subjects(const fzn_node_roster_t *nr, uint8_t (*out)[FZN_PUBKEY_LEN],
                                size_t cap)
{
	size_t i, j, n = 0;

	if (!nr || !out)
		return 0;
	for (i = 0; i < nr->roster.used && n < cap; i++) {
		for (j = 0; j < n; j++)
			if (memcmp(out[j], nr->roster.entries[i].subject, FZN_PUBKEY_LEN) == 0)
				break;
		if (j == n)
			memcpy(out[n++], nr->roster.entries[i].subject, FZN_PUBKEY_LEN);
	}
	return n;
}

fzn_node_roster_err_t fzn_node_roster_name_arrivals(const fzn_node_roster_t *nr,
                                                    const fzn_persist_ops_t *store,
                                                    const fzn_revocation_store_t *revocations,
                                                    size_t k,
                                                    int (*member)(void *ctx,
                                                                  const uint8_t *key),
                                                    void *member_ctx, uint64_t now_ms,
                                                    size_t *named)
{
	static const char HEX[] = "0123456789abcdef";
	size_t i;

	if (!nr || !store || !named)
		return FZN_NODE_ROSTER_MALFORMED;
	*named = 0;
	/* EVERY INCARNATION'S SUBJECT, sec 704, with no table of its own: one met
	 * twice is a contact by the second time, and passed over. */
	for (i = 0; i < nr->roster.used; i++) {
		const uint8_t *subject = nr->roster.entries[i].subject;
		fzn_contact_t c;
		fzn_contact_err_t cerr;
		char name[FZN_CONTACT_NAME_MAX + 1u];
		size_t digits, d;

		if (fzn_node_roster_standing(nr, subject, revocations, k) != FZN_ROSTER_ACTIVE
		    || (member && member(member_ctx, subject)))
			continue;
		cerr = fzn_contact_get(store, subject, &c);
		if (cerr == FZN_CONTACT_OK)
			continue;
		if (cerr != FZN_CONTACT_ERR_ABSENT)
			return FZN_NODE_ROSTER_STORE;
		/* `c_` AND AS MANY HEX DIGITS AS MAKE IT NOBODY ELSE'S, from 8 to
		 * the 30 a name has room for. */
		for (digits = 8u; digits <= FZN_CONTACT_NAME_MAX - 2u; digits += 2u) {
			name[0] = 'c';
			name[1] = '_';
			for (d = 0; d < digits; d++)
				name[2u + d] = HEX[(subject[d / 2u] >> ((d % 2u) ? 0 : 4)) & 15u];
			name[2u + digits] = '\0';
			cerr = fzn_contact_add(store, subject, name, 2u + digits, now_ms);
			if (cerr != FZN_CONTACT_ERR_TAKEN)
				break;
		}
		if (cerr != FZN_CONTACT_OK)
			return FZN_NODE_ROSTER_STORE;
		(*named)++;
	}
	return FZN_NODE_ROSTER_OK;
}

/* ONE CONTACT CARRIED onto the roster, unless it is held there already; a
 * write that fails stops the walk with its error. */
struct carrying {
	fzn_node_roster_t *nr;
	const fzn_persist_ops_t *store;
	const fzn_node_identity_t *id;
	const fzn_node_authority_t *authority;
	const fzn_random_ops_t *rng;
	size_t *written;
	fzn_node_roster_err_t err;
};

static int carry_one(void *ctx, const fzn_contact_t *contact)
{
	struct carrying *c = ctx;

	if (held(c->nr, contact->key))
		return 1;
	c->err = fzn_node_roster_write(c->nr, c->store, c->id, c->authority, c->rng, contact->key, 1,
	                               NULL, 0);
	if (c->err != FZN_NODE_ROSTER_OK)
		return 0;
	(*c->written)++;
	return 1;
}

fzn_node_roster_err_t fzn_node_roster_carry_names(fzn_node_roster_t *nr,
                                                  const fzn_persist_ops_t *store,
                                                  const fzn_node_identity_t *id,
                                                  const fzn_node_authority_t *authority,
                                                  const fzn_random_ops_t *rng,
                                                  size_t *written)
{
	struct carrying c;

	if (!nr || !store || !written)
		return FZN_NODE_ROSTER_MALFORMED;
	*written = 0;
	c.nr = nr;
	c.store = store;
	c.id = id;
	c.authority = authority;
	c.rng = rng;
	c.written = written;
	c.err = FZN_NODE_ROSTER_OK;
	/* WALKED, sec 704, however many contacts: the writes go to the roster's
	 * slot, not the contacts' being walked. */
	if (fzn_contact_each(store, carry_one, &c) != FZN_CONTACT_OK)
		return FZN_NODE_ROSTER_STORE;
	return c.err;
}
