/* See roster.h. */

#include "roster.h"

#include "../chain/revocation.h"

#include <string.h>

const char *fzn_roster_err_str(fzn_roster_err_t err)
{
	switch (err) {
	case FZN_ROSTER_OK:
		return "ok";
	case FZN_ROSTER_ERR_MALFORMED:
		return "malformed";
	case FZN_ROSTER_ERR_SHAPE:
		return "not a roster record";
	case FZN_ROSTER_ERR_SIGNATURE:
		return "the signature does not verify under the record's writer";
	case FZN_ROSTER_ERR_STANDING:
		return "the writer is not the root and shows no chain entitling it";
	case FZN_ROSTER_ERR_CONFLICT:
		return "a second, different add for an incarnation already added";
	case FZN_ROSTER_ERR_FULL:
		return "the roster is full";
	case FZN_ROSTER_ERR_UNSUPPORTED:
		return "setting records are not resolved yet";
	}
	return "unknown";
}

static int all_zero(const uint8_t *p, size_t len)
{
	uint8_t acc = 0;
	size_t i;

	for (i = 0; i < len; i++)
		acc |= p[i];
	return acc == 0u;
}

static int is_roster_object(uint8_t object)
{
	return object == (uint8_t)FZN_OBJECT_ROSTER_ADD
	       || object == (uint8_t)FZN_OBJECT_ROSTER_REMOVE
	       || object == (uint8_t)FZN_OBJECT_ROSTER_SET;
}

fzn_roster_err_t fzn_roster_open(const uint8_t *bytes, size_t len, fzn_roster_record_t *out)
{
	size_t body_len;
	uint8_t object;

	if (!bytes || !out)
		return FZN_ROSTER_ERR_MALFORMED;
	if (len < FZN_ROSTER_MIN_LEN || len > FZN_ROSTER_MAX_LEN)
		return FZN_ROSTER_ERR_SHAPE;
	object = bytes[FZN_ROSTER_OFF_OBJECT];
	body_len = bytes[FZN_ROSTER_OFF_BODY_LEN];
	if (bytes[FZN_ROSTER_OFF_VERSION] != (uint8_t)FZN_SIGNED_VERSION || !is_roster_object(object)
	    || body_len > FZN_ROSTER_BODY_MAX || len != FZN_ROSTER_LEN(body_len)
	    || all_zero(bytes + FZN_ROSTER_OFF_INCARNATION, FZN_ROSTER_INCARNATION_LEN))
		return FZN_ROSTER_ERR_SHAPE;
	/* AN ADD OR A REMOVE CARRIES NO SETTING AND NO BODY. Anything there
	 * would be bytes the signature covers and nothing reads -- a second
	 * encoding of one statement. */
	if (object != (uint8_t)FZN_OBJECT_ROSTER_SET
	    && (body_len != 0u || bytes[FZN_ROSTER_OFF_SETTING] != 0u
	        || bytes[FZN_ROSTER_OFF_SETTING + 1u] != 0u))
		return FZN_ROSTER_ERR_SHAPE;
	out->base = bytes;
	out->len = len;
	return FZN_ROSTER_OK;
}

static fzn_roster_err_t mint(uint8_t object, const uint8_t writer[FZN_PUBKEY_LEN],
                             const uint8_t subject[FZN_PUBKEY_LEN],
                             const uint8_t incarnation[FZN_ROSTER_INCARNATION_LEN],
                             uint64_t seq, uint16_t setting, const uint8_t *body,
                             size_t body_len, const fzn_sign_ops_t *sign, uint8_t *out,
                             size_t out_cap, size_t *out_len)
{
	size_t signed_len = (size_t)FZN_ROSTER_HEADER_LEN + body_len;

	if (!writer || !subject || !incarnation || !sign || !sign->sign || !out || !out_len
	    || (body_len && !body))
		return FZN_ROSTER_ERR_MALFORMED;
	if (body_len > FZN_ROSTER_BODY_MAX
	    || all_zero(incarnation, FZN_ROSTER_INCARNATION_LEN))
		return FZN_ROSTER_ERR_SHAPE;
	if (out_cap < FZN_ROSTER_LEN(body_len))
		return FZN_ROSTER_ERR_MALFORMED;

	out[FZN_ROSTER_OFF_VERSION] = (uint8_t)FZN_SIGNED_VERSION;
	out[FZN_ROSTER_OFF_OBJECT] = object;
	memcpy(out + FZN_ROSTER_OFF_WRITER, writer, FZN_PUBKEY_LEN);
	memcpy(out + FZN_ROSTER_OFF_SUBJECT, subject, FZN_PUBKEY_LEN);
	memcpy(out + FZN_ROSTER_OFF_INCARNATION, incarnation, FZN_ROSTER_INCARNATION_LEN);
	fzn_put_be64(out + FZN_ROSTER_OFF_SEQ, seq);
	out[FZN_ROSTER_OFF_SETTING] = (uint8_t)(setting >> 8);
	out[FZN_ROSTER_OFF_SETTING + 1u] = (uint8_t)(setting & 0xffu);
	out[FZN_ROSTER_OFF_BODY_LEN] = (uint8_t)body_len;
	if (body_len)
		memcpy(out + FZN_ROSTER_HEADER_LEN, body, body_len);
	if (!sign->sign(sign->ctx, out + signed_len, out, signed_len))
		return FZN_ROSTER_ERR_SIGNATURE;
	*out_len = signed_len + (size_t)FZN_SIG_LEN;
	return FZN_ROSTER_OK;
}

fzn_roster_err_t fzn_roster_issue_add(const uint8_t writer[FZN_PUBKEY_LEN],
                                      const uint8_t subject[FZN_PUBKEY_LEN],
                                      const uint8_t incarnation[FZN_ROSTER_INCARNATION_LEN],
                                      uint64_t seq, const fzn_sign_ops_t *sign, uint8_t *out,
                                      size_t out_cap, size_t *out_len)
{
	return mint((uint8_t)FZN_OBJECT_ROSTER_ADD, writer, subject, incarnation, seq, 0u, NULL,
	            0u, sign, out, out_cap, out_len);
}

fzn_roster_err_t fzn_roster_issue_remove(const uint8_t writer[FZN_PUBKEY_LEN],
                                         const uint8_t subject[FZN_PUBKEY_LEN],
                                         const uint8_t incarnation[FZN_ROSTER_INCARNATION_LEN],
                                         uint64_t seq, const fzn_sign_ops_t *sign,
                                         uint8_t *out, size_t out_cap, size_t *out_len)
{
	return mint((uint8_t)FZN_OBJECT_ROSTER_REMOVE, writer, subject, incarnation, seq, 0u,
	            NULL, 0u, sign, out, out_cap, out_len);
}

fzn_roster_err_t fzn_roster_issue_set(const uint8_t writer[FZN_PUBKEY_LEN],
                                      const uint8_t subject[FZN_PUBKEY_LEN],
                                      const uint8_t incarnation[FZN_ROSTER_INCARNATION_LEN],
                                      uint64_t seq, uint16_t setting, const uint8_t *body,
                                      size_t body_len, const fzn_sign_ops_t *sign, uint8_t *out,
                                      size_t out_cap, size_t *out_len)
{
	return mint((uint8_t)FZN_OBJECT_ROSTER_SET, writer, subject, incarnation, seq, setting,
	            body, body_len, sign, out, out_cap, out_len);
}

fzn_roster_err_t fzn_roster_init(fzn_roster_t *roster, fzn_roster_entry_t *entries,
                                 size_t capacity, fzn_roster_writer_t *writers,
                                 size_t writer_capacity)
{
	if (!roster || !entries || capacity == 0u || !writers || writer_capacity == 0u)
		return FZN_ROSTER_ERR_MALFORMED;
	memset(entries, 0, capacity * sizeof(*entries));
	memset(writers, 0, writer_capacity * sizeof(*writers));
	roster->entries = entries;
	roster->capacity = capacity;
	roster->used = 0;
	roster->writers = writers;
	roster->writer_capacity = writer_capacity;
	roster->writers_used = 0;
	roster->seq_seen = 0;
	return FZN_ROSTER_OK;
}

static fzn_roster_entry_t *find(const fzn_roster_t *roster, const uint8_t *subject,
                                const uint8_t *incarnation)
{
	size_t i;

	for (i = 0; i < roster->used; i++)
		if (memcmp(roster->entries[i].subject, subject, FZN_PUBKEY_LEN) == 0
		    && memcmp(roster->entries[i].incarnation, incarnation,
		              FZN_ROSTER_INCARNATION_LEN) == 0)
			return &roster->entries[i];
	return NULL;
}

/* STANDING AS A RECORD ARRIVES: the root, or a chain from it for the roster's
 * capability naming the writer as its last grantee -- checked as of the
 * newest hop's issue, with no revocations, since both are the reader's
 * (roster.h). What this can refuse is a chain that was never valid. */
static int has_standing(const uint8_t *writer, const fzn_chain_hop_t *hops, size_t hop_count,
                        const fzn_roster_authority_t *authority)
{
	fzn_chain_t verdict;
	size_t i;
	uint64_t latest = 0;

	if (hop_count == 0u)
		return memcmp(writer, authority->root, FZN_PUBKEY_LEN) == 0;
	if (!hops || hop_count > FZN_CHAIN_MAX_HOPS)
		return 0;
	for (i = 0; i < hop_count; i++)
		if (fzn_hop_issued_at(hops[i]) > latest)
			latest = fzn_hop_issued_at(hops[i]);
	if (fzn_chain_verify(hops, hop_count, authority->root, authority->capability, latest,
	                     authority->sign, NULL, NULL, &verdict)
	    != FZN_CHAIN_OK)
		return 0;
	return memcmp(verdict.grantee, writer, FZN_PUBKEY_LEN) == 0;
}

/* The writer-table slot for this writer and chain, adding one if new. A key
 * seen before with a different chain is a different slot: it stood on
 * different grants, and either can be revoked without the other. SIZE_MAX
 * when the table is full. */
static size_t intern_writer(fzn_roster_t *roster, const uint8_t *key,
                            const fzn_chain_hop_t *hops, size_t hop_count,
                            const fzn_cap_id_t *capability)
{
	fzn_roster_writer_t w;
	size_t i;

	memset(&w, 0, sizeof(w));
	memcpy(w.key, key, FZN_PUBKEY_LEN);
	w.capability = *capability;
	w.hop_count = hop_count;
	for (i = 0; i < hop_count; i++) {
		memcpy(w.grantor[i], fzn_hop_grantor(hops[i]), FZN_PUBKEY_LEN);
		memcpy(w.grantee[i], fzn_hop_grantee(hops[i]), FZN_PUBKEY_LEN);
	}
	for (i = 0; i < roster->writers_used; i++)
		if (memcmp(&roster->writers[i], &w, sizeof(w)) == 0)
			return i;
	if (roster->writers_used >= roster->writer_capacity)
		return (size_t)-1;
	roster->writers[roster->writers_used] = w;
	return roster->writers_used++;
}

static fzn_roster_err_t apply(fzn_roster_t *roster, fzn_roster_record_t record,
                              const fzn_chain_hop_t *hops, size_t hop_count,
                              const fzn_roster_authority_t *authority)
{
	fzn_roster_record_t rec;
	fzn_roster_entry_t *entry;
	size_t signed_len, w, i;
	uint8_t object;

	if (!roster || !roster->entries || !roster->writers || !authority || !authority->root
	    || !authority->capability || !authority->sign || !authority->sign->verify)
		return FZN_ROSTER_ERR_MALFORMED;
	/* Opened again rather than trusted: a view is only a pointer and a
	 * length, and one assembled by hand is not a record that was checked. */
	if (fzn_roster_open(record.base, record.len, &rec) != FZN_ROSTER_OK)
		return FZN_ROSTER_ERR_SHAPE;
	object = fzn_roster_object(rec);
	signed_len = rec.len - (size_t)FZN_SIG_LEN;
	if (!authority->sign->verify(authority->sign->ctx, fzn_roster_writer(rec), rec.base,
	                             signed_len, rec.base + signed_len))
		return FZN_ROSTER_ERR_SIGNATURE;
	if (object == (uint8_t)FZN_OBJECT_ROSTER_SET)
		return FZN_ROSTER_ERR_UNSUPPORTED;
	if (!has_standing(fzn_roster_writer(rec), hops, hop_count, authority))
		return FZN_ROSTER_ERR_STANDING;

	entry = find(roster, fzn_roster_subject(rec), fzn_roster_incarnation(rec));
	if (object == (uint8_t)FZN_OBJECT_ROSTER_ADD && entry && entry->added) {
		const fzn_roster_writer_t *held = &roster->writers[entry->add_writer];

		if (entry->add_seq == fzn_roster_seq(rec)
		    && memcmp(held->key, fzn_roster_writer(rec), FZN_PUBKEY_LEN) == 0)
			return FZN_ROSTER_OK;	/* the same add, again */
		return FZN_ROSTER_ERR_CONFLICT;
	}
	w = intern_writer(roster, fzn_roster_writer(rec), hops, hop_count,
	                  authority->capability);
	if (w == (size_t)-1)
		return FZN_ROSTER_ERR_FULL;
	if (!entry) {
		if (roster->used >= roster->capacity)
			return FZN_ROSTER_ERR_FULL;
		entry = &roster->entries[roster->used++];
		memset(entry, 0, sizeof(*entry));
		memcpy(entry->subject, fzn_roster_subject(rec), FZN_PUBKEY_LEN);
		memcpy(entry->incarnation, fzn_roster_incarnation(rec), FZN_ROSTER_INCARNATION_LEN);
	}
	if (object == (uint8_t)FZN_OBJECT_ROSTER_ADD) {
		entry->added = 1;
		entry->add_seq = fzn_roster_seq(rec);
		entry->add_writer = w;
	} else {
		/* ONE PLACE PER WRITER SLOT. The same writer removing twice is one
		 * removal; a retirement counts distinct KEYS at read time, so two
		 * slots of one key never make two. */
		for (i = 0; i < entry->remover_count; i++)
			if (entry->remover[i] == w)
				break;
		if (i == entry->remover_count) {
			if (entry->remover_count >= FZN_ROSTER_REMOVERS_MAX)
				return FZN_ROSTER_ERR_FULL;
			entry->remover[entry->remover_count++] = w;
		}
	}
	if (fzn_roster_seq(rec) > roster->seq_seen)
		roster->seq_seen = fzn_roster_seq(rec);
	return FZN_ROSTER_OK;
}

fzn_roster_err_t fzn_roster_admit(fzn_roster_t *roster, fzn_roster_record_t record,
                                  const fzn_chain_hop_t *hops, size_t hop_count,
                                  const fzn_roster_authority_t *authority)
{
	return apply(roster, record, hops, hop_count, authority);
}

fzn_roster_err_t fzn_roster_restore(fzn_roster_t *roster, fzn_roster_record_t record,
                                    const fzn_chain_hop_t *hops, size_t hop_count,
                                    const fzn_roster_authority_t *authority)
{
	return apply(roster, record, hops, hop_count, authority);
}

fzn_roster_err_t fzn_roster_bundle_pack(const uint8_t *record, size_t record_len,
                                        const uint8_t (*hops)[FZN_HOP_LEN], size_t hop_count,
                                        uint8_t *out, size_t out_cap, size_t *out_len)
{
	fzn_roster_record_t check;
	size_t i, at;

	if (!record || !out || !out_len || (hop_count && !hops))
		return FZN_ROSTER_ERR_MALFORMED;
	if (hop_count > FZN_CHAIN_MAX_HOPS
	    || fzn_roster_open(record, record_len, &check) != FZN_ROSTER_OK)
		return FZN_ROSTER_ERR_SHAPE;
	if (out_cap < FZN_ROSTER_BUNDLE_LEN(record_len, hop_count))
		return FZN_ROSTER_ERR_MALFORMED;
	out[0] = (uint8_t)hop_count;
	out[1] = (uint8_t)(record_len >> 8);
	out[2] = (uint8_t)(record_len & 0xffu);
	memcpy(out + FZN_ROSTER_BUNDLE_HEAD_LEN, record, record_len);
	at = FZN_ROSTER_BUNDLE_HEAD_LEN + record_len;
	for (i = 0; i < hop_count; i++, at += FZN_HOP_LEN)
		memcpy(out + at, hops[i], FZN_HOP_LEN);
	*out_len = at;
	return FZN_ROSTER_OK;
}

fzn_roster_err_t fzn_roster_bundle_open(const uint8_t *bytes, size_t len,
                                        fzn_roster_bundle_t *out)
{
	size_t hop_count, record_len, i, at;

	if (!bytes || !out)
		return FZN_ROSTER_ERR_MALFORMED;
	if (len < FZN_ROSTER_BUNDLE_HEAD_LEN)
		return FZN_ROSTER_ERR_SHAPE;
	hop_count = bytes[0];
	record_len = ((size_t)bytes[1] << 8) | bytes[2];
	/* THE LENGTH IS EXACT, not "at least": trailing bytes are a second
	 * encoding of one bundle, and a store keyed on the bytes would hold
	 * both. */
	if (hop_count > FZN_CHAIN_MAX_HOPS || record_len < FZN_ROSTER_MIN_LEN
	    || record_len > FZN_ROSTER_MAX_LEN || len != FZN_ROSTER_BUNDLE_LEN(record_len, hop_count)
	    || fzn_roster_open(bytes + FZN_ROSTER_BUNDLE_HEAD_LEN, record_len, &out->record)
	               != FZN_ROSTER_OK)
		return FZN_ROSTER_ERR_SHAPE;
	at = FZN_ROSTER_BUNDLE_HEAD_LEN + record_len;
	for (i = 0; i < hop_count; i++, at += FZN_HOP_LEN)
		if (fzn_hop_open(bytes + at, FZN_HOP_LEN, &out->hops[i]) != FZN_CHAIN_OK)
			return FZN_ROSTER_ERR_SHAPE;
	out->hop_count = hop_count;
	return FZN_ROSTER_OK;
}

/* WHETHER A WRITER COUNTS: no hop of the chain it wrote under is revoked, by
 * an issuer entitled to revoke that hop -- the root or an ancestor in the
 * chain, as `fzn_revocation_covers_chain` derives it. The root, with no
 * chain, is never revoked. */
static int counts(const fzn_roster_writer_t *w, const fzn_revocation_store_t *revocations)
{
	uint8_t revoked[FZN_CHAIN_MAX_HOPS];
	size_t i;

	/* THE STORE'S OWN RULE, k-of-n and admins included (sec 397), through
	 * the form that takes a chain's shape rather than its bytes. */
	if (!revocations || w->hop_count == 0u)
		return 1;
	fzn_revocation_covers_links(revocations, (const uint8_t (*)[FZN_PUBKEY_LEN])w->grantor,
	                            (const uint8_t (*)[FZN_PUBKEY_LEN])w->grantee, w->hop_count,
	                            &w->capability, revoked);
	for (i = 0; i < w->hop_count; i++)
		if (revoked[i])
			return 0;
	return 1;
}

static fzn_roster_state_t judge(const fzn_roster_t *roster, const fzn_roster_entry_t *e,
                                const fzn_revocation_store_t *revocations, size_t k)
{
	const uint8_t *keys[FZN_ROSTER_REMOVERS_MAX];
	size_t distinct = 0, i, j;

	if (k == 0u)
		k = FZN_ROSTER_K_DEFAULT;
	/* DISTINCT UNREVOKED REMOVERS, by key: one host under two chains is
	 * still one host, and agreement is between hosts. */
	for (i = 0; i < e->remover_count; i++) {
		const fzn_roster_writer_t *w = &roster->writers[e->remover[i]];

		if (!counts(w, revocations))
			continue;
		for (j = 0; j < distinct; j++)
			if (memcmp(keys[j], w->key, FZN_PUBKEY_LEN) == 0)
				break;
		if (j == distinct)
			keys[distinct++] = w->key;
	}
	if (distinct >= k)
		return FZN_ROSTER_RETIRED;
	if (distinct > 0u)
		return FZN_ROSTER_SUSPENDED;
	if (e->added && counts(&roster->writers[e->add_writer], revocations))
		return FZN_ROSTER_ACTIVE;
	return FZN_ROSTER_ABSENT;
}

fzn_roster_state_t fzn_roster_state(const fzn_roster_t *roster,
                                    const uint8_t subject[FZN_PUBKEY_LEN],
                                    const uint8_t incarnation[FZN_ROSTER_INCARNATION_LEN],
                                    const fzn_revocation_store_t *revocations, size_t k)
{
	const fzn_roster_entry_t *e;

	if (!roster || !roster->entries || !roster->writers || !subject || !incarnation)
		return FZN_ROSTER_ABSENT;
	e = find(roster, subject, incarnation);
	return e ? judge(roster, e, revocations, k) : FZN_ROSTER_ABSENT;
}

/* Whether add `a` beats add `b`: greater seq, then greater writer bytes. */
static int beats(const fzn_roster_t *roster, const fzn_roster_entry_t *a,
                 const fzn_roster_entry_t *b)
{
	if (a->add_seq != b->add_seq)
		return a->add_seq > b->add_seq;
	return memcmp(roster->writers[a->add_writer].key, roster->writers[b->add_writer].key,
	              FZN_PUBKEY_LEN) > 0;
}

int fzn_roster_active(const fzn_roster_t *roster, const uint8_t subject[FZN_PUBKEY_LEN],
                      const fzn_revocation_store_t *revocations, size_t k,
                      uint8_t incarnation[FZN_ROSTER_INCARNATION_LEN])
{
	const fzn_roster_entry_t *best = NULL;
	size_t i;

	if (!roster || !roster->entries || !roster->writers || !subject)
		return 0;
	for (i = 0; i < roster->used; i++) {
		const fzn_roster_entry_t *e = &roster->entries[i];

		if (memcmp(e->subject, subject, FZN_PUBKEY_LEN) != 0
		    || judge(roster, e, revocations, k) != FZN_ROSTER_ACTIVE)
			continue;
		if (!best || beats(roster, e, best))
			best = e;
	}
	if (!best)
		return 0;
	if (incarnation)
		memcpy(incarnation, best->incarnation, FZN_ROSTER_INCARNATION_LEN);
	return 1;
}
