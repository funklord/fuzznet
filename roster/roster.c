/* See roster.h. */

#include "roster.h"

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
                                 size_t capacity)
{
	if (!roster || !entries || capacity == 0u)
		return FZN_ROSTER_ERR_MALFORMED;
	memset(entries, 0, capacity * sizeof(*entries));
	roster->entries = entries;
	roster->capacity = capacity;
	roster->used = 0;
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

/* STANDING: the root, or a chain from it for the roster's capability naming
 * the writer as its last grantee.
 *
 * `blind` is a removal's admission, and it is blind to the CLOCK only: the
 * chain is checked at the moment its newest hop was issued, so a removal is
 * not lost to its writer's grant simply running out before it arrived. It is
 * NOT blind to revocations -- a revoked writer removes nothing (roster.h,
 * sec 388, the holder's decision of 2026-09-28). */
static int has_standing(const uint8_t *writer, const fzn_chain_hop_t *hops, size_t hop_count,
                        const fzn_roster_authority_t *authority, int blind)
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
	if (fzn_chain_verify(hops, hop_count, authority->root, authority->capability,
	                     blind ? latest : authority->now, authority->sign,
	                     authority->revocations, NULL, &verdict)
	    != FZN_CHAIN_OK)
		return 0;
	return memcmp(verdict.grantee, writer, FZN_PUBKEY_LEN) == 0;
}

fzn_roster_err_t fzn_roster_admit(fzn_roster_t *roster, fzn_roster_record_t record,
                                  const fzn_chain_hop_t *hops, size_t hop_count,
                                  const fzn_roster_authority_t *authority)
{
	fzn_roster_record_t rec;
	fzn_roster_entry_t *entry;
	size_t signed_len;
	uint8_t object;

	if (!roster || !roster->entries || !authority || !authority->root
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
	if (!has_standing(fzn_roster_writer(rec), hops, hop_count, authority,
	                  object == (uint8_t)FZN_OBJECT_ROSTER_REMOVE))
		return FZN_ROSTER_ERR_STANDING;

	entry = find(roster, fzn_roster_subject(rec), fzn_roster_incarnation(rec));
	if (object == (uint8_t)FZN_OBJECT_ROSTER_ADD && entry && entry->added) {
		if (entry->add_seq == fzn_roster_seq(rec)
		    && memcmp(entry->add_writer, fzn_roster_writer(rec), FZN_PUBKEY_LEN) == 0)
			return FZN_ROSTER_OK;	/* the same add, again */
		return FZN_ROSTER_ERR_CONFLICT;
	}
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
		memcpy(entry->add_writer, fzn_roster_writer(rec), FZN_PUBKEY_LEN);
	} else {
		entry->removed = 1;
	}
	if (fzn_roster_seq(rec) > roster->seq_seen)
		roster->seq_seen = fzn_roster_seq(rec);
	return FZN_ROSTER_OK;
}

/* Whether add `a` beats add `b`: greater seq, then greater writer bytes. */
static int beats(const fzn_roster_entry_t *a, const fzn_roster_entry_t *b)
{
	if (a->add_seq != b->add_seq)
		return a->add_seq > b->add_seq;
	return memcmp(a->add_writer, b->add_writer, FZN_PUBKEY_LEN) > 0;
}

int fzn_roster_active(const fzn_roster_t *roster, const uint8_t subject[FZN_PUBKEY_LEN],
                      uint8_t incarnation[FZN_ROSTER_INCARNATION_LEN])
{
	const fzn_roster_entry_t *best = NULL;
	size_t i;

	if (!roster || !roster->entries || !subject)
		return 0;
	for (i = 0; i < roster->used; i++) {
		const fzn_roster_entry_t *e = &roster->entries[i];

		if (!e->added || e->removed || memcmp(e->subject, subject, FZN_PUBKEY_LEN) != 0)
			continue;
		if (!best || beats(e, best))
			best = e;
	}
	if (!best)
		return 0;
	if (incarnation)
		memcpy(incarnation, best->incarnation, FZN_ROSTER_INCARNATION_LEN);
	return 1;
}

int fzn_roster_removed(const fzn_roster_t *roster, const uint8_t subject[FZN_PUBKEY_LEN],
                       const uint8_t incarnation[FZN_ROSTER_INCARNATION_LEN])
{
	const fzn_roster_entry_t *e;

	if (!roster || !roster->entries || !subject || !incarnation)
		return 0;
	e = find(roster, subject, incarnation);
	return e && e->removed;
}
