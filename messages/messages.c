/* See messages.h. */

#include "messages.h"

#include "../wire/bytes.h"

#include <string.h>

const char *fzn_messages_err_str(fzn_messages_err_t err)
{
	switch (err) {
	case FZN_MESSAGES_OK:
		return "ok";
	case FZN_MESSAGES_ERR_MALFORMED:
		return "malformed";
	case FZN_MESSAGES_ERR_TEXT:
		return "text too long";
	case FZN_MESSAGES_ERR_JOURNAL:
		return "the journal refused";
	case FZN_MESSAGES_ERR_BACKEND:
		return "the store refused";
	case FZN_MESSAGES_ERR_SEAL:
		return "the seal refused";
	case FZN_MESSAGES_ERR_DEEP:
		return "deeper than a listing walks";
	case FZN_MESSAGES_ERR_EQUIVOCATION:
		return "another key is held for that conversation and month";
	}
	return "unknown";
}

/* A state row: the state, then the time of the mark that set it. */
#define STATE_LEN 9u

static int record_at(const fzn_messages_t *m, const uint8_t device[FZN_PUBKEY_LEN], uint64_t seq,
                     uint8_t *buf, size_t cap, fzn_record_t *rec);

static int ready(const fzn_messages_t *m)
{
	return m && m->store && m->store->load && m->store->save && m->journal && m->issuer
	       && m->sign && m->rng && m->rng->fill && m->aead && m->hash && m->hash->hash
	       && m->now;
}

static int direction_ok(uint8_t d)
{
	return d == FZN_MESSAGE_OUT || d == FZN_MESSAGE_IN;
}

/* ---- the rows beside the journal ------------------------------------ */

/* A KEY PER WRITING DEVICE, so two devices that each draw one for the same
 * conversation and month never claim one row when keys travel between them:
 * a line opens under the key of the device that wrote it. */
static int key_row(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                   uint32_t epoch, const uint8_t device[FZN_PUBKEY_LEN],
                   uint8_t row[FZN_PUBKEY_LEN])
{
	static const char DOMAIN[] = "fuzznet.message.key";
	uint8_t in[sizeof(DOMAIN) - 1u + FZN_PUBKEY_LEN + 4u + FZN_PUBKEY_LEN];
	size_t at = sizeof(DOMAIN) - 1u;

	memcpy(in, DOMAIN, at);
	memcpy(in + at, contact, FZN_PUBKEY_LEN);
	at += FZN_PUBKEY_LEN;
	fzn_put_be32(in + at, epoch);
	memcpy(in + at + 4u, device, FZN_PUBKEY_LEN);
	return m->hash->hash(m->hash->ctx, row, FZN_PUBKEY_LEN, in, sizeof(in));
}

static int state_row(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                     uint8_t direction, const uint8_t id[FZN_MESSAGE_ID_LEN],
                     uint8_t row[FZN_PUBKEY_LEN])
{
	static const char DOMAIN[] = "fuzznet.message.state";
	uint8_t in[sizeof(DOMAIN) - 1u + FZN_PUBKEY_LEN + 1u + FZN_MESSAGE_ID_LEN];
	size_t at = sizeof(DOMAIN) - 1u;

	memcpy(in, DOMAIN, at);
	memcpy(in + at, contact, FZN_PUBKEY_LEN);
	at += FZN_PUBKEY_LEN;
	in[at++] = direction;
	memcpy(in + at, id, FZN_MESSAGE_ID_LEN);
	return m->hash->hash(m->hash->ctx, row, FZN_PUBKEY_LEN, in, sizeof(in));
}

/* `device`'s key for `contact` and `epoch`, held here. */
static int key_of(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN], uint32_t epoch,
                  const uint8_t device[FZN_PUBKEY_LEN], uint8_t key[FZN_CONVERSATION_KEY_LEN])
{
	uint8_t row[FZN_PUBKEY_LEN];
	size_t len = 0;

	return key_row(m, contact, epoch, device, row)
	       && m->store->load(m->store->ctx, FZN_PERSIST_CONVERSATION_KEY, row, key,
	                         FZN_CONVERSATION_KEY_LEN, &len)
	       && len == FZN_CONVERSATION_KEY_LEN;
}

/* SET A LINE'S STATE when this mark is at least as new as the one held. */
static int set_state(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                     uint8_t direction, const uint8_t id[FZN_MESSAGE_ID_LEN], uint8_t state,
                     uint64_t at)
{
	uint8_t row[FZN_PUBKEY_LEN], held[STATE_LEN], bytes[STATE_LEN];
	size_t len = 0;

	if (!state_row(m, contact, direction, id, row))
		return 0;
	if (m->store->load(m->store->ctx, FZN_PERSIST_MESSAGE_STATE, row, held, sizeof(held), &len)
	    && len == STATE_LEN && fzn_get_be64(held + 1u) > at)
		return 1;
	bytes[0] = state;
	fzn_put_be64(bytes + 1u, at);
	return m->store->save(m->store->ctx, FZN_PERSIST_MESSAGE_STATE, row, bytes, sizeof(bytes));
}

uint8_t fzn_messages_state(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                           uint8_t direction, const uint8_t id[FZN_MESSAGE_ID_LEN])
{
	uint8_t row[FZN_PUBKEY_LEN], held[STATE_LEN];
	size_t len = 0;

	if (!ready(m) || !contact || !id || !state_row(m, contact, direction, id, row)
	    || !m->store->load(m->store->ctx, FZN_PERSIST_MESSAGE_STATE, row, held, sizeof(held),
	                       &len)
	    || len != STATE_LEN)
		return 0u;
	return held[0];
}

/* ---- writing --------------------------------------------------------- */

fzn_messages_err_t fzn_messages_write(const fzn_messages_t *m,
                                      const uint8_t contact[FZN_PUBKEY_LEN], uint8_t direction,
                                      const uint8_t id[FZN_MESSAGE_ID_LEN], uint64_t stime,
                                      const char *text, size_t len)
{
	uint8_t key[FZN_CONVERSATION_KEY_LEN], row[FZN_PUBKEY_LEN], nonce[FZN_AEAD_NONCE_LEN];
	uint8_t body[FZN_RECORD_BODY_MAX];
	uint64_t now;
	uint32_t epoch;
	size_t parts, body_len = 0;
	uint8_t part;

	if (!ready(m) || !contact || !id || (!text && len) || !direction_ok(direction))
		return FZN_MESSAGES_ERR_MALFORMED;
	parts = fzn_message_parts_for(len);
	if (parts == 0u)
		return FZN_MESSAGES_ERR_TEXT;
	now = m->now();
	epoch = fzn_message_epoch_of(now);
	/* THE MONTH'S KEY, drawn by its first line and kept before anything is
	 * sealed under it, so no record names a key this store never held. */
	if (!key_of(m, contact, epoch, m->issuer, key)) {
		if (!key_row(m, contact, epoch, m->issuer, row)
		    || !m->rng->fill(m->rng->ctx, key, sizeof(key)))
			return FZN_MESSAGES_ERR_SEAL;
		if (!m->store->save(m->store->ctx, FZN_PERSIST_CONVERSATION_KEY, row, key,
		                    sizeof(key)))
			return FZN_MESSAGES_ERR_BACKEND;
	}
	for (part = 0; part < parts; part++) {
		if (!fzn_nonce_next(m->rng, nonce)
		    || !fzn_message_line_seal(m->aead, key, contact, direction, id, stime, epoch,
		                              nonce, (const uint8_t *)text, len, part, (uint8_t)parts,
		                              body, &body_len)) {
			memset(key, 0, sizeof(key));
			return FZN_MESSAGES_ERR_SEAL;
		}
		if (fzn_node_journal_append_on(m->journal, m->issuer, FZN_MESSAGE_STREAM, m->sign,
		                               FZN_MESSAGE_LINE_KIND, contact, body, body_len, now,
		                               NULL)
		    != FZN_NODE_JOURNAL_OK) {
			memset(key, 0, sizeof(key));
			return FZN_MESSAGES_ERR_JOURNAL;
		}
	}
	memset(key, 0, sizeof(key));
	return FZN_MESSAGES_OK;
}

fzn_messages_err_t fzn_messages_mark(const fzn_messages_t *m,
                                     const uint8_t contact[FZN_PUBKEY_LEN], uint8_t direction,
                                     const uint8_t id[FZN_MESSAGE_ID_LEN], uint8_t state)
{
	fzn_message_mark_t mark;
	uint8_t body[FZN_MESSAGE_MARK_LEN];
	uint64_t now;

	if (!ready(m) || !contact || !id)
		return FZN_MESSAGES_ERR_MALFORMED;
	mark.direction = direction;
	mark.state = state;
	memcpy(mark.id, id, FZN_MESSAGE_ID_LEN);
	if (!fzn_message_mark_write(&mark, body))
		return FZN_MESSAGES_ERR_MALFORMED;
	now = m->now();
	/* THE RECORD FIRST: the state row is derived from it, and a row with no
	 * record behind it would not survive a reindex. */
	if (fzn_node_journal_append_on(m->journal, m->issuer, FZN_MESSAGE_STREAM, m->sign,
	                               FZN_MESSAGE_MARK_KIND, contact, body, sizeof(body), now,
	                               NULL)
	    != FZN_NODE_JOURNAL_OK)
		return FZN_MESSAGES_ERR_JOURNAL;
	return set_state(m, contact, direction, id, state, now) ? FZN_MESSAGES_OK
	                                                       : FZN_MESSAGES_ERR_BACKEND;
}

fzn_messages_err_t fzn_messages_forget_epoch(const fzn_messages_t *m,
                                             const uint8_t contact[FZN_PUBKEY_LEN],
                                             uint32_t epoch)
{
	uint8_t row[FZN_PUBKEY_LEN];
	size_t d;

	if (!ready(m) || !contact || !m->store->remove || !m->devices
	    || m->device_count > FZN_MESSAGES_DEVICES_MAX)
		return FZN_MESSAGES_ERR_MALFORMED;
	/* EVERY DEVICE'S KEY FOR THE MONTH, this one's whether or not it is
	 * listed among them. */
	if (!key_row(m, contact, epoch, m->issuer, row)
	    || !m->store->remove(m->store->ctx, FZN_PERSIST_CONVERSATION_KEY, row))
		return FZN_MESSAGES_ERR_BACKEND;
	for (d = 0; d < m->device_count; d++)
		if (!key_row(m, contact, epoch, m->devices[d], row)
		    || !m->store->remove(m->store->ctx, FZN_PERSIST_CONVERSATION_KEY, row))
			return FZN_MESSAGES_ERR_BACKEND;
	return FZN_MESSAGES_OK;
}

/* ---- keys between devices --------------------------------------------- */

int fzn_messages_key_get(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                         uint32_t epoch, const uint8_t device[FZN_PUBKEY_LEN],
                         uint8_t key[FZN_CONVERSATION_KEY_LEN])
{
	return ready(m) && contact && device && key && key_of(m, contact, epoch, device, key);
}

fzn_messages_err_t fzn_messages_key_take(const fzn_messages_t *m,
                                         const uint8_t contact[FZN_PUBKEY_LEN], uint32_t epoch,
                                         const uint8_t device[FZN_PUBKEY_LEN],
                                         const uint8_t key[FZN_CONVERSATION_KEY_LEN])
{
	uint8_t held[FZN_CONVERSATION_KEY_LEN], row[FZN_PUBKEY_LEN];
	int same;

	if (!ready(m) || !contact || !device || !key)
		return FZN_MESSAGES_ERR_MALFORMED;
	if (key_of(m, contact, epoch, device, held)) {
		same = memcmp(held, key, sizeof(held)) == 0;
		memset(held, 0, sizeof(held));
		return same ? FZN_MESSAGES_OK : FZN_MESSAGES_ERR_EQUIVOCATION;
	}
	if (!key_row(m, contact, epoch, device, row))
		return FZN_MESSAGES_ERR_SEAL;
	return m->store->save(m->store->ctx, FZN_PERSIST_CONVERSATION_KEY, row, key,
	                      FZN_CONVERSATION_KEY_LEN)
	               ? FZN_MESSAGES_OK
	               : FZN_MESSAGES_ERR_BACKEND;
}

fzn_messages_err_t fzn_messages_absorb(const fzn_messages_t *m,
                                       const uint8_t device[FZN_PUBKEY_LEN], uint64_t *at,
                                       uint64_t to, fzn_messages_seen_fn seen, void *ctx,
                                       size_t *marks)
{
	static uint8_t buf[FZN_RECORD_MAX_LEN];
	uint8_t key[FZN_CONVERSATION_KEY_LEN];
	size_t read = 0;

	if (!ready(m) || !device || !at)
		return FZN_MESSAGES_ERR_MALFORMED;
	while (*at < to) {
		fzn_message_mark_t mark;
		fzn_message_part_t p;
		fzn_record_t rec;

		if (!record_at(m, device, *at + 1u, buf, sizeof(buf), &rec))
			return FZN_MESSAGES_ERR_JOURNAL;
		(*at)++;
		if (fzn_record_kind(rec) == FZN_MESSAGE_MARK_KIND
		    && fzn_message_mark_read(fzn_record_body(rec), fzn_record_body_len(rec), &mark)) {
			read++;
			if (!set_state(m, fzn_record_subject(rec), mark.direction, mark.id, mark.state,
			               fzn_record_issued_at(rec)))
				return FZN_MESSAGES_ERR_BACKEND;
		} else if (seen && fzn_record_kind(rec) == FZN_MESSAGE_LINE_KIND
		           && fzn_message_line_read(fzn_record_body(rec), fzn_record_body_len(rec), &p)
		           && p.part + 1u == p.parts) {
			int held = key_of(m, fzn_record_subject(rec), p.epoch, device, key);

			memset(key, 0, sizeof(key));
			seen(ctx, fzn_record_subject(rec), p.epoch, device, held);
		}
	}
	if (marks)
		*marks = read;
	return FZN_MESSAGES_OK;
}

/* ---- reading --------------------------------------------------------- */

/* Record `seq` of `device`'s stream, into `buf`. */
static int record_at(const fzn_messages_t *m, const uint8_t device[FZN_PUBKEY_LEN], uint64_t seq,
                     uint8_t *buf, size_t cap, fzn_record_t *rec)
{
	return fzn_record_store_get(&m->journal->store, device, FZN_MESSAGE_STREAM, seq, buf, cap,
	                            rec)
	       == FZN_RECORD_STORE_OK;
}

/* ONE LINE'S TEXT, from its last part at `seq` back through the parts
 * before it, opened under its month's key. Zero when it does not open --
 * the key gone, or a part missing -- `out->readable` 0 and the text
 * empty. */
static void open_text(const fzn_messages_t *m, const uint8_t device[FZN_PUBKEY_LEN],
                      uint64_t seq, const fzn_message_part_t *last, fzn_message_t *out)
{
	static uint8_t buf[FZN_RECORD_MAX_LEN];
	uint8_t key[FZN_CONVERSATION_KEY_LEN];
	uint8_t text[FZN_MESSAGE_TEXT_MAX];
	fzn_message_part_t p;
	fzn_record_t rec;
	size_t at = 0, n = 0;
	uint8_t i;

	out->readable = 0;
	out->text[0] = '\0';
	out->text_len = 0;
	if (!key_of(m, out->contact, last->epoch, device, key))
		return;
	for (i = 0; i < last->parts; i++) {
		uint64_t s = seq - (uint64_t)(last->parts - 1u - i);

		if (i + 1u == last->parts) {
			p = *last;
		} else if (s == 0u || !record_at(m, device, s, buf, sizeof(buf), &rec)
		           || fzn_record_kind(rec) != FZN_MESSAGE_LINE_KIND
		           || memcmp(fzn_record_subject(rec), out->contact, FZN_PUBKEY_LEN) != 0
		           || !fzn_message_line_read(fzn_record_body(rec), fzn_record_body_len(rec), &p)
		           || p.part != i || p.parts != last->parts || p.direction != last->direction
		           || memcmp(p.id, last->id, FZN_MESSAGE_ID_LEN) != 0) {
			memset(key, 0, sizeof(key));
			return;
		}
		if (!fzn_message_line_open(m->aead, key, out->contact, &p, text + at,
		                           sizeof(text) - at, &n)) {
			memset(key, 0, sizeof(key));
			memset(text, 0, sizeof(text));
			return;
		}
		at += n;
	}
	memset(key, 0, sizeof(key));
	memcpy(out->text, text, at);
	out->text[at] = '\0';
	out->text_len = at;
	out->readable = 1;
	memset(text, 0, sizeof(text));
}

/* What a walk has seen: each line once, by direction and id. */
static struct {
	uint8_t direction;
	uint8_t contact[FZN_PUBKEY_LEN];
	uint8_t id[FZN_MESSAGE_ID_LEN];
} seen[FZN_MESSAGES_WALK_MAX];

static int seen_before(size_t n, uint8_t direction, const uint8_t contact[FZN_PUBKEY_LEN],
                       const uint8_t id[FZN_MESSAGE_ID_LEN])
{
	size_t i;

	for (i = 0; i < n; i++)
		if (seen[i].direction == direction
		    && memcmp(seen[i].id, id, FZN_MESSAGE_ID_LEN) == 0
		    && memcmp(seen[i].contact, contact, FZN_PUBKEY_LEN) == 0)
			return 1;
	return 0;
}

fzn_messages_err_t fzn_messages_page(const fzn_messages_t *m, const uint8_t *contact,
                                     size_t offset, fzn_message_t *out, size_t cap,
                                     size_t *count, int *more)
{
	static uint8_t bufs[FZN_MESSAGES_DEVICES_MAX][FZN_RECORD_MAX_LEN];
	fzn_record_t heads[FZN_MESSAGES_DEVICES_MAX];
	uint64_t at[FZN_MESSAGES_DEVICES_MAX];
	int loaded[FZN_MESSAGES_DEVICES_MAX];
	size_t d, n_seen = 0, skipped = 0;

	if (!ready(m) || !out || !count || !more || !m->devices || m->device_count == 0u
	    || m->device_count > FZN_MESSAGES_DEVICES_MAX || cap > FZN_MESSAGES_PAGE_MAX)
		return FZN_MESSAGES_ERR_MALFORMED;
	if (offset > FZN_MESSAGES_WALK_MAX - cap)
		return FZN_MESSAGES_ERR_DEEP;
	*count = 0;
	*more = 0;
	for (d = 0; d < m->device_count; d++) {
		at[d] = fzn_node_journal_received(m->journal, m->devices[d], FZN_MESSAGE_STREAM);
		loaded[d] = 0;
	}
	/* NEWEST FIRST ACROSS THE DEVICES: each step takes the newest of every
	 * stream's next record back, so lines interleave as they were written. */
	for (;;) {
		fzn_message_part_t p;
		fzn_record_t rec;
		size_t best = m->device_count;
		uint64_t seq;

		for (d = 0; d < m->device_count; d++) {
			if (!loaded[d] && at[d] > 0u) {
				if (!record_at(m, m->devices[d], at[d], bufs[d], sizeof(bufs[d]), &heads[d]))
					return FZN_MESSAGES_ERR_JOURNAL;
				loaded[d] = 1;
			}
			if (loaded[d]
			    && (best == m->device_count
			        || fzn_record_issued_at(heads[d]) > fzn_record_issued_at(heads[best])))
				best = d;
		}
		if (best == m->device_count)
			return FZN_MESSAGES_OK;
		rec = heads[best];
		seq = at[best];
		at[best]--;
		loaded[best] = 0;
		/* A LINE IS FOUND BY ITS LAST PART; the parts before it are read
		 * back from there, and passed over when the walk reaches them. */
		if (fzn_record_kind(rec) != FZN_MESSAGE_LINE_KIND
		    || (contact && memcmp(fzn_record_subject(rec), contact, FZN_PUBKEY_LEN) != 0)
		    || !fzn_message_line_read(fzn_record_body(rec), fzn_record_body_len(rec), &p)
		    || p.part + 1u != p.parts
		    || seen_before(n_seen, p.direction, fzn_record_subject(rec), p.id))
			continue;
		if (*count == cap) {
			*more = 1;
			return FZN_MESSAGES_OK;
		}
		seen[n_seen].direction = p.direction;
		memcpy(seen[n_seen].contact, fzn_record_subject(rec), FZN_PUBKEY_LEN);
		memcpy(seen[n_seen].id, p.id, FZN_MESSAGE_ID_LEN);
		n_seen++;
		if (skipped < offset) {
			skipped++;
			continue;
		}
		{
			fzn_message_t *o = &out[*count];

			memcpy(o->contact, fzn_record_subject(rec), FZN_PUBKEY_LEN);
			memcpy(o->device, m->devices[best], FZN_PUBKEY_LEN);
			memcpy(o->id, p.id, FZN_MESSAGE_ID_LEN);
			o->direction = p.direction;
			o->stime = p.stime;
			o->written_at = fzn_record_issued_at(rec);
			o->state = fzn_messages_state(m, o->contact, o->direction, o->id);
			open_text(m, m->devices[best], seq, &p, o);
			(*count)++;
		}
	}
}

/*
 * TWO PASSES OVER EVERY MARK, because the store is unbounded and so is the
 * number of rows: listing them to clear them would fail past any cap. The
 * first removes each marked line's row, so a held row's time cannot outrank
 * the journal; the second applies every mark, the newest winning by when it
 * was written, whichever device it came from. A row for a line the journal
 * holds no mark for is not reached, and only a store written by something
 * else could hold one.
 */
fzn_messages_err_t fzn_messages_reindex(const fzn_messages_t *m, size_t *marks)
{
	static uint8_t buf[FZN_RECORD_MAX_LEN];
	size_t d, read = 0;
	int pass;

	if (!ready(m) || !m->store->remove || !m->devices
	    || m->device_count > FZN_MESSAGES_DEVICES_MAX)
		return FZN_MESSAGES_ERR_MALFORMED;
	for (pass = 0; pass < 2; pass++)
		for (d = 0; d < m->device_count; d++) {
			uint64_t seq, held = fzn_node_journal_received(m->journal, m->devices[d],
			                                               FZN_MESSAGE_STREAM);

			for (seq = 1u; seq <= held; seq++) {
				uint8_t row[FZN_PUBKEY_LEN];
				fzn_message_mark_t mark;
				fzn_record_t rec;

				if (!record_at(m, m->devices[d], seq, buf, sizeof(buf), &rec))
					return FZN_MESSAGES_ERR_JOURNAL;
				if (fzn_record_kind(rec) != FZN_MESSAGE_MARK_KIND
				    || !fzn_message_mark_read(fzn_record_body(rec),
				                              fzn_record_body_len(rec), &mark))
					continue;
				if (pass == 0) {
					if (!state_row(m, fzn_record_subject(rec), mark.direction, mark.id,
					               row)
					    || !m->store->remove(m->store->ctx, FZN_PERSIST_MESSAGE_STATE,
					                         row))
						return FZN_MESSAGES_ERR_BACKEND;
					continue;
				}
				read++;
				if (!set_state(m, fzn_record_subject(rec), mark.direction, mark.id,
				               mark.state, fzn_record_issued_at(rec)))
					return FZN_MESSAGES_ERR_BACKEND;
			}
		}
	if (marks)
		*marks = read;
	return FZN_MESSAGES_OK;
}
