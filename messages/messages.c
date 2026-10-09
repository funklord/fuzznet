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
	case FZN_MESSAGES_ERR_GONE:
		return "that conversation's month was trimmed";
	case FZN_MESSAGES_ERR_WINDOW:
		return "a stream is held from part way, and its lines below are in no journal";
	case FZN_MESSAGES_ERR_REFUSED:
		return "not a line one of the user's devices signed";
	}
	return "unknown";
}

/* A state row: the state, then the time of the mark that set it. */
#define STATE_LEN 9u

static int record_at(const fzn_messages_t *m, const uint8_t device[FZN_PUBKEY_LEN], uint64_t seq,
                     uint8_t *buf, size_t cap, fzn_record_t *rec);
static uint64_t cursor_of(const fzn_messages_t *m, const uint8_t device[FZN_PUBKEY_LEN]);
static int set_cursor(const fzn_messages_t *m, const uint8_t device[FZN_PUBKEY_LEN],
                      uint64_t seq);
static int index_append(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                        const uint8_t device[FZN_PUBKEY_LEN], uint64_t seq, uint8_t direction,
                        const uint8_t id[FZN_MESSAGE_ID_LEN], uint32_t epoch, size_t size);
static int is_gone(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                   uint32_t epoch);
static int keep_line(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                     const uint8_t device[FZN_PUBKEY_LEN], uint64_t seq, uint64_t written_at,
                     const fzn_message_part_t *last, const uint8_t *const body[2],
                     const size_t body_len[2], size_t held);
static int set_read(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                    const uint8_t id[FZN_MESSAGE_ID_LEN], uint64_t at);
static int open_waiting(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                        uint32_t epoch, const uint8_t device[FZN_PUBKEY_LEN]);
static int let_go(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN], uint32_t epoch);
static int item_keep(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                     uint32_t epoch, const uint8_t device[FZN_PUBKEY_LEN], uint64_t seq,
                     uint8_t parts);
static int waits_replay(const fzn_messages_t *m, fzn_messages_seen_fn seen, void *ctx);

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

/* ---- a line as the store keeps it, secs 536 and 539 ---------------------- */

/* `line.situ`'s fzn_message_stored, version 2: a head; the line's text,
 * OPENED, when its key has been held here (sec 539: data is kept decrypted
 * unless staying sealed buys something); and its parts still sealed, as the
 * line records' bodies were written, only while it waits for its key. */
#define STORED_VERSION 2u
#define STORED_CONTACT 1u
#define STORED_DEVICE (STORED_CONTACT + FZN_PUBKEY_LEN)
#define STORED_SEQ (STORED_DEVICE + FZN_PUBKEY_LEN)
#define STORED_WRITTEN (STORED_SEQ + 8u)
#define STORED_STIME (STORED_WRITTEN + 8u)
#define STORED_DIRECTION (STORED_STIME + 8u)
#define STORED_ID (STORED_DIRECTION + 1u)
#define STORED_EPOCH (STORED_ID + FZN_MESSAGE_ID_LEN)
#define STORED_PARTS (STORED_EPOCH + 4u)
#define STORED_OPENED (STORED_PARTS + 1u)
#define STORED_TEXT_LEN (STORED_OPENED + 1u)
#define STORED_TEXT (STORED_TEXT_LEN + 2u)
#define STORED_MAX (STORED_TEXT + FZN_MESSAGE_TEXT_MAX + 1u + 2u * (2u + FZN_RECORD_BODY_MAX))

/* One stored line, read: its text and parts point into the buffer it was
 * read into. OPENED, a row holds its text and no parts; not, no text and
 * either every part (waiting for its key) or none (let go by a trim). */
typedef struct stored {
	uint8_t contact[FZN_PUBKEY_LEN];
	uint8_t device[FZN_PUBKEY_LEN];
	uint64_t seq;
	uint64_t written_at;
	uint64_t stime;
	uint8_t direction;
	uint8_t id[FZN_MESSAGE_ID_LEN];
	uint32_t epoch;
	uint8_t parts;
	uint8_t opened;
	const uint8_t *text;
	size_t text_len;
	uint8_t held;
	const uint8_t *body[2];
	size_t body_len[2];
} stored_t;

/* A line's row: the device that wrote it and its last part's sequence,
 * which is what its index entry names. */
static int line_row(const fzn_messages_t *m, const uint8_t device[FZN_PUBKEY_LEN], uint64_t seq,
                    uint8_t row[FZN_PUBKEY_LEN])
{
	static const char DOMAIN[] = "fuzznet.message.line";
	uint8_t in[sizeof(DOMAIN) - 1u + FZN_PUBKEY_LEN + 8u];
	size_t at = sizeof(DOMAIN) - 1u;

	memcpy(in, DOMAIN, at);
	memcpy(in + at, device, FZN_PUBKEY_LEN);
	fzn_put_be64(in + at + FZN_PUBKEY_LEN, seq);
	return m->hash->hash(m->hash->ctx, row, FZN_PUBKEY_LEN, in, sizeof(in));
}

/* Whether a row's three parts agree: opened with no parts, or not opened
 * with no text and every part or none. */
static int stored_shape_ok(const stored_t *s)
{
	if (s->parts < 1u || s->parts > 2u || s->opened > 1u || s->text_len > FZN_MESSAGE_TEXT_MAX)
		return 0;
	if (s->opened)
		return s->held == 0u;
	return s->text_len == 0u && (s->held == 0u || s->held == s->parts);
}

static int stored_save(const fzn_messages_t *m, const stored_t *s)
{
	uint8_t row[FZN_PUBKEY_LEN], b[STORED_MAX];
	size_t at, i;
	int ok;

	if (!stored_shape_ok(s) || !line_row(m, s->device, s->seq, row))
		return 0;
	b[0] = STORED_VERSION;
	memcpy(b + STORED_CONTACT, s->contact, FZN_PUBKEY_LEN);
	memcpy(b + STORED_DEVICE, s->device, FZN_PUBKEY_LEN);
	fzn_put_be64(b + STORED_SEQ, s->seq);
	fzn_put_be64(b + STORED_WRITTEN, s->written_at);
	fzn_put_be64(b + STORED_STIME, s->stime);
	b[STORED_DIRECTION] = s->direction;
	memcpy(b + STORED_ID, s->id, FZN_MESSAGE_ID_LEN);
	fzn_put_be32(b + STORED_EPOCH, s->epoch);
	b[STORED_PARTS] = s->parts;
	b[STORED_OPENED] = s->opened;
	b[STORED_TEXT_LEN] = (uint8_t)(s->text_len >> 8);
	b[STORED_TEXT_LEN + 1u] = (uint8_t)s->text_len;
	if (s->text_len)
		memcpy(b + STORED_TEXT, s->text, s->text_len);
	at = STORED_TEXT + s->text_len;
	b[at++] = s->held;
	for (i = 0; i < s->held; i++) {
		if (s->body_len[i] < FZN_MESSAGE_LINE_HEAD || s->body_len[i] > FZN_RECORD_BODY_MAX)
			return 0;
		b[at] = (uint8_t)(s->body_len[i] >> 8);
		b[at + 1u] = (uint8_t)s->body_len[i];
		memcpy(b + at + 2u, s->body[i], s->body_len[i]);
		at += 2u + s->body_len[i];
	}
	ok = m->store->save(m->store->ctx, FZN_PERSIST_MESSAGE_LINE, row, b, at);
	memset(b, 0, at);
	return ok;
}

/* The line `device` wrote ending at `seq`, into `buf` (STORED_MAX bytes):
 * zero when no row is held or it does not read whole. */
static int stored_load(const fzn_messages_t *m, const uint8_t device[FZN_PUBKEY_LEN], uint64_t seq,
                       uint8_t *buf, stored_t *s)
{
	uint8_t row[FZN_PUBKEY_LEN];
	size_t len = 0, at, i;

	if (!line_row(m, device, seq, row)
	    || !m->store->load(m->store->ctx, FZN_PERSIST_MESSAGE_LINE, row, buf, STORED_MAX, &len)
	    || len < STORED_TEXT + 1u || buf[0] != STORED_VERSION)
		return 0;
	memcpy(s->contact, buf + STORED_CONTACT, FZN_PUBKEY_LEN);
	memcpy(s->device, buf + STORED_DEVICE, FZN_PUBKEY_LEN);
	s->seq = fzn_get_be64(buf + STORED_SEQ);
	s->written_at = fzn_get_be64(buf + STORED_WRITTEN);
	s->stime = fzn_get_be64(buf + STORED_STIME);
	s->direction = buf[STORED_DIRECTION];
	memcpy(s->id, buf + STORED_ID, FZN_MESSAGE_ID_LEN);
	s->epoch = fzn_get_be32(buf + STORED_EPOCH);
	s->parts = buf[STORED_PARTS];
	s->opened = buf[STORED_OPENED];
	s->text_len = ((size_t)buf[STORED_TEXT_LEN] << 8) | buf[STORED_TEXT_LEN + 1u];
	if (s->text_len > FZN_MESSAGE_TEXT_MAX || len < STORED_TEXT + s->text_len + 1u)
		return 0;
	s->text = buf + STORED_TEXT;
	at = STORED_TEXT + s->text_len;
	s->held = buf[at++];
	/* WHAT IT SAYS IT IS, where it was looked for: a row under another
	 * line's place is not that line. */
	if (memcmp(s->device, device, FZN_PUBKEY_LEN) != 0 || s->seq != seq
	    || !direction_ok(s->direction) || !stored_shape_ok(s))
		return 0;
	for (i = 0; i < s->held; i++) {
		if (len - at < 2u)
			return 0;
		s->body_len[i] = ((size_t)buf[at] << 8) | buf[at + 1u];
		if (s->body_len[i] < FZN_MESSAGE_LINE_HEAD || s->body_len[i] > FZN_RECORD_BODY_MAX
		    || len - at - 2u < s->body_len[i])
			return 0;
		s->body[i] = buf + at + 2u;
		at += 2u + s->body_len[i];
	}
	return at == len;
}

/* OPEN a line's sealed parts under `device`'s key for its month, into
 * `text` (FZN_MESSAGE_TEXT_MAX bytes), `*len` of them: nonzero when the key
 * is held and every part opens and is of this line. */
static int open_parts(const fzn_messages_t *m, const stored_t *s, uint8_t *text, size_t *len)
{
	uint8_t key[FZN_CONVERSATION_KEY_LEN];
	fzn_message_part_t p;
	size_t at = 0, n = 0;
	uint8_t i;

	*len = 0;
	if (s->held != s->parts || !key_of(m, s->contact, s->epoch, s->device, key))
		return 0;
	for (i = 0; i < s->parts; i++) {
		if (!fzn_message_line_read(s->body[i], s->body_len[i], &p) || p.part != i
		    || p.parts != s->parts || p.direction != s->direction || p.epoch != s->epoch
		    || memcmp(p.id, s->id, FZN_MESSAGE_ID_LEN) != 0
		    || !fzn_message_line_open(m->aead, key, s->contact, &p, text + at,
		                              FZN_MESSAGE_TEXT_MAX - at, &n)) {
			memset(key, 0, sizeof(key));
			memset(text, 0, FZN_MESSAGE_TEXT_MAX);
			return 0;
		}
		at += n;
	}
	memset(key, 0, sizeof(key));
	*len = at;
	return 1;
}

/* SAVE `s` OPENED when its key is here, sealed when it is not: the parts
 * are let go once the text is kept. */
static int stored_keep(const fzn_messages_t *m, stored_t *s)
{
	uint8_t text[FZN_MESSAGE_TEXT_MAX];
	size_t n = 0;
	int ok;

	if (!s->opened && s->held && open_parts(m, s, text, &n)) {
		s->opened = 1u;
		s->text = text;
		s->text_len = n;
		s->held = 0u;
	}
	ok = stored_save(m, s);
	memset(text, 0, sizeof(text));
	return ok;
}

/* ---- writing --------------------------------------------------------- */

/* How far this device's own stream reaches now. */
static uint64_t own_head(const fzn_messages_t *m)
{
	return fzn_node_journal_received(m->journal, m->issuer, FZN_MESSAGE_STREAM);
}

/* A RECORD WRITTEN HERE IS TAKEN IN AT ONCE when the store had taken in all
 * of this device's stream before it, `before`: then nothing is skipped by
 * moving the cursor past it. Otherwise the next absorb takes it in. */
static int took_own(const fzn_messages_t *m, uint64_t before)
{
	return cursor_of(m, m->issuer) == before;
}

fzn_messages_err_t fzn_messages_write(const fzn_messages_t *m,
                                      const uint8_t contact[FZN_PUBKEY_LEN], uint8_t direction,
                                      const uint8_t id[FZN_MESSAGE_ID_LEN], uint64_t stime,
                                      const char *text, size_t len)
{
	uint8_t key[FZN_CONVERSATION_KEY_LEN], row[FZN_PUBKEY_LEN], nonce[FZN_AEAD_NONCE_LEN];
	uint8_t bodies[2][FZN_RECORD_BODY_MAX];
	const uint8_t *body[2] = { bodies[0], bodies[1] };
	size_t body_len[2] = { 0, 0 };
	fzn_message_part_t last;
	uint64_t now, before;
	uint32_t epoch;
	size_t parts;
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
	before = own_head(m);
	for (part = 0; part < parts; part++) {
		if (!fzn_nonce_next(m->rng, nonce)
		    || !fzn_message_line_seal(m->aead, key, contact, direction, id, stime, epoch,
		                              nonce, (const uint8_t *)text, len, part, (uint8_t)parts,
		                              bodies[part], &body_len[part])) {
			memset(key, 0, sizeof(key));
			return FZN_MESSAGES_ERR_SEAL;
		}
		if (fzn_node_journal_append_on(m->journal, m->issuer, FZN_MESSAGE_STREAM, m->sign,
		                               FZN_MESSAGE_LINE_KIND, contact, bodies[part],
		                               body_len[part], now, NULL)
		    != FZN_NODE_JOURNAL_OK) {
			memset(key, 0, sizeof(key));
			return FZN_MESSAGES_ERR_JOURNAL;
		}
	}
	memset(key, 0, sizeof(key));
	/* ITS OWN LINE KEPT AND INDEXED NOW, so its conversation lists it
	 * without an absorb between. */
	if (took_own(m, before)
	    && (!fzn_message_line_read(bodies[parts - 1u], body_len[parts - 1u], &last)
	        || !keep_line(m, contact, m->issuer, own_head(m), now, &last, body, body_len, parts)
	        || !item_keep(m, contact, epoch, m->issuer, own_head(m), (uint8_t)parts)
	        || !set_cursor(m, m->issuer, own_head(m))))
		return FZN_MESSAGES_ERR_BACKEND;
	return FZN_MESSAGES_OK;
}

fzn_messages_err_t fzn_messages_import(const fzn_messages_t *m,
                                       const uint8_t contact[FZN_PUBKEY_LEN], uint8_t direction,
                                       const uint8_t id[FZN_MESSAGE_ID_LEN], uint64_t stime,
                                       const char *text, size_t len, int *written)
{
	fzn_messages_err_t err;

	if (!written)
		return FZN_MESSAGES_ERR_MALFORMED;
	*written = 0;
	if (!ready(m) || !contact || !id || !direction_ok(direction))
		return FZN_MESSAGES_ERR_MALFORMED;
	/* HELD ALREADY, BY ANY DEVICE: the import writes nothing, so a line the
	 * user's devices each held before the move is kept once. */
	if (fzn_messages_held(m, contact, direction, id))
		return FZN_MESSAGES_OK;
	err = fzn_messages_write(m, contact, direction, id, stime, text, len);
	if (err == FZN_MESSAGES_OK)
		*written = 1;
	return err;
}

fzn_messages_err_t fzn_messages_read_up_to(const fzn_messages_t *m,
                                           const uint8_t contact[FZN_PUBKEY_LEN],
                                           const uint8_t id[FZN_MESSAGE_ID_LEN])
{
	uint8_t body[FZN_MESSAGE_READ_LEN];
	uint64_t now, before;

	if (!ready(m) || !contact || !id || !fzn_message_position_write(id, body))
		return FZN_MESSAGES_ERR_MALFORMED;
	now = m->now();
	before = own_head(m);
	/* THE RECORD FIRST, as a mark's: the row is derived from it. */
	if (fzn_node_journal_append_on(m->journal, m->issuer, FZN_MESSAGE_STREAM, m->sign,
	                               FZN_MESSAGE_READ_KIND, contact, body, sizeof(body), now,
	                               NULL)
	    != FZN_NODE_JOURNAL_OK)
		return FZN_MESSAGES_ERR_JOURNAL;
	if (!set_read(m, contact, id, now)
	    || (took_own(m, before) && !set_cursor(m, m->issuer, own_head(m))))
		return FZN_MESSAGES_ERR_BACKEND;
	return FZN_MESSAGES_OK;
}

fzn_messages_err_t fzn_messages_mark(const fzn_messages_t *m,
                                     const uint8_t contact[FZN_PUBKEY_LEN], uint8_t direction,
                                     const uint8_t id[FZN_MESSAGE_ID_LEN], uint8_t state)
{
	fzn_message_mark_t mark;
	uint8_t body[FZN_MESSAGE_MARK_LEN];
	uint64_t now, before;

	if (!ready(m) || !contact || !id)
		return FZN_MESSAGES_ERR_MALFORMED;
	mark.direction = direction;
	mark.state = state;
	memcpy(mark.id, id, FZN_MESSAGE_ID_LEN);
	if (!fzn_message_mark_write(&mark, body))
		return FZN_MESSAGES_ERR_MALFORMED;
	now = m->now();
	before = own_head(m);
	/* THE RECORD FIRST: the state row is derived from it, and a row with no
	 * record behind it would not survive a reindex. */
	if (fzn_node_journal_append_on(m->journal, m->issuer, FZN_MESSAGE_STREAM, m->sign,
	                               FZN_MESSAGE_MARK_KIND, contact, body, sizeof(body), now,
	                               NULL)
	    != FZN_NODE_JOURNAL_OK)
		return FZN_MESSAGES_ERR_JOURNAL;
	if (!set_state(m, contact, direction, id, state, now)
	    || (took_own(m, before) && !set_cursor(m, m->issuer, own_head(m))))
		return FZN_MESSAGES_ERR_BACKEND;
	return FZN_MESSAGES_OK;
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
	/* AND THE ROWS' TEXT, sec 539: a row is kept opened, so destroying
	 * keys reaches only the journal's sealed copies. Then the month's items
	 * (sec 564), so no peer is handed what this device let go. */
	if (!let_go(m, contact, epoch)
	    || (m->items && m->items->drop && !m->items->drop(m->items->ctx, contact, epoch)))
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
	/* A TRIMMED MONTH TAKES NO KEY BACK, sec 531: a member still holding
	 * one would otherwise undo the trim at the next round. */
	if (is_gone(m, contact, epoch))
		return FZN_MESSAGES_ERR_GONE;
	if (key_of(m, contact, epoch, device, held)) {
		same = memcmp(held, key, sizeof(held)) == 0;
		memset(held, 0, sizeof(held));
		return same ? FZN_MESSAGES_OK : FZN_MESSAGES_ERR_EQUIVOCATION;
	}
	if (!key_row(m, contact, epoch, device, row))
		return FZN_MESSAGES_ERR_SEAL;
	/* KEPT, THEN EVERY ROW IT OPENS OPENED, sec 539: a line that arrived
	 * before its key has waited sealed for it. */
	return m->store->save(m->store->ctx, FZN_PERSIST_CONVERSATION_KEY, row, key,
	                      FZN_CONVERSATION_KEY_LEN)
	               && open_waiting(m, contact, epoch, device)
	               ? FZN_MESSAGES_OK
	               : FZN_MESSAGES_ERR_BACKEND;
}

/* ---- what is derived: indexes, read positions, cursors ---------------------- */

/* An index entry: the device that wrote the line, its last part's sequence
 * there, and the line's direction and id -- so a conversation is searched
 * by reading its index, not its records. */
#define ENTRY_SEQ FZN_PUBKEY_LEN
#define ENTRY_DIRECTION (ENTRY_SEQ + 8u)
#define ENTRY_ID (ENTRY_DIRECTION + 1u)
/* And its month and its text's size, sec 531, so the rules weigh a
 * conversation from its index alone. */
#define ENTRY_EPOCH (ENTRY_ID + FZN_MESSAGE_ID_LEN)
#define ENTRY_SIZE (ENTRY_EPOCH + 4u)
#define ENTRY_LEN (ENTRY_SIZE + 2u)
/* The conversations held, sec 531: a list of contact keys, chunked so. */
#define CONVERSATIONS_CHUNK 16u
/* How far back an absorb looks for the same line already indexed: a line
 * two devices both wrote is written by both at about the same time. */
#define RECENT_ENTRIES 64u
#define CHUNK_BYTES (FZN_MESSAGES_INDEX_CHUNK * ENTRY_LEN)
/* A read position's row: the line's id, then when it was written. */
#define READ_ROW_LEN (FZN_MESSAGE_ID_LEN + 8u)

/* A derived row's place in FZN_PERSIST_MESSAGE_INDEX: what it is (at most
 * eight letters), whose (a contact or a device), and a number. */
static int index_row(const fzn_messages_t *m, const char *what,
                     const uint8_t key[FZN_PUBKEY_LEN], uint32_t n, uint8_t row[FZN_PUBKEY_LEN])
{
	static const char DOMAIN[] = "fuzznet.message.";
	uint8_t in[sizeof(DOMAIN) - 1u + 8u + FZN_PUBKEY_LEN + 4u];
	size_t at = sizeof(DOMAIN) - 1u, w = strlen(what);

	memset(in, 0, sizeof(in));
	memcpy(in, DOMAIN, at);
	memcpy(in + at, what, w > 8u ? 8u : w);
	at += 8u;
	memcpy(in + at, key, FZN_PUBKEY_LEN);
	fzn_put_be32(in + at + FZN_PUBKEY_LEN, n);
	return m->hash->hash(m->hash->ctx, row, FZN_PUBKEY_LEN, in, sizeof(in));
}

static uint64_t load_number(const fzn_messages_t *m, const char *what,
                            const uint8_t key[FZN_PUBKEY_LEN])
{
	uint8_t row[FZN_PUBKEY_LEN], b[8];
	size_t len = 0;

	if (!index_row(m, what, key, 0u, row)
	    || !m->store->load(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row, b, sizeof(b), &len)
	    || len != sizeof(b))
		return 0u;
	return fzn_get_be64(b);
}

static int save_number(const fzn_messages_t *m, const char *what,
                       const uint8_t key[FZN_PUBKEY_LEN], uint64_t v)
{
	uint8_t row[FZN_PUBKEY_LEN], b[8];

	fzn_put_be64(b, v);
	return index_row(m, what, key, 0u, row)
	       && m->store->save(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row, b, sizeof(b));
}

/* How far `device`'s stream has been taken in, and how many lines a
 * conversation's index holds. */
static uint64_t cursor_of(const fzn_messages_t *m, const uint8_t device[FZN_PUBKEY_LEN])
{
	return load_number(m, "cursor", device);
}

static int set_cursor(const fzn_messages_t *m, const uint8_t device[FZN_PUBKEY_LEN],
                      uint64_t seq)
{
	return save_number(m, "cursor", device, seq);
}

static uint64_t count_of(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN])
{
	return load_number(m, "count", contact);
}

/* ONE CHUNK OF ONE INDEX, held, since a listing reads its entries in turn. */
static struct {
	int valid;
	uint8_t contact[FZN_PUBKEY_LEN];
	uint32_t chunk;
	size_t len;
	uint8_t bytes[CHUNK_BYTES];
} chunk_held;

/* One index entry, read. */
typedef struct entry {
	uint8_t device[FZN_PUBKEY_LEN];
	uint64_t seq;
	uint8_t direction;
	uint8_t id[FZN_MESSAGE_ID_LEN];
	uint32_t epoch;
	uint16_t size;
} entry_t;

static const uint8_t NOBODY[FZN_PUBKEY_LEN];

/* ADD `contact` to the conversations held: once, when its index gains its
 * first line. */
static int conversation_add(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN])
{
	uint8_t row[FZN_PUBKEY_LEN], chunk[CONVERSATIONS_CHUNK * FZN_PUBKEY_LEN];
	uint64_t n = load_number(m, "convs", NOBODY);
	size_t in_chunk = (size_t)(n % CONVERSATIONS_CHUNK), len = 0;

	if (!index_row(m, "convchnk", NOBODY, (uint32_t)(n / CONVERSATIONS_CHUNK), row))
		return 0;
	if (in_chunk
	    && (!m->store->load(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row, chunk, sizeof(chunk),
	                        &len)
	        || len != in_chunk * FZN_PUBKEY_LEN))
		return 0;
	memcpy(chunk + in_chunk * FZN_PUBKEY_LEN, contact, FZN_PUBKEY_LEN);
	return m->store->save(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row, chunk,
	                      (in_chunk + 1u) * FZN_PUBKEY_LEN)
	       && save_number(m, "convs", NOBODY, n + 1u);
}

/* Conversation `i`'s contact. */
static int conversation_at(const fzn_messages_t *m, uint64_t i, uint8_t contact[FZN_PUBKEY_LEN])
{
	uint8_t row[FZN_PUBKEY_LEN], chunk[CONVERSATIONS_CHUNK * FZN_PUBKEY_LEN];
	size_t k = (size_t)(i % CONVERSATIONS_CHUNK), len = 0;

	if (!index_row(m, "convchnk", NOBODY, (uint32_t)(i / CONVERSATIONS_CHUNK), row)
	    || !m->store->load(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row, chunk, sizeof(chunk),
	                       &len)
	    || (k + 1u) * FZN_PUBKEY_LEN > len)
		return 0;
	memcpy(contact, chunk + k * FZN_PUBKEY_LEN, FZN_PUBKEY_LEN);
	return 1;
}

static int conversations_clear(const fzn_messages_t *m)
{
	uint8_t row[FZN_PUBKEY_LEN];
	uint64_t n = load_number(m, "convs", NOBODY), c;

	for (c = 0; c * CONVERSATIONS_CHUNK < n; c++)
		if (!index_row(m, "convchnk", NOBODY, (uint32_t)c, row)
		    || !m->store->remove(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row))
			return 0;
	return index_row(m, "convs", NOBODY, 0u, row)
	       && m->store->remove(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row);
}

/* EVERY LINE IN THE ORDER IT WAS LEARNED, across conversations, sec 536:
 * each entry a conversation and its place in that conversation's index, so
 * a listing of everyone's lines reads the store and not the journal. */
#define ALL_ENTRY_LEN (FZN_PUBKEY_LEN + 8u)
#define ALL_CHUNK_BYTES (FZN_MESSAGES_INDEX_CHUNK * ALL_ENTRY_LEN)

static struct {
	int valid;
	uint32_t chunk;
	size_t len;
	uint8_t bytes[ALL_CHUNK_BYTES];
} all_held;

static int all_append(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN], uint64_t i)
{
	uint8_t row[FZN_PUBKEY_LEN], chunk[ALL_CHUNK_BYTES];
	uint64_t n = load_number(m, "alls", NOBODY);
	size_t in_chunk = (size_t)(n % FZN_MESSAGES_INDEX_CHUNK), len = 0;

	all_held.valid = 0;
	if (n / FZN_MESSAGES_INDEX_CHUNK > UINT32_MAX
	    || !index_row(m, "allchnk", NOBODY, (uint32_t)(n / FZN_MESSAGES_INDEX_CHUNK), row))
		return 0;
	if (in_chunk
	    && (!m->store->load(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row, chunk, sizeof(chunk),
	                        &len)
	        || len != in_chunk * ALL_ENTRY_LEN))
		return 0;
	memcpy(chunk + in_chunk * ALL_ENTRY_LEN, contact, FZN_PUBKEY_LEN);
	fzn_put_be64(chunk + in_chunk * ALL_ENTRY_LEN + FZN_PUBKEY_LEN, i);
	return m->store->save(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row, chunk,
	                      (in_chunk + 1u) * ALL_ENTRY_LEN)
	       && save_number(m, "alls", NOBODY, n + 1u);
}

/* Entry `k` of every line's order: its conversation and its place there. */
static int all_entry(const fzn_messages_t *m, uint64_t k, uint8_t contact[FZN_PUBKEY_LEN],
                     uint64_t *i)
{
	uint32_t c = (uint32_t)(k / FZN_MESSAGES_INDEX_CHUNK);
	size_t at = (size_t)(k % FZN_MESSAGES_INDEX_CHUNK) * ALL_ENTRY_LEN;

	if (!all_held.valid || all_held.chunk != c) {
		uint8_t row[FZN_PUBKEY_LEN];

		all_held.valid = 0;
		if (!index_row(m, "allchnk", NOBODY, c, row)
		    || !m->store->load(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row, all_held.bytes,
		                       sizeof(all_held.bytes), &all_held.len))
			return 0;
		all_held.chunk = c;
		all_held.valid = 1;
	}
	if (at + ALL_ENTRY_LEN > all_held.len)
		return 0;
	memcpy(contact, all_held.bytes + at, FZN_PUBKEY_LEN);
	*i = fzn_get_be64(all_held.bytes + at + FZN_PUBKEY_LEN);
	return 1;
}

static int all_clear(const fzn_messages_t *m)
{
	uint8_t row[FZN_PUBKEY_LEN];
	uint64_t n = load_number(m, "alls", NOBODY), c;

	all_held.valid = 0;
	for (c = 0; c * FZN_MESSAGES_INDEX_CHUNK < n; c++)
		if (!index_row(m, "allchnk", NOBODY, (uint32_t)c, row)
		    || !m->store->remove(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row))
			return 0;
	return index_row(m, "alls", NOBODY, 0u, row)
	       && m->store->remove(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row);
}

/* A TRIMMED MONTH, sec 531: its keys destroyed, and marked so none is taken
 * back. Not derived: nothing in the journal says it, so a reindex keeps it. */
static int is_gone(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                   uint32_t epoch)
{
	uint8_t row[FZN_PUBKEY_LEN], b[1];
	size_t len = 0;

	return index_row(m, "gone", contact, epoch, row)
	       && m->store->load(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row, b, sizeof(b), &len)
	       && len == 1u;
}

static int set_gone(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                    uint32_t epoch)
{
	uint8_t row[FZN_PUBKEY_LEN], b[1] = { 1u };

	return index_row(m, "gone", contact, epoch, row)
	       && m->store->save(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row, b, sizeof(b));
}

static int index_entry(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN], uint64_t i,
                       entry_t *e);

/* Whether (`direction`, `id`) is among `contact`'s last RECENT_ENTRIES. */
static int recently_indexed(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                            uint64_t n, uint8_t direction, const uint8_t id[FZN_MESSAGE_ID_LEN])
{
	entry_t e;
	uint64_t i;

	for (i = n; i > 0u && n - i < RECENT_ENTRIES; i--)
		if (index_entry(m, contact, i - 1u, &e) && e.direction == direction
		    && memcmp(e.id, id, FZN_MESSAGE_ID_LEN) == 0)
			return 1;
	return 0;
}

/* APPEND a line to `contact`'s index, once: a line already among its
 * recent entries, written by another device, is not appended again. */
static int index_append(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                        const uint8_t device[FZN_PUBKEY_LEN], uint64_t seq, uint8_t direction,
                        const uint8_t id[FZN_MESSAGE_ID_LEN], uint32_t epoch, size_t size)
{
	uint8_t row[FZN_PUBKEY_LEN], chunk[CHUNK_BYTES];
	uint64_t n = count_of(m, contact);
	size_t in_chunk = (size_t)(n % FZN_MESSAGES_INDEX_CHUNK), len = 0;

	if (recently_indexed(m, contact, n, direction, id))
		return 1;
	if (n == 0u && !conversation_add(m, contact))
		return 0;
	chunk_held.valid = 0;
	if (n / FZN_MESSAGES_INDEX_CHUNK > UINT32_MAX
	    || !index_row(m, "chunk", contact, (uint32_t)(n / FZN_MESSAGES_INDEX_CHUNK), row))
		return 0;
	if (in_chunk
	    && (!m->store->load(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row, chunk, sizeof(chunk),
	                        &len)
	        || len != in_chunk * ENTRY_LEN))
		return 0;
	memcpy(chunk + in_chunk * ENTRY_LEN, device, FZN_PUBKEY_LEN);
	fzn_put_be64(chunk + in_chunk * ENTRY_LEN + ENTRY_SEQ, seq);
	chunk[in_chunk * ENTRY_LEN + ENTRY_DIRECTION] = direction;
	memcpy(chunk + in_chunk * ENTRY_LEN + ENTRY_ID, id, FZN_MESSAGE_ID_LEN);
	fzn_put_be32(chunk + in_chunk * ENTRY_LEN + ENTRY_EPOCH, epoch);
	chunk[in_chunk * ENTRY_LEN + ENTRY_SIZE] = (uint8_t)(size >> 8);
	chunk[in_chunk * ENTRY_LEN + ENTRY_SIZE + 1u] = (uint8_t)size;
	/* THE ENTRY, THEN THE COUNT: a crash between leaves an entry the count
	 * does not reach, which the next append writes over. Then its place in
	 * every line's order; a crash before that leaves the line out of the
	 * listing of everyone's until a reindex. */
	return m->store->save(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row, chunk,
	                      (in_chunk + 1u) * ENTRY_LEN)
	       && save_number(m, "count", contact, n + 1u) && all_append(m, contact, n);
}

/* OPEN THE ROWS WAITING FOR A KEY: `contact`'s lines of `epoch` that
 * `device` wrote and that are kept sealed, now `device`'s key is here. The
 * conversation's index is walked, as rarely as keys arrive. */
static int open_waiting(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                        uint32_t epoch, const uint8_t device[FZN_PUBKEY_LEN])
{
	static uint8_t buf[STORED_MAX];
	stored_t s;
	entry_t e;
	uint64_t i;

	for (i = count_of(m, contact); i > 0u; i--) {
		if (!index_entry(m, contact, i - 1u, &e))
			return 0;
		if (e.epoch != epoch || memcmp(e.device, device, FZN_PUBKEY_LEN) != 0
		    || !stored_load(m, e.device, e.seq, buf, &s) || s.opened || s.held == 0u)
			continue;
		if (!stored_keep(m, &s))
			return 0;
	}
	return 1;
}

/* LET GO OF A MONTH'S TEXT: each of `contact`'s rows of `epoch` keeps its
 * head and holds neither text nor sealed parts. Removed, then the head
 * saved: a removal is what erases a row's history from an operation journal
 * (sec 523), where a rewrite would leave the text it held. */
static int let_go(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN], uint32_t epoch)
{
	static uint8_t buf[STORED_MAX];
	uint8_t row[FZN_PUBKEY_LEN];
	stored_t s;
	entry_t e;
	uint64_t i;

	for (i = count_of(m, contact); i > 0u; i--) {
		if (!index_entry(m, contact, i - 1u, &e))
			return 0;
		if (e.epoch != epoch || !stored_load(m, e.device, e.seq, buf, &s)
		    || (!s.opened && s.held == 0u))
			continue;
		s.opened = 0u;
		s.text_len = 0;
		s.held = 0u;
		if (!line_row(m, e.device, e.seq, row)
		    || !m->store->remove(m->store->ctx, FZN_PERSIST_MESSAGE_LINE, row)
		    || !stored_save(m, &s))
			return 0;
	}
	return 1;
}

/* KEEP A LINE: its row, then its index entry, once -- a line another device
 * wrote first is already kept, under that device's place. `held` of its
 * parts are given in `body`, all of them or none; a trimmed month's line
 * keeps its head alone, its parts let go with its keys. */
static int keep_line(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                     const uint8_t device[FZN_PUBKEY_LEN], uint64_t seq, uint64_t written_at,
                     const fzn_message_part_t *last, const uint8_t *const body[2],
                     const size_t body_len[2], size_t held)
{
	stored_t s;
	size_t i;

	if (recently_indexed(m, contact, count_of(m, contact), last->direction, last->id))
		return 1;
	memcpy(s.contact, contact, FZN_PUBKEY_LEN);
	memcpy(s.device, device, FZN_PUBKEY_LEN);
	s.seq = seq;
	s.written_at = written_at;
	s.stime = last->stime;
	s.direction = last->direction;
	memcpy(s.id, last->id, FZN_MESSAGE_ID_LEN);
	s.epoch = last->epoch;
	s.parts = last->parts;
	s.opened = 0u;
	s.text = NULL;
	s.text_len = 0;
	s.held = (uint8_t)(held == last->parts && !is_gone(m, contact, last->epoch) ? held : 0u);
	for (i = 0; i < s.held; i++) {
		s.body[i] = body[i];
		s.body_len[i] = body_len[i];
	}
	/* THE ROW, OPENED WHEN ITS KEY IS HERE, THEN THE ENTRY: an entry never
	 * names a line nothing keeps. */
	return stored_keep(m, &s)
	       && index_append(m, contact, device, seq, last->direction, last->id, last->epoch,
	                       last->text_len + (last->parts == 2u ? FZN_MESSAGE_PART_MAX : 0u));
}

/* Entry `i` of `contact`'s index. */
static int index_entry(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN], uint64_t i,
                       entry_t *e)
{
	uint32_t c = (uint32_t)(i / FZN_MESSAGES_INDEX_CHUNK);
	size_t k = (size_t)(i % FZN_MESSAGES_INDEX_CHUNK);

	if (!chunk_held.valid || chunk_held.chunk != c
	    || memcmp(chunk_held.contact, contact, FZN_PUBKEY_LEN) != 0) {
		uint8_t row[FZN_PUBKEY_LEN];

		chunk_held.valid = 0;
		if (!index_row(m, "chunk", contact, c, row)
		    || !m->store->load(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row, chunk_held.bytes,
		                       sizeof(chunk_held.bytes), &chunk_held.len))
			return 0;
		memcpy(chunk_held.contact, contact, FZN_PUBKEY_LEN);
		chunk_held.chunk = c;
		chunk_held.valid = 1;
	}
	if ((k + 1u) * ENTRY_LEN > chunk_held.len)
		return 0;
	memcpy(e->device, chunk_held.bytes + k * ENTRY_LEN, FZN_PUBKEY_LEN);
	e->seq = fzn_get_be64(chunk_held.bytes + k * ENTRY_LEN + ENTRY_SEQ);
	e->direction = chunk_held.bytes[k * ENTRY_LEN + ENTRY_DIRECTION];
	memcpy(e->id, chunk_held.bytes + k * ENTRY_LEN + ENTRY_ID, FZN_MESSAGE_ID_LEN);
	e->epoch = fzn_get_be32(chunk_held.bytes + k * ENTRY_LEN + ENTRY_EPOCH);
	e->size = (uint16_t)((chunk_held.bytes[k * ENTRY_LEN + ENTRY_SIZE] << 8)
	                     | chunk_held.bytes[k * ENTRY_LEN + ENTRY_SIZE + 1u]);
	return 1;
}

/* Every row of `contact`'s index, gone. */
static int index_clear(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN])
{
	uint8_t row[FZN_PUBKEY_LEN];
	uint64_t n = count_of(m, contact), c;

	chunk_held.valid = 0;
	for (c = 0; c * FZN_MESSAGES_INDEX_CHUNK < n; c++)
		if (!index_row(m, "chunk", contact, (uint32_t)c, row)
		    || !m->store->remove(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row))
			return 0;
	return index_row(m, "count", contact, 0u, row)
	       && m->store->remove(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row);
}

/* SET A CONVERSATION'S READ POSITION when it is at least as new as the one
 * held. */
static int set_read(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                    const uint8_t id[FZN_MESSAGE_ID_LEN], uint64_t at)
{
	uint8_t row[FZN_PUBKEY_LEN], held[READ_ROW_LEN], bytes[READ_ROW_LEN];
	size_t len = 0;

	if (!index_row(m, "read", contact, 0u, row))
		return 0;
	if (m->store->load(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row, held, sizeof(held), &len)
	    && len == READ_ROW_LEN && fzn_get_be64(held + FZN_MESSAGE_ID_LEN) > at)
		return 1;
	memcpy(bytes, id, FZN_MESSAGE_ID_LEN);
	fzn_put_be64(bytes + FZN_MESSAGE_ID_LEN, at);
	return m->store->save(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row, bytes, sizeof(bytes));
}

int fzn_messages_read_position(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                               uint8_t id[FZN_MESSAGE_ID_LEN])
{
	uint8_t row[FZN_PUBKEY_LEN], held[READ_ROW_LEN];
	size_t len = 0;

	if (!ready(m) || !contact || !id || !index_row(m, "read", contact, 0u, row)
	    || !m->store->load(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row, held, sizeof(held),
	                       &len)
	    || len != READ_ROW_LEN)
		return 0;
	memcpy(id, held, FZN_MESSAGE_ID_LEN);
	return 1;
}

/* ---- taking streams in ---------------------------------------------------- */

/* A LINE'S PARTS, from the journal, ending at `rec` (`seq`, parsed as
 * `last`): nonzero with every part's body when each is there and of this
 * line. Read while the journal still holds them, which is when a line is
 * taken in. */
static int parts_of(const fzn_messages_t *m, const uint8_t device[FZN_PUBKEY_LEN], uint64_t seq,
                    fzn_record_t rec, const fzn_message_part_t *last, const uint8_t *body[2],
                    size_t body_len[2])
{
	static uint8_t earlier[FZN_RECORD_MAX_LEN];
	fzn_message_part_t p;
	fzn_record_t prev;

	body[last->parts - 1u] = fzn_record_body(rec);
	body_len[last->parts - 1u] = fzn_record_body_len(rec);
	if (last->parts == 1u)
		return 1;
	if (seq < 2u || !record_at(m, device, seq - 1u, earlier, sizeof(earlier), &prev)
	    || fzn_record_kind(prev) != FZN_MESSAGE_LINE_KIND
	    || memcmp(fzn_record_subject(prev), fzn_record_subject(rec), FZN_PUBKEY_LEN) != 0
	    || !fzn_message_line_read(fzn_record_body(prev), fzn_record_body_len(prev), &p)
	    || p.part != 0u || p.parts != last->parts || p.direction != last->direction
	    || p.epoch != last->epoch || memcmp(p.id, last->id, FZN_MESSAGE_ID_LEN) != 0)
		return 0;
	body[0] = fzn_record_body(prev);
	body_len[0] = fzn_record_body_len(prev);
	return 1;
}

/* ONE RECORD TAKEN IN: its key reported whatever `done` says, and past
 * `*done` everything else -- the line indexed, the mark or the read position
 * applied -- with `*done` moved to it. */
static fzn_messages_err_t take_in(const fzn_messages_t *m, const uint8_t device[FZN_PUBKEY_LEN],
                                  uint64_t seq, fzn_record_t rec, uint64_t *done,
                                  fzn_messages_seen_fn seen, void *ctx, size_t *marks)
{
	uint8_t key[FZN_CONVERSATION_KEY_LEN], id[FZN_MESSAGE_ID_LEN];
	fzn_message_mark_t mark;
	fzn_message_part_t p;
	const uint8_t *contact = fzn_record_subject(rec);
	int fresh = seq > *done;

	if (fzn_record_kind(rec) == FZN_MESSAGE_LINE_KIND
	    && fzn_message_line_read(fzn_record_body(rec), fzn_record_body_len(rec), &p)
	    && p.part + 1u == p.parts) {
		/* A TRIMMED MONTH'S LINE is reported to nobody: its key is not to
		 * be asked for, nor given. */
		if (seen && !is_gone(m, contact, p.epoch)) {
			int held = key_of(m, contact, p.epoch, device, key);

			memset(key, 0, sizeof(key));
			seen(ctx, contact, p.epoch, device, held);
		}
		/* KEPT, THEN THE CURSOR MOVED, at once: an index entry is the one
		 * thing taken in twice that would show twice. */
		if (fresh) {
			const uint8_t *body[2] = { NULL, NULL };
			size_t body_len[2] = { 0, 0 };
			size_t held = parts_of(m, device, seq, rec, &p, body, body_len) ? p.parts : 0u;

			if (!keep_line(m, contact, device, seq, fzn_record_issued_at(rec), &p, body,
			               body_len, held)
			    || (held && !item_keep(m, contact, p.epoch, device, seq, p.parts))
			    || !set_cursor(m, device, seq))
				return FZN_MESSAGES_ERR_BACKEND;
		}
	} else if (fresh && fzn_record_kind(rec) == FZN_MESSAGE_MARK_KIND
	           && fzn_message_mark_read(fzn_record_body(rec), fzn_record_body_len(rec), &mark)) {
		(*marks)++;
		if (!set_state(m, contact, mark.direction, mark.id, mark.state,
		               fzn_record_issued_at(rec)))
			return FZN_MESSAGES_ERR_BACKEND;
	} else if (fresh && fzn_record_kind(rec) == FZN_MESSAGE_READ_KIND
	           && fzn_message_position_read(fzn_record_body(rec), fzn_record_body_len(rec), id)) {
		if (!set_read(m, contact, id, fzn_record_issued_at(rec)))
			return FZN_MESSAGES_ERR_BACKEND;
	}
	if (fresh)
		*done = seq;
	return FZN_MESSAGES_OK;
}

fzn_messages_err_t fzn_messages_absorb(const fzn_messages_t *m, uint64_t *at,
                                       fzn_messages_seen_fn seen, void *ctx, size_t *marks)
{
	static uint8_t bufs[FZN_MESSAGES_DEVICES_MAX][FZN_RECORD_MAX_LEN];
	fzn_record_t heads[FZN_MESSAGES_DEVICES_MAX];
	uint64_t to[FZN_MESSAGES_DEVICES_MAX], done[FZN_MESSAGES_DEVICES_MAX];
	uint64_t start[FZN_MESSAGES_DEVICES_MAX];
	int loaded[FZN_MESSAGES_DEVICES_MAX];
	size_t d, read = 0;
	fzn_messages_err_t err;

	if (!ready(m) || !at || !m->devices || m->device_count > FZN_MESSAGES_DEVICES_MAX)
		return FZN_MESSAGES_ERR_MALFORMED;
	if (seen && !waits_replay(m, seen, ctx))
		return FZN_MESSAGES_ERR_BACKEND;
	for (d = 0; d < m->device_count; d++) {
		to[d] = fzn_node_journal_received(m->journal, m->devices[d], FZN_MESSAGE_STREAM);
		done[d] = start[d] = cursor_of(m, m->devices[d]);
		loaded[d] = 0;
	}
	/* OLDEST FIRST ACROSS THE DEVICES, so a conversation's index follows
	 * the order its lines were written in as far as this store has them. */
	for (;;) {
		size_t best = m->device_count;
		uint64_t seq;

		for (d = 0; d < m->device_count; d++) {
			if (at[d] >= to[d])
				continue;
			if (!loaded[d]) {
				if (!record_at(m, m->devices[d], at[d] + 1u, bufs[d], sizeof(bufs[d]),
				               &heads[d]))
					return FZN_MESSAGES_ERR_JOURNAL;
				loaded[d] = 1;
			}
			if (best == m->device_count
			    || fzn_record_issued_at(heads[d]) < fzn_record_issued_at(heads[best]))
				best = d;
		}
		if (best == m->device_count)
			break;
		seq = ++at[best];
		loaded[best] = 0;
		err = take_in(m, m->devices[best], seq, heads[best], &done[best], seen, ctx, &read);
		if (err != FZN_MESSAGES_OK)
			return err;
	}
	for (d = 0; d < m->device_count; d++)
		if (done[d] != start[d] && !set_cursor(m, m->devices[d], done[d]))
			return FZN_MESSAGES_ERR_BACKEND;
	if (marks)
		*marks = read;
	return FZN_MESSAGES_OK;
}

/* ---- items: a line as its device signed it, sec 564 ---------------------- */

/* A LINE'S ITEM from the journal: the `parts` records ending at `seq` of
 * `device`'s stream, into `out` (FZN_MESSAGES_ITEM_MAX). */
static int item_from_journal(const fzn_messages_t *m, const uint8_t device[FZN_PUBKEY_LEN],
                             uint64_t seq, uint8_t parts, uint8_t *out, size_t *len)
{
	static uint8_t buf[FZN_RECORD_MAX_LEN];
	fzn_record_t r;
	size_t at = 1u;
	uint8_t i;

	if (parts < 1u || parts > 2u || seq < parts)
		return 0;
	out[0] = parts;
	for (i = 0; i < parts; i++) {
		if (!record_at(m, device, seq - parts + 1u + i, buf, sizeof(buf), &r)
		    || r.len > FZN_RECORD_MAX_LEN)
			return 0;
		fzn_put_be16(out + at, (uint16_t)r.len);
		memcpy(out + at + 2u, r.base, r.len);
		at += 2u + r.len;
	}
	*len = at;
	return 1;
}

/* KEEP A LINE'S ITEM, read back from the journal it was just taken from,
 * where the store keeps items at all. */
static int item_keep(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                     uint32_t epoch, const uint8_t device[FZN_PUBKEY_LEN], uint64_t seq,
                     uint8_t parts)
{
	static uint8_t item[FZN_MESSAGES_ITEM_MAX];
	size_t len = 0;

	if (!m->items || !m->items->add)
		return 1;
	return item_from_journal(m, device, seq, parts, item, &len)
	       && m->items->add(m->items->ctx, contact, epoch, item, len);
}

/* KEYS WANTED FOR LINES FILED FROM ITEMS: each a conversation, a month and
 * a device. A line read from the journal has its key noted again at every
 * start, by the absorb that walks the stream from its base; a line filed
 * from an item was in no stream here, so its want is kept in a row and
 * handed to every absorb's `seen` until the key is here or the month
 * gone. */
#define WAIT_LEN (FZN_PUBKEY_LEN + 4u + FZN_PUBKEY_LEN)
#define WAITS_MAX 256u

static uint8_t waits[WAITS_MAX * WAIT_LEN];

static int waits_load(const fzn_messages_t *m, size_t *n)
{
	uint8_t row[FZN_PUBKEY_LEN];
	size_t len = 0;

	*n = 0;
	if (!index_row(m, "waits", NOBODY, 0u, row))
		return 0;
	if (!m->store->load(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row, waits, sizeof(waits),
	                    &len))
		return 1;
	if (len % WAIT_LEN != 0u)
		return 0;
	*n = len / WAIT_LEN;
	return 1;
}

static int waits_save(const fzn_messages_t *m, size_t n)
{
	uint8_t row[FZN_PUBKEY_LEN];

	if (!index_row(m, "waits", NOBODY, 0u, row))
		return 0;
	if (n == 0u)
		return !m->store->remove || m->store->remove(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row);
	return m->store->save(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row, waits, n * WAIT_LEN);
}

/* NOTE A WANT once. Past WAITS_MAX places it is not kept, and that line's
 * key is asked for only until the next start. */
static int wait_add(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                    uint32_t epoch, const uint8_t device[FZN_PUBKEY_LEN])
{
	uint8_t e[WAIT_LEN];
	size_t n, i;

	memcpy(e, contact, FZN_PUBKEY_LEN);
	fzn_put_be32(e + FZN_PUBKEY_LEN, epoch);
	memcpy(e + FZN_PUBKEY_LEN + 4u, device, FZN_PUBKEY_LEN);
	if (!waits_load(m, &n))
		return 0;
	for (i = 0; i < n; i++)
		if (memcmp(waits + i * WAIT_LEN, e, WAIT_LEN) == 0)
			return 1;
	if (n >= WAITS_MAX)
		return 1;
	memcpy(waits + n * WAIT_LEN, e, WAIT_LEN);
	return waits_save(m, n + 1u);
}

/* EVERY WANT TO `seen`, and those whose key is here, or whose month is
 * gone, let go. */
static int waits_replay(const fzn_messages_t *m, fzn_messages_seen_fn seen, void *ctx)
{
	uint8_t key[FZN_CONVERSATION_KEY_LEN];
	size_t n, i, kept = 0;

	if (!waits_load(m, &n))
		return 0;
	for (i = 0; i < n; i++) {
		const uint8_t *e = waits + i * WAIT_LEN;
		uint32_t epoch = fzn_get_be32(e + FZN_PUBKEY_LEN);
		int held, gone = is_gone(m, e, epoch);

		held = !gone && key_of(m, e, epoch, e + FZN_PUBKEY_LEN + 4u, key);
		memset(key, 0, sizeof(key));
		if (!gone)
			seen(ctx, e, epoch, e + FZN_PUBKEY_LEN + 4u, held);
		if (!gone && !held) {
			if (kept != i)
				memmove(waits + kept * WAIT_LEN, e, WAIT_LEN);
			kept++;
		}
	}
	return kept == n || waits_save(m, kept);
}

static int is_device(const fzn_messages_t *m, const uint8_t key[FZN_PUBKEY_LEN])
{
	size_t d;

	if (memcmp(key, m->issuer, FZN_PUBKEY_LEN) == 0)
		return 1;
	for (d = 0; d < m->device_count; d++)
		if (memcmp(key, m->devices[d], FZN_PUBKEY_LEN) == 0)
			return 1;
	return 0;
}

fzn_messages_err_t fzn_messages_file(const fzn_messages_t *m, const uint8_t *item, size_t len,
                                     uint8_t contact_out[FZN_PUBKEY_LEN], uint32_t *epoch_out,
                                     int *waiting)
{
	static uint8_t buf[STORED_MAX];
	uint8_t key[FZN_CONVERSATION_KEY_LEN];
	fzn_record_t rec[2];
	fzn_message_part_t p[2];
	const uint8_t *body[2] = { NULL, NULL };
	size_t body_len[2] = { 0, 0 };
	const uint8_t *device, *contact;
	size_t at = 1u;
	uint64_t seq;
	uint32_t epoch;
	uint8_t parts, i;
	stored_t s;
	int held;

	if (waiting)
		*waiting = 0;
	if (!ready(m) || !item || !m->devices || m->device_count > FZN_MESSAGES_DEVICES_MAX)
		return FZN_MESSAGES_ERR_MALFORMED;
	if (len < 1u || len > FZN_MESSAGES_ITEM_MAX || (parts = item[0]) < 1u || parts > 2u)
		return FZN_MESSAGES_ERR_REFUSED;
	for (i = 0; i < parts; i++) {
		size_t n;

		if (len - at < 2u)
			return FZN_MESSAGES_ERR_REFUSED;
		n = fzn_get_be16(item + at);
		at += 2u;
		if (len - at < n || fzn_record_open(item + at, n, &rec[i]) != FZN_RECORD_OK)
			return FZN_MESSAGES_ERR_REFUSED;
		at += n;
	}
	if (at != len)
		return FZN_MESSAGES_ERR_REFUSED;
	device = fzn_record_issuer(rec[0]);
	contact = fzn_record_subject(rec[0]);
	seq = fzn_record_seq(rec[parts - 1u]);
	/* AS THE JOURNAL WOULD HAVE IT: one of the user's devices signed every
	 * part, on its conversations stream, one line's parts in sequence. */
	if (!is_device(m, device) || seq < parts)
		return FZN_MESSAGES_ERR_REFUSED;
	for (i = 0; i < parts; i++) {
		if (fzn_record_verify(rec[i], m->sign) != FZN_RECORD_OK
		    || memcmp(fzn_record_issuer(rec[i]), device, FZN_PUBKEY_LEN) != 0
		    || fzn_record_stream(rec[i]) != FZN_MESSAGE_STREAM
		    || fzn_record_kind(rec[i]) != FZN_MESSAGE_LINE_KIND
		    || memcmp(fzn_record_subject(rec[i]), contact, FZN_PUBKEY_LEN) != 0
		    || fzn_record_seq(rec[i]) != seq - parts + 1u + i
		    || !fzn_message_line_read(fzn_record_body(rec[i]), fzn_record_body_len(rec[i]), &p[i])
		    || p[i].part != i || p[i].parts != parts || p[i].direction != p[0].direction
		    || p[i].epoch != p[0].epoch || memcmp(p[i].id, p[0].id, FZN_MESSAGE_ID_LEN) != 0)
			return FZN_MESSAGES_ERR_REFUSED;
		body[i] = fzn_record_body(rec[i]);
		body_len[i] = fzn_record_body_len(rec[i]);
	}
	epoch = p[0].epoch;
	if (contact_out)
		memcpy(contact_out, contact, FZN_PUBKEY_LEN);
	if (epoch_out)
		*epoch_out = epoch;
	if (is_gone(m, contact, epoch))
		return FZN_MESSAGES_ERR_GONE;
	/* KEPT ALREADY under this place needs only its item. The same line
	 * another device wrote is found as the journal's absorb finds it, among
	 * the conversation's recent lines; one found nowhere is kept. */
	if (!stored_load(m, device, seq, buf, &s)
	    && !keep_line(m, contact, device, seq, fzn_record_issued_at(rec[parts - 1u]),
	                  &p[parts - 1u], body, body_len, parts))
		return FZN_MESSAGES_ERR_BACKEND;
	if (m->items && m->items->add && !m->items->add(m->items->ctx, contact, epoch, item, len))
		return FZN_MESSAGES_ERR_BACKEND;
	held = key_of(m, contact, epoch, device, key);
	memset(key, 0, sizeof(key));
	if (!held && !wait_add(m, contact, epoch, device))
		return FZN_MESSAGES_ERR_BACKEND;
	if (waiting)
		*waiting = !held;
	return FZN_MESSAGES_OK;
}

fzn_messages_err_t fzn_messages_items_backfill(const fzn_messages_t *m, size_t *added)
{
	static uint8_t rbuf[FZN_RECORD_MAX_LEN], item[FZN_MESSAGES_ITEM_MAX];
	size_t d, n = 0;

	if (added)
		*added = 0;
	if (!ready(m) || !m->devices || m->device_count > FZN_MESSAGES_DEVICES_MAX)
		return FZN_MESSAGES_ERR_MALFORMED;
	if (!m->items || !m->items->add || load_number(m, "itemsbf", NOBODY) == 1u)
		return FZN_MESSAGES_OK;
	for (d = 0; d < m->device_count; d++) {
		const uint8_t *device = m->devices[d];
		uint64_t base = fzn_node_journal_base(m->journal, device, FZN_MESSAGE_STREAM);
		uint64_t to = fzn_node_journal_received(m->journal, device, FZN_MESSAGE_STREAM), seq;

		for (seq = base; seq <= to && seq > 0u; seq++) {
			fzn_message_part_t p;
			fzn_record_t r;
			size_t len = 0;

			if (!record_at(m, device, seq, rbuf, sizeof(rbuf), &r))
				return FZN_MESSAGES_ERR_JOURNAL;
			/* A LINE WHOLE IN THE WINDOW: its first part may sit below the
			 * base only if the cut split it, which it never does (sec 548). */
			if (fzn_record_kind(r) != FZN_MESSAGE_LINE_KIND
			    || !fzn_message_line_read(fzn_record_body(r), fzn_record_body_len(r), &p)
			    || p.part + 1u != p.parts || seq < base + p.parts - 1u)
				continue;
			if (is_gone(m, fzn_record_subject(r), p.epoch))
				continue;
			if (!item_from_journal(m, device, seq, p.parts, item, &len))
				return FZN_MESSAGES_ERR_JOURNAL;
			if (!m->items->add(m->items->ctx, fzn_record_subject(r), p.epoch, item, len))
				return FZN_MESSAGES_ERR_BACKEND;
			n++;
		}
	}
	if (!save_number(m, "itemsbf", NOBODY, 1u))
		return FZN_MESSAGES_ERR_BACKEND;
	if (added)
		*added = n;
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

static void see(size_t *n, uint8_t direction, const uint8_t contact[FZN_PUBKEY_LEN],
                const uint8_t id[FZN_MESSAGE_ID_LEN])
{
	seen[*n].direction = direction;
	memcpy(seen[*n].contact, contact, FZN_PUBKEY_LEN);
	memcpy(seen[*n].id, id, FZN_MESSAGE_ID_LEN);
	(*n)++;
}

/* SEARCHED BY ITS INDEX ALONE, which names each line's direction and id: no
 * record is read. */
int fzn_messages_held(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                      uint8_t direction, const uint8_t id[FZN_MESSAGE_ID_LEN])
{
	entry_t e;
	uint64_t i;

	if (!ready(m) || !contact || !id)
		return 0;
	for (i = count_of(m, contact); i > 0u; i--)
		if (index_entry(m, contact, i - 1u, &e) && e.direction == direction
		    && memcmp(e.id, id, FZN_MESSAGE_ID_LEN) == 0)
			return 1;
	return 0;
}

fzn_messages_err_t fzn_messages_unread(const fzn_messages_t *m,
                                       const uint8_t contact[FZN_PUBKEY_LEN], size_t *count,
                                       int *more)
{
	uint8_t read_id[FZN_MESSAGE_ID_LEN];
	entry_t e;
	uint64_t i;
	size_t n_seen = 0;
	int has_read;

	if (!ready(m) || !contact || !count || !more)
		return FZN_MESSAGES_ERR_MALFORMED;
	*count = 0;
	*more = 0;
	has_read = fzn_messages_read_position(m, contact, read_id);
	/* COUNTED FROM THE INDEX, which names each line's direction and id. */
	for (i = count_of(m, contact); i > 0u; i--) {
		if (!index_entry(m, contact, i - 1u, &e))
			continue;
		/* THE READ POSITION ENDS THE COUNT, whichever way its line went. */
		if (has_read && memcmp(e.id, read_id, FZN_MESSAGE_ID_LEN) == 0)
			return FZN_MESSAGES_OK;
		if (seen_before(n_seen, e.direction, contact, e.id))
			continue;
		if (n_seen >= FZN_MESSAGES_WALK_MAX) {
			*more = 1;
			return FZN_MESSAGES_OK;
		}
		see(&n_seen, e.direction, contact, e.id);
		if (e.direction == FZN_MESSAGE_IN)
			(*count)++;
	}
	return FZN_MESSAGES_OK;
}

/* A listing's line, from its stored row. */
static void fill(const fzn_messages_t *m, const stored_t *s, fzn_message_t *o)
{
	memcpy(o->contact, s->contact, FZN_PUBKEY_LEN);
	memcpy(o->device, s->device, FZN_PUBKEY_LEN);
	memcpy(o->id, s->id, FZN_MESSAGE_ID_LEN);
	o->direction = s->direction;
	o->stime = s->stime;
	o->written_at = s->written_at;
	o->state = fzn_messages_state(m, o->contact, o->direction, o->id);
	/* KEPT OPENED or not readable here: a line waiting for its key is a
	 * shell until the key arrives and opens its row. */
	o->readable = s->opened;
	o->text_len = s->opened ? s->text_len : 0u;
	if (o->text_len)
		memcpy(o->text, s->text, o->text_len);
	o->text[o->text_len] = '\0';
}

/* ONE CONVERSATION'S PLACE `i` AS A PAGE'S LINE, unless seen before: 1 shown
 * or skipped, 0 passed over, -1 when the page is full. A line whose row will
 * not read is passed over, as one whose record would not read was. */
static int page_line(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN], uint64_t i,
                     size_t offset, fzn_message_t *out, size_t cap, size_t *count,
                     size_t *n_seen, size_t *skipped)
{
	static uint8_t buf[STORED_MAX];
	stored_t s;
	entry_t e;

	/* THE INDEX DECIDES what is skipped or seen before; a row is read only
	 * for a line the page shows. */
	if (!index_entry(m, contact, i, &e) || seen_before(*n_seen, e.direction, contact, e.id))
		return 0;
	if (*count == cap)
		return -1;
	see(n_seen, e.direction, contact, e.id);
	if (*skipped < offset) {
		(*skipped)++;
		return 1;
	}
	if (!stored_load(m, e.device, e.seq, buf, &s)
	    || memcmp(s.contact, contact, FZN_PUBKEY_LEN) != 0)
		return 0;
	fill(m, &s, &out[(*count)++]);
	return 1;
}

fzn_messages_err_t fzn_messages_page(const fzn_messages_t *m, const uint8_t *contact,
                                     size_t offset, fzn_message_t *out, size_t cap,
                                     size_t *count, int *more)
{
	uint8_t c[FZN_PUBKEY_LEN];
	uint64_t i, k;
	size_t n_seen = 0, skipped = 0;

	if (!ready(m) || !out || !count || !more || !m->devices || m->device_count == 0u
	    || m->device_count > FZN_MESSAGES_DEVICES_MAX || cap > FZN_MESSAGES_PAGE_MAX)
		return FZN_MESSAGES_ERR_MALFORMED;
	if (offset > FZN_MESSAGES_WALK_MAX - cap)
		return FZN_MESSAGES_ERR_DEEP;
	*count = 0;
	*more = 0;
	/* ONE CONVERSATION, from its index; or EVERYONE'S, from every line's
	 * order -- newest first either way, and from the store alone. */
	if (contact) {
		for (i = count_of(m, contact); i > 0u; i--)
			if (page_line(m, contact, i - 1u, offset, out, cap, count, &n_seen, &skipped) < 0) {
				*more = 1;
				break;
			}
		return FZN_MESSAGES_OK;
	}
	for (k = load_number(m, "alls", NOBODY); k > 0u; k--)
		if (all_entry(m, k - 1u, c, &i)
		    && page_line(m, c, i, offset, out, cap, count, &n_seen, &skipped) < 0) {
			*more = 1;
			break;
		}
	return FZN_MESSAGES_OK;
}

/*
 * EVERYTHING DERIVED, FROM NOTHING. A first pass removes what the journal's
 * records name -- each conversation's index, each line's state, each read
 * position -- and every device's cursor; then one absorb from the
 * beginning takes every stream in again, merged in the order the records
 * were written. Listing the rows to clear them would fail past any cap,
 * since nothing bounds them. A row for something the journal holds no
 * record of is not reached, and only a store written by something else
 * could hold one.
 */
fzn_messages_err_t fzn_messages_reindex(const fzn_messages_t *m, size_t *marks)
{
	static uint8_t buf[FZN_RECORD_MAX_LEN];
	uint64_t at[FZN_MESSAGES_DEVICES_MAX];
	size_t d;

	if (!ready(m) || !m->store->remove || !m->devices
	    || m->device_count > FZN_MESSAGES_DEVICES_MAX)
		return FZN_MESSAGES_ERR_MALFORMED;
	/* A STREAM HELD FROM PART WAY, and nothing is cleared: the index is the
	 * only record of the lines below its base. sec 560. */
	for (d = 0; d < m->device_count; d++)
		if (fzn_node_journal_base(m->journal, m->devices[d], FZN_MESSAGE_STREAM) > 1u)
			return FZN_MESSAGES_ERR_WINDOW;
	if (!conversations_clear(m) || !all_clear(m))
		return FZN_MESSAGES_ERR_BACKEND;
	for (d = 0; d < m->device_count; d++) {
		uint64_t seq, held = fzn_node_journal_received(m->journal, m->devices[d],
		                                               FZN_MESSAGE_STREAM);
		uint8_t row[FZN_PUBKEY_LEN];

		for (seq = fzn_node_journal_base(m->journal, m->devices[d], FZN_MESSAGE_STREAM);
		     seq <= held; seq++) {
			fzn_message_mark_t mark;
			fzn_record_t rec;
			const uint8_t *contact;

			if (!record_at(m, m->devices[d], seq, buf, sizeof(buf), &rec))
				return FZN_MESSAGES_ERR_JOURNAL;
			contact = fzn_record_subject(rec);
			if (fzn_record_kind(rec) == FZN_MESSAGE_LINE_KIND) {
				if (!index_clear(m, contact))
					return FZN_MESSAGES_ERR_BACKEND;
			} else if (fzn_record_kind(rec) == FZN_MESSAGE_MARK_KIND
			           && fzn_message_mark_read(fzn_record_body(rec), fzn_record_body_len(rec),
			                                    &mark)) {
				if (!state_row(m, contact, mark.direction, mark.id, row)
				    || !m->store->remove(m->store->ctx, FZN_PERSIST_MESSAGE_STATE, row))
					return FZN_MESSAGES_ERR_BACKEND;
			} else if (fzn_record_kind(rec) == FZN_MESSAGE_READ_KIND) {
				if (!index_row(m, "read", contact, 0u, row)
				    || !m->store->remove(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row))
					return FZN_MESSAGES_ERR_BACKEND;
			}
		}
		if (!index_row(m, "cursor", m->devices[d], 0u, row)
		    || !m->store->remove(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row))
			return FZN_MESSAGES_ERR_BACKEND;
		at[d] = 0u;
	}
	return fzn_messages_absorb(m, at, NULL, NULL, marks);
}

/* The store's layout: 1 once lines are kept in rows (sec 536), 2 once those
 * rows are kept opened (sec 539). */
#define LAYOUT_ROWS 2u

fzn_messages_err_t fzn_messages_upgrade(const fzn_messages_t *m, int *rebuilt)
{
	fzn_messages_err_t err;

	if (!rebuilt)
		return FZN_MESSAGES_ERR_MALFORMED;
	*rebuilt = 0;
	if (!ready(m))
		return FZN_MESSAGES_ERR_MALFORMED;
	if (load_number(m, "layout", NOBODY) >= LAYOUT_ROWS)
		return FZN_MESSAGES_OK;
	err = fzn_messages_reindex(m, NULL);
	if (err != FZN_MESSAGES_OK)
		return err;
	if (!save_number(m, "layout", NOBODY, LAYOUT_ROWS))
		return FZN_MESSAGES_ERR_BACKEND;
	/* A NEW STORE has nothing to rebuild, and says so. */
	*rebuilt = load_number(m, "convs", NOBODY) > 0u;
	return FZN_MESSAGES_OK;
}

/* ---- trimming, by the rules, sec 531 ------------------------------------- */

/* Months one conversation's walk keeps account of; a conversation spanning
 * more has its older months stay, never trimmed for want of room. */
#define TRIM_MONTHS 512u

/* Whether entry `e`, the rule's `counted`th line with `bytes` before it, is
 * within the rule's limit at `now_us`. AGE IS BY THE MONTH: a line is within
 * when any of its month is, so a prune takes only months wholly older, and
 * a keep protects every month it touches. */
static int trim_within(const fzn_retain_rule_t *r, const entry_t *e, uint64_t counted, uint64_t bytes,
                       uint64_t now_us)
{
	uint64_t end_us;

	switch (r->limit) {
	case FZN_RETAIN_AGE:
		end_us = fzn_message_epoch_start(e->epoch + 1u) * 1000u;
		return end_us >= now_us || now_us - end_us <= r->value;
	case FZN_RETAIN_SIZE:
		return bytes < r->value;
	case FZN_RETAIN_COUNT:
		return counted < r->value;
	}
	return 1;
}

fzn_messages_err_t fzn_messages_trim(const fzn_messages_t *m, const fzn_retain_rule_t *rules,
                                     size_t n_rules, uint64_t now_ms,
                                     fzn_messages_trim_tally_t *tally)
{
	static struct {
		uint32_t epoch;
		int stays;
	} months[TRIM_MONTHS];
	uint64_t counted[FZN_RETAIN_RULES_MAX], bytes[FZN_RETAIN_RULES_MAX];
	uint8_t contact[FZN_PUBKEY_LEN];
	uint32_t current;
	uint64_t now_us, n_conv, c;
	size_t r;

	if (!ready(m) || (!rules && n_rules) || n_rules > FZN_RETAIN_RULES_MAX || !tally)
		return FZN_MESSAGES_ERR_MALFORMED;
	memset(tally, 0, sizeof(*tally));
	if (!n_rules)
		return FZN_MESSAGES_OK;
	now_us = now_ms * 1000u;
	current = fzn_message_epoch_of(now_ms);
	n_conv = load_number(m, "convs", NOBODY);
	for (c = 0; c < n_conv; c++) {
		int applies[FZN_RETAIN_RULES_MAX], any = 0, trimmed = 0;
		size_t n_months = 0, k;
		uint64_t i;

		if (!conversation_at(m, c, contact))
			return FZN_MESSAGES_ERR_BACKEND;
		for (r = 0; r < n_rules; r++) {
			applies[r] = rules[r].data == FZN_RETAIN_MESSAGES
			             && (!rules[r].has_contact
			                 || memcmp(rules[r].contact, contact, FZN_PUBKEY_LEN) == 0);
			any |= applies[r];
			counted[r] = bytes[r] = 0u;
		}
		if (!any)
			continue;
		/* NEWEST FIRST: a line goes when a prune rule marks it and no keep
		 * rule protects it, and a MONTH goes when every line of it goes.
		 * Its key is the unit: no part of a month is deleted. */
		for (i = count_of(m, contact); i > 0u; i--) {
			entry_t e;
			int pruned = 0, kept = 0;

			if (!index_entry(m, contact, i - 1u, &e))
				return FZN_MESSAGES_ERR_BACKEND;
			for (r = 0; r < n_rules; r++) {
				int within;

				if (!applies[r])
					continue;
				within = trim_within(&rules[r], &e, counted[r], bytes[r], now_us);
				if (rules[r].kind == FZN_RETAIN_PRUNE && !within)
					pruned = 1;
				if (rules[r].kind == FZN_RETAIN_KEEP && within)
					kept = 1;
				counted[r]++;
				bytes[r] += e.size;
			}
			for (k = 0; k < n_months && months[k].epoch != e.epoch; k++)
				;
			if (k == n_months) {
				if (n_months == TRIM_MONTHS)
					continue;
				months[n_months].epoch = e.epoch;
				months[n_months].stays = 0;
				n_months++;
			}
			if (!pruned || kept)
				months[k].stays = 1;
		}
		/* THE CURRENT MONTH IS NEVER TRIMMED, as a log's open file is never
		 * pruned: its key is the one new lines are sealed under. */
		for (k = 0; k < n_months; k++) {
			fzn_messages_err_t err;

			if (months[k].stays || months[k].epoch >= current
			    || is_gone(m, contact, months[k].epoch))
				continue;
			err = fzn_messages_forget_epoch(m, contact, months[k].epoch);
			if (err != FZN_MESSAGES_OK)
				return err;
			if (!set_gone(m, contact, months[k].epoch))
				return FZN_MESSAGES_ERR_BACKEND;
			tally->months++;
			trimmed = 1;
		}
		tally->conversations += (size_t)trimmed;
	}
	return FZN_MESSAGES_OK;
}
