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
static int set_read(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                    const uint8_t id[FZN_MESSAGE_ID_LEN], uint64_t at);

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
	uint8_t body[FZN_RECORD_BODY_MAX];
	uint64_t now, before;
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
	before = own_head(m);
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
	/* ITS OWN LINE INDEXED NOW, so its conversation lists it without an
	 * absorb between. */
	if (took_own(m, before)
	    && (!index_append(m, contact, m->issuer, own_head(m), direction, id, epoch, len)
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
	return m->store->save(m->store->ctx, FZN_PERSIST_CONVERSATION_KEY, row, key,
	                      FZN_CONVERSATION_KEY_LEN)
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
	 * does not reach, which the next append writes over. */
	return m->store->save(m->store->ctx, FZN_PERSIST_MESSAGE_INDEX, row, chunk,
	                      (in_chunk + 1u) * ENTRY_LEN)
	       && save_number(m, "count", contact, n + 1u);
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
		/* INDEXED, THEN THE CURSOR MOVED, at once: an index entry is the
		 * one thing taken in twice that would show twice. */
		if (fresh
		    && (!index_append(m, contact, device, seq, p.direction, p.id, p.epoch,
		                      p.text_len + (p.parts == 2u ? FZN_MESSAGE_PART_MAX : 0u))
		        || !set_cursor(m, device, seq)))
			return FZN_MESSAGES_ERR_BACKEND;
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

static void see(size_t *n, uint8_t direction, const uint8_t contact[FZN_PUBKEY_LEN],
                const uint8_t id[FZN_MESSAGE_ID_LEN])
{
	seen[*n].direction = direction;
	memcpy(seen[*n].contact, contact, FZN_PUBKEY_LEN);
	memcpy(seen[*n].id, id, FZN_MESSAGE_ID_LEN);
	(*n)++;
}

/* `contact`'s index entry `i` as a line: its last part read from where the
 * entry points. Zero when the entry or the record will not read. */
static int indexed_line(const fzn_messages_t *m, const uint8_t contact[FZN_PUBKEY_LEN],
                        const entry_t *e, fzn_record_t *rec, fzn_message_part_t *p)
{
	static uint8_t buf[FZN_RECORD_MAX_LEN];

	return record_at(m, e->device, e->seq, buf, sizeof(buf), rec)
	       && fzn_record_kind(*rec) == FZN_MESSAGE_LINE_KIND
	       && memcmp(fzn_record_subject(*rec), contact, FZN_PUBKEY_LEN) == 0
	       && fzn_message_line_read(fzn_record_body(*rec), fzn_record_body_len(*rec), p)
	       && p->part + 1u == p->parts;
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

/* Fill a listing's line from its last part. */
static void fill(const fzn_messages_t *m, const uint8_t device[FZN_PUBKEY_LEN], uint64_t seq,
                 fzn_record_t rec, const fzn_message_part_t *p, fzn_message_t *o)
{
	memcpy(o->contact, fzn_record_subject(rec), FZN_PUBKEY_LEN);
	memcpy(o->device, device, FZN_PUBKEY_LEN);
	memcpy(o->id, p->id, FZN_MESSAGE_ID_LEN);
	o->direction = p->direction;
	o->stime = p->stime;
	o->written_at = fzn_record_issued_at(rec);
	o->state = fzn_messages_state(m, o->contact, o->direction, o->id);
	open_text(m, device, seq, p, o);
}

/* ONE CONVERSATION, from its index alone. */
static fzn_messages_err_t page_of(const fzn_messages_t *m, const uint8_t *contact, size_t offset,
                                  fzn_message_t *out, size_t cap, size_t *count, int *more)
{
	fzn_message_part_t p;
	fzn_record_t rec;
	entry_t e;
	uint64_t i;
	size_t n_seen = 0, skipped = 0;

	for (i = count_of(m, contact); i > 0u; i--) {
		/* THE INDEX DECIDES what is skipped or seen before; a record is
		 * read only for a line the page shows. */
		if (!index_entry(m, contact, i - 1u, &e)
		    || seen_before(n_seen, e.direction, contact, e.id))
			continue;
		if (*count == cap) {
			*more = 1;
			return FZN_MESSAGES_OK;
		}
		see(&n_seen, e.direction, contact, e.id);
		if (skipped < offset) {
			skipped++;
			continue;
		}
		if (!indexed_line(m, contact, &e, &rec, &p))
			continue;
		fill(m, e.device, e.seq, rec, &p, &out[(*count)++]);
	}
	return FZN_MESSAGES_OK;
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
	if (contact)
		return page_of(m, contact, offset, out, cap, count, more);
	for (d = 0; d < m->device_count; d++) {
		at[d] = fzn_node_journal_received(m->journal, m->devices[d], FZN_MESSAGE_STREAM);
		loaded[d] = 0;
	}
	/* EVERYONE'S, NEWEST FIRST ACROSS THE DEVICES: each step takes the newest
	 * of every stream's next record back, so lines interleave as they were
	 * written. */
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
		    || !fzn_message_line_read(fzn_record_body(rec), fzn_record_body_len(rec), &p)
		    || p.part + 1u != p.parts
		    || seen_before(n_seen, p.direction, fzn_record_subject(rec), p.id))
			continue;
		if (*count == cap) {
			*more = 1;
			return FZN_MESSAGES_OK;
		}
		see(&n_seen, p.direction, fzn_record_subject(rec), p.id);
		if (skipped < offset) {
			skipped++;
			continue;
		}
		fill(m, m->devices[best], seq, rec, &p, &out[(*count)++]);
	}
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
	if (!conversations_clear(m))
		return FZN_MESSAGES_ERR_BACKEND;
	for (d = 0; d < m->device_count; d++) {
		uint64_t seq, held = fzn_node_journal_received(m->journal, m->devices[d],
		                                               FZN_MESSAGE_STREAM);
		uint8_t row[FZN_PUBKEY_LEN];

		for (seq = 1u; seq <= held; seq++) {
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
