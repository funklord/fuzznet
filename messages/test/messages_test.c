/* messages_test -- conversations in the journal, sec 526: lines sealed
 * under a key per conversation and month, listed newest first across a
 * user's devices, marked, rebuilt, and trimmed only by a key destroyed on
 * purpose. Real Ed25519, BLAKE2b and XChaCha20-Poly1305 throughout. */

#include "../messages.h"
#include "../../chain/sign_monocypher.h"
#include "../../session/aead_monocypher.h"
#include "../../session/hash_monocypher.h"

#include <monocypher-ed25519.h>
#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;
	failures++;
	fprintf(stderr, "  FAIL messages_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, what)

/* ---- randomness and a clock ------------------------------------------------- */

static uint8_t rng_counter;

static int counter_fill(void *ctx, uint8_t *out, size_t len)
{
	size_t i;

	(void)ctx;
	for (i = 0; i < len; i++)
		out[i] = (uint8_t)(rng_counter++ * 37u + 11u);
	return 1;
}

static const fzn_random_ops_t RNG = { counter_fill, NULL };

/* 2026-10-08 12:00 UTC, which is epoch (2026 - 1970) * 12 + 9 = 681. */
#define OCTOBER_2026 1791460800000ull
static uint64_t clock_ms;

static uint64_t now_ms(void)
{
	return clock_ms += 1000u;
}

/* ---- a persist store in memory ----------------------------------------------- */

#define ROWS 160u

typedef struct row {
	int used;
	fzn_persist_slot_t slot;
	int has_subject;
	uint8_t subject[FZN_PUBKEY_LEN];
	size_t len;
	uint8_t bytes[64];
} row_t;

typedef struct mem {
	row_t rows[ROWS];
} mem_t;

static row_t *find(mem_t *m, fzn_persist_slot_t slot, const uint8_t *subject)
{
	size_t i;

	for (i = 0; i < ROWS; i++)
		if (m->rows[i].used && m->rows[i].slot == slot
		    && m->rows[i].has_subject == (subject != NULL)
		    && (!subject || memcmp(m->rows[i].subject, subject, FZN_PUBKEY_LEN) == 0))
			return &m->rows[i];
	return NULL;
}

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	row_t *r = find((mem_t *)ctx, slot, subject);

	if (!r || r->len > cap)
		return 0;
	memcpy(out, r->bytes, r->len);
	*len = r->len;
	return 1;
}

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	mem_t *m = (mem_t *)ctx;
	row_t *r = find(m, slot, subject);
	size_t i;

	if (len > sizeof(r->bytes))
		return 0;
	for (i = 0; !r && i < ROWS; i++)
		if (!m->rows[i].used)
			r = &m->rows[i];
	if (!r)
		return 0;
	r->used = 1;
	r->slot = slot;
	r->has_subject = subject != NULL;
	if (subject)
		memcpy(r->subject, subject, FZN_PUBKEY_LEN);
	memcpy(r->bytes, bytes, len);
	r->len = len;
	return 1;
}

static int mem_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max, size_t *count)
{
	mem_t *m = (mem_t *)ctx;
	size_t i, n = 0;

	for (i = 0; i < ROWS; i++)
		if (m->rows[i].used && m->rows[i].slot == slot && m->rows[i].has_subject) {
			if (n >= max)
				return 0;
			memcpy(out + (n * FZN_PUBKEY_LEN), m->rows[i].subject, FZN_PUBKEY_LEN);
			n++;
		}
	*count = n;
	return 1;
}

static int mem_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	row_t *r = find((mem_t *)ctx, slot, subject);

	if (r)
		memset(r, 0, sizeof(*r));
	return 1;
}

static size_t rows_in(mem_t *m, fzn_persist_slot_t slot)
{
	size_t i, n = 0;

	for (i = 0; i < ROWS; i++)
		n += m->rows[i].used && m->rows[i].slot == slot;
	return n;
}

/* ---- one record store in memory, shared by both devices' journals ---------- */

#define RECS 96u

static struct rec {
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint32_t stream;
	uint64_t seq;
	size_t len;
	uint8_t bytes[FZN_RECORD_MAX_LEN];
} recs[RECS];
static size_t n_recs;

static int rec_put(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t seq,
                   const uint8_t *bytes, size_t len)
{
	(void)ctx;
	if (n_recs >= RECS)
		return 0;
	memcpy(recs[n_recs].issuer, issuer, FZN_PUBKEY_LEN);
	recs[n_recs].stream = stream;
	recs[n_recs].seq = seq;
	recs[n_recs].len = len;
	memcpy(recs[n_recs].bytes, bytes, len);
	n_recs++;
	return 1;
}

static int rec_get(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t seq,
                   uint8_t *out, size_t cap, size_t *len_out, int *found_out)
{
	size_t i;

	(void)ctx;
	*found_out = 0;
	for (i = 0; i < n_recs; i++)
		if (recs[i].seq == seq && recs[i].stream == stream
		    && memcmp(recs[i].issuer, issuer, FZN_PUBKEY_LEN) == 0) {
			*found_out = 1;
			if (recs[i].len > cap)
				return 0;
			memcpy(out, recs[i].bytes, recs[i].len);
			*len_out = recs[i].len;
			return 1;
		}
	return 1;
}

static fzn_record_store_ops_t rops = { rec_put, rec_get, NULL };

/* ---- two devices of one user, and two contacts ----------------------------- */

typedef struct device {
	fzn_sign_monocypher_t key;
	fzn_sign_ops_t sign;
	uint8_t pub[FZN_PUBKEY_LEN];
	mem_t store;
	fzn_persist_ops_t store_ops;
	fzn_node_journal_t journal;
	fzn_messages_t m;
} device_t;

static device_t A, B;
static fzn_aead_ops_t AEAD;
static fzn_hash_ops_t HASH;
static uint8_t devices[2][FZN_PUBKEY_LEN];
static uint8_t X[FZN_PUBKEY_LEN], Y[FZN_PUBKEY_LEN];

static void device_up(device_t *d, uint8_t seed_byte, size_t device_count)
{
	uint8_t seed[32];

	memset(d, 0, sizeof(*d));
	memset(seed, seed_byte, sizeof(seed));
	crypto_ed25519_key_pair(d->key.secret_key, d->pub, seed);
	d->key.can_sign = 1;
	fzn_sign_monocypher_init(&d->sign, &d->key);
	d->store_ops.load = mem_load;
	d->store_ops.save = mem_save;
	d->store_ops.list = mem_list;
	d->store_ops.remove = mem_remove;
	d->store_ops.ctx = &d->store;
	(void)fzn_node_journal_init_store(&d->journal, &rops, &d->sign, &HASH);
	(void)fzn_node_journal_follow_stream(&d->journal, d->pub, FZN_MESSAGE_STREAM, NULL);
	d->m.store = &d->store_ops;
	d->m.journal = &d->journal;
	d->m.issuer = d->pub;
	d->m.sign = &d->sign;
	d->m.rng = &RNG;
	d->m.aead = &AEAD;
	d->m.hash = &HASH;
	d->m.now = now_ms;
	d->m.devices = (const uint8_t(*)[FZN_PUBKEY_LEN])devices;
	d->m.device_count = device_count;
}

/* Both devices fresh, A listing its own lines only until it follows B. */
static void setup(void)
{
	memset(recs, 0, sizeof(recs));
	n_recs = 0;
	rng_counter = 0;
	clock_ms = OCTOBER_2026;
	device_up(&B, 0x22, 1u);
	device_up(&A, 0x11, 1u);
	memcpy(devices[0], A.pub, FZN_PUBKEY_LEN);
	memcpy(devices[1], B.pub, FZN_PUBKEY_LEN);
	/* B lists B's own stream: its own first. */
	B.m.devices = (const uint8_t(*)[FZN_PUBKEY_LEN])devices[1];
}

static void id_of(uint8_t id[FZN_MESSAGE_ID_LEN], uint8_t n)
{
	memset(id, n, FZN_MESSAGE_ID_LEN);
}

static int write_line(device_t *d, const uint8_t *contact, uint8_t direction, uint8_t n,
                      const char *text)
{
	uint8_t id[FZN_MESSAGE_ID_LEN];

	id_of(id, n);
	return fzn_messages_write(&d->m, contact, direction, id, clock_ms, text, strlen(text))
	       == FZN_MESSAGES_OK;
}

static int mark(device_t *d, const uint8_t *contact, uint8_t direction, uint8_t n,
                uint8_t state)
{
	uint8_t id[FZN_MESSAGE_ID_LEN];

	id_of(id, n);
	return fzn_messages_mark(&d->m, contact, direction, id, state) == FZN_MESSAGES_OK;
}

static fzn_message_t page[FZN_MESSAGES_PAGE_MAX];
static size_t count;
static int more;

static int list(device_t *d, const uint8_t *contact, size_t offset, size_t cap)
{
	return fzn_messages_page(&d->m, contact, offset, page, cap, &count, &more)
	       == FZN_MESSAGES_OK;
}

static int is_line(size_t i, uint8_t n, uint8_t direction, const char *text)
{
	return i < count && page[i].id[0] == n && page[i].direction == direction
	       && page[i].readable && page[i].text_len == strlen(text)
	       && memcmp(page[i].text, text, page[i].text_len) == 0;
}

/* ---- cases ------------------------------------------------------------------- */

static void test_the_epoch(void)
{
	CHECK(fzn_message_epoch_of(0u) == 0u, "January 1970 is epoch 0");
	CHECK(fzn_message_epoch_of(OCTOBER_2026) == 681u, "October 2026 is epoch 681");
	/* 2024-02-29 00:00 and 2025-12-31 23:59:59 UTC. */
	CHECK(fzn_message_epoch_of(1709164800000ull) == 649u, "a leap day is February's");
	CHECK(fzn_message_epoch_of(1767225599000ull) == 671u
	              && fzn_message_epoch_of(1767225600000ull) == 672u,
	      "the last second of a year is December's, the next January's");
}

static void test_the_codec(void)
{
	uint8_t key[FZN_CONVERSATION_KEY_LEN], other[FZN_CONVERSATION_KEY_LEN], nonce[FZN_AEAD_NONCE_LEN];
	uint8_t id[FZN_MESSAGE_ID_LEN], body[FZN_RECORD_BODY_MAX], text[FZN_MESSAGE_TEXT_MAX];
	uint8_t out[FZN_MESSAGE_TEXT_MAX];
	fzn_message_part_t p;
	fzn_message_mark_t mk, back;
	uint8_t mb[FZN_MESSAGE_MARK_LEN];
	size_t len = 0, n = 0;

	memset(key, 0x4b, sizeof(key));
	memset(other, 0x4c, sizeof(other));
	memset(nonce, 0x6e, sizeof(nonce));
	id_of(id, 7u);
	memset(text, 'q', sizeof(text));
	CHECK(fzn_message_parts_for(0u) == 1u && fzn_message_parts_for(FZN_MESSAGE_PART_MAX) == 1u
	              && fzn_message_parts_for(FZN_MESSAGE_PART_MAX + 1u) == 2u
	              && fzn_message_parts_for(FZN_MESSAGE_TEXT_MAX) == 2u
	              && fzn_message_parts_for(FZN_MESSAGE_TEXT_MAX + 1u) == 0u,
	      "a text takes one part to 440 bytes, two to 512, and none past");
	CHECK(fzn_message_line_seal(&AEAD, key, X, FZN_MESSAGE_OUT, id, 5u, 681u, nonce, text, 5u,
	                            0u, 1u, body, &len)
	              && len == FZN_MESSAGE_LINE_HEAD + 5u
	              && memcmp(body + FZN_MESSAGE_LINE_HEAD, text, 5u) != 0
	              && fzn_message_line_read(body, len, &p)
	              && fzn_message_line_open(&AEAD, key, X, &p, out, sizeof(out), &n) && n == 5u
	              && memcmp(out, text, 5u) == 0,
	      "a line seals, reads and opens to its text, which is not in the clear");
	CHECK(!fzn_message_line_open(&AEAD, other, X, &p, out, sizeof(out), &n),
	      "under another key it does not open");
	CHECK(!fzn_message_line_open(&AEAD, key, Y, &p, out, sizeof(out), &n),
	      "nor in another conversation");
	p.direction = FZN_MESSAGE_IN;
	CHECK(!fzn_message_line_open(&AEAD, key, X, &p, out, sizeof(out), &n),
	      "nor with its direction turned round");
	p.direction = FZN_MESSAGE_OUT;
	p.epoch = 680u;
	CHECK(!fzn_message_line_open(&AEAD, key, X, &p, out, sizeof(out), &n),
	      "nor moved to another month");
	CHECK(fzn_message_line_seal(&AEAD, key, X, FZN_MESSAGE_OUT, id, 5u, 681u, nonce, text, 500u,
	                            0u, 2u, body, &len)
	              && len == FZN_RECORD_BODY_MAX,
	      "the first of two parts is full");
	body[FZN_MESSAGE_LINE_OFF_PART] = 1u;
	body[FZN_MESSAGE_LINE_OFF_PARTS] = 1u;
	CHECK(!fzn_message_line_read(body, len, &p), "a second part of a one-part line is refused");
	body[FZN_MESSAGE_LINE_OFF_PART] = 0u;
	body[FZN_MESSAGE_LINE_OFF_PARTS] = 2u;
	CHECK(!fzn_message_line_read(body, len - 1u, &p),
	      "and a first part short of full is two encodings of a line, refused");
	CHECK(!fzn_message_line_seal(&AEAD, key, X, FZN_MESSAGE_OUT, id, 5u, 681u, nonce, text, 5u,
	                             0u, 2u, body, &len),
	      "a part count the text does not take is not sealed");
	mk.direction = FZN_MESSAGE_OUT;
	mk.state = FZN_MESSAGE_NOT_DELIVERED;
	memcpy(mk.id, id, sizeof(id));
	CHECK(fzn_message_mark_write(&mk, mb) && fzn_message_mark_read(mb, sizeof(mb), &back)
	              && memcmp(&back, &mk, sizeof(mk)) == 0,
	      "a mark reads back as written");
	mb[FZN_MESSAGE_MARK_OFF_STATE] = 5u;
	CHECK(!fzn_message_mark_read(mb, sizeof(mb), &back), "an unknown state is refused");
}

static void test_lines_list_newest_first(void)
{
	char longer[501];

	setup();
	memset(longer, 'L', 500u);
	longer[500] = '\0';
	longer[0] = 'S';
	longer[499] = 'E';
	CHECK(write_line(&A, X, FZN_MESSAGE_OUT, 1u, "hello x")
	              && write_line(&A, X, FZN_MESSAGE_IN, 2u, "hi")
	              && write_line(&A, Y, FZN_MESSAGE_OUT, 3u, "hello y")
	              && write_line(&A, X, FZN_MESSAGE_OUT, 4u, longer)
	              && write_line(&A, X, FZN_MESSAGE_IN, 5u, ""),
	      "fixture: five lines, one of them two parts and one empty");
	CHECK(rows_in(&A.store, FZN_PERSIST_CONVERSATION_KEY) == 2u,
	      "one key per conversation for the month, drawn by its first line");
	CHECK(list(&A, X, 0u, FZN_MESSAGES_PAGE_MAX) && count == 4u && !more
	              && is_line(0, 5u, FZN_MESSAGE_IN, "") && is_line(1, 4u, FZN_MESSAGE_OUT, longer)
	              && is_line(2, 2u, FZN_MESSAGE_IN, "hi")
	              && is_line(3, 1u, FZN_MESSAGE_OUT, "hello x"),
	      "x's conversation, newest first, the long line whole and its direction kept");
	CHECK(list(&A, NULL, 0u, 2u) && count == 2u && more && is_line(0, 5u, FZN_MESSAGE_IN, "")
	              && is_line(1, 4u, FZN_MESSAGE_OUT, longer),
	      "everyone's, two to a page, with more to come");
	CHECK(list(&A, NULL, 2u, 2u) && count == 2u && more
	              && is_line(0, 3u, FZN_MESSAGE_OUT, "hello y")
	              && is_line(1, 2u, FZN_MESSAGE_IN, "hi"),
	      "and the next page, the other conversation among them");
	CHECK(list(&A, NULL, 4u, 2u) && count == 1u && !more,
	      "and the last, with nothing after it");
	CHECK(fzn_messages_page(&A.m, NULL, FZN_MESSAGES_WALK_MAX, page, 1u, &count, &more)
	              == FZN_MESSAGES_ERR_DEEP,
	      "a page past the deepest walk is refused, not cut short");
	{
		char too_long[FZN_MESSAGE_TEXT_MAX + 2u];
		uint8_t id[FZN_MESSAGE_ID_LEN];

		memset(too_long, 'x', sizeof(too_long));
		id_of(id, 9u);
		CHECK(fzn_messages_write(&A.m, X, FZN_MESSAGE_OUT, id, 1u, too_long,
		                         FZN_MESSAGE_TEXT_MAX + 1u)
		              == FZN_MESSAGES_ERR_TEXT,
		      "a text past 512 bytes is refused");
	}
}

/* SEC 521: a hand-off given up on stays in the conversation, its text
 * whole, marked not delivered. */
static void test_a_hand_off_given_up_on_stays(void)
{
	setup();
	CHECK(write_line(&A, X, FZN_MESSAGE_OUT, 1u, "via your laptop")
	              && mark(&A, X, FZN_MESSAGE_OUT, 1u, FZN_MESSAGE_HANDED_OVER),
	      "fixture: a message handed to another device, as this device's own line");
	CHECK(list(&A, X, 0u, 5u) && count == 1u && page[0].state == FZN_MESSAGE_HANDED_OVER,
	      "it shows, handed over");
	CHECK(mark(&A, X, FZN_MESSAGE_OUT, 1u, FZN_MESSAGE_NOT_DELIVERED) && list(&A, X, 0u, 5u)
	              && count == 1u && is_line(0, 1u, FZN_MESSAGE_OUT, "via your laptop")
	              && page[0].state == FZN_MESSAGE_NOT_DELIVERED,
	      "given up on, it stays as the user's own line, text whole, not delivered");
}

/* A's journal reopened over the same records, following both devices'
 * streams: what the journal sync leaves A holding. A's store is kept. */
static void sync_a(void)
{
	(void)fzn_node_journal_init_store(&A.journal, &rops, &A.sign, &HASH);
	(void)fzn_node_journal_follow_stream(&A.journal, A.pub, FZN_MESSAGE_STREAM, NULL);
	(void)fzn_node_journal_follow_stream(&A.journal, B.pub, FZN_MESSAGE_STREAM, NULL);
	A.m.device_count = 2u;
}

/* What the key carriage will do, which is not built: B's conversation keys,
 * copied into A's store. */
static void keys_b_to_a(void)
{
	size_t i;

	for (i = 0; i < ROWS; i++)
		if (B.store.rows[i].used && B.store.rows[i].slot == FZN_PERSIST_CONVERSATION_KEY)
			(void)mem_save(&A.store, FZN_PERSIST_CONVERSATION_KEY, B.store.rows[i].subject,
			               B.store.rows[i].bytes, B.store.rows[i].len);
}

/* TWO DEVICES: B's lines reach A's listing once A follows B's stream, as
 * shells until B's keys reach A; a line both wrote is shown once; and the
 * newest mark wins wherever it was made. */
static void test_two_devices(void)
{
	uint8_t one[FZN_MESSAGE_ID_LEN];
	size_t marks = 0;

	id_of(one, 1u);

	setup();
	CHECK(write_line(&A, X, FZN_MESSAGE_OUT, 1u, "from a")
	              && write_line(&B, X, FZN_MESSAGE_IN, 2u, "to b")
	              && write_line(&A, X, FZN_MESSAGE_IN, 2u, "to b")
	              && mark(&A, X, FZN_MESSAGE_OUT, 1u, FZN_MESSAGE_DELIVERED),
	      "fixture: a line each, one received by both, and A's mark");
	sync_a();
	CHECK(list(&A, X, 0u, 5u) && count == 2u && is_line(0, 2u, FZN_MESSAGE_IN, "to b")
	              && is_line(1, 1u, FZN_MESSAGE_OUT, "from a")
	              && page[1].state == FZN_MESSAGE_DELIVERED,
	      "A lists both devices' lines, the one both received once, as A wrote it last");
	CHECK(write_line(&B, X, FZN_MESSAGE_OUT, 7u, "b's own") && list(&A, X, 0u, 5u)
	              && count == 2u,
	      "a line B writes later is not A's until the sync carries it");
	CHECK(mark(&B, X, FZN_MESSAGE_OUT, 1u, FZN_MESSAGE_SETTLED)
	              && fzn_messages_state(&A.m, X, FZN_MESSAGE_OUT, one) == FZN_MESSAGE_DELIVERED,
	      "fixture: B settles A's line, and A has not seen it");
	sync_a();
	CHECK(list(&A, X, 0u, 5u) && count == 3u && page[0].id[0] == 7u && !page[0].readable
	              && page[0].direction == FZN_MESSAGE_OUT,
	      "carried, B's line is listed on A as a shell: B's key has not reached A");
	keys_b_to_a();
	CHECK(fzn_messages_reindex(&A.m, &marks) == FZN_MESSAGES_OK && marks == 2u,
	      "A reindexes both devices' marks");
	CHECK(list(&A, X, 0u, 5u) && count == 3u && is_line(0, 7u, FZN_MESSAGE_OUT, "b's own")
	              && is_line(2, 1u, FZN_MESSAGE_OUT, "from a")
	              && page[2].state == FZN_MESSAGE_SETTLED,
	      "with B's key it opens, and the newest mark, B's, is the line's state on A");
	CHECK(fzn_messages_forget_epoch(&A.m, X, 681u) == FZN_MESSAGES_OK && list(&A, X, 0u, 5u)
	              && count == 3u && !page[0].readable && !page[1].readable && !page[2].readable,
	      "forgetting the month takes both devices' keys for it on A");
}

/* THE NEWEST MARK WINS by when it was written, not by which device's
 * stream a reindex reads first: here the older is B's, read last. */
static void test_the_newest_mark_wins(void)
{
	size_t marks = 0;

	setup();
	CHECK(write_line(&A, X, FZN_MESSAGE_OUT, 1u, "one")
	              && mark(&B, X, FZN_MESSAGE_OUT, 1u, FZN_MESSAGE_DELIVERED)
	              && mark(&A, X, FZN_MESSAGE_OUT, 1u, FZN_MESSAGE_SETTLED),
	      "fixture: B marks the line, then A marks it later");
	sync_a();
	CHECK(fzn_messages_reindex(&A.m, &marks) == FZN_MESSAGES_OK && marks == 2u
	              && list(&A, X, 0u, 5u) && page[0].state == FZN_MESSAGE_SETTLED,
	      "A's later mark is the state, though B's stream is read after A's");
}

static void test_reindex_rebuilds_from_nothing(void)
{
	size_t marks = 0, i;

	setup();
	CHECK(write_line(&A, X, FZN_MESSAGE_OUT, 1u, "one")
	              && mark(&A, X, FZN_MESSAGE_OUT, 1u, FZN_MESSAGE_DELIVERED)
	              && mark(&A, X, FZN_MESSAGE_OUT, 1u, FZN_MESSAGE_SETTLED),
	      "fixture: a line, delivered then settled");
	/* A ROW NEWER THAN ANY MARK, so only clearing it can replace it. */
	for (i = 0; i < ROWS; i++)
		if (A.store.rows[i].used && A.store.rows[i].slot == FZN_PERSIST_MESSAGE_STATE) {
			A.store.rows[i].bytes[0] = FZN_MESSAGE_HANDED_OVER;
			memset(A.store.rows[i].bytes + 1, 0xff, 8u);
		}
	CHECK(list(&A, X, 0u, 5u) && page[0].state == FZN_MESSAGE_HANDED_OVER,
	      "fixture: its state row says something the journal never did, and later");
	CHECK(fzn_messages_reindex(&A.m, &marks) == FZN_MESSAGES_OK && marks == 2u
	              && list(&A, X, 0u, 5u) && page[0].state == FZN_MESSAGE_SETTLED,
	      "a reindex puts back the journal's latest mark");
}

/* NOTHING IS TRIMMED BY DEFAULT; a destroyed month's key leaves shells. */
static void test_a_month_forgotten_leaves_shells(void)
{
	uint32_t september;

	setup();
	clock_ms = OCTOBER_2026 - 31ull * 86400000u;
	september = fzn_message_epoch_of(clock_ms + 1000u);
	CHECK(write_line(&A, X, FZN_MESSAGE_OUT, 1u, "september")
	              && write_line(&A, Y, FZN_MESSAGE_OUT, 2u, "y in september"),
	      "fixture: September's lines");
	clock_ms = OCTOBER_2026;
	CHECK(write_line(&A, X, FZN_MESSAGE_OUT, 3u, "october") && september == 680u
	              && rows_in(&A.store, FZN_PERSIST_CONVERSATION_KEY) == 3u,
	      "and October's, under a key of its own");
	CHECK(fzn_messages_forget_epoch(&A.m, X, september) == FZN_MESSAGES_OK && list(&A, NULL, 0u, 5u)
	              && count == 3u && is_line(0, 3u, FZN_MESSAGE_OUT, "october")
	              && is_line(1, 2u, FZN_MESSAGE_OUT, "y in september") && !page[2].readable
	              && page[2].text_len == 0u && page[2].id[0] == 1u,
	      "forgetting x's September leaves its line listed as a shell, and nothing else");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	check_at(0, __LINE__, "deliberate");
	CHECK(failures == before + 1, "a failure counts");
	failures = before;
	checks -= 1;
}

int main(void)
{
	fzn_aead_monocypher_init(&AEAD);
	fzn_hash_monocypher_init(&HASH);
	memset(X, 0x58, sizeof(X));
	memset(Y, 0x59, sizeof(Y));
	test_the_suite_can_tell_pass_from_fail();
	test_the_epoch();
	test_the_codec();
	test_lines_list_newest_first();
	test_a_hand_off_given_up_on_stays();
	test_two_devices();
	test_the_newest_mark_wins();
	test_reindex_rebuilds_from_nothing();
	test_a_month_forgotten_leaves_shells();
	if (failures) {
		fprintf(stderr, "messages_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("messages_test: all %d checks passed\n", checks);
	return 0;
}
