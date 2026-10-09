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

#define ROWS 384u

typedef struct row {
	int used;
	fzn_persist_slot_t slot;
	int has_subject;
	uint8_t subject[FZN_PUBKEY_LEN];
	size_t len;
	uint8_t bytes[1280];
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

/* Line rows removed, for a trim that must remove before it saves. */
static size_t line_removes;

static int mem_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	row_t *r = find((mem_t *)ctx, slot, subject);

	line_removes += slot == FZN_PERSIST_MESSAGE_LINE && r != NULL;

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

#define RECS 160u

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

/* Every record read, for a listing that must read one conversation only. */
static size_t rec_reads;

static int rec_get(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t seq,
                   uint8_t *out, size_t cap, size_t *len_out, int *found_out)
{
	size_t i;

	(void)ctx;
	rec_reads++;
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

static fzn_record_store_ops_t rops = { rec_put, rec_get, NULL, NULL };

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
	/* From `date -u -d 2026-10-01 +%s` and `-d 2000-03-01`: not from the
	 * code under test, which the trim's fixtures also use. */
	CHECK(fzn_message_epoch_start(681u) == 1790812800000ull
	              && fzn_message_epoch_start(362u) == 951868800000ull,
	      "a month starts at its first millisecond, past a leap February of a 400th year");
	{
		uint32_t e;
		int all = 1;

		for (e = 1u; e < 2400u; e++)
			all = all && fzn_message_epoch_of(fzn_message_epoch_start(e)) == e
			      && fzn_message_epoch_of(fzn_message_epoch_start(e) - 1u) == e - 1u;
		CHECK(all, "and every month's start is its own, the millisecond before the last's");
	}
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
/* A `seen` that counts what it is told. */
static void count_seen(void *ctx, const uint8_t contact[FZN_PUBKEY_LEN], uint32_t epoch,
                       const uint8_t device[FZN_PUBKEY_LEN], int held)
{
	(void)contact;
	(void)epoch;
	(void)device;
	(void)held;
	(*(size_t *)ctx)++;
}

static void sync_a(void)
{
	uint64_t at[2] = { 0u, 0u };

	(void)fzn_node_journal_init_store(&A.journal, &rops, &A.sign, &HASH);
	(void)fzn_node_journal_follow_stream(&A.journal, A.pub, FZN_MESSAGE_STREAM, NULL);
	(void)fzn_node_journal_follow_stream(&A.journal, B.pub, FZN_MESSAGE_STREAM, NULL);
	A.m.device_count = 2u;
	/* AND TAKEN IN, as the daemon does after a pull: from the beginning
	 * here, which takes in only what A had not. */
	(void)fzn_messages_absorb(&A.m, at, NULL, NULL, NULL);
}

/* What the key carriage will do, which is not built: B's conversation keys,
 * copied into A's store. */
/* B's keys given to A as node/messages carries them, through
 * `fzn_messages_key_take`, which opens A's rows that waited for them: every
 * key B holds for x and y in the months the cases write in. */
static void keys_b_to_a(void)
{
	uint8_t key[FZN_CONVERSATION_KEY_LEN];
	const uint8_t *contacts[2] = { X, Y };
	uint32_t epoch;
	size_t c;

	for (c = 0; c < 2u; c++)
		for (epoch = 676u; epoch <= 682u; epoch++)
			if (fzn_messages_key_get(&B.m, contacts[c], epoch, B.pub, key))
				(void)fzn_messages_key_take(&A.m, contacts[c], epoch, B.pub, key);
	memset(key, 0, sizeof(key));
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

/* A WINDOW IS NOT REBUILT FROM, sec 560: A's stream held from part way --
 * here its base moved past the first record -- and a reindex refuses before
 * clearing anything, both lines still listed; while the base is the start
 * the same reindex runs. */
static void test_no_reindex_from_a_window(void)
{
	size_t marks = 0;

	setup();
	CHECK(write_line(&A, X, FZN_MESSAGE_OUT, 1u, "one")
	              && write_line(&A, X, FZN_MESSAGE_OUT, 2u, "two") && list(&A, X, 0u, 5u)
	              && count == 2u,
	      "fixture: A writes two lines");
	A.journal.keep = &A.store_ops;
	CHECK(fzn_messages_reindex(&A.m, &marks) == FZN_MESSAGES_OK && list(&A, X, 0u, 5u)
	              && count == 2u,
	      "a reindex over a whole journal did not run");
	CHECK(fzn_node_journal_base_set(&A.journal, A.pub, FZN_MESSAGE_STREAM, 2u)
	                      == FZN_NODE_JOURNAL_OK
	              && fzn_messages_reindex(&A.m, &marks) == FZN_MESSAGES_ERR_WINDOW
	              && list(&A, X, 0u, 5u) && count == 2u,
	      "a reindex over a window ran, or cleared the index before refusing");
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

/* FROM THE STORE ALONE, sec 536: a page of x's lines, and a page of
 * everyone's, read no journal record at all -- the rows and the index are
 * enough. */
static void test_one_conversation_reads_only_its_own(void)
{
	size_t i;

	setup();
	CHECK(write_line(&A, X, FZN_MESSAGE_OUT, 1u, "x one"), "fixture: x's first line");
	for (i = 0; i < 30u; i++)
		CHECK(write_line(&A, Y, FZN_MESSAGE_IN, (uint8_t)(40u + i), "y"), "fixture: y's lines");
	CHECK(write_line(&A, X, FZN_MESSAGE_IN, 2u, "x two"), "fixture: x's second line");
	rec_reads = 0;
	CHECK(list(&A, X, 0u, 5u) && count == 2u && !more && is_line(0, 2u, FZN_MESSAGE_IN, "x two")
	              && is_line(1, 1u, FZN_MESSAGE_OUT, "x one"),
	      "x's page holds x's two lines, newest first");
	CHECK(rec_reads == 0u, "and read no record, x's or y's thirty");
	CHECK(list(&A, NULL, 0u, 5u) && count == 5u && more && is_line(0, 2u, FZN_MESSAGE_IN, "x two")
	              && rec_reads == 0u,
	      "everyone's page too: newest first, from the store, no record read");
}

/* IMPORT, deduplicated by id and direction, by any device. */
static void test_import_keeps_a_line_once(void)
{
	uint8_t id[FZN_MESSAGE_ID_LEN];
	int written = -1;

	setup();
	id_of(id, 5u);
	CHECK(write_line(&B, X, FZN_MESSAGE_IN, 5u, "held on b"), "fixture: B holds a line");
	sync_a();
	CHECK(fzn_messages_held(&A.m, X, FZN_MESSAGE_IN, id), "absorbed, A holds it");
	CHECK(fzn_messages_import(&A.m, X, FZN_MESSAGE_IN, id, 1u, "held on b", 9u, &written)
	                      == FZN_MESSAGES_OK
	              && written == 0,
	      "importing it on A writes nothing");
	CHECK(fzn_messages_import(&A.m, X, FZN_MESSAGE_OUT, id, 1u, "the reply", 9u, &written)
	                      == FZN_MESSAGES_OK
	              && written == 1,
	      "the same id the other way is another line, and is written");
	id_of(id, 6u);
	CHECK(fzn_messages_import(&A.m, X, FZN_MESSAGE_IN, id, 1u, "new", 3u, &written)
	                      == FZN_MESSAGES_OK
	              && written == 1
	              && fzn_messages_import(&A.m, X, FZN_MESSAGE_IN, id, 1u, "new", 3u, &written)
	                         == FZN_MESSAGES_OK
	              && written == 0,
	      "a new one is written, and importing it twice writes it once");
}

/* READ STATE: a position per conversation, the newest wins wherever it was
 * written, and unread counts the IN lines above it. */
static void test_read_state_travels(void)
{
	uint8_t id[FZN_MESSAGE_ID_LEN];
	size_t unread = 99u;
	int beyond = 1;

	setup();
	CHECK(write_line(&A, X, FZN_MESSAGE_IN, 1u, "one") && write_line(&A, X, FZN_MESSAGE_IN, 2u, "two")
	              && write_line(&A, X, FZN_MESSAGE_OUT, 3u, "mine")
	              && write_line(&A, X, FZN_MESSAGE_IN, 4u, "three"),
	      "fixture: three lines in, one out");
	CHECK(fzn_messages_unread(&A.m, X, &unread, &beyond) == FZN_MESSAGES_OK && unread == 3u && !beyond,
	      "nothing read: three unread, the line out not among them");
	id_of(id, 2u);
	CHECK(fzn_messages_read_up_to(&A.m, X, id) == FZN_MESSAGES_OK
	              && fzn_messages_unread(&A.m, X, &unread, &beyond) == FZN_MESSAGES_OK && unread == 1u,
	      "read up to the second: one unread above it");
	id_of(id, 4u);
	sync_a();
	CHECK(fzn_messages_read_up_to(&B.m, X, id) == FZN_MESSAGES_OK, "fixture: B reads to the last");
	sync_a();
	CHECK(fzn_messages_read_position(&A.m, X, id) && id[0] == 4u
	              && fzn_messages_unread(&A.m, X, &unread, &beyond) == FZN_MESSAGES_OK && unread == 0u,
	      "read on B, carried and absorbed: nothing unread on A");
	id_of(id, 2u);
	CHECK(fzn_messages_read_up_to(&A.m, X, id) == FZN_MESSAGES_OK
	              && fzn_messages_read_position(&A.m, X, id) && id[0] == 2u,
	      "and a later read on A, though further back, is the newest and stands");
	/* AN OLDER READ ARRIVING LATER does not move it. */
	id_of(id, 1u);
	CHECK(fzn_messages_read_up_to(&B.m, X, id) == FZN_MESSAGES_OK, "fixture: B reads to the first");
	id_of(id, 3u);
	CHECK(fzn_messages_read_up_to(&A.m, X, id) == FZN_MESSAGES_OK,
	      "fixture: then A, later, to the third");
	sync_a();
	CHECK(fzn_messages_read_position(&A.m, X, id) && id[0] == 3u,
	      "B's read, absorbed after A's newer one, does not replace it");
}

/* THE ORDER A REBUILD GIVES is the order the lines were written, whichever
 * device wrote them; and taking a stream in again from the beginning adds
 * nothing. */
static void test_reindex_orders_by_writing(void)
{
	size_t marks = 0, before;
	uint64_t at[2] = { 0u, 0u };

	setup();
	CHECK(write_line(&A, X, FZN_MESSAGE_OUT, 1u, "a1") && write_line(&B, X, FZN_MESSAGE_IN, 2u, "b2")
	              && write_line(&A, X, FZN_MESSAGE_OUT, 3u, "a3")
	              && write_line(&B, X, FZN_MESSAGE_IN, 4u, "b4"),
	      "fixture: A and B write in turn");
	sync_a();
	keys_b_to_a();
	CHECK(fzn_messages_reindex(&A.m, &marks) == FZN_MESSAGES_OK && list(&A, X, 0u, 5u)
	              && count == 4u && is_line(0, 4u, FZN_MESSAGE_IN, "b4")
	              && is_line(1, 3u, FZN_MESSAGE_OUT, "a3") && is_line(2, 2u, FZN_MESSAGE_IN, "b2")
	              && is_line(3, 1u, FZN_MESSAGE_OUT, "a1"),
	      "rebuilt, the conversation lists as it was written");
	CHECK(mark(&B, X, FZN_MESSAGE_IN, 2u, FZN_MESSAGE_DELIVERED), "fixture: B marks a line");
	sync_a();
	before = rows_in(&A.store, FZN_PERSIST_MESSAGE_INDEX);
	/* A MARK TAKEN IN AGAIN is what a cursor ignored would show: index
	 * entries are also kept once by the recent-entries check, marks not. */
	CHECK(fzn_messages_absorb(&A.m, at, NULL, NULL, &marks) == FZN_MESSAGES_OK && marks == 0u
	              && rows_in(&A.store, FZN_PERSIST_MESSAGE_INDEX) == before && list(&A, X, 0u, 5u)
	              && count == 4u,
	      "and an absorb from the beginning again takes nothing in twice");
}

/* THE SAME LINE FROM TWO DEVICES, FAR APART, sec 575: A writes a line and
 * seventy more; B writes the same line, outside the 64 a look back would
 * reach. Taken in, it is kept once -- and a rebuilt index, its marks
 * cleared with it, keeps it once again. */
static void test_the_same_line_far_apart(void)
{
	size_t marks = 0, rows;
	uint8_t n;
	int all = 1;

	setup();
	all &= write_line(&A, X, FZN_MESSAGE_IN, 1u, "the line");
	for (n = 2u; n < 72u; n++)
		all &= write_line(&A, X, FZN_MESSAGE_OUT, n, "filler");
	all &= write_line(&B, X, FZN_MESSAGE_IN, 1u, "the line");
	CHECK(all, "fixture: A's line and seventy after it, then B's copy of the first");
	rows = rows_in(&A.store, FZN_PERSIST_MESSAGE_LINE);
	sync_a();
	CHECK(rows == 71u && rows_in(&A.store, FZN_PERSIST_MESSAGE_LINE) == 71u,
	      "B's copy of a line A wrote seventy lines before was kept again");
	CHECK(fzn_messages_reindex(&A.m, &marks) == FZN_MESSAGES_OK
	              && list(&A, X, 0u, FZN_MESSAGES_PAGE_MAX) && more,
	      "a rebuilt index lists nothing, its marks left behind");
	{
		size_t total = 0, offset = 0, ones = 0, i;

		/* EVERY PAGE, counting the line's copies. */
		while (offset < 80u && list(&A, X, offset, FZN_MESSAGES_PAGE_MAX) && count) {
			for (i = 0; i < count; i++)
				ones += page[i].id[0] == 1u && page[i].direction == FZN_MESSAGE_IN;
			total += count;
			offset += count;
			if (!more)
				break;
		}
		CHECK(total == 71u && ones == 1u, "the rebuilt index does not list the line once");
	}
}

/* A STORE FROM BEFORE MARKS, sec 575: its lines marked once, by the
 * upgrade. Made here by taking one line's mark and the pass's own flag out
 * of a store, their rows found as the store finds them. */
static int index_row_of(const char *what, const uint8_t key[FZN_PUBKEY_LEN], uint8_t row[32])
{
	static const char DOMAIN[] = "fuzznet.message.";
	uint8_t in[sizeof(DOMAIN) - 1u + 8u + FZN_PUBKEY_LEN + 4u];
	size_t at = sizeof(DOMAIN) - 1u;

	memset(in, 0, sizeof(in));
	memcpy(in, DOMAIN, at);
	memcpy(in + at, what, strlen(what));
	memcpy(in + at + 8u, key, FZN_PUBKEY_LEN);
	return HASH.hash(HASH.ctx, row, 32u, in, sizeof(in));
}

static void test_lines_from_before_marks(void)
{
	static const char DOMAIN[] = "fuzznet.message.lineid";
	uint8_t in[sizeof(DOMAIN) - 1u + FZN_PUBKEY_LEN + 1u + FZN_MESSAGE_ID_LEN];
	uint8_t key[FZN_PUBKEY_LEN], row[32], nobody[FZN_PUBKEY_LEN], id[FZN_MESSAGE_ID_LEN];
	int rebuilt = 0, all = 1;
	uint8_t n;

	setup();
	all &= write_line(&A, X, FZN_MESSAGE_IN, 1u, "the line");
	for (n = 2u; n < 72u; n++)
		all &= write_line(&A, X, FZN_MESSAGE_OUT, n, "filler");
	all &= fzn_messages_upgrade(&A.m, &rebuilt) == FZN_MESSAGES_OK;
	/* LINE 1's MARK AND THE PASS'S FLAG, taken out. */
	id_of(id, 1u);
	memcpy(in, DOMAIN, sizeof(DOMAIN) - 1u);
	memcpy(in + sizeof(DOMAIN) - 1u, X, FZN_PUBKEY_LEN);
	in[sizeof(DOMAIN) - 1u + FZN_PUBKEY_LEN] = FZN_MESSAGE_IN;
	memcpy(in + sizeof(DOMAIN) - 1u + FZN_PUBKEY_LEN + 1u, id, FZN_MESSAGE_ID_LEN);
	memset(nobody, 0, sizeof(nobody));
	/* EACH FOUND BEFORE IT IS TAKEN: a key derived wrong would take nothing,
	 * and the case would pass over a mark still there. */
	{
		uint8_t b[16];
		size_t len = 0;

		all &= HASH.hash(HASH.ctx, key, sizeof(key), in, sizeof(in))
		       && index_row_of("lineid", key, row)
		       && mem_load(&A.store, FZN_PERSIST_MESSAGE_INDEX, row, b, sizeof(b), &len)
		       && len == 1u && mem_remove(&A.store, FZN_PERSIST_MESSAGE_INDEX, row)
		       && index_row_of("lineids", nobody, row)
		       && mem_load(&A.store, FZN_PERSIST_MESSAGE_INDEX, row, b, sizeof(b), &len)
		       && len == 8u && mem_remove(&A.store, FZN_PERSIST_MESSAGE_INDEX, row);
	}
	CHECK(all, "fixture: a store whose first line has no mark, as before marks");
	CHECK(fzn_messages_upgrade(&A.m, &rebuilt) == FZN_MESSAGES_OK,
	      "the upgrade refused a store from before marks");
	CHECK(write_line(&B, X, FZN_MESSAGE_IN, 1u, "the line"), "fixture: B's copy of the first");
	sync_a();
	CHECK(rows_in(&A.store, FZN_PERSIST_MESSAGE_LINE) == 71u,
	      "a line indexed before marks was kept again from another device");
}

/* ---- trimming by the rules, sec 531 ------------------------------------------ */

/* A line written on the tenth of month `epoch` (678 July 2026 .. 681
 * October). */
static int write_in(device_t *d, uint32_t epoch, const uint8_t *contact, uint8_t n,
                    const char *text)
{
	clock_ms = fzn_message_epoch_start(epoch) + 9ull * 86400000u;
	return write_line(d, contact, FZN_MESSAGE_OUT, n, text);
}

static fzn_retain_rule_t rule_of(const char *line)
{
	fzn_retain_rule_t r;

	if (fzn_retain_parse(line, strlen(line), &r) != FZN_RETAIN_OK)
		memset(&r, 0, sizeof(r));
	return r;
}

/* Whether line `n` with `contact` reads, -1 when it is not listed. */
static int readable(device_t *d, const uint8_t *contact, uint8_t n)
{
	size_t i;

	if (!list(d, contact, 0u, FZN_MESSAGES_PAGE_MAX))
		return -1;
	for (i = 0; i < count; i++)
		if (page[i].id[0] == n)
			return page[i].readable;
	return -1;
}

static fzn_messages_trim_tally_t trimmed;

static int trim(device_t *d, const fzn_retain_rule_t *rules, size_t n)
{
	return fzn_messages_trim(&d->m, rules, n, OCTOBER_2026, &trimmed) == FZN_MESSAGES_OK;
}

static void test_trimming_by_age(void)
{
	fzn_retain_rule_t r;
	size_t marks;
	uint8_t key[FZN_CONVERSATION_KEY_LEN];

	setup();
	CHECK(write_in(&A, 678u, X, 1u, "july") && write_in(&A, 679u, X, 2u, "august")
	              && write_in(&A, 680u, X, 3u, "september") && write_in(&A, 681u, X, 4u, "october")
	              && write_in(&A, 678u, Y, 5u, "y in july"),
	      "fixture: x's lines from July to October, and one of y's in July");
	CHECK(trim(&A, NULL, 0u) && trimmed.months == 0u && readable(&A, X, 1u) == 1,
	      "no rule trims nothing");
	r = rule_of("prune messages age 60d");
	CHECK(trim(&A, &r, 1u) && trimmed.months == 2u && trimmed.conversations == 2u,
	      "older than 60 days by the month: July, of both conversations");
	CHECK(readable(&A, X, 1u) == 0 && readable(&A, X, 2u) == 1 && readable(&A, Y, 5u) == 0,
	      "July's lines are shells, listed, and August's read: it ended within 60 days");
	CHECK(trim(&A, &r, 1u) && trimmed.months == 0u, "trimming again finds nothing more");
	memset(key, 0x77, sizeof(key));
	CHECK(fzn_messages_key_take(&A.m, X, 678u, A.pub, key) == FZN_MESSAGES_ERR_GONE,
	      "and a trimmed month takes no key back");
	r = rule_of("prune messages age 0d");
	CHECK(trim(&A, &r, 1u) && readable(&A, X, 4u) == 1,
	      "the current month is never trimmed, whatever the rule");
	CHECK(fzn_messages_reindex(&A.m, &marks) == FZN_MESSAGES_OK
	              && fzn_messages_key_take(&A.m, X, 679u, A.pub, key) == FZN_MESSAGES_ERR_GONE,
	      "a rebuilt index keeps what was trimmed: a tombstone is not derived");
	r = rule_of("prune messages age 0d");
	CHECK(trim(&A, &r, 1u) && trimmed.months == 0u && readable(&A, X, 4u) == 1,
	      "and after it, nothing comes back to be trimmed twice");
}

static void test_trimming_by_count_with_a_keep(void)
{
	fzn_retain_rule_t r[2];
	char line[160];

	setup();
	CHECK(write_in(&A, 678u, X, 1u, "july") && write_in(&A, 679u, X, 2u, "august")
	              && write_in(&A, 680u, X, 3u, "september") && write_in(&A, 681u, X, 4u, "october")
	              && write_in(&A, 678u, Y, 5u, "y in july") && write_in(&A, 679u, Y, 6u, "y in august"),
	      "fixture: x from July to October, y in July and August");
	snprintf(line, sizeof(line), "prune messages contact=%s count 1",
	         "5858585858585858585858585858585858585858585858585858585858585858");
	r[0] = rule_of(line);
	r[1] = rule_of("keep messages age 50d");
	CHECK(trim(&A, r, 2u) && trimmed.months == 1u && readable(&A, X, 1u) == 0
	              && readable(&A, X, 2u) == 1 && readable(&A, X, 3u) == 1,
	      "past x's newest line, kept within 50 days: only July goes");
	CHECK(readable(&A, Y, 5u) == 1, "and a rule for x does not touch y, past whose newest July is");
	CHECK(trim(&A, r, 1u) && trimmed.months == 2u && readable(&A, X, 2u) == 0
	              && readable(&A, X, 3u) == 0 && readable(&A, X, 4u) == 1,
	      "without the keep, August and September go too, October being current");
}

/* THE CURRENT MONTH STAYS even when every line of it is past a rule: a line
 * dated earlier can be written after it, from an import or a clock set
 * back, and push it out of a count. */
static void test_the_current_month_stays(void)
{
	fzn_retain_rule_t r;

	setup();
	CHECK(write_in(&A, 681u, X, 4u, "october") && write_in(&A, 680u, X, 3u, "september, after"),
	      "fixture: October's line written, then September's");
	clock_ms = OCTOBER_2026;
	r = rule_of("prune messages count 1");
	CHECK(trim(&A, &r, 1u) && trimmed.months == 0u && readable(&A, X, 4u) == 1
	              && readable(&A, X, 3u) == 1,
	      "past the count, October stays: it is the month new lines are sealed under");
}

static void test_trimming_by_size(void)
{
	fzn_retain_rule_t r;

	setup();
	CHECK(write_in(&A, 679u, X, 2u, "cccccc") && write_in(&A, 680u, X, 3u, "bbbbbb")
	              && write_in(&A, 681u, X, 4u, "aaaaaa"),
	      "fixture: six bytes a month, August to October");
	r = rule_of("prune messages size 10");
	CHECK(trim(&A, &r, 1u) && trimmed.months == 1u && readable(&A, X, 3u) == 1
	              && readable(&A, X, 2u) == 0,
	      "the newest ten bytes reach into September, which stays; August goes");
}

/* A DEFAULT POLICY, sec 566: under drop only a keep rule holds a month,
 * and keep wins over drop. */
static void test_trimming_under_a_policy(void)
{
	fzn_retain_rule_t r[2];

	setup();
	CHECK(write_in(&A, 678u, X, 1u, "july") && write_in(&A, 679u, X, 2u, "august")
	              && write_in(&A, 680u, X, 3u, "september") && write_in(&A, 681u, X, 4u, "october")
	              && write_in(&A, 678u, Y, 5u, "y in july"),
	      "fixture: x from July to October, y in July");
	r[0] = rule_of("policy messages drop");
	r[1] = rule_of("policy messages keep");
	CHECK(trim(&A, r, 2u) && trimmed.months == 0u,
	      "a keep policy beside a drop one trims nothing: keep wins");
	r[1] = rule_of("keep messages age 50d");
	CHECK(trim(&A, r, 2u) && trimmed.months == 2u && readable(&A, X, 1u) == 0
	              && readable(&A, Y, 5u) == 0 && readable(&A, X, 2u) == 1,
	      "under drop, a keep of 50 days holds August on, and July goes from both");
	CHECK(trim(&A, r, 1u) && trimmed.months == 2u && readable(&A, X, 3u) == 0
	              && readable(&A, X, 4u) == 1,
	      "under drop alone every month goes but the current one");
}

/* WHAT A RECONCILER ASKS BEFORE FETCHING A MONTH, sec 566: whether the
 * trim would hold it, were it here. */
static void test_a_month_wanted(void)
{
	fzn_retain_rule_t r[2];
	int wanted = -1;

	setup();
	CHECK(write_in(&A, 678u, X, 1u, "july") && write_in(&A, 679u, X, 2u, "august")
	              && write_in(&A, 680u, X, 3u, "september") && write_in(&A, 681u, X, 4u, "october"),
	      "fixture: x from July to October");
#define WANTED(rules, n, epoch)                                                                    \
	(fzn_messages_wanted(&A.m, (rules), (n), OCTOBER_2026, X, (epoch), &wanted)                \
	         == FZN_MESSAGES_OK                                                                \
	 ? wanted                                                                                  \
	 : -1)
	CHECK(WANTED(NULL, 0u, 677u) == 1, "with no rule, June is wanted");
	r[0] = rule_of("policy messages drop");
	CHECK(WANTED(r, 1u, 677u) == 0 && WANTED(r, 1u, 681u) == 1,
	      "under drop alone June is not, and the current month is");
	r[1] = rule_of("keep messages age 50d");
	CHECK(WANTED(r, 2u, 677u) == 0 && WANTED(r, 2u, 679u) == 1,
	      "under drop with a keep of 50 days, August is and June is not");
	r[0] = rule_of("prune messages count 4");
	CHECK(WANTED(r, 1u, 677u) == 0 && WANTED(r, 1u, 679u) == 1,
	      "past the newest four lines held, June is not wanted; August, with two newer, is");
	r[0] = rule_of("prune messages age 60d");
	CHECK(trim(&A, r, 1u) && trimmed.months == 1u && WANTED(NULL, 0u, 678u) == 0,
	      "a month trimmed here is not wanted, whatever the rules");
#undef WANTED
}

/* EVERY DEVICE'S KEY FOR THE MONTH goes, and a trimmed month's lines are not
 * reported to whoever would ask for or give their keys. */
static void test_a_trim_reaches_every_device_key(void)
{
	fzn_retain_rule_t r;
	uint64_t at[2] = { 0u, 0u };
	size_t reported = 0;

	setup();
	CHECK(write_in(&B, 678u, X, 1u, "b in july"), "fixture: B writes in July");
	clock_ms = OCTOBER_2026;
	sync_a();
	keys_b_to_a();
	CHECK(readable(&A, X, 1u) == 1, "fixture: A reads B's July line");
	r = rule_of("prune messages age 30d");
	CHECK(trim(&A, &r, 1u) && trimmed.months == 1u && readable(&A, X, 1u) == 0,
	      "trimmed on A, B's key for July is gone from A too");
	CHECK(fzn_messages_absorb(&A.m, at, count_seen, &reported, NULL) == FZN_MESSAGES_OK
	              && reported == 0u,
	      "and its line is reported to no one, so its key is never asked for again");
}

/* ---- the store keeps the lines, sec 536 ---------------------------------------- */

/* A row's head alone, `line.situ`'s fzn_message_stored with neither text
 * nor parts. */
#define STORED_HEAD_LEN 115u

/* Whether any line row holds `text` in the clear. */
static int rows_hold(device_t *d, const char *text)
{
	size_t i, j, n = strlen(text);

	for (i = 0; i < ROWS; i++)
		if (d->store.rows[i].used && d->store.rows[i].slot == FZN_PERSIST_MESSAGE_LINE)
			for (j = 0; j + n <= d->store.rows[i].len; j++)
				if (memcmp(d->store.rows[i].bytes + j, text, n) == 0)
					return 1;
	return 0;
}

/* Every conversation key gone from `d`'s store. */
static void keys_gone(device_t *d)
{
	size_t i;

	for (i = 0; i < ROWS; i++)
		if (d->store.rows[i].used && d->store.rows[i].slot == FZN_PERSIST_CONVERSATION_KEY)
			memset(&d->store.rows[i], 0, sizeof(d->store.rows[i]));
}

/* Rows of the line slot, and of them those holding a head alone. */
static size_t line_rows(device_t *d, size_t *heads_only)
{
	size_t i, n = 0;

	*heads_only = 0;
	for (i = 0; i < ROWS; i++)
		if (d->store.rows[i].used && d->store.rows[i].slot == FZN_PERSIST_MESSAGE_LINE) {
			n++;
			*heads_only += d->store.rows[i].len == STORED_HEAD_LEN;
		}
	return n;
}

/* THE JOURNAL LET GO: every record gone, as a window cut past them would. */
static void journal_cut(void)
{
	memset(recs, 0, sizeof(recs));
	n_recs = 0;
}

static void test_the_store_outlives_the_journal(void)
{
	char long_text[FZN_MESSAGE_TEXT_MAX + 1u];
	size_t heads = 9;

	setup();
	memset(long_text, 'w', FZN_MESSAGE_TEXT_MAX);
	long_text[FZN_MESSAGE_TEXT_MAX] = '\0';
	CHECK(write_line(&A, X, FZN_MESSAGE_OUT, 1u, "a short one")
	              && write_line(&B, X, FZN_MESSAGE_IN, 2u, long_text),
	      "fixture: A writes a line, B a line of two parts");
	clock_ms = OCTOBER_2026 + 60000u;
	sync_a();
	keys_b_to_a();
	CHECK(line_rows(&A, &heads) == 2u && heads == 0u && rows_hold(&A, "a short one"),
	      "A keeps both lines in rows, opened: the text is there in the clear");
	journal_cut();
	rec_reads = 0;
	CHECK(list(&A, X, 0u, 5u) && count == 2u && is_line(0, 2u, FZN_MESSAGE_IN, long_text)
	              && is_line(1, 1u, FZN_MESSAGE_OUT, "a short one") && rec_reads == 0u,
	      "with every record gone, x's page reads both whole, the long one from two parts");
	CHECK(list(&A, NULL, 0u, 5u) && count == 2u && is_line(0, 2u, FZN_MESSAGE_IN, long_text)
	              && page[0].written_at > page[1].written_at && rec_reads == 0u,
	      "and everyone's page, newest first, with when each was written kept");
}

static void test_a_trimmed_month_keeps_heads_only(void)
{
	fzn_retain_rule_t r = rule_of("prune messages age 60d");
	size_t heads = 9, marks = 0;

	setup();
	CHECK(write_in(&A, 678u, X, 1u, "july") && write_in(&A, 679u, X, 2u, "august"),
	      "fixture: a line in July, one in August");
	line_removes = 0;
	CHECK(trim(&A, &r, 1u) && trimmed.months == 1u && line_rows(&A, &heads) == 2u
	              && heads == 1u && !rows_hold(&A, "july") && rows_hold(&A, "august"),
	      "July trimmed: its row keeps its head and its text is gone");
	CHECK(line_removes == 1u,
	      "removed before its head was saved, which erases an operation journal's copy");
	CHECK(fzn_messages_reindex(&A.m, &marks) == FZN_MESSAGES_OK && line_rows(&A, &heads) == 2u
	              && heads == 1u,
	      "and a rebuild from a journal that still holds July does not bring them back");
	journal_cut();
	CHECK(list(&A, X, 0u, 5u) && count == 2u && is_line(0, 2u, FZN_MESSAGE_OUT, "august")
	              && !page[1].readable && page[1].id[0] == 1u && page[1].stime != 0u
	              && page[1].written_at != 0u,
	      "July is listed as a shell with its times, from its head alone");
}

static void test_a_line_two_devices_wrote_is_kept_once(void)
{
	size_t heads = 9;

	setup();
	CHECK(write_line(&A, X, FZN_MESSAGE_OUT, 7u, "the same line")
	              && write_line(&B, X, FZN_MESSAGE_OUT, 7u, "the same line"),
	      "fixture: A and B each write line 7");
	sync_a();
	CHECK(line_rows(&A, &heads) == 1u && list(&A, X, 0u, 5u) && count == 1u,
	      "A keeps one row for it, and lists it once");
}

/* A ROW UNDER ANOTHER LINE'S PLACE is not that line: copied over line 1's
 * row, line 2's bytes are refused there rather than shown as line 1. */
static void test_a_row_must_be_its_own_line(void)
{
	row_t *first = NULL, *second = NULL;
	size_t i;

	setup();
	CHECK(write_line(&A, X, FZN_MESSAGE_OUT, 1u, "one") && write_line(&A, X, FZN_MESSAGE_OUT, 2u, "two"),
	      "fixture: two lines");
	for (i = 0; i < ROWS; i++)
		if (A.store.rows[i].used && A.store.rows[i].slot == FZN_PERSIST_MESSAGE_LINE) {
			if (!first)
				first = &A.store.rows[i];
			else
				second = &A.store.rows[i];
		}
	CHECK(first && second, "fixture: both rows found");
	if (!first || !second)
		return;
	memcpy(first->bytes, second->bytes, second->len);
	first->len = second->len;
	CHECK(list(&A, X, 0u, 5u) && count == 1u && page[0].text_len == 3u,
	      "one line lists, once: the copy under the other's place is passed over");
}

/* PAST WHAT KEEPING LOOKS BACK OVER: B's copy of a line arrives 64 lines
 * after A's, so the index holds it twice and the page alone shows it once. */
static void test_a_late_copy_is_listed_once(void)
{
	char text[8];
	uint8_t n;
	int ok = 1;

	setup();
	CHECK(write_line(&A, X, FZN_MESSAGE_OUT, 7u, "seven"), "fixture: A writes line 7");
	for (n = 100u; n < 164u && ok; n++) {
		snprintf(text, sizeof(text), "%u", n);
		ok = write_line(&A, X, FZN_MESSAGE_OUT, n, text);
	}
	CHECK(ok && write_line(&B, X, FZN_MESSAGE_OUT, 7u, "seven"),
	      "fixture: 64 more of A's, then B's copy of line 7");
	sync_a();
	CHECK(list(&A, X, 60u, 20u) && count == 5u && !more,
	      "65 lines, not 66: the copy past the look-back is shown once");
}

/* A LINE THAT ARRIVES BEFORE ITS KEY waits sealed in its row, opens when
 * the key comes, and once opened needs no key to read. sec 539. */
static void test_a_line_waits_for_its_key(void)
{
	setup();
	CHECK(write_line(&B, X, FZN_MESSAGE_IN, 3u, "from b"), "fixture: B writes a line");
	sync_a();
	CHECK(list(&A, X, 0u, 5u) && count == 1u && !page[0].readable && !rows_hold(&A, "from b"),
	      "A holds B's line before B's key: a shell, kept sealed");
	keys_b_to_a();
	CHECK(list(&A, X, 0u, 5u) && is_line(0, 3u, FZN_MESSAGE_IN, "from b")
	              && rows_hold(&A, "from b"),
	      "the key arrives and opens the row: readable, and kept opened");
	keys_gone(&A);
	journal_cut();
	CHECK(list(&A, X, 0u, 5u) && is_line(0, 3u, FZN_MESSAGE_IN, "from b"),
	      "and with every key and every record gone it still reads");
}

static void test_an_older_store_is_rebuilt_once(void)
{
	size_t i, heads = 9;
	int rebuilt = -1;

	setup();
	CHECK(write_line(&A, X, FZN_MESSAGE_OUT, 1u, "before rows"),
	      "fixture: a line written");
	/* AS A STORE FROM BEFORE SEC 536 HOLDS IT: its index, no rows. */
	for (i = 0; i < ROWS; i++)
		if (A.store.rows[i].used && A.store.rows[i].slot == FZN_PERSIST_MESSAGE_LINE)
			memset(&A.store.rows[i], 0, sizeof(A.store.rows[i]));
	CHECK(list(&A, X, 0u, 5u) && count == 0u, "fixture: without its row the line is not listed");
	CHECK(fzn_messages_upgrade(&A.m, &rebuilt) == FZN_MESSAGES_OK && rebuilt == 1
	              && line_rows(&A, &heads) == 1u && list(&A, X, 0u, 5u)
	              && is_line(0, 1u, FZN_MESSAGE_OUT, "before rows"),
	      "the upgrade rebuilds it from the journal, and the line lists again");
	CHECK(fzn_messages_upgrade(&A.m, &rebuilt) == FZN_MESSAGES_OK && rebuilt == 0,
	      "once: a second upgrade rebuilds nothing");
	setup();
	CHECK(fzn_messages_upgrade(&A.m, &rebuilt) == FZN_MESSAGES_OK && rebuilt == 0,
	      "and a new store, with nothing to rebuild, says it rebuilt nothing");
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
	test_no_reindex_from_a_window();
	test_the_newest_mark_wins();
	test_one_conversation_reads_only_its_own();
	test_import_keeps_a_line_once();
	test_read_state_travels();
	test_reindex_orders_by_writing();
	test_the_same_line_far_apart();
	test_lines_from_before_marks();
	test_trimming_by_age();
	test_the_store_outlives_the_journal();
	test_a_trimmed_month_keeps_heads_only();
	test_a_line_two_devices_wrote_is_kept_once();
	test_an_older_store_is_rebuilt_once();
	test_a_row_must_be_its_own_line();
	test_a_late_copy_is_listed_once();
	test_a_line_waits_for_its_key();
	test_trimming_by_count_with_a_keep();
	test_trimming_by_size();
	test_trimming_under_a_policy();
	test_a_month_wanted();
	test_the_current_month_stays();
	test_a_trim_reaches_every_device_key();
	test_reindex_rebuilds_from_nothing();
	test_a_month_forgotten_leaves_shells();
	if (failures) {
		fprintf(stderr, "messages_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("messages_test: all %d checks passed\n", checks);
	return 0;
}
