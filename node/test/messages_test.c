/* node messages_test -- a node's conversations, sec 527: the verbs, what a
 * pull brings absorbed, and conversation keys carried between a user's
 * devices, a hub that pulls from nobody among them. Real Ed25519, BLAKE2b
 * and XChaCha20-Poly1305. */

#include "../messages.h"
#include "../../chain/sign_monocypher.h"
#include "../../contact/contact.h"
#include "../../session/aead_monocypher.h"
#include "../../session/hash_monocypher.h"

#include <monocypher-ed25519.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;
	failures++;
	fprintf(stderr, "  FAIL node/test/messages_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, what)

static uint8_t rng_counter;

static int counter_fill(void *ctx, uint8_t *out, size_t len)
{
	size_t i;

	(void)ctx;
	for (i = 0; i < len; i++)
		out[i] = (uint8_t)(rng_counter++ * 53u + 7u);
	return 1;
}

static const fzn_random_ops_t RNG = { counter_fill, NULL };

/* 2026-10-08 12:00 UTC. */
static uint64_t clock_ms = 1791460800000ull;

static uint64_t now_ms(void)
{
	return clock_ms += 1000u;
}

/* ---- a persist store in memory ---------------------------------------------- */

#define ROWS 256u

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

/* ---- record stores: one shared, as the journal sync leaves every device,
 * and one per device, for hosts joined only by the exchange ---------------- */

#define RECS 64u

typedef struct recs {
	struct rec {
		uint8_t issuer[FZN_PUBKEY_LEN];
		uint32_t stream;
		uint64_t seq;
		size_t len;
		uint8_t bytes[FZN_RECORD_MAX_LEN];
	} r[RECS];
	size_t n;
} recs_t;

static recs_t shared;

static int rec_put(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t seq,
                   const uint8_t *bytes, size_t len)
{
	recs_t *s = (recs_t *)ctx;

	if (s->n >= RECS)
		return 0;
	memcpy(s->r[s->n].issuer, issuer, FZN_PUBKEY_LEN);
	s->r[s->n].stream = stream;
	s->r[s->n].seq = seq;
	s->r[s->n].len = len;
	memcpy(s->r[s->n].bytes, bytes, len);
	s->n++;
	return 1;
}

static int rec_get(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t seq,
                   uint8_t *out, size_t cap, size_t *len_out, int *found_out)
{
	recs_t *s = (recs_t *)ctx;
	size_t i;

	*found_out = 0;
	for (i = 0; i < s->n; i++)
		if (s->r[i].seq == seq && s->r[i].stream == stream
		    && memcmp(s->r[i].issuer, issuer, FZN_PUBKEY_LEN) == 0) {
			*found_out = 1;
			if (s->r[i].len > cap)
				return 0;
			memcpy(out, s->r[i].bytes, s->r[i].len);
			*len_out = s->r[i].len;
			return 1;
		}
	return 1;
}

static fzn_record_store_ops_t rops = { rec_put, rec_get, &shared };

/* ---- three devices of one user: A, B, and H the hub -------------------------- */

typedef struct device {
	fzn_sign_monocypher_t key;
	fzn_sign_ops_t sign;
	uint8_t pub[FZN_PUBKEY_LEN];
	mem_t store;
	fzn_persist_ops_t store_ops;
	fzn_node_journal_t journal;
	fzn_node_messages_t nm;
	/* A host's own records, when it keeps them apart. */
	recs_t own;
	fzn_record_store_ops_t own_ops;
} device_t;

static device_t A, B, H;
static fzn_aead_ops_t AEAD;
static fzn_hash_ops_t HASH;
static uint8_t X[FZN_PUBKEY_LEN];

static void device_up(device_t *d, uint8_t seed_byte)
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
	(void)fzn_node_messages_init(&d->nm, &d->store_ops, &d->journal, d->pub, &d->sign, &RNG,
	                             &AEAD, &HASH, now_ms);
}

/* What the journal sync leaves `d` holding: its journal reopened over the
 * shared records, following every device, its store and cursors kept. */
static void synced(device_t *d)
{
	uint8_t keys[3][FZN_PUBKEY_LEN];

	memcpy(keys[0], A.pub, FZN_PUBKEY_LEN);
	memcpy(keys[1], B.pub, FZN_PUBKEY_LEN);
	memcpy(keys[2], H.pub, FZN_PUBKEY_LEN);
	(void)fzn_node_journal_init_store(&d->journal, &rops, &d->sign, &HASH);
	(void)fzn_node_messages_devices(&d->nm, (const uint8_t(*)[FZN_PUBKEY_LEN])keys, 3u);
}

static void setup(void)
{
	memset(&shared, 0, sizeof(shared));
	rng_counter = 0;
	device_up(&A, 0x11);
	device_up(&B, 0x22);
	device_up(&H, 0x33);
	synced(&A);
	synced(&B);
	synced(&H);
}

/* AN ASK THAT IS ANOTHER DEVICE'S ANSWER, from a member. */
typedef struct link {
	device_t *to;
	device_t *from;
	/* 1: add a key nobody asked for to a KEYS answer; 2: move the first
	 * key in one to a place nobody asked for. */
	int extra;
} link_t;

static int over(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
                size_t reply_cap, size_t *reply_len)
{
	link_t *l = (link_t *)ctx;
	size_t n = fzn_node_messages_remote(&l->to->nm, l->from->pub, request, request_len, reply,
	                                    reply_cap);

	if (!n)
		return 0;
	if (l->extra == 2 && reply[1] == FZN_NODE_MESSAGES_KEYS && reply[2] > 0u)
		memset(reply + FZN_NODE_MESSAGES_HEAD_LEN, 0x5e, FZN_PUBKEY_LEN);
	if (l->extra == 1 && reply[1] == FZN_NODE_MESSAGES_KEYS && n + FZN_NODE_MESSAGES_HELD_LEN
	                                                               <= reply_cap) {
		memset(reply + n, 0x5e, FZN_NODE_MESSAGES_HELD_LEN);
		reply[2]++;
		n += FZN_NODE_MESSAGES_HELD_LEN;
	}
	*reply_len = n;
	return 1;
}

static fzn_node_messages_tally_t t;

static int round_with(device_t *from, device_t *to)
{
	link_t l = { to, from, 0 };

	memset(&t, 0, sizeof(t));
	return fzn_node_messages_round(&from->nm, over, &l, &t);
}

/* ---- the verbs ---------------------------------------------------------------- */

static char reply[FZN_REPLY_MAX];

static size_t verb(device_t *d, fzn_origin_t origin, const char *line)
{
	fzn_request_t req;

	memset(reply, 0, sizeof(reply));
	if (!fzn_vocabulary_split((const uint8_t *)line, strlen(line), &req))
		return 0;
	return fzn_node_messages_local(&d->nm, origin, &req, reply, sizeof(reply));
}

static int replied(const char *start)
{
	return strncmp(reply, start, strlen(start)) == 0;
}

#define ID1 "01010101010101010101010101010101"
#define ID2 "02020202020202020202020202020202"

static void test_the_verbs(void)
{
	char line[600], path[64];
	FILE *f;
	size_t i;

	setup();
	CHECK(fzn_contact_add(&A.store_ops, X, "carol", 5u, 1u) == FZN_CONTACT_OK,
	      "fixture: carol is a contact");
	CHECK(verb(&A, FZN_ORIGIN_SAME_USER, "add message carol out " ID1 " hello%20there%0a")
	              && replied("ok"),
	      "a line added by the contact's name, the text's escapes undone");
	snprintf(line, sizeof(line), "add message %s in " ID2 " at 12345 hi",
	         "5858585858585858585858585858585858585858585858585858585858585858");
	CHECK(verb(&A, FZN_ORIGIN_SAME_USER, line) && replied("ok"),
	      "and one by the contact's key, at the sender's time");
	CHECK(verb(&A, FZN_ORIGIN_SAME_USER, "list message carol") && replied("ok 0 2 0 ")
	              && strstr(reply, ",carol," ID2 ",in,-,12345,")
	              && strstr(reply, ",1,hi")
	              && strstr(reply, ",carol," ID1 ",out,-,")
	              && strstr(reply, ",1,hello%20there%0a"),
	      "carol's conversation lists both, newest first, names at the edge, text escaped");
	CHECK(verb(&A, FZN_ORIGIN_SAME_USER, "set message carol out " ID1 " delivered")
	              && replied("ok") && verb(&A, FZN_ORIGIN_SAME_USER, "list message")
	              && strstr(reply, ID1 ",out,delivered,"),
	      "a line set delivered lists so");
	CHECK(verb(&A, FZN_ORIGIN_SAME_USER, "list message 1") && replied("ok 1 1 0 ")
	              && strstr(reply, ID1),
	      "and a listing from 1 starts at the second");
	/* X's hex is all decimal digits, which a FROM is too. */
	CHECK(verb(&A, FZN_ORIGIN_SAME_USER,
	           "list message 5858585858585858585858585858585858585858585858585858585858585858 1")
	              && replied("ok 1 1 0 ") && strstr(reply, ",carol," ID1 ","),
	      "a key of digits alone is WHO, not a page offset, and FROM still follows it");
	CHECK(verb(&A, FZN_ORIGIN_SAME_USER, "get message carol unread") && replied("ok 1 0"),
	      "one line in, nothing read: one unread");
	A.nm.fresh = 0;
	CHECK(verb(&A, FZN_ORIGIN_SAME_USER, "set message carol read " ID2) && replied("ok")
	              && A.nm.fresh
	              && verb(&A, FZN_ORIGIN_SAME_USER, "get message carol unread")
	              && replied("ok 0 0"),
	      "read up to it, none unread, and the write marked fresh for the daemon to push");
	CHECK(verb(&A, FZN_ORIGIN_SAME_USER, "get message carol everything") && replied("malformed"),
	      "a get that is not unread is refused");
	CHECK(verb(&A, FZN_ORIGIN_LOCAL, "list message") && replied("denied"),
	      "another user is refused");
	CHECK(verb(&A, FZN_ORIGIN_SAME_USER, "add message dave out " ID1 " hi")
	              && replied("malformed"),
	      "a name no contact holds is refused");
	CHECK(verb(&A, FZN_ORIGIN_SAME_USER, "add message carol out " ID1 " bad%zz")
	              && replied("malformed"),
	      "and a bad escape");
	CHECK(verb(&A, FZN_ORIGIN_SAME_USER, "set message carol out " ID1 " lost")
	              && replied("malformed"),
	      "and a state that is not one");
	CHECK(!verb(&A, FZN_ORIGIN_SAME_USER, "list note top"), "a verb not about messages is not ours");

	/* A TEXT BY FILE, the whole 512 bytes, and one byte past refused. */
	snprintf(path, sizeof(path), "/tmp/fzn-messages-test-%ld", (long)getpid());
	f = fopen(path, "wb");
	for (i = 0; f && i < FZN_MESSAGE_TEXT_MAX; i++)
		(void)fputc('w', f);
	if (f)
		(void)fclose(f);
	snprintf(line, sizeof(line), "add message carol out 03030303030303030303030303030303 file %s",
	         path);
	CHECK(verb(&A, FZN_ORIGIN_SAME_USER, line) && replied("ok"), "a 512-byte text from a file");
	f = fopen(path, "ab");
	if (f) {
		(void)fputc('w', f);
		(void)fclose(f);
	}
	snprintf(line, sizeof(line), "add message carol out 04040404040404040404040404040404 file %s",
	         path);
	CHECK(verb(&A, FZN_ORIGIN_SAME_USER, line) && replied("malformed"),
	      "and 513 refused whole");
	CHECK(unlink(path) == 0, "fixture: the file removed");
	CHECK(verb(&A, FZN_ORIGIN_SAME_USER, "list message carol") && replied("ok 0 ")
	              && strstr(reply, ",03030303030303030303030303030303,out,-,")
	              && !strstr(reply, "04040404040404040404040404040404"),
	      "the long line is listed first, and the refused one nowhere");
}

/* ---- keys between devices ------------------------------------------------------ */

static int readable_on(device_t *d)
{
	static fzn_message_t page[FZN_MESSAGES_PAGE_MAX];
	size_t count = 0, i;
	int more = 0, all = 1;

	if (fzn_messages_page(&d->nm.m, NULL, 0u, page, FZN_MESSAGES_PAGE_MAX, &count, &more)
	    != FZN_MESSAGES_OK)
		return -1;
	for (i = 0; i < count; i++)
		all &= page[i].readable;
	return count ? all : -1;
}

static void test_keys_travel(void)
{
	uint8_t id[FZN_MESSAGE_ID_LEN];

	setup();
	memset(id, 0x21, sizeof(id));
	CHECK(fzn_messages_write(&B.nm.m, X, FZN_MESSAGE_IN, id, 5u, "from b", 6u) == FZN_MESSAGES_OK,
	      "fixture: B writes a line");
	synced(&A);
	CHECK(fzn_node_messages_absorb(&A.nm, &t) == FZN_MESSAGES_OK && t.lacking == 1u
	              && readable_on(&A) == 0,
	      "carried to A, B's line is a shell, and its key is lacked");
	CHECK(round_with(&A, &B) && t.taken == 1u && t.lacking == 0u && readable_on(&A) == 1,
	      "A asks B, takes the key, and the line opens");
	CHECK(round_with(&A, &B) && t.taken == 0u,
	      "and asks no more for it");
	id[0] = 0x22;
	CHECK(fzn_messages_write(&B.nm.m, X, FZN_MESSAGE_IN, id, 6u, "again", 5u) == FZN_MESSAGES_OK,
	      "fixture: B writes again, under the key A now holds");
	synced(&A);
	CHECK(fzn_node_messages_absorb(&A.nm, &t) == FZN_MESSAGES_OK && t.lacking == 0u
	              && A.nm.n_gives == 0u && readable_on(&A) == 1,
	      "A reads it at once, and never offers B's key as its own");
}

/* THE HUB pulls from nobody, so it comes by keys only by being given them;
 * then a device that lacks one asks it there. */
static void test_keys_through_a_hub(void)
{
	uint8_t id[FZN_MESSAGE_ID_LEN];

	setup();
	memset(id, 0x31, sizeof(id));
	CHECK(fzn_messages_write(&A.nm.m, X, FZN_MESSAGE_OUT, id, 5u, "from a", 6u) == FZN_MESSAGES_OK,
	      "fixture: A writes a line");
	synced(&A);
	CHECK(fzn_node_messages_absorb(&A.nm, &t) == FZN_MESSAGES_OK && A.nm.n_gives == 1u,
	      "A notes its own key to give");
	CHECK(round_with(&A, &H) && t.given == 1u && A.nm.n_gives == 0u
	              && rows_in(&H.store, FZN_PERSIST_CONVERSATION_KEY) == 1u,
	      "A gives it to the hub, as its own, and gives it no more");
	synced(&B);
	CHECK(fzn_node_messages_absorb(&B.nm, &t) == FZN_MESSAGES_OK && t.lacking == 1u
	              && round_with(&B, &H) && t.taken == 1u && readable_on(&B) == 1,
	      "B, which never talks to A, asks the hub and reads A's line");
}

static void test_keys_cannot_be_planted(void)
{
	uint8_t id[FZN_MESSAGE_ID_LEN], key[FZN_CONVERSATION_KEY_LEN];
	uint8_t give[FZN_NODE_MESSAGES_HEAD_LEN + FZN_PUBKEY_LEN + 4u + FZN_CONVERSATION_KEY_LEN];
	uint8_t out[FZN_NODE_MESSAGES_REPLY_MAX];
	link_t extra;
	size_t n;

	setup();
	memset(id, 0x41, sizeof(id));
	CHECK(fzn_messages_write(&A.nm.m, X, FZN_MESSAGE_OUT, id, 5u, "mine", 4u) == FZN_MESSAGES_OK
	              && fzn_messages_key_get(&A.nm.m, X, 681u, A.pub, key),
	      "fixture: A's line, and its key");
	CHECK(fzn_messages_key_take(&H.nm.m, X, 681u, A.pub, key) == FZN_MESSAGES_OK,
	      "fixture: the hub holds A's key");
	/* B GIVES A KEY FOR THE SAME CONVERSATION AND MONTH: it is kept as
	 * B's, never as A's, and A's at the hub is untouched. */
	give[0] = FZN_NODE_MESSAGES_VERSION;
	give[1] = FZN_NODE_MESSAGES_GIVE;
	give[2] = 1u;
	memcpy(give + 3, X, FZN_PUBKEY_LEN);
	give[3 + FZN_PUBKEY_LEN] = 0;
	give[4 + FZN_PUBKEY_LEN] = 0;
	give[5 + FZN_PUBKEY_LEN] = 0x02;
	give[6 + FZN_PUBKEY_LEN] = 0xa9; /* 681 */
	memset(give + 7 + FZN_PUBKEY_LEN, 0x66, FZN_CONVERSATION_KEY_LEN);
	n = fzn_node_messages_remote(&H.nm, B.pub, give, sizeof(give), out, sizeof(out));
	{
		uint8_t held[FZN_CONVERSATION_KEY_LEN];

		CHECK(n == FZN_NODE_MESSAGES_GIVEN_LEN && out[2] == 1u
		              && fzn_messages_key_get(&H.nm.m, X, 681u, A.pub, held)
		              && memcmp(held, key, sizeof(key)) == 0
		              && fzn_messages_key_get(&H.nm.m, X, 681u, B.pub, held)
		              && held[0] == 0x66u,
		      "a key B gives is kept as B's, and A's is untouched");
	}
	/* A GIVES ANOTHER KEY FOR A ROW THE HUB HOLDS: refused. */
	memset(give + 7 + FZN_PUBKEY_LEN, 0x77, FZN_CONVERSATION_KEY_LEN);
	n = fzn_node_messages_remote(&H.nm, A.pub, give, sizeof(give), out, sizeof(out));
	CHECK(n == FZN_NODE_MESSAGES_GIVEN_LEN && out[2] == 0u && out[3] == 1u,
	      "a different key for a row held is refused: the first stands");
	/* AN ANSWER CARRYING A KEY NOBODY ASKED FOR is not taken. */
	synced(&B);
	CHECK(fzn_node_messages_absorb(&B.nm, &t) == FZN_MESSAGES_OK && t.lacking == 1u,
	      "fixture: B lacks A's key");
	extra.to = &H;
	extra.from = &B;
	extra.extra = 1;
	CHECK(fzn_node_messages_round(&B.nm, over, &extra, &t) == 0
	              && rows_in(&B.store, FZN_PERSIST_CONVERSATION_KEY) == 0u,
	      "an answer with more keys than were asked is refused whole");
	extra.extra = 2;
	memset(&t, 0, sizeof(t));
	CHECK(fzn_node_messages_round(&B.nm, over, &extra, &t) == 1 && t.taken == 0u
	              && rows_in(&B.store, FZN_PERSIST_CONVERSATION_KEY) == 0u && t.lacking == 1u,
	      "and a key for a place nobody asked for is not taken");
}

static void test_marks_are_absorbed(void)
{
	uint8_t id[FZN_MESSAGE_ID_LEN];

	setup();
	memset(id, 0x51, sizeof(id));
	CHECK(fzn_messages_write(&A.nm.m, X, FZN_MESSAGE_OUT, id, 5u, "x", 1u) == FZN_MESSAGES_OK
	              && fzn_messages_mark(&B.nm.m, X, FZN_MESSAGE_OUT, id, FZN_MESSAGE_SETTLED)
	                         == FZN_MESSAGES_OK,
	      "fixture: A's line, settled on B");
	synced(&A);
	CHECK(fzn_node_messages_absorb(&A.nm, &t) == FZN_MESSAGES_OK && t.marks == 1u
	              && fzn_messages_state(&A.nm.m, X, FZN_MESSAGE_OUT, id) == FZN_MESSAGE_SETTLED,
	      "B's mark, carried, is the line's state on A once absorbed");
	CHECK(fzn_node_messages_absorb(&A.nm, &t) == FZN_MESSAGES_OK && t.marks == 0u,
	      "and an absorb with nothing new reads nothing");
}

/* ---- two hosts joined only by the exchange: what fzpd will run ---------- */

static device_t M, R; /* a member, and the hub it pulls from */

/* A HOST ANSWERING A MEMBER, as fuzznetd's admin dispatches it: the
 * journal's messages first, then the conversation keys. A PUSH taken is
 * noted, since the host absorbs after one. */
typedef struct serve {
	device_t *to;
	device_t *from;
	int pushed;
} serve_t;

static int serve(void *ctx, const uint8_t *request, size_t request_len, uint8_t *out,
                 size_t out_cap, size_t *out_len)
{
	serve_t *s = (serve_t *)ctx;
	size_t n = fzn_node_journal_answer(&s->to->journal, request, request_len, out, out_cap);

	if (n) {
		if (request_len >= 2u && request[0] == FZN_EXCHANGE_VERSION
		    && request[1] == FZN_EXCHANGE_PUSH)
			s->pushed = 1;
	} else {
		n = fzn_node_messages_remote(&s->to->nm, s->from->pub, request, request_len, out,
		                             out_cap);
	}
	if (!n)
		return 0;
	*out_len = n;
	return 1;
}

/* A host over records of its own, following itself and `peer`. */
static void host_up(device_t *d, const device_t *peer)
{
	memset(&d->own, 0, sizeof(d->own));
	d->own_ops.put = rec_put;
	d->own_ops.get = rec_get;
	d->own_ops.ctx = &d->own;
	(void)fzn_node_journal_init_store(&d->journal, &d->own_ops, &d->sign, &HASH);
	(void)fzn_node_messages_init(&d->nm, &d->store_ops, &d->journal, d->pub, &d->sign, &RNG,
	                             &AEAD, &HASH, now_ms);
	(void)fzn_node_messages_devices(&d->nm, (const uint8_t(*)[FZN_PUBKEY_LEN])peer->pub, 1u);
}

/* ONE ROUND OF THE MEMBER WITH ITS HUB, in the order a host runs it: pull,
 * push, the hub absorbing what was pushed, the member absorbing what was
 * pulled, then the keys. */
static int member_round(void)
{
	static uint8_t buf[16384];
	serve_t s = { &R, &M, 0 };
	fzn_exchange_tally_t pulled;
	fzn_exchange_push_tally_t pushed;
	fzn_node_messages_tally_t absorbed;

	if (fzn_node_journal_pull(&M.journal, serve, &s, buf, sizeof(buf), &pulled)
	            != FZN_EXCHANGE_OK
	    || fzn_node_journal_push(&M.journal, serve, &s, buf, sizeof(buf), &pushed)
	               != FZN_EXCHANGE_OK
	    || (s.pushed && fzn_node_messages_absorb(&R.nm, &absorbed) != FZN_MESSAGES_OK)
	    || fzn_node_messages_absorb(&M.nm, &absorbed) != FZN_MESSAGES_OK)
		return 0;
	memset(&t, 0, sizeof(t));
	return fzn_node_messages_round(&M.nm, serve, &s, &t);
}

static int one_line_is(device_t *d, uint8_t first, uint8_t state, const char *text)
{
	static fzn_message_t page[FZN_MESSAGES_PAGE_MAX];
	size_t count = 0, i;
	int more = 0;

	if (fzn_messages_page(&d->nm.m, X, 0u, page, FZN_MESSAGES_PAGE_MAX, &count, &more)
	    != FZN_MESSAGES_OK)
		return 0;
	for (i = 0; i < count; i++)
		if (page[i].id[0] == first)
			return page[i].readable && page[i].state == state
			       && page[i].text_len == strlen(text)
			       && memcmp(page[i].text, text, page[i].text_len) == 0;
	return 0;
}

static void test_two_hosts_over_the_exchange(void)
{
	uint8_t id[FZN_MESSAGE_ID_LEN];
	size_t unread = 9u, before;
	int beyond = 1;

	setup();
	device_up(&M, 0x44);
	device_up(&R, 0x55);
	host_up(&M, &R);
	host_up(&R, &M);

	memset(id, 0x61, sizeof(id));
	CHECK(fzn_messages_write(&R.nm.m, X, FZN_MESSAGE_OUT, id, 1u, "from the hub", 12u)
	              == FZN_MESSAGES_OK,
	      "fixture: the hub writes a line");
	before = M.own.n;
	CHECK(member_round() && M.own.n > before && t.taken == 1u
	              && one_line_is(&M, 0x61, 0u, "from the hub"),
	      "a round pulls it into the member's own records, asks its key, and it opens");

	memset(id, 0x62, sizeof(id));
	CHECK(fzn_messages_write(&M.nm.m, X, FZN_MESSAGE_IN, id, 2u, "from the member", 15u)
	              == FZN_MESSAGES_OK,
	      "fixture: the member writes a line");
	before = R.own.n;
	CHECK(member_round() && R.own.n > before && t.given == 1u
	              && one_line_is(&R, 0x62, 0u, "from the member"),
	      "the next pushes it to the hub, gives its key, and it opens there");

	memset(id, 0x61, sizeof(id));
	CHECK(fzn_messages_mark(&M.nm.m, X, FZN_MESSAGE_OUT, id, FZN_MESSAGE_DELIVERED)
	                      == FZN_MESSAGES_OK
	              && fzn_messages_unread(&R.nm.m, X, &unread, &beyond) == FZN_MESSAGES_OK
	              && unread == 1u,
	      "fixture: the member marks the hub's line; one unread on the hub");
	memset(id, 0x62, sizeof(id));
	CHECK(fzn_messages_read_up_to(&M.nm.m, X, id) == FZN_MESSAGES_OK && member_round()
	              && one_line_is(&R, 0x61, FZN_MESSAGE_DELIVERED, "from the hub")
	              && fzn_messages_unread(&R.nm.m, X, &unread, &beyond) == FZN_MESSAGES_OK
	              && unread == 0u,
	      "a round carries the mark and the read position to the hub");

	/* SEC 521, across hosts: handed over, given up on, text whole. */
	memset(id, 0x63, sizeof(id));
	CHECK(fzn_messages_write(&M.nm.m, X, FZN_MESSAGE_OUT, id, 3u, "via another", 11u)
	                      == FZN_MESSAGES_OK
	              && fzn_messages_mark(&M.nm.m, X, FZN_MESSAGE_OUT, id, FZN_MESSAGE_HANDED_OVER)
	                         == FZN_MESSAGES_OK
	              && fzn_messages_mark(&M.nm.m, X, FZN_MESSAGE_OUT, id,
	                                   FZN_MESSAGE_NOT_DELIVERED)
	                         == FZN_MESSAGES_OK
	              && member_round()
	              && one_line_is(&R, 0x63, FZN_MESSAGE_NOT_DELIVERED, "via another"),
	      "a line handed over and given up on reaches the hub, not delivered, text whole");
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
	test_the_suite_can_tell_pass_from_fail();
	test_the_verbs();
	test_keys_travel();
	test_keys_through_a_hub();
	test_keys_cannot_be_planted();
	test_marks_are_absorbed();
	test_two_hosts_over_the_exchange();
	if (failures) {
		fprintf(stderr, "node messages_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("node messages_test: all %d checks passed\n", checks);
	return 0;
}
