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

#define ROWS 2048u

typedef struct row {
	int used;
	fzn_persist_slot_t slot;
	int has_subject;
	uint8_t subject[FZN_PUBKEY_LEN];
	size_t len;
	/* A bucket's id chunk is 1632 bytes. */
	uint8_t bytes[2048];
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

/* SAVES LEFT BEFORE A POWER CUT, or -1 for none: the cut save and every one
 * after it do not land, as a crash between two would leave them. */
static long saves_left = -1;
static size_t saves_cut;

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	mem_t *m = (mem_t *)ctx;
	row_t *r = find(m, slot, subject);
	size_t i;

	if (saves_left == 0) {
		saves_cut++;
		return 0;
	}
	if (saves_left > 0)
		saves_left--;
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

#define RECS 320u

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

static fzn_record_store_ops_t rops = { rec_put, rec_get, &shared, NULL };

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

/* THE ROUND IN ONE CALL, as a caller asking in turn makes it. */
static int round_driven(device_t *from, device_t *to)
{
	link_t l = { to, from, 0 };

	memset(&t, 0, sizeof(t));
	return fzn_node_messages_round(&from->nm, over, &l, &t);
}

/* AND BY ITS STEPS, sec 636, as the loop drives it: every round below is
 * one. After a give is answered, its keys are wiped: what of the give the
 * next request does not overwrite is zero. */
static size_t keys_left, gives_seen;

static int round_with(device_t *from, device_t *to)
{
	static fzn_node_messages_rounding_t r;
	static uint8_t req[FZN_NODE_MESSAGES_REQUEST_MAX], out[FZN_NODE_MESSAGES_REPLY_MAX];
	link_t l = { to, from, 0 };
	size_t req_len = 0, out_len, turns = 0, k, gave;
	int ok, done = 0, answered;

	memset(&t, 0, sizeof(t));
	ok = fzn_node_messages_round_begin(&r, &from->nm, req, sizeof(req), &req_len, &done);
	while (ok && !done && turns++ < 64u) {
		gave = req[1] == FZN_NODE_MESSAGES_GIVE ? req_len : 0u;
		out_len = 0;
		answered = over(&l, req, req_len, out, sizeof(out), &out_len);
		ok = fzn_node_messages_round_step(&r, answered ? out : NULL, out_len, req, sizeof(req),
		                                  &req_len, &done);
		if (gave) {
			gives_seen++;
			for (k = done ? 0u : req_len; k < gave; k++)
				keys_left += req[k] != 0u;
		}
	}
	t.given += r.tally.given;
	t.refused += r.tally.refused;
	t.taken += r.tally.taken;
	t.lacking = r.tally.lacking;
	return ok;
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
	/* WHAT THIS HOST STILL OWES, sec 661: its own out lines, the in one not. */
	CHECK(verb(&A, FZN_ORIGIN_SAME_USER, "get message owed") && replied("ok 1 0 0"),
	      "one line written and not delivered is held");
	CHECK(verb(&A, FZN_ORIGIN_SAME_USER, "set message carol out " ID1 " delivered")
	              && replied("ok") && verb(&A, FZN_ORIGIN_SAME_USER, "list message")
	              && strstr(reply, ID1 ",out,delivered,"),
	      "a line set delivered lists so");
	CHECK(verb(&A, FZN_ORIGIN_SAME_USER, "get message owed") && replied("ok 0 1 0"),
	      "and is owed as delivered, not held");
	CHECK(verb(&A, FZN_ORIGIN_SAME_USER, "list message 1") && replied("ok 1 1 0 ")
	              && strstr(reply, ID1),
	      "and a listing from 1 starts at the second");
	/* X's hex is all decimal digits, which a FROM is too. Its own
	 * conversation is in the order written (secs 725, 744), where the in
	 * line, stamped 12345, is the older though it was filed second;
	 * everyone's listing stays in the order learned. */
	CHECK(verb(&A, FZN_ORIGIN_SAME_USER,
	           "list message 5858585858585858585858585858585858585858585858585858585858585858 1")
	              && replied("ok 1 1 0 ") && strstr(reply, ",carol," ID2 ","),
	      "a key of digits alone is WHO, not a page offset, and FROM still follows it");
	CHECK(verb(&A, FZN_ORIGIN_SAME_USER, "get message carol unread") && replied("ok 1 0"),
	      "one line in, nothing read: one unread");
	CHECK(verb(&A, FZN_ORIGIN_SAME_USER, "set message carol out " ID1 " settled")
	              && replied("ok") && verb(&A, FZN_ORIGIN_SAME_USER, "get message owed")
	              && replied("ok 0 0 0"),
	      "settled, it is owed no more");
	CHECK(verb(&A, FZN_ORIGIN_LOCAL, "get message owed") && replied("denied"),
	      "another user is not told what is owed");
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
	/* ONE ESCAPED WORD, sec 651: a text that begins `file ` is not the file
	 * form unless it is written so, and a file's path is absolute. */
	CHECK(verb(&A, FZN_ORIGIN_SAME_USER,
	           "add message carol out 05050505050505050505050505050505 file%20notes.txt")
	              && replied("ok"),
	      "an escaped text beginning file was not taken as a text");
	/* EITHER CASE READ, sec 654: an escape as the catalogue once wrote it. */
	CHECK(verb(&A, FZN_ORIGIN_SAME_USER,
	           "add message carol out 08080808080808080808080808080808 a%2Cb")
	              && replied("ok"),
	      "an upper-case escape was refused");
	CHECK(verb(&A, FZN_ORIGIN_SAME_USER,
	           "add message carol out 06060606060606060606060606060606 two words")
	              && replied("malformed"),
	      "a raw space in a text was not refused");
	CHECK(verb(&A, FZN_ORIGIN_SAME_USER,
	           "add message carol out 07070707070707070707070707070707 file notes.txt")
	              && replied("malformed"),
	      "a file named by a relative path was read");
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
	              && !strstr(reply, "04040404040404040404040404040404")
	              && strstr(reply, ",05050505050505050505050505050505,out,-,")
	              && strstr(reply, ",file%20notes.txt")
	              && strstr(reply, ",a%2cb")
	              && !strstr(reply, "06060606060606060606060606060606")
	              && !strstr(reply, "07070707070707070707070707070707"),
	      "the long line is listed first, the escaped file text as a text, and the refused "
	      "ones nowhere");
}

/* THE VERBS NEED THIS NODE'S OWN USER, sec 689's authorization bar for the
 * 1:1 chat journey: every messages verb from each other origin is denied,
 * and none of them changes what the user reads. */
static void test_the_verbs_need_the_user(void)
{
	static const char *const verbs[] = {
		"add message carol out " ID2 " not%20from%20the%20user",
		"set message carol out " ID1 " delivered",
		"set message carol read " ID1,
		"list message carol",
		"list message",
		"get message owed",
		"get message carol unread",
	};
	static const fzn_origin_t origins[] = { FZN_ORIGIN_LOCAL, FZN_ORIGIN_REMOTE,
		                                (fzn_origin_t)0, (fzn_origin_t)99 };
	char before[sizeof(reply)], owed[sizeof(reply)];
	size_t v, o;
	int denied = 1;

	setup();
	CHECK(fzn_contact_add(&A.store_ops, X, "carol", 5u, 1u) == FZN_CONTACT_OK,
	      "fixture: carol is a contact");
	CHECK(verb(&A, FZN_ORIGIN_SAME_USER, "add message carol out " ID1 " hello") && replied("ok"),
	      "fixture: a line to carol");
	(void)verb(&A, FZN_ORIGIN_SAME_USER, "list message carol");
	memcpy(before, reply, sizeof(before));
	(void)verb(&A, FZN_ORIGIN_SAME_USER, "get message owed");
	memcpy(owed, reply, sizeof(owed));
	for (v = 0; v < sizeof(verbs) / sizeof(verbs[0]); v++)
		for (o = 0; o < sizeof(origins) / sizeof(origins[0]); o++)
			if (!verb(&A, origins[o], verbs[v]) || !replied("denied ")) {
				fprintf(stderr, "    %s, origin %d: %s\n", verbs[v], (int)origins[o], reply);
				denied = 0;
			}
	CHECK(denied, "every messages verb from another origin is denied");
	(void)verb(&A, FZN_ORIGIN_SAME_USER, "list message carol");
	CHECK(strcmp(reply, before) == 0, "the conversation is as it was");
	(void)verb(&A, FZN_ORIGIN_SAME_USER, "get message owed");
	CHECK(strcmp(reply, owed) == 0, "what is owed is as it was");
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
	CHECK(round_driven(&A, &B) && t.taken == 1u && t.lacking == 0u && readable_on(&A) == 1,
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

/* A HAND-OFF GIVEN UP ON, sec 607: A's line to X, handed over, and X no
 * longer standing; A's line to Y, handed over, Y standing; and A's line to
 * X already delivered. Only the first is marked not delivered, once, and
 * the mark is B's state too once carried. */
static uint8_t Y[FZN_PUBKEY_LEN];

static int y_stands(void *ctx, const uint8_t contact[FZN_PUBKEY_LEN])
{
	(void)ctx;
	return memcmp(contact, Y, FZN_PUBKEY_LEN) == 0;
}

/* X WAS A CONTACT AND WAS REMOVED; nobody else was. */
static int x_removed(void *ctx, const uint8_t contact[FZN_PUBKEY_LEN])
{
	(void)ctx;
	return memcmp(contact, X, FZN_PUBKEY_LEN) == 0;
}

static void test_a_hand_off_to_a_removed_contact_is_given_up(void)
{
	uint8_t id1[FZN_MESSAGE_ID_LEN], id2[FZN_MESSAGE_ID_LEN], id3[FZN_MESSAGE_ID_LEN];
	uint8_t id4[FZN_MESSAGE_ID_LEN], Z[FZN_PUBKEY_LEN];
	size_t marked = 9;

	setup();
	memset(Y, 0x77, sizeof(Y));
	memset(Z, 0x5a, sizeof(Z));
	memset(id4, 0x64, sizeof(id4));
	memset(id1, 0x61, sizeof(id1));
	memset(id2, 0x62, sizeof(id2));
	memset(id3, 0x63, sizeof(id3));
	CHECK(fzn_messages_write(&A.nm.m, X, FZN_MESSAGE_OUT, id1, 5u, "to x", 4u) == FZN_MESSAGES_OK
	              && fzn_messages_mark(&A.nm.m, X, FZN_MESSAGE_OUT, id1, FZN_MESSAGE_HANDED_OVER)
	                         == FZN_MESSAGES_OK
	              && fzn_messages_write(&A.nm.m, X, FZN_MESSAGE_OUT, id2, 6u, "sent", 4u)
	                         == FZN_MESSAGES_OK
	              && fzn_messages_mark(&A.nm.m, X, FZN_MESSAGE_OUT, id2, FZN_MESSAGE_DELIVERED)
	                         == FZN_MESSAGES_OK
	              && fzn_messages_write(&A.nm.m, X, FZN_MESSAGE_IN, id3, 7u, "from x", 6u)
	                         == FZN_MESSAGES_OK
	              && fzn_messages_write(&A.nm.m, Y, FZN_MESSAGE_OUT, id3, 8u, "to y", 4u)
	                         == FZN_MESSAGES_OK
	              && fzn_messages_mark(&A.nm.m, Y, FZN_MESSAGE_OUT, id3, FZN_MESSAGE_HANDED_OVER)
	                         == FZN_MESSAGES_OK
	              && fzn_messages_write(&A.nm.m, X, FZN_MESSAGE_OUT, id4, 9u, "unsent", 6u)
	                         == FZN_MESSAGES_OK
	              && fzn_messages_write(&A.nm.m, Y, FZN_MESSAGE_OUT, id4, 10u, "unsent", 6u)
	                         == FZN_MESSAGES_OK
	              && fzn_messages_write(&A.nm.m, Z, FZN_MESSAGE_OUT, id4, 11u, "unsent", 6u)
	                         == FZN_MESSAGES_OK,
	      "fixture: lines to X and Y, handed over, delivered, received and still sent");
	CHECK(fzn_node_messages_give_up(&A.nm, y_stands, x_removed, NULL, &marked) == FZN_MESSAGES_OK
	              && marked == 2u,
	      "not two lines marked: the one handed over for X, which no longer stands, and the "
	      "one still being sent to it (sec 616)");
	CHECK(fzn_messages_state(&A.nm.m, Z, FZN_MESSAGE_OUT, id4) == 0u,
	      "a line still being sent to a key never a contact was given up on");
	CHECK(fzn_messages_state(&A.nm.m, X, FZN_MESSAGE_OUT, id4) == FZN_MESSAGE_NOT_DELIVERED
	              && fzn_messages_state(&A.nm.m, Y, FZN_MESSAGE_OUT, id4) == 0u,
	      "a line still being sent was marked for the contact that stands, or not for the one "
	      "that does not");
	CHECK(fzn_messages_state(&A.nm.m, X, FZN_MESSAGE_OUT, id1) == FZN_MESSAGE_NOT_DELIVERED,
	      "the line handed over for X is not marked not delivered");
	CHECK(fzn_messages_state(&A.nm.m, X, FZN_MESSAGE_OUT, id2) == FZN_MESSAGE_DELIVERED
	              && fzn_messages_state(&A.nm.m, X, FZN_MESSAGE_IN, id3) == 0u,
	      "a delivered line, or one received, was marked");
	CHECK(fzn_messages_state(&A.nm.m, Y, FZN_MESSAGE_OUT, id3) == FZN_MESSAGE_HANDED_OVER,
	      "a line handed over for a contact that stands was given up on");
	CHECK(fzn_node_messages_give_up(&A.nm, y_stands, x_removed, NULL, &marked) == FZN_MESSAGES_OK
	              && marked == 0u,
	      "a line given up on was marked again");
	/* THE ANSWER TRAVELS: B, which reads A's stream, holds the state too. */
	synced(&B);
	CHECK(fzn_node_messages_absorb(&B.nm, &t) == FZN_MESSAGES_OK
	              && fzn_messages_state(&B.nm.m, X, FZN_MESSAGE_OUT, id1)
	                         == FZN_MESSAGE_NOT_DELIVERED,
	      "the not-delivered mark is not B's state once carried");
	CHECK(fzn_node_messages_give_up(&A.nm, NULL, NULL, NULL, &marked) == FZN_MESSAGES_ERR_MALFORMED,
	      "a pass with no way to tell who stands was run");
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

/* ---- a returning device, sec 564: lines by bucket, not by journal ---------- */

/* EVERY ITEM `from` holds of conversation X, filed at `to` as a round
 * would file them: how many filed, and how many of those wait for a key. */
static int file_all(device_t *from, device_t *to, size_t *filed, size_t *waiting)
{
	static fzn_bucket_t buckets[512];
	static uint8_t ids[16][FZN_BUCKETS_ID_LEN], item[FZN_BUCKETS_ITEM_MAX];
	size_t nb = 0, b, n, i, len;
	uint64_t total;

	*filed = *waiting = 0;
	if (fzn_buckets_list(&from->nm.buckets, FZN_BUCKETS_MESSAGES, buckets, 512u, &nb)
	    != FZN_BUCKETS_OK)
		return 0;
	for (b = 0; b < nb; b++) {
		if (fzn_buckets_ids(&from->nm.buckets, FZN_BUCKETS_MESSAGES, buckets[b].subject,
		                    buckets[b].month, 0u, ids, 16u, &n, &total)
		    != FZN_BUCKETS_OK)
			return 0;
		for (i = 0; i < n; i++) {
			int wait = 0;
			fzn_messages_err_t err;

			if (fzn_buckets_has(&to->nm.buckets, FZN_BUCKETS_MESSAGES, ids[i]))
				continue;
			if (fzn_buckets_item(&from->nm.buckets, FZN_BUCKETS_MESSAGES, ids[i], item,
			                     sizeof(item), &len, NULL, NULL)
			    != FZN_BUCKETS_OK)
				return 0;
			err = fzn_node_messages_file(&to->nm, buckets[b].subject, buckets[b].month, item,
			                             len, &wait);
			if (err == FZN_MESSAGES_ERR_GONE)
				continue;
			if (err != FZN_MESSAGES_OK)
				return 0;
			(*filed)++;
			*waiting += (size_t)wait;
		}
	}
	return 1;
}

/* One item of `d`'s, the first of its first bucket, into `out`. */
static size_t first_item(device_t *d, uint8_t *out, uint8_t subject[FZN_PUBKEY_LEN],
                         uint32_t *month)
{
	fzn_bucket_t k;
	uint8_t id[1][FZN_BUCKETS_ID_LEN];
	size_t n = 0, len = 0;
	uint64_t total;

	if (fzn_buckets_list(&d->nm.buckets, FZN_BUCKETS_MESSAGES, &k, 1u, &n) != FZN_BUCKETS_OK
	    || n != 1u
	    || fzn_buckets_ids(&d->nm.buckets, FZN_BUCKETS_MESSAGES, k.subject, k.month, 0u, id, 1u,
	                       &n, &total)
	               != FZN_BUCKETS_OK
	    || n != 1u
	    || fzn_buckets_item(&d->nm.buckets, FZN_BUCKETS_MESSAGES, id[0], out,
	                        FZN_BUCKETS_ITEM_MAX, &len, subject, month)
	               != FZN_BUCKETS_OK)
		return 0;
	return len;
}

static void test_a_returning_device_files_lines(void)
{
	static uint8_t item[FZN_BUCKETS_ITEM_MAX];
	uint8_t id[FZN_MESSAGE_ID_LEN], subject[FZN_PUBKEY_LEN];
	char text[FZN_MESSAGE_TEXT_MAX];
	uint32_t month = 0;
	size_t filed = 0, waiting = 0, len;
	fzn_bucket_t r, m;
	serve_t s;

	setup();
	device_up(&M, 0x44);
	device_up(&R, 0x55);
	host_up(&M, &R);
	host_up(&R, &M);
	memset(text, 'z', sizeof(text));
	memset(id, 0x71, sizeof(id));
	CHECK(fzn_messages_write(&R.nm.m, X, FZN_MESSAGE_OUT, id, 1u, "one", 3u) == FZN_MESSAGES_OK,
	      "fixture: R writes a line");
	id[0] = 0x72;
	CHECK(fzn_messages_write(&R.nm.m, X, FZN_MESSAGE_IN, id, 2u, text, sizeof(text))
	              == FZN_MESSAGES_OK,
	      "fixture: R writes a line of two parts");
	CHECK(rows_in(&R.store, FZN_PERSIST_BUCKET_ITEM) == 2u
	              && rows_in(&R.store, FZN_PERSIST_BUCKET) == 1u,
	      "R's two lines are not two items in one bucket");

	/* M's journal holds none of R's stream: only the items reach it. */
	CHECK(file_all(&R, &M, &filed, &waiting) && filed == 2u && waiting == 2u,
	      "M did not file R's two lines, each waiting for R's key");
	CHECK(fzn_buckets_list(&R.nm.buckets, FZN_BUCKETS_MESSAGES, &r, 1u, &len) == FZN_BUCKETS_OK
	              && fzn_buckets_list(&M.nm.buckets, FZN_BUCKETS_MESSAGES, &m, 1u, &len)
	                         == FZN_BUCKETS_OK
	              && r.count == 2u && m.count == 2u
	              && memcmp(r.digest, m.digest, sizeof(r.digest)) == 0,
	      "after filing, M's bucket is not R's");
	CHECK(!one_line_is(&M, 0x71, 0u, "one"), "a line opened before its key was here");
	CHECK(file_all(&R, &M, &filed, &waiting) && filed == 0u,
	      "a second pass filed again what M holds");

	/* M RESTARTS before its key round: nothing in its journal names R's
	 * month, so only the wants kept in its store can ask for the key. */
	(void)fzn_node_messages_init(&M.nm, &M.store_ops, &M.journal, M.pub, &M.sign, &RNG, &AEAD,
	                             &HASH, now_ms);
	(void)fzn_node_messages_devices(&M.nm, (const uint8_t(*)[FZN_PUBKEY_LEN])R.pub, 1u);
	CHECK(fzn_node_messages_absorb(&M.nm, &t) == FZN_MESSAGES_OK && t.lacking == 1u,
	      "after a restart M does not lack the key its filed lines wait for");
	s.to = &R;
	s.from = &M;
	s.pushed = 0;
	memset(&t, 0, sizeof(t));
	CHECK(fzn_node_messages_round(&M.nm, serve, &s, &t) && t.taken == 1u
	              && one_line_is(&M, 0x71, 0u, "one"),
	      "the key was not taken, or the filed line did not open");
	id[0] = 0x72;
	{
		static fzn_message_t page[FZN_MESSAGES_PAGE_MAX];
		size_t count = 0, i;
		int more = 0, whole = 0;

		if (fzn_messages_page(&M.nm.m, X, 0u, page, FZN_MESSAGES_PAGE_MAX, &count, &more)
		    == FZN_MESSAGES_OK)
			for (i = 0; i < count; i++)
				if (page[i].id[0] == 0x72)
					whole = page[i].readable && page[i].text_len == sizeof(text)
					        && memcmp(page[i].text, text, sizeof(text)) == 0;
		CHECK(whole, "the line of two parts did not open whole");
	}
	CHECK(fzn_node_messages_absorb(&M.nm, &t) == FZN_MESSAGES_OK && t.lacking == 0u,
	      "a want whose key arrived is still kept");

	/* WHAT IS NOT FILED: a line under another month than it came from, a
	 * byte changed in its record, one a device not the user's signed. */
	len = first_item(&R, item, subject, &month);
	CHECK(len > 0u
	              && fzn_node_messages_file(&M.nm, subject, month + 1u, item, len, NULL)
	                         == FZN_MESSAGES_ERR_REFUSED,
	      "a line offered under another month was filed");
	item[len - 1u] ^= 0x01u;
	CHECK(fzn_node_messages_file(&M.nm, subject, month, item, len, NULL)
	              == FZN_MESSAGES_ERR_REFUSED,
	      "a line whose signature fails was filed");
	memset(id, 0x73, sizeof(id));
	CHECK(fzn_messages_write(&H.nm.m, X, FZN_MESSAGE_OUT, id, 3u, "other", 5u)
	                      == FZN_MESSAGES_OK
	              && (len = first_item(&H, item, subject, &month)) > 0u
	              && fzn_node_messages_file(&M.nm, subject, month, item, len, NULL)
	                         == FZN_MESSAGES_ERR_REFUSED,
	      "a line another user's device signed was filed");

	/* A TRIMMED MONTH lets its items go and takes none back. */
	CHECK(fzn_messages_forget_epoch(&M.nm.m, X, m.month) == FZN_MESSAGES_OK
	              && fzn_buckets_gone(&M.nm.buckets, FZN_BUCKETS_MESSAGES, X, m.month)
	              && rows_in(&M.store, FZN_PERSIST_BUCKET_ITEM) == 0u,
	      "a trimmed month kept its items");
	CHECK(file_all(&R, &M, &filed, &waiting) && filed == 0u
	              && rows_in(&M.store, FZN_PERSIST_BUCKET_ITEM) == 0u,
	      "a trimmed month took its items back");
}

/* A LINE PUSHED AND KEPT, sec 569: its key is this device's to give when
 * this device wrote it, and another device's when it did not. */
static void test_a_pushed_line_owes_its_key(void)
{
	static uint8_t item[FZN_BUCKETS_ITEM_MAX];
	uint8_t id[FZN_MESSAGE_ID_LEN], subject[FZN_PUBKEY_LEN];
	uint32_t month = 0;
	size_t len;

	setup();
	device_up(&M, 0x44);
	device_up(&R, 0x55);
	host_up(&M, &R);
	host_up(&R, &M);
	memset(id, 0x91, sizeof(id));
	CHECK(fzn_messages_write(&R.nm.m, X, FZN_MESSAGE_OUT, id, 1u, "pushed", 6u)
	              == FZN_MESSAGES_OK
	              && (len = first_item(&R, item, subject, &month)) > 0u,
	      "fixture: R writes a line and holds its item");
	R.nm.n_gives = 0;
	fzn_node_messages_pushed(&R.nm, subject, month, item, len);
	CHECK(R.nm.n_gives == 1u && memcmp(R.nm.gives[0].device, R.pub, FZN_PUBKEY_LEN) == 0
	              && R.nm.gives[0].epoch == month,
	      "R's own line pushed and kept did not owe R's key for its month");
	M.nm.n_gives = 0;
	fzn_node_messages_pushed(&M.nm, subject, month, item, len);
	CHECK(M.nm.n_gives == 0u, "a line another device wrote owed this device's key");
}

/* LINES TAKEN BEFORE ITEMS WERE KEPT get theirs from the journal, once. */
static void test_backfill_from_the_journal(void)
{
	uint8_t id[FZN_MESSAGE_ID_LEN];
	size_t added = 9u;

	setup();
	A.nm.m.items = NULL;
	B.nm.m.items = NULL;
	memset(id, 0x81, sizeof(id));
	CHECK(fzn_messages_write(&B.nm.m, X, FZN_MESSAGE_IN, id, 1u, "early", 5u) == FZN_MESSAGES_OK
	              && fzn_messages_write(&A.nm.m, X, FZN_MESSAGE_OUT, id, 2u, "mine", 4u)
	                         == FZN_MESSAGES_OK,
	      "fixture: two lines written with no items kept");
	synced(&A);
	CHECK(fzn_node_messages_absorb(&A.nm, &t) == FZN_MESSAGES_OK
	              && rows_in(&A.store, FZN_PERSIST_BUCKET_ITEM) == 0u,
	      "fixture: A absorbs B's line, keeping no item");
	A.nm.m.items = &A.nm.items;
	CHECK(fzn_messages_items_backfill(&A.nm.m, &added) == FZN_MESSAGES_OK && added == 2u
	              && rows_in(&A.store, FZN_PERSIST_BUCKET_ITEM) == 2u,
	      "the backfill did not keep both lines' items");
	CHECK(fzn_messages_items_backfill(&A.nm.m, &added) == FZN_MESSAGES_OK && added == 0u,
	      "a second backfill ran again");
	B.nm.m.items = &B.nm.items;
	id[0] = 0x82;
	CHECK(fzn_messages_write(&B.nm.m, X, FZN_MESSAGE_IN, id, 3u, "later", 5u) == FZN_MESSAGES_OK,
	      "fixture: B writes a line with items kept");
	synced(&A);
	CHECK(fzn_node_messages_absorb(&A.nm, &t) == FZN_MESSAGES_OK
	              && rows_in(&A.store, FZN_PERSIST_BUCKET_ITEM) == 3u,
	      "a line A absorbed from the journal kept no item");
}

/* THE CUT POINT, sec 548: a line of two parts, absorbed. A cut never ends on
 * its first part -- that is read back when the last is taken in -- whether
 * the absorb stopped there or not; it goes no further than what was
 * absorbed; and nothing younger than the window's edge goes. */
static void test_a_cut_keeps_a_line_whole(void)
{
	static uint8_t buf[FZN_RECORD_MAX_LEN];
	uint8_t id[FZN_MESSAGE_ID_LEN];
	char text[FZN_MESSAGE_TEXT_MAX];
	uint64_t held, s, first = 0, *at = NULL;
	size_t k;

	setup();
	memset(id, 0x41, sizeof(id));
	memset(text, 'w', sizeof(text));
	CHECK(fzn_messages_write(&A.nm.m, X, FZN_MESSAGE_OUT, id, 7u, text, sizeof(text))
	              == FZN_MESSAGES_OK
	              && fzn_node_messages_absorb(&A.nm, &t) == FZN_MESSAGES_OK,
	      "fixture: A writes a line of the whole 512 bytes, and absorbs it");
	held = fzn_node_journal_received(&A.journal, A.pub, FZN_MESSAGE_STREAM);
	for (s = 1u; s <= held && !first; s++) {
		fzn_message_part_t p;
		fzn_record_t rec;

		if (fzn_record_store_get(&A.journal.store, A.pub, FZN_MESSAGE_STREAM, s, buf,
		                         sizeof(buf), &rec) == FZN_RECORD_STORE_OK
		    && fzn_record_kind(rec) == FZN_MESSAGE_LINE_KIND
		    && fzn_message_line_read(fzn_record_body(rec), fzn_record_body_len(rec), &p)
		    && p.part == 0u && p.parts == 2u)
			first = s;
	}
	for (k = 0; k < A.nm.n_cursors; k++)
		if (memcmp(A.nm.cursors[k].key, A.pub, FZN_PUBKEY_LEN) == 0)
			at = &A.nm.cursors[k].at;
	CHECK(first != 0u && at && *at == held, "fixture: the line's first part, and A's cursor");
	if (!first || !at)
		return;
	CHECK(fzn_node_messages_cut_point(&A.nm, A.pub, UINT64_MAX) == held + 1u,
	      "everything absorbed and older did not go");
	*at = first;
	CHECK(fzn_node_messages_cut_point(&A.nm, A.pub, UINT64_MAX) == first,
	      "a cut ended on a line's first part");
	*at = first - 1u;
	CHECK(fzn_node_messages_cut_point(&A.nm, A.pub, UINT64_MAX) == first,
	      "a cut went past what was absorbed");
	*at = held;
	CHECK(fzn_node_messages_cut_point(&A.nm, A.pub, 0u) == 1u,
	      "a record younger than the window's edge went");
}

/* ---- delivery to a contact, sec 613 ----------------------------------------- */

static device_t S, C; /* a sender, and its contact's host */

/* THE CONTACT'S HOST ANSWERING, as fuzznetd's contact branch does: the
 * line filed under the sender's key when it keeps messages. `mode` 1 does
 * not answer; 2 answers another line's id; 3 answers a length short. */
typedef struct contact_link {
	int keeps;
	int mode;
	size_t asked;
} contact_link_t;

static int to_contact(void *ctx, const uint8_t *request, size_t request_len, uint8_t *out,
                      size_t out_cap, size_t *out_len)
{
	contact_link_t *l = (contact_link_t *)ctx;
	size_t n;

	l->asked++;
	if (l->mode == 1)
		return 0;
	n = fzn_node_messages_contact(&C.nm, S.pub, l->keeps, request, request_len, out, out_cap);
	if (!n)
		return 0;
	if (l->mode == 2)
		out[2] ^= 0x01u;
	if (l->mode == 3)
		n--;
	*out_len = n;
	return 1;
}

static uint8_t state_of_line(device_t *d, const uint8_t contact[FZN_PUBKEY_LEN], uint8_t first,
                             uint8_t direction, size_t *found)
{
	static fzn_message_t page[FZN_MESSAGES_PAGE_MAX];
	size_t count = 0, i;
	uint8_t state = 0xffu;
	int more = 0;

	*found = 0;
	if (fzn_messages_page(&d->nm.m, contact, 0u, page, FZN_MESSAGES_PAGE_MAX, &count, &more)
	    != FZN_MESSAGES_OK)
		return 0xffu;
	for (i = 0; i < count; i++)
		if (page[i].id[0] == first && page[i].direction == direction) {
			(*found)++;
			state = page[i].state;
		}
	return state;
}

static fzn_node_messages_delivery_t dv;

static int deliver(contact_link_t *l)
{
	return fzn_node_messages_deliver(&S.nm, C.pub, 0, to_contact, l, &dv) == FZN_MESSAGES_OK;
}

static void test_a_line_is_delivered_to_a_contact(void)
{
	contact_link_t l = { 1, 0, 0 };
	uint8_t id[FZN_MESSAGE_ID_LEN];
	size_t found = 0;
	static fzn_message_t page[FZN_MESSAGES_PAGE_MAX];
	size_t count = 0;
	int more = 0;

	setup();
	device_up(&S, 0x66);
	device_up(&C, 0x77);
	host_up(&S, &S);
	host_up(&C, &C);

	memset(id, 0x71, sizeof(id));
	CHECK(fzn_messages_write(&S.nm.m, C.pub, FZN_MESSAGE_OUT, id, 7u, "hello there", 11u)
	              == FZN_MESSAGES_OK,
	      "fixture: the sender writes a line to its contact");
	memset(id, 0x72, sizeof(id));
	CHECK(fzn_messages_write(&S.nm.m, C.pub, FZN_MESSAGE_IN, id, 8u, "an earlier reply", 16u)
	              == FZN_MESSAGES_OK,
	      "fixture: and holds one it received");

	CHECK(deliver(&l) && dv.sent == 1u && dv.delivered == 1u && l.asked == 1u
	              && state_of_line(&S, C.pub, 0x71, FZN_MESSAGE_OUT, &found)
	                         == FZN_MESSAGE_DELIVERED
	              && found == 1u,
	      "the line being sent is offered alone, held, and marked delivered");
	CHECK(fzn_messages_page(&C.nm.m, S.pub, 0u, page, FZN_MESSAGES_PAGE_MAX, &count, &more)
	                      == FZN_MESSAGES_OK
	              && count == 1u && page[0].direction == FZN_MESSAGE_IN && page[0].id[0] == 0x71
	              && page[0].stime == 7u && page[0].readable && page[0].text_len == 11u
	              && memcmp(page[0].text, "hello there", 11u) == 0,
	      "the contact's host files it IN under the sender, time and text whole");
	CHECK(deliver(&l) && dv.sent == 0u && l.asked == 1u,
	      "a delivered line is not offered again");


	/* A RE-OFFER, as after a reply lost: held again, filed once. */
	{
		uint8_t req[FZN_NODE_MESSAGES_DELIVER_MAX], out[64];
		size_t n;

		req[0] = FZN_NODE_MESSAGES_VERSION;
		req[1] = FZN_NODE_MESSAGES_DELIVER;
		memset(req + 2, 0x71, FZN_MESSAGE_ID_LEN);
		memset(req + 2 + FZN_MESSAGE_ID_LEN, 0, 8u);
		req[2 + FZN_MESSAGE_ID_LEN + 7] = 7u;
		req[2 + FZN_MESSAGE_ID_LEN + 8] = 0u;
		req[2 + FZN_MESSAGE_ID_LEN + 9] = 11u;
		memcpy(req + FZN_NODE_MESSAGES_DELIVER_HEAD_LEN, "hello there", 11u);
		n = fzn_node_messages_contact(&C.nm, S.pub, 1, req,
		                              FZN_NODE_MESSAGES_DELIVER_HEAD_LEN + 11u, out, sizeof(out));
		CHECK(n == FZN_NODE_MESSAGES_DELIVERED_LEN && out[2 + FZN_MESSAGE_ID_LEN]
		                                                     == FZN_NODE_MESSAGES_HELD
		              && fzn_messages_page(&C.nm.m, S.pub, 0u, page, FZN_MESSAGES_PAGE_MAX,
		                                   &count, &more)
		                         == FZN_MESSAGES_OK
		              && count == 1u,
		      "a re-offer is answered held and files nothing twice");
		CHECK(fzn_node_messages_contact(&C.nm, S.pub, 1, req,
		                                FZN_NODE_MESSAGES_DELIVER_HEAD_LEN + 10u, out,
		                                sizeof(out))
		                      == 0u
		              && fzn_node_messages_contact(&C.nm, S.pub, 1, req,
		                                           FZN_NODE_MESSAGES_DELIVER_HEAD_LEN + 12u,
		                                           out, sizeof(out))
		                         == 0u,
		      "a text shorter or longer than its length says is no delivery");
		req[1] = FZN_NODE_MESSAGES_GIVE;
		CHECK(fzn_node_messages_contact(&C.nm, S.pub, 1, req,
		                                FZN_NODE_MESSAGES_DELIVER_HEAD_LEN + 11u, out,
		                                sizeof(out))
		              == 0u,
		      "a member's message on the contact branch is not one");
	}

	/* BY STEPS, sec 636, over more lines than a page: each offered once,
	 * held, and marked, the page read again between them. */
	{
		static fzn_node_messages_delivering_t d;
		uint8_t req[FZN_NODE_MESSAGES_DELIVER_MAX], out[64];
		size_t req_len = 0, out_len, k, turns = 0;
		int done = 0;
		fzn_messages_err_t err;

		for (k = 0; k < FZN_MESSAGES_PAGE_MAX + 5u; k++) {
			memset(id, 0x30, sizeof(id));
			id[1] = (uint8_t)k;
			CHECK(fzn_messages_write(&S.nm.m, C.pub, FZN_MESSAGE_OUT, id, 20u + k, "by steps",
			                         8u) == FZN_MESSAGES_OK,
			      "fixture: a page and more of lines to send");
		}
		err = fzn_node_messages_deliver_begin(&d, &S.nm, C.pub, 0, req, sizeof(req), &req_len,
		                                      &done);
		while (err == FZN_MESSAGES_OK && !done && turns++ < 64u) {
			out_len = 0;
			(void)to_contact(&l, req, req_len, out, sizeof(out), &out_len);
			err = fzn_node_messages_deliver_step(&d, out, out_len, req, sizeof(req), &req_len,
			                                     &done);
		}
		CHECK(err == FZN_MESSAGES_OK && done && d.tally.sent == FZN_MESSAGES_PAGE_MAX + 5u
		              && d.tally.delivered == FZN_MESSAGES_PAGE_MAX + 5u
		              && deliver(&l) && dv.sent == 0u,
		      "a page and more of lines by steps were not each delivered once");
		CHECK(fzn_node_messages_deliver_begin(&d, &S.nm, C.pub, 1, req, sizeof(req), &req_len,
		                                      &done) == FZN_MESSAGES_OK
		              && !done
		              && fzn_node_messages_deliver_step(&d, NULL, 0, req, sizeof(req), &req_len,
		                                                &done) == FZN_MESSAGES_OK
		              && done && d.tally.unanswered == 1u
		              && fzn_node_messages_deliver_step(&d, out, 8, req, sizeof(req), &req_len,
		                                                &done) == FZN_MESSAGES_ERR_MALFORMED,
		      "a delivery with no answer did not end, counting it, refusing a step after");
	}
}

/* A DELIVERY CUT AT EVERY SAVE OF THE CONTACT'S HOST, sec 748: a crash
 * while the host files a line, then a restart, its store and records as the
 * cut left them. The sender heard no answer, so it offers the line again --
 * `absorb` 1 after the host has absorbed its journal, 0 before -- and the
 * line is answered held, filed once, and listed once, whole. */
static int delivery_cut_at(long k, int absorb, int *cut)
{
	static fzn_message_t page[FZN_MESSAGES_PAGE_MAX];
	uint8_t req[FZN_NODE_MESSAGES_DELIVER_MAX], out[64];
	size_t req_len = FZN_NODE_MESSAGES_DELIVER_HEAD_LEN + 11u, count = 0, i, n, found = 0;
	int more = 0, whole = 0;

	setup();
	device_up(&S, 0x66);
	device_up(&C, 0x77);
	host_up(&S, &S);
	host_up(&C, &S);
	req[0] = FZN_NODE_MESSAGES_VERSION;
	req[1] = FZN_NODE_MESSAGES_DELIVER;
	memset(req + 2, 0x71, FZN_MESSAGE_ID_LEN);
	memset(req + 2 + FZN_MESSAGE_ID_LEN, 0, 8u);
	req[2 + FZN_MESSAGE_ID_LEN + 7] = 7u;
	req[2 + FZN_MESSAGE_ID_LEN + 8] = 0u;
	req[2 + FZN_MESSAGE_ID_LEN + 9] = 11u;
	memcpy(req + FZN_NODE_MESSAGES_DELIVER_HEAD_LEN, "hello there", 11u);
	saves_cut = 0;
	saves_left = k;
	(void)fzn_node_messages_contact(&C.nm, S.pub, 1, req, req_len, out, sizeof(out));
	saves_left = -1;
	*cut = saves_cut != 0u;
	if (!*cut)
		return 1;
	/* STARTED AGAIN: its store and records kept, all else fresh. */
	(void)fzn_node_journal_init_store(&C.journal, &C.own_ops, &C.sign, &HASH);
	(void)fzn_node_messages_init(&C.nm, &C.store_ops, &C.journal, C.pub, &C.sign, &RNG, &AEAD,
	                             &HASH, now_ms);
	(void)fzn_node_messages_devices(&C.nm, (const uint8_t(*)[FZN_PUBKEY_LEN])S.pub, 1u);
	if (absorb && fzn_node_messages_absorb(&C.nm, &t) != FZN_MESSAGES_OK) {
		fprintf(stderr, "    cut at save %ld: the host would not absorb\n", k);
		return 0;
	}
	n = fzn_node_messages_contact(&C.nm, S.pub, 1, req, req_len, out, sizeof(out));
	if (n != FZN_NODE_MESSAGES_DELIVERED_LEN
	    || out[2 + FZN_MESSAGE_ID_LEN] != FZN_NODE_MESSAGES_HELD) {
		fprintf(stderr, "    cut at save %ld: the line offered again was not held\n", k);
		return 0;
	}
	if (fzn_node_messages_absorb(&C.nm, &t) != FZN_MESSAGES_OK
	    || fzn_messages_page(&C.nm.m, S.pub, 0u, page, FZN_MESSAGES_PAGE_MAX, &count, &more)
	               != FZN_MESSAGES_OK)
		return 0;
	for (i = 0; i < count; i++)
		if (page[i].id[0] == 0x71u && page[i].direction == FZN_MESSAGE_IN) {
			found++;
			whole += page[i].readable && page[i].stime == 7u && page[i].text_len == 11u
			         && memcmp(page[i].text, "hello there", 11u) == 0;
		}
	/* FILED ONCE, in the host's own stream: a listing shows an id once
	 * however often it was filed, so the records are counted. */
	for (i = 0, n = 0; i < C.own.n; i++) {
		fzn_record_t rec;

		n += C.own.r[i].stream == FZN_MESSAGE_STREAM
		     && fzn_record_open(C.own.r[i].bytes, C.own.r[i].len, &rec) == FZN_RECORD_OK
		     && fzn_record_kind(rec) == FZN_MESSAGE_LINE_KIND;
	}
	if (found != 1u || whole != 1 || n != 1u) {
		fprintf(stderr, "    cut at save %ld%s: listed %zu times, %d whole, filed %zu times\n",
		        k, absorb ? " absorbed first" : "", found, whole, n);
		return 0;
	}
	return 1;
}

static void test_a_delivery_cut_at_every_save(void)
{
	int cuts[2] = { 0, 0 }, ends[2] = { 0, 0 }, all_ok = 1, cut = 0, absorb;
	long k;

	for (absorb = 0; absorb < 2; absorb++)
		for (k = 0; k < 64; k++) {
			all_ok &= delivery_cut_at(k, absorb, &cut);
			if (!cut) {
				ends[absorb] = 1;
				break;
			}
			cuts[absorb]++;
		}
	CHECK(cuts[0] && cuts[1] && ends[0] && ends[1],
	      "fixture: a delivery's saves were cut, and a budget passed them all");
	CHECK(all_ok, "a delivery cut at a save was not held when offered again, or was filed or "
	              "listed other than once");
}

static void test_a_host_that_keeps_none_refuses(void)
{
	contact_link_t l = { 0, 0, 0 };
	uint8_t id[FZN_MESSAGE_ID_LEN];
	size_t found = 0, count = 0;
	static fzn_message_t page[FZN_MESSAGES_PAGE_MAX];
	int more = 0;

	setup();
	device_up(&S, 0x66);
	device_up(&C, 0x77);
	host_up(&S, &S);
	host_up(&C, &C);
	memset(id, 0x81, sizeof(id));
	(void)fzn_messages_write(&S.nm.m, C.pub, FZN_MESSAGE_OUT, id, 1u, "one", 3u);
	memset(id, 0x82, sizeof(id));
	(void)fzn_messages_write(&S.nm.m, C.pub, FZN_MESSAGE_OUT, id, 2u, "two", 3u);

	CHECK(deliver(&l) && dv.sent == 1u && dv.refused == 1u && dv.delivered == 0u
	              && l.asked == 1u
	              && state_of_line(&S, C.pub, 0x81, FZN_MESSAGE_OUT, &found) == 0u
	              && state_of_line(&S, C.pub, 0x82, FZN_MESSAGE_OUT, &found) == 0u
	              && fzn_messages_page(&C.nm.m, S.pub, 0u, page, FZN_MESSAGES_PAGE_MAX, &count,
	                                   &more)
	                         == FZN_MESSAGES_OK
	              && count == 0u,
	      "refused: one offer, nothing filed there, both lines still being sent");

	l.keeps = 1;
	l.mode = 1;
	CHECK(deliver(&l) && dv.sent == 1u && dv.unanswered == 1u && l.asked == 2u
	              && state_of_line(&S, C.pub, 0x81, FZN_MESSAGE_OUT, &found) == 0u,
	      "unanswered: one offer, and the lines wait");
	l.mode = 2;
	CHECK(deliver(&l) && dv.unanswered == 1u && dv.delivered == 0u
	              && state_of_line(&S, C.pub, 0x82, FZN_MESSAGE_OUT, &found) == 0u,
	      "an answer naming another line is no answer, and marks nothing");
	l.mode = 3;
	CHECK(deliver(&l) && dv.unanswered == 1u && dv.delivered == 0u,
	      "an answer cut short is no answer");
	l.mode = 0;
	CHECK(deliver(&l) && dv.sent == 2u && dv.delivered == 2u
	              && state_of_line(&S, C.pub, 0x81, FZN_MESSAGE_OUT, &found)
	                         == FZN_MESSAGE_DELIVERED
	              && state_of_line(&S, C.pub, 0x82, FZN_MESSAGE_OUT, &found)
	                         == FZN_MESSAGE_DELIVERED,
	      "a host that keeps them takes both");
}

static void test_another_devices_line_is_its_own_to_send(void)
{
	contact_link_t l = { 1, 0, 0 };
	uint8_t id[FZN_MESSAGE_ID_LEN];
	fzn_node_messages_tally_t absorbed;
	fzn_node_messages_delivery_t d;

	setup();
	device_up(&C, 0x77);
	host_up(&C, &C);
	memset(id, 0x91, sizeof(id));
	CHECK(fzn_messages_write(&A.nm.m, C.pub, FZN_MESSAGE_OUT, id, 1u, "from A", 6u)
	                      == FZN_MESSAGES_OK
	              && (synced(&B), fzn_node_messages_absorb(&B.nm, &absorbed)) == FZN_MESSAGES_OK
	              && round_with(&B, &A) && readable_on(&B) == 1,
	      "fixture: A writes a line, and B holds it and can read it");
	memcpy(S.pub, A.pub, FZN_PUBKEY_LEN); /* to_contact files under S's key */
	CHECK(fzn_node_messages_deliver(&B.nm, C.pub, 0, to_contact, &l, &d) == FZN_MESSAGES_OK
	              && d.sent == 0u && l.asked == 0u,
	      "B does not offer A's line");
	CHECK(fzn_node_messages_deliver(&A.nm, C.pub, 0, to_contact, &l, &d) == FZN_MESSAGES_OK
	              && d.sent == 1u && d.delivered == 1u,
	      "A does");
}

/* ---- settlement, sec 615 ----------------------------------------------------- */

/* THE RECIPIENT'S HOST IS A, B ANOTHER OF ITS USER'S DEVICES: a line S
 * delivers is filed at A, and A asks B whether it holds it. */
static int to_a(void *ctx, const uint8_t *request, size_t request_len, uint8_t *out,
                size_t out_cap, size_t *out_len)
{
	size_t n;

	(void)ctx;
	n = fzn_node_messages_contact(&A.nm, S.pub, 1, request, request_len, out, out_cap);
	if (!n)
		return 0;
	*out_len = n;
	return 1;
}

static int b_keeps;

static int b_keeps_none(void *ctx, const uint8_t contact[FZN_PUBKEY_LEN])
{
	(void)ctx;
	(void)contact;
	return b_keeps;
}

static fzn_node_messages_settlement_t st;

static int settle_a(link_t *to_b)
{
	fzn_node_messages_member_t member = { B.pub, to_b ? over : NULL, to_b };

	return fzn_node_messages_settle(&A.nm, &member, 1u, 16u, &st) == FZN_MESSAGES_OK;
}

static void test_a_line_settles_once_every_keeping_device_holds_it(void)
{
	link_t a_to_b = { &B, &A, 0 };
	fzn_node_messages_tally_t absorbed;
	fzn_node_messages_delivery_t d;
	uint8_t id[FZN_MESSAGE_ID_LEN];
	size_t found = 0;

	setup();
	device_up(&S, 0x66);
	host_up(&S, &S);
	b_keeps = 1;
	B.nm.keeps = b_keeps_none;
	memset(id, 0xa1, sizeof(id));
	CHECK(fzn_messages_write(&S.nm.m, A.pub, FZN_MESSAGE_OUT, id, 1u, "settle me", 9u)
	                      == FZN_MESSAGES_OK
	              && fzn_node_messages_deliver(&S.nm, A.pub, 0, to_a, NULL, &d) == FZN_MESSAGES_OK
	              && d.delivered == 1u
	              && state_of_line(&S, A.pub, 0xa1, FZN_MESSAGE_OUT, &found)
	                         == FZN_MESSAGE_DELIVERED,
	      "fixture: S's line delivered to A");
	CHECK(settle_a(NULL) && st.weighed == 1u && st.settled == 0u && st.waiting == 1u,
	      "a member that cannot be reached leaves the line unsettled");
	CHECK(settle_a(&a_to_b) && st.settled == 0u && st.waiting == 1u,
	      "a member keeping messages and lacking the line leaves it unsettled");
	CHECK(fzn_node_messages_deliver(&S.nm, A.pub, 1, to_a, NULL, &d) == FZN_MESSAGES_OK
	              && d.sent == 1u && d.settled == 0u && d.delivered == 0u
	              && state_of_line(&S, A.pub, 0xa1, FZN_MESSAGE_OUT, &found)
	                         == FZN_MESSAGE_DELIVERED,
	      "re-offered before it settles, it stays delivered");
	synced(&B);
	CHECK(fzn_node_messages_absorb(&B.nm, &absorbed) == FZN_MESSAGES_OK && settle_a(&a_to_b)
	              && st.settled == 1u
	              && state_of_line(&A, S.pub, 0xa1, FZN_MESSAGE_IN, &found)
	                         == FZN_MESSAGE_SETTLED,
	      "once B holds it, A marks it settled");
	CHECK(settle_a(&a_to_b) && st.weighed == 0u, "a settled line is weighed no more");
	CHECK(fzn_node_messages_deliver(&S.nm, A.pub, 0, to_a, NULL, &d) == FZN_MESSAGES_OK
	              && d.sent == 0u,
	      "a delivered line is not offered when settlement is not due");
	CHECK(fzn_node_messages_deliver(&S.nm, A.pub, 1, to_a, NULL, &d) == FZN_MESSAGES_OK
	              && d.sent == 1u && d.settled == 1u
	              && state_of_line(&S, A.pub, 0xa1, FZN_MESSAGE_OUT, &found)
	                         == FZN_MESSAGE_SETTLED,
	      "re-offered when due, it is answered settled and marked so");
	CHECK(fzn_node_messages_deliver(&S.nm, A.pub, 1, to_a, NULL, &d) == FZN_MESSAGES_OK
	              && d.sent == 0u,
	      "a settled line is offered no more");

	/* B DECLINES: it keeps none of S's lines, so A settles without it. */
	memset(id, 0xa2, sizeof(id));
	b_keeps = 0;
	CHECK(fzn_messages_write(&S.nm.m, A.pub, FZN_MESSAGE_OUT, id, 2u, "again", 5u)
	                      == FZN_MESSAGES_OK
	              && fzn_node_messages_deliver(&S.nm, A.pub, 0, to_a, NULL, &d) == FZN_MESSAGES_OK
	              && d.delivered == 1u && settle_a(&a_to_b) && st.settled == 1u,
	      "a member keeping none of the conversation does not hold settlement up");
	b_keeps = 1;
	B.nm.keeps = NULL;

	/* NO OTHER DEVICE: settled at once. */
	memset(id, 0xa3, sizeof(id));
	CHECK(fzn_messages_write(&S.nm.m, A.pub, FZN_MESSAGE_OUT, id, 3u, "alone", 5u)
	                      == FZN_MESSAGES_OK
	              && fzn_node_messages_deliver(&S.nm, A.pub, 0, to_a, NULL, &d) == FZN_MESSAGES_OK
	              && fzn_node_messages_settle(&A.nm, NULL, 0u, 16u, &st) == FZN_MESSAGES_OK
	              && st.settled == 1u,
	      "a recipient with no other device settles a line at once");
	CHECK(fzn_node_messages_settle(&B.nm, NULL, 0u, 16u, &st) == FZN_MESSAGES_OK
	              && st.weighed == 0u,
	      "a device that filed none of them weighs none");
}

static void test_a_holds_question_is_exact(void)
{
	uint8_t req[FZN_NODE_MESSAGES_HOLDS_LEN + 1u], out[64];

	setup();
	memset(req, 0, sizeof(req));
	req[0] = FZN_NODE_MESSAGES_VERSION;
	req[1] = FZN_NODE_MESSAGES_HOLDS;
	CHECK(fzn_node_messages_remote(&A.nm, B.pub, req, FZN_NODE_MESSAGES_HOLDS_LEN, out,
	                               sizeof(out))
	                      == FZN_NODE_MESSAGES_HOLDING_LEN
	              && out[2 + FZN_BUCKETS_ID_LEN] == FZN_NODE_MESSAGES_LACKS,
	      "an item not held is answered lacking");
	CHECK(fzn_node_messages_remote(&A.nm, B.pub, req, FZN_NODE_MESSAGES_HOLDS_LEN + 1u, out,
	                               sizeof(out))
	                      == 0u
	              && fzn_node_messages_remote(&A.nm, B.pub, req, FZN_NODE_MESSAGES_HOLDS_LEN - 1u,
	                                          out, sizeof(out))
	                         == 0u,
	      "a question a byte long or short was answered");
}

/* A WRITER GONE, sec 616: the device the caller says takes over sends it. */
static int takes;

static int b_takes_over(void *ctx, const uint8_t writer[FZN_PUBKEY_LEN],
                        const uint8_t id[FZN_MESSAGE_ID_LEN])
{
	(void)ctx;
	(void)id;
	return takes && memcmp(writer, A.pub, FZN_PUBKEY_LEN) == 0;
}

static void test_a_line_is_taken_over_from_a_writer_gone(void)
{
	contact_link_t l = { 1, 0, 0 };
	uint8_t id[FZN_MESSAGE_ID_LEN];
	fzn_node_messages_tally_t absorbed;
	fzn_node_messages_delivery_t d;
	size_t found = 0;

	setup();
	device_up(&C, 0x77);
	host_up(&C, &C);
	memcpy(S.pub, A.pub, FZN_PUBKEY_LEN); /* to_contact files under S's key */
	memset(id, 0x92, sizeof(id));
	CHECK(fzn_messages_write(&A.nm.m, C.pub, FZN_MESSAGE_OUT, id, 1u, "orphan", 6u)
	                      == FZN_MESSAGES_OK
	              && (synced(&B), fzn_node_messages_absorb(&B.nm, &absorbed)) == FZN_MESSAGES_OK
	              && round_with(&B, &A) && readable_on(&B) == 1,
	      "fixture: A writes a line, and B holds it and can read it");
	B.nm.takes_over = b_takes_over;
	takes = 0;
	CHECK(fzn_node_messages_deliver(&B.nm, C.pub, 0, to_contact, &l, &d) == FZN_MESSAGES_OK
	              && d.sent == 0u,
	      "B sent A's line while A is not gone");
	takes = 1;
	CHECK(fzn_node_messages_deliver(&B.nm, C.pub, 0, to_contact, &l, &d) == FZN_MESSAGES_OK
	              && d.sent == 1u && d.delivered == 1u
	              && state_of_line(&B, C.pub, 0x92, FZN_MESSAGE_OUT, &found)
	                         == FZN_MESSAGE_DELIVERED,
	      "B, taking A's line over, delivered it and marked it");
	B.nm.takes_over = NULL;
}

static void test_which_hosts_keep_messages(void)
{
	fzn_retain_rule_t r[2];
	uint8_t other[FZN_PUBKEY_LEN];

	memset(r, 0, sizeof(r));
	memset(other, 0x4f, sizeof(other));
	CHECK(fzn_messages_keeps(NULL, 0u, X), "no rule keeps");
	r[0].kind = FZN_RETAIN_POLICY;
	r[0].data = FZN_RETAIN_MESSAGES;
	r[0].drop = 1;
	CHECK(!fzn_messages_keeps(r, 1u, X), "a drop policy keeps none");
	r[0].data = FZN_RETAIN_LOG;
	CHECK(fzn_messages_keeps(r, 1u, X), "a log policy says nothing of messages");
	r[0].data = FZN_RETAIN_MESSAGES;
	r[1].kind = FZN_RETAIN_KEEP;
	r[1].data = FZN_RETAIN_MESSAGES;
	r[1].has_contact = 1;
	memcpy(r[1].contact, other, FZN_PUBKEY_LEN);
	CHECK(!fzn_messages_keeps(r, 2u, X) && fzn_messages_keeps(r, 2u, other),
	      "under drop, a keep rule keeps its own conversation only");
	r[1].has_contact = 0;
	CHECK(fzn_messages_keeps(r, 2u, X), "and one naming none keeps every one");
	r[1].kind = FZN_RETAIN_PRUNE;
	CHECK(!fzn_messages_keeps(r, 2u, X), "a prune rule keeps nothing");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	check_at(0, __LINE__, "deliberate");
	CHECK(failures == before + 1, "a failure counts");
	failures = before;
	checks -= 1;
}

/* SEVENTY DEVICES, sec 704: listed into the struct's own 32 the rest are
 * wanted, and given room all 71 list; their 70 month keys overrun the own
 * 64 lacked, and given room the next absorb notes all 70 again -- where the
 * dropped were learned only at the next start. */
/* WANTS PAST 256, sec 704: R writes one line in each of 260 months, M
 * files them all without R's keys, and after a restart lacks all 260 --
 * where the wants were one row of 256, and the rest never kept. */
static void test_wants_past_one_row(void)
{
	static fzn_node_message_key_t lacks[512], gives[512];
	uint8_t id[FZN_MESSAGE_ID_LEN];
	size_t filed = 0, waiting = 0, i;
	int wrote = 1;

	setup();
	device_up(&M, 0x46);
	device_up(&R, 0x57);
	host_up(&M, &R);
	host_up(&R, &M);
	for (i = 0; i < 260u && wrote; i++) {
		memset(id, 0x30, sizeof(id));
		id[0] = (uint8_t)(i >> 8);
		id[1] = (uint8_t)i;
		/* A MONTH APART, on the clock the device writes by. */
		clock_ms += 2678400000u;
		wrote = fzn_messages_write(&R.nm.m, X, FZN_MESSAGE_OUT, id, clock_ms, "w", 1u)
		        == FZN_MESSAGES_OK;
	}
	CHECK(wrote, "fixture: R writes a line in each of 260 months");
	CHECK(file_all(&R, &M, &filed, &waiting) && filed == 260u && waiting == 260u,
	      "M did not file 260 lines, each waiting for its month's key");
	(void)fzn_node_messages_init(&M.nm, &M.store_ops, &M.journal, M.pub, &M.sign, &RNG, &AEAD,
	                             &HASH, now_ms);
	(void)fzn_node_messages_use_keys(&M.nm, lacks, gives, 512u);
	(void)fzn_node_messages_devices(&M.nm, (const uint8_t(*)[FZN_PUBKEY_LEN])R.pub, 1u);
	CHECK(fzn_node_messages_absorb(&M.nm, &t) == FZN_MESSAGES_OK && t.lacking == 260u,
	      "after a restart M did not lack all 260 keys its filed lines wait for");
}

static void test_seventy_devices(void)
{
	static device_t W;
	static uint8_t keys[70][FZN_PUBKEY_LEN];
	static uint8_t room_devices[128][FZN_PUBKEY_LEN];
	static fzn_node_message_cursor_t room_cursors[128];
	static uint64_t room_at[128];
	static fzn_messages_work_t room_work[128];
	static fzn_node_message_key_t room_lacks[128], room_gives[128];
	uint8_t id[FZN_MESSAGE_ID_LEN];
	size_t i;
	int wrote = 1;

	setup();
	for (i = 0; i < 70u && wrote; i++) {
		device_up(&W, (uint8_t)(0x80u + i));
		memcpy(keys[i], W.pub, FZN_PUBKEY_LEN);
		memset(id, (int)(0x40u + i), sizeof(id));
		wrote = fzn_messages_write(&W.nm.m, X, FZN_MESSAGE_IN, id, 10u + i, "w", 1u)
		        == FZN_MESSAGES_OK;
	}
	CHECK(wrote, "fixture: seventy devices' lines");
	(void)fzn_node_journal_init_store(&A.journal, &rops, &A.sign, &HASH);
	CHECK(fzn_node_messages_devices(&A.nm, (const uint8_t(*)[FZN_PUBKEY_LEN])keys, 70u) == 32u
	              && A.nm.devices_wanted == 71u,
	      "the control: the own 32 listed more, or did not say how many were wanted");
	CHECK(fzn_node_messages_use_devices(&A.nm, room_devices, room_cursors, room_at, room_work,
	                                    128u)
	              && fzn_node_messages_devices(&A.nm, (const uint8_t(*)[FZN_PUBKEY_LEN])keys,
	                                           70u)
	                         == 71u
	              && A.nm.devices_wanted == 0u,
	      "given room, the 71 devices did not all list");
	CHECK(fzn_node_messages_absorb(&A.nm, &t) == FZN_MESSAGES_OK && t.lacking == 64u
	              && A.nm.keys_wanted == 65u && A.nm.dropped == 6u,
	      "the 70 keys did not overrun the own 64, saying so");
	CHECK(fzn_node_messages_use_keys(&A.nm, room_lacks, room_gives, 128u)
	              && fzn_node_messages_absorb(&A.nm, &t) == FZN_MESSAGES_OK && t.lacking == 70u,
	      "given room, the next absorb did not note the six dropped keys again");
}

int main(void)
{
	fzn_aead_monocypher_init(&AEAD);
	fzn_hash_monocypher_init(&HASH);
	memset(X, 0x58, sizeof(X));
	test_the_suite_can_tell_pass_from_fail();
	test_the_verbs();
	test_the_verbs_need_the_user();
	test_keys_travel();
	test_keys_through_a_hub();
	test_keys_cannot_be_planted();
	test_marks_are_absorbed();
	test_a_hand_off_to_a_removed_contact_is_given_up();
	test_two_hosts_over_the_exchange();
	test_a_cut_keeps_a_line_whole();
	test_a_returning_device_files_lines();
	test_backfill_from_the_journal();
	test_a_pushed_line_owes_its_key();
	test_a_line_is_delivered_to_a_contact();
	test_a_delivery_cut_at_every_save();
	test_a_host_that_keeps_none_refuses();
	test_another_devices_line_is_its_own_to_send();
	test_which_hosts_keep_messages();
	test_a_line_settles_once_every_keeping_device_holds_it();
	test_a_line_is_taken_over_from_a_writer_gone();
	test_a_holds_question_is_exact();
	test_seventy_devices();
	test_wants_past_one_row();
	CHECK(gives_seen > 0u && keys_left == 0u,
	      "a give by steps left its keys in the request, or no round gave any");
	if (failures) {
		fprintf(stderr, "node messages_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("node messages_test: all %d checks passed\n", checks);
	return 0;
}
