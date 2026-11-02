/*
 * A fuzz harness for a notes pull, `notes/sync.c` (sec 432): what a peer
 * answers -- a page of its index, a batch of records -- as this node pulls
 * from it. The peer is a host of this user or a sharer, and either may be
 * lost or buggy.
 *
 * Each case writes some notes on A, then has B pull them from A through an
 * ask that answers as A would and bends that answer with even odds -- bits
 * flipped, cut short, grown, a slice repeated or two bytes swapped -- and
 * hands it over as a copy ending where an unreadable page begins, so a
 * read past the end faults in any build.
 *
 * THE PROPERTY: whatever the answers, B holds only what A holds. Every
 * record B keeps is byte for byte A's record of that note by that writer:
 * a bent answer is refused or yields nothing B did not have, since every
 * record is admitted by its writer's signature and B's own policy.
 *
 * FLOORS: a run in which no pull met a bent answer and went on, or none
 * took a record, has not tested what it claims.
 */

#include "../author.h"
#include "blob_stub.h"
#include "chain_stub.h"
#include "../purge.h"
#include "../received.h"
#include "../share.h"
#include "../sync.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define FUZZ_DEFAULT_CASES 600u
#define FUZZ_MIN_CASES 100u

static int failures;

static void fail(const char *what, unsigned long c)
{
	failures++;
	if (failures <= 10)
		fprintf(stderr, "  FAIL notes_sync_fuzz.c: case %lu: %s\n", c, what);
}

static uint64_t state = 0x1f83d9abfb41bd6bull;

static uint64_t next(void)
{
	state ^= state << 13;
	state ^= state >> 7;
	state ^= state << 17;
	return state;
}

static void fnv(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len, uint8_t *out,
                size_t out_len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	for (i = 0; i < a_len; i++) {
		h ^= a[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < b_len; i++) {
		h ^= b[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < out_len; i++) {
		h ^= (uint64_t)i + 0x9e3779b97f4a7c15ull;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 32);
	}
}

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	(void)ctx;
	fnv(in, in_len, NULL, 0, out, out_len);
	return 1;
}

static const fzn_hash_ops_t HASH = { stub_hash, NULL };

static int toy_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	fnv((const uint8_t *)ctx, FZN_PUBKEY_LEN, msg, msg_len, sig, FZN_SIG_LEN);
	return 1;
}

static int toy_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                      size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	fnv(pubkey, FZN_PUBKEY_LEN, msg, msg_len, want, sizeof(want));
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static uint8_t KEY_A[FZN_PUBKEY_LEN], KEY_B[FZN_PUBKEY_LEN];

static uint64_t counter = 3;

static int counter_fill(void *ctx, uint8_t *out, size_t len)
{
	size_t i;

	(void)ctx;
	for (i = 0; i < len; i++)
		out[i] = (uint8_t)((counter * 131u + i * 7u) >> (i % 5u));
	counter++;
	return 1;
}

static const fzn_random_ops_t RNG = { counter_fill, NULL };

/* ---- persist over memory, one table per store --------------------------- */

#define MEM_ROWS 128u

struct row {
	int used;
	fzn_persist_slot_t slot;
	int has_subject;
	uint8_t subject[FZN_PUBKEY_LEN];
	/* Room for a shared note's row: a sharer and a claim key before the
	 * record. sec 437. */
	uint8_t bytes[FZN_PERSIST_HEAD_LEN + (2u * FZN_PUBKEY_LEN) + FZN_RECORD_MAX_LEN];
	size_t len;
};

struct table {
	struct row rows[MEM_ROWS];
};

static struct row *find(struct table *t, fzn_persist_slot_t slot, const uint8_t *subject)
{
	size_t i;

	for (i = 0; i < MEM_ROWS; i++)
		if (t->rows[i].used && t->rows[i].slot == slot
		    && t->rows[i].has_subject == (subject != NULL)
		    && (!subject || memcmp(t->rows[i].subject, subject, FZN_PUBKEY_LEN) == 0))
			return &t->rows[i];
	return NULL;
}

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	struct row *r = find((struct table *)ctx, slot, subject);

	if (!r || r->len > cap)
		return 0;
	memcpy(out, r->bytes, r->len);
	*len = r->len;
	return 1;
}

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	struct table *t = (struct table *)ctx;
	struct row *r = find(t, slot, subject);
	size_t i;

	for (i = 0; !r && i < MEM_ROWS; i++)
		if (!t->rows[i].used)
			r = &t->rows[i];
	if (!r || len > sizeof(r->bytes))
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
	struct table *t = (struct table *)ctx;
	size_t i, n = 0;

	for (i = 0; i < MEM_ROWS; i++)
		if (t->rows[i].used && t->rows[i].slot == slot && t->rows[i].has_subject) {
			if (n == max)
				return 0;
			memcpy(out + (n * FZN_PUBKEY_LEN), t->rows[i].subject, FZN_PUBKEY_LEN);
			n++;
		}
	*count = n;
	return 1;
}

static int mem_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	struct row *r = find((struct table *)ctx, slot, subject);

	if (r)
		r->used = 0;
	return 1;
}

/* A REMOVAL THAT FAILS FOR A NOTE while `refuse_note_removal` is set: the
 * erase after a purge's last answer, failing. */
static struct table table_a, table_b;
static fzn_persist_ops_t ops_a = { mem_load, mem_save, mem_list, mem_remove, &table_a, NULL };
static fzn_persist_ops_t ops_b = { mem_load, mem_save, mem_list, mem_remove, &table_b, NULL };
static fzn_notes_store_t store_a, store_b;

/* ---- writing notes on A -------------------------------------------------- */

static fzn_notes_writer_t writers[2];
static fzn_notes_view_t view;
static fzn_sign_ops_t sign_a = { toy_verify, toy_sign, KEY_A };
static fzn_sign_ops_t sign_b = { toy_verify, toy_sign, KEY_B };

static fzn_notes_policy_t both(void)
{
	memcpy(writers[0].key, KEY_A, FZN_PUBKEY_LEN);
	memcpy(writers[1].key, KEY_B, FZN_PUBKEY_LEN);
	return fzn_notes_policy_writers(writers, 2u);
}

static fzn_notes_author_t author_on(fzn_notes_store_t *store, uint8_t *key, fzn_sign_ops_t *sign)
{
	fzn_notes_author_t a;

	a.store = store;
	a.view = &view;
	a.issuer = key;
	a.sign = sign;
	a.rng = &RNG;
	a.policy = both();
	blob_stub_attach(&a);
	chain_stub_attach(&a);
	return a;
}

static int write_note(fzn_notes_author_t *a, const char *title, uint8_t id[FZN_TREE_ID_LEN])
{
	static const uint8_t top[FZN_TREE_ID_LEN];
	fzn_note_t note;

	memset(&note, 0, sizeof(note));
	note.title = (const uint8_t *)title;
	note.title_len = strlen(title);
	return fzn_notes_create(a, top, FZN_NOTE_TYPE_NOTE, &note, 1u, id) == FZN_NOTES_OK;
}

/* ---- the lie, and the page an over-read meets ---------------------------- */

#define BEND_CAP (FZN_NOTES_SYNC_REPLY_MAX + 64u)

static size_t bend(uint8_t *b, size_t len, size_t cap)
{
	static uint8_t was[BEND_CAP];
	size_t k, i, j;
	uint8_t t;

	memcpy(was, b, len);
	switch (next() % 5u) {
	case 1:
		if (len)
			return (size_t)(next() % len);
		break;
	case 2:
		if (len < cap) {
			for (k = 1u + next() % 8u; k > 0u && len < cap; k--)
				b[len++] = (uint8_t)next();
			return len;
		}
		break;
	case 3:
		if (len >= 8u) {
			i = next() % (len - 4u);
			for (j = 0; j < 4u && i + j + 4u < len && b[i + j] == b[i + j + 4u]; j++)
				;
			if (j < 4u && i + j + 4u < len) {
				memmove(b + i + 4u, b + i, len - i - 4u);
				return len;
			}
		}
		break;
	case 4:
		if (len >= 2u) {
			i = next() % len;
			j = next() % len;
			if (b[i] != b[j]) {
				t = b[i];
				b[i] = b[j];
				b[j] = t;
				return len;
			}
		}
		break;
	default:
		break;
	}
	for (k = 1u + next() % 2u; k > 0u && len; k--)
		b[next() % len] ^= (uint8_t)(1u << (next() % 8u));
	if (len && memcmp(b, was, len) == 0)
		b[next() % len] ^= 0x01u;
	return len;
}

static uint8_t *guarded_end;

static void guard(void)
{
	long page = sysconf(_SC_PAGESIZE);
	size_t room;
	uint8_t *map;

	if (page <= 0)
		abort();
	room = ((BEND_CAP + (size_t)page - 1u) / (size_t)page) * (size_t)page;
	map = mmap(NULL, room + (size_t)page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
	           -1, 0);
	if (map == MAP_FAILED || mprotect(map + room, (size_t)page, PROT_NONE) != 0)
		abort();
	guarded_end = map + room;
}

/* ---- the lying peer ------------------------------------------------------ */

static unsigned long bent_answers;

static int ask(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
               size_t reply_cap, size_t *reply_len)
{
	static uint8_t answer[BEND_CAP];
	size_t n;

	(void)ctx;
	n = fzn_notes_sync_answer(&store_a, both(), KEY_B, 1u, request, request_len, answer,
	                          reply_cap < FZN_NOTES_SYNC_REPLY_MAX ? reply_cap
	                                                               : FZN_NOTES_SYNC_REPLY_MAX);
	if (!n)
		return 0;
	if (next() & 1u) {
		n = bend(answer, n, reply_cap < BEND_CAP ? reply_cap : BEND_CAP);
		bent_answers++;
	}
	if (n > reply_cap)
		n = reply_cap;
	/* THE ANSWER ENDS AT THE PAGE, then is handed over as the caller's. */
	memcpy(guarded_end - n, answer, n);
	memcpy(reply, guarded_end - n, n);
	*reply_len = n;
	return 1;
}

/* WHETHER EVERYTHING B HOLDS IS A'S: each claim B lists -- a note by a
 * writer, keyed by the pair -- read under that key from both stores, the
 * same bytes. A claim B lists and cannot read counts against it. `*n_out`
 * is how many B holds, so a pass over none is seen. */
static int b_holds_only_as(size_t *n_out)
{
	static uint8_t keys[FZN_NOTES_MAX][FZN_PUBKEY_LEN];
	static uint8_t rb[FZN_RECORD_MAX_LEN], ra[FZN_RECORD_MAX_LEN];
	size_t n = 0, i;

	*n_out = 0;
	if (fzn_notes_claims(&store_b, keys, FZN_NOTES_MAX, &n) != FZN_NOTES_OK)
		return 0;
	*n_out = n;
	for (i = 0; i < n; i++) {
		size_t lb = 0, la = 0;

		if (fzn_notes_get_key(&store_b, keys[i], rb, sizeof(rb), &lb) != FZN_NOTES_OK
		    || fzn_notes_get_key(&store_a, keys[i], ra, sizeof(ra), &la) != FZN_NOTES_OK
		    || la != lb || memcmp(ra, rb, la) != 0)
			return 0;
	}
	return 1;
}

int main(int argc, char **argv)
{
	unsigned long cases = FUZZ_DEFAULT_CASES, c, took = 0, went_on = 0;

	if (argc > 1)
		cases = strtoul(argv[1], NULL, 10);
	if (cases < FUZZ_MIN_CASES)
		cases = FUZZ_MIN_CASES;
	guard();
	memset(KEY_A, 0xa1, sizeof(KEY_A));
	memset(KEY_B, 0xb2, sizeof(KEY_B));

	for (c = 0; c < cases; c++) {
		fzn_notes_author_t a;
		fzn_notes_sync_tally_t t;
		size_t i, notes = 1u + (size_t)(next() % 6u);
		unsigned long bent_before = bent_answers;
		fzn_notes_sync_err_t err;

		memset(&table_a, 0, sizeof(table_a));
		memset(&table_b, 0, sizeof(table_b));
		/* THE STUB'S ARENA, made for one suite's few notes, emptied each case. */
		blob_stub.used = blob_stub.count = 0;
		if (fzn_notes_store_init(&store_a, &ops_a, &HASH) != FZN_NOTES_OK
		    || fzn_notes_store_init(&store_b, &ops_b, &HASH) != FZN_NOTES_OK) {
			fail("fixture: the stores would not open", c);
			continue;
		}
		a = author_on(&store_a, KEY_A, &sign_a);
		for (i = 0; i < notes; i++) {
			uint8_t id[FZN_TREE_ID_LEN];
			char title[48];

			(void)snprintf(title, sizeof(title), "n%lu.%zu", c, i);
			if (!write_note(&a, title, id))
				fail("fixture: a note would not write on A", c);
		}
		memset(&t, 0, sizeof(t));
		err = fzn_notes_sync_pull(&store_b, both(), &sign_b, ask, NULL, &t);
		if (bent_answers > bent_before && err == FZN_NOTES_SYNC_OK)
			went_on++;
		{
			size_t compared = 0;

			if (!b_holds_only_as(&compared))
				fail("B holds a record A does not, after a pull through bent answers", c);
			if (compared)
				took++;
		}
	}

	if (went_on == 0u || took == 0u)
		fail("FLOOR: no pull went on past a bent answer, or none took a record", cases);
	printf("notes_sync_fuzz: %lu cases, %lu bent answer(s), %lu pull(s) past one, %lu took records, "
	       "%d failure(s)\n",
	       cases, bent_answers, went_on, took, failures);
	return failures ? 1 : 0;
}
