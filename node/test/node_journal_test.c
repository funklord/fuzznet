/* Tests for node/journal.c: a node's estate streams on disk. sec 501.
 *
 * Two hosts, each with a record store in a scratch directory of its own under
 * /tmp. A writes a key's stream, survives a restart, and B -- following that
 * key and nothing else -- pulls it through the exchange and survives one too.
 *
 * THE SCRATCH IS NAMED AND REMOVED BY NAME, and a directory that will not go
 * fails the suite: a cleanup that cannot fail is one nobody would notice
 * leaking.
 */

#include "../journal.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;
static int checks;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL node_journal_test.c:%d: %s\n", __LINE__, what);      \
		}                                                                              \
	} while (0)

static void mac(uint8_t out[FZN_SIG_LEN], uint8_t key, const uint8_t *msg, size_t len)
{
	uint64_t h = 0xcbf29ce484222325ull ^ key;
	size_t i;

	for (i = 0; i < len; i++)
		h = (h ^ msg[i]) * 0x100000001b3ull;
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h = (h ^ (uint64_t)i) * 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
}

static uint8_t signing_as;

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t len)
{
	(void)ctx;
	mac(sig, signing_as, msg, len);
	return 1;
}

static int stub_verify(void *ctx, const uint8_t pk[FZN_PUBKEY_LEN], const uint8_t *msg, size_t len,
                       const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	mac(want, pk[0], msg, len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static int mix_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0x84222325cbf29ce4ull;
	size_t i;

	(void)ctx;
	for (i = 0; i < in_len; i++)
		h = (h ^ in[i]) * 0x100000001b3ull;
	for (i = 0; i < out_len; i++) {
		h = (h ^ (uint64_t)i) * 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 40);
	}
	return 1;
}

static const fzn_sign_ops_t SIGN = { stub_verify, stub_sign, NULL };
static const fzn_hash_ops_t HASH = { mix_hash, NULL };

static void key(uint8_t out[FZN_PUBKEY_LEN], uint8_t seed)
{
	size_t i;

	for (i = 0; i < FZN_PUBKEY_LEN; i++)
		out[i] = (uint8_t)(seed + i * 5u);
	out[0] = seed;
}

static char dir_a[128], dir_b[128];

static int ask(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
               size_t reply_cap, size_t *reply_len)
{
	*reply_len = fzn_node_journal_answer((fzn_node_journal_t *)ctx, request, request_len, reply,
	                                     reply_cap);
	return *reply_len != 0u;
}

static int append(fzn_node_journal_t *nj, uint8_t writer, uint8_t subject_byte,
                  uint8_t id[FZN_RECORD_ID_LEN])
{
	uint8_t issuer[FZN_PUBKEY_LEN], subject[FZN_SUBJECT_LEN], body = 1u;

	key(issuer, writer);
	memset(subject, subject_byte, sizeof(subject));
	signing_as = writer;
	return fzn_node_journal_append(nj, issuer, &SIGN, (uint32_t)FZN_OBJECT_HOP, subject, &body,
	                               1u, 1000u, id) == FZN_NODE_JOURNAL_OK;
}

/* The file the store keeps `writer`'s `stream` in, by the rule store_file.c
 * follows. */
static void stream_file(char *out, size_t cap, const char *dir, uint8_t writer, uint32_t stream);

/* The file the store keeps an estate stream in. */
static void stream_path(char *out, size_t cap, const char *dir, uint8_t writer)
{
	stream_file(out, cap, dir, writer, FZN_NODE_JOURNAL_STREAM);
}

static void stream_file(char *out, size_t cap, const char *dir, uint8_t writer, uint32_t stream)
{
	static const char DIGITS[] = "0123456789abcdef";
	uint8_t issuer[FZN_PUBKEY_LEN];
	char hex[FZN_PUBKEY_LEN * 2u + 1u];
	size_t i;

	key(issuer, writer);
	for (i = 0; i < FZN_PUBKEY_LEN; i++) {
		hex[i * 2u] = DIGITS[issuer[i] >> 4];
		hex[i * 2u + 1u] = DIGITS[issuer[i] & 0x0fu];
	}
	hex[FZN_PUBKEY_LEN * 2u] = '\0';
	snprintf(out, cap, "%s/%s-%08lx.rec", dir, hex, (unsigned long)stream);
}

static void test_streams_on_disk_and_between_hosts(void)
{
	static fzn_node_journal_t a, b;
	uint8_t w[FZN_PUBKEY_LEN], x[FZN_PUBKEY_LEN];
	uint8_t ids[3][FZN_RECORD_ID_LEN], xid[FZN_RECORD_ID_LEN];
	uint8_t reply[8192];
	fzn_exchange_tally_t t;
	size_t replayed = 0;

	key(w, 0x31);
	key(x, 0x77);
	CHECK(fzn_node_journal_init(&a, dir_a, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_init(&b, dir_b, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK,
	      "fixture: two journals");

	/* A WRITES W's STREAM, chained. */
	CHECK(append(&a, 0x31, 0x01, ids[0]) && append(&a, 0x31, 0x02, ids[1])
	              && append(&a, 0x31, 0x03, ids[2])
	              && fzn_journal_next(&a.journal, w, FZN_NODE_JOURNAL_STREAM) == 4u,
	      "A did not write three records of W's stream");
	CHECK(fzn_record_store_stands(&a.store, &HASH, w, FZN_NODE_JOURNAL_STREAM, 3u, ids[2], 1u,
	                              ids[0]),
	      "A's three records are not one chain");
	CHECK(append(&a, 0x77, 0x09, xid), "fixture: A writes a stranger's stream too");

	/* A RESTART AT A: the stream replays from disk, and writing goes on
	 * from its head. */
	fzn_node_journal_close(&a);
	CHECK(fzn_node_journal_init(&a, dir_a, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_follow(&a, w, &replayed) == FZN_NODE_JOURNAL_OK
	              && replayed == 3u
	              && fzn_node_journal_follow(&a, w, &replayed) == FZN_NODE_JOURNAL_OK
	              && replayed == 0u
	              && fzn_node_journal_follow(&a, x, NULL) == FZN_NODE_JOURNAL_OK,
	      "A's streams did not replay from disk, or replayed twice");

	/* B FOLLOWS W, NOT X, and pulls. */
	CHECK(fzn_node_journal_follow(&b, w, NULL) == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_pull(&b, ask, &a, reply, sizeof(reply), &t)
	                         == FZN_EXCHANGE_OK
	              && t.learned == 3u && t.forks == 0u
	              && fzn_journal_next(&b.journal, w, FZN_NODE_JOURNAL_STREAM) == 4u
	              && fzn_journal_next(&b.journal, x, FZN_NODE_JOURNAL_STREAM) == 1u,
	      "B did not learn W's stream and only W's");
	CHECK(fzn_record_store_stands(&b.store, &HASH, w, FZN_NODE_JOURNAL_STREAM, 3u, ids[2], 2u,
	                              ids[1]),
	      "W's chain at B does not hold");

	/* A RESTART AT B. */
	fzn_node_journal_close(&b);
	CHECK(fzn_node_journal_init(&b, dir_b, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_follow(&b, w, &replayed) == FZN_NODE_JOURNAL_OK
	              && replayed == 3u,
	      "what B pulled did not replay from its disk");

	/* A RECORD EDITED ON DISK STOPS THE REPLAY THERE. */
	{
		char path[512];
		FILE *f;

		fzn_node_journal_close(&b);
		stream_path(path, sizeof(path), dir_b, 0x31);
		f = fopen(path, "r+b");
		CHECK(f != NULL && fseek(f, (long)(2u * FZN_RECORD_STORE_FILE_SLOT) + 2L + 140L, SEEK_SET)
		                           == 0
		              && fputc(0xee, f) != EOF,
		      "fixture: a byte of B's third record changed on disk");
		if (f)
			fclose(f);
		CHECK(fzn_node_journal_init(&b, dir_b, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK
		              && fzn_node_journal_follow(&b, w, &replayed) == FZN_NODE_JOURNAL_OK
		              && replayed == 2u,
		      "a record edited on disk was replayed");
	}
	fzn_node_journal_close(&a);
	fzn_node_journal_close(&b);
}

/* AN OBJECT, CARRIED WHOLE, sec 502: the record's kind is the object's tag,
 * its subject the object's hash, its body the object's bytes. Something that
 * is no signed object of this library's -- a tag below 128 -- is refused. */
static void test_an_object_carried_whole(void)
{
	static fzn_node_journal_t a;
	uint8_t w[FZN_PUBKEY_LEN], object[194], hash[FZN_SUBJECT_LEN], buf[FZN_RECORD_MAX_LEN];
	fzn_record_t rec;
	size_t i;

	key(w, 0x31);
	for (i = 0; i < sizeof(object); i++)
		object[i] = (uint8_t)(i * 13u);
	object[0] = 1u;
	object[1] = (uint8_t)FZN_OBJECT_SUCCESSION;
	mix_hash(NULL, hash, sizeof(hash), object, sizeof(object));
	signing_as = 0x31;
	CHECK(fzn_node_journal_init(&a, dir_a, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_append_object(&a, w, &SIGN, object, sizeof(object), 7u,
	                                                NULL) == FZN_NODE_JOURNAL_OK
	              && fzn_record_store_get(&a.store, w, FZN_NODE_JOURNAL_STREAM,
	                                      fzn_journal_next(&a.journal, w, FZN_NODE_JOURNAL_STREAM)
	                                              - 1u,
	                                      buf, sizeof(buf), &rec) == FZN_RECORD_STORE_OK
	              && fzn_record_kind(rec) == (uint32_t)FZN_OBJECT_SUCCESSION
	              && memcmp(fzn_record_subject(rec), hash, sizeof(hash)) == 0
	              && fzn_record_body_len(rec) == sizeof(object)
	              && memcmp(fzn_record_body(rec), object, sizeof(object)) == 0,
	      "an object was not carried whole, under its tag and its hash");
	object[1] = 0x36u;
	CHECK(fzn_node_journal_append_object(&a, w, &SIGN, object, sizeof(object), 7u, NULL)
	              == FZN_NODE_JOURNAL_MALFORMED,
	      "something that is no signed object of this library's was carried");
	fzn_node_journal_close(&a);
}

/* THE ACT LOG, sec 506: a key's stream answers what root-log entries did.
 * Writer W signs three acts; the head is the third; an act stands under a
 * cut at or above it, and not under one below it or one this stream does not
 * hold. A second record at the head marks a fork, which leaves no head while
 * the held branch still answers; and a record edited on disk breaks every
 * answer that walks through it. */
static void test_the_stream_is_the_act_log(void)
{
	static fzn_node_journal_t a;
	uint8_t w[FZN_PUBKEY_LEN], ids[3][FZN_RECORD_ID_LEN], head[FZN_RECORD_ID_LEN];
	uint8_t acts[3][FZN_SUBJECT_LEN], other[FZN_RECORD_ID_LEN], stranger[FZN_PUBKEY_LEN];
	fzn_act_log_ops_t ops;
	char path[512];
	size_t i;

	key(w, 0x55);
	key(stranger, 0x56);
	for (i = 0; i < 3u; i++)
		memset(acts[i], (int)(0x41u + i), sizeof(acts[i]));
	memset(other, 0x99, sizeof(other));
	CHECK(fzn_node_journal_init(&a, dir_a, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK
	              && append(&a, 0x55, 0x41, ids[0]) && append(&a, 0x55, 0x42, ids[1])
	              && append(&a, 0x55, 0x43, ids[2]),
	      "fixture: W signs three acts");
	CHECK(fzn_node_journal_head(&a, w, head) && memcmp(head, ids[2], sizeof(head)) == 0
	              && !fzn_node_journal_head(&a, stranger, head),
	      "the head is not W's last record, or a key not followed had one");
	CHECK(fzn_node_journal_stands(&a, w, ids[1], acts[0])
	              && fzn_node_journal_stands(&a, w, ids[1], acts[1])
	              && !fzn_node_journal_stands(&a, w, ids[1], acts[2]),
	      "an act at or below the cut did not stand, or one above it did");
	CHECK(!fzn_node_journal_stands(&a, w, other, acts[0])
	              && !fzn_node_journal_stands(&a, stranger, ids[2], acts[0]),
	      "an act stood under a cut the stream does not hold, or for a key not followed");
	fzn_node_journal_acts(&a, &ops);
	CHECK(ops.stands(ops.ctx, w, ids[2], acts[2]) && !ops.stands(ops.ctx, w, ids[0], acts[1]),
	      "the act-log ops did not answer as the journal does");

	/* A FORK: a second record at the head, and the stream has no head. */
	{
		uint8_t forked_id[FZN_RECORD_ID_LEN];

		memset(forked_id, 0x13, sizeof(forked_id));
		CHECK(fzn_journal_admit_chained(&a.journal, w, FZN_NODE_JOURNAL_STREAM, 3u, ids[1],
		                                forked_id) == FZN_JOURNAL_ERR_FORK
		              && fzn_node_journal_forked(&a, w) && !fzn_node_journal_head(&a, w, head)
		              && fzn_node_journal_stands(&a, w, ids[2], acts[0]),
		      "a fork left a head, went unmarked, or lost the branch held");
	}

	/* AND THE OTHER SHAPE OF A FORK, on a stream of its own: a next record
	 * naming a predecessor that is not the head. */
	{
		uint8_t v[FZN_PUBKEY_LEN], v_id[FZN_RECORD_ID_LEN], next_id[FZN_RECORD_ID_LEN];

		key(v, 0x57);
		memset(next_id, 0x24, sizeof(next_id));
		CHECK(append(&a, 0x57, 0x01, v_id) && !fzn_node_journal_forked(&a, v)
		              && fzn_journal_admit_chained(&a.journal, v, FZN_NODE_JOURNAL_STREAM, 2u,
		                                           other, next_id) == FZN_JOURNAL_ERR_FORK
		              && fzn_node_journal_forked(&a, v),
		      "a record naming another predecessor than the head went unmarked as a fork");
	}

	/* EDITED UNDERNEATH: one byte of the second record, and nothing that
	 * walks through it stands. */
	stream_path(path, sizeof(path), dir_a, 0x55);
	{
		FILE *f = fopen(path, "r+b");
		int c;

		CHECK(f != NULL && fseek(f, (long)FZN_RECORD_STORE_FILE_SLOT + 2L + 140L, SEEK_SET) == 0
		              && (c = fgetc(f)) != EOF
		              && fseek(f, (long)FZN_RECORD_STORE_FILE_SLOT + 2L + 140L, SEEK_SET) == 0
		              && fputc(c ^ 1, f) != EOF,
		      "fixture: a byte of the second record flipped");
		if (f)
			fclose(f);
	}
	CHECK(fzn_node_journal_stands(&a, w, ids[2], acts[2])
	              && !fzn_node_journal_stands(&a, w, ids[2], acts[0]),
	      "an act was found standing through a record edited on disk");
	fzn_node_journal_close(&a);
}

/* A persist store in memory, enough for the spine and the bases: a few rows
 * by subject. */
#define ROWS_MAX 16u

typedef struct memstore {
	uint8_t subject[ROWS_MAX][FZN_PUBKEY_LEN];
	uint8_t bytes[ROWS_MAX][1536];
	size_t len[ROWS_MAX];
	size_t n;
} memstore_t;

/* The store a NULL context means, and a second for a second journal. */
static memstore_t mem, mem_b;

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	memstore_t *m = ctx ? (memstore_t *)ctx : &mem;
	size_t i;

	for (i = 0; i < m->n; i++)
		if ((slot == FZN_PERSIST_JOURNAL_SPINE || slot == FZN_PERSIST_JOURNAL_BASE)
		    && memcmp(m->subject[i], subject, FZN_PUBKEY_LEN) == 0 && m->len[i] <= cap) {
			memcpy(out, m->bytes[i], m->len[i]);
			*len = m->len[i];
			return 1;
		}
	return 0;
}

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	memstore_t *m = ctx ? (memstore_t *)ctx : &mem;
	size_t i;

	if ((slot != FZN_PERSIST_JOURNAL_SPINE && slot != FZN_PERSIST_JOURNAL_BASE)
	    || len > sizeof(m->bytes[0]))
		return 0;
	for (i = 0; i < m->n && memcmp(m->subject[i], subject, FZN_PUBKEY_LEN) != 0; i++)
		;
	if (i == m->n) {
		if (m->n == ROWS_MAX)
			return 0;
		m->n++;
	}
	memcpy(m->subject[i], subject, FZN_PUBKEY_LEN);
	memcpy(m->bytes[i], bytes, len);
	m->len[i] = len;
	return 1;
}

/* Blank slot `seq` of a stream file's length prefix, as a cut leaves it. */
static int blank(const char *path, uint64_t seq)
{
	FILE *f = fopen(path, "r+b");
	int ok = f != NULL && fseek(f, (long)((seq - 1u) * FZN_RECORD_STORE_FILE_SLOT), SEEK_SET) == 0
	         && fputc(0, f) != EOF && fputc(0, f) != EOF;

	if (f)
		ok = fclose(f) == 0 && ok;
	return ok;
}

/* THE SPINE, sec 546: the ids of acts cut from a stream kept beside it, so
 * an act below the cut still stands. Writer X signs three acts; the first two
 * are kept in the spine and then blanked on disk. Every answer the whole
 * stream gave is given again; without the spine the walk stops at the gap;
 * and a spine entry edited underneath answers no more than an edited record
 * does. */
static void test_the_spine_outlives_a_cut(void)
{
	static fzn_node_journal_t a;
	static const fzn_persist_ops_t SPINE = { mem_load, mem_save, NULL, NULL, NULL };
	uint8_t x[FZN_PUBKEY_LEN], ids[3][FZN_RECORD_ID_LEN], acts[3][FZN_SUBJECT_LEN];
	char path[512];
	size_t i;

	key(x, 0x58);
	for (i = 0; i < 3u; i++)
		memset(acts[i], (int)(0x61u + i), sizeof(acts[i]));
	CHECK(fzn_node_journal_init(&a, dir_a, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK
	              && append(&a, 0x58, 0x61, ids[0]) && append(&a, 0x58, 0x62, ids[1])
	              && append(&a, 0x58, 0x63, ids[2]),
	      "fixture: X signs three acts");
	CHECK(fzn_node_journal_spine_keep(&a, x, 1u) == FZN_NODE_JOURNAL_MALFORMED,
	      "an entry was kept with no spine");
	a.keep = &SPINE;
	CHECK(fzn_node_journal_spine_keep(&a, x, 1u) == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_spine_keep(&a, x, 2u) == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_spine_keep(&a, x, 9u) == FZN_NODE_JOURNAL_STORE,
	      "the first two acts were not kept, or one never held was");
	stream_path(path, sizeof(path), dir_a, 0x58);
	CHECK(blank(path, 1u) && blank(path, 2u), "fixture: the first two records cut");
	CHECK(fzn_node_journal_stands(&a, x, ids[0], acts[0])
	              && fzn_node_journal_stands(&a, x, ids[1], acts[0])
	              && fzn_node_journal_stands(&a, x, ids[2], acts[1])
	              && !fzn_node_journal_stands(&a, x, ids[0], acts[1])
	              && !fzn_node_journal_stands(&a, x, ids[1], acts[2]),
	      "an act below the cut did not stand through the spine, or one above it did");
	a.keep = NULL;
	CHECK(!fzn_node_journal_stands(&a, x, ids[2], acts[0])
	              && fzn_node_journal_stands(&a, x, ids[2], acts[2]),
	      "an act stood across a gap with no spine, or one above the gap did not");
	a.keep = &SPINE;
	/* EDITED UNDERNEATH: the second entry's predecessor, and the walk
	 * through it reaches nothing. */
	mem.bytes[0][FZN_RECORD_ID_LEN + FZN_RECORD_ID_LEN + FZN_SUBJECT_LEN + FZN_RECORD_ID_LEN] ^= 1u;
	CHECK(!fzn_node_journal_stands(&a, x, ids[2], acts[0])
	              && fzn_node_journal_stands(&a, x, ids[2], acts[1]),
	      "an act stood through a spine entry edited underneath");
	fzn_node_journal_close(&a);
}

/* THE BASE, sec 547: a stream cut below it is followed from there. Writer Y
 * signs four acts; the first two go to the spine, the base moves to the
 * third, and the two are blanked on disk. A journal opened afresh replays
 * the two held, counts the two cut as applied, holds the same head, and an
 * act behind the base still stands. With no base kept the same store reads
 * as empty; a base row whose id is not the one the first held record names
 * admits nothing; and a base never moves down or past what is held. */
static void test_a_stream_read_from_its_base(void)
{
	static fzn_node_journal_t a, b;
	static const fzn_persist_ops_t KEEP = { mem_load, mem_save, NULL, NULL, NULL };
	uint8_t y[FZN_PUBKEY_LEN], ids[4][FZN_RECORD_ID_LEN], acts[4][FZN_SUBJECT_LEN];
	uint8_t head[FZN_RECORD_ID_LEN];
	char path[512];
	size_t i, n = 0;

	key(y, 0x59);
	for (i = 0; i < 4u; i++)
		memset(acts[i], (int)(0x71u + i), sizeof(acts[i]));
	CHECK(fzn_node_journal_init(&a, dir_a, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK
	              && append(&a, 0x59, 0x71, ids[0]) && append(&a, 0x59, 0x72, ids[1])
	              && append(&a, 0x59, 0x73, ids[2]) && append(&a, 0x59, 0x74, ids[3]),
	      "fixture: Y signs four acts");
	CHECK(fzn_node_journal_base_set(&a, y, FZN_NODE_JOURNAL_STREAM, 3u)
	              == FZN_NODE_JOURNAL_MALFORMED
	              && fzn_node_journal_base(&a, y, FZN_NODE_JOURNAL_STREAM) == 1u,
	      "a base was kept with nowhere to keep it");
	a.keep = &KEEP;
	CHECK(fzn_node_journal_base_set(&a, y, FZN_NODE_JOURNAL_STREAM, 6u)
	              == FZN_NODE_JOURNAL_MALFORMED
	              && fzn_node_journal_base_set(&a, y, FZN_NODE_JOURNAL_STREAM, 1u)
	                         == FZN_NODE_JOURNAL_MALFORMED,
	      "a base past what is held, or at the start, was kept");
	CHECK(fzn_node_journal_spine_keep(&a, y, 1u) == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_spine_keep(&a, y, 2u) == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_base_set(&a, y, FZN_NODE_JOURNAL_STREAM, 3u)
	                         == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_base(&a, y, FZN_NODE_JOURNAL_STREAM) == 3u
	              && fzn_node_journal_base_set(&a, y, FZN_NODE_JOURNAL_STREAM, 2u)
	                         == FZN_NODE_JOURNAL_MALFORMED,
	      "the base did not move to the third, or moved back down");
	fzn_node_journal_close(&a);
	stream_path(path, sizeof(path), dir_a, 0x59);
	CHECK(blank(path, 1u) && blank(path, 2u), "fixture: the first two records cut");

	CHECK(fzn_node_journal_init(&b, dir_a, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK,
	      "fixture: a journal opened afresh");
	b.keep = &KEEP;
	CHECK(fzn_node_journal_follow(&b, y, &n) == FZN_NODE_JOURNAL_OK && n == 2u
	              && fzn_node_journal_received(&b, y, FZN_NODE_JOURNAL_STREAM) == 4u
	              && fzn_journal_pending(&b.journal, y, FZN_NODE_JOURNAL_STREAM) == 2u
	              && fzn_node_journal_head(&b, y, head)
	              && memcmp(head, ids[3], sizeof(head)) == 0,
	      "the stream was not followed from its base, or what was cut was not applied");
	CHECK(fzn_node_journal_stands(&b, y, ids[3], acts[0])
	              && fzn_node_journal_stands(&b, y, ids[1], acts[1])
	              && !fzn_node_journal_stands(&b, y, ids[1], acts[2]),
	      "an act behind the base did not stand, or one above the cut did");
	fzn_node_journal_close(&b);

	/* NO BASE KEPT: the same store reads from 1 and stops at the hole. */
	CHECK(fzn_node_journal_init(&b, dir_a, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_follow(&b, y, &n) == FZN_NODE_JOURNAL_OK && n == 0u
	              && fzn_node_journal_received(&b, y, FZN_NODE_JOURNAL_STREAM) == 0u,
	      "a stream with no base kept read past a hole at its start");
	fzn_node_journal_close(&b);

	/* A BASE ROW EDITED UNDERNEATH: its id no longer the one the third
	 * record names, and the chain admits nothing. */
	for (i = 0; i < mem.n; i++)
		if (mem.len[i] == 8u + FZN_RECORD_ID_LEN)
			mem.bytes[i][8] ^= 1u;
	CHECK(fzn_node_journal_init(&b, dir_a, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK,
	      "fixture: a journal opened afresh");
	b.keep = &KEEP;
	CHECK(fzn_node_journal_follow(&b, y, &n) == FZN_NODE_JOURNAL_OK && n == 0u
	              && fzn_node_journal_received(&b, y, FZN_NODE_JOURNAL_STREAM) == 2u,
	      "a record was admitted under a base whose id it does not name");
	fzn_node_journal_close(&b);
}

/* THE CUT, sec 548. Writer Z signs five acts ten seconds apart -- the first
 * two stamped in seconds, as the estate stream was before sec 561, the rest
 * in milliseconds. The cut point compares them on one clock: it stops at the
 * first record as young as the window's edge, in milliseconds, and at what
 * the reader has taken; a cut below the fourth keeps the three in the spine,
 * moves the base and lets them go; the acts behind it still stand, and a
 * journal opened afresh follows from the base. A cut at or under the base
 * cuts nothing; one past what is held, or with nowhere to keep, is refused. */
/* An instant in each unit: seconds, and the same instant in milliseconds. */
#define T_SECONDS 1700000000ull
#define T_MS (T_SECONDS * 1000u)

static void test_the_cut(void)
{
	static fzn_node_journal_t a, b;
	static const fzn_persist_ops_t KEEP = { mem_load, mem_save, NULL, NULL, NULL };
	uint8_t z[FZN_PUBKEY_LEN], ids[5][FZN_RECORD_ID_LEN], acts[5][FZN_SUBJECT_LEN];
	uint8_t buf[FZN_RECORD_MAX_LEN];
	fzn_record_t rec;
	size_t i, n = 0;
	int ok = 1;

	key(z, 0x5a);
	signing_as = 0x5a;
	CHECK(fzn_node_journal_init(&a, dir_a, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK,
	      "fixture: a journal");
	for (i = 0; i < 5u; i++) {
		uint8_t body = 1u;

		memset(acts[i], (int)(0x81u + i), sizeof(acts[i]));
		uint64_t at = i < 2u ? T_SECONDS + (10u * (i + 1u)) : T_MS + (10000u * (i + 1u));

		ok = ok
		     && fzn_node_journal_append(&a, z, &SIGN, (uint32_t)FZN_OBJECT_HOP, acts[i], &body,
		                                1u, at, ids[i]) == FZN_NODE_JOURNAL_OK;
	}
	CHECK(ok, "fixture: Z signs five acts ten seconds apart, two in seconds");
	CHECK(fzn_node_journal_cut_point(&a, z, FZN_NODE_JOURNAL_STREAM, 5u, T_MS + 35000u) == 4u
	              && fzn_node_journal_cut_point(&a, z, FZN_NODE_JOURNAL_STREAM, 2u, T_MS + 35000u)
	                         == 3u
	              && fzn_node_journal_cut_point(&a, z, FZN_NODE_JOURNAL_STREAM, 5u, T_MS + 10000u)
	                         == 1u,
	      "the cut point passed a young record, or what the reader has not taken");
	CHECK(fzn_node_journal_cut_point(&a, z, FZN_NODE_JOURNAL_STREAM, 5u, T_MS + 15000u) == 2u,
	      "a record stamped in seconds was read raw, as older than one ten seconds before it");
	CHECK(fzn_node_journal_cut(&a, z, FZN_NODE_JOURNAL_STREAM, 4u, &n)
	              == FZN_NODE_JOURNAL_MALFORMED,
	      "a cut with nowhere to keep the base was made");
	a.keep = &KEEP;
	CHECK(fzn_node_journal_cut(&a, z, FZN_NODE_JOURNAL_STREAM, 7u, &n)
	              == FZN_NODE_JOURNAL_MALFORMED,
	      "a cut past what is held was made");
	CHECK(fzn_node_journal_cut(&a, z, FZN_NODE_JOURNAL_STREAM, 4u, &n) == FZN_NODE_JOURNAL_OK
	              && n == 3u && fzn_node_journal_base(&a, z, FZN_NODE_JOURNAL_STREAM) == 4u,
	      "the first three were not cut, or the base did not move");
	for (i = 1; i <= 3u; i++)
		if (fzn_record_store_get(&a.store, z, FZN_NODE_JOURNAL_STREAM, i, buf, sizeof(buf),
		                         &rec) != FZN_RECORD_STORE_ERR_ABSENT)
			ok = 0;
	CHECK(ok
	              && fzn_record_store_get(&a.store, z, FZN_NODE_JOURNAL_STREAM, 4u, buf,
	                                      sizeof(buf), &rec) == FZN_RECORD_STORE_OK,
	      "a record cut is still held, or the one above the cut is not");
	CHECK(fzn_node_journal_stands(&a, z, ids[4], acts[0])
	              && fzn_node_journal_stands(&a, z, ids[2], acts[2])
	              && !fzn_node_journal_stands(&a, z, ids[2], acts[3]),
	      "an act behind the cut did not stand, or one above its cut did");
	CHECK(fzn_node_journal_cut(&a, z, FZN_NODE_JOURNAL_STREAM, 4u, &n) == FZN_NODE_JOURNAL_OK
	              && n == 0u
	              && fzn_node_journal_cut(&a, z, FZN_NODE_JOURNAL_STREAM, 2u, &n)
	                         == FZN_NODE_JOURNAL_OK
	              && n == 0u,
	      "a cut at or under the base cut something");
	fzn_node_journal_close(&a);

	CHECK(fzn_node_journal_init(&b, dir_a, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK,
	      "fixture: a journal opened afresh");
	b.keep = &KEEP;
	CHECK(fzn_node_journal_follow(&b, z, &n) == FZN_NODE_JOURNAL_OK && n == 2u
	              && fzn_node_journal_received(&b, z, FZN_NODE_JOURNAL_STREAM) == 5u
	              && fzn_node_journal_stands(&b, z, ids[4], acts[1]),
	      "a cut stream was not followed from its base after a restart");
	fzn_node_journal_close(&b);
}

/* A STREAM BEHIND A PEER'S BASE, sec 552. A holds writer V's six acts; B
 * pulls the first two, then A cuts below the fifth. B's next pull is
 * missing the third, so B takes A's base, the id below it and A's spine
 * for the third and fourth. A bridge broken anywhere, or of the wrong
 * length, is refused; the whole one moves B up: its head the fourth, both
 * pulled after it, its own two records cut and kept in its spine, every
 * act standing under the sixth -- and a journal opened afresh at B follows
 * from the new base. */
static void test_a_stream_rebased(void)
{
	static fzn_node_journal_t a, b;
	static const fzn_persist_ops_t KEEP_A = { mem_load, mem_save, NULL, NULL, NULL };
	static const fzn_persist_ops_t KEEP_B = { mem_load, mem_save, NULL, NULL, &mem_b };
	uint8_t v[FZN_PUBKEY_LEN], ids[6][FZN_RECORD_ID_LEN], acts[6][FZN_SUBJECT_LEN];
	uint8_t below[FZN_RECORD_ID_LEN], bridge[2][FZN_NODE_JOURNAL_SPINE_ENTRY];
	uint8_t head[FZN_RECORD_ID_LEN], reply[8192];
	fzn_exchange_tally_t t;
	uint64_t base;
	size_t i, n = 0;
	int ok = 1;

	key(v, 0x5b);
	for (i = 0; i < 6u; i++)
		memset(acts[i], (int)(0xa1u + i), sizeof(acts[i]));
	CHECK(fzn_node_journal_init(&a, dir_a, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_init(&b, dir_b, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK,
	      "fixture: two journals");
	a.keep = &KEEP_A;
	b.keep = &KEEP_B;
	for (i = 0; i < 2u; i++)
		ok = ok && append(&a, 0x5b, (uint8_t)(0xa1u + i), ids[i]);
	CHECK(ok && fzn_node_journal_follow(&b, v, NULL) == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_pull(&b, ask, &a, reply, sizeof(reply), &t)
	                         == FZN_EXCHANGE_OK
	              && t.learned == 2u,
	      "fixture: B pulls V's first two from A");
	for (i = 2; i < 6u; i++)
		ok = ok && append(&a, 0x5b, (uint8_t)(0xa1u + i), ids[i]);
	CHECK(ok
	              && fzn_node_journal_cut(&a, v, FZN_NODE_JOURNAL_STREAM, 5u, &n)
	                         == FZN_NODE_JOURNAL_OK
	              && n == 4u
	              && fzn_node_journal_pull(&b, ask, &a, reply, sizeof(reply), &t)
	                         == FZN_EXCHANGE_OK
	              && t.learned == 0u && t.missing == 1u,
	      "fixture: A writes four more and cuts below the fifth; B's pull finds it missing");
	base = fzn_node_journal_base_below(&a, v, FZN_NODE_JOURNAL_STREAM, below);
	CHECK(base == 5u && memcmp(below, ids[3], sizeof(below)) == 0
	              && fzn_node_journal_spine_entry(&a, v, 3u, bridge[0])
	              && fzn_node_journal_spine_entry(&a, v, 4u, bridge[1])
	              && memcmp(bridge[1], ids[3], FZN_RECORD_ID_LEN) == 0,
	      "A's base, the id below it, or its spine for the third and fourth were not served");
	CHECK(fzn_node_journal_rebase(&b, v, FZN_NODE_JOURNAL_STREAM, base, below,
	                              (const uint8_t(*)[FZN_NODE_JOURNAL_SPINE_ENTRY])bridge, 1u)
	              == FZN_NODE_JOURNAL_REFUSED,
	      "a bridge one entry short was taken");
	bridge[0][FZN_RECORD_ID_LEN] ^= 1u;
	CHECK(fzn_node_journal_rebase(&b, v, FZN_NODE_JOURNAL_STREAM, base, below,
	                              (const uint8_t(*)[FZN_NODE_JOURNAL_SPINE_ENTRY])bridge, 2u)
	              == FZN_NODE_JOURNAL_REFUSED,
	      "a bridge not naming B's head was taken");
	bridge[0][FZN_RECORD_ID_LEN] ^= 1u;
	bridge[1][FZN_RECORD_ID_LEN] ^= 1u;
	CHECK(fzn_node_journal_rebase(&b, v, FZN_NODE_JOURNAL_STREAM, base, below,
	                              (const uint8_t(*)[FZN_NODE_JOURNAL_SPINE_ENTRY])bridge, 2u)
	              == FZN_NODE_JOURNAL_REFUSED
	              && fzn_node_journal_received(&b, v, FZN_NODE_JOURNAL_STREAM) == 2u,
	      "a bridge broken in the middle was taken, or moved B");
	bridge[1][FZN_RECORD_ID_LEN] ^= 1u;
	below[0] ^= 1u;
	CHECK(fzn_node_journal_rebase(&b, v, FZN_NODE_JOURNAL_STREAM, base, below,
	                              (const uint8_t(*)[FZN_NODE_JOURNAL_SPINE_ENTRY])bridge, 2u)
	              == FZN_NODE_JOURNAL_REFUSED,
	      "a bridge whose top is not the id below the base was taken");
	below[0] ^= 1u;
	CHECK(fzn_node_journal_rebase(&b, v, FZN_NODE_JOURNAL_STREAM, base, below,
	                              (const uint8_t(*)[FZN_NODE_JOURNAL_SPINE_ENTRY])bridge, 2u)
	              == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_received(&b, v, FZN_NODE_JOURNAL_STREAM) == 4u
	              && fzn_journal_pending(&b.journal, v, FZN_NODE_JOURNAL_STREAM) == 0u
	              && fzn_node_journal_base(&b, v, FZN_NODE_JOURNAL_STREAM) == 5u
	              && fzn_node_journal_head(&b, v, head) && memcmp(head, ids[3], sizeof(head)) == 0,
	      "the whole bridge did not move B up to A's base");
	CHECK(fzn_node_journal_pull(&b, ask, &a, reply, sizeof(reply), &t) == FZN_EXCHANGE_OK
	              && t.learned == 2u && t.missing == 0u
	              && fzn_node_journal_stands(&b, v, ids[5], acts[0])
	              && fzn_node_journal_stands(&b, v, ids[5], acts[2])
	              && fzn_node_journal_stands(&b, v, ids[5], acts[5]),
	      "B did not pull on from the base, or an act behind it did not stand");
	{
		uint8_t buf[FZN_RECORD_MAX_LEN];
		fzn_record_t rec;

		CHECK(fzn_record_store_get(&b.store, v, FZN_NODE_JOURNAL_STREAM, 1u, buf, sizeof(buf),
		                           &rec) == FZN_RECORD_STORE_ERR_ABSENT,
		      "B kept the records the new base put below it");
	}
	fzn_node_journal_close(&b);
	CHECK(fzn_node_journal_init(&b, dir_b, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK,
	      "fixture: B opened afresh");
	b.keep = &KEEP_B;
	CHECK(fzn_node_journal_follow(&b, v, &n) == FZN_NODE_JOURNAL_OK && n == 2u
	              && fzn_node_journal_received(&b, v, FZN_NODE_JOURNAL_STREAM) == 6u
	              && fzn_node_journal_stands(&b, v, ids[5], acts[2]),
	      "a journal opened afresh at B did not follow from the new base");
	fzn_node_journal_close(&a);
	fzn_node_journal_close(&b);
}

/* ANY STREAM, sec 512: a key's notes are its stream 0 beside its estate
 * stream. Two records appended on stream 0 chain there, leave the estate
 * stream alone, and replay into a fresh journal following stream 0. */
static void test_a_second_stream(void)
{
	static fzn_node_journal_t a;
	uint8_t w[FZN_PUBKEY_LEN], subject[FZN_SUBJECT_LEN], body = 1u, ids[2][FZN_RECORD_ID_LEN];
	size_t replayed = 0;

	key(w, 0x60);
	memset(subject, 0x22, sizeof(subject));
	signing_as = 0x60;
	CHECK(fzn_node_journal_init(&a, dir_a, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_append_on(&a, w, 0u, &SIGN, 0x36u, subject, &body, 1u, 5u,
	                                            ids[0]) == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_append_on(&a, w, 0u, &SIGN, 0x36u, subject, &body, 1u, 6u,
	                                            ids[1]) == FZN_NODE_JOURNAL_OK,
	      "fixture: two records on W's stream 0");
	CHECK(fzn_node_journal_received(&a, w, 0u) == 2u
	              && fzn_node_journal_received(&a, w, FZN_NODE_JOURNAL_STREAM) == 0u
	              && fzn_record_store_stands(&a.store, &HASH, w, 0u, 2u, ids[1], 1u, ids[0]),
	      "stream 0 did not chain its two, or the estate stream moved");
	/* A WRITE HANDS THE RECORD BACK, sec 517: the bytes the store keeps,
	 * the third of the stream, naming the second. */
	{
		static uint8_t out[FZN_RECORD_MAX_LEN], held[FZN_RECORD_MAX_LEN];
		uint8_t id[FZN_RECORD_ID_LEN];
		fzn_record_t rec, kept;
		size_t len = 0;

		CHECK(fzn_node_journal_write(&a, w, 0u, &SIGN, 0x36u, subject, &body, 1u, 7u, out,
		                             FZN_RECORD_MAX_LEN - 1u, &len, id)
		              == FZN_NODE_JOURNAL_MALFORMED
		              && fzn_node_journal_received(&a, w, 0u) == 2u,
		      "a write into a short buffer was signed or kept");
		CHECK(fzn_node_journal_write(&a, w, 0u, &SIGN, 0x36u, subject, &body, 1u, 7u, out,
		                             sizeof(out), &len, id)
		                      == FZN_NODE_JOURNAL_OK
		              && fzn_record_open(out, len, &rec) == FZN_RECORD_OK
		              && fzn_record_seq(rec) == 3u
		              && memcmp(fzn_record_prev(rec), ids[1], FZN_RECORD_ID_LEN) == 0
		              && fzn_record_store_get(&a.store, w, 0u, 3u, held, sizeof(held), &kept)
		                         == FZN_RECORD_STORE_OK
		              && kept.len == len && memcmp(held, out, len) == 0,
		      "a write did not hand back the third record, chained, as the store keeps it");
	}
	fzn_node_journal_close(&a);
	CHECK(fzn_node_journal_init(&a, dir_a, &SIGN, &HASH) == FZN_NODE_JOURNAL_OK
	              && fzn_node_journal_follow_stream(&a, w, 0u, &replayed) == FZN_NODE_JOURNAL_OK
	              && replayed == 3u && fzn_node_journal_received(&a, w, 0u) == 3u,
	      "a fresh journal following stream 0 did not replay its three");
	fzn_node_journal_close(&a);
}

int main(void)
{
	char path[512];

	snprintf(dir_a, sizeof(dir_a), "/tmp/fzn-node-journal-test-%ld-a", (long)getpid());
	snprintf(dir_b, sizeof(dir_b), "/tmp/fzn-node-journal-test-%ld-b", (long)getpid());
	if (mkdir(dir_a, 0700) != 0 || mkdir(dir_b, 0700) != 0) {
		fprintf(stderr, "node_journal_test: could not make the scratch directories\n");
		return 1;
	}
	test_streams_on_disk_and_between_hosts();
	test_an_object_carried_whole();
	test_the_stream_is_the_act_log();
	test_a_second_stream();
	test_the_spine_outlives_a_cut();
	test_a_stream_read_from_its_base();
	test_the_cut();
	test_a_stream_rebased();

	/* EVERY FILE THE SUITE MADE, BY NAME, then the directories. */
	stream_path(path, sizeof(path), dir_a, 0x31);
	(void)unlink(path);
	stream_path(path, sizeof(path), dir_a, 0x77);
	(void)unlink(path);
	stream_path(path, sizeof(path), dir_a, 0x55);
	(void)unlink(path);
	stream_path(path, sizeof(path), dir_a, 0x57);
	(void)unlink(path);
	stream_path(path, sizeof(path), dir_a, 0x58);
	(void)unlink(path);
	stream_path(path, sizeof(path), dir_a, 0x59);
	(void)unlink(path);
	stream_path(path, sizeof(path), dir_a, 0x5a);
	(void)unlink(path);
	stream_path(path, sizeof(path), dir_a, 0x5b);
	(void)unlink(path);
	stream_path(path, sizeof(path), dir_b, 0x5b);
	(void)unlink(path);
	stream_file(path, sizeof(path), dir_a, 0x60, 0u);
	(void)unlink(path);
	stream_path(path, sizeof(path), dir_b, 0x31);
	(void)unlink(path);
	CHECK(rmdir(dir_a) == 0 && rmdir(dir_b) == 0,
	      "a scratch directory would not go: the suite left a file it did not name");

	if (failures) {
		fprintf(stderr, "node_journal_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("node_journal_test: all %d checks passed\n", checks);
	return 0;
}
