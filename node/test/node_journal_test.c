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

/* The file the store keeps a stream in, by the rule store_file.c follows. */
static void stream_path(char *out, size_t cap, const char *dir, uint8_t writer)
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
	snprintf(out, cap, "%s/%s-%08lx.rec", dir, hex, (unsigned long)FZN_NODE_JOURNAL_STREAM);
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

	/* EVERY FILE THE SUITE MADE, BY NAME, then the directories. */
	stream_path(path, sizeof(path), dir_a, 0x31);
	(void)unlink(path);
	stream_path(path, sizeof(path), dir_a, 0x77);
	(void)unlink(path);
	stream_path(path, sizeof(path), dir_a, 0x55);
	(void)unlink(path);
	stream_path(path, sizeof(path), dir_a, 0x57);
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
