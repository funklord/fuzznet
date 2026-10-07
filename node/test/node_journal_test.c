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

	/* EVERY FILE THE SUITE MADE, BY NAME, then the directories. */
	stream_path(path, sizeof(path), dir_a, 0x31);
	(void)unlink(path);
	stream_path(path, sizeof(path), dir_a, 0x77);
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
