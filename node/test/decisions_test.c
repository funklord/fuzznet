/* node decisions_test -- what was decided while hosts were apart, sec 895:
 * heads worked out from the records alone, a fork where they disagree, and a
 * decision that names them closing it.
 */

#include "../decisions.h"
#include "../../state/setting.h"
#include "../../messages/line.h"
#include "../../log/retain.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
static int checks;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL decisions_test.c:%d: %s\n", __LINE__, what);      \
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

static const fzn_sign_ops_t SIGN = { stub_verify, stub_sign, NULL };

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

static const fzn_hash_ops_t HASH = { mix_hash, NULL };

/* ---- a store per node ---------------------------------------------------- */

#define ROWS 400

struct row {
	int used;
	fzn_persist_slot_t slot;
	uint8_t subject[FZN_PUBKEY_LEN];
	uint8_t bytes[FZN_BUCKETS_ITEM_MAX + 64u];
	size_t len;
};

struct mem {
	struct row rows[ROWS];
	/* The save that fails, counting from 1; 0 for none. */
	int fail_at, saves;
};

static struct row *row_of(struct mem *m, fzn_persist_slot_t slot, const uint8_t *subject, int make)
{
	int i, free_one = -1;

	for (i = 0; i < ROWS; i++) {
		if (!m->rows[i].used) {
			if (free_one < 0)
				free_one = i;
			continue;
		}
		if (m->rows[i].slot == slot && memcmp(m->rows[i].subject, subject, FZN_PUBKEY_LEN) == 0)
			return &m->rows[i];
	}
	if (!make || free_one < 0)
		return NULL;
	m->rows[free_one].used = 1;
	m->rows[free_one].slot = slot;
	memcpy(m->rows[free_one].subject, subject, FZN_PUBKEY_LEN);
	return &m->rows[free_one];
}

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	struct row *r = row_of((struct mem *)ctx, slot, subject, 0);

	if (!r || r->len > cap)
		return 0;
	memcpy(out, r->bytes, r->len);
	*len = r->len;
	return 1;
}

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	struct mem *m = (struct mem *)ctx;
	struct row *r;

	if (m->fail_at && ++m->saves == m->fail_at)
		return 0;
	r = row_of(m, slot, subject, 1);
	if (!r || len > sizeof(r->bytes))
		return 0;
	memcpy(r->bytes, bytes, len);
	r->len = len;
	return 1;
}

static int mem_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max, size_t *count)
{
	struct mem *m = (struct mem *)ctx;
	size_t n = 0;
	int i;

	for (i = 0; i < ROWS; i++)
		if (m->rows[i].used && m->rows[i].slot == slot) {
			if (n >= max)
				return 0;
			memcpy(out + n * FZN_PUBKEY_LEN, m->rows[i].subject, FZN_PUBKEY_LEN);
			n++;
		}
	*count = n;
	return 1;
}

static int mem_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	struct row *r = row_of((struct mem *)ctx, slot, subject, 0);

	if (r)
		memset(r, 0, sizeof(*r));
	return 1;
}


/* ---- the cases ------------------------------------------------------------ */

static struct mem node;
static const fzn_persist_ops_t STORE = { mem_load, mem_save, mem_list, mem_remove, &node, NULL, NULL };
static const fzn_buckets_t B = { &STORE, &HASH };
static fzn_node_identity_t me;
static uint64_t clock_ms = 1793500000000ull; /* 2026-11 */

static uint64_t now_ms(void)
{
	return clock_ms;
}

static char reply[4096];

static size_t said(const fzn_node_records_t *nr, fzn_origin_t origin, const char *line)
{
	fzn_request_t req;

	memset(reply, 0, sizeof(reply));
	if (!fzn_vocabulary_split((const uint8_t *)line, strlen(line), &req))
		return 0;
	return fzn_node_decisions_local((void *)nr, origin, &req, reply, sizeof(reply));
}

static int replied(const char *start)
{
	return strncmp(reply, start, strlen(start)) == 0;
}

#define HOST_A 0xaau
#define HOST_B 0xbbu

static fzn_node_records_t nr;
static const uint8_t SUBJECT[] = "tune/x";
#define SUBJECT_LEN 6u

static void be(uint8_t host)
{
	memset(me.pubkey, host, FZN_PUBKEY_LEN);
	signing_as = host;
	clock_ms += 1000u;
}

/* A DECISION AS A HOST THAT HAD SEEN ONLY `bases` WROTE IT. */
static int raw(uint8_t host, const char *text)
{
	static const uint8_t KEY[] = "decided/tune/x";

	int ok;

	be(host);
	ok = fzn_node_records_write(&nr, KEY, sizeof(KEY) - 1u, (const uint8_t *)text, strlen(text))
	     == FZN_NODE_RECORDS_OK;
	/* AS A RECORD FROM A PEER IS TOLD. */
	fzn_node_decisions_forget();
	return ok;
}

static int decide(uint8_t host, const char *grounds, const char *value)
{
	be(host);
	return fzn_node_decisions_write(&nr, SUBJECT, SUBJECT_LEN, 0u, NULL,
	                                (const uint8_t *)grounds, grounds ? strlen(grounds) : 0u,
	                                (const uint8_t *)value, strlen(value))
	       == FZN_NODE_RECORDS_OK;
}

static long heads(void)
{
	return fzn_node_decisions_heads(&nr, SUBJECT, SUBJECT_LEN, NULL, NULL);
}

static long forks(void)
{
	return fzn_node_decisions_forks(&nr, NULL, NULL);
}

struct seen_rows {
	int n;
	char value[4][32];
};

static void seen_row(void *ctx, const fzn_node_decision_t *d)
{
	struct seen_rows *s = ctx;

	if (s->n < 4)
		snprintf(s->value[s->n++], sizeof(s->value[0]), "%.*s", (int)d->value_len,
		         (const char *)d->value);
}

static void reset(void)
{
	memset(&node, 0, sizeof(node));
	fzn_node_decisions_forget();
}

int main(void)
{
	static const uint8_t OTHER[] = "tune/y";
	struct seen_rows rows;

	me.sign = &SIGN;
	nr.b = &B;
	nr.verify = &SIGN;
	nr.id = &me;
	nr.now_ms = now_ms;

	/* ---- one writer, one after another */
	CHECK(heads() == 0 && forks() == 0, "nothing decided, nothing forked");
	CHECK(decide(HOST_A, NULL, "one"), "A decides");
	CHECK(heads() == 1 && forks() == 0, "one decision is one head");
	CHECK(decide(HOST_B, NULL, "two"), "B decides, having seen A's");
	CHECK(heads() == 1 && forks() == 0, "a decision that saw the last replaces it: no fork");
	memset(&rows, 0, sizeof(rows));
	CHECK(fzn_node_decisions_heads(&nr, SUBJECT, SUBJECT_LEN, seen_row, &rows) == 1
	              && !strcmp(rows.value[0], "two"),
	      "and it is the head");

	/* ---- held, and read again only when told */
	{
		long n = heads();

		memset(&node, 0, sizeof(node));
		CHECK(heads() == n, "the store is not walked again for a read");
		fzn_node_decisions_forget();
		CHECK(heads() == 0, "until it is told");
	}

	/* ---- apart */
	reset();
	CHECK(raw(HOST_A, "100.aaaaaaaa - - one") && raw(HOST_B, "100.bbbbbbbb - - two"),
	      "A and B each decide, neither having seen the other");
	CHECK(heads() == 2 && forks() == 1, "two heads that disagree are a fork");
	memset(&rows, 0, sizeof(rows));
	CHECK(fzn_node_decisions_forks(&nr, seen_row, &rows) == 1 && rows.n == 2
	              && !strcmp(rows.value[0], "two") && !strcmp(rows.value[1], "one"),
	      "both sides are shown, newest first");
	CHECK(decide(HOST_A, NULL, "three"), "and a decision that has seen both");
	CHECK(heads() == 1 && forks() == 0, "closes it, naming every head");

	/* ---- agreement needs no closing */
	reset();
	CHECK(raw(HOST_A, "100.aaaaaaaa - - same") && raw(HOST_B, "100.bbbbbbbb - - same"),
	      "A and B reach one value apart");
	CHECK(heads() == 2 && forks() == 0, "heads of one value are no fork");

	/* ---- what the writer saw arrives after what it wrote */
	reset();
	CHECK(raw(HOST_B, "101.bbbbbbbb 100.aaaaaaaa - later"),
	      "B saw A's setting, and A's record has not come");
	CHECK(heads() == 1 && forks() == 0, "alone it is the head");
	CHECK(raw(HOST_A, "100.aaaaaaaa - - earlier"), "A's record arrives after");
	CHECK(heads() == 1 && forks() == 0, "and is superseded as it lands, no fork ever shown");

	/* ---- a name is matched whole */
	reset();
	CHECK(raw(HOST_A, "100.aaaaaaaa - - one")
	              && raw(HOST_B, "101.bbbbbbbb 1100.aaaaaaaa,2100.aaaaaaaa - three"),
	      "a base that contains another's name");
	CHECK(heads() == 2 && forks() == 1, "does not supersede it");

	/* ---- the setting seen is named */
	reset();
	{
		fzn_node_decision_ref_t seen;

		CHECK(raw(HOST_A, "500.aaaaaaaa - - gone-soon"), "A's decision held");
		seen.number = 500u;
		memset(seen.host, HOST_A, FZN_PUBKEY_LEN);
		be(HOST_B);
		CHECK(fzn_node_decisions_write(&nr, SUBJECT, SUBJECT_LEN, 777u, &seen, NULL, 0u,
		                               (const uint8_t *)"mine", 4u)
		              == FZN_NODE_RECORDS_OK,
		      "B decides naming the setting it saw");
		CHECK(heads() == 1, "and the base is not named twice into a second head");
	}
	reset();
	CHECK(raw(HOST_A, "600.aaaaaaaa - - gone"), "a removal's");
	be(HOST_B);
	CHECK(fzn_node_decisions_write(&nr, SUBJECT, SUBJECT_LEN, 0u, NULL, NULL, 0u, NULL, 0u)
	              == FZN_NODE_RECORDS_OK
	              && heads() == 1,
	      "empty value is a decision too");

	/* ---- two deciders reach one answer from each other's grounds */
	reset();
	CHECK(raw(HOST_A, "100.aaaaaaaa - g1 5") && raw(HOST_B, "100.bbbbbbbb - g2 7"),
	      "two jobs decide apart, from different grounds");
	CHECK(forks() == 1, "a fork");
	{
		static const char *const BOTH = "g1+g2";

		CHECK(decide(HOST_A, BOTH, "7"), "the first decides again from both grounds");
		/* THE SECOND, not yet having heard the first's. Forged by a raw write
		 * naming the two old heads, as it would have. */
		CHECK(raw(HOST_B, "101.bbbbbbbb 100.aaaaaaaa,100.bbbbbbbb g1+g2 7"),
		      "and so does the second, not having heard");
		CHECK(heads() == 2 && forks() == 0, "one matrix over one set of grounds: no fork");
	}

	/* ---- subjects apart, and what is no decision */
	reset();
	CHECK(raw(HOST_A, "100.aaaaaaaa - - one") && raw(HOST_B, "100.bbbbbbbb - - two"), "a fork");
	be(HOST_A);
	CHECK(fzn_node_decisions_write(&nr, OTHER, 6u, 0u, NULL, NULL, 0u, (const uint8_t *)"z", 1u)
	              == FZN_NODE_RECORDS_OK
	              && forks() == 1,
	      "another subject's decision closes nothing and forks nothing");
	CHECK(raw(HOST_A, "garbage"), "a record that is no decision");
	CHECK(heads() == 2 && forks() == 1, "is passed over");

	/* ---- refused */
	{
		static uint8_t long_value[FZN_SETTING_VALUE_MAX + 1u];

		memset(long_value, 'v', sizeof(long_value));
		be(HOST_A);
		CHECK(fzn_node_decisions_write(&nr, SUBJECT, SUBJECT_LEN, 0u, NULL, NULL, 0u, long_value,
		                               sizeof(long_value))
		              == FZN_NODE_RECORDS_MALFORMED,
		      "a value past a record's room is refused");
		CHECK(fzn_node_decisions_write(&nr, SUBJECT, SUBJECT_LEN, 0u, NULL,
		                               (const uint8_t *)"two words", 9u, long_value, 1u)
		              == FZN_NODE_RECORDS_MALFORMED,
		      "grounds are one word");
		CHECK(fzn_node_decisions_write(&nr, (const uint8_t *)"BAD KEY", 7u, 0u, NULL, NULL, 0u,
		                               long_value, 1u)
		              == FZN_NODE_RECORDS_MALFORMED,
		      "a subject is a key's words");
	}

	/* ---- the verbs */
	reset();
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "list fork") && replied("ok 0 0 0"), "no fork listed");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "get decided tune/x") && replied("ok absent"),
	      "nothing decided is absent");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "add decided tune/x grounds=g1 a%20b") && replied("ok"),
	      "added");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "get decided tune/x") && replied("ok 1 ")
	              && strstr(reply, ",g1,a%20b"),
	      "read back, its grounds and its value");
	CHECK(raw(HOST_B, "100.bbbbbbbb - - other"), "another head");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "list fork") && replied("ok 0 2 0 tune/x,"),
	      "both heads listed by subject");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "list fork 1") && replied("ok 1 1 0 tune/x,"),
	      "and paged");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "list fork x") && replied("malformed"),
	      "a FROM that is no number");
	CHECK(said(&nr, FZN_ORIGIN_LOCAL, "list fork") && replied("denied"),
	      "another user is refused");
	CHECK(said(&nr, FZN_ORIGIN_SAME_USER, "list record") == 0, "a record's verb is not one of these");

	printf("decisions_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
