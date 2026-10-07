/* Tests for record/exchange.c: the journal between two hosts. sec 501.
 *
 * TWO HOSTS IN ONE PROCESS. Each has a journal and an in-memory store; the
 * client's `ask` calls the server's `fzn_exchange_answer` directly, so what
 * travels is exactly the bytes a remote hop would carry, without the hop.
 *
 * THE SIGNER IS A KEYED MIXING FUNCTION, keyed by the first byte of the
 * public key, as record_test's is: a record verifies under the key it was
 * signed as and under no other, and a changed signed byte refuses it.
 */

#include "../exchange.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL exchange_test.c:%d: %s\n", __LINE__, what);     \
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

/* ---- an in-memory store ---------------------------------------------- */

#define SLOTS 32

struct slot {
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint32_t stream;
	uint64_t seq;
	uint8_t bytes[FZN_RECORD_MAX_LEN];
	size_t len;
	int used;
};

struct host {
	struct slot slots[SLOTS];
	fzn_record_store_ops_t ops;
	fzn_record_store_t store;
	fzn_journal_entry_t entries[8];
	fzn_journal_t journal;
	size_t reply_cap;
};

static int mem_put(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t seq,
                   const uint8_t *bytes, size_t len)
{
	struct host *h = ctx;
	int i, free_one = -1;

	for (i = 0; i < SLOTS; i++) {
		if (!h->slots[i].used) {
			if (free_one < 0)
				free_one = i;
			continue;
		}
		if (h->slots[i].stream == stream && h->slots[i].seq == seq
		    && memcmp(h->slots[i].issuer, issuer, FZN_PUBKEY_LEN) == 0) {
			free_one = i;
			break;
		}
	}
	if (free_one < 0)
		return 0;
	memcpy(h->slots[free_one].issuer, issuer, FZN_PUBKEY_LEN);
	h->slots[free_one].stream = stream;
	h->slots[free_one].seq = seq;
	memcpy(h->slots[free_one].bytes, bytes, len);
	h->slots[free_one].len = len;
	h->slots[free_one].used = 1;
	return 1;
}

static int mem_get(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream, uint64_t seq,
                   uint8_t *out, size_t cap, size_t *len_out, int *found_out)
{
	struct host *h = ctx;
	int i;

	*found_out = 0;
	for (i = 0; i < SLOTS; i++)
		if (h->slots[i].used && h->slots[i].stream == stream && h->slots[i].seq == seq
		    && memcmp(h->slots[i].issuer, issuer, FZN_PUBKEY_LEN) == 0) {
			*found_out = 1;
			if (h->slots[i].len > cap)
				return 0;
			memcpy(out, h->slots[i].bytes, h->slots[i].len);
			*len_out = h->slots[i].len;
			return 1;
		}
	return 0;
}

static void host_init(struct host *h)
{
	memset(h, 0, sizeof(*h));
	h->ops.put = mem_put;
	h->ops.get = mem_get;
	h->ops.ctx = h;
	h->store.ops = &h->ops;
	h->store.log = NULL;
	fzn_journal_init(&h->journal, h->entries, 8);
	h->reply_cap = 4096u;
}

/* The client's asking: the server's answer, in this process. */
static int ask(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
               size_t reply_cap, size_t *reply_len)
{
	struct host *server = ctx;
	size_t cap = reply_cap < server->reply_cap ? reply_cap : server->reply_cap;

	*reply_len = fzn_exchange_answer(&server->journal, &server->store, request, request_len,
	                                 reply, cap);
	return *reply_len != 0u;
}

/* ---- fixtures ---------------------------------------------------------- */

static void key(uint8_t out[FZN_PUBKEY_LEN], uint8_t seed)
{
	size_t i;

	for (i = 0; i < FZN_PUBKEY_LEN; i++)
		out[i] = (uint8_t)(seed + i * 7u);
	out[0] = seed;
}

/* Record `seq` of `writer`'s stream 1, naming `prev`, with a body byte; into
 * `buf`, its length in `*len` and its id in `id`. */
static int make(uint8_t buf[FZN_RECORD_MAX_LEN], size_t *len, uint8_t writer, uint64_t seq,
                const uint8_t *prev, uint8_t body_byte, uint8_t id[FZN_RECORD_ID_LEN])
{
	uint8_t issuer[FZN_PUBKEY_LEN], subject[FZN_SUBJECT_LEN], body[40];

	key(issuer, writer);
	memset(subject, 0x5b, sizeof(subject));
	memset(body, body_byte, sizeof(body));
	signing_as = writer;
	return fzn_record_sign(issuer, subject, 1u, 9u, seq, prev, 100u + seq, body, sizeof(body),
	                       &SIGN, buf, FZN_RECORD_MAX_LEN, len) == FZN_RECORD_OK
	       && mix_hash(NULL, id, FZN_RECORD_ID_LEN, buf, *len);
}

/* Give `h` writer's chain 1..n, followed, admitted and stored. */
static int hold_chain(struct host *h, uint8_t writer, uint64_t n,
                      uint8_t ids[][FZN_RECORD_ID_LEN])
{
	uint8_t buf[FZN_RECORD_MAX_LEN], issuer[FZN_PUBKEY_LEN];
	uint64_t s;
	size_t len = 0;
	fzn_record_t r;

	key(issuer, writer);
	if (fzn_journal_anchor(&h->journal, issuer, 1u, 0) != FZN_JOURNAL_OK)
		return 0;
	for (s = 1; s <= n; s++) {
		if (!make(buf, &len, writer, s, s == 1u ? NULL : ids[s - 2u], (uint8_t)s, ids[s - 1u])
		    || fzn_record_open(buf, len, &r) != FZN_RECORD_OK
		    || fzn_journal_admit_chained(&h->journal, issuer, 1u, s, fzn_record_prev(r),
		                                 ids[s - 1u]) != FZN_JOURNAL_OK
		    || fzn_record_store_put(&h->store, r) != FZN_RECORD_STORE_OK)
			return 0;
	}
	return 1;
}

static uint8_t reply[8192];

static void test_a_follower_learns_the_chain(void)
{
	static struct host a, b;
	uint8_t ids[5][FZN_RECORD_ID_LEN], x_ids[2][FZN_RECORD_ID_LEN], w[FZN_PUBKEY_LEN];
	fzn_exchange_tally_t t;

	host_init(&a);
	host_init(&b);
	key(w, 0x41);
	CHECK(hold_chain(&a, 0x41, 5, ids) && hold_chain(&a, 0x58, 2, x_ids), "fixture: A holds two");
	CHECK(fzn_journal_anchor(&b.journal, w, 1u, 0) == FZN_JOURNAL_OK, "fixture: B follows W");

	/* ONE RECORD A PAGE: the reply buffer at its floor. */
	a.reply_cap = FZN_EXCHANGE_REPLY_MIN;
	CHECK(fzn_exchange_pull(&b.journal, &b.store, &SIGN, &HASH, 64u, ask, &a, reply,
	                        sizeof(reply), &t) == FZN_EXCHANGE_OK
	              && t.positions == 2u && t.requested == 1u && t.learned == 5u
	              && t.refused == 0u && t.forks == 0u,
	      "B did not learn W's five records from A, one a page");
	CHECK(fzn_journal_next(&b.journal, w, 1u) == 6u, "B's position is not past W's fifth");
	CHECK(fzn_record_store_stands(&b.store, &HASH, w, 1u, 5u, ids[4], 2u, ids[1]),
	      "a cut at W's fifth did not hold its second at B");
	{
		uint8_t x[FZN_PUBKEY_LEN];

		key(x, 0x58);
		CHECK(fzn_journal_next(&b.journal, x, 1u) == 1u,
		      "a stream B does not follow was fetched");
	}
	CHECK(fzn_exchange_pull(&b.journal, &b.store, &SIGN, &HASH, 64u, ask, &a, reply,
	                        sizeof(reply), &t) == FZN_EXCHANGE_OK
	              && t.learned == 0u,
	      "a second round learned something again");

	/* A SMALL WINDOW: three a request, still every record. */
	{
		static struct host c;

		host_init(&c);
		CHECK(fzn_journal_anchor(&c.journal, w, 1u, 0) == FZN_JOURNAL_OK
		              && fzn_exchange_pull(&c.journal, &c.store, &SIGN, &HASH, 3u, ask, &a,
		                                   reply, sizeof(reply), &t) == FZN_EXCHANGE_OK
		              && t.learned == 3u
		              && fzn_exchange_pull(&c.journal, &c.store, &SIGN, &HASH, 3u, ask, &a,
		                                   reply, sizeof(reply), &t) == FZN_EXCHANGE_OK
		              && t.learned == 2u && fzn_journal_next(&c.journal, w, 1u) == 6u,
		      "a window of three did not take the five in two rounds");
	}
}

/* THE PUSH, sec 512. The taker answers a digest as any server does, and
 * takes a PUSH through `fzn_exchange_take_push`. */
static int push_ask(void *ctx, const uint8_t *request, size_t request_len, uint8_t *out,
                    size_t out_cap, size_t *out_len)
{
	struct host *taker = ctx;
	size_t cap = out_cap < taker->reply_cap ? out_cap : taker->reply_cap;

	*out_len = fzn_exchange_take_push(&taker->journal, &taker->store, &SIGN, &HASH, request,
	                                  request_len, out, cap);
	if (*out_len)
		return 1;
	return ask(ctx, request, request_len, out, out_cap, out_len);
}

/* A holds W's five and X's two. B follows W and holds its first two. A pushes:
 * B takes W's third to fifth and is never offered X; a second push offers
 * nothing. At the floor buffer it goes over several messages. A PUSH carrying
 * X's record, which B does not follow, is refused; and C, holding a different
 * third record of W's, stops W at the fork. */
static void test_a_push(void)
{
	static struct host a, b, c, d;
	uint8_t ids[5][FZN_RECORD_ID_LEN], x_ids[2][FZN_RECORD_ID_LEN], w[FZN_PUBKEY_LEN];
	uint8_t x[FZN_PUBKEY_LEN];
	fzn_exchange_push_tally_t t;

	host_init(&a);
	host_init(&b);
	key(w, 0x41);
	key(x, 0x58);
	CHECK(hold_chain(&a, 0x41, 5, ids) && hold_chain(&a, 0x58, 2, x_ids)
	              && hold_chain(&b, 0x41, 2, ids),
	      "fixture: A holds W's five and X's two, B W's first two");
	CHECK(fzn_exchange_push(&a.journal, &a.store, push_ask, &b, reply, sizeof(reply), &t)
	                      == FZN_EXCHANGE_OK
	              && t.positions == 1u && t.offered == 3u && t.taken == 3u && t.held == 0u
	              && t.refused == 0u && t.forks == 0u,
	      "B did not take W's third to fifth, or was offered more");
	CHECK(fzn_journal_next(&b.journal, w, 1u) == 6u
	              && fzn_record_store_stands(&b.store, &HASH, w, 1u, 5u, ids[4], 1u, ids[0]),
	      "B's position is not past W's fifth, or the chain does not hold");
	CHECK(fzn_journal_next(&b.journal, x, 1u) == 1u, "B took a stream it does not follow");
	CHECK(fzn_exchange_push(&a.journal, &a.store, push_ask, &b, reply, sizeof(reply), &t)
	                      == FZN_EXCHANGE_OK
	              && t.offered == 0u,
	      "a second push offered what B holds");

	/* AT THE FLOOR BUFFER: room for one record of the largest size, so a
	 * stream goes over several messages. */
	host_init(&d);
	CHECK(fzn_journal_anchor(&d.journal, w, 1u, 0) == FZN_JOURNAL_OK
	              && fzn_exchange_push(&a.journal, &a.store, push_ask, &d, reply,
	                                   FZN_EXCHANGE_REPLY_MIN, &t) == FZN_EXCHANGE_OK
	              && t.offered == 5u && t.taken == 5u && fzn_journal_next(&d.journal, w, 1u) == 6u,
	      "at the floor buffer W's five did not all arrive");

	/* A STREAM THE TAKER DOES NOT FOLLOW, sent anyway: refused. */
	{
		uint8_t msg[FZN_EXCHANGE_PUSH_HEAD_LEN + 2u + FZN_RECORD_MAX_LEN], out[16];
		uint8_t buf[FZN_RECORD_MAX_LEN], id[FZN_RECORD_ID_LEN];
		size_t len = 0, n;

		CHECK(make(buf, &len, 0x58, 1, NULL, 1, id), "fixture: X's first record");
		msg[0] = (uint8_t)FZN_EXCHANGE_VERSION;
		msg[1] = (uint8_t)FZN_EXCHANGE_PUSH;
		msg[2] = 0u;
		msg[3] = 1u;
		msg[4] = (uint8_t)(len >> 8);
		msg[5] = (uint8_t)len;
		memcpy(msg + 6, buf, len);
		n = fzn_exchange_take_push(&b.journal, &b.store, &SIGN, &HASH, msg, 6u + len, out,
		                           sizeof(out));
		CHECK(n == FZN_EXCHANGE_PUSHED_LEN && out[3] == 0u && out[7] == 1u
		              && fzn_journal_next(&b.journal, x, 1u) == 1u,
		      "a pushed record of a stream B does not follow was taken");

		/* AND ONE B DOES FOLLOW, ITS SIGNATURE BROKEN: refused unread. */
		host_init(&d);
		CHECK(fzn_journal_anchor(&d.journal, w, 1u, 0) == FZN_JOURNAL_OK
		              && make(buf, &len, 0x41, 1, NULL, 1, id),
		      "fixture: W's first record, for a taker following W");
		buf[len - 1u] ^= 1u;
		msg[4] = (uint8_t)(len >> 8);
		msg[5] = (uint8_t)len;
		memcpy(msg + 6, buf, len);
		n = fzn_exchange_take_push(&d.journal, &d.store, &SIGN, &HASH, msg, 6u + len, out,
		                           sizeof(out));
		CHECK(n == FZN_EXCHANGE_PUSHED_LEN && out[3] == 0u && out[7] == 1u
		              && fzn_journal_next(&d.journal, w, 1u) == 1u,
		      "a pushed record whose signature fails was taken");
	}

	/* A FORK AT THE TAKER: C holds a different third record of W's. */
	{
		uint8_t buf[FZN_RECORD_MAX_LEN], other[FZN_RECORD_ID_LEN];
		size_t len = 0;
		fzn_record_t r;

		host_init(&c);
		CHECK(hold_chain(&c, 0x41, 2, ids) && make(buf, &len, 0x41, 3, ids[1], 0x77, other)
		              && fzn_record_open(buf, len, &r) == FZN_RECORD_OK
		              && fzn_journal_admit_chained(&c.journal, w, 1u, 3u, fzn_record_prev(r),
		                                           other) == FZN_JOURNAL_OK
		              && fzn_record_store_put(&c.store, r) == FZN_RECORD_STORE_OK,
		      "fixture: C holds a different third record of W's");
		CHECK(fzn_exchange_push(&a.journal, &a.store, push_ask, &c, reply,
		                        FZN_EXCHANGE_REPLY_MIN, &t) == FZN_EXCHANGE_OK
		              && t.offered == 2u && t.forks == 1u && t.taken == 0u
		              && fzn_journal_next(&c.journal, w, 1u) == 4u,
		      "a push past C's different third record was not stopped at the fork");
	}
	CHECK(fzn_exchange_take_push(NULL, &b.store, &SIGN, &HASH, reply, 4u, reply, sizeof(reply))
	              == 0u,
	      "take_push took no journal");
}

/* A SERVER THAT LIES, by rewriting what it was asked: one sequence further
 * on, or another issuer's stream. What comes back is well signed and is not
 * the record the client asked for. */
static int lie_seq, lie_issuer;
static uint8_t lie_to[FZN_PUBKEY_LEN];

static int lying_ask(void *ctx, const uint8_t *request, size_t request_len, uint8_t *out,
                     size_t out_cap, size_t *out_len)
{
	uint8_t bent[FZN_EXCHANGE_RECORDS_QUERY_LEN];

	if (request_len == sizeof(bent) && request[1] == (uint8_t)FZN_EXCHANGE_RECORDS_QUERY) {
		memcpy(bent, request, sizeof(bent));
		if (lie_seq)
			bent[45]++;
		if (lie_issuer)
			memcpy(bent + 2, lie_to, FZN_PUBKEY_LEN);
		return ask(ctx, bent, sizeof(bent), out, out_cap, out_len);
	}
	return ask(ctx, request, request_len, out, out_cap, out_len);
}

static void test_a_lying_server(void)
{
	static struct host a, b;
	uint8_t ids[3][FZN_RECORD_ID_LEN], x_ids[3][FZN_RECORD_ID_LEN], w[FZN_PUBKEY_LEN];
	fzn_exchange_tally_t t;

	host_init(&a);
	host_init(&b);
	key(w, 0x41);
	key(lie_to, 0x58);
	CHECK(hold_chain(&a, 0x41, 3, ids) && hold_chain(&a, 0x58, 3, x_ids)
	              && fzn_journal_anchor(&b.journal, w, 1u, 0) == FZN_JOURNAL_OK,
	      "fixture: A holds W and X, B follows W");
	lie_seq = 1;
	CHECK(fzn_exchange_pull(&b.journal, &b.store, &SIGN, &HASH, 64u, lying_ask, &a, reply,
	                        sizeof(reply), &t) == FZN_EXCHANGE_OK
	              && t.refused == 1u && t.learned == 0u,
	      "a record one past the one asked for was taken");
	lie_seq = 0;
	lie_issuer = 1;
	CHECK(fzn_exchange_pull(&b.journal, &b.store, &SIGN, &HASH, 64u, lying_ask, &a, reply,
	                        sizeof(reply), &t) == FZN_EXCHANGE_OK
	              && t.refused == 1u && t.learned == 0u
	              && fzn_journal_next(&b.journal, w, 1u) == 1u,
	      "another issuer's record was taken for W's");
	lie_issuer = 0;
}

/* A FORK AND A FORGERY. B holds W's first three. A serves a fourth whose
 * `prev` is not the third: a fork, counted, and B stays at three. A serves a
 * fourth with a broken signature: refused. The honest fourth is learned. */
static void test_a_fork_and_a_forgery(void)
{
	static struct host a, b;
	uint8_t ids[5][FZN_RECORD_ID_LEN], w[FZN_PUBKEY_LEN], other[FZN_RECORD_ID_LEN];
	uint8_t buf[FZN_RECORD_MAX_LEN], id4[FZN_RECORD_ID_LEN], honest[FZN_RECORD_MAX_LEN];
	size_t len = 0, honest_len = 0;
	fzn_exchange_tally_t t;
	fzn_record_t r;
	int i;

	host_init(&a);
	host_init(&b);
	key(w, 0x41);
	CHECK(hold_chain(&a, 0x41, 5, ids) && hold_chain(&b, 0x41, 3, ids),
	      "fixture: A holds five, B three");
	/* A's fourth swapped for one naming another predecessor. */
	memset(other, 0x99, sizeof(other));
	for (i = 0; i < SLOTS; i++)
		if (a.slots[i].used && a.slots[i].seq == 4u) {
			memcpy(honest, a.slots[i].bytes, a.slots[i].len);
			honest_len = a.slots[i].len;
		}
	CHECK(make(buf, &len, 0x41, 4u, other, 0x44, id4)
	              && fzn_record_open(buf, len, &r) == FZN_RECORD_OK
	              && fzn_record_store_put(&a.store, r) == FZN_RECORD_STORE_OK,
	      "fixture: a forked fourth at A");
	CHECK(fzn_exchange_pull(&b.journal, &b.store, &SIGN, &HASH, 64u, ask, &a, reply,
	                        sizeof(reply), &t) == FZN_EXCHANGE_OK
	              && t.forks == 1u && t.learned == 0u && fzn_journal_next(&b.journal, w, 1u) == 4u,
	      "a fourth naming another predecessor was taken, or not counted as a fork");

	/* THE HONEST FOURTH WITH ITS SIGNATURE BROKEN. */
	honest[honest_len - 1u] ^= 1u;
	CHECK(fzn_record_open(honest, honest_len, &r) == FZN_RECORD_OK
	              && fzn_record_store_put(&a.store, r) == FZN_RECORD_STORE_OK
	              && fzn_exchange_pull(&b.journal, &b.store, &SIGN, &HASH, 64u, ask, &a, reply,
	                                   sizeof(reply), &t) == FZN_EXCHANGE_OK
	              && t.refused == 1u && fzn_journal_next(&b.journal, w, 1u) == 4u,
	      "a fourth with a broken signature was taken");

	/* AND WHOLE: B catches up to five. */
	honest[honest_len - 1u] ^= 1u;
	CHECK(fzn_record_open(honest, honest_len, &r) == FZN_RECORD_OK
	              && fzn_record_store_put(&a.store, r) == FZN_RECORD_STORE_OK
	              && fzn_exchange_pull(&b.journal, &b.store, &SIGN, &HASH, 64u, ask, &a, reply,
	                                   sizeof(reply), &t) == FZN_EXCHANGE_OK
	              && t.learned == 2u && fzn_journal_next(&b.journal, w, 1u) == 6u,
	      "the honest fourth and fifth were not learned after the fork");
}

/* THE SERVER'S REFUSALS: another version, a query that does not parse, and
 * a reply buffer under the floor. */
static void test_the_edges(void)
{
	static struct host a;
	uint8_t q[FZN_EXCHANGE_RECORDS_QUERY_LEN], small[64];
	fzn_exchange_tally_t t;

	host_init(&a);
	memset(q, 0, sizeof(q));
	q[0] = 2u;
	q[1] = (uint8_t)FZN_EXCHANGE_DIGEST_QUERY;
	CHECK(fzn_exchange_answer(&a.journal, &a.store, q, FZN_EXCHANGE_DIGEST_QUERY_LEN, reply,
	                          sizeof(reply)) == 0u,
	      "another message version was answered");
	q[0] = (uint8_t)FZN_EXCHANGE_VERSION;
	q[1] = (uint8_t)FZN_EXCHANGE_RECORDS_QUERY;
	CHECK(fzn_exchange_answer(&a.journal, &a.store, q, sizeof(q) - 1u, reply, sizeof(reply))
	              == 0u,
	      "a short records query was answered");
	CHECK(fzn_exchange_answer(&a.journal, &a.store, q, sizeof(q), reply, sizeof(reply)) == 0u,
	      "a records query from sequence zero was answered");
	CHECK(fzn_exchange_pull(&a.journal, &a.store, &SIGN, &HASH, 64u, ask, &a, small,
	                        sizeof(small), &t) == FZN_EXCHANGE_ERR_MALFORMED,
	      "a pull with a reply buffer under one record went ahead");
}

int main(void)
{
	test_a_push();
	test_a_follower_learns_the_chain();
	test_a_fork_and_a_forgery();
	test_a_lying_server();
	test_the_edges();
	if (failures) {
		fprintf(stderr, "exchange_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("exchange_test: all %d checks passed\n", checks);
	return 0;
}
