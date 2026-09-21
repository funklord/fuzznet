/* Tests for catalog/index.c: the signed shard index and the blob it names.
 * sec 341.
 *
 * TWO THINGS THIS SUITE IS FOR.
 *
 * The canonical encoding, because the signature is over these bytes: a
 * trailing byte, a wrong tag and a zero count are each refused rather than
 * tolerated, and a body that encodes must decode to what went in.
 *
 * And the LOOKUP, which is a binary search over bytes that arrived from
 * somewhere else. It is checked against an INDEPENDENT LINEAR MODEL over
 * random keys at several sizes rather than against a handful of cases chosen
 * by the person who wrote the search -- the two agree only where the search is
 * right, and the model is small enough to be obviously correct.
 */

#include "../index.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

#if defined(__GNUC__)
#define FZN_CHECK_PRINTF __attribute__((format(printf, 3, 4)))
#else
#define FZN_CHECK_PRINTF
#endif

static void check_at(int ok, int line, const char *fmt, ...) FZN_CHECK_PRINTF;

static void check_at(int ok, int line, const char *fmt, ...)
{
	va_list ap;

	checks++;
	if (ok)
		return;

	failures++;
	fprintf(stderr, "  FAIL index_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

/* Deterministic, so a failure is reproducible without a seed to record. */
static uint32_t rng_state = 0x9e3779b9u;

static uint32_t rng_next(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 17;
	rng_state ^= rng_state << 5;
	return rng_state;
}

static void test_the_head_round_trips(void)
{
	fzn_catalog_index_t ix, back;
	uint8_t body[FZN_CATALOG_INDEX_HEAD_LEN + 1u];
	size_t len = 0;

	memset(&ix, 0, sizeof(ix));
	ix.floor = FZN_CATALOG_SHARD_ENTRIES_MIN;
	ix.shards = 4883;
	memset(ix.root.b, 0xab, sizeof(ix.root.b));

	CHECK(fzn_catalog_index_encode(&ix, body, sizeof(body), &len)
	          == FZN_CATALOG_OK, "the head would not encode");
	CHECK(len == FZN_CATALOG_INDEX_HEAD_LEN, "the head is %u bytes",
	      (unsigned)len);
	CHECK(body[0] == FZN_CATALOG_OBJECT_INDEX, "the object tag is wrong");

	CHECK(fzn_catalog_index_decode(body, len, &back) == FZN_CATALOG_OK,
	      "the head would not decode");
	CHECK(back.floor == ix.floor && back.shards == ix.shards,
	      "the numbers did not survive: floor %u shards %u",
	      (unsigned)back.floor, (unsigned)back.shards);
	CHECK(memcmp(back.root.b, ix.root.b, sizeof(ix.root.b)) == 0,
	      "the root did not survive");

	/* THE CANONICAL RULES. A trailing byte is refused rather than ignored:
	 * two spellings of one index would let a peer re-sign a different
	 * one. */
	CHECK(fzn_catalog_index_decode(body, len + 1u, &back)
	          == FZN_CATALOG_ERR_MALFORMED, "a trailing byte was ignored");
	CHECK(fzn_catalog_index_decode(body, len - 1u, &back)
	          == FZN_CATALOG_ERR_MALFORMED, "a truncated head decoded");
	/* PURGE's tag, spelled rather than including purge.h for one
	 * constant -- and it is another object's tag that matters here, not
	 * which one. */
	body[0] = 2u;
	CHECK(fzn_catalog_index_decode(body, len, &back)
	          == FZN_CATALOG_ERR_MALFORMED, "another object's tag decoded");
	body[0] = FZN_CATALOG_OBJECT_INDEX;
	/* The control: putting it back makes it decode again, so the three
	 * refusals above are about what they say and not about the buffer. */
	CHECK(fzn_catalog_index_decode(body, len, &back) == FZN_CATALOG_OK,
	      "the restored head would not decode");
}

static void test_the_empty_claims_are_refused(void)
{
	fzn_catalog_index_t ix, back;
	uint8_t body[FZN_CATALOG_INDEX_HEAD_LEN];
	size_t len = 0;

	memset(&ix, 0, sizeof(ix));
	ix.floor = 0;
	ix.shards = 4;
	CHECK(fzn_catalog_index_encode(&ix, body, sizeof(body), &len)
	          == FZN_CATALOG_ERR_MALFORMED,
	      "a floor of zero encoded -- C26's claim about an empty set");
	ix.floor = 8;
	ix.shards = 0;
	CHECK(fzn_catalog_index_encode(&ix, body, sizeof(body), &len)
	          == FZN_CATALOG_ERR_MALFORMED,
	      "an index over no shards encoded");
	/* The control. */
	ix.shards = 1;
	CHECK(fzn_catalog_index_encode(&ix, body, sizeof(body), &len)
	          == FZN_CATALOG_OK, "a one-shard index would not encode");

	/* And the same two refusals on the way in, where they arrive from a
	 * peer rather than from this host's own caller. */
	memset(body, 0, sizeof(body));
	body[0] = FZN_CATALOG_OBJECT_INDEX;
	body[8] = 4;   /* shards = 4, floor still 0 */
	CHECK(fzn_catalog_index_decode(body, sizeof(body), &back)
	          == FZN_CATALOG_ERR_MALFORMED, "a zero floor decoded");
	body[4] = 8;   /* floor = 8 */
	body[8] = 0;   /* shards = 0 */
	CHECK(fzn_catalog_index_decode(body, sizeof(body), &back)
	          == FZN_CATALOG_ERR_MALFORMED, "a zero shard count decoded");
	body[8] = 4;
	CHECK(fzn_catalog_index_decode(body, sizeof(body), &back)
	          == FZN_CATALOG_OK, "the control head would not decode");
}

static void test_the_length_guards_the_multiplication(void)
{
	size_t len = 0;

	CHECK(fzn_catalog_index_body_len(1, &len) == FZN_CATALOG_OK
	          && len == FZN_CATALOG_INDEX_ENTRY_LEN,
	      "one shard is not one entry long");
	CHECK(fzn_catalog_index_body_len(4883, &len) == FZN_CATALOG_OK
	          && len == 4883u * FZN_CATALOG_INDEX_ENTRY_LEN,
	      "a real-sized index is the wrong length");
	CHECK(fzn_catalog_index_body_len(0, &len) == FZN_CATALOG_ERR_MALFORMED,
	      "no shards has a length");

	/* THE COUNT ARRIVES OVER THE WIRE. A wrapped product is a legal
	 * size_t, so it cannot be detected after the multiplication -- which
	 * is why the guard is before it. */
	CHECK(fzn_catalog_index_body_len(((size_t)-1
	                                  / FZN_CATALOG_INDEX_ENTRY_LEN) + 1u,
	                                 &len) == FZN_CATALOG_ERR_RANGE,
	      "a count that overflows the length was accepted");
	/* The control, one below the boundary. */
	CHECK(fzn_catalog_index_body_len((size_t)-1
	                                 / FZN_CATALOG_INDEX_ENTRY_LEN, &len)
	          == FZN_CATALOG_OK, "the largest addressable index was refused");
	/* And a head naming such a count is refused at decode, so a caller
	 * never reaches the multiplication holding it. */
	{
		uint8_t head[FZN_CATALOG_INDEX_HEAD_LEN];
		fzn_catalog_index_t back;

		memset(head, 0, sizeof(head));
		head[0] = FZN_CATALOG_OBJECT_INDEX;
		head[4] = 1;                 /* floor = 1 */
		head[5] = head[6] = head[7] = head[8] = 0xff;  /* shards = 2^32-1 */
		if (sizeof(size_t) <= 4)
			CHECK(fzn_catalog_index_decode(head, sizeof(head), &back)
			          == FZN_CATALOG_ERR_RANGE,
			      "an unaddressable shard count decoded");
		else
			CHECK(fzn_catalog_index_decode(head, sizeof(head), &back)
			          == FZN_CATALOG_OK,
			      "a large but addressable count was refused");
	}
}

/* A plan of `n` shards whose first keys ascend, and roots that differ. */
static void build_plan(fzn_catalog_shard_t *plan, fzn_catalog_blob_root_t *roots,
                       size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		memset(plan[i].first.b, 0, sizeof(plan[i].first.b));
		/* Leave gaps, so there are keys BETWEEN starts to look up. */
		plan[i].first.b[0] = (uint8_t)(i * 3u);
		plan[i].first.b[31] = (uint8_t)i;
		plan[i].entries = FZN_CATALOG_SHARD_ENTRIES_MIN;
		memset(roots[i].b, (int)(0x40u + i), sizeof(roots[i].b));
	}
}

static void test_the_body_refuses_overlapping_ranges(void)
{
	fzn_catalog_shard_t plan[4];
	fzn_catalog_blob_root_t roots[4];
	uint8_t body[4u * FZN_CATALOG_INDEX_ENTRY_LEN];
	size_t len = 0;

	build_plan(plan, roots, 4);

	/* The control: a sorted plan encodes, and reads back entry by entry. */
	CHECK(fzn_catalog_index_body_encode(plan, roots, 4, body, sizeof(body),
	                                    &len) == FZN_CATALOG_OK,
	      "a sorted plan would not encode");
	CHECK(len == sizeof(body), "the body is the wrong length");
	CHECK(fzn_catalog_index_body_ok(body, len, 4),
	      "a well-formed body was called malformed");
	{
		fzn_catalog_shard_key_t first;
		fzn_catalog_blob_root_t root;
		size_t i;

		for (i = 0; i < 4; i++) {
			CHECK(fzn_catalog_index_entry_at(body, len, i, &first,
			                                 &root) == FZN_CATALOG_OK,
			      "entry %u would not read", (unsigned)i);
			CHECK(memcmp(first.b, plan[i].first.b, sizeof(first.b)) == 0,
			      "entry %u has the wrong first key", (unsigned)i);
			CHECK(memcmp(root.b, roots[i].b, sizeof(root.b)) == 0,
			      "entry %u has the wrong root", (unsigned)i);
		}
		CHECK(fzn_catalog_index_entry_at(body, len, 4, &first, &root)
		          == FZN_CATALOG_ERR_RANGE, "entry 4 of 4 was readable");
		/* Both outputs are optional. */
		CHECK(fzn_catalog_index_entry_at(body, len, 0, NULL, NULL)
		          == FZN_CATALOG_OK, "a caller wanting neither half failed");
	}

	/* OUT OF ORDER: ranges that overlap cannot say which blob holds a key,
	 * and nothing downstream would notice. */
	{
		fzn_catalog_shard_key_t swap = plan[1].first;

		plan[1].first = plan[2].first;
		plan[2].first = swap;
		CHECK(fzn_catalog_index_body_encode(plan, roots, 4, body,
		                                    sizeof(body), &len)
		          == FZN_CATALOG_ERR_MALFORMED,
		      "an out-of-order plan encoded");
		swap = plan[1].first;
		plan[1].first = plan[2].first;
		plan[2].first = swap;
	}
	/* EQUAL is out of order too: two entries with one start is two blobs
	 * claiming the same key. */
	plan[2].first = plan[1].first;
	CHECK(fzn_catalog_index_body_encode(plan, roots, 4, body, sizeof(body),
	                                    &len) == FZN_CATALOG_ERR_MALFORMED,
	      "two shards with the same start encoded");
	/* A body too small is refused before anything is written. */
	build_plan(plan, roots, 4);
	CHECK(fzn_catalog_index_body_encode(plan, roots, 4, body,
	                                    sizeof(body) - 1u, &len)
	          == FZN_CATALOG_ERR_RANGE, "the body overflowed its buffer");
}

static void test_body_ok_is_the_precondition(void)
{
	fzn_catalog_shard_t plan[4];
	fzn_catalog_blob_root_t roots[4];
	uint8_t body[4u * FZN_CATALOG_INDEX_ENTRY_LEN];
	size_t len = 0;

	build_plan(plan, roots, 4);
	fzn_catalog_index_body_encode(plan, roots, 4, body, sizeof(body), &len);

	CHECK(fzn_catalog_index_body_ok(body, len, 0), "the control failed");
	CHECK(fzn_catalog_index_body_ok(body, len, 4), "the count was rejected");
	CHECK(!fzn_catalog_index_body_ok(body, len, 3),
	      "a body of 4 passed as 3 -- the head and the blob disagreeing");
	CHECK(!fzn_catalog_index_body_ok(body, len - 1u, 0),
	      "a partial entry passed");
	CHECK(!fzn_catalog_index_body_ok(body, 0, 0), "an empty body passed");
	CHECK(!fzn_catalog_index_body_ok(NULL, len, 0), "a null body passed");

	/* Out of order in the BLOB, which is where it matters: the encoder
	 * refuses it, and a blob arrives from somewhere that may not have
	 * used the encoder. */
	{
		uint8_t swap[FZN_CATALOG_INDEX_ENTRY_LEN];

		memcpy(swap, &body[1u * FZN_CATALOG_INDEX_ENTRY_LEN],
		       sizeof(swap));
		memcpy(&body[1u * FZN_CATALOG_INDEX_ENTRY_LEN],
		       &body[2u * FZN_CATALOG_INDEX_ENTRY_LEN], sizeof(swap));
		memcpy(&body[2u * FZN_CATALOG_INDEX_ENTRY_LEN], swap,
		       sizeof(swap));
		CHECK(!fzn_catalog_index_body_ok(body, len, 4),
		      "an out-of-order blob passed the precondition");
	}
}

/* The independent model: the last entry whose first key is <= `key`, or 0. */
static size_t linear_lookup(const uint8_t *body, size_t entries,
                            const uint8_t *key)
{
	size_t i, best = 0;

	for (i = 0; i < entries; i++) {
		if (memcmp(&body[i * FZN_CATALOG_INDEX_ENTRY_LEN], key,
		           FZN_CATALOG_SHARD_KEY_LEN) <= 0)
			best = i;
	}
	return best;
}

static void test_lookup_against_a_linear_model(void)
{
	static const size_t sizes[] = { 1, 2, 3, 7, 8, 9, 64 };
	fzn_catalog_shard_t plan[64];
	fzn_catalog_blob_root_t roots[64];
	uint8_t body[64u * FZN_CATALOG_INDEX_ENTRY_LEN];
	size_t s, len = 0;
	int disagreements = 0;

	for (s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
		size_t n = sizes[s], t;

		build_plan(plan, roots, n);
		CHECK(fzn_catalog_index_body_encode(plan, roots, n, body,
		                                    sizeof(body), &len)
		          == FZN_CATALOG_OK, "a plan of %u would not encode",
		      (unsigned)n);

		/* Every start key, which is the boundary case a search gets
		 * wrong: a key EQUAL to a start belongs to that shard, not the
		 * one before it. */
		for (t = 0; t < n; t++) {
			fzn_catalog_shard_key_t k;
			size_t got = (size_t)-1;

			k = plan[t].first;
			CHECK(fzn_catalog_index_lookup(body, len, &k, &got)
			          == FZN_CATALOG_OK, "a start key would not look up");
			if (got != t)
				disagreements++;
			CHECK(got == t, "the start of shard %u routed to %u",
			      (unsigned)t, (unsigned)got);
		}

		/* And random keys against the model. */
		for (t = 0; t < 400; t++) {
			fzn_catalog_shard_key_t k;
			size_t got = (size_t)-1, want;
			size_t b;

			for (b = 0; b < FZN_CATALOG_SHARD_KEY_LEN; b++)
				k.b[b] = (uint8_t)(rng_next() >> 13);
			/* Keep most keys inside the range the plan spans, or
			 * nearly every draw lands past the last start and the
			 * interesting cases never come up. */
			k.b[0] = (uint8_t)(rng_next() % (3u * (unsigned)n + 2u));

			want = linear_lookup(body, n, k.b);
			CHECK(fzn_catalog_index_lookup(body, len, &k, &got)
			          == FZN_CATALOG_OK, "a random key would not look up");
			if (got != want)
				disagreements++;
		}
	}
	CHECK(disagreements == 0,
	      "the search and the linear model disagreed %d times",
	      disagreements);

	/* And the two refusals that are not about a key at all. */
	{
		fzn_catalog_shard_key_t k;
		size_t got = 0;

		memset(k.b, 0, sizeof(k.b));
		CHECK(fzn_catalog_index_lookup(body, 0, &k, &got)
		          == FZN_CATALOG_ERR_ABSENT, "an empty index answered");
		CHECK(fzn_catalog_index_lookup(body, len - 1u, &k, &got)
		          == FZN_CATALOG_ERR_RANGE, "a partial entry answered");
		CHECK(fzn_catalog_index_lookup(NULL, len, &k, &got)
		          == FZN_CATALOG_ERR_MALFORMED, "a null body answered");
	}
}

int main(void)
{
	test_the_head_round_trips();
	test_the_empty_claims_are_refused();
	test_the_length_guards_the_multiplication();
	test_the_body_refuses_overlapping_ranges();
	test_body_ok_is_the_precondition();
	test_lookup_against_a_linear_model();

	printf("index_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
