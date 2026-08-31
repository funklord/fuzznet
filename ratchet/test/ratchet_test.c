/* Tests for ratchet/ratchet.c: the KDF step, its alias-safety, and the
 * bounded fast-forward.
 *
 * THE PROPERTY THAT MATTERS MOST HERE CANNOT BE TESTED, and saying so is
 * better than pretending otherwise. That a message key does not yield the
 * next chain key is a property of the HASH, not of this file: against the
 * mixing stub below it is false in whatever way the stub is invertible, and
 * against a real hash it is not something a test can demonstrate. What this
 * file can and does check is that the two halves come from one call over the
 * chain key and are not each other -- which is the part that could be got
 * wrong by writing the code, as opposed to by choosing the primitive.
 *
 * The stub is a mixing function over every input byte, as elsewhere here. It
 * has to depend on everything or "this input reached the derivation" becomes
 * a question with no observable answer.
 */

#include "../ratchet.h"

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
	fprintf(stderr, "  FAIL ratchet_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

static unsigned long hash_calls;

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	(void)ctx;
	hash_calls++;
	if (!out || !in)
		return 0;

	h ^= (uint64_t)out_len;
	h *= 0x100000001b3ull;
	for (i = 0; i < in_len; i++) {
		h ^= in[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < out_len; i++) {
		h ^= (uint64_t)i + 0x9e3779b97f4a7c15ull;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 32);
	}
	return 1;
}

/* Refuses after `budget` calls, so the failing paths can be reached at a
 * chosen depth rather than only at the first step. */
static unsigned long refuse_after;

static int budgeted_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in,
                         size_t in_len)
{
	if (hash_calls >= refuse_after) {
		hash_calls++;
		return 0;
	}
	return stub_hash(ctx, out, out_len, in, in_len);
}

static const fzn_hash_ops_t HASH = { stub_hash, NULL };
static const fzn_hash_ops_t BUDGET = { budgeted_hash, NULL };

static void seed(uint8_t key[FZN_CHAIN_KEY_LEN], uint8_t byte)
{
	size_t i;

	for (i = 0; i < FZN_CHAIN_KEY_LEN; i++)
		key[i] = (uint8_t)(byte + i);
}

/* ---- the cases -------------------------------------------------------- */

/* INIT IS TOTAL, ON THE ONE PATH NOTHING TAKES.
 *
 * `fzn_ratchet_init` zeroes the chain, copies the key ONLY IF it is
 * non-NULL, and sets the sequence. So with a key the struct is written in
 * full either way and the zeroing cannot be observed -- but with NULL it is
 * the only thing putting `key` in a known state, and removing it leaves the
 * chain carrying whatever the caller's memory held. Every key the ratchet
 * then derives comes off that.
 *
 * NINE CALL SITES AND NOT ONE PASSES NULL, measured across the tree: two in
 * session_test.c, one in tool/consumer_check.c, one in persist.c restoring
 * from bytes, and five here. So the branch is never executed and removing
 * the zeroing changed no result -- which is how `make sabotage` found it and
 * why it needs a case rather than a reader.
 *
 * WHAT IS ASSERTED IS DETERMINISM, NOT A VALUE. ratchet.h documents the
 * struct and the meaning of `seq` and says nothing about a NULL key; the
 * `if (key)` in ratchet.c is the only statement that the case exists. So
 * this pins what the zeroing actually provides -- that the result does not
 * depend on the caller's memory -- rather than inventing a promise about
 * what a keyless chain contains, which is not this test's to make.
 *
 * The `with a key` half is here to show the asymmetry rather than to guard
 * it: it passes with the zeroing removed, and a version of this test that
 * only did that would prove nothing. */
static void test_init_does_not_depend_on_what_the_memory_held(void)
{
	fzn_ratchet_chain_t dirty, clean;
	uint8_t k[FZN_CHAIN_KEY_LEN];

	memset(k, 0x5c, sizeof(k));

	/* The control: 0xab must differ from what init leaves behind, or the
	 * comparison below is between two copies of nothing. */
	memset(&dirty, 0xab, sizeof(dirty));
	fzn_ratchet_init(&dirty, k, 7u);
	CHECK(memcmp(dirty.key, k, sizeof(k)) == 0 && dirty.seq == 7u,
	      "init with a key did not write the chain, so this test cannot fail");

	/* With a key, both start states converge because the copy covers every
	 * byte. This half holds with the zeroing deleted. */
	memset(&dirty, 0xab, sizeof(dirty));
	memset(&clean, 0, sizeof(clean));
	fzn_ratchet_init(&dirty, k, 3u);
	fzn_ratchet_init(&clean, k, 3u);
	CHECK(memcmp(&dirty, &clean, sizeof(dirty)) == 0,
	      "init with a key depends on the caller's memory");

	/* With NO key, only the zeroing makes the two agree. This is the half
	 * that fails when it is removed. */
	memset(&dirty, 0xab, sizeof(dirty));
	memset(&clean, 0, sizeof(clean));
	fzn_ratchet_init(&dirty, NULL, 3u);
	fzn_ratchet_init(&clean, NULL, 3u);
	CHECK(memcmp(&dirty, &clean, sizeof(dirty)) == 0,
	      "init with no key left the caller's bytes in the chain, so every "
	      "key derived from it would come off whatever the memory held");
}

static void test_a_step_produces_two_different_keys(void)
{
	uint8_t k[FZN_CHAIN_KEY_LEN];
	uint8_t mk[FZN_MESSAGE_KEY_LEN];
	uint8_t next[FZN_CHAIN_KEY_LEN];

	seed(k, 0x10);
	CHECK(fzn_ratchet_derive(&HASH, k, mk, next) == FZN_RATCHET_OK, "a step refused");
	CHECK(memcmp(mk, next, FZN_MESSAGE_KEY_LEN) != 0,
	      "the message key and the next chain key are the same bytes, so the two "
	      "halves are one half twice");
	CHECK(memcmp(mk, k, FZN_MESSAGE_KEY_LEN) != 0,
	      "the message key is the chain key, so nothing was derived");
	CHECK(memcmp(next, k, FZN_CHAIN_KEY_LEN) != 0,
	      "the next chain key is the current one, so the chain does not move");
}

static void test_a_step_is_a_function_of_the_chain_key(void)
{
	uint8_t a[FZN_CHAIN_KEY_LEN];
	uint8_t b[FZN_CHAIN_KEY_LEN];
	uint8_t mk_a[FZN_MESSAGE_KEY_LEN], mk_b[FZN_MESSAGE_KEY_LEN];
	uint8_t nx_a[FZN_CHAIN_KEY_LEN], nx_b[FZN_CHAIN_KEY_LEN];
	size_t i;

	seed(a, 0x20);
	memcpy(b, a, sizeof(b));

	CHECK(fzn_ratchet_derive(&HASH, a, mk_a, nx_a) == FZN_RATCHET_OK, "refused");
	CHECK(fzn_ratchet_derive(&HASH, b, mk_b, nx_b) == FZN_RATCHET_OK, "refused");
	CHECK(memcmp(mk_a, mk_b, sizeof(mk_a)) == 0 && memcmp(nx_a, nx_b, sizeof(nx_a)) == 0,
	      "the same chain key gave two different answers");

	/* EVERY BYTE OF THE CHAIN KEY REACHES BOTH OUTPUTS. A derivation that
	 * read a prefix would pass every case above and would mean two chains
	 * agreeing on 31 bytes produce one keystream. Checked at every
	 * position rather than the first and the last, which is where a
	 * length is usually wrong. */
	for (i = 0; i < FZN_CHAIN_KEY_LEN; i++) {
		memcpy(b, a, sizeof(b));
		b[i] = (uint8_t)(b[i] ^ 0x01u);
		CHECK(fzn_ratchet_derive(&HASH, b, mk_b, nx_b) == FZN_RATCHET_OK, "refused");
		CHECK(memcmp(mk_a, mk_b, sizeof(mk_a)) != 0,
		      "byte %zu of the chain key does not reach the message key", i);
		CHECK(memcmp(nx_a, nx_b, sizeof(nx_a)) != 0,
		      "byte %zu of the chain key does not reach the next chain key", i);
	}
}

static void test_a_step_is_alias_safe(void)
{
	uint8_t k[FZN_CHAIN_KEY_LEN];
	uint8_t mk[FZN_MESSAGE_KEY_LEN];
	uint8_t next[FZN_CHAIN_KEY_LEN];
	uint8_t in_place[FZN_CHAIN_KEY_LEN];
	uint8_t in_place_mk[FZN_MESSAGE_KEY_LEN];

	seed(k, 0x30);
	CHECK(fzn_ratchet_derive(&HASH, k, mk, next) == FZN_RATCHET_OK, "the control refused");

	/* `derive(k, mk, k)` -- the natural way to spell "advance this chain"
	 * when the caller owns the state, and therefore the form somebody
	 * will write whether or not it is documented. */
	memcpy(in_place, k, sizeof(in_place));
	CHECK(fzn_ratchet_derive(&HASH, in_place, in_place_mk, in_place) == FZN_RATCHET_OK,
	      "the in-place advance refused");
	CHECK(memcmp(in_place, next, FZN_CHAIN_KEY_LEN) == 0,
	      "advancing in place gave a different chain key than advancing into a "
	      "separate buffer");
	CHECK(memcmp(in_place_mk, mk, FZN_MESSAGE_KEY_LEN) == 0,
	      "advancing in place gave a different message key");

	/* And the other aliasing, `derive(k, k, next)`, which is the shape a
	 * caller writes when it wants the message key and does not care about
	 * the old chain key. */
	memcpy(in_place, k, sizeof(in_place));
	CHECK(fzn_ratchet_derive(&HASH, in_place, in_place, next) == FZN_RATCHET_OK,
	      "the message-key-over-input form refused");
	CHECK(memcmp(in_place, mk, FZN_MESSAGE_KEY_LEN) == 0,
	      "writing the message key over the chain key gave the wrong key");
	CHECK(memcmp(next, in_place, FZN_CHAIN_KEY_LEN) != 0,
	      "the next chain key equals the message key");
}

static void test_a_fast_forward_equals_stepping(void)
{
	fzn_ratchet_chain_t moved;
	uint8_t k[FZN_CHAIN_KEY_LEN];
	fzn_ratchet_chain_t chain;
	uint8_t stepped_key[FZN_CHAIN_KEY_LEN];
	uint8_t stepped_mk[FZN_MESSAGE_KEY_LEN];
	uint8_t jumped_mk[FZN_MESSAGE_KEY_LEN];
	uint8_t skipped[8][FZN_MESSAGE_KEY_LEN];
	size_t kept = 0, lost = 1;
	unsigned i;

	seed(k, 0x40);

	/* THE ORACLE IS STEPPING ONE AT A TIME, which is a second
	 * implementation of the fast-forward rather than a restatement of it:
	 * the loop is here, in the test, over the public one-step function. A
	 * fast-forward that agreed with itself would prove nothing. */
	memcpy(stepped_key, k, sizeof(stepped_key));
	for (i = 0; i <= 5u; i++)
		CHECK(fzn_ratchet_derive(&HASH, stepped_key, stepped_mk, stepped_key)
		              == FZN_RATCHET_OK, "step %u refused", i);

	fzn_ratchet_init(&chain, k, 0);
	CHECK(fzn_ratchet_advance(&HASH, &chain, 5u, jumped_mk, &moved, skipped[0], 8, &kept,
	                          &lost) == FZN_RATCHET_OK, "the fast-forward refused");
	chain = moved;
	CHECK(memcmp(jumped_mk, stepped_mk, FZN_MESSAGE_KEY_LEN) == 0,
	      "jumping to 5 and stepping to 5 gave different message keys");
	CHECK(memcmp(chain.key, stepped_key, FZN_CHAIN_KEY_LEN) == 0,
	      "jumping to 5 and stepping to 5 left different chain keys");
	CHECK(chain.seq == 6u, "the chain is at %llu after reaching 5, wanted 6",
	      (unsigned long long)chain.seq);

	/* THE SKIPPED KEYS ARE THE ONES JUMPED OVER, in order, and this is
	 * checked against the same stepping oracle rather than against
	 * itself. */
	CHECK(kept == 5u, "kept %zu skipped keys, wanted 5", kept);
	CHECK(lost == 0u, "reported %zu dropped with room for eight", lost);
	{
		uint8_t again[FZN_CHAIN_KEY_LEN];
		uint8_t mk[FZN_MESSAGE_KEY_LEN];

		memcpy(again, k, sizeof(again));
		for (i = 0; i < 5u; i++) {
			CHECK(fzn_ratchet_derive(&HASH, again, mk, again) == FZN_RATCHET_OK,
			      "oracle step refused");
			CHECK(memcmp(skipped[i], mk, FZN_MESSAGE_KEY_LEN) == 0,
			      "skipped key %u is not the key for sequence %u", i, i);
		}
	}
}

static void test_a_zero_length_advance_is_one_step(void)
{
	fzn_ratchet_chain_t moved;
	uint8_t k[FZN_CHAIN_KEY_LEN];
	fzn_ratchet_chain_t chain;
	uint8_t mk[FZN_MESSAGE_KEY_LEN];
	uint8_t direct_mk[FZN_MESSAGE_KEY_LEN];
	uint8_t next[FZN_CHAIN_KEY_LEN];
	size_t kept = 9, lost = 9;
	uint8_t skipped[1][FZN_MESSAGE_KEY_LEN];

	seed(k, 0x50);
	CHECK(fzn_ratchet_derive(&HASH, k, direct_mk, next) == FZN_RATCHET_OK, "refused");

	/* Asking for the sequence number the chain is already at is the
	 * ordinary in-order case, and it must be exactly one step. An
	 * off-by-one here is the failure the header's note about `seq` meaning
	 * "the one it will produce" exists to prevent, and it would surface as
	 * two peers failing to authenticate rather than as anything local. */
	fzn_ratchet_init(&chain, k, 0);
	CHECK(fzn_ratchet_advance(&HASH, &chain, 0, mk, &moved, skipped[0], 1, &kept, &lost)
	              == FZN_RATCHET_OK, "an in-order advance refused");
	chain = moved;
	CHECK(memcmp(mk, direct_mk, FZN_MESSAGE_KEY_LEN) == 0,
	      "the in-order message key is not one step from the chain key");
	CHECK(memcmp(chain.key, next, FZN_CHAIN_KEY_LEN) == 0, "the chain did not advance once");
	CHECK(chain.seq == 1u, "the chain is at %llu, wanted 1", (unsigned long long)chain.seq);
	CHECK(kept == 0u && lost == 0u, "an in-order advance skipped %zu keys", kept);
}

static void test_behind_is_refused_and_is_not_an_attack(void)
{
	fzn_ratchet_chain_t moved;
	uint8_t k[FZN_CHAIN_KEY_LEN];
	fzn_ratchet_chain_t chain;
	fzn_ratchet_chain_t before;
	uint8_t mk[FZN_MESSAGE_KEY_LEN];

	seed(k, 0x60);
	fzn_ratchet_init(&chain, k, 10u);
	before = chain;

	CHECK(fzn_ratchet_advance(&HASH, &chain, 9u, mk, &moved, NULL, 0, NULL, NULL)
	              == FZN_RATCHET_ERR_BEHIND,
	      "a target behind the chain was accepted, so the chain runs backwards");
	CHECK(memcmp(&before, &chain, sizeof(chain)) == 0,
	      "a refused advance moved the chain");

	/* ITS OWN CODE, not folded into MALFORMED. A caller has to be able to
	 * tell "a duplicate arrived", which is hourly on a datagram transport,
	 * from "my own code passed a null". */
	CHECK(FZN_RATCHET_ERR_BEHIND != FZN_RATCHET_ERR_MALFORMED,
	      "a duplicate and a caller bug share an error code");
}

static void test_the_fast_forward_is_bounded(void)
{
	fzn_ratchet_chain_t moved;
	uint8_t k[FZN_CHAIN_KEY_LEN];
	fzn_ratchet_chain_t chain;
	fzn_ratchet_chain_t before;
	uint8_t mk[FZN_MESSAGE_KEY_LEN];
	unsigned long at_the_bound;

	seed(k, 0x70);

	/* PAST THE BOUND IS REFUSED WITHOUT DERIVING ANYTHING, which is the
	 * whole value of the valve: the refusal has to be cheap, or a
	 * stranger still buys the work by being refused. Counted rather than
	 * asserted in prose. */
	fzn_ratchet_init(&chain, k, 0);
	before = chain;
	hash_calls = 0;
	CHECK(fzn_ratchet_advance(&HASH, &chain, (uint64_t)FZN_RATCHET_MAX_ADVANCE + 1u, mk,
	                          &moved, NULL, 0, NULL, NULL) == FZN_RATCHET_ERR_TOO_FAR,
	      "a jump past the bound was accepted");
	CHECK(hash_calls == 0u, "a refused jump cost %lu derivations, so the bound is not "
	      "a defence", hash_calls);
	CHECK(memcmp(&before, &chain, sizeof(chain)) == 0, "a refused jump moved the chain");

	/* AND EXACTLY AT THE BOUND IS ACCEPTED, so the comparison is not off
	 * by one in the direction that quietly narrows it. This is also the
	 * measurement the header cites: what one message naming a far-future
	 * sequence actually costs a receiver. */
	fzn_ratchet_init(&chain, k, 0);
	hash_calls = 0;
	CHECK(fzn_ratchet_advance(&HASH, &chain, (uint64_t)FZN_RATCHET_MAX_ADVANCE, mk, &moved,
	                          NULL, 0, NULL, NULL) == FZN_RATCHET_OK,
	      "a jump of exactly FZN_RATCHET_MAX_ADVANCE was refused");
	at_the_bound = hash_calls;
	CHECK(at_the_bound == (unsigned long)FZN_RATCHET_MAX_ADVANCE + 1u,
	      "a jump to the bound cost %lu derivations, wanted %lu", at_the_bound,
	      (unsigned long)FZN_RATCHET_MAX_ADVANCE + 1u);
	printf("ratchet_test: a jump to the bound costs %lu derivations\n", at_the_bound);
}

static void test_a_refused_hash_leaves_the_chain_alone(void)
{
	fzn_ratchet_chain_t moved;
	uint8_t k[FZN_CHAIN_KEY_LEN];
	fzn_ratchet_chain_t chain;
	fzn_ratchet_chain_t before;
	uint8_t mk[FZN_MESSAGE_KEY_LEN];

	seed(k, 0x80);
	fzn_ratchet_init(&chain, k, 0);
	before = chain;

	/* REFUSED PART-WAY THROUGH, at the third of six steps, which is the
	 * case the atomicity is for -- a failure at the first step could be
	 * survived by a function that mutated as it went. */
	hash_calls = 0;
	refuse_after = 3u;
	CHECK(fzn_ratchet_advance(&BUDGET, &chain, 5u, mk, &moved, NULL, 0, NULL, NULL)
	              == FZN_RATCHET_ERR_HASH,
	      "a refusing hash did not stop the fast-forward");
	CHECK(memcmp(&before, &chain, sizeof(chain)) == 0,
	      "a fast-forward that failed part-way moved its source chain");
}

static void test_the_skipped_cap_reports_what_it_dropped(void)
{
	fzn_ratchet_chain_t moved;
	uint8_t k[FZN_CHAIN_KEY_LEN];
	fzn_ratchet_chain_t chain;
	uint8_t mk[FZN_MESSAGE_KEY_LEN];
	uint8_t skipped[2][FZN_MESSAGE_KEY_LEN];
	size_t kept = 0, lost = 0;

	seed(k, 0x90);
	fzn_ratchet_init(&chain, k, 0);

	/* A caller that asked for less than there was must be TOLD, rather
	 * than left to infer it from a count that stopped short -- which is
	 * `fzn_manifest_deficit`'s shape and the same argument. */
	CHECK(fzn_ratchet_advance(&HASH, &chain, 5u, mk, &moved, skipped[0], 2, &kept, &lost)
	              == FZN_RATCHET_OK, "the advance refused");
	chain = moved;
	CHECK(kept == 2u, "kept %zu with room for two", kept);
	CHECK(lost == 3u, "reported %zu dropped, wanted 3", lost);
	CHECK(chain.seq == 6u, "a capped advance did not reach the target");
}

static void test_a_live_chain_cannot_be_advanced_in_place(void)
{
	uint8_t k[FZN_CHAIN_KEY_LEN];
	fzn_ratchet_chain_t chain;
	fzn_ratchet_chain_t before;
	fzn_ratchet_chain_t moved;
	uint8_t mk[FZN_MESSAGE_KEY_LEN];

	seed(k, 0xc0);
	fzn_ratchet_init(&chain, k, 4u);
	before = chain;

	/* THE DEFECT THIS SIGNATURE EXISTS TO MAKE UNSPELLABLE, and it is not
	 * hypothetical -- fuzzypickles traced it in their own live path at
	 * a311c7f after this library asked them a question about CPU cost.
	 *
	 * A receiver reads a sequence number out of an arriving frame,
	 * fast-forwards, derives a key and only then tries to open the
	 * ciphertext. With the chain advanced first, a frame that FAILS to
	 * open has still moved it -- so every later genuine message from that
	 * sender is behind the position, is refused as a duplicate, and its
	 * keys are unrecoverable. One forged datagram from anyone who has seen
	 * a real one ends that sender's delivery permanently, silently, with
	 * no key material.
	 *
	 * A comment saying "commit only after the frame opens" would hold
	 * until the first caller who did not read it. This returns
	 * FZN_RATCHET_ERR_IN_PLACE instead. */
	CHECK(fzn_ratchet_advance(&HASH, &chain, 6u, mk, &chain, NULL, 0, NULL, NULL)
	              == FZN_RATCHET_ERR_IN_PLACE,
	      "a live chain was advanced in place, so a forged frame can end a sender's "
	      "delivery permanently");
	CHECK(memcmp(&before, &chain, sizeof(chain)) == 0,
	      "the refused in-place advance moved the chain anyway");

	/* And the two-step form works, which is what makes the refusal a
	 * redirection rather than a wall. */
	CHECK(fzn_ratchet_advance(&HASH, &chain, 6u, mk, &moved, NULL, 0, NULL, NULL)
	              == FZN_RATCHET_OK, "the separate-destination form refused");
	CHECK(memcmp(&before, &chain, sizeof(chain)) == 0,
	      "a successful advance moved the source chain, so the caller cannot decline "
	      "to commit");
	CHECK(moved.seq == 7u, "the derived position is %llu, wanted 7",
	      (unsigned long long)moved.seq);

	/* THE COMMIT IS THE CALLER'S AND IS A PLAIN ASSIGNMENT, which is the
	 * whole recipe: derive, verify, then this line. */
	chain = moved;
	CHECK(chain.seq == 7u, "committing did not take");
}

static void test_a_refused_advance_does_not_write_the_destination(void)
{
	uint8_t k[FZN_CHAIN_KEY_LEN];
	fzn_ratchet_chain_t chain;
	fzn_ratchet_chain_t moved;
	fzn_ratchet_chain_t untouched;
	uint8_t mk[FZN_MESSAGE_KEY_LEN];

	seed(k, 0xd0);
	fzn_ratchet_init(&chain, k, 0);
	/* A destination carrying a recognisable position, so a partial write
	 * is visible rather than merely plausible. */
	fzn_ratchet_init(&moved, k, 0xfeedu);
	untouched = moved;

	hash_calls = 0;
	refuse_after = 3u;
	CHECK(fzn_ratchet_advance(&BUDGET, &chain, 5u, mk, &moved, NULL, 0, NULL, NULL)
	              == FZN_RATCHET_ERR_HASH, "a refusing hash did not stop the advance");
	CHECK(memcmp(&untouched, &moved, sizeof(moved)) == 0,
	      "a failed advance wrote a position into the destination, so a caller has "
	      "neither the old chain nor a usable new one");
}

static void test_every_guard_refuses_its_own_argument(void)
{
	fzn_ratchet_chain_t moved;
	uint8_t k[FZN_CHAIN_KEY_LEN];
	uint8_t mk[FZN_MESSAGE_KEY_LEN];
	uint8_t next[FZN_CHAIN_KEY_LEN];
	uint8_t skipped[2][FZN_MESSAGE_KEY_LEN];
	fzn_ratchet_chain_t chain;
	size_t kept = 0, lost = 0;

	seed(k, 0xa0);
	fzn_ratchet_init(&chain, k, 0);

	CHECK(fzn_ratchet_derive(NULL, k, mk, next) == FZN_RATCHET_ERR_MALFORMED, "null ops");
	CHECK(fzn_ratchet_derive(&HASH, NULL, mk, next) == FZN_RATCHET_ERR_MALFORMED, "null key");
	CHECK(fzn_ratchet_derive(&HASH, k, NULL, next) == FZN_RATCHET_ERR_MALFORMED, "null mk");
	CHECK(fzn_ratchet_derive(&HASH, k, mk, NULL) == FZN_RATCHET_ERR_MALFORMED, "null next");

	CHECK(fzn_ratchet_advance(NULL, &chain, 0, mk, &moved, NULL, 0, NULL, NULL)
	              == FZN_RATCHET_ERR_MALFORMED, "null ops");
	CHECK(fzn_ratchet_advance(&HASH, NULL, 0, mk, &moved, NULL, 0, NULL, NULL)
	              == FZN_RATCHET_ERR_MALFORMED, "null from");
	CHECK(fzn_ratchet_advance(&HASH, &chain, 0, mk, NULL, NULL, 0, NULL, NULL)
	              == FZN_RATCHET_ERR_MALFORMED, "null to");
	CHECK(fzn_ratchet_advance(&HASH, &chain, 0, NULL, &moved, NULL, 0, NULL, NULL)
	              == FZN_RATCHET_ERR_MALFORMED, "null message key out");
	/* A capacity with no buffer, and a buffer with no count to report
	 * into: both are the caller asking for skipped keys and giving this
	 * function no way to hand them over. */
	CHECK(fzn_ratchet_advance(&HASH, &chain, 0, mk, &moved, NULL, 4, NULL, NULL)
	              == FZN_RATCHET_ERR_MALFORMED, "a capacity with no buffer");
	CHECK(fzn_ratchet_advance(&HASH, &chain, 0, mk, &moved, skipped[0], 2, NULL, &lost)
	              == FZN_RATCHET_ERR_MALFORMED, "a buffer with no count");
	CHECK(fzn_ratchet_advance(&HASH, &chain, 0, mk, &moved, skipped[0], 2, &kept, NULL)
	              == FZN_RATCHET_ERR_MALFORMED, "a buffer with nowhere to report drops");

	/* Nulls into the helpers must not fault, which is the whole of what
	 * they promise. */
	fzn_ratchet_init(NULL, k, 0);
	fzn_ratchet_wipe(NULL);

	CHECK(strcmp(fzn_ratchet_err_str(FZN_RATCHET_OK), "ok") == 0, "ok does not render");
	CHECK(strcmp(fzn_ratchet_err_str((fzn_ratchet_err_t)77), "unknown") == 0,
	      "a value that is not an enumerator does not render as unknown");
}

static void test_a_wipe_forgets_the_key(void)
{
	uint8_t k[FZN_CHAIN_KEY_LEN];
	fzn_ratchet_chain_t chain;
	size_t i;
	int all_zero = 1;

	seed(k, 0xb0);
	fzn_ratchet_init(&chain, k, 42u);
	fzn_ratchet_wipe(&chain);
	for (i = 0; i < FZN_CHAIN_KEY_LEN; i++)
		if (chain.key[i] != 0u)
			all_zero = 0;
	CHECK(all_zero, "a wiped chain still holds its key");
	CHECK(chain.seq == 0u, "a wiped chain still holds its position");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	check_at(0, __LINE__, "deliberate");
	CHECK(failures == before + 1, "a failing check did not count");
	failures = before;
	checks -= 1;
}

int main(void)
{
	test_init_does_not_depend_on_what_the_memory_held();
	test_a_step_produces_two_different_keys();
	test_a_step_is_a_function_of_the_chain_key();
	test_a_step_is_alias_safe();
	test_a_fast_forward_equals_stepping();
	test_a_zero_length_advance_is_one_step();
	test_behind_is_refused_and_is_not_an_attack();
	test_the_fast_forward_is_bounded();
	test_a_refused_hash_leaves_the_chain_alone();
	test_the_skipped_cap_reports_what_it_dropped();
	test_a_live_chain_cannot_be_advanced_in_place();
	test_a_refused_advance_does_not_write_the_destination();
	test_every_guard_refuses_its_own_argument();
	test_a_wipe_forgets_the_key();
	test_the_suite_can_tell_pass_from_fail();

	printf("ratchet_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
