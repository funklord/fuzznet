/* THE OUTERMOST DECODER, OVER BYTES THAT WERE NEVER A FRAME.
 *
 * WHY THIS EXISTS, AND THE GAP IS OLDER THAN THE FILE IT CLOSES. sec 20's
 * criterion is that every decoder of stranger bytes carries a fuzz harness.
 * `wire/seal.c` is the first thing a datagram meets -- every byte from the
 * network reaches `fzn_seal_open` before anything else in this library sees
 * it -- and it had no harness. Measured before writing this: no `*_fuzz.c`
 * anywhere mentions `fzn_seal_open`, `fzn_seal_peek` or
 * `fzn_seal_peek_sender`, and `frame/test/receive_fuzz.c` says in its own
 * header that steps 4 and 5 "live in `wire/seal.c`" and are skipped there.
 *
 * WHAT WAS ALREADY COVERED, SO THAT THIS FILE IS NOT SOLD AS MORE THAN IT IS.
 * `wire/test/seal_test.c` drives hand-written cases, `golden_frame_test.c`
 * pins a fixed vector, and `tamper_test.c` flips every tag-covered byte of a
 * frame ONE AT A TIME and requires each to be refused. Those are strong and
 * they share a population: **a frame that is already valid.** The bytes
 * nobody had ever handed this decoder are the ones that were never a frame --
 * truncated, suffixed, a version or object byte from another protocol, a
 * chunk count of zero, a length that disagrees with the buffer.
 *
 * AND `fzn_seal_peek` IS THE MOST EXPOSED FUNCTION HERE, which is why it gets
 * the sharpest properties. It runs BEFORE a key is chosen -- that is what it
 * exists for -- so it is reachable by anyone who can put a packet on the
 * wire, with no authentication ahead of it whatsoever. It shipped with unit
 * coverage only.
 *
 * SIX PROPERTIES:
 *
 *   1. NOTHING ESCAPES THE BUFFER. On acceptance every pointer the decoder
 *      publishes lies inside the frame it was given, and the payload length
 *      it implies fits. Under a sanitizer this is also what catches a read
 *      past the end; without one, the arithmetic is still checked here.
 *
 *   2. PEEK AND PEEK_SENDER AGREE, ALWAYS. The narrow call is documented as
 *      the narrow case of the wide one, so two verdicts that ever differ
 *      means one of them has drifted -- and a receiver choosing a key by the
 *      cheap call would then be selecting on a frame the real parser
 *      rejects.
 *
 *   3. A REFUSAL CLEARS THE OUTPUT. Both calls zero their result before
 *      validating, so a caller that ignores the return code reads zeroes and
 *      a null rather than its own stack. Documented in `seal.h` on 2026-09-02
 *      after `tool/consumer_check.c` asserted the wrong half of it.
 *
 *   4. PEEK DOES NOT WRITE TO THE FRAME. `fzn_seal_peek` casts away const
 *      internally -- `seal.c` says "THE CAST IS READ-ONLY AND THE FUNCTION IS
 *      NOT" -- and that is a comment until something checks it. The buffer is
 *      compared byte for byte across every call.
 *
 *   5. PEEK REFUSES WHAT OPEN REFUSES. Where peek answers SHAPE, `fzn_seal_open`
 *      must not get further than shape either. A peek that accepted frames the
 *      opener rejects would hand a receiver pointers into something that is not
 *      a frame.
 *
 *   6. THE LENGTH IS THE FRAME'S, NOT AN UPPER BOUND ON IT. `seal.c` records
 *      that a valid 168-byte frame handed in at every size up to 168 + 4096
 *      once opened happily. So a valid frame is presented here at every length
 *      from zero to eight past its own, and **exactly one** of those may be
 *      accepted. That is the regression this property exists for, and a
 *      counter proves the sweep ran rather than the assertion merely not
 *      firing.
 *
 * VALID FRAMES ARE BUILT WITH STUBS, not real crypto, for the reason
 * `seal_test.c` uses them: the shape checks under test do not care whether
 * the tag means anything, and stubs keep this harness in every build
 * arrangement rather than only where Monocypher is present.
 */

#include "../seal.h"
#include "../../chain/chain.h"
#include "../../session/random.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u
#define FUZZ_MIN_CASES 1000u

static int failures;

struct coverage {
	unsigned long refused;      /* a buffer the decoder rejected */
	unsigned long accepted;     /* a buffer it accepted */
	unsigned long near_miss;    /* a mutated valid frame */
	unsigned long length_sweeps;/* property 6 actually run */
	unsigned long open_agreed;  /* property 5 actually compared */
};

static uint32_t next(uint32_t *state)
{
	uint32_t x = *state;

	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	*state = x;
	return x;
}

/* --- stubs, so a structurally valid frame can be built anywhere --- */

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in,
                     size_t in_len)
{
	uint32_t acc = 0x9e3779b9u;
	size_t i;

	(void)ctx;
	for (i = 0; i < in_len; i++)
		acc = (acc ^ in[i]) * 16777619u + (uint32_t)i;
	for (i = 0; i < out_len; i++) {
		acc = acc * 1103515245u + 12345u;
		out[i] = (uint8_t)(acc >> 24);
	}
	return 1;
}

static void stub_tag(const uint8_t *key, const uint8_t *nonce, const uint8_t *aad,
                     size_t aad_len, const uint8_t *text, size_t text_len,
                     uint8_t *tag)
{
	uint32_t acc = 0x01000193u;
	size_t i;

	for (i = 0; i < FZN_AEAD_KEY_LEN; i++)
		acc = (acc ^ key[i]) * 16777619u;
	for (i = 0; i < FZN_AEAD_NONCE_LEN; i++)
		acc = (acc ^ nonce[i]) * 16777619u;
	for (i = 0; i < aad_len; i++)
		acc = (acc ^ aad[i]) * 16777619u;
	for (i = 0; i < text_len; i++)
		acc = (acc ^ text[i]) * 16777619u;
	for (i = 0; i < FZN_AEAD_TAG_LEN; i++) {
		acc = acc * 1103515245u + 12345u;
		tag[i] = (uint8_t)(acc >> 24);
	}
}

static int stub_seal(void *ctx, const uint8_t *key, const uint8_t *nonce,
                     const uint8_t *aad, size_t aad_len, uint8_t *text,
                     size_t text_len, uint8_t *tag)
{
	size_t i;

	(void)ctx;
	for (i = 0; i < text_len; i++)
		text[i] = (uint8_t)(text[i] ^ key[i % FZN_AEAD_KEY_LEN]);
	stub_tag(key, nonce, aad, aad_len, text, text_len, tag);
	return 1;
}

static int stub_aead_open(void *ctx, const uint8_t *key, const uint8_t *nonce,
                          const uint8_t *aad, size_t aad_len, uint8_t *text,
                          size_t text_len, const uint8_t *tag)
{
	uint8_t want[FZN_AEAD_TAG_LEN];
	size_t i;

	(void)ctx;
	stub_tag(key, nonce, aad, aad_len, text, text_len, want);
	if (memcmp(want, tag, FZN_AEAD_TAG_LEN) != 0)
		return 0;
	for (i = 0; i < text_len; i++)
		text[i] = (uint8_t)(text[i] ^ key[i % FZN_AEAD_KEY_LEN]);
	return 1;
}

static uint32_t rng_state = 0x12345678u;

static int stub_fill(void *ctx, uint8_t *out, size_t len)
{
	size_t i;

	(void)ctx;
	for (i = 0; i < len; i++)
		out[i] = (uint8_t)next(&rng_state);
	return 1;
}

static fzn_hash_ops_t hash_ops = { stub_hash, NULL };
static fzn_aead_ops_t aead_ops = { stub_seal, stub_aead_open, NULL };
static fzn_random_ops_t rng_ops = { stub_fill, NULL };

static uint8_t seal_key[FZN_AEAD_KEY_LEN];
static uint8_t commit_key[FZN_COMMITMENT_KEY_LEN];

static void say(const char *what)
{
	failures++;
	printf("seal_fuzz: %s\n", what);
}

/* Properties 1 to 5, over whatever bytes the caller supplies. */
static int decode_once(const uint8_t *frame, size_t len, struct coverage *cov)
{
	uint8_t before[512];
	fzn_peek_t peek, zeroed;
	const uint8_t *claimed = (const uint8_t *)&peek;
	fzn_seal_err_t pe, se;

	if (len > sizeof(before))
		return 0;
	memcpy(before, frame, len);
	memset(&peek, 0xA5, sizeof(peek));
	memset(&zeroed, 0, sizeof(zeroed));

	pe = fzn_seal_peek(frame, len, &peek);

	/* 4. It must not have written to the frame. */
	if (memcmp(before, frame, len) != 0) {
		say("peek modified the frame it was given");
		return 1;
	}

	if (pe != FZN_SEAL_OK) {
		cov->refused++;
		/* 3. A refusal clears the output. */
		if (memcmp(&peek, &zeroed, sizeof(peek)) != 0) {
			say("a refused peek left something in the output");
			return 1;
		}
	} else {
		cov->accepted++;
		/* 1. Every pointer lands inside the frame, and the payload the
		 * length implies fits within it. */
		if (peek.sender < frame || peek.sender + 32u > frame + len ||
		    peek.nonce < frame ||
		    peek.nonce + FZN_AEAD_NONCE_LEN > frame + len ||
		    peek.commitment < frame ||
		    peek.commitment + FZN_COMMITMENT_LEN > frame + len) {
			say("an accepted frame published a pointer outside itself");
			return 1;
		}
		if (len < FZN_SEAL_OVERHEAD) {
			say("a frame shorter than the overhead was accepted");
			return 1;
		}
		/* The schema constrains this and a consumer relies on it: a
		 * zero chunk count would make a reassembler divide by it. */
		if (peek.chunks == 0u) {
			say("a frame claiming zero chunks was accepted");
			return 1;
		}
	}

	/* 2. The narrow call agrees, in verdict and in pointer. */
	se = fzn_seal_peek_sender(frame, len, &claimed);
	if ((se == FZN_SEAL_OK) != (pe == FZN_SEAL_OK)) {
		say("peek and peek_sender disagreed about the same frame");
		return 1;
	}
	if (se == FZN_SEAL_OK) {
		if (claimed != peek.sender) {
			say("peek and peek_sender named different senders");
			return 1;
		}
	} else if (claimed != NULL) {
		say("a refused peek_sender left the caller's pointer");
		return 1;
	}

	/* 5. Where peek refuses on shape, opening must not get past shape. A
	 * mutable copy, because `fzn_seal_open` decrypts in place. */
	if (pe == FZN_SEAL_ERR_SHAPE) {
		uint8_t copy[512];
		fzn_opened_t opened;

		memcpy(copy, frame, len);
		se = fzn_seal_open(copy, len, seal_key, commit_key, &hash_ops,
		                   &aead_ops, &opened);
		cov->open_agreed++;
		if (se == FZN_SEAL_OK) {
			say("peek refused a frame that opened");
			return 1;
		}
	}
	return 0;
}

/* Property 6: a valid frame is exactly its own length and nothing else. */
static int length_discipline(struct coverage *cov)
{
	uint8_t built[FZN_SEAL_OVERHEAD + 16];
	uint8_t work[sizeof(built) + 8];
	fzn_send_t what;
	fzn_peek_t peek;
	uint8_t sender[32], cap[FZN_CAP_ID_LEN];
	static const uint8_t payload[16] = "sixteen bytes!!";
	size_t built_len = 0, n, accepted = 0;

	memset(sender, 0x5A, sizeof(sender));
	memset(cap, 0x6B, sizeof(cap));
	memset(&what, 0, sizeof(what));
	what.sender = sender;
	what.capability = cap;
	what.payload = payload;
	what.payload_len = sizeof(payload);
	what.msg = 7u;
	what.index = 0u;
	what.chunks = 1u;
	what.kind = FZN_KIND_UNIT;

	if (fzn_seal_build(built, sizeof(built), &built_len, &what, seal_key,
	                   commit_key, &hash_ops, &rng_ops, &aead_ops) != FZN_SEAL_OK) {
		say("the harness could not build a valid frame");
		return 1;
	}

	memset(work, 0, sizeof(work));
	memcpy(work, built, built_len);
	for (n = 0; n <= built_len + 8u; n++) {
		if (fzn_seal_peek(work, n, &peek) == FZN_SEAL_OK)
			accepted++;
	}
	cov->length_sweeps++;
	if (accepted != 1u) {
		printf("seal_fuzz: %zu lengths accepted, exactly 1 is correct\n",
		       accepted);
		failures++;
		return 1;
	}
	/* And the one accepted is the true length rather than some other. */
	if (fzn_seal_peek(work, built_len, &peek) != FZN_SEAL_OK) {
		say("the frame's own length was not the accepted one");
		return 1;
	}
	return 0;
}

static unsigned long floor_of(unsigned long cases, unsigned long per)
{
	unsigned long f = cases / per;

	return f == 0u ? 1u : f;
}

int main(int argc, char **argv)
{
	unsigned long cases = FUZZ_DEFAULT_CASES;
	struct coverage cov;
	uint8_t buf[512];
	uint8_t valid[FZN_SEAL_OVERHEAD + 16];
	fzn_send_t what;
	uint8_t sender[32], cap[FZN_CAP_ID_LEN];
	static const uint8_t payload[16] = "sixteen bytes!!";
	size_t valid_len = 0;

	memset(&cov, 0, sizeof(cov));
	memset(seal_key, 0x31, sizeof(seal_key));
	memset(commit_key, 0x32, sizeof(commit_key));

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}
	if (cases < FUZZ_MIN_CASES) {
		printf("seal_fuzz: %lu cases is below FUZZ_MIN_CASES (%u); the "
		       "coverage floors below are cleared by single lucky hits, "
		       "so this run will not report success.\n",
		       cases, (unsigned)FUZZ_MIN_CASES);
		return 1;
	}

	/* One valid frame, kept for the near-miss half: random bytes almost
	 * never form a frame, so a harness driven only by them exercises the
	 * refusal path and nothing else. Corrupting a real frame is where a
	 * parser's accept path is actually tested. */
	memset(sender, 0x5A, sizeof(sender));
	memset(cap, 0x6B, sizeof(cap));
	memset(&what, 0, sizeof(what));
	what.sender = sender;
	what.capability = cap;
	what.payload = payload;
	what.payload_len = sizeof(payload);
	what.msg = 7u;
	what.chunks = 1u;
	what.kind = FZN_KIND_UNIT;
	if (fzn_seal_build(valid, sizeof(valid), &valid_len, &what, seal_key,
	                   commit_key, &hash_ops, &rng_ops, &aead_ops) != FZN_SEAL_OK) {
		printf("seal_fuzz: could not build the reference frame\n");
		return 1;
	}

	if (length_discipline(&cov))
		return 1;

	for (unsigned long c = 0; c < cases; c++) {
		uint32_t state = (uint32_t)c + 1u;
		size_t len, i;

		if ((c & 1u) == 0u) {
			/* Arbitrary bytes: was never a frame. */
			len = (size_t)(next(&state) % 200u);
			for (i = 0; i < len; i++)
				buf[i] = (uint8_t)next(&state);
		} else {
			/* A near miss: a real frame with a few bytes rewritten
			 * and sometimes a different length claimed. */
			unsigned k = next(&state) % 4u + 1u;

			len = valid_len;
			memcpy(buf, valid, len);
			for (i = 0; i < k; i++)
				buf[next(&state) % len] = (uint8_t)next(&state);
			if ((next(&state) % 4u) == 0u)
				len = (size_t)(next(&state) % (valid_len + 8u));
			cov.near_miss++;
		}

		if (decode_once(buf, len, &cov)) {
			printf("seal_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	printf("seal_fuzz: %lu cases; %lu refused, %lu accepted, %lu near misses, "
	       "%lu length sweeps, %lu peek/open comparisons\n",
	       cases, cov.refused, cov.accepted, cov.near_miss,
	       cov.length_sweeps, cov.open_agreed);

	/* FLOORS PROPORTIONAL TO `cases`, WHICH IS WHAT THE REFUSAL ABOVE
	 * ALREADY PROMISED. They were `== 0u` until 2026-09-04 -- at least one
	 * hit, at any case count -- while `FUZZ_MIN_CASES` refused a short run
	 * on the grounds that "the coverage floors below are cleared by single
	 * lucky hits". The guard was protecting floors this file did not have,
	 * and every other harness here (`prekey_fuzz`, `blob_fuzz`,
	 * `provision_fuzz`, `sync_fuzz`) scales them.
	 *
	 * What that cost was nothing yet and everything later: with a floor of
	 * one, a generator change that dropped `accepted` from 65203 to 3
	 * would leave this passing, and `accepted` is the path where a frame
	 * is actually parsed rather than refused.
	 *
	 * An eighth is chosen against the measured shares -- refused 67%,
	 * accepted 33%, near misses 50%, peek/open agreements 67% over 200000
	 * cases -- so the tightest of them has better than a two-fold margin.
	 * A floor is a tripwire for a generator that has stopped reaching a
	 * state, not a target to tune against.
	 *
	 * `length_sweeps` KEEPS ITS FLOOR OF ONE, and that is not an oversight:
	 * `length_discipline` is called once from `main` before the case loop,
	 * so one is the whole population. A proportional floor there would
	 * refuse every run. */
	if (cov.refused < floor_of(cases, 8u) || cov.accepted < floor_of(cases, 8u) ||
	    cov.near_miss < floor_of(cases, 8u) || cov.open_agreed < floor_of(cases, 8u) ||
	    cov.length_sweeps == 0u) {
		printf("seal_fuzz: REACHED TOO LITTLE -- %lu refused, %lu accepted, "
		       "%lu near misses, %lu peek/open comparisons, %lu length sweeps "
		       "in %lu cases. This run proves less than it appears to.\n",
		       cov.refused, cov.accepted, cov.near_miss, cov.open_agreed,
		       cov.length_sweeps, cases);
		return 1;
	}
	return failures == 0 ? 0 : 1;
}
