/* box_test -- a sealed box to a prekey, sec 618: sealed to one key and
 * opened by it alone, every byte bound, and never a frame. Real X25519,
 * BLAKE2b and XChaCha20-Poly1305. */

#include "../box.h"
#include "../aead_monocypher.h"
#include "../agree_monocypher.h"
#include "../hash_monocypher.h"
#include "../random_system.h"

#include <stdio.h>
#include <string.h>

static int failures, checks;

#define CHECK(cond, what)                                                               \
	do {                                                                            \
		checks++;                                                               \
		if (!(cond)) {                                                          \
			failures++;                                                     \
			fprintf(stderr, "  FAIL box_test.c:%d: %s\n", __LINE__, what);  \
		}                                                                       \
	} while (0)

static fzn_agree_ops_t AGREE;
static fzn_hash_ops_t HASH;
static fzn_aead_ops_t AEAD;
static fzn_random_ops_t RNG;

static void key_of(fzn_agree_secret_t *sk, uint8_t fill)
{
	uint8_t seed[FZN_AGREE_SECRET_LEN];

	memset(sk, 0, sizeof(*sk));
	memset(seed, fill, sizeof(seed));
	(void)fzn_agree_secret_install(sk, &AGREE, seed);
}

static void test_a_box_opens_for_its_key_alone(void)
{
	static const char TEXT[] = "a pairing request";
	fzn_agree_secret_t host, other;
	uint8_t box[FZN_BOX_OVERHEAD + 64u], again[FZN_BOX_OVERHEAD + 64u], out[64];
	size_t len = 0, again_len = 0, n = 0, i;

	key_of(&host, 0x21);
	key_of(&other, 0x42);
	CHECK(fzn_box_seal(&AGREE, &HASH, &AEAD, &RNG, fzn_agree_secret_public(&host),
	                   (const uint8_t *)TEXT, sizeof(TEXT), box, sizeof(box), &len)
	                      == FZN_BOX_OK
	              && len == FZN_BOX_OVERHEAD + sizeof(TEXT) && fzn_box_is(box, len),
	      "fixture: a box sealed to the host");
	CHECK(fzn_box_open(&host, &AGREE, &HASH, &AEAD, box, len, out, sizeof(out), &n) == FZN_BOX_OK
	              && n == sizeof(TEXT) && memcmp(out, TEXT, n) == 0,
	      "the host did not open its box to the same text");
	CHECK(fzn_box_open(&other, &AGREE, &HASH, &AEAD, box, len, out, sizeof(out), &n)
	              == FZN_BOX_ERR_OPEN,
	      "another key opened the host's box");
	CHECK(fzn_box_seal(&AGREE, &HASH, &AEAD, &RNG, fzn_agree_secret_public(&host),
	                   (const uint8_t *)TEXT, sizeof(TEXT), again, sizeof(again), &again_len)
	                      == FZN_BOX_OK
	              && again_len == len && memcmp(again + 2, box + 2, FZN_AGREE_PUBLIC_LEN) != 0,
	      "two boxes of one text shared an ephemeral key");
	/* EVERY BYTE BOUND: head, ephemeral key, text and tag. */
	for (i = 1; i < len; i++) {
		box[i] ^= 0x01u;
		if (fzn_box_open(&host, &AGREE, &HASH, &AEAD, box, len, out, sizeof(out), &n)
		    == FZN_BOX_OK) {
			CHECK(0, "a box with a byte changed opened");
			box[i] ^= 0x01u;
			break;
		}
		box[i] ^= 0x01u;
	}
	CHECK(i == len, "every byte past the mark is bound");
	box[0] = 1u;
	CHECK(!fzn_box_is(box, len)
	              && fzn_box_open(&host, &AGREE, &HASH, &AEAD, box, len, out, sizeof(out), &n)
	                         == FZN_BOX_ERR_SHAPE,
	      "a datagram opening as a frame does, version 1, read as a box");
	box[0] = FZN_BOX_MARK;
	box[1] = FZN_BOX_VERSION + 1u;
	CHECK(!fzn_box_is(box, len), "a box of another version is one");
	box[1] = FZN_BOX_VERSION;
	CHECK(fzn_box_open(&host, &AGREE, &HASH, &AEAD, box, len - 1u, out, sizeof(out), &n)
	              == FZN_BOX_ERR_OPEN,
	      "a box a byte short opened");
	CHECK(!fzn_box_is(box, FZN_BOX_OVERHEAD - 1u), "a box shorter than its overhead is one");
	CHECK(fzn_box_seal(&AGREE, &HASH, &AEAD, &RNG, fzn_agree_secret_public(&host), NULL, 0u,
	                   box, sizeof(box), &len)
	                      == FZN_BOX_OK
	              && fzn_box_open(&host, &AGREE, &HASH, &AEAD, box, len, out, sizeof(out), &n)
	                         == FZN_BOX_OK
	              && n == 0u,
	      "an empty box did not round trip");
	CHECK(fzn_box_seal(&AGREE, &HASH, &AEAD, &RNG, fzn_agree_secret_public(&host),
	                   (const uint8_t *)TEXT, sizeof(TEXT), box, FZN_BOX_OVERHEAD, &len)
	              == FZN_BOX_ERR_MALFORMED,
	      "a box was sealed into too little room");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	CHECK(0, "deliberate");
	CHECK(failures == before + 1, "a failure counts");
	failures = before;
	checks -= 1;
}

int main(void)
{
	fzn_agree_monocypher_init(&AGREE);
	fzn_hash_monocypher_init(&HASH);
	fzn_aead_monocypher_init(&AEAD);
	fzn_random_system_init(&RNG);
	test_the_suite_can_tell_pass_from_fail();
	test_a_box_opens_for_its_key_alone();
	if (failures) {
		fprintf(stderr, "box_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("box_test: all %d checks passed\n", checks);
	return 0;
}
