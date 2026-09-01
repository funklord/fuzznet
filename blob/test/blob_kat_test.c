/* THE PER-LEAF KEY SCHEDULE, RECOMPUTED FROM THE SPECIFICATION.
 *
 * WHY THIS FILE EXISTS. `fuzznet-blob-v1` survived a mutation to
 * `fuzznet-blob-v9` with the whole suite green. Every blob test seals a leaf
 * and opens it with the same code, so the label cancels out of both sides.
 * project.md sec 45 has the sweep. Its sibling `fuzznet-root-v1` was already
 * held, which is worth noting: the two labels sit four lines apart in blob.c
 * and only one of them was pinned by anything, which is not a distinction
 * anybody made on purpose.
 *
 * IT PINS THE INDEX ENCODING TOO, and that is half the value. The leaf index
 * enters the hash as a BIG-ENDIAN 64-bit integer through `fzn_put_be64`.
 * Nothing else in the suite could tell that from little-endian: both peers are
 * this library, both encode the same way, and every leaf round-trips. A
 * consumer reading blob.h and reaching for the host's byte order would derive
 * a different key for every leaf but the first -- and index 0 is the one a
 * first test tends to use, which is exactly how that survives review. Indices
 * 0, 1 and a large one are all checked below.
 *
 * THE AUTHORITY IS THE SPECIFICATION, with the same limit `session_kat_test`
 * states: this compares the library against the documented construction, not
 * against an independently produced vector, so it cannot catch a wrong
 * specification. The labels are repeated as literals rather than included,
 * because a constant shared between code and its own test cannot detect a
 * change to itself.
 *
 * THE SEALED LEAF IS PINNED TOO, AND IT WAS A SECOND GAP. The first version
 * of this file pinned the key schedule and stopped, which read as though blob
 * were done. It was not: `nonce_for_index` puts the leaf index big-endian at
 * the END of a 24-byte nonce, and moving it to the front left the whole suite
 * green -- the nonce is built in one place and both sides call it, so the
 * layout cancels out exactly as a domain label does. blob.c's own comment
 * predicts this: "a nonce whose bytes have to be explained is one somebody
 * eventually re-derives differently". Nothing held it to an explanation.
 *
 * Sealing one leaf and comparing the whole artifact pins three things at once
 * -- the nonce construction, the `commitment | ciphertext | tag` layout, and
 * the choice of the commitment as AAD, which blob.c argues is what stops a
 * peer swapping one leaf's commitment for another's.
 *
 * GATED ON MONOCYPHER because it needs the real BLAKE2b, and now the real
 * XChaCha20-Poly1305 as well.
 */

#include "../blob.h"

#include "../../session/aead_monocypher.h"
#include "../../session/hash_monocypher.h"

#include "monocypher.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check(int ok, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		fprintf(stderr, "  FAIL: %s\n", what);
	}
}

/*
 * From blob.h and blob.c's derivation:
 *
 *   derived(48) = BLAKE2b( label(16) | content key(32) | be64(index) )
 *   aead key    = derived[0..32]
 *   commitment  = derived[32..48]      (16 bytes, not 32 -- it is a wire field)
 *
 * The big-endian write is spelled out here rather than borrowed from
 * `fzn_put_be64`, for the reason the header comment gives: the encoding is
 * what is being checked, so taking it from the code under test would check
 * nothing.
 */
static void expected_leaf(const uint8_t content_key[FZN_BLOB_KEY_LEN], uint64_t index,
                          uint8_t key_out[FZN_AEAD_KEY_LEN],
                          uint8_t commitment_out[FZN_COMMITMENT_LEN])
{
	static const char BLOB_KEY_LABEL[16] = "fuzznet-blob-v1\0";
	uint8_t input[16 + FZN_BLOB_KEY_LEN + 8u];
	uint8_t derived[FZN_AEAD_KEY_LEN + FZN_COMMITMENT_LEN];
	unsigned i;

	memcpy(input, BLOB_KEY_LABEL, 16);
	memcpy(input + 16, content_key, FZN_BLOB_KEY_LEN);
	for (i = 0u; i < 8u; i++)
		input[16u + FZN_BLOB_KEY_LEN + i] = (uint8_t)(index >> (8u * (7u - i)));

	crypto_blake2b(derived, sizeof(derived), input, sizeof(input));
	memcpy(key_out, derived, FZN_AEAD_KEY_LEN);
	memcpy(commitment_out, derived + FZN_AEAD_KEY_LEN, FZN_COMMITMENT_LEN);

	crypto_wipe(input, sizeof(input));
	crypto_wipe(derived, sizeof(derived));
}

static const uint8_t CONTENT_KEY[FZN_BLOB_KEY_LEN] = {
	0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
	0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
	0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
	0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
};

int main(void)
{
	/* 0 is the index a first test uses and the only one whose big-endian
	 * and little-endian encodings agree. 1 separates them in the last byte;
	 * the third separates them in every byte, so a partial reversal has
	 * nowhere to hide either. */
	static const uint64_t INDICES[] = { 0u, 1u, 0x0102030405060708u };

	fzn_hash_ops_t hash;
	uint8_t prev_key[FZN_AEAD_KEY_LEN];
	size_t i;

	fzn_hash_monocypher_init(&hash);
	memset(prev_key, 0, sizeof(prev_key));

	for (i = 0; i < sizeof(INDICES) / sizeof(INDICES[0]); i++) {
		uint8_t want_key[FZN_AEAD_KEY_LEN], want_com[FZN_COMMITMENT_LEN];
		uint8_t got_key[FZN_AEAD_KEY_LEN], got_com[FZN_COMMITMENT_LEN];

		expected_leaf(CONTENT_KEY, INDICES[i], want_key, want_com);

		check(fzn_blob_derive_leaf(&hash, CONTENT_KEY, INDICES[i], got_key, got_com)
		              == FZN_BLOB_OK,
		      "the leaf derives");
		check(memcmp(got_key, want_key, sizeof(want_key)) == 0,
		      "the leaf AEAD key is the one the documented derivation produces");
		check(memcmp(got_com, want_com, sizeof(want_com)) == 0,
		      "the leaf commitment is the one the documented derivation produces");

		/* THE CONTROLS. A schedule that ignored the index would satisfy
		 * every comparison above, since both sides would ignore it
		 * together -- so the keys are checked to MOVE between indices,
		 * which is the property the index is in the hash for. */
		check(memcmp(want_key, prev_key, sizeof(want_key)) != 0,
		      "a different leaf index gives a different key");
		memcpy(prev_key, want_key, sizeof(prev_key));
	}

	/* ---- one sealed leaf, whole ---------------------------------------- */
	{
		static const uint8_t PLAIN[] = "fuzznet blob leaf vector";
		const size_t plain_len = sizeof(PLAIN) - 1u;
		const uint64_t index = 0x0102030405060708u;

		fzn_aead_ops_t aead;
		uint8_t sealed[FZN_BLOB_SEALED_MAX];
		uint8_t key[FZN_AEAD_KEY_LEN];
		uint8_t com[FZN_COMMITMENT_LEN];
		uint8_t nonce[FZN_AEAD_NONCE_LEN];
		uint8_t want[FZN_BLOB_SEALED_MAX];
		size_t sealed_len = 0;
		unsigned k;

		fzn_aead_monocypher_init(&aead);

		/* The nonce, written from blob.c's description rather than taken
		 * from it: zero bytes, then the index big-endian at the END, so
		 * the whole 24 bytes read as one big-endian integer. This is the
		 * construction whose mutation survived. */
		memset(nonce, 0, sizeof(nonce));
		for (k = 0u; k < 8u; k++)
			nonce[FZN_AEAD_NONCE_LEN - 8u + k] =
			        (uint8_t)(index >> (8u * (7u - k)));

		expected_leaf(CONTENT_KEY, index, key, com);

		/* The layout: commitment in the clear, then the ciphertext, then
		 * the tag -- and the commitment is the AAD, not part of the
		 * plaintext. */
		memcpy(want, com, FZN_COMMITMENT_LEN);
		crypto_aead_lock(want + FZN_COMMITMENT_LEN,
		                 want + FZN_COMMITMENT_LEN + plain_len, key, nonce, com,
		                 FZN_COMMITMENT_LEN, PLAIN, plain_len);

		check(fzn_blob_leaf_seal(&hash, &aead, CONTENT_KEY, index, PLAIN, plain_len,
		                         sealed, sizeof(sealed), &sealed_len)
		              == FZN_BLOB_OK,
		      "the leaf seals");
		check(sealed_len == plain_len + FZN_BLOB_LEAF_OVERHEAD,
		      "a sealed leaf is the plaintext plus commitment and tag");
		check(memcmp(sealed, want, plain_len + FZN_BLOB_LEAF_OVERHEAD) == 0,
		      "the sealed leaf is the bytes blob.c's construction specifies");

		/* THE CONTROL for the nonce specifically: the same plaintext under
		 * the same content key at a DIFFERENT index must not produce the
		 * same ciphertext. A nonce that ignored the index would satisfy
		 * every byte comparison above, because both sides would ignore it
		 * together -- which is exactly how the mutation survived. */
		{
			uint8_t other[FZN_BLOB_SEALED_MAX];
			size_t other_len = 0;
			check(fzn_blob_leaf_seal(&hash, &aead, CONTENT_KEY, index + 1u, PLAIN,
			                         plain_len, other, sizeof(other), &other_len)
			              == FZN_BLOB_OK,
			      "the neighbouring leaf seals");
			check(memcmp(sealed + FZN_COMMITMENT_LEN, other + FZN_COMMITMENT_LEN,
			             plain_len) != 0,
			      "the same plaintext at a different index seals differently");
		}
	}

	if (failures == 0)
		printf("blob_kat_test: %d checks OK\n", checks);
	else
		fprintf(stderr, "blob_kat_test: %d of %d FAILED\n", failures, checks);
	return failures ? 1 : 0;
}
