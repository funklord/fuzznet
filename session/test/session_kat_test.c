/* THE SESSION ROOT DERIVATION, RECOMPUTED FROM THE SPECIFICATION.
 *
 * WHAT WAS MISSING, MEASURED RATHER THAN ASSUMED. `wire/test/golden_frame_test.c`
 * freezes one whole sealed frame, and it is the model for this file -- but look
 * at what it takes as INPUT: `KEY` and `COMMITMENT_KEY` are literals. It pins
 * what this library puts on the wire GIVEN a key, and nothing pinned how that
 * key is derived. The gap was demonstrated before this file was written, by
 * changing FZN_SESSION_LABEL from "fuzznet-sess-v1" to "...-v2" and running the
 * suite: 64 binaries, all green. A wire-visible, interop-breaking change to the
 * most security-critical derivation in the library failed nothing.
 *
 * It is the same failure golden_frame_test's own comment names one layer down
 * -- "nothing would have noticed a change to it as long as both halves of our
 * own round trip moved together" -- and every session test here derives BOTH
 * sides with the same code, so every one of them moves together by
 * construction. `session_test.c` proves the initiator and the responder agree
 * WITH EACH OTHER. That is a different claim from agreeing with the protocol,
 * and only the second one is what a peer on the far side of a network needs.
 *
 * HOW THIS FILE GETS AUTHORITY, WHICH IS THE WHOLE QUESTION. golden_frame_test
 * has independent provenance: its bytes came from the fuzzypickles consumer,
 * against a stated commit, and it warns in terms against ever regenerating them
 * from a run, because a vector recomputed from the code beside it freezes
 * whatever that code currently does INCLUDING WHATEVER IT DOES WRONG.
 *
 * That warning applies here and no second implementation was available, so the
 * authority is a different one: `expected_root` below is written from the
 * DOCUMENTATION -- session.h's transcript layout, commitment.h's root
 * construction -- and computes the answer with Monocypher directly. It never
 * calls fzn_session or fzn_commitment. So the two things being compared are the
 * library and the specification, and agreement says the code implements what
 * the headers promise a peer.
 *
 * THAT IS NOT THE SAME CLAIM AS THE GOLDEN FRAME'S and the difference is worth
 * being exact about: this cannot catch a specification that is itself wrong,
 * because one hand wrote the reading of it. What it does catch is the code
 * drifting from the documented protocol, in either direction, which is the
 * failure that leaves two implementations unable to talk.
 *
 * IT ALREADY PAID FOR ITSELF BEFORE IT COMPILED. Writing the transcript out
 * from session.h found that session.h:96 stated the field order WRONG -- it
 * read `identity | identity | prekey | prekey`, which is the regrouping
 * session.c, session_test.c and project.md all describe as the REJECTED
 * alternative, while the code interleaves each identity with its own prekey. A
 * consumer implementing interop from that comment derives a different root and
 * cannot talk, which is precisely the outcome session.h's own preamble warns
 * about. Nothing executable had ever read that line.
 *
 * GATED ON MONOCYPHER because the recomputation needs the real X25519 and the
 * real BLAKE2b. A stub of either derives different bytes and there is nothing
 * to compare.
 */

#include "../session.h"

#include "../agree.h"
#include "../agree_monocypher.h"
#include "../commitment.h"
#include "../hash_monocypher.h"

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
 * THE INPUTS. Arbitrary fixed bytes -- their only requirement is that they are
 * a valid X25519 scalar (any 32 bytes are, after clamping) and that the two
 * identities are distinct, since equal identities are FZN_SESSION_ERR_SELF.
 */
static const uint8_t SECRET_A[FZN_AGREE_SECRET_LEN] = {
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
	0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
	0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
};

static const uint8_t SECRET_B[FZN_AGREE_SECRET_LEN] = {
	0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
	0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
	0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99,
	0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
};

/*
 * The identities are laid out so the CANONICAL SORT is exercised in both
 * directions rather than only the one the first-written test happened to take:
 * ID_LOW sorts below ID_HIGH under memcmp, and the two establishes below pass
 * them as (self, peer) and (peer, self) respectively. A transcript that ignored
 * the sort would still agree with itself and disagree with this file.
 */
static const uint8_t ID_LOW[FZN_SESSION_IDENTITY_LEN] = {
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
};

static const uint8_t ID_HIGH[FZN_SESSION_IDENTITY_LEN] = {
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
};

/*
 * THE SPECIFICATION, WRITTEN OUT. Nothing below calls into session/ or
 * commitment/ -- that is the point of the file, and a call here would make the
 * comparison circular.
 *
 * From session.h:
 *   transcript = label(16) | version(1)
 *              | lower identity | ITS prekey | higher identity | ITS prekey
 *              | shared(32)
 * ordered canonically by identity so that neither host needs to know which of
 * them is the initiator. From commitment.h:
 *   derived(64) = BLAKE2b( root label(16) | transcript )
 *   key         = derived[0..32]
 *   commitment  = derived[32..64]
 * one call rather than two, which is what makes a second key matching a given
 * commitment a second-preimage problem rather than merely an unrelated search.
 *
 * The labels are repeated as literals rather than included from the sources
 * that define them. THAT IS DELIBERATE AND IS MOST OF THE VALUE: they are
 * static to their translation units and, more to the point, a constant shared
 * between the code and its own test cannot detect a change to itself. These
 * sixteen bytes are protocol, the same as a field offset, and a peer cannot see
 * our header file.
 */
static void expected_root(const uint8_t self_secret[32], const uint8_t self_id[32],
                          const uint8_t peer_secret[32], const uint8_t peer_id[32],
                          uint8_t key_out[FZN_AEAD_KEY_LEN],
                          uint8_t ckey_out[FZN_COMMITMENT_KEY_LEN])
{
	static const char SESSION_LABEL[16] = "fuzznet-sess-v1\0";
	static const char ROOT_LABEL[16] = "fuzznet-kdf-v2\0\0";

	uint8_t self_pk[32];
	uint8_t peer_pk[32];
	uint8_t shared[FZN_AGREE_SHARED_LEN];
	uint8_t transcript[FZN_SESSION_TRANSCRIPT_LEN];
	uint8_t input[16 + FZN_SESSION_TRANSCRIPT_LEN];
	uint8_t derived[FZN_DERIVED_LEN];
	const uint8_t *first_id;
	const uint8_t *first_pk;
	const uint8_t *second_id;
	const uint8_t *second_pk;
	size_t at = 0;

	crypto_x25519_public_key(self_pk, self_secret);
	crypto_x25519_public_key(peer_pk, peer_secret);
	crypto_x25519(shared, self_secret, peer_pk);

	if (memcmp(self_id, peer_id, FZN_SESSION_IDENTITY_LEN) < 0) {
		first_id = self_id;
		first_pk = self_pk;
		second_id = peer_id;
		second_pk = peer_pk;
	} else {
		first_id = peer_id;
		first_pk = peer_pk;
		second_id = self_id;
		second_pk = self_pk;
	}

	memcpy(transcript + at, SESSION_LABEL, 16);
	at += 16;
	transcript[at++] = 1u;
	memcpy(transcript + at, first_id, 32);
	at += 32;
	memcpy(transcript + at, first_pk, 32);
	at += 32;
	memcpy(transcript + at, second_id, 32);
	at += 32;
	memcpy(transcript + at, second_pk, 32);
	at += 32;
	memcpy(transcript + at, shared, 32);
	at += 32;

	/* The length the header pins with a _Static_assert. Recomputing it here
	 * from the fields actually written is what makes that assertion mean
	 * something to a reader who is not compiling this library. */
	check(at == FZN_SESSION_TRANSCRIPT_LEN && at == 177u,
	      "the transcript this file builds is the 177 bytes session.h declares");

	memcpy(input, ROOT_LABEL, 16);
	memcpy(input + 16, transcript, FZN_SESSION_TRANSCRIPT_LEN);
	crypto_blake2b(derived, sizeof(derived), input, sizeof(input));

	memcpy(key_out, derived, FZN_AEAD_KEY_LEN);
	memcpy(ckey_out, derived + FZN_AEAD_KEY_LEN, FZN_COMMITMENT_KEY_LEN);

	crypto_wipe(shared, sizeof(shared));
	crypto_wipe(transcript, sizeof(transcript));
	crypto_wipe(input, sizeof(input));
	crypto_wipe(derived, sizeof(derived));
}

int main(void)
{
	fzn_agree_ops_t agree;
	fzn_hash_ops_t hash;
	fzn_agree_secret_t sk_a;
	fzn_agree_secret_t sk_b;
	uint8_t pub_a[32];
	uint8_t pub_b[32];
	uint8_t want_key[FZN_AEAD_KEY_LEN];
	uint8_t want_ckey[FZN_COMMITMENT_KEY_LEN];
	uint8_t got_key[FZN_AEAD_KEY_LEN];
	uint8_t got_ckey[FZN_COMMITMENT_KEY_LEN];
	uint8_t b_key[FZN_AEAD_KEY_LEN];
	uint8_t b_ckey[FZN_COMMITMENT_KEY_LEN];

	fzn_agree_monocypher_init(&agree);
	fzn_hash_monocypher_init(&hash);

	check(fzn_agree_secret_install(&sk_a, &agree, SECRET_A) == FZN_AGREE_OK,
	      "A's prekey secret installs");
	check(fzn_agree_secret_install(&sk_b, &agree, SECRET_B) == FZN_AGREE_OK,
	      "B's prekey secret installs");

	crypto_x25519_public_key(pub_a, SECRET_A);
	crypto_x25519_public_key(pub_b, SECRET_B);

	/* The library's own view of a public key must be the one X25519 gives,
	 * or every comparison below is against the wrong peer. Checked rather
	 * than assumed, because `fzn_agree_secret_public` is what establish()
	 * uses instead of taking the public as an argument. */
	check(memcmp(fzn_agree_secret_public(&sk_a), pub_a, 32) == 0,
	      "the secret's own public is X25519's public");

	/* A's view: self is the LOWER identity, so self sorts first. */
	expected_root(SECRET_A, ID_LOW, SECRET_B, ID_HIGH, want_key, want_ckey);
	check(fzn_session_establish(&sk_a, &agree, &hash, ID_LOW, ID_HIGH, pub_b, got_key,
	                            got_ckey) == FZN_SESSION_OK,
	      "A establishes");
	check(memcmp(got_key, want_key, sizeof(want_key)) == 0,
	      "A's AEAD key is the one the documented derivation produces");
	check(memcmp(got_ckey, want_ckey, sizeof(want_ckey)) == 0,
	      "A's commitment key is the one the documented derivation produces");

	/* B's view: self is the HIGHER identity, so self sorts SECOND and the
	 * canonical order has to move it. Same expected bytes, reached through
	 * the other arm of the sort. */
	check(fzn_session_establish(&sk_b, &agree, &hash, ID_HIGH, ID_LOW, pub_a, b_key,
	                           b_ckey) == FZN_SESSION_OK,
	      "B establishes");
	check(memcmp(b_key, want_key, sizeof(want_key)) == 0,
	      "B derives the same AEAD key from the mirrored arguments");
	check(memcmp(b_ckey, want_ckey, sizeof(want_ckey)) == 0,
	      "B derives the same commitment key from the mirrored arguments");

	/* THE CONTROL, and without it every check above is satisfied by a
	 * derivation that returned zeroes. `expected_root` and the library
	 * would agree perfectly on nothing at all. */
	{
		uint8_t zero[FZN_AEAD_KEY_LEN] = { 0 };
		check(memcmp(want_key, zero, sizeof(zero)) != 0,
		      "the derived key is not all zero");
		check(memcmp(want_key, want_ckey, sizeof(zero)) != 0,
		      "the two halves of the root are not the same 32 bytes");
	}

	if (failures == 0)
		printf("session_kat_test: %d checks OK\n", checks);
	else
		fprintf(stderr, "session_kat_test: %d of %d FAILED\n", failures, checks);
	return failures ? 1 : 0;
}
