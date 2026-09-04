/*
 * SELECTIVE DISCLOSURE: one signed record, different recipients seeing
 * different parts of it, with no second signature and no library change.
 *
 * WHY THIS FILE EXISTS. project.md sec 5j asked how the same statement
 * reaches different recipients at different fidelities, listed three possible
 * shapes, and eliminated two. The second elimination read: *"Layering
 * encrypted detail inside one record means defining a body format, which is
 * an encoding sec 2 keeps out"*, and the first turned on the library having
 * to *"understand body structure"*.
 *
 * Both of those rest on the reading of sec 2 that sec 71 corrects. Sec 2
 * scopes its exclusion to the LOCAL HOP, and its test is *"is this anybody's
 * application"*. A construction that lets one signature cover several fields
 * and reveals a subset is not anybody's application -- it is a generic
 * cryptographic construction, and the holder's rule is that everything
 * generic to a crypto protocol belongs in this library.
 *
 * So the elimination was re-examined, and this file is the re-examination.
 * It is EVIDENCE rather than a proposal: it builds the shape out of what this
 * library already has, and reports what works, what does not, and what the
 * missing piece costs. Whether any of it becomes a module is the holder's,
 * and sec 5j's chosen answer -- fidelity as a separate stream -- may still be
 * the better one. This file does not argue against it. It establishes that
 * the alternative was rejected for a reason that is not true.
 *
 * THE CONSTRUCTION, which uses four calls that already exist:
 *
 *   each field   ->  fzn_blob_leaf_hash        a leaf
 *   the leaves   ->  fzn_blob_tree_push/_root  one 32-byte root
 *   the root     ->  fzn_record_sign           the body, signed once
 *   a subset     ->  fzn_blob_proof_verify     checked against that root
 *
 * The library never sees a field. It sees leaf hashes, a tree and 32 opaque
 * bytes in a body it already declines to interpret -- so "it would have to
 * understand body structure" is answered: it understands the TREE, and the
 * leaves stay as opaque as any other body.
 *
 * TWO PROPERTIES COME FREE AND ARE ASSERTED HERE RATHER THAN ASSUMED.
 * `fzn_blob_proof_verify` binds `leaf_count` into the root, so a recipient
 * cannot be told a record has fewer fields than it has -- which in this
 * setting is a recipient being walked to a truncation of the statement they
 * were sent. And the two recipients verify the SAME BYTES: this file asserts
 * the record is byte-identical for both, because a construction that needed
 * a per-recipient signature would be three shapes back.
 *
 * WHAT DOES NOT COME FREE, AND IT IS THE FINDING: a leaf hash of a small
 * field is a preimage anybody can search. `test_the_salt_is_load_bearing`
 * recovers a withheld one-byte field from the root alone in 256 tries, and
 * then shows the same search failing once the leaf carries 16 bytes of salt.
 * That is one line of convention -- `salt || field` -- and it is exactly the
 * kind of line that four consumers would each have to get right separately,
 * which is what sec 15 says this library exists to prevent.
 *
 * AND ONE THING BLOB CANNOT DO HERE, measured rather than assumed:
 * `fzn_blob_leaf_seal` requires FZN_BLOB_LEAF_SIZE (1024) bytes for every
 * leaf but the last, so blob's own sealing cannot carry small fields. The
 * tree and the proofs transfer; the sealing does not. A disclosure
 * construction that wanted per-field encryption rather than per-field
 * withholding would need its own, and this file does not build one --
 * withholding the bytes is what it demonstrates.
 */

#include "../../blob/blob.h"
#include "../../record/record.h"
#include "../../chain/chain.h"
#include "../../session/hash_monocypher.h"
#include "../../chain/sign_monocypher.h"
#include "../../version/version.h"

#include <monocypher.h>

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check(int ok, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL: %s\n", what);
	}
}

static void seed_bytes(uint8_t out[32], uint8_t v)
{
	memset(out, v, 32);
	out[0] = v;
	out[31] = (uint8_t)(v ^ 0xa5u);
}

/* Four fields, which is enough for a tree with a real climb and few enough
 * that every index can be walked. */
#define FIELDS 4u
#define SALT_LEN 16u
#define FIELD_MAX 48u

/* A field as it is hashed: salt, then the bytes. The salt is the whole of
 * what stops a withheld field being searched for, and its absence is
 * demonstrated below rather than argued. */
typedef struct field {
	uint8_t bytes[SALT_LEN + FIELD_MAX];
	size_t len;
} field_t;

static void field_make(field_t *f, uint8_t salt_seed, const char *text, int salted)
{
	size_t n = strlen(text);

	memset(f, 0, sizeof(*f));
	if (n > FIELD_MAX)
		n = FIELD_MAX;

	if (salted) {
		size_t i;

		for (i = 0; i < SALT_LEN; i++)
			f->bytes[i] = (uint8_t)(salt_seed * 131u + i * 17u + 7u);
		memcpy(f->bytes + SALT_LEN, text, n);
		f->len = SALT_LEN + n;
	} else {
		memcpy(f->bytes, text, n);
		f->len = n;
	}
}

/* Hash every field into a leaf, fold the leaves into a root. Returns 0 on any
 * refusal, so a caller can REQUIRE the fixture rather than proceeding over a
 * root that was never built. */
static int commit(const fzn_hash_ops_t *hash, const field_t *fields, unsigned n,
                  uint8_t leaf_hashes[FIELDS][FZN_BLOB_HASH_LEN],
                  uint8_t root[FZN_BLOB_HASH_LEN])
{
	fzn_blob_tree_t tree;
	unsigned i;

	fzn_blob_tree_init(&tree);
	for (i = 0; i < n; i++) {
		if (fzn_blob_leaf_hash(hash, fields[i].bytes, fields[i].len,
		                       leaf_hashes[i]) != FZN_BLOB_OK)
			return 0;
		if (fzn_blob_tree_push(hash, &tree, leaf_hashes[i]) != FZN_BLOB_OK)
			return 0;
	}

	return fzn_blob_tree_root(hash, &tree, root) == FZN_BLOB_OK;
}

/* What a recipient does with one disclosed field: check it belongs to the
 * root the issuer signed. This is the whole receiving side, and it needs no
 * key -- `fzn_blob_proof_verify` is keyless by design, which is what lets a
 * recipient check a field without being able to mint one. */
static int recipient_accepts(const fzn_hash_ops_t *hash, const field_t *disclosed,
                             uint64_t index, uint64_t leaf_count, const uint8_t *siblings,
                             unsigned sibling_count, const uint8_t root[FZN_BLOB_HASH_LEN])
{
	uint8_t leaf[FZN_BLOB_HASH_LEN];

	if (fzn_blob_leaf_hash(hash, disclosed->bytes, disclosed->len, leaf) != FZN_BLOB_OK)
		return 0;

	return fzn_blob_proof_verify(hash, leaf, index, leaf_count, siblings, sibling_count,
	                             root) == FZN_BLOB_OK;
}

static fzn_hash_ops_t hash_ops;
static fzn_sign_ops_t issuer_sign, verify_ops;
static uint8_t issuer_pub[FZN_PUBKEY_LEN];

static void identities(void)
{
	static fzn_sign_monocypher_t signer, verifier;
	uint8_t seed[32];

	fzn_hash_monocypher_init(&hash_ops);

	memset(&signer, 0, sizeof(signer));
	seed_bytes(seed, 0x71u);
	crypto_eddsa_key_pair(signer.secret_key, issuer_pub, seed);
	signer.can_sign = 1;
	fzn_sign_monocypher_init(&issuer_sign, &signer);

	/* Verify-only, so a recipient checking the record cannot mint one. */
	memset(&verifier, 0, sizeof(verifier));
	verifier.can_sign = 0;
	fzn_sign_monocypher_init(&verify_ops, &verifier);
}

/* The whole shape, end to end: one record, two recipients, different views. */
static void test_one_signature_serves_two_fidelities(void)
{
	field_t fields[FIELDS];
	uint8_t leaf_hashes[FIELDS][FZN_BLOB_HASH_LEN];
	uint8_t root[FZN_BLOB_HASH_LEN];
	uint8_t subject[FZN_SUBJECT_LEN];
	uint8_t record_bytes[FZN_RECORD_MAX_LEN];
	size_t record_len = 0;
	fzn_record_t opened;
	uint8_t proof_a[FZN_BLOB_MAX_DEPTH * FZN_BLOB_HASH_LEN];
	uint8_t proof_b[FZN_BLOB_MAX_DEPTH * FZN_BLOB_HASH_LEN];
	unsigned count_a = 0, count_b = 0;

	field_make(&fields[0], 0x01u, "region: north", 1);
	field_make(&fields[1], 0x02u, "street and number", 1);
	field_make(&fields[2], 0x03u, "bearing 043", 1);
	field_make(&fields[3], 0x04u, "accuracy 3m", 1);
	memset(subject, 0x2c, sizeof(subject));

	if (!commit(&hash_ops, fields, FIELDS, leaf_hashes, root)) {
		check(0, "the commitment did not build, so nothing below is tested");
		return;
	}

	/* THE BODY IS THE ROOT AND NOTHING ELSE. 32 opaque bytes, which
	 * `record/` already carries without interpreting. */
	if (fzn_record_sign(issuer_pub, subject, 1u, 9u, 1u, 1000u, root,
	                    FZN_BLOB_HASH_LEN, &issuer_sign, record_bytes,
	                    sizeof(record_bytes), &record_len) != FZN_RECORD_OK) {
		check(0, "the record did not sign, so nothing below is tested");
		return;
	}

	check(fzn_record_open(record_bytes, record_len, &opened) == FZN_RECORD_OK,
	      "the record did not open");
	check(fzn_record_verify(opened, &verify_ops) == FZN_RECORD_OK,
	      "the record did not verify under the issuer");
	check(fzn_record_body_len(opened) == FZN_BLOB_HASH_LEN,
	      "the body is not one root");
	check(memcmp(fzn_record_body(opened), root, FZN_BLOB_HASH_LEN) == 0,
	      "the root did not survive into the signed body");

	if (fzn_blob_proof_build(&hash_ops, &leaf_hashes[0][0], FIELDS, 0u, proof_a,
	                         sizeof(proof_a), &count_a) != FZN_BLOB_OK) {
		check(0, "the coarse proof did not build");
		return;
	}
	if (fzn_blob_proof_build(&hash_ops, &leaf_hashes[0][0], FIELDS, 1u, proof_b,
	                         sizeof(proof_b), &count_b) != FZN_BLOB_OK) {
		check(0, "the precise proof did not build");
		return;
	}

	/* Recipient A is entitled to field 0 only and is sent only field 0. */
	check(recipient_accepts(&hash_ops, &fields[0], 0u, FIELDS, proof_a, count_a,
	                        fzn_record_body(opened)),
	      "the coarse recipient could not verify the field it was given");

	/* Recipient B is entitled to both, against the SAME record. */
	check(recipient_accepts(&hash_ops, &fields[0], 0u, FIELDS, proof_a, count_a,
	                        fzn_record_body(opened)),
	      "the precise recipient could not verify the coarse field");
	check(recipient_accepts(&hash_ops, &fields[1], 1u, FIELDS, proof_b, count_b,
	                        fzn_record_body(opened)),
	      "the precise recipient could not verify the precise field");

	/* AND IT IS ONE SIGNATURE, not two. Both recipients were handed the
	 * same bytes; if this ever needed a per-recipient record, the whole
	 * construction has collapsed back into sec 5j's third shape. */
	{
		uint8_t again[FZN_RECORD_MAX_LEN];
		size_t again_len = 0;

		check(fzn_record_sign(issuer_pub, subject, 1u, 9u, 1u, 1000u, root,
		                      FZN_BLOB_HASH_LEN, &issuer_sign, again, sizeof(again),
		                      &again_len) == FZN_RECORD_OK,
		      "the record did not re-sign");
		check(again_len == record_len && memcmp(again, record_bytes, record_len) == 0,
		      "the two recipients are not being served the same signed bytes");
	}

	/* A SUBSTITUTED FIELD IS REFUSED. Without this the proofs above could
	 * be accepting anything, and every check in this file would pass over
	 * a construction with no content. */
	{
		field_t forged;

		field_make(&forged, 0x02u, "somebody else's street", 1);
		check(!recipient_accepts(&hash_ops, &forged, 1u, FIELDS, proof_b, count_b,
		                         fzn_record_body(opened)),
		      "a substituted field verified against the issuer's root");
	}

	/* A TRUNCATED VIEW IS REFUSED, and this one is free: `leaf_count` is
	 * bound into the root, so a recipient told the statement has one field
	 * when it has four recomputes a different root. Without that binding a
	 * sender could hide the EXISTENCE of fields rather than their
	 * contents, which is a different and worse thing to be able to do. */
	check(!recipient_accepts(&hash_ops, &fields[0], 0u, 1u, proof_a, count_a,
	                         fzn_record_body(opened)),
	      "a recipient accepted a claim that the record has fewer fields than it has");
}

/*
 * THE FINDING, demonstrated in both directions.
 *
 * A leaf is a hash of a field. If the field is small, anybody holding the
 * root can search for it -- so "withheld" would mean "not sent", not "not
 * knowable", and a construction that reveals what it withholds is worse than
 * useless because it looks like it works.
 *
 * The search below is the honest one a recipient could run: they hold the
 * root and the proof for their own field, so they can compute the sibling
 * that stands where the withheld field is, and they know the leaf hash
 * function. Enumerating a one-byte domain is 256 hashes.
 */
static void test_the_salt_is_load_bearing(void)
{
	field_t fields[FIELDS];
	uint8_t leaf_hashes[FIELDS][FZN_BLOB_HASH_LEN];
	uint8_t root[FZN_BLOB_HASH_LEN];
	unsigned guess;
	int found_unsalted = 0;
	int found_salted = 0;

	/* Field 1 is a single byte out of 256 -- a fidelity flag, a level, a
	 * count. Small domains are the normal case for the field somebody
	 * wants withheld, not a contrived one. */

	/* ---- without a salt ------------------------------------------- */
	field_make(&fields[0], 0x01u, "region: north", 0);
	field_make(&fields[1], 0x02u, "", 0);
	fields[1].bytes[0] = 0xc7u;
	fields[1].len = 1;
	field_make(&fields[2], 0x03u, "bearing 043", 0);
	field_make(&fields[3], 0x04u, "accuracy 3m", 0);

	if (!commit(&hash_ops, fields, FIELDS, leaf_hashes, root)) {
		check(0, "the unsalted commitment did not build");
		return;
	}

	for (guess = 0; guess < 256u; guess++) {
		uint8_t candidate = (uint8_t)guess;
		uint8_t h[FZN_BLOB_HASH_LEN];

		if (fzn_blob_leaf_hash(&hash_ops, &candidate, 1u, h) != FZN_BLOB_OK)
			continue;
		if (memcmp(h, leaf_hashes[1], FZN_BLOB_HASH_LEN) == 0) {
			found_unsalted = 1;
			check(candidate == 0xc7u,
			      "the search matched a leaf but recovered the wrong byte, so it "
			      "is not the search it claims to be");
			break;
		}
	}
	check(found_unsalted == 1,
	      "the unsalted search did NOT recover the withheld field -- so this "
	      "control cannot fail and the salted case below proves nothing");

	/* ---- with one ------------------------------------------------- */
	field_make(&fields[1], 0x02u, "", 1);
	fields[1].bytes[SALT_LEN] = 0xc7u;
	fields[1].len = SALT_LEN + 1u;

	if (!commit(&hash_ops, fields, FIELDS, leaf_hashes, root)) {
		check(0, "the salted commitment did not build");
		return;
	}

	for (guess = 0; guess < 256u; guess++) {
		uint8_t candidate = (uint8_t)guess;
		uint8_t h[FZN_BLOB_HASH_LEN];

		if (fzn_blob_leaf_hash(&hash_ops, &candidate, 1u, h) != FZN_BLOB_OK)
			continue;
		if (memcmp(h, leaf_hashes[1], FZN_BLOB_HASH_LEN) == 0) {
			found_salted = 1;
			break;
		}
	}
	check(found_salted == 0,
	      "the salted field was recovered by the same search, so the salt is not "
	      "doing what this file says it does");

	/* AND THE SEARCH IS STILL A SEARCH, which the check above cannot show
	 * on its own. A loop that enumerates one-byte candidates against a
	 * seventeen-byte leaf fails whatever the salt is worth, so "it did not
	 * find it" is consistent with the salt being load-bearing AND with the
	 * search being broken. Those are different worlds and the file has to
	 * separate them.
	 *
	 * So the same enumeration is run once more with the true salt in front
	 * of each candidate -- an attacker who somehow knows it -- and it must
	 * succeed. Then the failure above is attributable to not knowing the
	 * salt, which is the claim, rather than to a loop that could not have
	 * matched anything. `evidence.md`: a control has to be able to fail the
	 * way the thing it controls for fails. */
	{
		int found_with_salt = 0;

		for (guess = 0; guess < 256u; guess++) {
			uint8_t candidate[SALT_LEN + 1u];
			uint8_t h[FZN_BLOB_HASH_LEN];

			memcpy(candidate, fields[1].bytes, SALT_LEN);
			candidate[SALT_LEN] = (uint8_t)guess;
			if (fzn_blob_leaf_hash(&hash_ops, candidate, SALT_LEN + 1u, h)
			    != FZN_BLOB_OK)
				continue;
			if (memcmp(h, leaf_hashes[1], FZN_BLOB_HASH_LEN) == 0) {
				found_with_salt = 1;
				check((uint8_t)guess == 0xc7u,
				      "the salted search matched the wrong byte");
				break;
			}
		}
		check(found_with_salt == 1,
		      "knowing the salt did not recover the field either, so the search "
		      "is broken and the refusal above is evidence of nothing");
	}

	printf("  disclosure: a withheld 1-byte field is recovered from the root in "
	       "256 hashes unsalted, and is not recovered with 16 bytes of salt "
	       "unless the salt is known\n");
}

/* The suite must be able to tell a pass from a failure, which is this tree's
 * standing requirement and not a formality: every check above is a negative
 * or a positive that could be reported by a harness doing nothing. */
static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	check(0, "deliberate");
	check(failures == before + 1, "a failing check did not count");
	failures = before;
	checks -= 1;
}

int main(void)
{
	identities();

	test_one_signature_serves_two_fidelities();
	test_the_salt_is_load_bearing();
	test_the_suite_can_tell_pass_from_fail();

	printf("disclosure_test: %d checks, %d failure(s); fuzznet %s\n", checks, failures,
	       fzn_version_string());
	return failures == 0 ? 0 : 1;
}
