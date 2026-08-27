/* WHETHER EVERY FIELD IS BOUND TO THE SIGNATURE, one field at a time.
 *
 * WHY ONE MUTATION PER FIELD RATHER THAN ONE FOR THE BINDING. A single
 * "delete the binding" case is satisfied by a binding that checks one field
 * and forgets the rest -- which is exactly the state this module was in
 * before `record.h` became a view. The suite that preceded this one had a
 * stub verifier that ignored the message it was handed, so a tampered
 * subject, stream, kind, sequence, timestamp, body or body length all
 * verified and the file was green on every one. Only `issuer` was refused,
 * and only because it is the verification key rather than because anything
 * bound it.
 *
 * So there is a case per field, each naming its field when it goes red, and
 * the stub below hashes what it is given so that a case CAN go red.
 *
 * AND EVERY NEGATIVE CARRIES A POSITIVE CONTROL. Each tampered record is a
 * copy of a genuine one with a single field rewritten and the signature left
 * byte-identical, so the control is that same copy with the field left alone,
 * verifying. Without it, "the tampered record was refused" is satisfied by a
 * verifier that refuses everything -- and a verifier that refuses everything
 * scores a perfect mutation table.
 *
 * THE ORDERING CLAIM survives from the file this replaces and is now
 * structural rather than observed: a record refused for its shape or its
 * sequence is refused by `fzn_record_open`, which has no signer to spend. The
 * counters below still watch it, because a claim nobody measures is a comment.
 */

#include "../record.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
static int checks;

static void expect_err(fzn_record_err_t got, fzn_record_err_t want, const char *what)
{
	checks++;
	if (got != want) {
		failures++;
		printf("  FAIL: %s -- got \"%s\", wanted \"%s\"\n", what, fzn_record_err_str(got),
		       fzn_record_err_str(want));
	}
}

static void expect(int ok, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL: %s\n", what);
	}
}

/* THE LAYOUT AGAINST THE PAYLOAD CEILING.
 *
 * A record must fit inside one frame's sealed payload or it cannot travel
 * whole, and `frame.situ` bounds that payload with `u16 length [max = 1024]`
 * -- generated as SITU_FZN_HEAD_LENGTH_VALUE_MAX in `wire/generated/frame.h`,
 * where 1024 is justified against the IPv6 minimum MTU and re-checked in
 * `wire/test/constants_test.c`. The number is repeated here rather than
 * included because this test links no generated object and adding the include
 * path would make the record module depend on the schema it deliberately does
 * not need. If that ceiling ever moves, this assertion is what fails.
 *
 * 668 against 1024 leaves 356 bytes for whatever a consumer wraps a record
 * in, at a full 512-byte body. */
_Static_assert(FZN_RECORD_MAX_LEN == 668u, "a full record is not 668 bytes");
_Static_assert(FZN_RECORD_MIN_LEN == 156u, "an empty record is not 156 bytes");
_Static_assert(FZN_RECORD_MAX_LEN <= 1024u,
                "a full record does not fit frame.situ's payload ceiling");

/* How many verifications this file can record the key of. */
#define MAX_KEYS_SEEN 8

struct stub {
	unsigned verifies;
	unsigned signs;

	/* THE IDENTITY THIS STUB SIGNS AS. A real signer holds a secret key
	 * and a verifier holds the matching public one; this holds one value
	 * and plays both parts, which is all the suite needs and is not a
	 * signature scheme. */
	uint8_t key[FZN_PUBKEY_LEN];

	/* WHICH KEY EACH VERIFICATION USED, recorded in order.
	 *
	 * record.c verifies under the record's issuer; verifying under its
	 * subject -- the party the statement is ABOUT rather than the party
	 * asserting it -- would let anyone publish a record about themselves
	 * and have it believed, with an identical call count and an identical
	 * return code. Only the key tells them apart. The same idiom is in
	 * chain/test/chain_test.c and for the same reason. */
	size_t keys_seen;
	uint8_t key_seen[MAX_KEYS_SEEN][FZN_PUBKEY_LEN];
};

/* A STAND-IN THAT DEPENDS ON EVERY BYTE IT IS HANDED. Not cryptography, and
 * nothing outside this file may use it: it is FNV-1a over the key and then
 * the message, smeared across 64 bytes. What matters is only that flipping
 * any single bit of either input changes the result, because that is the
 * property the mutation table below is measuring against. The stub it
 * replaces threw the message away, which is why the table it produced was all
 * green. */
static void tag(uint8_t out[FZN_SIG_LEN], const uint8_t key[FZN_PUBKEY_LEN], const uint8_t *msg,
                size_t msg_len)
{
	uint64_t h = 14695981039346656037u;
	size_t i;

	for (i = 0; i < FZN_PUBKEY_LEN; i++) {
		h ^= key[i];
		h *= 1099511628211u;
	}
	for (i = 0; i < msg_len; i++) {
		h ^= msg[i];
		h *= 1099511628211u;
	}
	/* Every byte of the signature carries some of it, so a tampering that
	 * reached the signature would be caught too. */
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h ^= (uint64_t)i;
		h *= 1099511628211u;
		out[i] = (uint8_t)(h >> 32);
	}
}

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	struct stub *s = (struct stub *)ctx;

	s->signs++;
	tag(sig, s->key, msg, msg_len);

	return 1;
}

static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                       size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	struct stub *s = (struct stub *)ctx;
	uint8_t want[FZN_SIG_LEN];

	if (s->keys_seen < MAX_KEYS_SEEN) {
		memcpy(s->key_seen[s->keys_seen], pubkey, FZN_PUBKEY_LEN);
		s->keys_seen++;
	}
	s->verifies++;
	tag(want, pubkey, msg, msg_len);

	return fzn_ct_memeq(want, sig, FZN_SIG_LEN);
}

/* A signer that refuses, so that FZN_RECORD_ERR_UNSIGNED out of
 * `fzn_record_sign` is reachable and reached. */
static int refusing_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	(void)ctx;
	(void)sig;
	(void)msg;
	(void)msg_len;

	return 0;
}

/* THE FIXTURE. Distinct values per field, so that a case whose patch landed at
 * the wrong offset shows up as the wrong field rather than as a pass. */
static const uint32_t STREAM = 7u;
static const uint32_t KIND = 3u;
static const uint64_t SEQ = 5u;
static const uint64_t ISSUED_AT = 1000u;

/* One tampering, applied to a copy of a genuine record.
 *
 * `off`, `patch` and `width` name a decoded field and the bytes to put there.
 * The signature and every byte outside the field are left exactly as the
 * issuer produced them, so what is measured is whether the field is BOUND to
 * that signature -- not whether the module notices a mangled buffer.
 *
 * Returns nothing and reports everything, including the control and the
 * assertion that the patch actually changes something. */
static void tampered(const char *field, const uint8_t *genuine, size_t len, size_t off,
                     const uint8_t *patch, size_t width, const fzn_sign_ops_t *sign)
{
	uint8_t copy[FZN_RECORD_MAX_LEN];
	fzn_record_t r;
	fzn_record_err_t err;

	memcpy(copy, genuine, len);

	/* THE CONTROL, FIRST. */
	checks++;
	if (fzn_record_open(copy, len, &r) != FZN_RECORD_OK ||
	    fzn_record_verify(r, sign) != FZN_RECORD_OK) {
		failures++;
		printf("  FAIL: control for the %s case -- the untampered copy did not "
		       "verify, so any refusal below proves nothing\n", field);
		return;
	}

	/* A patch that writes what was already there tests nothing at all. */
	checks++;
	if (memcmp(copy + off, patch, width) == 0) {
		failures++;
		printf("  FAIL: the %s case patches in the value already present, so it "
		       "mutates nothing\n", field);
		return;
	}
	memcpy(copy + off, patch, width);

	/* It must still PARSE, or the signature was never consulted and the
	 * case is measuring `fzn_record_open` instead. */
	checks++;
	err = fzn_record_open(copy, len, &r);
	if (err != FZN_RECORD_OK) {
		failures++;
		printf("  FAIL: the %s case was refused by open (\"%s\") before the "
		       "signature was consulted\n", field, fzn_record_err_str(err));
		return;
	}

	checks++;
	err = fzn_record_verify(r, sign);
	if (err != FZN_RECORD_ERR_UNSIGNED) {
		failures++;
		printf("  FAIL: a record with a tampered %s verified -- got \"%s\", wanted "
		       "\"%s\"\n", field, fzn_record_err_str(err),
		       fzn_record_err_str(FZN_RECORD_ERR_UNSIGNED));
	}
}

/* The same, for a field whose tampering is caught at PARSE rather than by the
 * signature: the version byte, the object byte, and a `body_len` that stops
 * agreeing with the buffer it sits in. Same control, same insistence that the
 * patch changes something. */
static void refused_shape(const char *field, const uint8_t *genuine, size_t len, size_t off,
                          const uint8_t *patch, size_t width, fzn_record_err_t want,
                          const fzn_sign_ops_t *sign)
{
	uint8_t copy[FZN_RECORD_MAX_LEN];
	fzn_record_t r;
	char what[128];

	memcpy(copy, genuine, len);

	checks++;
	if (fzn_record_open(copy, len, &r) != FZN_RECORD_OK ||
	    fzn_record_verify(r, sign) != FZN_RECORD_OK) {
		failures++;
		printf("  FAIL: control for the %s case -- the untampered copy did not "
		       "verify, so any refusal below proves nothing\n", field);
		return;
	}

	checks++;
	if (memcmp(copy + off, patch, width) == 0) {
		failures++;
		printf("  FAIL: the %s case patches in the value already present, so it "
		       "mutates nothing\n", field);
		return;
	}
	memcpy(copy + off, patch, width);

	snprintf(what, sizeof(what), "opening a record with a tampered %s", field);
	expect_err(fzn_record_open(copy, len, &r), want, what);
}

/* THE GUARD `state/` AND `log/` USE MUST REFUSE WHAT `open` REFUSES.
 *
 * `fzn_record_is_open` used to test only `base != NULL` and a minimum length.
 * That is not enough to make an accessor safe: `fzn_record_body_len` reads
 * the length out of the bytes, so a view whose embedded length disagrees with
 * its buffer hands a caller a pointer and a size that do not belong together
 * -- and the overflow lands in the CONSUMER, past anything a reader looking
 * at the crash would blame on this library.
 *
 * Every case here is a byte string `fzn_record_open` rejects, so the two must
 * agree; the last is the control, without which "is_open refuses" is
 * satisfied by a guard that refuses everything.  */
static void test_is_open_agrees_with_open(void)
{
	uint8_t buf[FZN_RECORD_MAX_LEN];
	uint8_t issuer[FZN_PUBKEY_LEN], subject[FZN_SUBJECT_LEN], body[4];
	fzn_sign_ops_t ops;
	struct stub st;
	fzn_record_t v;
	size_t wrote = 0;

	memset(issuer, 0xa1, sizeof(issuer));
	memset(subject, 0x51, sizeof(subject));
	memset(body, 7, sizeof(body));
	memset(&st, 0, sizeof(st));
	memcpy(st.key, issuer, sizeof(st.key));
	memset(&ops, 0, sizeof(ops));
	ops.sign = stub_sign;
	ops.ctx = &st;

	expect(fzn_record_sign(issuer, subject, 0, 1, 1, 1, body, sizeof(body), &ops, buf,
	                      sizeof(buf), &wrote) == FZN_RECORD_OK,
	      "the fixture could not sign a record");

	/* THE CONTROL FIRST: the genuine record must pass both. */
	expect(fzn_record_open(buf, wrote, &v) == FZN_RECORD_OK, "a genuine record would not open");
	expect(fzn_record_is_open(v) == 1, "a genuine record was not recognised as open");

	/* A body length past the buffer -- the case that reached a consumer. */
	{
		fzn_record_t forged;

		buf[FZN_RECORD_OFF_BODY_LEN] = 0x02;
		buf[FZN_RECORD_OFF_BODY_LEN + 1u] = 0x00;
		forged.base = buf;
		forged.len = wrote;
		expect(fzn_record_open(buf, wrote, &v) != FZN_RECORD_OK,
		      "open accepted a body length past the buffer");
		expect(fzn_record_is_open(forged) == 0,
		      "is_open accepted a body length past the buffer, which open refuses");
		buf[FZN_RECORD_OFF_BODY_LEN] = 0x00;
		buf[FZN_RECORD_OFF_BODY_LEN + 1u] = (uint8_t)sizeof(body);
	}

	/* A wrong version, a wrong object tag, and a buffer longer than the
	 * record it holds -- each refused by `open`, so each must be refused
	 * here. */
	{
		fzn_record_t bad;

		bad.base = buf;
		bad.len = wrote;

		buf[FZN_RECORD_OFF_VERSION] = 2;
		expect(fzn_record_is_open(bad) == 0, "is_open accepted a wrong version byte");
		buf[FZN_RECORD_OFF_VERSION] = (uint8_t)FZN_SIGNED_VERSION;

		buf[FZN_RECORD_OFF_OBJECT] = (uint8_t)FZN_OBJECT_HOP;
		expect(fzn_record_is_open(bad) == 0, "is_open accepted a record tagged as a hop");
		buf[FZN_RECORD_OFF_OBJECT] = (uint8_t)FZN_OBJECT_RECORD;

		/* SEQUENCE ZERO, WHICH THIS TEST DID NOT COVER AND THE FUZZER
		 * FOUND. `fzn_record_open` refusing it is asserted below and
		 * `fzn_record_sign` refusing it further down, but `is_open` --
		 * the guard `fzn_record_verify` gates on -- was pinned by
		 * neither, so a hand-built view at sequence zero was verified.
		 * The gap was closed in the header this morning after
		 * `record_fuzz` reported it; deleting the guard again leaves
		 * this file at 114 checks and zero failures, which is how it
		 * was measured. Three entry points share one rule and each
		 * needs its own assertion, because covering two of three reads
		 * exactly like covering the rule. */
		fzn_put_be64(buf + FZN_RECORD_OFF_SEQ, 0u);
		expect(fzn_record_is_open(bad) == 0, "is_open accepted a record at sequence zero");
		fzn_put_be64(buf + FZN_RECORD_OFF_SEQ, 1u);

		bad.len = wrote + 1u;
		expect(fzn_record_is_open(bad) == 0, "is_open accepted an over-long buffer");
	}

	/* And the control again at the end, so a guard that simply started
	 * refusing everything cannot pass this function. */
	expect(fzn_record_open(buf, wrote, &v) == FZN_RECORD_OK,
	      "the record did not survive being put back");
	expect(fzn_record_is_open(v) == 1, "is_open refuses everything, so it checks nothing");
}

/* THE BODY BOUND IN `is_open`, WHICH NOTHING PINNED.
 *
 * The case above patches `body_len` to 512 and watches both functions refuse
 * it -- but 512 IS the bound, so what refuses that buffer is the exact-length
 * rule below it, not the bound at all. Delete `body_len > FZN_RECORD_BODY_MAX`
 * from `fzn_record_is_open` and every one of the 47 binaries in this suite
 * still passes, this file included. Measured, by doing it.
 *
 * WHAT THE HOLE COSTS. A buffer whose length AGREES with an oversized
 * declaration satisfies everything else `is_open` tests, so the bound is the
 * only thing standing in front of it: 756 bytes declaring a 600-byte body is
 * refused by `fzn_record_open` ("body exceeds what a record carries") and, with
 * the bound gone, admitted by `fzn_record_is_open` -- with
 * `fzn_record_body_len` then reporting 600 against a ceiling of 512.
 * `fzn_record_verify` GATES ON `is_open`, and `state/` and `log/` call it
 * directly before reading, so a record 88 bytes past the bound verifies and is
 * admitted through a gate `fzn_record_open` closes. The same divergence class
 * as the sequence-zero one above, and the same consequence.
 *
 * The buffer has to be bigger than FZN_RECORD_MAX_LEN, which is why this is
 * its own function rather than another block in the one above: nothing this
 * module signs can reach the case, because `fzn_record_sign` refuses an
 * oversized body too. Only a hand-built view gets here -- which is exactly the
 * input class `is_open` exists for.
 *
 * The bound is pinned from both sides. 512 with a 668-byte buffer must be
 * ACCEPTED and 513 with a 669-byte buffer REFUSED, so a guard that refuses
 * everything long scores nothing here and `>=` in place of `>` goes red. */
/* A VIEW SHORTER THAN A HEADER, ON A BUFFER SIZED EXACTLY TO IT.
 *
 * `fzn_record_is_open` opens with `r.len < FZN_RECORD_MIN_LEN`, and that
 * half of the guard is what BOUNDS THE THREE HEADER READS below it -- the
 * version byte, the object byte and the big-endian `body_len`. The
 * closing `r.len == HEADER + body_len + SIG` already implies the length,
 * so removing the guard changes the VERDICT for no input: it still
 * answers 0. It just reads past the end first.
 *
 * SO THIS CASE CANNOT DISCRIMINATE BY ITS ASSERTION, and pretending
 * otherwise would be the vacuous shape this file has spent a day
 * removing. What it contributes is the INPUT: a heap buffer sized
 * exactly to a short view, which is a thing no other harness here
 * produces -- every one of them hands `is_open` at least
 * FZN_RECORD_MAX_LEN bytes, so the read has always landed inside slack
 * nobody was using. Under `make test SANITIZE=1` this case is what gives
 * ASan something to see. Measured with the length half removed:
 * `heap-buffer-overflow READ of size 1 ... in fzn_record_is_open
 * record/record.h:268`, through `fzn_get_be16`.
 *
 * The buffer is malloc'd rather than a stack array on purpose: an exact
 * heap allocation puts a redzone immediately after the last byte, where
 * a stack array may sit inside padding the compiler chose. */
static void test_is_open_bounds_its_own_reads(void)
{
	static const size_t SHORT_LENS[] = { 1u, 2u, 3u, 4u, 91u, FZN_RECORD_MIN_LEN - 1u };
	unsigned accepted = 0;

	for (size_t i = 0; i < sizeof(SHORT_LENS) / sizeof(SHORT_LENS[0]); i++) {
		uint8_t *tiny = malloc(SHORT_LENS[i]);
		fzn_record_t r;

		if (!tiny) {
			expect(0, "the fixture could not allocate a short view");
			return;
		}
		memset(tiny, 0, SHORT_LENS[i]);
		if (SHORT_LENS[i] > FZN_RECORD_OFF_VERSION)
			tiny[FZN_RECORD_OFF_VERSION] = (uint8_t)FZN_SIGNED_VERSION;
		if (SHORT_LENS[i] > FZN_RECORD_OFF_OBJECT)
			tiny[FZN_RECORD_OFF_OBJECT] = (uint8_t)FZN_OBJECT_RECORD;

		r.base = tiny;
		r.len = SHORT_LENS[i];
		if (fzn_record_is_open(r))
			accepted++;
		free(tiny);
	}

	expect(accepted == 0, "is_open accepted a view shorter than a record header");
}

static void test_is_open_bounds_the_body(void)
{
	/* 156 + 600. Deliberately past FZN_RECORD_MAX_LEN, and the only buffer
	 * in this file that is. */
	static uint8_t oversize[(size_t)FZN_RECORD_HEADER_LEN + 600u + FZN_SIG_LEN];
	fzn_sign_ops_t ops;
	struct stub st;
	fzn_record_t view;
	fzn_record_t opened;

	memset(&st, 0, sizeof(st));
	memset(&ops, 0, sizeof(ops));
	ops.verify = stub_verify;
	ops.sign = stub_sign;
	ops.ctx = &st;

	/* Every structural field the guard reads, set to something it accepts,
	 * so that the body length is the ONLY thing left to refuse it. */
	memset(oversize, 0, sizeof(oversize));
	oversize[FZN_RECORD_OFF_VERSION] = (uint8_t)FZN_SIGNED_VERSION;
	oversize[FZN_RECORD_OFF_OBJECT] = (uint8_t)FZN_OBJECT_RECORD;
	fzn_put_be64(oversize + FZN_RECORD_OFF_SEQ, 1u);
	fzn_put_be16(oversize + FZN_RECORD_OFF_BODY_LEN, 600u);

	view.base = oversize;
	view.len = sizeof(oversize);

	/* WHAT `open` SAYS, first, because the whole point is that the two
	 * must agree. BODY_TOO_LARGE rather than SHAPE: the length and the
	 * declaration do agree, so the only fault is the size. */
	expect_err(fzn_record_open(oversize, sizeof(oversize), &opened),
	           FZN_RECORD_ERR_BODY_TOO_LARGE,
	           "opening a 756-byte buffer declaring a 600-byte body");
	expect(fzn_record_is_open(view) == 0,
	       "is_open accepted a body 88 bytes past the bound, which open refuses");

	/* AND THE CONSEQUENCE ITSELF, not merely the guard. `fzn_record_verify`
	 * gates on `is_open`, so the refusal has to arrive as MALFORMED without
	 * a key ever being spent -- and with the bound gone this instead reaches
	 * the verifier and answers UNSIGNED. */
	expect_err(fzn_record_verify(view, &ops), FZN_RECORD_ERR_MALFORMED,
	           "verifying a view whose body length is past the bound");
	expect(st.verifies == 0,
	       "an oversized body reached the verifier, so a key was spent on it");

	/* THE BOUND ITSELF, from both sides, on the same bytes. */
	fzn_put_be16(oversize + FZN_RECORD_OFF_BODY_LEN, (uint16_t)FZN_RECORD_BODY_MAX);
	view.len = FZN_RECORD_MAX_LEN;
	expect(fzn_record_is_open(view) == 1,
	       "is_open refused a body of exactly FZN_RECORD_BODY_MAX, so it refuses "
	       "everything long and this proves nothing");

	fzn_put_be16(oversize + FZN_RECORD_OFF_BODY_LEN, (uint16_t)(FZN_RECORD_BODY_MAX + 1u));
	view.len = FZN_RECORD_MAX_LEN + 1u;
	expect(fzn_record_is_open(view) == 0,
	       "is_open accepted a body one byte past FZN_RECORD_BODY_MAX");
}

int main(void)
{
	struct stub stub;
	fzn_sign_ops_t sign = { stub_verify, stub_sign, &stub };
	fzn_sign_ops_t no_verify = { NULL, stub_sign, &stub };
	fzn_sign_ops_t no_sign = { stub_verify, NULL, &stub };
	fzn_sign_ops_t refuses = { stub_verify, refusing_sign, &stub };
	uint8_t issuer[FZN_PUBKEY_LEN], subject[FZN_SUBJECT_LEN];
	uint8_t body[4] = { 0xb0, 0xb1, 0xb2, 0xb3 };
	static uint8_t genuine[FZN_RECORD_MAX_LEN];
	size_t genuine_len = 0;
	fzn_record_t rec;
	uint8_t patch[8];

	memset(&stub, 0, sizeof(stub));
	memset(issuer, 0x21, sizeof(issuer));
	memset(subject, 0x22, sizeof(subject));
	memcpy(stub.key, issuer, sizeof(issuer));

	/* ------------------------------------------------------------------
	 * THE ROUND TRIP, which is the property `evidence.md` asks a layout
	 * change to carry: sign(fields) then open() then read reproduces the
	 * fields, and open() then re-encode reproduces the bytes.
	 *
	 * The second half is only checkable because the stub signer is a
	 * deterministic function of what it is handed -- which it is on
	 * purpose, and which a real Ed25519 signer also is. */
	expect_err(fzn_record_sign(issuer, subject, STREAM, KIND, SEQ, ISSUED_AT, body,
	                           sizeof(body), &sign, genuine, sizeof(genuine), &genuine_len),
	           FZN_RECORD_OK, "signing a well-formed record");
	expect(genuine_len == FZN_RECORD_HEADER_LEN + sizeof(body) + FZN_SIG_LEN,
	       "a signed record is not the length the layout says");

	expect_err(fzn_record_open(genuine, genuine_len, &rec), FZN_RECORD_OK,
	           "opening a record that was just signed");
	expect(fzn_ct_memeq(fzn_record_issuer(rec), issuer, FZN_PUBKEY_LEN),
	       "issuer did not survive the round trip");
	expect(fzn_ct_memeq(fzn_record_subject(rec), subject, FZN_SUBJECT_LEN),
	       "subject did not survive the round trip");
	expect(fzn_record_stream(rec) == STREAM, "stream did not survive the round trip");
	expect(fzn_record_kind(rec) == KIND, "kind did not survive the round trip");
	expect(fzn_record_seq(rec) == SEQ, "seq did not survive the round trip");
	expect(fzn_record_issued_at(rec) == ISSUED_AT,
	       "issued_at did not survive the round trip");
	expect(fzn_record_body_len(rec) == sizeof(body),
	       "body_len did not survive the round trip");
	expect(memcmp(fzn_record_body(rec), body, sizeof(body)) == 0,
	       "body did not survive the round trip");

	/* The signed range and the signature must partition the buffer, with
	 * nothing left over and nothing counted twice. */
	{
		const uint8_t *at = NULL;
		size_t signed_len = 0;

		fzn_record_signed_bytes(rec, &at, &signed_len);
		expect(at == genuine, "the signed range does not start at the record");
		expect(signed_len == genuine_len - FZN_SIG_LEN,
		       "the signed range is not everything but the signature");
		expect(fzn_record_signature(rec) == genuine + signed_len,
		       "the signature does not begin where the signed range ends");
	}

	/* AND BACK TO BYTES. Re-encoding from what `open` read must reproduce
	 * the buffer exactly -- which is the canonical-encoding property, and
	 * the one that makes a signature over these bytes mean something. */
	{
		uint8_t again[FZN_RECORD_MAX_LEN];
		size_t again_len = 0;

		expect_err(fzn_record_sign(fzn_record_issuer(rec), fzn_record_subject(rec),
		                           fzn_record_stream(rec), fzn_record_kind(rec),
		                           fzn_record_seq(rec), fzn_record_issued_at(rec),
		                           fzn_record_body(rec), fzn_record_body_len(rec),
		                           &sign, again, sizeof(again), &again_len),
		           FZN_RECORD_OK, "re-encoding what open read back");
		expect(again_len == genuine_len, "the re-encoded record is a different length");
		expect(memcmp(again, genuine, genuine_len) == 0,
		       "re-encoding what open read back did not reproduce the bytes");
	}

	expect_err(fzn_record_verify(rec, &sign), FZN_RECORD_OK, "verifying a genuine record");

	/* UNDER WHOSE KEY, which is what makes the OK above mean anything. */
	expect(stub.keys_seen >= 1 &&
	               fzn_ct_memeq(stub.key_seen[stub.keys_seen - 1], issuer, FZN_PUBKEY_LEN),
	       "the record was not verified under its issuer's key");
	expect(!fzn_ct_memeq(issuer, subject, FZN_PUBKEY_LEN),
	       "the fixture's issuer and subject are the same key, so the check above "
	       "proves nothing");

	/* ------------------------------------------------------------------
	 * THE MUTATION TABLE. One case per field. Every one of these verified
	 * OK before the record became a view over its own bytes.
	 *
	 * `seq` and `stream` come first because they are the two that reach
	 * `state/`: a bumped sequence resurrects a permission a revocation had
	 * already withdrawn, and a moved stream wedges a cell at CROSS_STREAM
	 * for ever, so the revocation never lands at all. */

	/* seq 5 -> 1<<40. The replay: an issuer's own signed grant, re-presented
	 * far enough ahead that `fzn_state_apply` prefers it to the revocation
	 * that superseded it. */
	fzn_put_be64(patch, 1ull << 40);
	tampered("seq", genuine, genuine_len, FZN_RECORD_OFF_SEQ, patch, 8, &sign);

	/* stream 7 -> 9. `state/` derives writer identity from this, so a
	 * genuine record moved to another stream contends with the cell it
	 * lands in and nothing can ever resolve it. */
	fzn_put_be32(patch, 9u);
	tampered("stream", genuine, genuine_len, FZN_RECORD_OFF_STREAM, patch, 4, &sign);

	/* issuer. Refused before this change too, but only because it is the
	 * key the verification uses -- nothing bound it. It is in the table so
	 * that the reason changes with the code. */
	patch[0] = 0x99;
	tampered("issuer", genuine, genuine_len, FZN_RECORD_OFF_ISSUER, patch, 1, &sign);

	/* subject: who the statement is ABOUT. */
	patch[0] = 0x99;
	tampered("subject", genuine, genuine_len, FZN_RECORD_OFF_SUBJECT, patch, 1, &sign);

	/* kind: which of a consumer's taxonomies this belongs to, and what
	 * capability authorises it. */
	fzn_put_be32(patch, 4u);
	tampered("kind", genuine, genuine_len, FZN_RECORD_OFF_KIND, patch, 4, &sign);

	/* issued_at: not trusted for ordering, but it is what an expiry policy
	 * compares and what a consumer displays. */
	fzn_put_be64(patch, 2000u);
	tampered("issued_at", genuine, genuine_len, FZN_RECORD_OFF_ISSUED_AT, patch, 8, &sign);

	/* body: the consumer's own bytes -- the value being set. */
	patch[0] = 0xff;
	tampered("body", genuine, genuine_len, FZN_RECORD_OFF_BODY, patch, 1, &sign);

	/* ------------------------------------------------------------------
	 * `body_len`, WHICH IS THE OTHER HALF OF THE CLASSIC BREAK and takes
	 * three cases, because the length is bound two ways at once.
	 *
	 * The buffer's length must agree with the field, which `open` checks;
	 * and the field is inside the signed range, which `verify` checks. A
	 * design that had only the first would let a length be edited as long
	 * as the buffer were re-cut to match, which is the third case. */

	/* Grown, 4 -> 64, with the buffer unchanged. */
	fzn_put_be16(patch, 64u);
	refused_shape("body_len grown past the buffer", genuine, genuine_len,
	              FZN_RECORD_OFF_BODY_LEN, patch, 2, FZN_RECORD_ERR_SHAPE, &sign);

	/* Shrunk, 4 -> 0, with the buffer unchanged. */
	fzn_put_be16(patch, 0u);
	refused_shape("body_len shrunk below the buffer", genuine, genuine_len,
	              FZN_RECORD_OFF_BODY_LEN, patch, 2, FZN_RECORD_ERR_SHAPE, &sign);

	/* AND THE ONE THE SHAPE CHECK CANNOT CATCH: re-cut the buffer to match
	 * the lie. A genuine record with a 64-byte body, re-presented with
	 * `body_len` 4 and only the first 160 bytes handed over, is a perfectly
	 * well-shaped record -- and the last 64 of those bytes are the original
	 * body rather than a signature, so it is the SIGNATURE that has to
	 * refuse it. Truncation and extension are the same attack from either
	 * end, and this is the case that says the signed range moves with the
	 * length. */
	{
		static uint8_t big[FZN_RECORD_MAX_LEN];
		static uint8_t cut[FZN_RECORD_MAX_LEN];
		uint8_t big_body[64];
		size_t big_len = 0, cut_len;
		fzn_record_t r;

		memset(big_body, 0xc0, sizeof(big_body));
		expect_err(fzn_record_sign(issuer, subject, STREAM, KIND, SEQ, ISSUED_AT,
		                           big_body, sizeof(big_body), &sign, big, sizeof(big),
		                           &big_len),
		           FZN_RECORD_OK, "signing a record with a 64-byte body");

		/* The control: untouched, it verifies. */
		expect_err(fzn_record_open(big, big_len, &r), FZN_RECORD_OK,
		           "control: opening the 64-byte-body record");
		expect_err(fzn_record_verify(r, &sign), FZN_RECORD_OK,
		           "control: the 64-byte-body record must verify before it is cut");

		cut_len = (size_t)FZN_RECORD_HEADER_LEN + 4u + FZN_SIG_LEN;
		memcpy(cut, big, cut_len);
		fzn_put_be16(cut + FZN_RECORD_OFF_BODY_LEN, 4u);

		expect_err(fzn_record_open(cut, cut_len, &r), FZN_RECORD_OK,
		           "a truncated record is well-shaped, so open must accept it");
		expect_err(fzn_record_verify(r, &sign), FZN_RECORD_ERR_UNSIGNED,
		           "a record truncated to a shorter body_len verified");
	}

	/* ------------------------------------------------------------------
	 * THE TWO BYTES INSIDE THE SIGNED RANGE THAT NOTHING ELSE READS. Both
	 * are refused at parse, and both must be, because their whole purpose
	 * is to make one signed object unpresentable as another. */
	patch[0] = (uint8_t)(FZN_SIGNED_VERSION + 1u);
	refused_shape("version byte", genuine, genuine_len, FZN_RECORD_OFF_VERSION, patch, 1,
	              FZN_RECORD_ERR_SHAPE, &sign);

	patch[0] = (uint8_t)FZN_OBJECT_HOP;
	refused_shape("object byte", genuine, genuine_len, FZN_RECORD_OFF_OBJECT, patch, 1,
	              FZN_RECORD_ERR_SHAPE, &sign);

	/* ------------------------------------------------------------------
	 * THE ORDER. A record refused for its sequence must not cost a
	 * signature verification -- and it cannot, because the refusal happens
	 * in a function with no signer. Measured rather than asserted in prose. */
	{
		uint8_t copy[FZN_RECORD_MAX_LEN];
		unsigned before = stub.verifies;
		fzn_record_t r;

		memcpy(copy, genuine, genuine_len);
		fzn_put_be64(copy + FZN_RECORD_OFF_SEQ, 0u);
		expect_err(fzn_record_open(copy, genuine_len, &r), FZN_RECORD_ERR_SEQ_ZERO,
		           "opening a record whose sequence is zero");
		expect(stub.verifies == before,
		       "a record refused for its sequence still cost a signature check");
	}

	/* And a shapeless buffer costs nothing either. */
	{
		unsigned before = stub.verifies;
		fzn_record_t r;

		expect_err(fzn_record_open(genuine, FZN_RECORD_MIN_LEN - 1u, &r),
		           FZN_RECORD_ERR_SHAPE, "opening a buffer below the minimum length");
		expect_err(fzn_record_open(genuine, genuine_len + 1u, &r),
		           FZN_RECORD_ERR_SHAPE,
		           "opening a buffer longer than its body_len accounts for");
		expect(stub.verifies == before,
		       "a buffer refused for its shape still cost a signature check");
	}

	/* ------------------------------------------------------------------
	 * A BAD SIGNATURE IS A BAD SIGNATURE, not a malformed record, and the
	 * check has to actually run. */
	{
		uint8_t copy[FZN_RECORD_MAX_LEN];
		unsigned before = stub.verifies;
		fzn_record_t r;

		memcpy(copy, genuine, genuine_len);
		copy[genuine_len - 1u] ^= 0x01u;
		expect_err(fzn_record_open(copy, genuine_len, &r), FZN_RECORD_OK,
		           "a record with a bad signature is still well-shaped");
		expect_err(fzn_record_verify(r, &sign), FZN_RECORD_ERR_UNSIGNED,
		           "a forged signature");
		expect(stub.verifies == before + 1u, "the signature was not actually checked");
	}

	/* ------------------------------------------------------------------
	 * THE BODY BOUND, at it and past it, in both directions. */
	{
		static uint8_t full[FZN_RECORD_MAX_LEN];
		static uint8_t max_body[FZN_RECORD_BODY_MAX];
		static uint8_t over[FZN_RECORD_MAX_LEN + 1u];
		size_t full_len = 0;
		fzn_record_t r;

		memset(max_body, 0x5a, sizeof(max_body));
		expect_err(fzn_record_sign(issuer, subject, STREAM, KIND, SEQ, ISSUED_AT,
		                           max_body, FZN_RECORD_BODY_MAX, &sign, full,
		                           sizeof(full), &full_len),
		           FZN_RECORD_OK, "signing a body exactly at the bound");
		expect(full_len == FZN_RECORD_MAX_LEN,
		       "a record with a full body is not FZN_RECORD_MAX_LEN bytes");
		expect_err(fzn_record_open(full, full_len, &r), FZN_RECORD_OK,
		           "opening a record with a body at the bound");
		expect_err(fzn_record_verify(r, &sign), FZN_RECORD_OK,
		           "verifying a record with a body at the bound");

		/* One past it, refused by the encoder. */
		expect_err(fzn_record_sign(issuer, subject, STREAM, KIND, SEQ, ISSUED_AT,
		                           max_body, FZN_RECORD_BODY_MAX + 1u, &sign, over,
		                           sizeof(over), &full_len),
		           FZN_RECORD_ERR_BODY_TOO_LARGE, "signing a body past the bound");

		/* And by the parser, on a buffer that is internally consistent
		 * and simply too big. That is its own error rather than SHAPE:
		 * a consumer can split the statement or raise the bound, and
		 * can do nothing at all about a shapeless buffer. */
		memcpy(over, full, FZN_RECORD_HEADER_LEN);
		fzn_put_be16(over + FZN_RECORD_OFF_BODY_LEN, (uint16_t)(FZN_RECORD_BODY_MAX + 1u));
		expect_err(fzn_record_open(over, sizeof(over), &r),
		           FZN_RECORD_ERR_BODY_TOO_LARGE, "opening a body past the bound");
	}

	/* ------------------------------------------------------------------
	 * A RECORD WITH NO BODY is legitimate: a statement whose meaning is
	 * entirely in `kind` and `subject` carries nothing else. Its body
	 * pointer is not null -- there is nowhere for a null to come from -- so
	 * the null-body-with-a-length case every consumer used to test for is
	 * now unrepresentable. */
	{
		static uint8_t empty[FZN_RECORD_MAX_LEN];
		size_t empty_len = 0;
		fzn_record_t r;

		expect_err(fzn_record_sign(issuer, subject, STREAM, KIND, SEQ, ISSUED_AT, NULL,
		                           0, &sign, empty, sizeof(empty), &empty_len),
		           FZN_RECORD_OK, "signing a record with no body");
		expect(empty_len == FZN_RECORD_MIN_LEN,
		       "a record with no body is not FZN_RECORD_MIN_LEN bytes");
		expect_err(fzn_record_open(empty, empty_len, &r), FZN_RECORD_OK,
		           "opening a record with no body");
		expect_err(fzn_record_verify(r, &sign), FZN_RECORD_OK,
		           "verifying a record with no body");
		expect(fzn_record_body_len(r) == 0, "an empty body is not zero-length");
		expect(fzn_record_body(r) != NULL, "an empty body still has somewhere to point");
	}

	/* ------------------------------------------------------------------
	 * ARGUMENTS: the caller's bugs, kept distinct from a bad record. */
	{
		fzn_record_t r;
		uint8_t small[FZN_RECORD_MIN_LEN];
		size_t n = 0;

		expect_err(fzn_record_open(NULL, genuine_len, &r), FZN_RECORD_ERR_MALFORMED,
		           "opening a null buffer");
		expect_err(fzn_record_open(genuine, genuine_len, NULL),
		           FZN_RECORD_ERR_MALFORMED, "opening into a null view");

		expect_err(fzn_record_verify(rec, NULL), FZN_RECORD_ERR_MALFORMED,
		           "verifying with null sign ops");
		expect_err(fzn_record_verify(rec, &no_verify), FZN_RECORD_ERR_MALFORMED,
		           "verifying with sign ops that have no verify");

		/* A view nobody opened. MALFORMED rather than a read through
		 * whatever the caller had. */
		{
			fzn_record_t unopened;

			memset(&unopened, 0, sizeof(unopened));
			expect(!fzn_record_is_open(unopened),
			       "a zeroed view claims to have been opened");
			expect_err(fzn_record_verify(unopened, &sign),
			           FZN_RECORD_ERR_MALFORMED, "verifying a view nobody opened");
		}

		expect_err(fzn_record_sign(NULL, subject, STREAM, KIND, SEQ, ISSUED_AT, body,
		                           sizeof(body), &sign, small, sizeof(small), &n),
		           FZN_RECORD_ERR_MALFORMED, "signing with no issuer");
		expect_err(fzn_record_sign(issuer, subject, STREAM, KIND, SEQ, ISSUED_AT, body,
		                           sizeof(body), &no_sign, small, sizeof(small), &n),
		           FZN_RECORD_ERR_MALFORMED, "signing with sign ops that have no sign");
		expect_err(fzn_record_sign(issuer, subject, STREAM, KIND, SEQ, ISSUED_AT, NULL,
		                           4, &sign, small, sizeof(small), &n),
		           FZN_RECORD_ERR_MALFORMED, "signing a null body of non-zero length");
		expect_err(fzn_record_sign(issuer, subject, STREAM, KIND, 0, ISSUED_AT, body,
		                           sizeof(body), &sign, small, sizeof(small), &n),
		           FZN_RECORD_ERR_SEQ_ZERO, "signing a record at sequence zero");

		/* `small` holds a record with no body and this one has four
		 * bytes of it, so the buffer is short by exactly four. */
		expect_err(fzn_record_sign(issuer, subject, STREAM, KIND, SEQ, ISSUED_AT, body,
		                           sizeof(body), &sign, small, sizeof(small), &n),
		           FZN_RECORD_ERR_MALFORMED, "signing into a buffer four bytes short");
		expect(n == 0, "a failed sign reported a length");

		/* A signer that refuses is UNSIGNED, not MALFORMED: the request
		 * was well formed and the answer was no. */
		expect_err(fzn_record_sign(issuer, subject, STREAM, KIND, SEQ, ISSUED_AT, NULL,
		                           0, &refuses, small, sizeof(small), &n),
		           FZN_RECORD_ERR_UNSIGNED, "a signer that refuses");

		/* AND IT LEAVES NO STALE SIGNATURE BEHIND, which matters because
		 * the header and body are already written by then. A caller
		 * signing a series into one buffer would otherwise be left with
		 * the PREVIOUS record's signature sitting under this record's
		 * header -- measured at 64 non-zero bytes before this was
		 * fixed. Both siblings zero it and both say why; this one did
		 * not. */
		{
			static uint8_t reused[FZN_RECORD_MAX_LEN];
			size_t good_len = 0;
			size_t nonzero = 0;
			size_t i;

			expect_err(fzn_record_sign(issuer, subject, STREAM, KIND, SEQ, ISSUED_AT,
			                           body, sizeof(body), &sign, reused,
			                           sizeof(reused), &good_len),
			           FZN_RECORD_OK, "the first record into the shared buffer");
			/* The control: that first signature really is non-zero, or
			 * the check below passes on an empty buffer. */
			for (i = good_len - FZN_SIG_LEN; i < good_len; i++)
				nonzero += reused[i] ? 1u : 0u;
			expect(nonzero != 0, "the fixture's signature is all zero, so this "
			                     "proves nothing");

			expect_err(fzn_record_sign(issuer, subject, STREAM, KIND, SEQ + 1u,
			                           ISSUED_AT, body, sizeof(body), &refuses,
			                           reused, sizeof(reused), &n),
			           FZN_RECORD_ERR_UNSIGNED, "the refused record into the same "
			                                    "buffer");
			nonzero = 0;
			for (i = good_len - FZN_SIG_LEN; i < good_len; i++)
				nonzero += reused[i] ? 1u : 0u;
			expect(nonzero == 0, "a refused sign left the previous record's "
			                     "signature in the buffer");
		}
	}

	/* Every enumerator renders, including one that is not an enumerator at
	 * all -- `err_str` is documented never to return NULL. */
	expect(fzn_record_err_str(FZN_RECORD_ERR_SHAPE)[0] != '\0',
	       "FZN_RECORD_ERR_SHAPE renders as nothing");
	expect(strcmp(fzn_record_err_str((fzn_record_err_t)-99), "unknown") == 0,
	       "a value that is not an enumerator does not render as unknown");

	printf("record_test: layout %u + body + %u, %zu..%zu bytes\n",
	       (unsigned)FZN_RECORD_HEADER_LEN, (unsigned)FZN_SIG_LEN,
	       (size_t)FZN_RECORD_MIN_LEN, (size_t)FZN_RECORD_MAX_LEN);
	test_is_open_agrees_with_open();
	test_is_open_bounds_its_own_reads();
	test_is_open_bounds_the_body();
	printf("record_test: %d checks, %d failure(s)\n", checks, failures);

	return failures == 0 ? 0 : 1;
}
