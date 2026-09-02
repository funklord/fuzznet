/* ONE SIGNED RECORD, RECOMPUTED FROM THE LAYOUT TABLE IN record.h.
 *
 * WHY THIS EXISTS, AND THE FIRST REASON I HAD WAS WRONG. The argument that
 * sent me here was `tree/`'s: on 2026-09-02 two of its offsets were
 * exchanged, its whole suite stayed green, and `record/` looked like the same
 * case -- `record_fuzz.c` asserts canonicality, which is self-consistency,
 * and self-consistency survives a permuted table.
 *
 * **It is not the same case, and the difference was found by trying it.**
 * `record/record.c` carries ten `_Static_assert`s pinning every offset to a
 * literal -- issuer at 2, subject at 34, and so on to a 668-byte maximum --
 * so the permutation does not merely fail a test, it fails to COMPILE. That
 * protection is stronger than anything a run-time vector gives, and it is why
 * this file does not exist for offsets.
 *
 * WHAT NOTHING PINNED IS BYTE ORDER. There is no assertion anywhere that a
 * multi-byte field is big-endian, and a little-endian encoder agrees
 * perfectly with a little-endian decoder. Measured rather than argued: with
 * `fzn_record_sign` and `fzn_record_stream` BOTH changed to little-endian, so
 * that the two sides still agree with each other, `record_fuzz` ran 4000
 * cases green on a record format that no longer matches its own documented
 * table. This file caught it.
 *
 * That is the same blindness the permutation exposed in `tree/`, pointed at
 * ordering instead of position: **the encoder meets the parser, so anything
 * both of them do consistently cancels out of every comparison.** A vector
 * is the only test that has an opinion about the bytes themselves.
 *
 * WHY IT MATTERS. A record is the signed statement every dynamic permission
 * in this workspace is made of, and `record.h` prints the table so that "a
 * reader and the code cannot disagree about them either". That is a promise
 * to a second implementation, and a wrong byte order makes two implementations
 * that each verify at home and interoperate with nobody -- which a signature
 * over the bytes turns from inconvenient into fatal.
 *
 * THE OFFSET CHECKS BELOW ARE DELIBERATELY REDUNDANT with those static
 * assertions, and kept for two reasons: the table is transcribed here by hand
 * from the comment rather than read from the code, so this file is a second
 * witness to what the table SAYS; and if the assertions were ever removed as
 * clutter, the vector still holds. They cost nothing and they are not the
 * reason the file exists.
 *
 * BOTH DIRECTIONS. Hand-written bytes are checked against the encoder's
 * output, and separately fed to the parser and every accessor read back. An
 * encoder-only vector leaves a parser reading the wrong offsets uncaught,
 * which is the half a receiver depends on.
 *
 * AND THE SIGNED RANGE IS PART OF THE FORMAT. `fzn_record_signed_bytes` says
 * which span a signature covers; one byte short at either end is a field that
 * can be edited on a record that still verifies, which `record.h` records as
 * having actually happened to this module.
 *
 * THE AUTHORITY IS THE HEADER'S TABLE, with the limit `session_kat_test`
 * states: this compares the library against its own documented layout, not
 * against an independently produced artifact, so it cannot catch a table that
 * is itself wrong.
 *
 * NO CRYPTO AND NO GATE. The signer is a stub whose signature is a constant,
 * because nothing here tests signing -- only where the bytes sit.
 */
#include "../record.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void expect(int ok, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		fprintf(stderr, "  FAIL: %s\n", what);
	}
}

/* THE TABLE, AS LITERALS. Copied by hand from the comment in `record.h`:
 *
 *      off  size  field
 *        0     1  version
 *        1     1  object
 *        2    32  issuer
 *       34    32  subject
 *       66     4  stream
 *       70     4  kind
 *       74     8  seq
 *       82     8  issued_at
 *       90     2  body_len
 *       92     n  body
 *     92+n    64  signature
 */
#define KAT_OFF_VERSION    0
#define KAT_OFF_OBJECT     1
#define KAT_OFF_ISSUER     2
#define KAT_OFF_SUBJECT   34
#define KAT_OFF_STREAM    66
#define KAT_OFF_KIND      70
#define KAT_OFF_SEQ       74
#define KAT_OFF_ISSUED_AT 82
#define KAT_OFF_BODY_LEN  90
#define KAT_OFF_BODY      92
#define KAT_HEADER_LEN    92
#define KAT_SIG_LEN       64
#define KAT_MIN_LEN      156   /* 92 + 0 + 64 */
#define KAT_MAX_LEN      668   /* 92 + 512 + 64 */

static void test_the_constants_match_the_table(void)
{
	expect(FZN_RECORD_OFF_VERSION == KAT_OFF_VERSION, "version is not at 0");
	expect(FZN_RECORD_OFF_OBJECT == KAT_OFF_OBJECT, "object is not at 1");
	expect(FZN_RECORD_OFF_ISSUER == KAT_OFF_ISSUER, "issuer is not at 2");
	expect(FZN_RECORD_OFF_SUBJECT == KAT_OFF_SUBJECT, "subject is not at 34");
	expect(FZN_RECORD_OFF_STREAM == KAT_OFF_STREAM, "stream is not at 66");
	expect(FZN_RECORD_OFF_KIND == KAT_OFF_KIND, "kind is not at 70");
	expect(FZN_RECORD_OFF_SEQ == KAT_OFF_SEQ, "seq is not at 74");
	expect(FZN_RECORD_OFF_ISSUED_AT == KAT_OFF_ISSUED_AT,
	       "issued_at is not at 82");
	expect(FZN_RECORD_OFF_BODY_LEN == KAT_OFF_BODY_LEN,
	       "body_len is not at 90");
	expect(FZN_RECORD_OFF_BODY == KAT_OFF_BODY, "the body is not at 92");
	expect(FZN_RECORD_HEADER_LEN == KAT_HEADER_LEN, "the header is not 92");
	expect(FZN_SIG_LEN == KAT_SIG_LEN, "a signature is not 64 bytes");
	expect((size_t)FZN_RECORD_MIN_LEN == (size_t)KAT_MIN_LEN,
	       "the minimum record is not 156 bytes");
	expect((size_t)FZN_RECORD_MAX_LEN == (size_t)KAT_MAX_LEN,
	       "the maximum record is not 668 bytes");
	expect(FZN_PUBKEY_LEN == 32, "an issuer is not 32 bytes");
	expect(FZN_SUBJECT_LEN == 32, "a subject is not 32 bytes");
}

/* THE VECTOR. Issuer 0x11 repeated, subject 0x22 repeated, stream
 * 0x0A0B0C0D, kind 0x00C0FFEE, seq 0x0011223344556677, issued_at
 * 0x8899AABBCCDDEEFF, and a four-byte body. */
static const uint8_t KAT_ISSUER[32] = {
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11
};
static const uint8_t KAT_SUBJECT[32] = {
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22
};
#define KAT_STREAM    0x0A0B0C0Du
#define KAT_KIND      0x00C0FFEEu
#define KAT_SEQ       0x0011223344556677ull
#define KAT_ISSUED_AT 0x8899AABBCCDDEEFFull
static const uint8_t KAT_BODY[4] = { 0xDE, 0xAD, 0xBE, 0xEF };

/* The signed range, written out from the table. The signature follows and is
 * the stub's, so it is not part of this array. */
static const uint8_t KAT_SIGNED[KAT_HEADER_LEN + 4] = {
	0x01,                   /* 0      version   */
	0x82,                   /* 1      object    FZN_OBJECT_RECORD = 130 */
	/* 2..33   issuer */
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	/* 34..65  subject */
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
	/* 66..69  stream, big-endian */
	0x0A, 0x0B, 0x0C, 0x0D,
	/* 70..73  kind, big-endian */
	0x00, 0xC0, 0xFF, 0xEE,
	/* 74..81  seq, big-endian */
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	/* 82..89  issued_at, big-endian */
	0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
	/* 90..91  body_len, big-endian */
	0x00, 0x04,
	/* 92..95  body */
	0xDE, 0xAD, 0xBE, 0xEF
};

/* A signer that returns a constant, because nothing here tests signing. */
static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg,
                     size_t msg_len)
{
	(void)ctx;
	(void)msg;
	(void)msg_len;
	memset(sig, 0x5C, FZN_SIG_LEN);
	return 1;
}

static int stub_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN],
                       const uint8_t *msg, size_t msg_len,
                       const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	(void)pubkey;
	(void)msg;
	(void)msg_len;
	memset(want, 0x5C, sizeof(want));
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static fzn_sign_ops_t stub = { stub_verify, stub_sign, NULL };

static void test_the_encoder_produces_these_bytes(void)
{
	uint8_t out[FZN_RECORD_MAX_LEN];
	size_t out_len = 0u, i;

	memset(out, 0xA5, sizeof(out));
	expect(fzn_record_sign(KAT_ISSUER, KAT_SUBJECT, KAT_STREAM, KAT_KIND,
	                       KAT_SEQ, KAT_ISSUED_AT, KAT_BODY, sizeof(KAT_BODY),
	                       &stub, out, sizeof(out), &out_len) == FZN_RECORD_OK,
	       "the vector's record was refused");
	expect(out_len == sizeof(KAT_SIGNED) + KAT_SIG_LEN,
	       "the encoded record is not 160 bytes");

	for (i = 0; i < sizeof(KAT_SIGNED) && i < out_len; i++) {
		if (out[i] != KAT_SIGNED[i]) {
			char msg[96];

			snprintf(msg, sizeof(msg),
			         "byte %u is 0x%02X, the table says 0x%02X",
			         (unsigned)i, out[i], KAT_SIGNED[i]);
			expect(0, msg);
			return;
		}
	}
	expect(1, "the signed range matches the table byte for byte");

	/* And the signature sits where the table puts it. */
	expect(out[sizeof(KAT_SIGNED)] == 0x5C,
	       "the signature does not begin one byte past the body");
	expect(out[out_len - 1u] == 0x5C, "the record does not end in signature");
}

static void test_the_parser_reads_these_bytes(void)
{
	uint8_t buf[FZN_RECORD_MAX_LEN];
	fzn_record_t rec;
	const uint8_t *at = NULL;
	size_t len = 0u;

	memcpy(buf, KAT_SIGNED, sizeof(KAT_SIGNED));
	memset(buf + sizeof(KAT_SIGNED), 0x5C, KAT_SIG_LEN);

	expect(fzn_record_open(buf, sizeof(KAT_SIGNED) + KAT_SIG_LEN, &rec) ==
	       FZN_RECORD_OK, "the vector's bytes would not open");
	expect(memcmp(fzn_record_issuer(rec), KAT_ISSUER, 32) == 0,
	       "the parser read the issuer from the wrong place");
	expect(memcmp(fzn_record_subject(rec), KAT_SUBJECT, 32) == 0,
	       "the parser read the subject from the wrong place");
	expect(fzn_record_stream(rec) == KAT_STREAM,
	       "the parser read the stream from the wrong place");
	expect(fzn_record_kind(rec) == KAT_KIND,
	       "the parser read the kind from the wrong place");
	expect(fzn_record_seq(rec) == KAT_SEQ,
	       "the parser read the sequence from the wrong place");
	expect(fzn_record_issued_at(rec) == KAT_ISSUED_AT,
	       "the parser read the timestamp from the wrong place");
	expect(fzn_record_body_len(rec) == sizeof(KAT_BODY),
	       "the parser read the body length from the wrong place");
	expect(memcmp(fzn_record_body(rec), KAT_BODY, sizeof(KAT_BODY)) == 0,
	       "the parser read the body from the wrong place");

	/* THE SIGNED RANGE, AS OFFSETS. One byte short at either end is a
	 * field that can be edited on a record that still verifies, which
	 * `record.h` records as having happened here. */
	fzn_record_signed_bytes(rec, &at, &len);
	expect(at == buf, "the signed range does not start at the record");
	expect(len == sizeof(KAT_SIGNED),
	       "the signed range is not everything but the signature");
	expect(memcmp(fzn_record_signature(rec), buf + sizeof(KAT_SIGNED),
	              KAT_SIG_LEN) == 0,
	       "the signature is not the last 64 bytes");
	expect(fzn_record_verify(rec, &stub) == FZN_RECORD_OK,
	       "the vector's record did not verify against the stub");
}

/* Byte order stated as positions rather than as a round trip: a
 * little-endian encoder and a little-endian decoder agree with each other and
 * with nobody else. */
static void test_the_multibyte_fields_are_big_endian(void)
{
	expect(KAT_SIGNED[KAT_OFF_STREAM] == 0x0A,
	       "the stream's high byte is not first");
	expect(KAT_SIGNED[KAT_OFF_STREAM + 3] == 0x0D,
	       "the stream's low byte is not last");
	expect(KAT_SIGNED[KAT_OFF_KIND] == 0x00 &&
	       KAT_SIGNED[KAT_OFF_KIND + 3] == 0xEE,
	       "the kind is not big-endian");
	expect(KAT_SIGNED[KAT_OFF_SEQ] == 0x00 &&
	       KAT_SIGNED[KAT_OFF_SEQ + 7] == 0x77,
	       "the sequence is not big-endian");
	expect(KAT_SIGNED[KAT_OFF_ISSUED_AT] == 0x88 &&
	       KAT_SIGNED[KAT_OFF_ISSUED_AT + 7] == 0xFF,
	       "the timestamp is not big-endian");
	expect(KAT_SIGNED[KAT_OFF_BODY_LEN] == 0x00 &&
	       KAT_SIGNED[KAT_OFF_BODY_LEN + 1] == 0x04,
	       "the body length is not big-endian");
}

/* The two discriminator bytes are inside the signed range, which is the whole
 * point of them: neither can be added later without invalidating every
 * signature already issued. Pinned as values, since a consumer implements
 * them from the table rather than from an enum it cannot see. */
static void test_the_version_and_object_bytes(void)
{
	expect(KAT_SIGNED[KAT_OFF_VERSION] == 0x01,
	       "the version byte is not 1");
	expect(KAT_SIGNED[KAT_OFF_OBJECT] == 0x82,
	       "the object byte is not 130");
	expect(KAT_OFF_VERSION < KAT_HEADER_LEN &&
	       KAT_OFF_OBJECT < KAT_HEADER_LEN,
	       "a discriminator byte is outside the signed range");
}

int main(void)
{
	printf("record_kat_test: the table in record.h, as literals: "
	       "issuer %d, subject %d, stream %d, kind %d, seq %d, "
	       "issued_at %d, body_len %d, body %d\n",
	       KAT_OFF_ISSUER, KAT_OFF_SUBJECT, KAT_OFF_STREAM, KAT_OFF_KIND,
	       KAT_OFF_SEQ, KAT_OFF_ISSUED_AT, KAT_OFF_BODY_LEN, KAT_OFF_BODY);
	test_the_constants_match_the_table();
	test_the_encoder_produces_these_bytes();
	test_the_parser_reads_these_bytes();
	test_the_multibyte_fields_are_big_endian();
	test_the_version_and_object_bytes();
	printf("record_kat_test: %d checks, %d failure(s)\n", checks, failures);

	return failures == 0 ? 0 : 1;
}
