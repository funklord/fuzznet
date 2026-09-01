/* ONE NODE BODY, RECOMPUTED FROM THE LAYOUT TABLE IN tree.h.
 *
 * WHAT WAS MISSING, MEASURED FIRST. `FZN_TREE_OFF_ORDER` and
 * `FZN_TREE_OFF_CONTENT_TYPE` were exchanged -- content_type to 32, order to
 * 34, content still at 42, so **the body is the same 42 bytes and every
 * length is unchanged**. A pure layout change. The whole suite stayed green:
 * `tree_test` 55 checks and no failures, `tree_fuzz` 20000 cases with counts
 * identical to the digit, `network_test` 1411 checks and no failures.
 *
 * The reason is that every test `tree/` had was the encoder meeting the
 * parser. Permute both and they agree exactly as before, so the offsets
 * cancel out of both sides of every comparison. project.md records the
 * general form: a permuted field offset takes the same branches as the
 * correct version, in the same order, with the same outcome at every
 * decision -- so branch coverage is blind to this class by construction.
 *
 * THE LAYOUT ASSERTIONS IN `tree_test.c` DID NOT HELP, AND IT IS WORTH
 * SAYING WHY. They read
 *
 *     expect(body[FZN_TREE_OFF_ORDER] == 0x01u, "big-endian, high byte first")
 *
 * which uses the constant, so the check moves with the permutation. A test
 * written in terms of the thing it is checking cannot catch that thing
 * moving. **Every offset below is a literal**, taken from the table in
 * `tree.h` by hand, and the constants are then asserted to equal them -- so
 * drift is caught whichever side drifts.
 *
 * WHY IT MATTERS. A node body travels between hosts inside a signed record.
 * `tree.h` prints the table, and two implementations that agree on it produce
 * the same bytes for the same node -- which is what a signature over those
 * bytes requires. Until this file the table was a comment, and a consumer
 * implementing from it while the library drifted would produce nodes that
 * parsed at home and nowhere else.
 *
 * BOTH DIRECTIONS, DELIBERATELY. The encoder is checked against hand-written
 * expected bytes, and separately a hand-written body is fed to the parser and
 * its fields checked. An encoder-only vector would leave a parser reading the
 * wrong offsets uncaught, which is half the interoperability claim and the
 * half a receiver depends on.
 *
 * THE AUTHORITY IS THE HEADER'S TABLE, with the limit `session_kat_test`
 * states: this compares the library against its own documented layout, not
 * against an independently produced artifact, so it cannot catch a table that
 * is itself wrong. It catches the code drifting from the table, and the table
 * is what a consumer implements.
 *
 * NO CRYPTO AND NO GATE. A node body is plain bytes and `fzn_record_open`
 * does not verify, so the record around it is built by hand and this file
 * runs in every arrangement rather than only where Monocypher is present.
 */

#include "../tree.h"
#include "../../wire/bytes.h"

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

/* THE TABLE, AS LITERALS. Copied from the comment in `tree.h`:
 *
 *      off  size  field
 *        0    32  parent
 *       32     8  order
 *       40     2  content_type
 *       42     n  content
 */
#define KAT_OFF_PARENT        0
#define KAT_OFF_ORDER        32
#define KAT_OFF_CONTENT_TYPE 40
#define KAT_OFF_CONTENT      42
#define KAT_HEADER_LEN       42
#define KAT_CONTENT_MAX     470   /* 512 - 42, and 512 is FZN_RECORD_BODY_MAX */

/* The constants must equal the table. This is the check that fires when the
 * code moves and the comment does not, or the reverse. */
static void test_the_constants_match_the_table(void)
{
	expect(FZN_TREE_OFF_PARENT == KAT_OFF_PARENT,
	       "parent is not at offset 0");
	expect(FZN_TREE_OFF_ORDER == KAT_OFF_ORDER,
	       "order is not at offset 32");
	expect(FZN_TREE_OFF_CONTENT_TYPE == KAT_OFF_CONTENT_TYPE,
	       "content_type is not at offset 40");
	expect(FZN_TREE_OFF_CONTENT == KAT_OFF_CONTENT,
	       "content is not at offset 42");
	expect(FZN_TREE_BODY_HEADER_LEN == KAT_HEADER_LEN,
	       "the body header is not 42 bytes");
	expect(FZN_TREE_CONTENT_MAX == (size_t)KAT_CONTENT_MAX,
	       "content max is not 470");
	expect(FZN_TREE_ID_LEN == 32, "a node id is not 32 bytes");
}

/* THE VECTOR. Parent is 0x11 repeated, order is 0x0123456789ABCDEF,
 * content_type is 0xBEEF, content is four bytes. Every byte below was written
 * out from the table above rather than produced by the encoder. */
static const uint8_t KAT_PARENT[32] = {
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11
};
#define KAT_ORDER        0x0123456789ABCDEFull
#define KAT_CONTENT_TYPE 0xBEEFu
static const uint8_t KAT_CONTENT[4] = { 0xDE, 0xAD, 0xC0, 0xDE };

static const uint8_t KAT_BODY[KAT_HEADER_LEN + 4] = {
	/* 0..31   parent */
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	/* 32..39  order, big-endian, high byte first */
	0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
	/* 40..41  content_type, big-endian */
	0xBE, 0xEF,
	/* 42..45  content */
	0xDE, 0xAD, 0xC0, 0xDE
};

static void test_the_encoder_produces_these_bytes(void)
{
	uint8_t body[FZN_RECORD_BODY_MAX];
	size_t body_len = 0u;
	size_t i;

	memset(body, 0xA5, sizeof body);
	expect(fzn_tree_body(KAT_PARENT, KAT_ORDER, KAT_CONTENT_TYPE,
	                     KAT_CONTENT, sizeof KAT_CONTENT,
	                     body, sizeof body, &body_len) == FZN_TREE_OK,
	       "the vector's body was refused");
	expect(body_len == sizeof KAT_BODY,
	       "the encoded body is not 46 bytes");

	/* Byte for byte, and the first mismatch named. A memcmp alone would say
	 * only that something is wrong, and the offset is the whole diagnosis
	 * for a layout defect. */
	for (i = 0; i < sizeof KAT_BODY && i < body_len; i++) {
		if (body[i] != KAT_BODY[i]) {
			char msg[96];

			snprintf(msg, sizeof msg,
			         "byte %u is 0x%02X, the table says 0x%02X",
			         (unsigned)i, body[i], KAT_BODY[i]);
			expect(0, msg);
			return;
		}
	}
	expect(1, "the encoded body matches the table byte for byte");

	/* And nothing past the body was touched. */
	expect(body[sizeof KAT_BODY] == 0xA5,
	       "the encoder wrote past the length it reported");
}

/* Build a record around a body without signing: `fzn_record_open` checks
 * shape, not signatures, which is all the parser side needs. */
static int record_around(uint8_t *buf, size_t cap, const uint8_t *body,
                         size_t body_len, fzn_record_t *out)
{
	size_t total = (size_t)FZN_RECORD_HEADER_LEN + body_len + FZN_SIG_LEN;

	if (total > cap)
		return 0;
	memset(buf, 0, total);
	buf[FZN_RECORD_OFF_VERSION] = (uint8_t)FZN_SIGNED_VERSION;
	buf[FZN_RECORD_OFF_OBJECT] = (uint8_t)FZN_OBJECT_RECORD;
	fzn_put_be64(buf + FZN_RECORD_OFF_SEQ, 1u);
	fzn_put_be16(buf + FZN_RECORD_OFF_BODY_LEN, (uint16_t)body_len);
	memcpy(buf + FZN_RECORD_OFF_BODY, body, body_len);
	return fzn_record_open(buf, total, out) == FZN_RECORD_OK;
}

/* THE OTHER DIRECTION. Hand-written bytes in, fields out -- so a parser
 * reading the wrong offsets is caught even though the encoder is correct. */
static void test_the_parser_reads_these_bytes(void)
{
	uint8_t buf[FZN_RECORD_MAX_LEN];
	fzn_record_t rec;
	fzn_tree_node_t node;

	expect(record_around(buf, sizeof buf, KAT_BODY, sizeof KAT_BODY, &rec),
	       "the vector's record would not open");
	expect(fzn_tree_open(rec, &node) == FZN_TREE_OK,
	       "the vector's body would not parse as a node");

	expect(memcmp(node.parent, KAT_PARENT, sizeof KAT_PARENT) == 0,
	       "the parser read the parent from the wrong place");
	expect(node.order == KAT_ORDER,
	       "the parser read the order from the wrong place, or the wrong way round");
	expect(node.content_type == KAT_CONTENT_TYPE,
	       "the parser read the content type from the wrong place");
	expect(node.content_len == sizeof KAT_CONTENT,
	       "the parser computed the wrong content length");
	expect(memcmp(node.content, KAT_CONTENT, sizeof KAT_CONTENT) == 0,
	       "the parser read the content from the wrong place");
}

/* THE BYTE ORDER, STATED AS POSITIONS RATHER THAN AS A ROUND TRIP. A
 * little-endian encoder and a little-endian decoder agree with each other and
 * with nobody else, so this names which byte is where. */
static void test_the_multibyte_fields_are_big_endian(void)
{
	expect(KAT_BODY[KAT_OFF_ORDER] == 0x01,
	       "the order's high byte is not first");
	expect(KAT_BODY[KAT_OFF_ORDER + 7] == 0xEF,
	       "the order's low byte is not last");
	expect(KAT_BODY[KAT_OFF_CONTENT_TYPE] == 0xBE,
	       "the content type's high byte is not first");
	expect(KAT_BODY[KAT_OFF_CONTENT_TYPE + 1] == 0xEF,
	       "the content type's low byte is not last");
}

/* THE ROOT SENTINEL IS PART OF THE FORMAT, not a convention of this
 * implementation: an all-zero parent means "a child of the root", so a
 * consumer building bytes by hand needs it pinned. */
static void test_an_all_zero_parent_is_the_root(void)
{
	uint8_t body[FZN_RECORD_BODY_MAX];
	uint8_t zero[32];
	size_t body_len = 0u;
	size_t i;

	memset(zero, 0, sizeof zero);
	expect(fzn_tree_body(zero, 0u, 0u, NULL, 0u, body, sizeof body,
	                     &body_len) == FZN_TREE_OK,
	       "a root-parented body was refused");
	expect(body_len == KAT_HEADER_LEN,
	       "an empty-content body is not exactly the header");
	for (i = 0; i < KAT_HEADER_LEN; i++) {
		if (body[i] != 0u) {
			expect(0, "an all-zero node body is not all zero");
			return;
		}
	}
	expect(fzn_tree_is_root(body + KAT_OFF_PARENT) != 0,
	       "the all-zero parent is not read as the root");
}

int main(void)
{
	printf("tree_kat_test: the table in tree.h, as literals: "
	       "parent %d, order %d, content_type %d, content %d\n",
	       KAT_OFF_PARENT, KAT_OFF_ORDER, KAT_OFF_CONTENT_TYPE,
	       KAT_OFF_CONTENT);
	test_the_constants_match_the_table();
	test_the_encoder_produces_these_bytes();
	test_the_parser_reads_these_bytes();
	test_the_multibyte_fields_are_big_endian();
	test_an_all_zero_parent_is_the_root();
	printf("tree_kat_test: %d checks, %d failure(s)\n", checks, failures);

	return failures == 0 ? 0 : 1;
}
