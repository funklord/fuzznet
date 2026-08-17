/* Does `chunk/reassembly.c` agree with the schema it says it is enforcing?
 *
 * `wire/frame.situ` declares `same_message`, and `chunk/reassembly.c`
 * enforces those clauses by hand because the generated predicate reads
 * encoded views while the reassembler reads decoded fields. project.md
 * records that as a deliberate position. What it could not record is
 * whether the two actually say the same thing -- until now nothing compared
 * them, and the claim rested on three lines of C matching three lines of
 * schema by inspection.
 *
 * This compares them. For each combination of sender, message id and chunk
 * count, it asks both:
 *
 *   - situ's generated `situ_rel_same_message`, over two encoded frames;
 *   - `fzn_reasm_accept`, over the same values decoded.
 *
 * THE TWO ANSWER DIFFERENT QUESTIONS AND THAT IS THE POINT. The relation
 * says "these are pieces of one message". The reassembler says "this chunk
 * joined that partial message". They correspond exactly when the second
 * chunk lands in the SAME slot as the first and is accepted -- a differing
 * `sender` or `msg` sends it to a different slot, and a differing `chunks`
 * lands in the same slot and is refused. Both are "not the same message",
 * arrived at by different routes, and the mapping between them is the thing
 * under test rather than an incidental detail.
 *
 * A disagreement here would mean one of two things, and both are worth
 * finding: the schema declares a rule the code does not keep, or the code
 * keeps a rule the schema does not declare. The first is a security gap in
 * the direction that matters -- `same_message`'s `sender` clause is what
 * stops two senders' chunks reassembling into one message that
 * authenticates as neither.
 *
 * TWO DIVERGENCES ARE DELIBERATE AND ARE ASSERTED RATHER THAN SMOOTHED
 * OVER. The reassembler is stricter than the schema in exactly two places,
 * and both are things a schema cannot express:
 *
 *   - **A resource bound.** `FZN_REASM_MAX_CHUNKS` refuses a message
 *     claiming more pieces than a receiver will track. `chunks` is a `u16`
 *     off the wire; the schema says any non-zero value is a legal frame,
 *     and it is right, because affordability is not a property of the
 *     bytes.
 *   - **An arrival rule.** A last chunk arriving first is refused, because
 *     a short last piece cannot set the stride. That is a statement about a
 *     sequence, and a schema describes one message rather than a
 *     conversation.
 *
 * The second was found by this test failing on its first run, having been
 * written to assert an agreement that does not hold. That is the test doing
 * its job on the day it was written, and the divergence is now pinned
 * instead of latent.
 */

#include "../reassembly.h"

#include "frame.h"
#include "frame_relate.h"

#include <stdio.h>
#include <string.h>

/* The schema-versus-C CONSTANTS live in wire/tests/constants_test.c, not
 * here. This file is about behavioural agreement -- whether the reassembler
 * enforces what the relation and the constraints say -- and a constant is a
 * different question with a different failure mode. `chunk/split.h`'s payload
 * ceiling was asserted here first and moved once there were five of them.
 */

static int failures;
static int checks;

static void check(int ok, const char *what, uint8_t s2, uint32_t m2, uint16_t c2)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL: %s (sender=%02x msg=%u chunks=%u)\n", what, s2, m2, c2);
	}
}

/* From wire/frame.situ.map, as in wire/tests/generated_test.c and for the
 * same reason: asking the generated code where a field lives could not
 * detect it being wrong about that. */
#define OFF_VERSION 0x00
#define OFF_KIND    0x05
#define OFF_SENDER  0x06
#define OFF_MSG     0x56
#define OFF_INDEX   0x5A
#define OFF_CHUNKS  0x5C
#define OFF_LENGTH  0x5E
#define FRAME_MIN   144

static void put_be16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)(v & 0xffu);
}

static void put_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)((v >> 16) & 0xffu);
	p[2] = (uint8_t)((v >> 8) & 0xffu);
	p[3] = (uint8_t)(v & 0xffu);
}

static void build(uint8_t *buf, uint8_t sender, uint32_t msg, uint16_t index, uint16_t chunks)
{
	memset(buf, 0, FRAME_MIN);
	buf[OFF_VERSION] = 1;
	buf[OFF_KIND] = 2;
	memset(buf + OFF_SENDER, sender, 32);
	put_be32(buf + OFF_MSG, msg);
	put_be16(buf + OFF_INDEX, index);
	put_be16(buf + OFF_CHUNKS, chunks);
	put_be16(buf + OFF_LENGTH, 0);
}

/* What the schema says: are these two frames pieces of one message? */
static int schema_says_same(uint8_t s1, uint32_t m1, uint16_t c1, uint8_t s2, uint32_t m2,
                            uint16_t c2)
{
	uint8_t a[FRAME_MIN], b[FRAME_MIN];
	situ_msg_t ma, mb;
	situ_view_t fa, fb;

	build(a, s1, m1, 0, c1);
	build(b, s2, m2, 1, c2);
	situ_msg_init(&ma, a, sizeof(a));
	situ_msg_init(&mb, b, sizeof(b));
	if (situ_fzn_frame_view(&ma, 0, (uint32_t)sizeof(a), &fa) != SITU_OK)
		return -1;
	if (situ_fzn_frame_view(&mb, 0, (uint32_t)sizeof(b), &fb) != SITU_OK)
		return -1;

	return situ_rel_same_message(fa, fb) == SITU_OK;
}

/* What the code does: does the second chunk join the first's partial
 * message? Same slot AND accepted, which is the reassembler's spelling of
 * the relation's question. */
static int code_says_same(uint8_t s1, uint32_t m1, uint16_t c1, uint8_t s2, uint32_t m2,
                          uint16_t c2)
{
	fzn_partial_t slots[2];
	uint8_t storage[2][256];
	fzn_reasm_t table;
	fzn_partial_t *done = NULL;
	uint8_t sender1[FZN_SENDER_LEN], sender2[FZN_SENDER_LEN];
	uint8_t payload[8];
	size_t live_before, live_after;

	memset(payload, 0x5a, sizeof(payload));
	memset(sender1, s1, sizeof(sender1));
	memset(sender2, s2, sizeof(sender2));

	for (size_t i = 0; i < 2; i++)
		fzn_reasm_slot_init(&slots[i], storage[i], sizeof(storage[i]));
	fzn_reasm_init(&table, slots, 2, 2);

	if (fzn_reasm_accept(&table, sender1, m1, 0, c1, payload, sizeof(payload), 0, 100,
	                     &done) != FZN_REASM_OK)
		return -1;

	live_before = 0;
	for (size_t i = 0; i < 2; i++)
		live_before += slots[i].live ? 1u : 0u;

	if (fzn_reasm_accept(&table, sender2, m2, 1, c2, payload, sizeof(payload), 0, 100,
	                     &done) != FZN_REASM_OK)
		return 0; /* refused outright -- not the same message */

	live_after = 0;
	for (size_t i = 0; i < 2; i++)
		live_after += slots[i].live ? 1u : 0u;

	/* Accepted into a NEW slot means a different message; accepted with
	 * the slot count unchanged means it joined the first. */
	return live_after == live_before;
}

/* The schema's verdict on a lone frame: version, chunks and index bounds.
 * `situ_fzn_frame_validate` is what enforces `[must_ne = 0]` and
 * `[max = chunks - 1]`. */
static int schema_accepts_shape(uint16_t index, uint16_t chunks)
{
	uint8_t a[FRAME_MIN];
	situ_msg_t ma;
	situ_view_t fa;

	build(a, 0xa1, 7, index, chunks);
	situ_msg_init(&ma, a, sizeof(a));
	if (situ_fzn_frame_view(&ma, 0, (uint32_t)sizeof(a), &fa) != SITU_OK)
		return -1;
	return situ_fzn_frame_validate(fa) == SITU_OK;
}

/* The reassembler's verdict on the same shape, as a FIRST chunk. */
static int code_accepts_shape(uint16_t index, uint16_t chunks)
{
	fzn_partial_t slot;
	uint8_t storage[8192];
	fzn_reasm_t table;
	fzn_partial_t *done = NULL;
	uint8_t sender[FZN_SENDER_LEN];
	uint8_t payload[8];

	memset(payload, 0x5a, sizeof(payload));
	memset(sender, 0xa1, sizeof(sender));
	fzn_reasm_slot_init(&slot, storage, sizeof(storage));
	fzn_reasm_init(&table, &slot, 1, 1);

	return fzn_reasm_accept(&table, sender, 7, index, chunks, payload, sizeof(payload), 0,
	                        100, &done) == FZN_REASM_OK;
}

/* Where the two agree about a frame's SHAPE, and where the code is
 * deliberately stricter.
 *
 * The schema says a chunk count must be non-zero and an index below it.
 * `chunk/reassembly.c` says that too, and adds a resource bound the schema
 * does not express: FZN_REASM_MAX_CHUNKS, because `chunks` is a u16 off the
 * wire and tracking 65535 pieces is a stranger's choice to make a receiver
 * pay for.
 *
 * **So the code is a strict subset of the schema here, and that is correct
 * rather than a disagreement to fix.** A schema describes what a legal
 * message looks like; a receiver additionally decides what it can afford.
 * Asserting equality would be wrong, and asserting nothing would leave the
 * divergence undocumented -- so this asserts the containment in the safe
 * direction and pins where the extra strictness starts. */
static void shapes(void)
{
	static const uint16_t counts[] = { 0, 1, 2, 256, 257, 1000 };

	for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
		uint16_t c = counts[i];
		int schema = schema_accepts_shape(0, c);
		int code = code_accepts_shape(0, c);

		checks++;
		if (schema < 0 || code < 0) {
			failures++;
			printf("  FAIL: neither side could answer for chunks=%u\n", c);
			continue;
		}

		/* The safe direction: the code must never accept a shape the
		 * schema calls illegal. The reverse is allowed and expected. */
		checks++;
		if (code && !schema) {
			failures++;
			printf("  FAIL: chunk/reassembly.c accepts chunks=%u which the "
			       "schema refuses\n", c);
		}

		/* And the divergence is where it is claimed to be, so a change
		 * to either bound shows up here rather than silently. */
		checks++;
		if (c > 0 && c <= FZN_REASM_MAX_CHUNKS && !(schema && code)) {
			failures++;
			printf("  FAIL: chunks=%u is inside both bounds and was refused "
			       "(schema=%d code=%d)\n", c, schema, code);
		}
		checks++;
		if (c > FZN_REASM_MAX_CHUNKS && !(schema && !code)) {
			failures++;
			printf("  FAIL: chunks=%u should be schema-legal and code-refused "
			       "(schema=%d code=%d)\n", c, schema, code);
		}
	}

	/* index >= chunks: both refuse, and this is the bound situ implemented
	 * for us. The schema enforces it in the generated validator; the code
	 * enforces it by hand three files away. */
	checks++;
	if (schema_accepts_shape(4, 4) || code_accepts_shape(4, 4)) {
		failures++;
		printf("  FAIL: index 4 of 4 was accepted by one of the two\n");
	}

	/* THE SECOND DELIBERATE DIVERGENCE, found by this test failing on its
	 * first run rather than by anybody reasoning about it.
	 *
	 * `index 3 of 4` is a legal frame and the schema says so. As a FIRST
	 * arrival the reassembler refuses it, because the last piece may be
	 * short and so cannot set the stride -- guessing would let whoever
	 * sends the final chunk first decide how much is held.
	 *
	 * That is a rule about an arrival SEQUENCE, and a schema describes one
	 * message rather than a conversation, so there is nowhere in
	 * `frame.situ` for it to live. The divergence is therefore permanent
	 * and correct, and asserting it is the only way it stays visible. */
	checks++;
	if (!schema_accepts_shape(3, 4)) {
		failures++;
		printf("  FAIL: the schema refuses index 3 of 4, which is a legal frame\n");
	}
	checks++;
	if (code_accepts_shape(3, 4)) {
		failures++;
		printf("  FAIL: the reassembler accepted a last-chunk-first arrival\n");
	}

	/* And a non-last index of the same message is accepted by both, so the
	 * refusal above is about position rather than about the frame. */
	checks++;
	if (!schema_accepts_shape(2, 4) || !code_accepts_shape(2, 4)) {
		failures++;
		printf("  FAIL: index 2 of 4 was refused by one of the two\n");
	}
}

int main(void)
{
	static const uint8_t senders[] = { 0xa1, 0xb2 };
	static const uint32_t msgs[] = { 7, 9 };
	static const uint16_t counts[] = { 3, 5 };

	for (size_t si = 0; si < 2; si++) {
		for (size_t mi = 0; mi < 2; mi++) {
			for (size_t ci = 0; ci < 2; ci++) {
				uint8_t s2 = senders[si];
				uint32_t m2 = msgs[mi];
				uint16_t c2 = counts[ci];
				int schema = schema_says_same(0xa1, 7, 3, s2, m2, c2);
				int code = code_says_same(0xa1, 7, 3, s2, m2, c2);

				check(schema >= 0, "the schema predicate could not answer", s2,
				      m2, c2);
				check(code >= 0, "the reassembler could not answer", s2, m2, c2);
				check(schema == code,
				      "the schema and chunk/reassembly.c disagree", s2, m2, c2);
			}
		}
	}

	/* The positive control. Every case above asserts agreement, and two
	 * implementations that both answered "no" to everything would agree
	 * perfectly. One case must be a yes. */
	check(schema_says_same(0xa1, 7, 3, 0xa1, 7, 3) == 1,
	      "the identical case is not the same message -- nothing above proves anything",
	      0xa1, 7, 3);
	check(code_says_same(0xa1, 7, 3, 0xa1, 7, 3) == 1,
	      "the reassembler rejects the identical case", 0xa1, 7, 3);

	shapes();

	printf("agreement_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
