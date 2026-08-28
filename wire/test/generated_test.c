/* Exercises the generated accessors and the generated relation.
 *
 * It exists because adopting `wire/generated/` put three source files into
 * this build that **nothing touched**, and `make coverage` -- the target
 * written to refuse exactly that -- could not see them: they live in
 * `GEN_SRCS` rather than `SRCS`. A guard is only as wide as the list it
 * iterates, and that list was widened an hour after the guard was written.
 *
 * WHAT IT IS FOR, beyond not being nothing. project.md sec 7 has consumers
 * compiling these sources into their own objects, so this generated code is
 * shipped rather than incidental, and it is the first thing a consumer
 * touches. Two independent things are checked:
 *
 *   - **The accessors agree with the committed map.** The frame here is
 *     built by writing bytes at the offsets `wire/frame.situ.map` records,
 *     and then read back through the generated getters. The two are
 *     independent descriptions of one layout: the map is what `situc`
 *     published and `make schema` pins, the getters are what `situc`
 *     emitted. A generator whose map and emitter disagreed would pass its
 *     own tests and fail this one.
 *   - **The relation predicate answers.** `situ_rel_same_message` is the
 *     clause `chunk/reassembly.c` hand-enforces, so this is the first place
 *     the two implementations of one rule can be compared at all -- even
 *     though they cannot be swapped, since one reads encoded views and the
 *     other decoded fields.
 *
 * Offsets are hard-coded here and that is deliberate rather than a
 * shortcut. Everywhere else this library refuses to know the layout; here
 * the point IS to know it independently, because a test that asked the
 * generated code where a field lives could not detect the generated code
 * being wrong about it.
 */

#include "frame.h"
#include "frame_relate.h"

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

/* From wire/frame.situ.map, which `make schema` pins against the schema. */
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

/* A frame written by hand at the committed offsets. */
static void build(uint8_t *buf, uint8_t sender_seed, uint32_t msg, uint16_t index,
                  uint16_t chunks)
{
	memset(buf, 0, FRAME_MIN);
	buf[OFF_VERSION] = 1;
	buf[OFF_KIND] = 2; /* chunk */
	memset(buf + OFF_SENDER, sender_seed, 32);
	put_be32(buf + OFF_MSG, msg);
	put_be16(buf + OFF_INDEX, index);
	put_be16(buf + OFF_CHUNKS, chunks);
	put_be16(buf + OFF_LENGTH, 0);
}

int main(void)
{
	uint8_t a[FRAME_MIN], b[FRAME_MIN];
	situ_msg_t ma, mb;
	situ_view_t fa, fb, va, ha, hb;
	uint16_t u16;
	uint32_t u32;

	build(a, 0xa1, 7, 0, 3);

	situ_msg_init(&ma, a, sizeof(a));
	check(situ_fzn_frame_view(&ma, 0, (uint32_t)sizeof(a), &fa) == SITU_OK,
	      "frame view refused over a minimum-size frame");
	check(situ_fzn_frame_hop_view(fa, &va) == SITU_OK, "hop view refused");
	check(situ_fzn_frame_head_view(fa, &ha) == SITU_OK, "head view refused");

	/* The accessors against the bytes the map said to write. */
	u32 = situ_fzn_head_msg_get(ha);
	check(u32 == 7, "msg read back wrong -- the emitter and the map disagree");
	u16 = situ_fzn_head_index_get(ha);
	check(u16 == 0, "index read back wrong");
	u16 = situ_fzn_head_chunks_get(ha);
	check(u16 == 3, "chunks read back wrong");
	u16 = situ_fzn_head_length_get(ha);
	check(u16 == 0, "length read back wrong");

	/* Big-endian, which is what `endian big` in the schema promises and
	 * what a byte written high-first should produce. A little-endian
	 * emitter would return 0x07000000 here and pass every self-consistent
	 * test that wrote through its own setters. */
	put_be32(a + OFF_MSG, 0x01020304u);
	situ_msg_init(&ma, a, sizeof(a));
	situ_fzn_frame_view(&ma, 0, (uint32_t)sizeof(a), &fa);
	situ_fzn_frame_head_view(fa, &ha);
	u32 = situ_fzn_head_msg_get(ha);
	check(u32 == 0x01020304u, "msg is not read big-endian");
	put_be32(a + OFF_MSG, 7);

	/* The relation, against two frames that agree and two that do not.
	 *
	 * It takes FRAME views, not head views -- `relation same_message(first:
	 * fzn_frame, later: fzn_frame)` -- while the accessors above take head
	 * views, and the two calls sit three lines apart. A first version
	 * passed head views and every one of these four checks failed, in both
	 * directions at once, which is what a type-correct wrong argument
	 * looks like. */
	build(b, 0xa1, 7, 1, 3);
	situ_msg_init(&ma, a, sizeof(a));
	situ_msg_init(&mb, b, sizeof(b));
	situ_fzn_frame_view(&ma, 0, (uint32_t)sizeof(a), &fa);
	situ_fzn_frame_view(&mb, 0, (uint32_t)sizeof(b), &fb);
	situ_fzn_frame_head_view(fa, &ha);
	situ_fzn_frame_head_view(fb, &hb);
	check(situ_rel_same_message(fa, fb) == SITU_OK,
	      "two chunks of one message were not the same message");

	/* A different sender: the splice `chunk/reassembly.c` refuses by hand,
	 * refused here by the schema's own predicate. */
	build(b, 0xb2, 7, 1, 3);
	situ_msg_init(&mb, b, sizeof(b));
	situ_fzn_frame_view(&mb, 0, (uint32_t)sizeof(b), &fb);
	situ_fzn_frame_head_view(fb, &hb);
	check(situ_rel_same_message(fa, fb) == SITU_ERR_CONSTRAINT,
	      "two senders' chunks were accepted as one message");

	/* A different total, which is the resize attempt. */
	build(b, 0xa1, 7, 1, 5);
	situ_msg_init(&mb, b, sizeof(b));
	situ_fzn_frame_view(&mb, 0, (uint32_t)sizeof(b), &fb);
	situ_fzn_frame_head_view(fb, &hb);
	check(situ_rel_same_message(fa, fb) == SITU_ERR_CONSTRAINT,
	      "a chunk claiming a different total was accepted");

	/* And a different message id. */
	build(b, 0xa1, 9, 1, 3);
	situ_msg_init(&mb, b, sizeof(b));
	situ_fzn_frame_view(&mb, 0, (uint32_t)sizeof(b), &fb);
	situ_fzn_frame_head_view(fb, &hb);
	check(situ_rel_same_message(fa, fb) == SITU_ERR_CONSTRAINT,
	      "chunks of two different messages were accepted as one");

	/* VALIDATION, which is where the schema's constraints are actually
	 * enforced and where `[max = chunks - 1]` lands. Nothing above this
	 * called it -- `make coverage` said `frame.c` was exercised by nothing
	 * and was right, because every accessor used so far is inline in the
	 * header and the validators are the only things in the .c.
	 *
	 * This is also the first time this library has executed that bound.
	 * It took two situ commits to make it compile; compiling is not the
	 * same as enforcing, and nothing had checked the second. */
	build(a, 0xa1, 7, 0, 3);
	situ_msg_init(&ma, a, sizeof(a));
	situ_fzn_frame_view(&ma, 0, (uint32_t)sizeof(a), &fa);
	check(situ_fzn_frame_validate(fa) == SITU_OK, "a well-formed frame failed validation");

	/* version [must_eq = 1] */
	a[OFF_VERSION] = 2;
	situ_msg_init(&ma, a, sizeof(a));
	situ_fzn_frame_view(&ma, 0, (uint32_t)sizeof(a), &fa);
	check(situ_fzn_frame_validate(fa) != SITU_OK, "a frame with version 2 validated");
	a[OFF_VERSION] = 1;

	/* chunks [must_ne = 0] */
	put_be16(a + OFF_CHUNKS, 0);
	situ_msg_init(&ma, a, sizeof(a));
	situ_fzn_frame_view(&ma, 0, (uint32_t)sizeof(a), &fa);
	check(situ_fzn_frame_validate(fa) != SITU_OK, "a frame claiming zero chunks validated");

	/* index [max = chunks - 1] -- the sibling-relative bound itself.
	 * index 3 of 4 passes, 4 of 4 does not, and 4 passes again once
	 * chunks becomes 8. The third case is the one a folded constant
	 * cannot get right, and it is why this is three checks and not one. */
	put_be16(a + OFF_CHUNKS, 4);
	put_be16(a + OFF_INDEX, 3);
	situ_msg_init(&ma, a, sizeof(a));
	situ_fzn_frame_view(&ma, 0, (uint32_t)sizeof(a), &fa);
	check(situ_fzn_frame_validate(fa) == SITU_OK, "index 3 of 4 was refused");

	put_be16(a + OFF_INDEX, 4);
	situ_msg_init(&ma, a, sizeof(a));
	situ_fzn_frame_view(&ma, 0, (uint32_t)sizeof(a), &fa);
	check(situ_fzn_frame_validate(fa) != SITU_OK, "index 4 of 4 validated");

	put_be16(a + OFF_CHUNKS, 8);
	situ_msg_init(&ma, a, sizeof(a));
	situ_fzn_frame_view(&ma, 0, (uint32_t)sizeof(a), &fa);
	check(situ_fzn_frame_validate(fa) == SITU_OK,
	      "index 4 was still refused once chunks became 8 -- the bound is folded");

	/* A short buffer must be refused rather than read past. */
	{
		situ_msg_t tiny;
		situ_view_t tv;

		situ_msg_init(&tiny, a, 4);
		check(situ_fzn_frame_view(&tiny, 0, 4, &tv) != SITU_OK,
		      "a frame view was granted over four bytes");
	}

	printf("generated_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
