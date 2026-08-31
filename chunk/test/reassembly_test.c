/* Tests for chunk/reassembly.c. Deterministic: `now` is a parameter and
 * every buffer is caller-owned, so a state is constructed rather than
 * arrived at. */

#include "../reassembly.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* How long a half-finished message may hold a slot. Generous, because what
 * these cases test is the bound EXISTING -- a zero expiry no longer means
 * for ever -- rather than any particular value of it. */
#define REASM_MAX_HOLD 1000000u

static int failures;
static int checks;

#if defined(__GNUC__)
#define FZN_CHECK_PRINTF __attribute__((format(printf, 3, 4)))
#else
#define FZN_CHECK_PRINTF
#endif

static void check_at(int ok, int line, const char *fmt, ...) FZN_CHECK_PRINTF;

static void check_at(int ok, int line, const char *fmt, ...)
{
	va_list ap;

	checks++;
	if (ok)
		return;

	failures++;
	fprintf(stderr, "  FAIL reassembly_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

#define SLOTS 3
#define SLOT_BYTES 64

struct fixture {
	fzn_reasm_t table;
	fzn_partial_t slots[SLOTS];
	uint8_t storage[SLOTS][SLOT_BYTES];
	uint8_t alice[FZN_SENDER_LEN];
	uint8_t bob[FZN_SENDER_LEN];
};

static void fixture_init(struct fixture *f, size_t per_sender_max)
{
	memset(f, 0, sizeof(*f));
	for (size_t i = 0; i < SLOTS; i++)
		fzn_reasm_slot_init(&f->slots[i], f->storage[i], SLOT_BYTES);
	fzn_reasm_init(&f->table, f->slots, SLOTS, per_sender_max, REASM_MAX_HOLD);
	memset(f->alice, 0xa1, FZN_SENDER_LEN);
	memset(f->bob, 0xb2, FZN_SENDER_LEN);
}

/* Chunk `index` of a message whose pieces are `len` bytes of (seed+index). */
static void fill(uint8_t *out, size_t len, uint8_t seed, uint16_t index)
{
	memset(out, (uint8_t)(seed + index), len);
}

static void test_reassembles_in_order(void)
{
	struct fixture f;
	fzn_partial_t *done = NULL;
	uint8_t piece[8];

	fixture_init(&f, 2);
	for (uint16_t i = 0; i < 3; i++) {
		fill(piece, 8, 0x10, i);
		CHECK(fzn_reasm_accept(&f.table, f.alice, 7, i, 3, piece, 8, 0, 100, &done) ==
		              FZN_REASM_OK,
		      "chunk %u refused", i);
	}
	CHECK(done != NULL, "three of three chunks did not complete the message");
	if (done) {
		CHECK(done->bytes == 24, "held %zu bytes, wanted 24", done->bytes);
		CHECK(done->buf[0] == 0x10 && done->buf[8] == 0x11 && done->buf[16] == 0x12,
		      "chunks landed in the wrong places");
	}
}

static void test_reassembles_out_of_order(void)
{
	struct fixture f;
	fzn_partial_t *done = NULL;
	uint8_t piece[8];
	const uint16_t order[3] = { 1, 0, 2 };

	/* The point of carrying an index: a chunk is placed where it belongs
	 * rather than where it arrived. */
	fixture_init(&f, 2);
	for (size_t k = 0; k < 3; k++) {
		fill(piece, 8, 0x10, order[k]);
		CHECK(fzn_reasm_accept(&f.table, f.alice, 7, order[k], 3, piece, 8, 0, 100,
		                       &done) == FZN_REASM_OK,
		      "chunk %u refused", order[k]);
		CHECK(k == 2 || done == NULL, "completed before every chunk arrived");
	}
	CHECK(done != NULL, "out-of-order arrival did not complete");
	if (done)
		CHECK(done->buf[0] == 0x10 && done->buf[8] == 0x11 && done->buf[16] == 0x12,
		      "out-of-order chunks landed in the wrong places");
}

static void test_a_short_last_chunk_is_allowed(void)
{
	struct fixture f;
	fzn_partial_t *done = NULL;
	uint8_t big[8], small[3];

	fixture_init(&f, 2);
	fill(big, 8, 0x20, 0);
	fill(small, 3, 0x20, 1);
	CHECK(fzn_reasm_accept(&f.table, f.alice, 1, 0, 2, big, 8, 0, 100, &done) ==
	              FZN_REASM_OK,
	      "first chunk refused");
	CHECK(fzn_reasm_accept(&f.table, f.alice, 1, 1, 2, small, 3, 0, 100, &done) ==
	              FZN_REASM_OK,
	      "a short LAST chunk was refused");
	CHECK(done != NULL && done->bytes == 11, "short last chunk did not complete");

	/* But a short chunk in the MIDDLE is a mismatch: the stride is fixed
	 * by the first, and a short middle chunk would leave a hole nobody
	 * can account for. */
	fixture_init(&f, 2);
	CHECK(fzn_reasm_accept(&f.table, f.alice, 1, 0, 3, big, 8, 0, 100, &done) ==
	              FZN_REASM_OK,
	      "first chunk refused");
	CHECK(fzn_reasm_accept(&f.table, f.alice, 1, 1, 3, small, 3, 0, 100, &done) ==
	              FZN_REASM_ERR_MISMATCH,
	      "a short MIDDLE chunk was accepted");
}

static void test_the_bound_is_enforced_on_the_first_chunk(void)
{
	struct fixture f;
	fzn_partial_t *done = NULL;
	uint8_t piece[8];

	/* SLOT_BYTES is 64, so 9 chunks of 8 is 72 and must be refused before
	 * a byte is held -- sized from the first piece rather than discovered
	 * as pieces arrive. */
	fixture_init(&f, 2);
	fill(piece, 8, 0x30, 0);
	CHECK(fzn_reasm_accept(&f.table, f.alice, 1, 0, 9, piece, 8, 0, 100, &done) ==
	              FZN_REASM_ERR_TOO_LARGE,
	      "a message larger than the slot was admitted");
	CHECK(f.slots[0].live == 0, "a refused message took a slot anyway");

	/* And a claim beyond the compile-time ceiling never reaches sizing.
	 *
	 * ON THIS FIXTURE THAT ASSERTION CANNOT FAIL, and the case below is
	 * what makes it mean something. SLOT_BYTES is 64, so `payload_len >
	 * buf_capacity / chunks` -- 8 against 64/257, which is 0 -- refuses 257
	 * chunks whether or not the ceiling exists. The refusal is real and the
	 * evidence for the ceiling is not. */
	fixture_init(&f, 2);
	CHECK(fzn_reasm_accept(&f.table, f.alice, 1, 0, (uint16_t)(FZN_REASM_MAX_CHUNKS + 1),
	                       piece, 8, 0, 100, &done) == FZN_REASM_ERR_TOO_LARGE,
	      "a chunk count past FZN_REASM_MAX_CHUNKS was admitted");
}

/* THE CEILING ITSELF, ON A SLOT BIG ENOUGH THAT NOTHING ELSE CAN DO THE
 * REFUSING.
 *
 * `chunks > FZN_REASM_MAX_CHUNKS` could be deleted from `admit_first` with
 * `reassembly_test`, `reassembly_fuzz`, `reassembly_guided`, `roundtrip_fuzz`,
 * `split_test` and `sim/test/network_test` all still green -- measured, by
 * deleting it. Only `chunk/test/agreement_test` noticed, and it noticed at the
 * API level ("chunks=257 should be schema-legal and code-refused") without ever
 * reaching what an admitted count does.
 *
 * WHAT IT DOES. `seen` is `uint8_t[FZN_REASM_MAX_CHUNKS / 8]`, 32 bytes, sized
 * against that ceiling and against nothing else. Measured on a 1-slot table
 * with an 8192-byte buffer, `chunks = 300` and a 16-byte payload: index 0 is
 * admitted, because the per-chunk bound is satisfied -- 8192/300 is 27 and the
 * payload is 16 -- and index 260 is admitted too, at which point marking it
 * seen writes byte 32 of a 32-byte array, one past its end and onto the
 * `fzn_partial_t` members that follow it. `live` came back 17. NO SANITIZER
 * SEES IT: the write stays inside the slot's own allocation, so the object it
 * corrupts is the one it was allowed to touch.
 *
 * So the size of the slot is the whole point of this fixture. On the 64-byte
 * slots above, division refuses every large count before the ceiling is
 * consulted; here it refuses none of them, and the ceiling is the only thing
 * left. The control is FZN_REASM_MAX_CHUNKS exactly, which must be ADMITTED --
 * without it "large counts are refused" is satisfied by a slot too small to
 * take any of them, which is precisely the state the case above was in. */
static void test_the_chunk_ceiling_is_what_refuses_a_large_count(void)
{
	/* 300 chunks of 16 bytes is 4800, so the per-chunk bound has nothing
	 * to say about any count this case uses. */
	static uint8_t storage[8192];
	fzn_reasm_t table;
	fzn_partial_t slot;
	fzn_partial_t *done = NULL;
	uint8_t sender[FZN_SENDER_LEN];
	uint8_t piece[16];

	memset(sender, 0xa1, sizeof(sender));
	fill(piece, sizeof(piece), 0x70, 0);

	CHECK(fzn_reasm_slot_init(&slot, storage, sizeof(storage)) == FZN_REASM_OK,
	      "the wide fixture's slot would not initialise");
	CHECK(fzn_reasm_init(&table, &slot, 1, 1, REASM_MAX_HOLD) == FZN_REASM_OK,
	      "the wide fixture's table would not initialise");

	/* THE CONTROL. Exactly at the ceiling, and the slot must take it --
	 * otherwise every refusal below is the buffer being too small. */
	CHECK(fzn_reasm_accept(&table, sender, 1, 0, (uint16_t)FZN_REASM_MAX_CHUNKS, piece,
	                       sizeof(piece), 0, 100, &done) == FZN_REASM_OK,
	      "the wide fixture refused a claim of exactly FZN_REASM_MAX_CHUNKS, so it "
	      "is too small to test the ceiling with");
	CHECK(slot.live == 1, "a claim at the ceiling was accepted without taking a slot");

	/* ONE PAST IT. Same buffer, same payload, one more chunk. */
	fzn_reasm_slot_init(&slot, storage, sizeof(storage));
	fzn_reasm_init(&table, &slot, 1, 1, REASM_MAX_HOLD);
	CHECK(fzn_reasm_accept(&table, sender, 1, 0, (uint16_t)(FZN_REASM_MAX_CHUNKS + 1u),
	                       piece, sizeof(piece), 0, 100, &done) == FZN_REASM_ERR_TOO_LARGE,
	      "a claim of one past FZN_REASM_MAX_CHUNKS was admitted by a slot wide "
	      "enough to hold it");
	CHECK(slot.live == 0, "a claim past the ceiling took a slot anyway");

	/* AND THE COUNT THAT REACHES PAST `seen`, refused at the first chunk,
	 * so that nothing ever gets as far as an index the bitmap cannot
	 * address. */
	fzn_reasm_slot_init(&slot, storage, sizeof(storage));
	fzn_reasm_init(&table, &slot, 1, 1, REASM_MAX_HOLD);
	CHECK(fzn_reasm_accept(&table, sender, 1, 0, 300, piece, sizeof(piece), 0, 100,
	                       &done) == FZN_REASM_ERR_TOO_LARGE,
	      "a claim of 300 chunks was admitted");

	/* The index that would write past `seen`, asked for directly. It is
	 * refused for the same reason and not for its index: no slot was ever
	 * taken, so there is no bitmap for it to reach past. */
	CHECK(fzn_reasm_accept(&table, sender, 1, 260, 300, piece, sizeof(piece), 0, 100,
	                       &done) == FZN_REASM_ERR_TOO_LARGE,
	      "index 260 of a 300-chunk claim was admitted, which marks a bit past the "
	      "end of a 32-byte seen set");
	CHECK(slot.live == 0, "a claim of 300 chunks took a slot anyway");
	CHECK(done == NULL, "a refused claim completed a message");
}

static void test_later_chunks_must_agree(void)
{
	struct fixture f;
	fzn_partial_t *done = NULL;
	uint8_t piece[8];

	/* frame.situ's same_message relation. A differing `chunks` tries to
	 * resize a buffer already sized against the first claim. */
	fixture_init(&f, 2);
	fill(piece, 8, 0x40, 0);
	fzn_reasm_accept(&f.table, f.alice, 1, 0, 3, piece, 8, 0, 100, &done);
	CHECK(fzn_reasm_accept(&f.table, f.alice, 1, 1, 5, piece, 8, 0, 100, &done) ==
	              FZN_REASM_ERR_MISMATCH,
	      "a later chunk claiming a different total was accepted");
	CHECK(fzn_reasm_accept(&f.table, f.alice, 1, 9, 3, piece, 8, 0, 100, &done) ==
	              FZN_REASM_ERR_MISMATCH,
	      "an index past the total was accepted");
}

/* A REFUSAL CLEARS THE COMPLETION POINTER, AND A CALLER IS MEANT TO READ IT.
 *
 * reassembly.h states the contract: "When the message completes, *out is
 * pointed at the slot and the caller owns its bytes until it calls
 * fzn_reasm_release. Until then *out is left NULL, so 'did this finish
 * something' needs no second call." That last clause is why this matters --
 * the header invites a caller to keep one `fzn_partial_t *` and test it
 * after every accept, which is the natural way to write the loop.
 *
 * `*out = NULL` at the top of fzn_reasm_accept is what makes it true, and
 * removing it left all 63 binaries green. What it costs is a caller whose
 * pointer still names the slot from the LAST completion: released, possibly
 * re-sized for another sender, and read as "this finished something".
 *
 * THE REFUSAL HAS TO HAPPEN AFTER THE CLEAR, which is the part that decides
 * the shape of this case. A malformed-argument refusal returns before
 * `*out` is touched -- correctly, since a null `out` is one of the things it
 * is refusing -- so the expiry branch is used instead: it sits below the
 * clear and needs only a chunk whose deadline has passed.
 *
 * The control is the completion itself. Without it, "the pointer is NULL
 * after a refusal" is satisfied by an accept that never sets it at all. */
static void test_a_refusal_clears_the_completion_pointer(void)
{
	struct fixture f;
	fzn_partial_t *done = NULL;
	uint8_t piece[8];

	fixture_init(&f, 2);
	fill(piece, 8, 0x40, 0);

	/* The control: a one-chunk message completes and hands over a slot. */
	CHECK(fzn_reasm_accept(&f.table, f.alice, 1, 0, 1, piece, 8, 0, 100, &done) ==
	              FZN_REASM_OK,
	      "the control message was not accepted");
	CHECK(done != NULL,
	      "a completed message did not point *out at its slot, so nothing below "
	      "can fail");
	fzn_reasm_release(done);

	/* `done` still names the slot just released. A refused accept must not
	 * leave it there. */
	CHECK(fzn_reasm_accept(&f.table, f.alice, 2, 0, 1, piece, 8, 50, 100, &done) ==
	              FZN_REASM_ERR_EXPIRED,
	      "a chunk past its expiry was accepted");
	CHECK(done == NULL,
	      "a refused accept left the caller's pointer on the slot from the last "
	      "completion, which has since been released");
}

static void test_two_senders_do_not_splice(void)
{
	struct fixture f;
	fzn_partial_t *done = NULL;
	uint8_t piece[8];

	/* Without sender in the key, two senders' chunks reassemble into one
	 * message that authenticates as neither. Both send index 0 of msg 1,
	 * which is the sharp case: identical everything except who sent it,
	 * so a key missing the sender collides exactly here. */
	fixture_init(&f, 2);
	fill(piece, 8, 0x50, 0);
	CHECK(fzn_reasm_accept(&f.table, f.alice, 1, 0, 2, piece, 8, 0, 100, &done) ==
	              FZN_REASM_OK,
	      "alice's chunk was refused");
	fill(piece, 8, 0x55, 0);
	CHECK(fzn_reasm_accept(&f.table, f.bob, 1, 0, 2, piece, 8, 0, 100, &done) ==
	              FZN_REASM_OK,
	      "bob's chunk was refused");
	CHECK(done == NULL, "two senders' chunks completed one message");
	CHECK(f.slots[0].live && f.slots[1].live, "the two senders shared a slot");
	CHECK(f.slots[0].arrived == 1 && f.slots[1].arrived == 1,
	      "one sender's chunk was counted against the other's message");
}

/* A pair of senders agreeing on every byte but the last.
 *
 * Every sender in this file is `memset(buf, seed, 32)` -- thirty-two copies
 * of one byte -- so alice and bob differ at byte 0 and a comparison of ONE
 * byte separates them exactly as well as a comparison of thirty-two. That is
 * what made the length in reassembly.c's `memcmp(slot->sender, sender,
 * FZN_SENDER_LEN)` unfalsifiable in both places it appears: truncating either
 * to 1 left this whole suite green, measured before these cases were written.
 *
 * A seed cannot express the pair that separates a full comparison from a
 * short one, which is precisely why nothing here could fail. */
static void twin_senders(uint8_t a[FZN_SENDER_LEN], uint8_t b[FZN_SENDER_LEN])
{
	memset(a, 0x5a, FZN_SENDER_LEN);
	memset(b, 0x5a, FZN_SENDER_LEN);
	b[FZN_SENDER_LEN - 1u] ^= 0x01u;
}

static void test_the_twin_fixture_is_what_it_claims(void)
{
	uint8_t a[FZN_SENDER_LEN], b[FZN_SENDER_LEN];

	/* Asserted once, here, rather than in each case below, so that a
	 * fixture which quietly stopped producing a near-miss pair fails by
	 * name instead of turning three cases green for the wrong reason. */
	twin_senders(a, b);
	CHECK(memcmp(a, b, FZN_SENDER_LEN - 1u) == 0,
	      "the twin senders must agree on every byte but the last, or the cases "
	      "below are not testing what they say");
	CHECK(memcmp(a, b, FZN_SENDER_LEN) != 0,
	      "the twin senders must differ somewhere, or nothing below can fail");
}

static void test_two_near_senders_do_not_splice(void)
{
	struct fixture f;
	fzn_partial_t *done = NULL;
	uint8_t twin_a[FZN_SENDER_LEN], twin_b[FZN_SENDER_LEN];
	uint8_t piece[8];

	/* `test_two_senders_do_not_splice` above asks the right question of
	 * the wrong pair: alice and bob differ at byte 0, so it passes against
	 * a key made of ONE byte of the sender. This is that case with a pair
	 * only a full comparison separates.
	 *
	 * What fails open is the same splice, reached by a near-miss key
	 * rather than by a missing field: a stranger who matches a victim's
	 * first byte writes into the victim's half-built message, and the
	 * result authenticates as neither. */
	twin_senders(twin_a, twin_b);
	fixture_init(&f, 2);
	fill(piece, 8, 0x50, 0);
	CHECK(fzn_reasm_accept(&f.table, twin_a, 1, 0, 2, piece, 8, 0, 100, &done) ==
	              FZN_REASM_OK,
	      "the first twin's chunk was refused");
	fill(piece, 8, 0x55, 0);
	CHECK(fzn_reasm_accept(&f.table, twin_b, 1, 0, 2, piece, 8, 0, 100, &done) ==
	              FZN_REASM_OK,
	      "the second twin's chunk was refused -- it landed in the first twin's "
	      "slot, so find() is not reading the whole sender");
	CHECK(done == NULL, "two senders' chunks completed one message");
	CHECK(f.slots[0].live && f.slots[1].live,
	      "two senders differing only in their last key byte shared a slot -- "
	      "find() is not reading the whole sender");
	CHECK(f.slots[0].arrived == 1 && f.slots[1].arrived == 1,
	      "one twin's chunk was counted against the other's message");
}

static void test_a_near_sender_does_not_spend_the_quota(void)
{
	struct fixture f;
	fzn_partial_t *done = NULL;
	uint8_t twin_a[FZN_SENDER_LEN], twin_b[FZN_SENDER_LEN];
	uint8_t piece[8];

	/* `held_by` IS A SECOND COMPARISON ON A SEPARATE PATH, and closing the
	 * one in find() says nothing about it -- the vacuity is one per
	 * comparison, not one per file. It was vacuous for the same reason and
	 * measured the same way.
	 *
	 * What fails open here is the quota, in the direction the quota exists
	 * to prevent. `held_by` counts what one sender is already holding, so
	 * a short compare counts a stranger's partials against a victim: an
	 * attacker who matches the first byte of a key spends somebody else's
	 * allowance and the victim is refused a slot it never used. The
	 * per-sender bound is what stops one sender filling the table, and
	 * this turns it into a way to deny service to a chosen host.
	 *
	 * A quota of ONE, so a single stranger's slot is enough to exhaust it.
	 * Different message numbers, so that find() cannot fold the two
	 * together and reach this by another route. */
	twin_senders(twin_a, twin_b);
	fixture_init(&f, 1);
	fill(piece, 8, 0x80, 0);
	CHECK(fzn_reasm_accept(&f.table, twin_a, 1, 0, 2, piece, 8, 0, 100, &done) ==
	              FZN_REASM_OK,
	      "the first twin could not take a slot");
	CHECK(fzn_reasm_accept(&f.table, twin_b, 2, 0, 2, piece, 8, 0, 100, &done) ==
	              FZN_REASM_OK,
	      "one sender's slot was charged to another differing only in its last "
	      "key byte -- held_by() is not reading the whole sender");
	CHECK(f.slots[0].live && f.slots[1].live, "the two twins did not take a slot each");

	/* The control, which is what makes the check above mean something: a
	 * quota that never refuses anything would satisfy it too. The first
	 * twin is at its own quota of one and must still be refused. */
	CHECK(fzn_reasm_accept(&f.table, twin_a, 3, 0, 2, piece, 8, 0, 100, &done) ==
	              FZN_REASM_ERR_QUOTA,
	      "a sender at its quota was given a second slot");
}

static void test_retransmission_versus_rewrite(void)
{
	struct fixture f;
	fzn_partial_t *done = NULL;
	uint8_t piece[8], other[8], near[8];

	fixture_init(&f, 2);
	fill(piece, 8, 0x60, 0);
	fill(other, 8, 0x99, 0);
	fzn_reasm_accept(&f.table, f.alice, 1, 0, 2, piece, 8, 0, 100, &done);

	/* Identical repeat: that is what a retransmission looks like, and
	 * refusing it would break loss recovery. */
	CHECK(fzn_reasm_accept(&f.table, f.alice, 1, 0, 2, piece, 8, 0, 100, &done) ==
	              FZN_REASM_OK,
	      "a byte-identical retransmission was refused");
	CHECK(f.slots[0].arrived == 1, "a retransmission was counted twice");

	/* Differing repeat: rewriting part of a message after the rest was
	 * accepted. */
	CHECK(fzn_reasm_accept(&f.table, f.alice, 1, 0, 2, other, 8, 0, 100, &done) ==
	              FZN_REASM_ERR_CONFLICT,
	      "a chunk was allowed to rewrite one already held");

	/* AND A REPEAT THAT DIFFERS ONLY IN ITS LAST BYTE, because the one
	 * above does not test the length of that comparison. `piece` and
	 * `other` differ at byte 0, so a `memcmp` of ONE byte tells them apart
	 * exactly as well as a memcmp of eight -- truncating the length in
	 * reassembly.c to 1 left this case, and the whole suite, green.
	 *
	 * It is the same vacuity as the sender comparisons in this file, one
	 * layer down: two inputs that differ at the first byte cannot show how
	 * much of them was read. What fails open is the distinction
	 * `reassembly.h` draws between a retransmission and a rewrite -- a
	 * chunk altered anywhere past the first byte is reported OK, so a
	 * consumer watching for CONFLICT to see a message being tampered with
	 * sees nothing at all. */
	memcpy(near, piece, sizeof(near));
	near[sizeof(near) - 1u] ^= 0x01u;
	CHECK(memcmp(near, piece, sizeof(near) - 1u) == 0 &&
	              memcmp(near, piece, sizeof(near)) != 0,
	      "the near repeat must agree with the chunk on every byte but the last, "
	      "or this case is not testing what it says");
	CHECK(fzn_reasm_accept(&f.table, f.alice, 1, 0, 2, near, 8, 0, 100, &done) ==
	              FZN_REASM_ERR_CONFLICT,
	      "a chunk differing only in its last byte was taken for a byte-identical "
	      "retransmission -- the payload comparison is not reading the whole chunk");
}

static void test_quota_stops_one_sender_filling_the_table(void)
{
	struct fixture f;
	fzn_partial_t *done = NULL;
	uint8_t piece[8];

	/* A capacity bound alone only relocates the denial of service: one
	 * sender fills the table and nobody else is served. */
	fixture_init(&f, 2);
	fill(piece, 8, 0x70, 0);
	CHECK(fzn_reasm_accept(&f.table, f.alice, 1, 0, 2, piece, 8, 0, 100, &done) ==
	              FZN_REASM_OK,
	      "first");
	CHECK(fzn_reasm_accept(&f.table, f.alice, 2, 0, 2, piece, 8, 0, 100, &done) ==
	              FZN_REASM_OK,
	      "second");
	CHECK(fzn_reasm_accept(&f.table, f.alice, 3, 0, 2, piece, 8, 0, 100, &done) ==
	              FZN_REASM_ERR_QUOTA,
	      "one sender exceeded its quota");
	/* The slot it could not have is still there for somebody else. */
	CHECK(fzn_reasm_accept(&f.table, f.bob, 1, 0, 2, piece, 8, 0, 100, &done) ==
	              FZN_REASM_OK,
	      "the quota did not leave a slot for another sender");
}

static void test_full_table_and_expiry(void)
{
	struct fixture f;
	fzn_partial_t *done = NULL;
	uint8_t piece[8];
	uint8_t carol[FZN_SENDER_LEN];

	memset(carol, 0xc3, FZN_SENDER_LEN);
	fixture_init(&f, SLOTS);
	fill(piece, 8, 0x80, 0);
	fzn_reasm_accept(&f.table, f.alice, 1, 0, 2, piece, 8, 50, 10, &done);
	fzn_reasm_accept(&f.table, f.bob, 1, 0, 2, piece, 8, 50, 10, &done);
	fzn_reasm_accept(&f.table, carol, 1, 0, 2, piece, 8, 50, 10, &done);

	{
		uint8_t dave[FZN_SENDER_LEN];
		memset(dave, 0xd4, FZN_SENDER_LEN);
		CHECK(fzn_reasm_accept(&f.table, dave, 1, 0, 2, piece, 8, 50, 10, &done) ==
		              FZN_REASM_ERR_FULL,
		      "a full table admitted a fourth message");

		/* Expiry is what makes the bound survive: past 50 the three
		 * half-finished messages are dead and their slots come back. */
		CHECK(fzn_reasm_expire(&f.table, 60) == 3, "expired slots were not reclaimed");
		CHECK(fzn_reasm_accept(&f.table, dave, 1, 0, 2, piece, 8, 100, 60, &done) ==
		              FZN_REASM_OK,
		      "a reclaimed slot was not reusable");
	}

	/* A stale chunk never costs a slot in the first place. */
	fixture_init(&f, 2);
	CHECK(fzn_reasm_accept(&f.table, f.alice, 1, 0, 2, piece, 8, 50, 60, &done) ==
	              FZN_REASM_ERR_EXPIRED,
	      "an expired chunk was admitted");
	CHECK(f.slots[0].live == 0, "an expired chunk took a slot");
}

/* Offers chunk `index` of a `chunks`-piece message, so the cases below read
 * as the arrival pattern they are testing rather than as argument lists. */
static void offer(struct fixture *f, const uint8_t *who, uint32_t msg, uint16_t index,
                  uint16_t chunks)
{
	fzn_partial_t *done = NULL;
	uint8_t piece[8];

	fill(piece, sizeof(piece), 0x40, index);
	(void)fzn_reasm_accept(&f->table, who, msg, index, chunks, piece, sizeof(piece), 0, 10,
	                       &done);
}

static int ranges_are(const fzn_reasm_range_t *got, size_t n, const uint16_t *want, size_t want_n)
{
	if (n != want_n)
		return 0;
	for (size_t i = 0; i < n; i++)
		if (got[i].first != want[i * 2u] || got[i].count != want[i * 2u + 1u])
			return 0;
	return 1;
}

/*
 * WHAT A RECEIVER IS STILL MISSING, which it has always known and never been
 * able to say. The `seen` bitmap has existed since reassembly did; only the
 * accessor was absent, so loss recovery on this path could only be "wait and
 * hope the sender repeats itself".
 */
static void test_a_receiver_can_name_what_it_lacks(void)
{
	struct fixture f;
	fzn_reasm_range_t got[8];
	size_t n = 0;

	/* Chunks 0, 3 and 4 of eight arrive: gaps at 1-2 and 5-7. */
	fixture_init(&f, 4);
	offer(&f, f.alice, 1, 0, 8);
	offer(&f, f.alice, 1, 3, 8);
	offer(&f, f.alice, 1, 4, 8);

	CHECK(fzn_reasm_plan_want(&f.table, f.alice, 1, 100, got, 8, &n) == FZN_REASM_OK,
	      "a live message reported no plan");
	{
		static const uint16_t WANT[] = { 1, 2, 5, 3 };

		CHECK(ranges_are(got, n, WANT, 2),
		      "the gaps were not coalesced into two runs: %u ranges", (unsigned)n);
	}

	/* THE TRAILING GAP IS THE ORDINARY CASE, not an edge one: the walk
	 * only closes a run on meeting a chunk that arrived, and a message
	 * missing its tail never does. It is emitted outside the loop, which
	 * is exactly the kind of line a rewrite drops. */
	CHECK(got[1].first == 5 && got[1].count == 3,
	      "the run reaching the last chunk was dropped");

	/* SPLIT, because a peer should not be asked for an unbounded run in
	 * one range. */
	CHECK(fzn_reasm_plan_want(&f.table, f.alice, 1, 2, got, 8, &n) == FZN_REASM_OK,
	      "a split plan was refused");
	{
		static const uint16_t WANT[] = { 1, 2, 5, 2, 7, 1 };

		CHECK(ranges_are(got, n, WANT, 3), "a bound of 2 did not split the runs: %u",
		      (unsigned)n);
	}

	/* A SHORT ARRAY STOPS AND SAYS HOW FAR IT GOT, rather than
	 * overflowing or reporting a plan it did not write. */
	CHECK(fzn_reasm_plan_want(&f.table, f.alice, 1, 100, got, 1, &n) == FZN_REASM_OK,
	      "a short array was an error");
	CHECK(n == 1 && got[0].first == 1 && got[0].count == 2,
	      "a short array did not stop at the first gap: %u ranges", (unsigned)n);

	/* ZERO IS REFUSED RATHER THAN MEANING UNLIMITED. */
	CHECK(fzn_reasm_plan_want(&f.table, f.alice, 1, 0, got, 8, &n) == FZN_REASM_ERR_MALFORMED,
	      "a zero bound was accepted, so a caller that forgot one got no bound");
}

/*
 * ABSENT IS ITS OWN CODE, because "nothing outstanding" and "I could not
 * look" must not be the same answer to a caller deciding whether to ask a
 * peer for anything.
 */
static void test_a_message_this_table_does_not_hold_is_absent(void)
{
	struct fixture f;
	fzn_reasm_range_t got[8];
	size_t n = 99;
	fzn_partial_t *done = NULL;
	uint8_t piece[8];

	fixture_init(&f, 4);
	offer(&f, f.alice, 1, 0, 8);

	CHECK(fzn_reasm_plan_want(&f.table, f.alice, 2, 100, got, 8, &n) == FZN_REASM_ERR_ABSENT,
	      "a message id nobody sent reported a plan");
	/* SAME ID, DIFFERENT SENDER. Without the sender in the match, bob
	 * would learn which chunks of ALICE's message this host still lacks --
	 * a small leak, and the same splice the accept path refuses. */
	CHECK(fzn_reasm_plan_want(&f.table, f.bob, 1, 100, got, 8, &n) == FZN_REASM_ERR_ABSENT,
	      "another sender's message answered for this id");

	/* AND A COMPLETED MESSAGE IS ABSENT ONCE RELEASED, which is what makes
	 * the code ordinary rather than a fault. */
	fixture_init(&f, 4);
	fill(piece, sizeof(piece), 0x40, 0);
	CHECK(fzn_reasm_accept(&f.table, f.alice, 5, 0, 2, piece, sizeof(piece), 0, 10, &done)
	              == FZN_REASM_OK, "setup");
	fill(piece, sizeof(piece), 0x40, 1);
	CHECK(fzn_reasm_accept(&f.table, f.alice, 5, 1, 2, piece, sizeof(piece), 0, 10, &done)
	              == FZN_REASM_OK, "setup");
	CHECK(done != NULL, "the message did not complete");
	fzn_reasm_release(done);
	CHECK(fzn_reasm_plan_want(&f.table, f.alice, 5, 100, got, 8, &n) == FZN_REASM_ERR_ABSENT,
	      "a released message still reported a plan");

	/*
	 * A FREE SLOT MUST NOT ANSWER, and this is the one shape that can
	 * reach it. `fzn_reasm_release` zeroes a whole slot and
	 * `fzn_reasm_expire` goes through it, so a dead slot's `msg` is 0 and
	 * its sender is all zeroes -- which means the ONLY query that can
	 * match a non-live slot is exactly this one.
	 *
	 * It matters because the failure is fail-open: without the `live`
	 * test the walk finds a slot whose `chunks` is 0, emits no ranges, and
	 * returns OK -- and OK with no ranges reads as "I have everything".
	 * Found by mutation; the released-message case above cannot catch it,
	 * because release had already zeroed the id it queries.
	 */
	{
		struct fixture empty;
		uint8_t nobody[FZN_SENDER_LEN];

		fixture_init(&empty, 4);
		memset(nobody, 0, sizeof(nobody));
		n = 99;
		CHECK(fzn_reasm_plan_want(&empty.table, nobody, 0, 100, got, 8, &n)
		              == FZN_REASM_ERR_ABSENT,
		      "an empty table answered for a zeroed sender and id, so a caller is "
		      "told it has every chunk of a message nobody sent");
	}

	CHECK(fzn_reasm_plan_want(NULL, f.alice, 1, 100, got, 8, &n) == FZN_REASM_ERR_MALFORMED,
	      "a null table was accepted");
	CHECK(fzn_reasm_plan_want(&f.table, NULL, 1, 100, got, 8, &n) == FZN_REASM_ERR_MALFORMED,
	      "a null sender was accepted");
	CHECK(fzn_reasm_plan_want(&f.table, f.alice, 1, 100, NULL, 8, &n)
	              == FZN_REASM_ERR_MALFORMED, "a null output was accepted");
}

static void test_last_chunk_first_is_refused(void)
{
	struct fixture f;
	fzn_partial_t *done = NULL;
	uint8_t piece[3];

	/* The last chunk may be short, so it cannot set the stride. Guessing
	 * would let whoever sends the final piece first choose how much is
	 * held. */
	fixture_init(&f, 2);
	fill(piece, 3, 0x90, 2);
	CHECK(fzn_reasm_accept(&f.table, f.alice, 1, 2, 3, piece, 3, 0, 100, &done) ==
	              FZN_REASM_ERR_MISMATCH,
	      "a last-chunk-first arrival set the stride");
	CHECK(f.slots[0].live == 0, "it took a slot anyway");
}

static void test_release_clears_the_arrived_set(void)
{
	struct fixture f;
	fzn_partial_t *done = NULL;
	uint8_t piece[8];

	/* A stale bit would admit a chunk into the next message using the
	 * slot, which is a splice across messages rather than across senders. */
	fixture_init(&f, 2);
	fill(piece, 8, 0xa0, 0);
	fzn_reasm_accept(&f.table, f.alice, 1, 0, 2, piece, 8, 0, 100, &done);
	fzn_reasm_release(&f.slots[0]);
	CHECK(f.slots[0].live == 0, "release left the slot live");
	CHECK(f.slots[0].arrived == 0, "release left the arrival count");
	CHECK(f.slots[0].buf != NULL, "release dropped the buffer it must keep");

	fzn_reasm_accept(&f.table, f.alice, 2, 1, 2, piece, 8, 0, 100, &done);
	CHECK(done == NULL, "a stale arrived-set completed the next message early");
}

/* A COMPLETED SLOT IS THE CALLER'S UNTIL IT RELEASES IT, which is what
 * reassembly.h promises and what the code did not do.
 *
 * Completion only set `*out`. The slot stayed live with its original expiry,
 * so the next `fzn_reasm_accept` from anybody swept it, released it, and
 * handed the same slot and the same buffer to the next message -- while the
 * first caller still held the pointer. No overrun, so a sanitizer stays
 * quiet: the consumer simply attributes one sender's bytes to another, and
 * neither side gets an error.
 *
 * `sim/test/network_test.c` escapes it only because it releases inside the
 * same call, which is the consumer's discipline rather than the module's
 * guarantee.  */
/* SLOTS ARE RECLAIMED EVEN WHEN EVERY CHUNK IS STALE.
 *
 * The sweep used to sit below the freshness return, so a stale chunk skipped
 * it and a receiver whose traffic was made entirely of stale chunks never
 * handed a slot back. `frame/freshness.c` records the identical defect and
 * fix in near-identical words; the two modules are the same shape and only
 * one had been corrected.  */
/* A CHUNK CLAIMING NO EXPIRY MUST NOT HOLD A SLOT FOR EVER.
 *
 * `expires_at == 0` is legitimate on the wire -- `frame/freshness.h` gives it
 * to a grant, where it means "no expiry" -- and this module used to read it as
 * "never reclaim". Measured before `max_hold`: four partials with a zero
 * expiry, then `fzn_reasm_expire(UINT64_MAX)` dropped NONE of them, and a new
 * sender a century later was refused because every slot was live.
 *
 * The two modules read the same field and disagreed about its sentinel:
 * freshness declines to RECORD a zero-expiry frame so nothing accumulates,
 * and reassembly held one for ever. Only one had noticed it could be zero.  */
/* A COMPLETED SLOT IS HANDED ONCE, NOT ONCE PER RETRANSMISSION.
 *
 * `find` matches on `live`, and a handed slot is still live, so an identical
 * resend of the last chunk -- which this module accepts on purpose, because
 * that is what loss recovery looks like -- used to hand the caller the same
 * slot again. The caller then holds two pointers to one slot and releases
 * twice, which is what the ownership contract asks of it, and the second
 * release lands on a slot another sender has since taken.  */
/* THE OFFSET GUARD FIRES, so it is not dead code.
 *
 * Through the public API with a consistent table it cannot: `admit_first`
 * bounds the stride by `buf_capacity / chunks`. But the table and its slots
 * are caller-owned and this module already treats a hand-built one as inside
 * its threat model. Shrink a slot's capacity below what it already holds and
 * the guard is the thing standing between that and a memcpy.
 *
 * Written because an audit reported the branch as provably unreachable and
 * this file's own doctrine says dead code is not depth. The doctrine is
 * right; it does not reach a branch a corrupt argument takes.  */
static void test_the_offset_guard_is_reachable(void)
{
	struct fixture f;
	fzn_partial_t *done = NULL;
	uint8_t piece[8];

	fixture_init(&f, SLOTS);
	memset(piece, 0x31, sizeof(piece));

	CHECK(fzn_reasm_accept(&f.table, f.alice, 1, 0, 4, piece, sizeof(piece), 0, 100,
	                       &done) == FZN_REASM_OK,
	      "the first chunk was refused");

	/* The control: with the table consistent, the next chunk is fine. */
	CHECK(fzn_reasm_accept(&f.table, f.alice, 1, 1, 4, piece, sizeof(piece), 0, 100,
	                       &done) == FZN_REASM_OK,
	      "a good chunk was refused, so the refusal below proves nothing");

	/* Now a capacity smaller than what the slot already holds. */
	f.slots[0].buf_capacity = 4u;
	CHECK(fzn_reasm_accept(&f.table, f.alice, 1, 2, 4, piece, sizeof(piece), 0, 100,
	                       &done) == FZN_REASM_ERR_TOO_LARGE,
	      "a slot whose capacity shrank below its own contents accepted a write");
}

static void test_a_completed_slot_is_handed_only_once(void)
{
	struct fixture f;
	fzn_partial_t *first = NULL;
	fzn_partial_t *again = NULL;
	fzn_partial_t *theirs = NULL;
	uint8_t piece[8];

	fixture_init(&f, SLOTS);
	memset(piece, 0xaa, sizeof(piece));

	CHECK(fzn_reasm_accept(&f.table, f.alice, 1, 0, 1, piece, sizeof(piece), 0, 100,
	                       &first) == FZN_REASM_OK,
	      "alice's single-chunk message was refused");
	CHECK(first != NULL, "a single-chunk message did not complete");

	/* The identical resend must still be ACCEPTED -- refusing it would
	 * break loss recovery, which is the other half of the rule. */
	CHECK(fzn_reasm_accept(&f.table, f.alice, 1, 0, 1, piece, sizeof(piece), 0, 100,
	                       &again) == FZN_REASM_OK,
	      "a byte-identical resend was refused");
	CHECK(again == NULL, "a resend handed the caller the completed slot a second time");

	/* And the consequence, spelled out: release once, let another sender
	 * take the slot, and the caller must have no second pointer to free. */
	fzn_reasm_release(first);
	memset(piece, 0xbb, sizeof(piece));
	CHECK(fzn_reasm_accept(&f.table, f.bob, 2, 0, 2, piece, sizeof(piece), 0, 200,
	                       &theirs) == FZN_REASM_OK,
	      "the released slot was not reusable");
	CHECK(memcmp(f.slots[0].sender, f.bob, FZN_SENDER_LEN) == 0 || SLOTS > 1,
	      "the slot did not go to the next sender");
}

static void test_a_zero_expiry_is_bounded_by_max_hold(void)
{
	struct fixture f;
	fzn_partial_t *done = NULL;
	uint8_t piece[8];
	size_t i;

	fixture_init(&f, SLOTS);
	memset(piece, 0x22, sizeof(piece));

	for (i = 0; i < SLOTS; i++) {
		uint8_t who[FZN_SENDER_LEN];

		memset(who, (uint8_t)(0x60 + i), sizeof(who));
		CHECK(fzn_reasm_accept(&f.table, who, 1, 0, 2, piece, sizeof(piece), 0, 100,
		                       &done) == FZN_REASM_OK,
		      "a chunk claiming no expiry was refused");
	}

	/* Inside the hold, the slots are still theirs -- the bound must not be
	 * so eager that a legitimate message cannot finish. */
	CHECK(fzn_reasm_expire(&f.table, 100 + (REASM_MAX_HOLD / 2u)) == 0,
	      "a partial was reclaimed while still inside its hold");

	/* Past it, every one goes. */
	CHECK(fzn_reasm_expire(&f.table, 100 + REASM_MAX_HOLD + 1u) == SLOTS,
	      "a chunk claiming no expiry held its slot past max_hold");

	/* And the table is usable again, which is what the reclamation is FOR.
	 * Without this the case above is satisfied by a table that dropped
	 * everything and can no longer take anything either. */
	{
		uint8_t later[FZN_SENDER_LEN];

		memset(later, 0xee, sizeof(later));
		CHECK(fzn_reasm_accept(&f.table, later, 9, 0, 2, piece, sizeof(piece), 0,
		                       100 + REASM_MAX_HOLD + 2u, &done) == FZN_REASM_OK,
		      "a new sender was refused after the holds expired");
	}

	/* THE OTHER HALF: an expiry SOONER than the hold is still honoured, so
	 * the bound is a ceiling rather than a replacement. */
	{
		struct fixture g;
		uint8_t who[FZN_SENDER_LEN];

		fixture_init(&g, SLOTS);
		memset(who, 0x71, sizeof(who));
		CHECK(fzn_reasm_accept(&g.table, who, 1, 0, 2, piece, sizeof(piece), 200, 100,
		                       &done) == FZN_REASM_OK,
		      "a short-expiry chunk was refused");
		CHECK(fzn_reasm_expire(&g.table, 201) == 1,
		       "an expiry sooner than max_hold was not honoured");
	}
}

static void test_stale_traffic_still_reclaims_slots(void)
{
	struct fixture f;
	fzn_partial_t *done = NULL;
	uint8_t piece[8];
	size_t live = 0;
	size_t i;

	fixture_init(&f, SLOTS);
	memset(piece, 0x11, sizeof(piece));

	/* Every slot holding a partial that expires at 200. */
	for (i = 0; i < SLOTS; i++) {
		uint8_t who[FZN_SENDER_LEN];

		memset(who, (uint8_t)(0x30 + i), sizeof(who));
		CHECK(fzn_reasm_accept(&f.table, who, 1, 0, 2, piece, sizeof(piece), 200, 100,
		                       &done) == FZN_REASM_OK,
		      "a partial was refused while filling the table");
	}
	for (i = 0; i < SLOTS; i++)
		live += f.slots[i].live ? 1u : 0u;
	CHECK(live == SLOTS, "the table did not fill, so this proves nothing");

	/* Now nothing but stale chunks, long after those expiries. */
	for (i = 0; i < 50u; i++) {
		uint8_t who[FZN_SENDER_LEN];

		memset(who, 0xee, sizeof(who));
		CHECK(fzn_reasm_accept(&f.table, who, 9, 0, 2, piece, sizeof(piece), 150, 100000,
		                       &done) == FZN_REASM_ERR_EXPIRED,
		      "a stale chunk was not refused");
	}

	live = 0;
	for (i = 0; i < SLOTS; i++)
		live += f.slots[i].live ? 1u : 0u;
	CHECK(live == 0, "stale traffic left expired partials holding every slot");

	/* THE CONTROL. A stale chunk must still not TAKE a slot -- the sweep
	 * reclaims, it does not admit. Without this, "the table emptied" is
	 * satisfied by a module that let the stale sender in. */
	CHECK(fzn_reasm_expire(&f.table, 100000) == 0,
	      "a sweep after the accepts found something left to drop");
	for (i = 0; i < SLOTS; i++)
		CHECK(!f.slots[i].live, "a stale chunk took a slot after all");
}

static void test_a_completed_slot_is_not_taken_from_under_the_caller(void)
{
	struct fixture f;
	fzn_partial_t *mine = NULL;
	fzn_partial_t *theirs = NULL;
	uint8_t piece[8];

	/* One slot, so the next sender must take this one or none. */
	fixture_init(&f, 1);
	f.table.capacity = 1;

	memset(piece, 0xaa, sizeof(piece));
	CHECK(fzn_reasm_accept(&f.table, f.alice, 1, 0, 1, piece, sizeof(piece), 1000, 100,
	                       &mine) == FZN_REASM_OK,
	      "alice's single-chunk message was refused");
	CHECK(mine != NULL, "a single-chunk message did not complete");
	CHECK(mine != NULL && mine->buf[0] == 0xaa, "the completed slot holds the wrong bytes");

	/* Bob arrives long after alice's expiry, and the caller has NOT
	 * released. The slot must not be swept out from under it. */
	memset(piece, 0xbb, sizeof(piece));
	CHECK(fzn_reasm_accept(&f.table, f.bob, 2, 0, 1, piece, sizeof(piece), 5000, 2000,
	                       &theirs) != FZN_REASM_OK,
	      "a second sender took the slot a caller was still holding");
	CHECK(mine != NULL && mine->buf[0] == 0xaa,
	      "the held slot's bytes were overwritten by another sender");
	CHECK(mine != NULL && memcmp(mine->sender, f.alice, FZN_SENDER_LEN) == 0,
	      "the held slot now names another sender");

	/* An explicit sweep must not take it either -- that is the same
	 * promise through the other door. */
	CHECK(fzn_reasm_expire(&f.table, 100000) == 0,
	      "a sweep reclaimed a slot the caller still holds");
	CHECK(mine != NULL && mine->buf[0] == 0xaa, "the sweep overwrote a held slot");

	/* THE POSITIVE CONTROL. Releasing must free it, or the fix is a leak
	 * rather than a guarantee and every case above is satisfied by a slot
	 * that can never be reused at all. */
	fzn_reasm_release(mine);
	theirs = NULL;
	CHECK(fzn_reasm_accept(&f.table, f.bob, 2, 0, 1, piece, sizeof(piece), 5000, 2000,
	                       &theirs) == FZN_REASM_OK,
	      "the slot was not reusable after release");
	CHECK(theirs != NULL && theirs->buf[0] == 0xbb, "the reused slot holds the wrong bytes");
}

static void test_a_reused_slot_starts_empty(void)
{
	struct fixture f;
	fzn_partial_t *done = NULL;
	uint8_t piece[8];

	/* A slot whose storage was reused without going through release must
	 * not carry arrival bits into the next message -- that is a splice
	 * across MESSAGES, and it would let a chunk nobody sent count towards
	 * completion.
	 *
	 * Constructed directly, because normal operation cannot reach it:
	 * release clears the set, so the clearing in admit_first is defence
	 * in depth and was untested until this existed. A sabotage run
	 * removing that memset passed the whole suite, which is how the gap
	 * was found. A partial is a value, so a test can simply build the
	 * state rather than manoeuvre into it. */
	fixture_init(&f, 2);
	memset(f.slots[0].seen, 0xff, sizeof(f.slots[0].seen));
	f.slots[0].arrived = 5;
	f.slots[0].live = 0;

	fill(piece, 8, 0xc0, 0);
	CHECK(fzn_reasm_accept(&f.table, f.alice, 1, 0, 2, piece, 8, 0, 100, &done) ==
	              FZN_REASM_OK,
	      "a first chunk into a dirty slot was refused");
	CHECK(done == NULL, "a stale arrived-set completed a message on its first chunk");
	CHECK(f.slots[0].arrived == 1, "arrived %u, wanted 1", f.slots[0].arrived);
}

static void test_bad_arguments(void)
{
	struct fixture f;
	fzn_partial_t *done = NULL;
	uint8_t piece[8];
	fzn_reasm_t t;

	fixture_init(&f, 2);
	CHECK(fzn_reasm_init(&t, f.slots, SLOTS, 0, REASM_MAX_HOLD) == FZN_REASM_ERR_MALFORMED,
	      "per_sender_max of 0 was accepted, and would mean unlimited");
	CHECK(fzn_reasm_init(&t, f.slots, 0, 1, REASM_MAX_HOLD) == FZN_REASM_ERR_MALFORMED,
	      "a zero-capacity table was accepted");
	CHECK(fzn_reasm_slot_init(&f.slots[0], NULL, 8) == FZN_REASM_ERR_MALFORMED,
	      "a slot with no buffer was accepted");
	CHECK(fzn_reasm_accept(&f.table, f.alice, 1, 0, 2, NULL, 8, 0, 100, &done) ==
	              FZN_REASM_ERR_MALFORMED,
	      "a null payload was accepted");
	CHECK(fzn_reasm_accept(&f.table, f.alice, 1, 0, 0, piece, 8, 0, 100, &done) ==
	              FZN_REASM_ERR_TOO_LARGE,
	      "a message claiming zero chunks was accepted");
	CHECK(fzn_reasm_expire(NULL, 1) == 0, "expire on a null table did not return 0");
}

/* The positive control: nearly every case above asserts a refusal, and an
 * accept that refused everything would satisfy them. */
/* The multiplication in admit_first, which used to wrap.
 *
 * `payload_len` is a size_t the caller supplies, and the sizing was
 * `payload_len * chunks` compared against the buffer. 2^62 with four chunks
 * is exactly 2^64, which is zero, so the comparison passed and the slot went
 * live claiming a stride of 2^62. Nothing downstream of that was tested: the
 * offset guard in fzn_reasm_accept was the only thing that refused the copy,
 * and it had never fired in any test or in 20000 fuzz cases.
 *
 * The claim checked here is not just "refused" -- both the old code and the
 * new one return TOO_LARGE. It is that the slot is NOT TAKEN, which is what
 * separates admit_first refusing from the guard behind it catching up. */
static void test_a_wrapping_size_is_refused_before_a_slot_is_taken(void)
{
	fzn_partial_t slot;
	uint8_t storage[256];
	fzn_reasm_t table;
	fzn_partial_t *done = NULL;
	uint8_t sender[FZN_SENDER_LEN];
	uint8_t payload[8];
	/* DERIVED FROM SIZE_MAX, NOT HARD-CODED, and that is the whole point of
	 * the line. This was `(size_t)1 << 62`, which is 2^62 on a 64-bit host
	 * and undefined on a 32-bit one -- where it evaluates to 0, the premise
	 * check below passes because 0 * 4 is 0, and `fzn_reasm_accept` then
	 * refuses a zero-length payload for being zero rather than for
	 * wrapping. The test passed and measured nothing, on the platform class
	 * sec 7 aims at: routers and phones.
	 *
	 * `SIZE_MAX / 4 + 1` times four is SIZE_MAX + 1, which is zero at any
	 * width. 2^62 on this host, 2^30 on a 32-bit one, and a real value on
	 * both. */
	size_t huge = (SIZE_MAX / 4u) + 1u;

	memset(sender, 0xa1, sizeof(sender));
	memset(payload, 0x5a, sizeof(payload));
	fzn_reasm_slot_init(&slot, storage, sizeof(storage));
	fzn_reasm_init(&table, &slot, 1, 1, REASM_MAX_HOLD);

	CHECK(huge != 0 && huge * 4u == 0,
	      "the premise is wrong on this platform: the stride must be non-zero and "
	      "must wrap to zero when multiplied by the chunk count");
	CHECK(fzn_reasm_accept(&table, sender, 7, 0, 4, payload, huge, 0, 100, &done) ==
	              FZN_REASM_ERR_TOO_LARGE,
	      "a stride whose total wraps to zero was accepted");
	CHECK(slot.live == 0,
	      "the slot was taken by a claim that wrapped, so admit_first was defeated "
	      "and only the offset guard refused the copy");
}

/* The offset guard itself, which nothing could reach.
 *
 * WHY THIS TEST MANUFACTURES ITS STATE. With the sizing above fixed,
 * admit_first guarantees chunks * chunk_size <= buf_capacity, and every later
 * chunk must match that stride -- so offset + payload_len can no longer exceed
 * the buffer and the guard is unreachable through the public API. That is the
 * correct outcome and it leaves the guard as defence in depth with no way to
 * exercise it from outside.
 *
 * So the state it exists to catch is built by hand: a live slot whose
 * chunk_size was made inconsistent with its capacity. That is white-box and
 * deliberately so. The alternative is a guard nothing has ever run, which is
 * what this file just finished being bitten by.
 *
 * Both halves of the condition are covered, because they fail differently: an
 * offset past the end of the buffer, and an offset inside it with a length
 * that runs past. A test of only the first would leave the arithmetic that
 * cannot underflow -- `buf_capacity - offset` -- unchecked. */
static void test_the_offset_guard_refuses_a_slot_that_cannot_hold_the_chunk(void)
{
	fzn_partial_t slot;
	uint8_t storage[64];
	fzn_reasm_t table;
	fzn_partial_t *done = NULL;
	uint8_t sender[FZN_SENDER_LEN];
	uint8_t payload[64];

	memset(sender, 0xa1, sizeof(sender));
	memset(payload, 0x5a, sizeof(payload));

	/* A legitimate first chunk: 4 pieces of 8 into 64 bytes. */
	fzn_reasm_slot_init(&slot, storage, sizeof(storage));
	fzn_reasm_init(&table, &slot, 1, 1, REASM_MAX_HOLD);
	CHECK(fzn_reasm_accept(&table, sender, 7, 0, 4, payload, 8, 0, 100, &done) ==
	              FZN_REASM_OK,
	      "the setup chunk was refused");

	/* Offset past the end: stride 100 puts piece 1 at 100 in a 64-byte
	 * buffer. */
	slot.chunk_size = 100;
	CHECK(fzn_reasm_accept(&table, sender, 7, 1, 4, payload, 100, 0, 100, &done) ==
	              FZN_REASM_ERR_TOO_LARGE,
	      "a chunk whose offset lies past the buffer was accepted");

	/* Offset inside, length running past: piece 1 starts at 40 and is 40
	 * long, so it ends at 80 in a 64-byte buffer. This is the half that
	 * `buf_capacity - offset` exists for. */
	slot.chunk_size = 40;
	CHECK(fzn_reasm_accept(&table, sender, 7, 1, 4, payload, 40, 0, 100, &done) ==
	              FZN_REASM_ERR_TOO_LARGE,
	      "a chunk starting inside the buffer and ending past it was accepted");

	/* And the guard does not refuse what fits: piece 1 at 8, 8 long. */
	slot.chunk_size = 8;
	CHECK(fzn_reasm_accept(&table, sender, 7, 1, 4, payload, 8, 0, 100, &done) ==
	              FZN_REASM_OK,
	      "the guard refused a chunk that fits, so it is not discriminating");
}

/* Every guard of every entry point, one argument at a time, plus the two
 * terms that describe a value rather than a pointer. See chain_test.c's
 * equivalent for why the dull version earns its place.
 *
 * `payload_len == 0` on a LAST chunk is the interesting one here. It is not a
 * null check and it is not the same as the zero-length check in the sizing
 * path: a last chunk may legitimately be shorter than the stride, so the
 * refusal of an empty one is a separate branch, and it had never been taken.
 * An empty final piece would complete a message a byte short of what its
 * sender sent. */
static void test_every_guard_refuses_its_own_argument(void)
{
	fzn_partial_t slot, slots[2];
	uint8_t storage[256], storage2[2][256];
	fzn_reasm_t table;
	fzn_partial_t *done = NULL;
	uint8_t sender[FZN_SENDER_LEN];
	uint8_t payload[8];

	memset(sender, 0xa1, sizeof(sender));
	memset(payload, 0x5a, sizeof(payload));

	CHECK(fzn_reasm_slot_init(NULL, storage, sizeof(storage)) == FZN_REASM_ERR_MALFORMED,
	      "a null slot was initialised");
	CHECK(fzn_reasm_slot_init(&slot, NULL, sizeof(storage)) == FZN_REASM_ERR_MALFORMED,
	      "a slot with no buffer was initialised");
	CHECK(fzn_reasm_slot_init(&slot, storage, 0) == FZN_REASM_ERR_MALFORMED,
	      "a slot with a zero-length buffer was initialised");

	fzn_reasm_slot_init(&slot, storage, sizeof(storage));
	CHECK(fzn_reasm_init(NULL, &slot, 1, 1, REASM_MAX_HOLD) == FZN_REASM_ERR_MALFORMED, "a null table");
	CHECK(fzn_reasm_init(&table, NULL, 1, 1, REASM_MAX_HOLD) == FZN_REASM_ERR_MALFORMED, "null slots");
	CHECK(fzn_reasm_init(&table, &slot, 0, 1, REASM_MAX_HOLD) == FZN_REASM_ERR_MALFORMED, "zero capacity");
	CHECK(fzn_reasm_init(&table, &slot, 1, 0, REASM_MAX_HOLD) == FZN_REASM_ERR_MALFORMED, "a zero quota");

	/* A table whose slots were never given buffers. Each half of that
	 * check separately, since a slot with a pointer and no capacity is a
	 * different mistake from one with neither. */
	for (size_t i = 0; i < 2; i++)
		fzn_reasm_slot_init(&slots[i], storage2[i], sizeof(storage2[i]));
	slots[1].buf = NULL;
	CHECK(fzn_reasm_init(&table, slots, 2, 1, REASM_MAX_HOLD) == FZN_REASM_ERR_MALFORMED,
	      "a table holding a slot with no buffer");
	fzn_reasm_slot_init(&slots[1], storage2[1], sizeof(storage2[1]));
	slots[1].buf_capacity = 0;
	CHECK(fzn_reasm_init(&table, slots, 2, 1, REASM_MAX_HOLD) == FZN_REASM_ERR_MALFORMED,
	      "a table holding a slot of zero capacity");

	/* release and expire */
	fzn_reasm_release(NULL); /* must simply return */
	CHECK(1, "releasing a null slot did not crash");
	CHECK(fzn_reasm_expire(NULL, 100) == 0, "a null table was expired");
	{
		fzn_reasm_t no_slots;

		for (size_t i = 0; i < 2; i++)
			fzn_reasm_slot_init(&slots[i], storage2[i], sizeof(storage2[i]));
		fzn_reasm_init(&no_slots, slots, 2, 1, REASM_MAX_HOLD);
		no_slots.slots = NULL;
		CHECK(fzn_reasm_expire(&no_slots, 100) == 0, "a table with no slots was expired");
		CHECK(fzn_reasm_accept(&no_slots, sender, 7, 0, 1, payload, 8, 0, 100, &done) ==
		              FZN_REASM_ERR_MALFORMED,
		      "a table with no slots accepted a chunk");
	}

	/* accept */
	fzn_reasm_slot_init(&slot, storage, sizeof(storage));
	fzn_reasm_init(&table, &slot, 1, 1, REASM_MAX_HOLD);
	CHECK(fzn_reasm_accept(NULL, sender, 7, 0, 1, payload, 8, 0, 100, &done) ==
	              FZN_REASM_ERR_MALFORMED,
	      "a null table accepted a chunk");
	CHECK(fzn_reasm_accept(&table, NULL, 7, 0, 1, payload, 8, 0, 100, &done) ==
	              FZN_REASM_ERR_MALFORMED,
	      "a null sender was accepted");
	CHECK(fzn_reasm_accept(&table, sender, 7, 0, 1, NULL, 8, 0, 100, &done) ==
	              FZN_REASM_ERR_MALFORMED,
	      "a null payload was accepted");
	CHECK(fzn_reasm_accept(&table, sender, 7, 0, 1, payload, 8, 0, 100, NULL) ==
	              FZN_REASM_ERR_MALFORMED,
	      "a null out was accepted");

	/* An EMPTY LAST CHUNK, which is not a null check and not the sizing
	 * path's zero-length refusal. Two pieces of eight, then a final piece
	 * of nothing. */
	fzn_reasm_slot_init(&slot, storage, sizeof(storage));
	fzn_reasm_init(&table, &slot, 1, 1, REASM_MAX_HOLD);
	CHECK(fzn_reasm_accept(&table, sender, 7, 0, 2, payload, 8, 0, 100, &done) ==
	              FZN_REASM_OK,
	      "the setup chunk was refused");
	CHECK(fzn_reasm_accept(&table, sender, 7, 1, 2, payload, 0, 0, 100, &done) ==
	              FZN_REASM_ERR_MISMATCH,
	      "an empty last chunk was accepted, completing the message short");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	struct fixture f;
	fzn_partial_t *done = NULL;
	uint8_t piece[8];

	fixture_init(&f, 2);
	fill(piece, 8, 0xb0, 0);
	CHECK(fzn_reasm_accept(&f.table, f.alice, 1, 0, 1, piece, 8, 0, 100, &done) ==
	              FZN_REASM_OK,
	      "the positive control fails, so every refusal above proves nothing");
	CHECK(done != NULL, "a single-chunk message did not complete immediately");
}

int main(void)
{
	test_reassembles_in_order();
	test_reassembles_out_of_order();
	test_a_short_last_chunk_is_allowed();
	test_the_bound_is_enforced_on_the_first_chunk();
	test_the_chunk_ceiling_is_what_refuses_a_large_count();
	test_later_chunks_must_agree();
	test_a_refusal_clears_the_completion_pointer();
	test_two_senders_do_not_splice();
	test_the_twin_fixture_is_what_it_claims();
	test_two_near_senders_do_not_splice();
	test_a_near_sender_does_not_spend_the_quota();
	test_retransmission_versus_rewrite();
	test_quota_stops_one_sender_filling_the_table();
	test_full_table_and_expiry();
	test_a_receiver_can_name_what_it_lacks();
	test_a_message_this_table_does_not_hold_is_absent();
	test_last_chunk_first_is_refused();
	test_release_clears_the_arrived_set();
	test_the_offset_guard_is_reachable();
	test_a_completed_slot_is_handed_only_once();
	test_a_zero_expiry_is_bounded_by_max_hold();
	test_stale_traffic_still_reclaims_slots();
	test_a_completed_slot_is_not_taken_from_under_the_caller();
	test_a_reused_slot_starts_empty();
	test_bad_arguments();
	test_a_wrapping_size_is_refused_before_a_slot_is_taken();
	test_the_offset_guard_refuses_a_slot_that_cannot_hold_the_chunk();
	test_every_guard_refuses_its_own_argument();
	test_the_suite_can_tell_pass_from_fail();

	printf("reassembly_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
