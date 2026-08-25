/* Tests for chunk/reassembly.c. Deterministic: `now` is a parameter and
 * every buffer is caller-owned, so a state is constructed rather than
 * arrived at. */

#include "../reassembly.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

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
	printf("  FAIL reassembly_test.c:%d: ", line);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
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
	fzn_reasm_init(&f->table, f->slots, SLOTS, per_sender_max);
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

	/* And a claim beyond the compile-time ceiling never reaches sizing. */
	fixture_init(&f, 2);
	CHECK(fzn_reasm_accept(&f.table, f.alice, 1, 0, (uint16_t)(FZN_REASM_MAX_CHUNKS + 1),
	                       piece, 8, 0, 100, &done) == FZN_REASM_ERR_TOO_LARGE,
	      "a chunk count past FZN_REASM_MAX_CHUNKS was admitted");
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

static void test_retransmission_versus_rewrite(void)
{
	struct fixture f;
	fzn_partial_t *done = NULL;
	uint8_t piece[8], other[8];

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
	CHECK(fzn_reasm_init(&t, f.slots, SLOTS, 0) == FZN_REASM_ERR_MALFORMED,
	      "per_sender_max of 0 was accepted, and would mean unlimited");
	CHECK(fzn_reasm_init(&t, f.slots, 0, 1) == FZN_REASM_ERR_MALFORMED,
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
	fzn_reasm_init(&table, &slot, 1, 1);

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
	fzn_reasm_init(&table, &slot, 1, 1);
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
	CHECK(fzn_reasm_init(NULL, &slot, 1, 1) == FZN_REASM_ERR_MALFORMED, "a null table");
	CHECK(fzn_reasm_init(&table, NULL, 1, 1) == FZN_REASM_ERR_MALFORMED, "null slots");
	CHECK(fzn_reasm_init(&table, &slot, 0, 1) == FZN_REASM_ERR_MALFORMED, "zero capacity");
	CHECK(fzn_reasm_init(&table, &slot, 1, 0) == FZN_REASM_ERR_MALFORMED, "a zero quota");

	/* A table whose slots were never given buffers. Each half of that
	 * check separately, since a slot with a pointer and no capacity is a
	 * different mistake from one with neither. */
	for (size_t i = 0; i < 2; i++)
		fzn_reasm_slot_init(&slots[i], storage2[i], sizeof(storage2[i]));
	slots[1].buf = NULL;
	CHECK(fzn_reasm_init(&table, slots, 2, 1) == FZN_REASM_ERR_MALFORMED,
	      "a table holding a slot with no buffer");
	fzn_reasm_slot_init(&slots[1], storage2[1], sizeof(storage2[1]));
	slots[1].buf_capacity = 0;
	CHECK(fzn_reasm_init(&table, slots, 2, 1) == FZN_REASM_ERR_MALFORMED,
	      "a table holding a slot of zero capacity");

	/* release and expire */
	fzn_reasm_release(NULL); /* must simply return */
	CHECK(1, "releasing a null slot did not crash");
	CHECK(fzn_reasm_expire(NULL, 100) == 0, "a null table was expired");
	{
		fzn_reasm_t no_slots;

		for (size_t i = 0; i < 2; i++)
			fzn_reasm_slot_init(&slots[i], storage2[i], sizeof(storage2[i]));
		fzn_reasm_init(&no_slots, slots, 2, 1);
		no_slots.slots = NULL;
		CHECK(fzn_reasm_expire(&no_slots, 100) == 0, "a table with no slots was expired");
		CHECK(fzn_reasm_accept(&no_slots, sender, 7, 0, 1, payload, 8, 0, 100, &done) ==
		              FZN_REASM_ERR_MALFORMED,
		      "a table with no slots accepted a chunk");
	}

	/* accept */
	fzn_reasm_slot_init(&slot, storage, sizeof(storage));
	fzn_reasm_init(&table, &slot, 1, 1);
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
	fzn_reasm_init(&table, &slot, 1, 1);
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
	test_later_chunks_must_agree();
	test_two_senders_do_not_splice();
	test_retransmission_versus_rewrite();
	test_quota_stops_one_sender_filling_the_table();
	test_full_table_and_expiry();
	test_last_chunk_first_is_refused();
	test_release_clears_the_arrived_set();
	test_a_reused_slot_starts_empty();
	test_bad_arguments();
	test_a_wrapping_size_is_refused_before_a_slot_is_taken();
	test_the_offset_guard_refuses_a_slot_that_cannot_hold_the_chunk();
	test_every_guard_refuses_its_own_argument();
	test_the_suite_can_tell_pass_from_fail();

	printf("reassembly_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
