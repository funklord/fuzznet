/* A fuzz harness for the reassembly path, with canaries.
 *
 * project.md sec 4.1 makes fuzzability a design property rather than an
 * afterthought -- "reader/writer primitives over caller-owned buffers, no
 * I/O, so they are fuzzable directly with no daemon or socket in the loop"
 * -- and sec 4.4 calls reassembly the largest and riskiest piece. Every
 * field it takes comes off the wire: `chunks`, `index`, `payload_len` and
 * the sender are all a stranger's to choose.
 *
 * WHAT IT CHECKS IS THE POINT. A harness that only watches for a crash
 * finds the bugs a crash announces, which on a plain -Os build without a
 * sanitiser is a small fraction of them: a two-byte overrun into a
 * neighbouring slot corrupts somebody else's message and returns success.
 * So each slot's buffer sits inside a canary and every invariant the
 * headers claim is asserted after every single call:
 *
 *   - nothing was written outside a slot's buffer;
 *   - the table never holds more than its capacity;
 *   - no sender holds more than its quota;
 *   - a slot never reports more bytes than its buffer can hold, nor more
 *     arrived pieces than it claims chunks.
 *
 * TERMINATION, because it runs unattended. `main` performs a fixed number
 * of cases -- argv[1] or FUZZ_DEFAULT_CASES -- from a seeded generator with
 * no entropy in it, so the run is bounded, reproducible from the source
 * alone, and prints the failing case's seed when it finds one. There is no
 * loop here that a slow machine makes longer. It allocates nothing, opens
 * nothing and spawns nothing.
 *
 * It also compiles as a libFuzzer target: fuzz_one is the entry point and
 * LLVMFuzzerTestOneInput forwards to it under -DFZN_LIBFUZZER, so a longer
 * campaign with coverage feedback needs no second harness to drift from
 * this one.
 */

#include "../reassembly.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 20000u

#define SLOTS 3
#define SLOT_BYTES 64
#define CANARY 16
#define CANARY_BYTE 0x7e

/* Storage laid out as canary | buffer | canary, so an overrun in either
 * direction lands somewhere that is checked rather than somewhere that
 * happens to belong to the next slot.
 *
 * A SANITIZER DOES NOT MAKE THIS REDUNDANT, which is worth saying because
 * it looks as though it should. AddressSanitizer brackets OBJECTS, and this
 * arena is one object: a write from a slot into its neighbour's canary is
 * in bounds as far as ASan is concerned, and it says nothing. Measured
 * rather than assumed -- removing two bounds checks in reassembly.c
 * produces an overrun that this canary catches and that `make test
 * SANITIZE=1` does not. The two cover different classes and neither
 * replaces the other: ASan sees reads of what nothing wrote and use after
 * free, the canary sees writes that stay inside the harness's own
 * allocation. */
struct arena {
	uint8_t block[SLOTS][CANARY + SLOT_BYTES + CANARY];
};

static void arena_init(struct arena *a)
{
	memset(a->block, CANARY_BYTE, sizeof(a->block));
}

static uint8_t *slot_buf(struct arena *a, size_t i)
{
	return &a->block[i][CANARY];
}

static int canaries_intact(const struct arena *a)
{
	for (size_t i = 0; i < SLOTS; i++) {
		for (size_t k = 0; k < CANARY; k++) {
			if (a->block[i][k] != CANARY_BYTE)
				return 0;
			if (a->block[i][CANARY + SLOT_BYTES + k] != CANARY_BYTE)
				return 0;
		}
	}
	return 1;
}

/* Everything the headers promise, asserted after every call. Returns the
 * name of the first broken invariant, or NULL. */
static const char *invariants(const struct arena *a, const fzn_reasm_t *table)
{
	size_t live = 0;

	if (!canaries_intact(a))
		return "a write landed outside a slot buffer";

	for (size_t i = 0; i < table->capacity; i++) {
		const fzn_partial_t *slot = &table->slots[i];

		if (!slot->live)
			continue;
		live++;

		if (slot->bytes > slot->buf_capacity)
			return "a slot reports more bytes than its buffer holds";
		if (slot->chunks == 0)
			return "a live slot claims zero chunks";
		if (slot->arrived > slot->chunks)
			return "more pieces arrived than the message claims";
		if (slot->chunk_size == 0)
			return "a live slot has a zero stride";
		if (slot->chunk_size * slot->chunks > slot->buf_capacity)
			return "a slot was sized past its buffer";
	}

	if (live > table->capacity)
		return "more slots are live than the table has";

	/* The quota, recomputed rather than trusted. */
	for (size_t i = 0; i < table->capacity; i++) {
		const fzn_partial_t *slot = &table->slots[i];
		size_t n = 0;

		if (!slot->live)
			continue;
		for (size_t k = 0; k < table->capacity; k++) {
			if (table->slots[k].live &&
			    memcmp(table->slots[k].sender, slot->sender, FZN_SENDER_LEN) == 0)
				n++;
		}
		if (n > table->per_sender_max)
			return "a sender holds more slots than its quota";
	}

	return NULL;
}

/* How much of the module a run actually reached. Counted rather than
 * assumed, because the first version of this harness reached almost none of
 * it and said "no invariant broken" exactly as loudly.
 *
 * Random bytes make `chunks` a uniform uint16, which is past
 * FZN_REASM_MAX_CHUNKS in 99.6% of draws, so nearly every offer was refused
 * before a slot was taken. Three of four planted bugs survived 200000
 * cases. situ/suggestions/fuzznet.md names this exact shape -- "a fuzzer
 * rediscovers the correlation by luck or never reaches the interesting code
 * at all", the same problem as a negative result with no positive control.
 *
 * So the generator is biased towards values that get past the front door,
 * and `main` REFUSES TO REPORT SUCCESS if a run completed no messages. A
 * harness that cannot say what it reached is one nobody can trust. */
struct coverage {
	unsigned long admitted;  /* offers the module accepted */
	unsigned long completed; /* messages fully reassembled */
};

/* One case. `data` is read as a sequence of chunk offers; anything it does
 * not supply is simply the end of the case, so a short input is a short
 * sequence rather than a rejected one. Returns 0, or prints and returns 1
 * when an invariant broke. */
static int fuzz_one(const uint8_t *data, size_t len, struct coverage *cov)
{
	struct arena arena;
	fzn_partial_t slots[SLOTS];
	fzn_reasm_t table;
	fzn_partial_t *done = NULL;
	static uint8_t payload[512];
	size_t pos = 0;

	arena_init(&arena);
	for (size_t i = 0; i < SLOTS; i++) {
		if (fzn_reasm_slot_init(&slots[i], slot_buf(&arena, i), SLOT_BYTES) !=
		    FZN_REASM_OK)
			return 0;
	}
	if (fzn_reasm_init(&table, slots, SLOTS, 2) != FZN_REASM_OK)
		return 0;

	while (pos + 8 <= len) {
		uint8_t sender[FZN_SENDER_LEN];
		uint32_t msg;
		uint16_t index, chunks;
		size_t plen;
		const char *broke;

		/* BIASED ON PURPOSE, and the bias is the difference between a
		 * harness that reaches the module and one that only reaches its
		 * first refusal. A low bit of the mode byte picks between a
		 * plausible value and a wild one, so the wild cases -- which are
		 * what a hostile sender actually sends -- still occur, they just
		 * stop being the only thing that occurs.
		 *
		 * The sender and message come from small sets so that offers
		 * ACCUMULATE into the same partial message. With a random sender
		 * per offer, a second chunk of anything essentially never
		 * arrives, and every path past the first admission is dead. */
		uint8_t mode = data[pos];

		memset(sender, data[pos + 1] & 0x03u, FZN_SENDER_LEN);
		msg = data[pos + 2] & 0x03u;

		chunks = (mode & 1u) ? (uint16_t)(1u + (data[pos + 4] & 0x07u))
		                     : (uint16_t)((data[pos + 4] << 8) | data[pos + 5]);
		index = (mode & 2u) ? (uint16_t)(data[pos + 3] % (chunks ? chunks : 1u))
		                    : (uint16_t)((data[pos + 2] << 8) | data[pos + 3]);
		plen = (mode & 4u) ? (size_t)(data[pos + 6] & 0x1fu)
		                   : ((size_t)data[pos + 6] << 8 | data[pos + 7]) %
		                             (sizeof(payload) + 1u);
		pos += 8;

		if (plen > len - pos)
			plen = len - pos;
		if (plen > 0)
			memcpy(payload, data + pos, plen);
		pos += plen;

		if (fzn_reasm_accept(&table, sender, msg, index, chunks, payload, plen, 0, 100,
		                     &done) == FZN_REASM_OK)
			cov->admitted++;

		broke = invariants(&arena, &table);
		if (broke) {
			printf("  INVARIANT: %s\n", broke);
			printf("    at offset %zu: index=%u chunks=%u len=%zu\n", pos, index,
			       chunks, plen);
			return 1;
		}

		if (done) {
			cov->completed++;
			fzn_reasm_release(done);
			done = NULL;
			if (invariants(&arena, &table)) {
				printf("  INVARIANT: broken by release\n");
				return 1;
			}
		}
	}

	return 0;
}

#ifdef FZN_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct coverage cov = { 0, 0 };

	(void)fuzz_one(data, size, &cov);
	return 0;
}
#else

/* A seeded generator, so a run is reproducible from the source alone. Not
 * a good PRNG and not meant to be -- what it has to be is the SAME one
 * every time, on every machine, so that a case that fails here fails for
 * whoever reads the report. */
static uint32_t next(uint32_t *state)
{
	*state = (*state * 1103515245u) + 12345u;
	return (*state >> 16) & 0xffffu;
}

int main(int argc, char **argv)
{
	unsigned long cases = FUZZ_DEFAULT_CASES;
	struct coverage cov = { 0, 0 };
	uint8_t buf[256];

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}

	for (unsigned long c = 0; c < cases; c++) {
		uint32_t state = (uint32_t)c + 1u;
		size_t len = (size_t)(next(&state) % (sizeof(buf) + 1u));

		for (size_t i = 0; i < len; i++)
			buf[i] = (uint8_t)next(&state);

		if (fuzz_one(buf, len, &cov)) {
			printf("reassembly_fuzz: FAILED on case %lu (seed %lu)\n", c, c + 1u);
			return 1;
		}
	}

	/* The harness's own positive control, and the threshold is not zero.
	 *
	 * "More than nothing" was the first version and it is not the
	 * question: disabling the generator's bias produced 2 admissions and 1
	 * completion in 20000 cases, which is reaching nothing in every sense
	 * that matters, and it passed. A floor proportional to the run is what
	 * distinguishes a generator that works from one that got lucky twice.
	 *
	 * A half percent is far below what a working generator produces -- the
	 * biased one completes around 4.5% -- and far above what a broken one
	 * manages. It is a smoke alarm rather than a measurement, and it is
	 * deliberately loose so that tightening the module's refusals does not
	 * start failing the harness. */
	if (cov.completed < cases / 200u || cov.admitted == 0) {
		printf("reassembly_fuzz: REACHED NOTHING -- %lu admitted, %lu completed "
		       "in %lu cases. The generator is not producing inputs the module "
		       "accepts, so this run proves nothing.\n",
		       cov.admitted, cov.completed, cases);
		return 1;
	}

	printf("reassembly_fuzz: %lu cases, %lu admitted, %lu completed, "
	       "no invariant broken\n",
	       cases, cov.admitted, cov.completed);
	return 0;
}
#endif
