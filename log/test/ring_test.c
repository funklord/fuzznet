/* ring_test -- the flight recorder: order, eviction of whole records, the
 * dump a crash handler writes, and reading a dump back. sec 457. */

#include "../ring.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL ring_test.c:%d: %s\n", __LINE__, what);        \
		}                                                                              \
	} while (0)

static fzn_ring_t ring, again;
static uint8_t text[FZN_ENTRY_TEXT_MAX];
static uint8_t dump[FZN_RING_BYTES];

static fzn_entry_t entry(uint64_t position, size_t text_len)
{
	fzn_entry_t e;

	memset(&e, 0, sizeof(e));
	memset(e.name.machine, 0x5a, sizeof(e.name.machine));
	strcpy(e.name.user, "root");
	strcpy(e.name.program, "netcfgd");
	e.name.pid = 812u;
	e.name.start_ms = 1727778001000u;
	e.name.position = position;
	e.time_us = 1790944496000000u + position;
	e.level = position % 2u ? FZN_ENTRY_DEBUG : FZN_ENTRY_INFO;
	strcpy(e.subsystem, "apply/exec");
	memset(text, (int)('a' + (position % 26u)), text_len);
	e.text = text;
	e.text_len = text_len;
	return e;
}

/* What a walk saw: the positions in order, and whether each text was the
 * one put. */
static uint64_t seen[4096];
static size_t n_seen;
static int texts_ok;

static void note(void *ctx, const fzn_entry_t *e)
{
	size_t i;

	(void)ctx;
	if (n_seen < 4096u)
		seen[n_seen++] = e->name.position;
	for (i = 0; i < e->text_len; i++)
		if (e->text[i] != (uint8_t)('a' + (e->name.position % 26u)))
			texts_ok = 0;
}

static size_t walk(const fzn_ring_t *r)
{
	n_seen = 0;
	texts_ok = 1;
	return fzn_ring_walk(r, note, NULL);
}

/* Positions `first` .. `first + n - 1`, in order. */
static int consecutive(uint64_t first, size_t n)
{
	size_t i;

	if (n_seen != n)
		return 0;
	for (i = 0; i < n; i++)
		if (seen[i] != first + i)
			return 0;
	return 1;
}

/* The two spans written one after the other, as a crash handler would. */
static size_t dumped(const fzn_ring_t *r)
{
	const uint8_t *a, *b;
	size_t al = 0, bl = 0;

	fzn_ring_spans(r, &a, &al, &b, &bl);
	memcpy(dump, a, al);
	memcpy(dump + al, b, bl);
	return al + bl;
}

int main(void)
{
	fzn_entry_t e;
	const uint8_t *a, *b;
	size_t al = 0, bl = 0, i, len, put = 0;

	fzn_ring_init(&ring);
	CHECK(walk(&ring) == 0u && dumped(&ring) == 0u, "an empty ring walks nothing and dumps nothing");

	for (i = 0; i < 3u; i++) {
		e = entry(i, 10u);
		CHECK(fzn_ring_put(&ring, &e) == FZN_RING_OK, "an entry is kept");
	}
	CHECK(walk(&ring) == 3u && consecutive(0u, 3u) && texts_ok && ring.evicted == 0u,
	      "three entries walk back in order, each with its text");
	e = entry(99u, 10u);
	strcpy(e.subsystem, "bad//path");
	CHECK(fzn_ring_put(&ring, &e) == FZN_RING_ERR_MALFORMED && ring.held == 3u,
	      "an entry the line would refuse is refused, and nothing is evicted for it");

	/* PAST ITS SIZE, the oldest whole records go, and what is left is the
	 * newest, in order. */
	fzn_ring_init(&ring);
	for (i = 0; i < 300u; i++) {
		e = entry(i, 1000u + (i * 13u) % 3000u);
		if (fzn_ring_put(&ring, &e) == FZN_RING_OK)
			put++;
	}
	CHECK(put == 300u && ring.evicted > 0u && ring.held + ring.evicted == 300u
	              && ring.used <= FZN_RING_BYTES,
	      "past 256 KiB the oldest are evicted and counted, and the ring never overruns");
	CHECK(walk(&ring) == ring.held && consecutive(300u - ring.held, ring.held) && texts_ok,
	      "what is held is the newest entries, whole and in order");
	fzn_ring_spans(&ring, &a, &al, &b, &bl);
	CHECK(bl > 0u && al + bl == ring.used, "a ring that has wrapped dumps as two spans");

	/* THE DUMP READ BACK: the two spans in order are the records. */
	len = dumped(&ring);
	CHECK(fzn_ring_load(&again, dump, len) == FZN_RING_OK && again.held == ring.held
	              && walk(&again) == ring.held && consecutive(300u - ring.held, ring.held)
	              && texts_ok,
	      "the dump loads back to the same entries in the same order");
	CHECK(fzn_ring_load(&again, dump, len - 1u) == FZN_RING_ERR_MALFORMED && again.held == 0u,
	      "a dump cut short is refused, and the ring left empty");
	dump[2] ^= 0xffu; /* the first record's version */
	CHECK(fzn_ring_load(&again, dump, len) == FZN_RING_ERR_MALFORMED && again.held == 0u,
	      "a dump holding a record that is not one is refused");

	/* ONE LARGEST ENTRY AFTER ANOTHER: every put fits, however full. */
	fzn_ring_init(&ring);
	for (i = 0; i < 200u; i++) {
		e = entry(i, FZN_ENTRY_TEXT_MAX);
		(void)fzn_ring_put(&ring, &e);
	}
	CHECK(walk(&ring) == ring.held && consecutive(200u - ring.held, ring.held)
	              && ring.held >= (FZN_RING_BYTES / (FZN_ENTRY_RECORD_MAX + 2u)) - 1u,
	      "the largest entries fill the ring to within one record");

	if (failures) {
		fprintf(stderr, "ring_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("ring_test: all %d checks passed\n", checks);
	return 0;
}
