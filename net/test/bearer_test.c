/* A frame in pieces and back, and SLIP: net/bearer.h. */

#include "../bearer.h"
#include "../udp.h"

#include <stdio.h>
#include <string.h>

static int failures, checks;

#define CHECK(c, what)                                                        \
	do {                                                                      \
		checks++;                                                             \
		if (!(c)) {                                                           \
			failures++;                                                       \
			fprintf(stderr, "  FAIL bearer_test.c:%d: %s\n", __LINE__, what); \
		}                                                                     \
	} while (0)

/* WHAT WENT OUT: each unit, in order. */
#define UNITS_MAX 160u
static uint8_t units[UNITS_MAX][FZN_BEARER_UNIT_MAX];
static size_t unit_lens[UNITS_MAX], n_units;
static size_t refuse_at = (size_t)-1;

static int catch_unit(void *ctx, const uint8_t *bytes, size_t len)
{
	(void)ctx;
	if (n_units == refuse_at || n_units == UNITS_MAX)
		return 0;
	memcpy(units[n_units], bytes, len);
	unit_lens[n_units++] = len;
	return 1;
}

static void pattern(uint8_t *b, size_t n, uint8_t seed)
{
	size_t i;

	for (i = 0; i < n; i++)
		b[i] = (uint8_t)(seed + i * 7u);
}

int main(void)
{
	static fzn_bearer_slot_t slots[2];
	static uint8_t frame[FZN_BEARER_FRAME_MAX], other[FZN_BEARER_FRAME_MAX];
	static uint8_t coded[2u * sizeof(frame) + 2u], read_back[FZN_BEARER_FRAME_MAX];
	static const size_t sizes[] = { 12u, 51u, 222u, 255u, FZN_BEARER_UNIT_MAX };
	fzn_bearer_t b;
	fzn_bearer_join_t j;
	const uint8_t *whole = NULL;
	size_t i, k, n, got;

	CHECK(FZN_BEARER_FRAME_MAX == FZN_UDP_DATAGRAM_MAX, "a frame's bound moved from UDP's");
	CHECK(fzn_bearer_pieces(FZN_BEARER_FRAME_MAX, FZN_BEARER_UNIT_MIN) != 0u,
	      "the largest frame cannot cross the smallest unit");
	CHECK(fzn_bearer_pieces(FZN_BEARER_FRAME_MAX + 1u, 222u) == 0u, "too long a frame was planned");
	CHECK(fzn_bearer_pieces(0u, 222u) == 0u, "an empty frame was planned");
	CHECK(fzn_bearer_pieces(100u, FZN_BEARER_UNIT_MIN - 1u) == 0u, "too small a unit was taken");
	CHECK(fzn_bearer_pieces(47u, 51u) == 1u && fzn_bearer_pieces(48u, 51u) == 2u,
	      "a frame's pieces miscounted at the edge of a unit");

	memset(&b, 0, sizeof(b));
	b.send = catch_unit;
	memset(&j, 0, sizeof(j));
	j.held = slots;
	j.n_held = 2u;

	/* EVERY UNIT, FORWARDS AND BACKWARDS: pieces may arrive in any order. */
	for (k = 0; k < sizeof(sizes) / sizeof(sizes[0]); k++) {
		size_t lens[3] = { 1u, 300u, sizeof(frame) };
		size_t l;

		b.unit = j.unit = sizes[k];
		for (l = 0; l < 3u; l++) {
			pattern(frame, lens[l], (uint8_t)(k + l));
			n_units = 0;
			CHECK(fzn_bearer_send(&b, 0x1234u, frame, lens[l]) == 1, "a frame would not go");
			CHECK(n_units == fzn_bearer_pieces(lens[l], sizes[k]), "pieces went uncounted");
			for (i = 0, got = 0; i < n_units; i++) {
				CHECK(unit_lens[i] <= sizes[k], "a unit went past the bearer's");
				got = fzn_bearer_take(&j, units[i], unit_lens[i], &whole);
				CHECK((got != 0u) == (i + 1u == n_units), "a frame finished at the wrong piece");
			}
			CHECK(got == lens[l] && memcmp(whole, frame, got) == 0, "a frame came back changed");
			for (i = n_units, got = 0; i > 0; i--)
				got = fzn_bearer_take(&j, units[i - 1u], unit_lens[i - 1u], &whole);
			CHECK(got == lens[l] && memcmp(whole, frame, got) == 0,
			      "a frame's pieces in reverse came back changed");
		}
	}

	/* A PIECE HEARD TWICE counts once. */
	b.unit = j.unit = 51u;
	pattern(frame, 200u, 3u);
	n_units = 0;
	(void)fzn_bearer_send(&b, 7u, frame, 200u);
	n = n_units;
	for (i = 0; i + 1u < n; i++) {
		CHECK(fzn_bearer_take(&j, units[0], unit_lens[0], &whole) == 0u,
		      "a piece heard twice finished a frame");
	}
	for (i = 1; i < n; i++)
		got = fzn_bearer_take(&j, units[i], unit_lens[i], &whole);
	CHECK(got == 200u && memcmp(whole, frame, got) == 0, "a repeated piece spoiled its frame");

	/* TWO SENDERS AT ONCE, their pieces interleaved. */
	pattern(other, 200u, 90u);
	n_units = 0;
	(void)fzn_bearer_send(&b, 1u, frame, 200u);
	n = n_units;
	(void)fzn_bearer_send(&b, 2u, other, 200u);
	for (i = 0; i < n; i++) {
		got = fzn_bearer_take(&j, units[i], unit_lens[i], &whole);
		if (got)
			CHECK(memcmp(whole, frame, got) == 0, "one sender's frame held the other's");
		got = fzn_bearer_take(&j, units[n + i], unit_lens[n + i], &whole);
		if (got)
			CHECK(memcmp(whole, other, got) == 0, "the other's frame held the one's");
	}
	CHECK(got == 200u, "interleaved senders were not both joined");

	/* A THIRD SENDER TAKES THE OLDEST'S SLOT, and the two newest finish. */
	n_units = 0;
	(void)fzn_bearer_send(&b, 11u, frame, 100u);
	(void)fzn_bearer_send(&b, 12u, frame, 100u);
	(void)fzn_bearer_send(&b, 13u, frame, 100u);
	n = n_units / 3u;
	(void)fzn_bearer_take(&j, units[0], unit_lens[0], &whole);
	(void)fzn_bearer_take(&j, units[n], unit_lens[n], &whole);
	(void)fzn_bearer_take(&j, units[2u * n], unit_lens[2u * n], &whole);
	for (i = 1, got = 0; i < n; i++)
		got = fzn_bearer_take(&j, units[n + i], unit_lens[n + i], &whole);
	CHECK(got == 100u, "the newer of two was the one evicted");
	memset(slots, 0, sizeof(slots));

	/* NOT PIECES: each dropped, and none reaches past its frame. */
	{
		uint8_t bad[64];

		memset(bad, 0, sizeof(bad));
		CHECK(fzn_bearer_take(&j, bad, FZN_BEARER_HEAD_LEN, &whole) == 0u, "no bytes was a piece");
		CHECK(fzn_bearer_take(&j, bad, 20u, &whole) == 0u, "a count of 0 was taken");
		bad[2] = 3u;
		bad[3] = 2u;
		CHECK(fzn_bearer_take(&j, bad, 20u, &whole) == 0u, "an index past the count was taken");
		/* A SHORT PIECE MID-FRAME, and then its last: taken, the two would make
		 * a frame with a hole in it. */
		bad[0] = 0x51u;
		bad[2] = 0u;
		bad[3] = 2u;
		CHECK(fzn_bearer_take(&j, bad, 20u, &whole) == 0u, "a short piece finished a frame");
		bad[2] = 1u;
		CHECK(fzn_bearer_take(&j, bad, 20u, &whole) == 0u, "a short piece was taken as a full one");
		memset(slots, 0, sizeof(slots));
		/* PIECES RUNNING PAST THE FRAME: 26 of 47 bytes is 1222, past 1168, and
		 * if all were taken the last would finish it. */
		bad[0] = 0x52u;
		bad[3] = 26u;
		for (i = 0, got = 0; i < 26u; i++) {
			bad[2] = (uint8_t)i;
			got = fzn_bearer_take(&j, bad, 51u, &whole);
		}
		CHECK(got == 0u, "a frame past the largest was joined");
		memset(slots, 0, sizeof(slots));
		bad[0] = 0u;
		bad[3] = 255u;
		CHECK(fzn_bearer_take(&j, bad, 51u, &whole) == 0u, "more pieces than a frame was taken");
		bad[2] = 145u;
		bad[3] = 146u;
		CHECK(fzn_bearer_take(&j, bad, 51u, &whole) == 0u, "a piece past the frame's room was taken");
		CHECK(fzn_bearer_take(&j, bad, 52u, &whole) == 0u, "a unit past the link's was taken");
	}

	/* A SEND THAT STOPS says so. */
	refuse_at = 2u;
	n_units = 0;
	CHECK(fzn_bearer_send(&b, 3u, frame, 200u) == 0, "a bearer's refusal went unsaid");
	refuse_at = (size_t)-1;

	/* SLIP: every byte value through, and its two marks. */
	{
		fzn_slip_reader_t r;
		size_t len, w = 0;

		for (i = 0; i < 256u; i++)
			frame[i] = (uint8_t)i;
		len = fzn_slip_encode(frame, 256u, coded, sizeof(coded));
		CHECK(len == 256u + 2u + 2u, "SLIP escaped other than its two marks");
		memset(&r, 0, sizeof(r));
		r.buffer = read_back;
		r.cap = sizeof(read_back);
		for (i = 0, got = 0; i < len; i++) {
			w = fzn_slip_feed(&r, coded[i]);
			if (w)
				got = w;
		}
		CHECK(got == 256u && memcmp(read_back, frame, 256u) == 0, "SLIP changed its bytes");
		CHECK(fzn_slip_encode(frame, 256u, coded, 100u) == 0u, "SLIP wrote past its room");

		/* TOO LONG: lost, and the next is read. */
		r.cap = 4u;
		for (i = 0; i < 6u; i++)
			(void)fzn_slip_feed(&r, 1u);
		CHECK(fzn_slip_feed(&r, FZN_SLIP_END) == 0u, "an overrun packet was given");
		(void)fzn_slip_feed(&r, 9u);
		CHECK(fzn_slip_feed(&r, FZN_SLIP_END) == 1u && read_back[0] == 9u,
		      "the packet after an overrun was lost");

		/* A BAD ESCAPE: that packet lost. */
		(void)fzn_slip_feed(&r, FZN_SLIP_ESC);
		(void)fzn_slip_feed(&r, 0x11u);
		CHECK(fzn_slip_feed(&r, FZN_SLIP_END) == 0u, "a bad escape was given");
	}

	printf("bearer_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
