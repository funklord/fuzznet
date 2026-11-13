/* live_test -- `node/live.h`, sec 1019: a call's words read back as written, a
 * malformed one refused, and the calls a host keeps found, ended and expired. */
#include "../live.h"
#include "../types.h"

#include <stdio.h>
#include <string.h>

static int failures, checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;
	failures++;
	fprintf(stderr, "  FAIL live_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, what)

static void test_words(void)
{
	uint8_t whom[FZN_PUBKEY_LEN], buf[64], media[20];
	fzn_live_word_t w, r;
	size_t n;

	memset(whom, 0x77, sizeof(whom));
	memset(media, 0x5e, sizeof(media));
	memset(&w, 0, sizeof(w));
	w.kind = FZN_LIVE_RING;
	memset(w.call, 0xc1, sizeof(w.call));
	w.kinds = FZN_LIVE_AUDIO | FZN_LIVE_VIDEO;
	w.whom = whom;
	n = fzn_live_write(&w, buf, sizeof(buf));
	CHECK(n == FZN_LIVE_RING_LEN && fzn_live_is_word(buf, n), "a ring was not written");
	CHECK(fzn_live_read(buf, n, &r) && r.kind == FZN_LIVE_RING && r.kinds == w.kinds
	              && memcmp(r.whom, whom, sizeof(whom)) == 0
	              && memcmp(r.call, w.call, sizeof(w.call)) == 0,
	      "a ring did not read back");
	CHECK(!fzn_live_read(buf, n - 1u, &r), "a ring cut short was read");
	buf[FZN_LIVE_HEAD_LEN] = 4u;
	CHECK(!fzn_live_read(buf, n, &r), "a ring of an unknown kind of media was read");
	w.kinds = 0u;
	CHECK(fzn_live_write(&w, buf, sizeof(buf)) == 0u, "a ring of no media was written");

	memset(&w, 0, sizeof(w));
	w.kind = FZN_LIVE_HANGUP;
	memset(w.call, 0xc2, sizeof(w.call));
	n = fzn_live_write(&w, buf, sizeof(buf));
	CHECK(n == FZN_LIVE_HEAD_LEN && fzn_live_read(buf, n, &r) && r.kind == FZN_LIVE_HANGUP,
	      "a hang-up did not read back");
	CHECK(!fzn_live_read(buf, n + 1u, &r), "a hang-up with bytes after it was read");

	/* RINGING, sec 1062: the callee's answer to each ring, bare as a hang-up. */
	memset(&w, 0, sizeof(w));
	w.kind = FZN_LIVE_RINGING;
	memset(w.call, 0xc3, sizeof(w.call));
	n = fzn_live_write(&w, buf, sizeof(buf));
	CHECK(n == FZN_LIVE_HEAD_LEN && fzn_live_read(buf, n, &r) && r.kind == FZN_LIVE_RINGING
	              && r.call[0] == 0xc3u,
	      "a ringing did not read back");

	/* NO_ANSWER, sec 1073: the callee's ring time passed, bare too. */
	memset(&w, 0, sizeof(w));
	w.kind = FZN_LIVE_NO_ANSWER;
	memset(w.call, 0xc4, sizeof(w.call));
	n = fzn_live_write(&w, buf, sizeof(buf));
	CHECK(n == FZN_LIVE_HEAD_LEN && fzn_live_read(buf, n, &r) && r.kind == FZN_LIVE_NO_ANSWER
	              && r.call[0] == 0xc4u,
	      "a no-answer did not read back");
	buf[n] = 0;
	CHECK(!fzn_live_read(buf, n + 1u, &r), "a no-answer with a byte after it was read");

	memset(&w, 0, sizeof(w));
	w.kind = FZN_LIVE_FRAME;
	memset(w.call, 0xc3, sizeof(w.call));
	w.stream = FZN_LIVE_VIDEO;
	w.from = 513u;
	w.seq = 70000u;
	w.at_ms = 123456u;
	w.piece = 2u;
	w.pieces = 3u;
	w.media = media;
	w.media_len = sizeof(media);
	n = fzn_live_write(&w, buf, sizeof(buf));
	CHECK(n == FZN_LIVE_FRAME_HEAD_LEN + sizeof(media), "a frame was not written");
	CHECK(fzn_live_read(buf, n, &r) && r.kind == FZN_LIVE_FRAME && r.stream == FZN_LIVE_VIDEO
	              && r.from == 513u && r.seq == 70000u && r.at_ms == 123456u && r.piece == 2u
	              && r.pieces == 3u
	              && r.media_len == sizeof(media) && memcmp(r.media, media, sizeof(media)) == 0,
	      "a frame did not read back");
	w.piece = 3u;
	CHECK(fzn_live_write(&w, buf, sizeof(buf)) == 0u, "a piece past its pieces was written");
	/* AND ONE COME OFF THE WIRE so: piece 3 of 3 refused as it is read. */
	buf[FZN_LIVE_HEAD_LEN + 11u] = 0u;
	buf[FZN_LIVE_HEAD_LEN + 12u] = 3u;
	CHECK(!fzn_live_read(buf, n, &r), "a piece past its pieces was read");
	CHECK(fzn_live_write(&w, buf, 10u) == 0u, "a word past the room was written");
	buf[0] = FZN_CMD_CALL + 1u;
	CHECK(!fzn_live_is_word(buf, n), "another CMD was taken for a call's word");

	/* A PARTICIPANT, sec 1024: who the hub numbers INDEX; 0 is the caller, never
	 * said. */
	{
		uint8_t named[FZN_PUBKEY_LEN];

		memset(named, 0x5a, sizeof(named));
		memset(&w, 0, sizeof(w));
		w.kind = FZN_LIVE_PARTICIPANT;
		memset(w.call, 0xc5, sizeof(w.call));
		w.from = 300u;
		w.whom = named;
		n = fzn_live_write(&w, buf, sizeof(buf));
		CHECK(n == FZN_LIVE_PARTICIPANT_LEN && fzn_live_read(buf, n, &r) && r.kind == FZN_LIVE_PARTICIPANT
		              && r.from == 300u && memcmp(r.whom, named, sizeof(named)) == 0,
		      "a participant did not read back");
		CHECK(!fzn_live_read(buf, n - 1u, &r), "a participant cut short was read");
		w.from = 0u;
		CHECK(fzn_live_write(&w, buf, sizeof(buf)) == 0u, "the caller's 0 was said as a participant");
	}
}

/* A REPORT, and what a receiver counts: a gap lost, a late piece taking one back,
 * and jitter rising with an uneven transit (sec 1021). */
static void test_reports(void)
{
	fzn_live_word_t w, r;
	fzn_live_stats_t st;
	uint8_t buf[64];
	size_t n;

	memset(&w, 0, sizeof(w));
	w.kind = FZN_LIVE_REPORT;
	memset(w.call, 0xc4, sizeof(w.call));
	w.stream = FZN_LIVE_AUDIO;
	w.received = 4000000u;
	w.lost = 12u;
	w.jitter_ms = 33u;
	w.last_at_ms = 0x80000001u;
	w.held_ms = 250u;
	n = fzn_live_write(&w, buf, sizeof(buf));
	CHECK(n == FZN_LIVE_REPORT_LEN && fzn_live_read(buf, n, &r) && r.kind == FZN_LIVE_REPORT
	              && r.stream == FZN_LIVE_AUDIO && r.received == 4000000u && r.lost == 12u
	              && r.jitter_ms == 33u && r.last_at_ms == 0x80000001u && r.held_ms == 250u,
	      "a report did not read back");
	CHECK(!fzn_live_read(buf, n - 1u, &r), "a report cut short was read");

	memset(&st, 0, sizeof(st));
	fzn_live_count(&st, 10u, 1000u, 5000u);
	fzn_live_count(&st, 11u, 1020u, 5020u);
	fzn_live_count(&st, 14u, 1080u, 5080u);
	CHECK(st.received == 3u && st.lost == 2u, "a gap of two not counted lost");
	CHECK(st.jitter16 == 0u, "an even transit made jitter");
	fzn_live_count(&st, 12u, 1040u, 5150u);
	CHECK(st.received == 4u && st.lost == 1u, "a late piece did not take one back");
	CHECK(st.jitter16 > 0u, "an uneven transit made no jitter");
	/* THE NEWEST TO ARRIVE, late or not, is what a round trip is read from:
	 * HELD runs from its arrival (sec 1026). */
	CHECK(st.last_at == 1040u && st.last_arrival_ms == 5150u,
	      "the newest piece's AT and arrival were not kept");
}

static size_t gone_n;

static void gone(void *ctx, const fzn_live_call_t *c)
{
	(void)ctx;
	(void)c;
	gone_n++;
}

/* A ROW'S OWN RING TIME, sec 1073: the receiver's value, FZN_LIVE_RING_S unset. */
static void test_ring_time(void)
{
	static fzn_live_calls_t t;
	uint8_t id[FZN_LIVE_CALL_LEN];
	fzn_live_call_t *set, *unset, *most;

	memset(id, 1, sizeof(id));
	set = fzn_live_open(&t, id);
	memset(id, 2, sizeof(id));
	unset = fzn_live_open(&t, id);
	memset(id, 3, sizeof(id));
	most = fzn_live_open(&t, id);
	CHECK(set && unset && most, "fixture: three ringing calls");
	if (!set || !unset || !most)
		return;
	set->state = FZN_LIVE_RINGING_IN;
	set->ring_s = 10u;
	unset->state = FZN_LIVE_RINGING_IN;
	most->state = FZN_LIVE_RINGING_OUT;
	most->ring_s = FZN_LIVE_RING_MAX_S;
	set->since_s = unset->since_s = most->since_s = 1000u;
	CHECK(fzn_live_expire(&t, 1009u, NULL, NULL) == 0u, "a call ended before its ring time");
	CHECK(fzn_live_expire(&t, 1010u, NULL, NULL) == 1u && !set->used && unset->used,
	      "a call set to ring 10 s did not end at 10 s");
	CHECK(fzn_live_expire(&t, 1000u + FZN_LIVE_RING_S, NULL, NULL) == 1u && !unset->used
	              && most->used,
	      "a call with no ring time did not end at FZN_LIVE_RING_S");
	CHECK(fzn_live_expire(&t, 1000u + FZN_LIVE_RING_MAX_S - 1u, NULL, NULL) == 0u
	              && fzn_live_expire(&t, 1000u + FZN_LIVE_RING_MAX_S, NULL, NULL) == 1u,
	      "a caller's call did not ring to the most a receiver may set");
	fzn_live_release(&t);
}

static void test_calls(void)
{
	static fzn_live_calls_t t;
	uint8_t id[FZN_LIVE_CALL_LEN];
	fzn_live_call_t *c, *ringing = NULL, *up = NULL;
	unsigned i;

	for (i = 0; i < 20u; i++) {
		memset(id, (int)i + 1, sizeof(id));
		c = fzn_live_open(&t, id);
		CHECK(c != NULL, "a call was not kept");
		if (!c)
			return;
		c->state = i % 2u ? FZN_LIVE_UP : FZN_LIVE_RINGING_OUT;
		c->since_s = 100u;
		c->heard_s = 100u;
	}
	CHECK(t.n == 20u, "twenty calls are not twenty rows");
	memset(id, 3, sizeof(id));
	CHECK(fzn_live_open(&t, id) == fzn_live_find(&t, id) && t.n == 20u,
	      "a call opened again took another row");
	memset(id, 99, sizeof(id));
	CHECK(fzn_live_find(&t, id) == NULL, "a call never opened was found");
	memset(id, 2, sizeof(id));
	up = fzn_live_find(&t, id);
	memset(id, 1, sizeof(id));
	ringing = fzn_live_find(&t, id);
	CHECK(up && ringing, "fixture: an up call and a ringing one");
	if (!up || !ringing)
		return;
	up->heard_s = 130u;
	/* AT 140: every call up and unheard since 100 is past its 30 s, and none
	 * ringing past its 45; the one heard at 130 stays. */
	CHECK(fzn_live_expire(&t, 140u, gone, NULL) == 9u && gone_n == 9u,
	      "expiry at 140 did not end the nine idle calls");
	CHECK(fzn_live_find(&t, id) == ringing && up->used, "a call within its time was ended");
	CHECK(fzn_live_expire(&t, 145u, gone, NULL) == 10u, "the ringing calls did not end at 145");
	CHECK(t.n == 1u && up->used, "the call heard at 130 did not stay");
	fzn_live_end(&t, up);
	CHECK(t.n == 0u, "an ended call stays counted");
	/* ENDED AND REMEMBERED, sec 1039: a ring said again after a decline opens
	 * nothing; a new call opens; the oldest is forgotten past FZN_LIVE_ENDED. */
	memset(id, 2, sizeof(id));
	CHECK(fzn_live_open(&t, id) == NULL && t.n == 0u, "an ended call was opened again by its id");
	for (i = 0; i < FZN_LIVE_ENDED; i++) {
		memset(id, (int)(100u + i), sizeof(id));
		c = fzn_live_open(&t, id);
		CHECK(c != NULL, "a new call was refused among ended ones");
		if (c)
			fzn_live_end(&t, c);
	}
	memset(id, 2, sizeof(id));
	c = fzn_live_open(&t, id);
	CHECK(c != NULL, "the oldest ended call was not forgotten past FZN_LIVE_ENDED");
	if (c)
		fzn_live_end(&t, c);
	fzn_live_release(&t);
	CHECK(!t.rows && !t.cap, "a table let go still holds");
}

int main(void)
{
	test_words();
	test_reports();
	test_calls();
	test_ring_time();
	printf("live_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
