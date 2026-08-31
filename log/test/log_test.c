/* A log that evicts, and the difference between "gone" and "not yet".
 *
 * That distinction is the reason this module exists rather than being a
 * second journal. A peer that fell behind asks for a sequence; if the answer
 * to "evicted" and the answer to "not arrived" are the same, it asks for ever
 * and neither side can tell that from a lost datagram.
 *
 * THE LINE BETWEEN THE TWO IS THE JOURNAL'S `received`, not the oldest entry
 * this log still holds, and most of what is below exists because the two look
 * identical in the easy case and disagree in every hard one. A test that only
 * evicts the bottom of one stream passes against either rule -- which is what
 * the suite used to do, and why a module that answered ABSENT to a stream it
 * had evicted entirely went unnoticed. Every case here that names a hole is
 * one the old rule got wrong.
 *
 * AND THE CONTROLS MATTER AS MUCH AS THE HOLES: a module that answered GONE
 * to everything would satisfy every one of the negative cases, so the
 * sequences that must still answer ABSENT and OK are checked beside them.
 */

#include "../../chain/chain.h" /* fzn_sign_ops_t */
#include "../log.h"

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

static void expect_err(fzn_log_err_t got, fzn_log_err_t want, const char *what)
{
	checks++;
	if (got != want) {
		failures++;
		fprintf(stderr, "  FAIL: %s -- got \"%s\", wanted \"%s\"\n", what, fzn_log_err_str(got),
		       fzn_log_err_str(want));
	}
}

static uint8_t BODIES[16][4];

/* A signer for the fixture, and storage for the bytes its records occupy.
 *
 * A record is a VIEW over the bytes its signature covers, so a fixture must
 * ENCODE one rather than fill a struct -- which is the property being bought:
 * a field cannot disagree with the signature because there is nothing left
 * for it to disagree with. This suite never verifies, so the signer answers
 * for nobody in particular; what it must do is sign the bytes it is handed.
 *
 * A ring, because a test holds more than one record at a time. */
static int fixture_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	uint32_t acc = 0x9e3779b9u;
	size_t i;

	(void)ctx;
	for (i = 0; i < msg_len; i++)
		acc = (acc * 31u) + msg[i];
	for (i = 0; i < FZN_SIG_LEN; i++)
		sig[i] = (uint8_t)(acc >> ((i % 4u) * 8u));
	return 1;
}

#define WIRE_SLOTS 32u
static uint8_t wire_pool[WIRE_SLOTS][FZN_RECORD_MAX_LEN];
static size_t wire_next;

static int fixture_record(fzn_record_t *r, const uint8_t issuer[FZN_PUBKEY_LEN],
                          const uint8_t subject[FZN_SUBJECT_LEN], uint32_t stream, uint32_t kind,
                          uint64_t seq, const uint8_t *body, size_t body_len)
{
	fzn_sign_ops_t ops;
	uint8_t *slot = wire_pool[wire_next % WIRE_SLOTS];
	size_t wrote = 0;

	wire_next++;
	memset(&ops, 0, sizeof(ops));
	ops.sign = fixture_sign;

	if (fzn_record_sign(issuer, subject, stream, kind, seq, 1, body, body_len, &ops, slot,
	                    FZN_RECORD_MAX_LEN, &wrote) != FZN_RECORD_OK)
		return 0;
	return fzn_record_open(slot, wrote, r) == FZN_RECORD_OK;
}

static void make_on(fzn_record_t *r, uint8_t issuer_seed, uint32_t stream, uint64_t seq)
{
	uint8_t issuer[FZN_PUBKEY_LEN], subject[FZN_SUBJECT_LEN];

	memset(issuer, issuer_seed, sizeof(issuer));
	memset(subject, 0, sizeof(subject));
	if (!fixture_record(r, issuer, subject, stream, 3, seq, BODIES[seq % 16u],
	                    sizeof(BODIES[0]))) {
		fprintf(stderr, "  FAIL: the fixture could not build a record\n");
		failures++;
		memset(r, 0, sizeof(*r));
	}
}

static void make(fzn_record_t *r, uint8_t issuer_seed, uint64_t seq)
{
	make_on(r, issuer_seed, 0, seq);
}

int main(void)
{
	fzn_log_t log;
	fzn_log_entry_t entries[4];
	/* THE POSITION `fzn_log_get` JUDGES AGAINST. It is a parameter rather
	 * than a second call this test is trusted to make, and log.h says why:
	 * a caller that forgot would be told ABSENT, which is a legitimate
	 * answer nothing can distinguish from a correct one. */
	fzn_journal_t journal;
	fzn_journal_entry_t positions[8];
	fzn_record_t rec;
	const fzn_log_entry_t *got;
	const fzn_log_entry_t *page[8];
	uint8_t alice[FZN_PUBKEY_LEN], bob[FZN_PUBKEY_LEN];
	uint64_t first, last;

	memset(alice, 0xa1, sizeof(alice));
	memset(bob, 0xb2, sizeof(bob));
	for (size_t i = 0; i < 16; i++)
		memset(BODIES[i], (int)i, sizeof(BODIES[0]));

	expect_err(fzn_log_init(NULL, entries, 4), FZN_LOG_ERR_MALFORMED, "a null log");
	expect_err(fzn_log_init(&log, NULL, 4), FZN_LOG_ERR_MALFORMED, "null entries");
	expect_err(fzn_log_init(&log, entries, 0), FZN_LOG_ERR_MALFORMED, "zero capacity");
	expect_err(fzn_log_init(&log, entries, 4), FZN_LOG_OK, "a well-formed log");
	expect(fzn_journal_init(&journal, positions, 8) == FZN_JOURNAL_OK, "a journal to ask");
	expect(fzn_journal_anchor(&journal, alice, 0, 0) == FZN_JOURNAL_OK,
	       "following alice's first stream from the beginning");

	fzn_log_range(&log, alice, 0, &first, &last);
	expect(first == 0 && last == 0, "an empty log holds no range");
	/* NOTHING RECEIVED AND NOTHING HELD IS ABSENT, NOT GONE. A stream
	 * followed from the beginning has `received == 0`, so no sequence is at
	 * or below it and nothing can have been evicted. A module that answered
	 * GONE here would send a peer to `fzn_journal_anchor` on its first
	 * question. */
	expect_err(fzn_log_get(&log, &journal, alice, 0, 1, &got), FZN_LOG_ERR_ABSENT,
	           "asking an empty log for anything");
	expect_err(fzn_log_get(&log, &journal, alice, 55, 1, &got), FZN_LOG_ERR_ABSENT,
	           "asking about a stream nobody follows and nobody wrote");

	/* APPEND, AND WHAT IS HELD. */
	for (uint64_t seq = 1; seq <= 3; seq++) {
		make(&rec, 0xa1, seq);
		expect_err(fzn_log_append(&log, &rec), FZN_LOG_OK, "appending in order");
		expect(fzn_journal_admit(&journal, alice, 0, seq) == FZN_JOURNAL_OK,
		       "and the position advances with it");
	}
	fzn_log_range(&log, alice, 0, &first, &last);
	expect(first == 1 && last == 3, "the range should be one to three");
	expect_err(fzn_log_get(&log, &journal, alice, 0, 2, &got), FZN_LOG_OK, "fetching a held entry");
	expect(got != NULL && got->seq == 2, "and it is the right one");
	expect_err(fzn_log_get(&log, &journal, alice, 0, 9, &got), FZN_LOG_ERR_ABSENT,
	           "asking beyond the newest");

	make(&rec, 0xa1, 2);
	expect_err(fzn_log_append(&log, &rec), FZN_LOG_ERR_DUPLICATE, "appending one held already");

	/* EVICTION. A log evicts where a journal refuses, because losing its
	 * oldest is a log's normal condition rather than a failure. */
	expect(fzn_log_dropped(&log) == 0, "nothing dropped yet");
	make(&rec, 0xa1, 4);
	expect_err(fzn_log_append(&log, &rec), FZN_LOG_OK, "the fourth fills it");
	expect(fzn_journal_admit(&journal, alice, 0, 4) == FZN_JOURNAL_OK, "received four");
	make(&rec, 0xa1, 5);
	expect_err(fzn_log_append(&log, &rec), FZN_LOG_OK, "the fifth evicts the oldest");
	expect(fzn_journal_admit(&journal, alice, 0, 5) == FZN_JOURNAL_OK, "received five");
	expect(fzn_log_dropped(&log) == 1, "and says that it dropped one");

	fzn_log_range(&log, alice, 0, &first, &last);
	expect(first == 2 && last == 5, "the log now starts at two");

	/* THE WHOLE POINT: two different answers for two different reasons.
	 * `received` is five and the log starts at two, so one was received and
	 * evicted while six was never received at all. */
	expect_err(fzn_log_get(&log, &journal, alice, 0, 1, &got), FZN_LOG_ERR_GONE,
	           "asking for what retention removed");
	expect_err(fzn_log_get(&log, &journal, alice, 0, 6, &got), FZN_LOG_ERR_ABSENT,
	           "asking for what has not arrived");
	/* AND THE BOUNDARY IN BOTH DIRECTIONS, which is what an off-by-one in
	 * the comparison moves. Five is held, so ask about a stream where the
	 * edge is not: see "the position is the line" below. */
	expect_err(fzn_log_get(&log, &journal, alice, 0, 5, &got), FZN_LOG_OK,
	           "the newest received is held, not gone");

	/* READING A RANGE, OLDEST FIRST, because a receiver admits by one and
	 * refuses a jump -- newest-first would be refused entry by entry. */
	{
		size_t n = fzn_log_read_since(&log, alice, 0, 2, page, 8);

		expect(n == 3, "three entries after two");
		expect(n == 3 && page[0]->seq == 3 && page[1]->seq == 4 && page[2]->seq == 5,
		       "and they must be oldest first");
	}
	expect(fzn_log_read_since(&log, alice, 0, 5, page, 8) == 0, "nothing after the newest");
	expect(fzn_log_read_since(&log, alice, 0, 0, page, 2) == 2, "a bounded read stops at its cap");

	/* ANOTHER ISSUER IS A SEPARATE STREAM. */
	expect(fzn_log_read_since(&log, bob, 0, 0, page, 8) == 0, "an unheard issuer has nothing");
	fzn_log_range(&log, bob, 0, &first, &last);
	expect(first == 0 && last == 0, "and no range");
	make(&rec, 0xb2, 1);
	expect_err(fzn_log_append(&log, &rec), FZN_LOG_OK, "bob's first entry");
	expect(fzn_log_read_since(&log, bob, 0, 0, page, 8) == 1, "which is bob's alone");

	/* Arguments. */
	expect_err(fzn_log_append(&log, NULL), FZN_LOG_ERR_MALFORMED, "a null record");
	expect_err(fzn_log_append(NULL, &rec), FZN_LOG_ERR_MALFORMED, "a null log to append to");
	/* SEQUENCE ZERO IS NOW UNBUILDABLE, which is the change working rather
	 * than coverage lost: `fzn_record_sign` refuses it at the point a
	 * record is made, so it cannot reach this module at all. `record_test`
	 * holds that refusal. */
	/* A RECORD THAT WAS NEVER OPENED. This used to build a good record and
	 * then set `body` NULL with a non-zero length -- a state a view cannot
	 * represent, which is the point of the change: the two can no longer
	 * disagree because there is only one of them. What a caller CAN still
	 * hand over is a record it never opened, and that must be refused. */
	memset(&rec, 0, sizeof(rec));
	expect_err(fzn_log_append(&log, &rec), FZN_LOG_ERR_MALFORMED, "a record never opened");
	expect_err(fzn_log_get(&log, &journal, alice, 0, 0, &got), FZN_LOG_ERR_MALFORMED, "asking for zero");
	expect_err(fzn_log_get(&log, &journal, alice, 0, 1, NULL), FZN_LOG_ERR_MALFORMED, "nowhere to answer");
	expect(fzn_log_read_since(&log, alice, 0, 0, page, 0) == 0, "a zero-capacity read");
	expect(fzn_log_read_since(NULL, alice, 0, 0, page, 8) == 0, "reading a null log");
	expect(fzn_log_dropped(NULL) == 0, "a null log dropped nothing");
	fzn_log_range(NULL, alice, 0, &first, &last);
	expect(first == 0 && last == 0, "a null log has no range");

	/* STREAMS DO NOT SEE EACH OTHER, which the cases above never mixed:
	 * every one of them used stream 0, so the stream comparison in `find`,
	 * `range` and `read_since` had never once decided anything. A log that
	 * ignored it would serve one stream's entries to a follower of
	 * another, which is the fidelity guarantee in sec 5j undone at the
	 * storage layer. */
	{
		fzn_log_t two;
		fzn_log_entry_t rows[4];
		uint64_t lo = 0, hi = 0;

		expect_err(fzn_log_init(&two, rows, 4), FZN_LOG_OK, "a log for two streams");
		for (uint64_t seq = 1; seq <= 2; seq++) {
			make_on(&rec, 0xa1, 1, seq);
			expect_err(fzn_log_append(&two, &rec), FZN_LOG_OK, "stream one");
			make_on(&rec, 0xa1, 2, seq);
			expect_err(fzn_log_append(&two, &rec), FZN_LOG_OK, "stream two");
		}

		/* The same issuer and the same sequences in both, so anything
		 * that ignored the stream would look correct on counts alone. */
		fzn_log_range(&two, alice, 1, &lo, &hi);
		expect(lo == 1 && hi == 2, "stream one's range is its own");
		expect(fzn_log_read_since(&two, alice, 1, 0, page, 8) == 2,
		       "and reading it returns only its own");
		expect(fzn_log_read_since(&two, alice, 9, 0, page, 8) == 0,
		       "a stream nobody wrote holds nothing");
		fzn_log_range(&two, alice, 9, &lo, &hi);
		expect(lo == 0 && hi == 0, "and has no range");
		expect_err(fzn_log_get(&two, &journal, alice, 9, 1, &got), FZN_LOG_ERR_ABSENT,
		           "and answers absent rather than another stream's entry");
	}

	/* A RECORD WITH NO BODY AT ALL is legitimate -- a statement whose
	 * meaning is entirely in its kind and subject -- and the guard is
	 * `body == NULL AND length != 0`, so this is the half that must pass. */
	{
		uint8_t issuer[FZN_PUBKEY_LEN], subject[FZN_SUBJECT_LEN];

		memset(issuer, 0xa1, sizeof(issuer));
		memset(subject, 0, sizeof(subject));
		expect(fixture_record(&rec, issuer, subject, 0, 3, 12, NULL, 0),
		       "the fixture could not build a bodyless record");
		expect_err(fzn_log_append(&log, &rec), FZN_LOG_OK, "a record carrying no body");
	}

	/* RANGE TAKES EITHER POINTER OR NEITHER, since a caller often wants
	 * only the oldest or only the newest. */
	{
		uint64_t only = 99;

		fzn_log_range(&log, alice, 0, &only, NULL);
		expect(only != 99, "asking for the first alone");
		only = 99;
		fzn_log_range(&log, alice, 0, NULL, &only);
		expect(only != 99, "asking for the last alone");
		fzn_log_range(&log, alice, 0, NULL, NULL); /* must not crash */
		fzn_log_range(&log, NULL, 0, &only, &only);
		expect(only == 0, "a null issuer has no range");
	}

	expect_err(fzn_log_get(&log, &journal, NULL, 0, 1, &got), FZN_LOG_ERR_MALFORMED,
	           "asking about a null issuer");
	expect(fzn_log_read_since(&log, NULL, 0, 0, page, 8) == 0, "reading a null issuer");

	/* A CORRUPT `used` MUST BE REFUSED AT EVERY ENTRY POINT that scans,
	 * not at one of them -- the argument frame/freshness.c makes and
	 * record/journal.c repeats. */
	{
		fzn_log_t corrupt = log;

		corrupt.used = corrupt.capacity + 1u;
		expect_err(fzn_log_append(&corrupt, &rec), FZN_LOG_ERR_MALFORMED,
		           "appending to a corrupt log");
		expect_err(fzn_log_get(&corrupt, &journal, alice, 0, 1, &got), FZN_LOG_ERR_MALFORMED,
		           "reading a corrupt log");
		expect(fzn_log_read_since(&corrupt, alice, 0, 0, page, 8) == 0,
		       "a corrupt log serves nothing");
		expect(fzn_log_dropped(&corrupt) == 0, "and reports no drops");
		{
			uint64_t lo = 99, hi = 99;

			fzn_log_range(&corrupt, alice, 0, &lo, &hi);
			expect(lo == 0 && hi == 0, "and has no range");
		}
	}

	/* THE POSITION IS THE LINE, NOT THE OLDEST HELD, and the three blocks
	 * below are the cases where the two rules disagree. Deriving GONE from
	 * `fzn_log_range` gets every one of them wrong, and nothing above this
	 * point could tell: every case so far evicted the bottom of a single
	 * stream, which is the one shape both rules agree on.
	 *
	 * Each block builds its own log so that eviction can be AIMED. Entries
	 * leave in append order across every stream in the log, which is what
	 * makes a hole in the middle and a hole at the top reachable at all. */
	{
		fzn_log_t small;
		fzn_log_entry_t slots[2];
		uint64_t lo = 0, hi = 0;

		expect(fzn_log_init(&small, slots, 2) == FZN_LOG_OK, "a two-entry log");
		expect(fzn_journal_anchor(&journal, alice, 7, 0) == FZN_JOURNAL_OK,
		       "following stream seven");
		expect(fzn_journal_anchor(&journal, alice, 8, 0) == FZN_JOURNAL_OK,
		       "following stream eight");

		for (uint64_t seq = 1; seq <= 2; seq++) {
			make_on(&rec, 0xa1, 7, seq);
			expect(fzn_log_append(&small, &rec) == FZN_LOG_OK, "stream seven's entries");
			expect(fzn_journal_admit(&journal, alice, 7, seq) == FZN_JOURNAL_OK,
			       "and seven's position");
		}
		/* Two more from another stream, which is enough to push every one
		 * of seven's out of a log this size. */
		for (uint64_t seq = 1; seq <= 2; seq++) {
			make_on(&rec, 0xa1, 8, seq);
			expect(fzn_log_append(&small, &rec) == FZN_LOG_OK, "stream eight's entries");
			expect(fzn_journal_admit(&journal, alice, 8, seq) == FZN_JOURNAL_OK,
			       "and eight's position");
		}

		fzn_log_range(&small, alice, 7, &lo, &hi);
		expect(lo == 0 && hi == 0, "stream seven now holds nothing at all");

		/* A WHOLE STREAM EVICTED, which is the failure that started this.
		 * `first` is zero, so the old `first != 0` guard fell through and
		 * the answer was ABSENT; the peer then asks for ever, and neither
		 * side can tell that from a lost datagram. */
		expect_err(fzn_log_get(&small, &journal, alice, 7, 1, &got), FZN_LOG_ERR_GONE,
		           "a stream evicted down to nothing is gone, not absent");
		/* THE BOUNDARY WITH NOTHING HELD TO BLUR IT: two is `received`
		 * exactly and three is one past it. This pair is what an
		 * off-by-one in the comparison moves, in whichever direction. */
		expect_err(fzn_log_get(&small, &journal, alice, 7, 2, &got), FZN_LOG_ERR_GONE,
		           "the last sequence received and evicted is gone");
		expect_err(fzn_log_get(&small, &journal, alice, 7, 3, &got), FZN_LOG_ERR_ABSENT,
		           "and the first never received is absent");
		/* And the stream that did the evicting is untouched, so a rule
		 * that had simply started answering GONE would be caught here. */
		expect_err(fzn_log_get(&small, &journal, alice, 8, 1, &got), FZN_LOG_OK,
		           "what is still held is still served");
	}

	{
		fzn_log_t back;
		fzn_log_entry_t slots[4];

		/* A HOLE BELOW THE OLDEST HELD. This host has received three and
		 * holds five and six -- a back-fill in progress, or a peer that
		 * pushed further than it was asked. Four was never received, so
		 * it cannot have been evicted, and answering GONE sends the
		 * consumer to `fzn_journal_anchor` to accept an IRREVERSIBLE loss
		 * that never happened. That is what the old rule answered, with
		 * `dropped == 0` sitting right beside it. */
		expect(fzn_log_init(&back, slots, 4) == FZN_LOG_OK, "a log for back-fill");
		expect(fzn_journal_anchor(&journal, bob, 3, 3) == FZN_JOURNAL_OK,
		       "bob's stream three, received up to three");
		for (uint64_t seq = 5; seq <= 6; seq++) {
			make_on(&rec, 0xb2, 3, seq);
			expect(fzn_log_append(&back, &rec) == FZN_LOG_OK, "an entry above the position");
		}
		expect(fzn_log_dropped(&back) == 0, "nothing was evicted here at all");

		fzn_log_range(&back, bob, 3, &first, &last);
		expect(first == 5 && last == 6, "the oldest held is five");
		expect_err(fzn_log_get(&back, &journal, bob, 3, 4, &got), FZN_LOG_ERR_ABSENT,
		           "below the oldest held but never received is absent");
		expect_err(fzn_log_get(&back, &journal, bob, 3, 3, &got), FZN_LOG_ERR_GONE,
		           "while at the position, and not held, it is gone");
		/* WHAT IS HELD IS SERVED WHATEVER THE POSITION SAYS. The log is
		 * the authority on its own contents; the journal only settles
		 * what is NOT there. Six is held and is above `received`. */
		expect_err(fzn_log_get(&back, &journal, bob, 3, 6, &got), FZN_LOG_OK,
		           "an entry held above the position is still served");
		expect(got != NULL && got->seq == 6, "and it is the right one");
	}

	{
		fzn_log_t mixed;
		fzn_log_entry_t slots[4];
		static const uint64_t ARRIVAL[4] = { 3, 1, 2, 4 };

		/* A HOLE IN THE MIDDLE. Append takes any order and eviction takes
		 * the oldest by APPEND order, so the entry that leaves need not
		 * be the lowest sequence. Three arrived first and so leaves
		 * first, leaving one, two and four held. The old rule read three
		 * as "above the oldest held, therefore not yet arrived" and
		 * answered ABSENT for something this host had received and thrown
		 * away -- and no floor could have done better, since a floor
		 * describes a prefix and this is not one. */
		expect(fzn_log_init(&mixed, slots, 4) == FZN_LOG_OK, "a log to put a hole in");
		expect(fzn_journal_anchor(&journal, bob, 4, 0) == FZN_JOURNAL_OK, "bob's stream four");
		for (size_t i = 0; i < 4; i++) {
			make_on(&rec, 0xb2, 4, ARRIVAL[i]);
			expect(fzn_log_append(&mixed, &rec) == FZN_LOG_OK, "arriving out of order");
		}
		for (uint64_t seq = 1; seq <= 4; seq++)
			expect(fzn_journal_admit(&journal, bob, 4, seq) == FZN_JOURNAL_OK,
			       "the journal takes them in order and reaches four");

		make_on(&rec, 0xb2, 5, 9);
		expect(fzn_log_append(&mixed, &rec) == FZN_LOG_OK, "another stream's entry evicts one");
		expect(fzn_log_dropped(&mixed) == 1, "and it was the first to arrive");

		fzn_log_range(&mixed, bob, 4, &first, &last);
		expect(first == 1 && last == 4, "the hole is invisible in the range");
		expect_err(fzn_log_get(&mixed, &journal, bob, 4, 3, &got), FZN_LOG_ERR_GONE,
		           "a hole in the middle is gone");
		expect_err(fzn_log_get(&mixed, &journal, bob, 4, 2, &got), FZN_LOG_OK,
		           "its neighbours are still held");
		expect_err(fzn_log_get(&mixed, &journal, bob, 4, 5, &got), FZN_LOG_ERR_ABSENT,
		           "and one above the position is still absent");
	}

	/* A JOURNAL THIS MODULE WILL NOT READ IS MALFORMED, not a reason to
	 * guess. `fzn_journal_next` answers 1 for a journal it refuses AND for
	 * a stream nobody follows, so a log that took that at face value would
	 * call every eviction ABSENT: the ask-for-ever loop again, entered
	 * through a corrupt argument this time rather than through a wrong
	 * rule. Same discipline as the corrupt `used` above -- refused at the
	 * entry point that reads it. */
	{
		fzn_journal_t broken = journal;

		expect_err(fzn_log_get(&log, NULL, alice, 0, 1, &got), FZN_LOG_ERR_MALFORMED,
		           "asking with no position at all");
		broken.used = broken.capacity + 1u;
		expect_err(fzn_log_get(&log, &broken, alice, 0, 1, &got), FZN_LOG_ERR_MALFORMED,
		           "asking against a corrupt position");
		broken = journal;
		broken.entries = NULL;
		expect_err(fzn_log_get(&log, &broken, alice, 0, 1, &got), FZN_LOG_ERR_MALFORMED,
		           "asking against a position with no entries");
	}

	/* THE ONE SEQUENCE AT THE TOP THAT IS ANSWERED CONSERVATIVELY, pinned
	 * so that log.h's paragraph about it is not read as hypothetical.
	 * `fzn_journal_next` saturates at UINT64_MAX rather than wrapping to
	 * the reserved zero, so an exhausted stream and one a single step below
	 * it give the same answer and this module cannot tell them apart.
	 * ABSENT is the safe half of that ambiguity: one more request, rather
	 * than an `fzn_journal_anchor` nobody can undo. If `record/journal.h`
	 * ever publishes `received` itself, this case becomes GONE -- and this
	 * comment is what says the change is allowed rather than a regression. */
	{
		expect(fzn_journal_anchor(&journal, bob, 21, UINT64_MAX) == FZN_JOURNAL_OK,
		       "a stream run to the very top");
		expect_err(fzn_log_get(&log, &journal, bob, 21, UINT64_MAX - 1u, &got),
		           FZN_LOG_ERR_GONE, "one below the top is gone as usual");
		expect_err(fzn_log_get(&log, &journal, bob, 21, UINT64_MAX, &got), FZN_LOG_ERR_ABSENT,
		           "and the top itself is answered absent, the safe half");
	}

	/* TWO ISSUERS THAT AGREE ON EVERY BYTE BUT THE LAST.
	 *
	 * Every other identity in this file is `memset(buf, seed, 32)`, so any
	 * two of them differ at byte 0 and a comparison of ONE byte tells them
	 * apart exactly as well as a comparison of thirty-two. That makes the
	 * length in `fzn_ct_memeq(entries[i].issuer, issuer, FZN_PUBKEY_LEN)`
	 * unfalsifiable: truncating it to 1 left this whole suite green, in
	 * both `find` and `fzn_log_range`, measured before this case was
	 * written.
	 *
	 * WHAT WOULD FAIL OPEN IS A CROSS-ISSUER ANSWER. `find` matches on
	 * (issuer, stream, seq), so a short compare makes one issuer's entry
	 * answer a question about another's -- the same shape as the
	 * cross-root revocation defect fixed today, one layer up, and a log is
	 * where a consumer looks to decide what happened.
	 *
	 * The pair below is built so that ONLY a full-length comparison
	 * separates them. `trust/test/trust_test.c` already had this shape --
	 * a second root differing in a single byte -- which is why truncating
	 * its comparison IS caught. This is that case, brought to `log/`. */
	{
		uint8_t twin_a[FZN_PUBKEY_LEN], twin_b[FZN_PUBKEY_LEN];
		fzn_record_t ra, rb;
		fzn_log_t tlog;
		fzn_log_entry_t tentries[4];
		fzn_journal_t tjournal;
		fzn_journal_entry_t tpositions[4];
		const fzn_log_entry_t *hit = NULL;

		memset(twin_a, 0x5a, sizeof(twin_a));
		memset(twin_b, 0x5a, sizeof(twin_b));
		twin_b[FZN_PUBKEY_LEN - 1u] ^= 0x01u;

		expect(memcmp(twin_a, twin_b, FZN_PUBKEY_LEN - 1u) == 0,
		       "the twins must agree on every byte but the last, or this "
		       "case is not testing what it says");
		expect(memcmp(twin_a, twin_b, FZN_PUBKEY_LEN) != 0,
		       "the twins must differ somewhere, or nothing here can fail");

		fzn_log_init(&tlog, tentries, 4);
		fzn_journal_init(&tjournal, tpositions, 4);
		expect(fzn_journal_anchor(&tjournal, twin_a, 0, 0) == FZN_JOURNAL_OK,
		       "following the first twin");
		expect(fzn_journal_anchor(&tjournal, twin_b, 0, 0) == FZN_JOURNAL_OK,
		       "following the second twin");

		/* Same stream, same sequence, different issuer. A truncated
		 * comparison cannot tell these two entries apart at all. */
		expect(fixture_record(&ra, twin_a, twin_a, 0, 3, 1, BODIES[1], sizeof(BODIES[0])),
		       "building the first twin's record");
		expect(fixture_record(&rb, twin_b, twin_b, 0, 3, 1, BODIES[2], sizeof(BODIES[0])),
		       "building the second twin's record");
		expect(fzn_log_append(&tlog, &ra) == FZN_LOG_OK, "appending the first twin's");
		expect(fzn_log_append(&tlog, &rb) == FZN_LOG_OK, "appending the second twin's");
		expect(fzn_journal_admit(&tjournal, twin_a, 0, 1) == FZN_JOURNAL_OK,
		       "admitting the first twin's position");
		expect(fzn_journal_admit(&tjournal, twin_b, 0, 1) == FZN_JOURNAL_OK,
		       "admitting the second twin's position");

		expect_err(fzn_log_get(&tlog, &tjournal, twin_a, 0, 1, &hit), FZN_LOG_OK,
		           "the first twin's entry is found");
		expect(hit && memcmp(hit->issuer, twin_a, FZN_PUBKEY_LEN) == 0,
		       "a lookup for the first twin returned an entry belonging to the "
		       "second -- the issuer comparison is not reading the whole key");

		hit = NULL;
		expect_err(fzn_log_get(&tlog, &tjournal, twin_b, 0, 1, &hit), FZN_LOG_OK,
		           "the second twin's entry is found");
		expect(hit && memcmp(hit->issuer, twin_b, FZN_PUBKEY_LEN) == 0,
		       "a lookup for the second twin returned an entry belonging to the "
		       "first -- the issuer comparison is not reading the whole key");

		/* AND THE SAME FOR `fzn_log_range`, WHICH IS A SEPARATE LOOP OVER
		 * A SEPARATE COMPARISON. Truncating log.c's OTHER `fzn_ct_memeq`
		 * left the case above green -- one vacuous comparison per
		 * function, and closing one says nothing about the other.
		 *
		 * Give the second twin a sequence the first does not have. Then a
		 * short comparison folds the two issuers together and reports a
		 * range of 1..2 for a twin that holds only one of them. */
		{
			fzn_record_t rb2;
			uint64_t lo = 0, hi = 0;

			expect(fixture_record(&rb2, twin_b, twin_b, 0, 3, 2, BODIES[3],
			                      sizeof(BODIES[0])),
			       "building the second twin's later record");
			expect(fzn_log_append(&tlog, &rb2) == FZN_LOG_OK,
			       "appending the second twin's later record");

			fzn_log_range(&tlog, twin_a, 0, &lo, &hi);
			expect(lo == 1u && hi == 1u,
			       "the first twin's range swallowed a sequence only the second "
			       "holds -- fzn_log_range is not reading the whole issuer");

			lo = hi = 0;
			fzn_log_range(&tlog, twin_b, 0, &lo, &hi);
			expect(lo == 1u && hi == 2u,
			       "the second twin's range is not its own two sequences");
		}

		/* AND `fzn_log_read_since`, A THIRD LOOP OVER A THIRD
		 * COMPARISON -- the selection pass that takes the lowest
		 * sequence still above what has been drained. Truncating it to
		 * one byte left BOTH cases above green, which is the same
		 * lesson a third time: a vacuous comparison is one per
		 * FUNCTION, not one per file, and closing two says nothing
		 * about the next.
		 *
		 * WHAT FAILS OPEN HERE IS A READER'S CATCH-UP. `read_since` is
		 * how a consumer drains a stream it has fallen behind on, so a
		 * short compare hands it another issuer's records under the
		 * issuer it asked for -- provenance forged at the one call a
		 * consumer trusts to say what an issuer wrote. The first twin
		 * holds one sequence and the second holds two, so a folded
		 * comparison returns two records to a twin that wrote one. */
		{
			const fzn_log_entry_t *drained[4] = { NULL, NULL, NULL, NULL };
			size_t foreign = 0;
			size_t n;

			n = fzn_log_read_since(&tlog, twin_a, 0, 0, drained, 4);
			expect(n == 1u,
			       "reading since 0 for the first twin returned more than the "
			       "one record it wrote -- fzn_log_read_since is not reading "
			       "the whole issuer");
			/* Counted and asserted once, rather than a check per
			 * entry: a loop of checks inflates the total without
			 * testing anything more. */
			for (size_t i = 0; i < n; i++) {
				if (!drained[i] ||
				    memcmp(drained[i]->issuer, twin_a, FZN_PUBKEY_LEN) != 0)
					foreign++;
			}
			expect(foreign == 0,
			       "fzn_log_read_since handed the first twin a record belonging "
			       "to the second");

			n = fzn_log_read_since(&tlog, twin_b, 0, 0, drained, 4);
			expect(n == 2u,
			       "reading since 0 for the second twin is not its own two "
			       "records");
		}
	}

	/* INIT LEAVES THE CALLER'S ENTRY ARRAY IN A KNOWN STATE.
	 *
	 * No lookup in log.c can observe it -- every loop there is bounded by
	 * `used` -- so removing the zeroing fails nothing, which is how
	 * `make sabotage` found it. It is held anyway because what would remove
	 * it is somebody measuring exactly that and concluding it is dead, and a
	 * later lookup that scans `capacity` would need it. project.md sec 39
	 * has the reasoning once; three sibling modules carry the same eight
	 * lines and the same case.
	 *
	 * Determinism is asserted rather than a value: init from dirty memory
	 * must equal init from clean. The header promises nothing about what a
	 * fresh entry contains, and this case is not the place to invent it. */
	{
		fzn_log_t from_dirty, from_clean;
		fzn_log_entry_t dirty_entries[3], clean_entries[3];

		memset(dirty_entries, 0xab, sizeof(dirty_entries));
		memset(clean_entries, 0, sizeof(clean_entries));
		expect(memcmp(dirty_entries, clean_entries, sizeof(dirty_entries)) != 0,
		       "the two arrays start equal, so the comparison below cannot fail");

		expect(fzn_log_init(&from_dirty, dirty_entries, 3) == FZN_LOG_OK,
		       "init refused a dirty array");
		expect(fzn_log_init(&from_clean, clean_entries, 3) == FZN_LOG_OK,
		       "init refused a clean array");
		expect(memcmp(dirty_entries, clean_entries, sizeof(dirty_entries)) == 0,
		       "init left the caller's bytes in the entry array, so what a fresh "
		       "table holds depends on what its memory held");
	}

	printf("log_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
