/* `record/`, `state/` and `log/` driven together under a coverage-guided
 * fuzzer, against a model.
 *
 * WHY TOGETHER. Each has unit tests and one simulation scenario, which is
 * exactly the coverage profile that hides a defect between modules: a
 * consumer admits a record into the journal, applies it to the state and
 * appends it to the log, and an inconsistency among those three is invisible
 * to any test that exercises one of them.
 *
 * THE MODEL IS WRITTEN FROM THE HEADERS, not from the implementations, so
 * that a mistake shared with the code cannot cancel itself out. It is
 * deliberately partial: it tracks the things the headers PROMISE and ignores
 * everything else.
 *
 *   - `record.h`: a record is a VIEW over the bytes it was encoded into, so
 *     every record this harness drives is built by `fzn_record_sign` and read
 *     back by `fzn_record_open`. That is not decoration. The harness used to
 *     assemble the struct field by field, which is the shape that let a
 *     decoded field disagree with what was signed -- and a model driving a
 *     record no encoder could have produced is a model of nothing.
 *   - `journal.h`: a position advances by exactly one, never on a refusal;
 *     `next` is always received + 1; `applied` never exceeds `received`, so
 *     `pending` can never underflow.
 *   - `state.h`: a later record from the same WRITER supersedes and an older
 *     one never does; a different issuer is refused as CONFLICT and the same
 *     issuer on another stream as CROSS_STREAM, unless resolved; the entry
 *     always names a writer that actually succeeded.
 *
 *     A writer is (issuer, stream). This clause used to say "issuer", which
 *     was the module's own defect written into the model -- two independent
 *     sequence spaces compared as one.
 *   - `log.h`: `GONE` for a sequence the journal says was RECEIVED and the
 *     log no longer holds, `ABSENT` for one that never arrived, and
 *     `dropped` only ever increases.
 *
 *     This clause used to read "GONE exactly below the oldest held, ABSENT
 *     above the newest" -- the module's own defect, written into the oracle,
 *     so the fuzzer could never have found it and would have rejected the
 *     fix. That is `evidence.md`'s independence rule: a model derived from
 *     the implementation is one witness wearing two hats.
 *
 * THE UNDERFLOW IS THE ONE WORTH NAMING. `fzn_journal_pending` returns
 * `received - applied` as an unsigned value. If confirmation could ever
 * outrun reception the result would not be negative, it would be enormous --
 * and a consumer sizing anything from it would then be told it is eighteen
 * quintillion records behind.
 */

#include "../../log/log.h"
#include "../../state/state.h"
#include "../journal.h"
#include "../record.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ISSUERS  3u
#define STREAMS  2u
#define SUBJECTS 3u
#define KINDS    2u
#define SLOTS    4u

struct cursor {
	const uint8_t *p;
	size_t n, i;
};

static uint8_t take8(struct cursor *c)
{
	return c->i < c->n ? c->p[c->i++] : 0u;
}

/* What the headers say should be true. */
struct model {
	uint64_t received[ISSUERS][STREAMS];
	uint64_t applied[ISSUERS][STREAMS];
	int following[ISSUERS][STREAMS];
	/* Current holder of each (subject, kind), or -1 for nothing set. */
	int holder[SUBJECTS][KINDS];
	/* THE WRITER IS (ISSUER, STREAM), NOT THE ISSUER. `state.h` orders by
	 * sequence within one writer, and `record.h` says a sequence is unique
	 * within (issuer, stream) and NOT within issuer -- so a model keyed by
	 * issuer alone compares two independent sequence spaces, which is the
	 * defect `state/` was just fixed for. A model carrying it could not
	 * check the fix and would reject it. */
	int holder_stream[SUBJECTS][KINDS];
	uint64_t holder_seq[SUBJECTS][KINDS];
	uint64_t dropped;
};

static void identity(uint8_t out[FZN_PUBKEY_LEN], uint8_t which)
{
	memset(out, (int)(0x40u + which), FZN_PUBKEY_LEN);
}

/* A SIGNER THAT ANSWERS THE SAME THING EVERY TIME, because this harness is
 * about ORDER and never about authenticity: nothing here calls
 * `fzn_record_verify`, and a record's journal position, its precedence in a
 * cell and its place in the log are decided without one. What the harness
 * needs from `fzn_record_sign` is the ENCODER -- records built field by field
 * are exactly what `record.h` stopped being able to represent, and building
 * them through the real encoder is what keeps this model driving the same
 * bytes a consumer would.
 *
 * The binding between a field and a signature is measured in
 * `record/test/record_test.c`, one mutation per field, which is where a
 * constant like this would be worthless. */
static int fuzz_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	(void)ctx;
	(void)msg;
	(void)msg_len;
	memset(sig, 0x5a, FZN_SIG_LEN);

	return 1;
}

/* The log's promises, in their own function so that the checks are not four
 * levels deep inside a switch -- which made every continuation line ambiguous
 * to the style gate and, more to the point, to a reader. */
static int log_step(fzn_log_t *log, const fzn_journal_t *journal, const fzn_record_t *rec,
                    const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream)
{
	const fzn_log_entry_t *got = NULL;
	uint64_t first = 0, last = 0;
	uint64_t before = fzn_log_dropped(log);

	(void)fzn_log_append(log, rec);
	if (fzn_log_dropped(log) < before)
		return 1; /* dropped went backwards */

	fzn_log_range(log, issuer, stream, &first, &last);
	if (first != 0 && first > last)
		return 1;

	/* THE VERDICT COMES FROM THE POSITION, NOT FROM WHAT IS HELD, and the
	 * check runs unconditionally rather than bailing out when the stream
	 * holds nothing.
	 *
	 * `if (first == 0) return 0;` used to sit above this, so the harness
	 * gave up at exactly the state the module is about -- a stream evicted
	 * down to nothing, which is the case `log.h` says GONE exists for. The
	 * two assertions below it were skipped whenever they would have
	 * mattered most. */
	{
		uint64_t next = fzn_journal_next(journal, issuer, stream);

		/* Anything the journal has not received cannot have been
		 * evicted, whether or not the log holds something older. */
		if (fzn_log_get(log, journal, issuer, stream, next, &got) != FZN_LOG_ERR_ABSENT)
			return 1;

		/* And a received sequence the log does not hold was evicted.
		 * `next - 1` is the newest received; walk down from it and the
		 * first one not held must say GONE rather than ABSENT. */
		for (uint64_t seq = next > 1u ? next - 1u : 0u; seq >= 1u; seq--) {
			fzn_log_err_t err = fzn_log_get(log, journal, issuer, stream, seq, &got);

			if (err == FZN_LOG_OK)
				continue;
			if (err != FZN_LOG_ERR_GONE)
				return 1;
			break;
		}
	}

	return 0;
}

static int drive(const uint8_t *data, size_t size)
{
	fzn_journal_t journal;
	fzn_journal_entry_t jentries[ISSUERS * STREAMS];
	fzn_state_t state;
	fzn_state_entry_t sentries[SLOTS];
	fzn_log_t log;
	fzn_log_entry_t lentries[SLOTS];
	static uint8_t bodies[16][4];
	/* THE RECORDS' OWN STORAGE, AND IT HAS TO OUTLIVE THE ENTRIES. A state
	 * cell and a log entry point INTO a record's bytes (see `state.h`), so
	 * the buffer a record was opened from cannot be a loop local. A ring of
	 * sixteen, indexed the way `bodies` already was, keeps a bounded amount
	 * of storage alive for the whole run; nothing here reads a body back,
	 * so reuse is invisible and boundedness is what matters. */
	static uint8_t encoded[16][FZN_RECORD_MAX_LEN];
	fzn_sign_ops_t sign = { NULL, fuzz_sign, NULL };
	size_t step = 0;
	struct model m;
	struct cursor c = { data, size, 0 };

	if (fzn_journal_init(&journal, jentries, ISSUERS * STREAMS) != FZN_JOURNAL_OK)
		return 1;
	if (fzn_state_init(&state, sentries, SLOTS) != FZN_STATE_OK)
		return 1;
	if (fzn_log_init(&log, lentries, SLOTS) != FZN_LOG_OK)
		return 1;
	memset(&m, 0, sizeof(m));
	for (size_t s = 0; s < SUBJECTS; s++) {
		for (size_t k = 0; k < KINDS; k++) {
			m.holder[s][k] = -1;
			m.holder_stream[s][k] = -1;
		}
	}
	for (size_t i = 0; i < 16; i++)
		memset(bodies[i], (int)i, sizeof(bodies[0]));

	while (c.i < c.n) {
		uint8_t op = take8(&c);
		uint8_t iss = take8(&c) % ISSUERS;
		uint8_t str = take8(&c) % STREAMS;
		uint64_t seq = 1u + (take8(&c) % 8u);
		uint8_t subj_i = take8(&c) % SUBJECTS;
		uint8_t kind_i = take8(&c) % KINDS;
		uint8_t issuer[FZN_PUBKEY_LEN], subject[FZN_SUBJECT_LEN];
		uint8_t *buf = encoded[step % 16u];
		size_t rec_len = 0;
		fzn_record_t rec;

		step++;
		identity(issuer, iss);
		memset(subject, (int)(0x80u + subj_i), sizeof(subject));

		/* THROUGH THE ENCODER, NOT FIELD BY FIELD. A record is a view
		 * over the bytes its signature covers, so the only way to make
		 * one is to encode it -- and a harness that assembled a struct
		 * by hand would be driving a shape no consumer can produce. */
		if (fzn_record_sign(issuer, subject, str, kind_i, seq, seq, bodies[seq % 16u],
		                    sizeof(bodies[0]), &sign, buf, FZN_RECORD_MAX_LEN,
		                    &rec_len) != FZN_RECORD_OK)
			return 1;
		if (fzn_record_open(buf, rec_len, &rec) != FZN_RECORD_OK)
			return 1;

		switch (op % 6u) {
		case 0: { /* journal admit */
			uint64_t before = m.received[iss][str];
			fzn_journal_err_t err = fzn_journal_admit(&journal, issuer, str, seq);

			if (err == FZN_JOURNAL_OK) {
				/* ADMITTING NEVER ADOPTS. A stream nobody chose to
				 * follow cannot be opened by a record arriving on
				 * it -- not even at sequence 1, which used to open
				 * one implicitly. This is the model's whole share
				 * of that change, and it is the clause that would
				 * catch it being undone. */
				if (!m.following[iss][str])
					return 1;
				/* A position advances by EXACTLY one. */
				if (seq != before + 1u)
					return 1;
				m.received[iss][str] = seq;
			} else if (m.received[iss][str] != before) {
				return 1; /* a refusal moved the position */
			}
			break;
		}
		case 1: { /* journal anchor */
			uint64_t where = seq % 2u ? seq : 0u;
			fzn_journal_err_t err;

			err = fzn_journal_anchor(&journal, issuer, str, where);

			if (err == FZN_JOURNAL_OK) {
				m.following[iss][str] = 1;
				if (seq % 2u)
					m.received[iss][str] = seq;
			}
			break;
		}
		case 2: { /* journal confirm */
			uint64_t want = seq % (m.received[iss][str] + 2u);
			fzn_journal_err_t err = fzn_journal_confirm(&journal, issuer, str, want);

			if (err == FZN_JOURNAL_OK) {
				if (want > m.received[iss][str])
					return 1; /* confirmed past what arrived */
				m.applied[iss][str] = want;
			}
			break;
		}
		case 3: { /* state apply */
			fzn_state_err_t err = fzn_state_apply(&state, &rec);
			int *holder = &m.holder[subj_i][kind_i];
			int *hstream = &m.holder_stream[subj_i][kind_i];
			uint64_t *hseq = &m.holder_seq[subj_i][kind_i];
			int same_writer = *holder == (int)iss && *hstream == (int)str;

			if (err == FZN_STATE_OK) {
				/* Either nothing held it, or the same WRITER did
				 * with a strictly older sequence. */
				if (*holder != -1 && !same_writer)
					return 1;
				if (same_writer && seq <= *hseq)
					return 1;
				*holder = (int)iss;
				*hstream = (int)str;
				*hseq = seq;
			} else if (err == FZN_STATE_ERR_CONFLICT) {
				/* Another ISSUER. */
				if (*holder == -1 || *holder == (int)iss)
					return 1;
			} else if (err == FZN_STATE_ERR_CROSS_STREAM) {
				/* The same issuer on a different stream -- two
				 * sequence spaces with no shared zero, so there
				 * is no fact about which is newer. */
				if (*holder != (int)iss || *hstream == (int)str)
					return 1;
			} else if (err == FZN_STATE_ERR_STALE) {
				if (!same_writer || seq > *hseq)
					return 1;
			}
			break;
		}
		case 4: { /* state resolve */
			if (fzn_state_resolve(&state, &rec) == FZN_STATE_OK) {
				m.holder[subj_i][kind_i] = (int)iss;
				m.holder_stream[subj_i][kind_i] = (int)str;
				m.holder_seq[subj_i][kind_i] = seq;
			}
			break;
		}
		default: /* log append and read back */
			if (log_step(&log, &journal, &rec, issuer, str))
				return 1;
			break;
		}

		/* AFTER EVERY OPERATION, the cross-cutting promises. */
		for (uint8_t i = 0; i < ISSUERS; i++) {
			for (uint8_t s = 0; s < STREAMS; s++) {
				uint8_t id[FZN_PUBKEY_LEN];
				uint64_t next, pending;

				identity(id, i);
				next = fzn_journal_next(&journal, id, s);
				pending = fzn_journal_pending(&journal, id, s);

				if (next != m.received[i][s] + 1u)
					return 1;
				/* THE UNDERFLOW. Unsigned, so a confirmation
				 * outrunning reception would be enormous rather
				 * than negative. */
				if (pending > m.received[i][s])
					return 1;
				if (pending != m.received[i][s] - m.applied[i][s])
					return 1;
			}
		}
		if (fzn_state_count(&state) > SLOTS)
			return 1;
	}

	return 0;
}

#ifdef FZN_LIBFUZZER

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (drive(data, size))
		__builtin_trap();
	return 0;
}

#else

static const uint8_t CASE_SEQ[] = { 0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 3, 0, 0 };
static const uint8_t CASE_STATE[] = { 3, 0, 0, 1, 0, 0, 3, 1, 0, 5, 0, 0, 4, 1, 0, 5, 0, 0 };
static const uint8_t CASE_LOG[] = { 5, 0, 0, 1, 0, 0, 5, 0, 0, 2, 0, 0, 5, 0, 0, 3, 0, 0,
	                            5, 0, 0, 4, 0, 0, 5, 0, 0, 5, 0, 0 };

int main(int argc, char **argv)
{
	static uint8_t buf[65536];
	int failures = 0, cases = 0;

	if (argc > 1) {
		for (int i = 1; i < argc; i++) {
			FILE *f = fopen(argv[i], "rb");
			size_t n;

			if (!f) {
				printf("  FAIL: cannot open %s\n", argv[i]);
				failures++;
				continue;
			}
			n = fread(buf, 1, sizeof(buf), f);
			fclose(f);
			cases++;
			if (drive(buf, n)) {
				printf("  FAIL: %s broke a promise the headers make\n", argv[i]);
				failures++;
			}
		}
	} else {
		const uint8_t *builtin[] = { CASE_SEQ, CASE_STATE, CASE_LOG };
		const size_t sizes[] = { sizeof(CASE_SEQ), sizeof(CASE_STATE), sizeof(CASE_LOG) };

		for (size_t i = 0; i < 3; i++) {
			cases++;
			if (drive(builtin[i], sizes[i])) {
				printf("  FAIL: built-in case %zu broke a promise\n", i);
				failures++;
			}
		}
	}

	printf("record_guided: %d case(s), %d failure(s)\n", cases, failures);
	return failures == 0 ? 0 : 1;
}

#endif
