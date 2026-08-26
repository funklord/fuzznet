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
 *   - `journal.h`: a position advances by exactly one, never on a refusal;
 *     `next` is always received + 1; `applied` never exceeds `received`, so
 *     `pending` can never underflow.
 *   - `state.h`: a later record from the same issuer supersedes and an older
 *     one never does; a different issuer is refused unless resolved; the
 *     entry always names an issuer that actually succeeded.
 *   - `log.h`: `GONE` exactly below the oldest held, `ABSENT` above the
 *     newest, and `dropped` only ever increases.
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
	uint64_t holder_seq[SUBJECTS][KINDS];
	uint64_t dropped;
};

static void identity(uint8_t out[FZN_PUBKEY_LEN], uint8_t which)
{
	memset(out, (int)(0x40u + which), FZN_PUBKEY_LEN);
}

/* The log's promises, in their own function so that the checks are not four
 * levels deep inside a switch -- which made every continuation line ambiguous
 * to the style gate and, more to the point, to a reader. */
static int log_step(fzn_log_t *log, const fzn_record_t *rec,
                    const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream)
{
	const fzn_log_entry_t *got = NULL;
	uint64_t first = 0, last = 0;
	uint64_t before = fzn_log_dropped(log);

	(void)fzn_log_append(log, rec);
	if (fzn_log_dropped(log) < before)
		return 1; /* dropped went backwards */

	fzn_log_range(log, issuer, stream, &first, &last);
	if (first == 0)
		return 0;
	if (first > last)
		return 1;
	/* GONE exactly below the oldest held, ABSENT above the newest. */
	if (first > 1u && fzn_log_get(log, issuer, stream, first - 1u, &got) != FZN_LOG_ERR_GONE)
		return 1;
	if (fzn_log_get(log, issuer, stream, last + 1u, &got) != FZN_LOG_ERR_ABSENT)
		return 1;

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
	struct model m;
	struct cursor c = { data, size, 0 };

	if (fzn_journal_init(&journal, jentries, ISSUERS * STREAMS) != FZN_JOURNAL_OK)
		return 1;
	if (fzn_state_init(&state, sentries, SLOTS) != FZN_STATE_OK)
		return 1;
	if (fzn_log_init(&log, lentries, SLOTS) != FZN_LOG_OK)
		return 1;
	memset(&m, 0, sizeof(m));
	for (size_t s = 0; s < SUBJECTS; s++)
		for (size_t k = 0; k < KINDS; k++)
			m.holder[s][k] = -1;
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
		fzn_record_t rec;

		identity(issuer, iss);
		memset(subject, (int)(0x80u + subj_i), sizeof(subject));

		memset(&rec, 0, sizeof(rec));
		memcpy(rec.issuer, issuer, FZN_PUBKEY_LEN);
		memcpy(rec.subject, subject, FZN_SUBJECT_LEN);
		rec.stream = str;
		rec.kind = kind_i;
		rec.seq = seq;
		rec.body = bodies[seq % 16u];
		rec.body_len = sizeof(bodies[0]);

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
			uint64_t *hseq = &m.holder_seq[subj_i][kind_i];

			if (err == FZN_STATE_OK) {
				/* Either nothing held it, or the same issuer did
				 * with a strictly older sequence. */
				if (*holder != -1 && *holder != (int)iss)
					return 1;
				if (*holder == (int)iss && seq <= *hseq)
					return 1;
				*holder = (int)iss;
				*hseq = seq;
			} else if (err == FZN_STATE_ERR_CONFLICT) {
				if (*holder == -1 || *holder == (int)iss)
					return 1;
			} else if (err == FZN_STATE_ERR_STALE) {
				if (*holder != (int)iss || seq > *hseq)
					return 1;
			}
			break;
		}
		case 4: { /* state resolve */
			if (fzn_state_resolve(&state, &rec) == FZN_STATE_OK) {
				m.holder[subj_i][kind_i] = (int)iss;
				m.holder_seq[subj_i][kind_i] = seq;
			}
			break;
		}
		default: /* log append and read back */
			if (log_step(&log, &rec, issuer, str))
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
