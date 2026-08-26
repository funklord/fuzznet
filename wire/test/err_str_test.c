/* Every error code this library hands back, rendered.
 *
 * Seven public enums carry forty codes between them, and until these
 * functions existed **nothing rendered any of them**. situ's generated header
 * ships `situ_err_str`; this library shipped nothing, so a consumer wanting
 * to log why a frame was refused had to write its own switch -- and a
 * consumer's switch goes stale silently the day a code is added here.
 *
 * WHAT THE COMPILER ALREADY COVERS, so that this file does not duplicate it.
 * Each renderer is a switch with no `default:`, which is what makes
 * `-Wswitch` warn about an enumerator with no case. Verified rather than
 * assumed: adding a code to `fzn_split_err_t` and no case for it produces
 * "enumeration value 'FZN_SPLIT_ERR_INVENTED' not handled in switch".
 *
 * SO THIS FILE TESTS WHAT THE COMPILER CANNOT SEE, which is three things:
 *
 *   - **Distinctness.** Two codes rendering the same text is a copy-paste in
 *     a switch, it compiles perfectly, and it destroys the one thing these
 *     functions are for. `FZN_SEAL_ERR_TAG` and `FZN_SEAL_ERR_COMMITMENT`
 *     are distinct on purpose -- seal.h says so -- and a reader who cannot
 *     tell them apart in a log has lost that distinction no matter how
 *     carefully the enum preserved it.
 *   - **Never NULL**, including for a value that is not an enumerator, since
 *     the header promises a caller may printf the result without a check.
 *   - **The fallback is reached, and is not any real code's text.** A value
 *     off the end must render "unknown" and nothing else may.
 *
 * HOW THE COUNT IS CHECKED, and why it is not a hand-written list of names.
 * A list of enumerators here would be an eighth place to keep in step, and
 * it would drift exactly like the consumer switch this whole change exists
 * to spare people. Instead each renderer is walked from zero in its own
 * direction until the fallback answers, which measures how many codes render
 * as themselves, and that count is pinned. Adding a code WITH a case moves
 * the count and fails here, which makes the addition deliberate; adding one
 * WITHOUT a case is the compiler's half above.
 *
 * The error enums run 0, -1, -2 ...; `fzn_peer_verdict_t` runs 0, 1, 2. The
 * direction is per subject rather than assumed, because a verdict is not an
 * error and this file would otherwise quietly test three codes as one.
 */

#include "../../chain/chain.h"
#include "../../chunk/reassembly.h"
#include "../../chunk/split.h"
#include "../../frame/freshness.h"
#include "../../local/peer.h"
#include "../../record/journal.h"
#include "../../record/sync.h"
#include "../../state/state.h"
#include "../../log/log.h"
#include "../../link/link.h"
#include "../../sched/sched.h"
#include "../../trust/trust.h"
#include "../../record/record.h"
#include "../../session/commitment.h"
#include "../relay.h"
#include "../seal.h"

#include <stdio.h>
#include <string.h>

#define FZN_FALLBACK "unknown"
#define FZN_SCAN_CAP 32

static int failures;
static int checks;

static void expect(int ok, const char *subject, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL: %s: %s\n", subject, what);
	}
}

/* One wrapper per enum, taking `int`, because the subjects below are walked
 * through a common function pointer and a cast between function types with
 * different parameter types would not be one this library should rely on. */
static const char *r_chain(int v) { return fzn_err_str((fzn_err_t)v); }
static const char *r_commitment(int v) { return fzn_commitment_err_str((fzn_commitment_err_t)v); }
static const char *r_fresh(int v) { return fzn_fresh_err_str((fzn_fresh_err_t)v); }
static const char *r_reasm(int v) { return fzn_reasm_err_str((fzn_reasm_err_t)v); }
static const char *r_split(int v) { return fzn_split_err_str((fzn_split_err_t)v); }
static const char *r_seal(int v) { return fzn_seal_err_str((fzn_seal_err_t)v); }
static const char *r_peer(int v) { return fzn_peer_verdict_str((fzn_peer_verdict_t)v); }
static const char *r_record(int v) { return fzn_record_err_str((fzn_record_err_t)v); }
static const char *r_journal(int v) { return fzn_journal_err_str((fzn_journal_err_t)v); }
static const char *r_sync(int v) { return fzn_sync_err_str((fzn_sync_err_t)v); }
static const char *r_state(int v) { return fzn_state_err_str((fzn_state_err_t)v); }
static const char *r_trust(int v) { return fzn_trust_err_str((fzn_trust_err_t)v); }
static const char *r_log(int v) { return fzn_log_err_str((fzn_log_err_t)v); }
static const char *r_relay(int v) { return fzn_relay_err_str((fzn_relay_err_t)v); }
static const char *r_sched(int v) { return fzn_sched_err_str((fzn_sched_err_t)v); }
static const char *r_link(int v) { return fzn_link_err_str((fzn_link_err_t)v); }

struct subject {
	const char *name;
	const char *(*render)(int);
	int step;
	int codes;
};

/* The pinned counts. Each is the number of enumerators in that type, and
 * moving one without moving the other is the failure this table catches. */
static const struct subject SUBJECTS[] = {
	{ "fzn_err_str", r_chain, -1, 8 },
	{ "fzn_commitment_err_str", r_commitment, -1, 4 },
	{ "fzn_fresh_err_str", r_fresh, -1, 6 },
	{ "fzn_reasm_err_str", r_reasm, -1, 8 },
	{ "fzn_split_err_str", r_split, -1, 4 },
	{ "fzn_seal_err_str", r_seal, -1, 7 },
	{ "fzn_peer_verdict_str", r_peer, 1, 3 },
	{ "fzn_record_err_str", r_record, -1, 5 },
	{ "fzn_journal_err_str", r_journal, -1, 7 },
	{ "fzn_sync_err_str", r_sync, -1, 2 },
	{ "fzn_state_err_str", r_state, -1, 6 },
	{ "fzn_trust_err_str", r_trust, -1, 4 },
	{ "fzn_log_err_str", r_log, -1, 5 },
	{ "fzn_relay_err_str", r_relay, -1, 4 },
	{ "fzn_sched_err_str", r_sched, -1, 3 },
	{ "fzn_link_err_str", r_link, -1, 5 },
};

static void check_subject(const struct subject *s)
{
	const char *seen[FZN_SCAN_CAP];
	int n = 0;

	/* Walk until the fallback answers, which is where this type's codes
	 * stop. Capped so that a renderer which never falls back -- one that
	 * grew a `default:` returning something else -- fails here rather than
	 * looping. */
	while (n < FZN_SCAN_CAP) {
		const char *text = s->render(s->step * n);

		if (!text) {
			expect(0, s->name, "rendered NULL, which the header forbids");
			return;
		}
		if (strcmp(text, FZN_FALLBACK) == 0)
			break;
		seen[n++] = text;
	}

	expect(n == s->codes, s->name,
	       "renders a different number of codes than this table pins");

	/* Distinctness, which is the copy-paste a compiler cannot see. */
	for (int i = 0; i < n; i++)
		for (int j = i + 1; j < n; j++)
			expect(strcmp(seen[i], seen[j]) != 0, s->name,
			       "two codes render the same text");

	/* And well past the end, where nothing is an enumerator. */
	expect(strcmp(s->render(s->step * (FZN_SCAN_CAP + 1)), FZN_FALLBACK) == 0, s->name,
	       "a value far outside the enum did not render the fallback");
}

int main(void)
{
	size_t count = sizeof(SUBJECTS) / sizeof(SUBJECTS[0]);

	for (size_t i = 0; i < count; i++)
		check_subject(&SUBJECTS[i]);

	printf("err_str_test: %d checks over %zu renderers, %d failure(s)\n",
	       checks, count, failures);
	return failures == 0 ? 0 : 1;
}
