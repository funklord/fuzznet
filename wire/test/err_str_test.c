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
#include "../../chain/manifest.h"
#include "../../chunk/reassembly.h"
#include "../../chunk/split.h"
#include "../../frame/freshness.h"
#include "../../local/peer.h"
#include "../../record/journal.h"
#include "../../record/ledger.h"
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
#include "../../blob/blob.h"
#include "../../spool/message.h"
#include "../../spool/transfer.h"
#include "../../spool/scrub.h"
#include "../../chain/authz.h"
#include "../../prekey/prekey.h"
#include "../../provision/provision.h"
#include "../../disclose/disclose.h"
#include "../../ratchet/ratchet.h"
#include "../../session/agree.h"
#include "../../session/session.h"
#include "../../spool/spool.h"
#include "../../persist/persist.h"
#include "../../tree/tree.h"

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
		fprintf(stderr, "  FAIL: %s: %s\n", subject, what);
	}
}

/* One wrapper per enum, taking `int`, because the subjects below are walked
 * through a common function pointer and a cast between function types with
 * different parameter types would not be one this library should rely on. */
static const char *r_chain(int v) { return fzn_chain_err_str((fzn_chain_err_t)v); }
static const char *r_manifest(int v) { return fzn_manifest_err_str((fzn_manifest_err_t)v); }
static const char *r_commitment(int v) { return fzn_commitment_err_str((fzn_commitment_err_t)v); }
static const char *r_fresh(int v) { return fzn_fresh_err_str((fzn_fresh_err_t)v); }
static const char *r_reasm(int v) { return fzn_reasm_err_str((fzn_reasm_err_t)v); }
static const char *r_split(int v) { return fzn_split_err_str((fzn_split_err_t)v); }
static const char *r_seal(int v) { return fzn_seal_err_str((fzn_seal_err_t)v); }
static const char *r_peer(int v) { return fzn_peer_verdict_str((fzn_peer_verdict_t)v); }
static const char *r_record(int v) { return fzn_record_err_str((fzn_record_err_t)v); }
static const char *r_journal(int v) { return fzn_journal_err_str((fzn_journal_err_t)v); }
static const char *r_ledger(int v) { return fzn_ledger_err_str((fzn_ledger_err_t)v); }
static const char *r_sync(int v) { return fzn_sync_err_str((fzn_sync_err_t)v); }
static const char *r_state(int v) { return fzn_state_err_str((fzn_state_err_t)v); }
static const char *r_trust(int v) { return fzn_trust_err_str((fzn_trust_err_t)v); }
static const char *r_log(int v) { return fzn_log_err_str((fzn_log_err_t)v); }
static const char *r_relay(int v) { return fzn_relay_err_str((fzn_relay_err_t)v); }
static const char *r_sched(int v) { return fzn_sched_err_str((fzn_sched_err_t)v); }
static const char *r_link(int v) { return fzn_link_err_str((fzn_link_err_t)v); }
static const char *r_blob(int v) { return fzn_blob_err_str((fzn_blob_err_t)v); }
static const char *r_authz(int v) { return fzn_authz_verdict_str((fzn_authz_verdict_t)v); }
static const char *r_prekey(int v) { return fzn_prekey_err_str((fzn_prekey_err_t)v); }
static const char *r_ratchet(int v) { return fzn_ratchet_err_str((fzn_ratchet_err_t)v); }
static const char *r_agree(int v) { return fzn_agree_err_str((fzn_agree_err_t)v); }
static const char *r_session(int v) { return fzn_session_err_str((fzn_session_err_t)v); }
static const char *r_spool(int v) { return fzn_spool_err_str((fzn_spool_err_t)v); }
static const char *r_msg(int v) { return fzn_msg_err_str((fzn_msg_err_t)v); }
static const char *r_transfer(int v) { return fzn_transfer_err_str((fzn_transfer_err_t)v); }
static const char *r_scrub(int v) { return fzn_scrub_err_str((fzn_scrub_err_t)v); }
static const char *r_persist(int v) { return fzn_persist_err_str((fzn_persist_err_t)v); }
static const char *r_tree(int v) { return fzn_tree_err_str((fzn_tree_err_t)v); }
static const char *r_provision(int v) { return fzn_provision_err_str((fzn_provision_err_t)v); }
static const char *r_disclose(int v) { return fzn_disclose_err_str((fzn_disclose_err_t)v); }

struct subject {
	const char *name;
	const char *(*render)(int);
	int codes;
};

/* The pinned counts. Each is the number of enumerators in that type, and
 * moving one without moving the other is the failure this table catches.
 *
 * THE DIRECTION IS NO LONGER A COLUMN, and that column is why nine renderers
 * sat outside this sweep for a week. Sixteen of the seventeen rows here were
 * error enums counting DOWN from `OK = 0`, and the nine that were missing all
 * count UP -- so the table had quietly become a table of one family, and a
 * tenth row added without noticing would have been walked in the wrong
 * direction and reported as rendering one code. `check_subject` probes for it
 * now and refuses an enum that answers in both directions. project.md sec 67. */
static const struct subject SUBJECTS[] = {
	{ "fzn_chain_err_str", r_chain, 11 },
	{ "fzn_manifest_err_str", r_manifest, 7 },
	{ "fzn_commitment_err_str", r_commitment, 4 },
	{ "fzn_fresh_err_str", r_fresh, 7 },
	{ "fzn_reasm_err_str", r_reasm, 9 },
	{ "fzn_split_err_str", r_split, 4 },
	{ "fzn_seal_err_str", r_seal, 9 },
	{ "fzn_peer_verdict_str", r_peer, 3 },
	{ "fzn_record_err_str", r_record, 6 },
	{ "fzn_journal_err_str", r_journal, 7 },
	{ "fzn_ledger_err_str", r_ledger, 4 },
	{ "fzn_sync_err_str", r_sync, 2 },
	{ "fzn_state_err_str", r_state, 7 },
	{ "fzn_trust_err_str", r_trust, 4 },
	{ "fzn_log_err_str", r_log, 5 },
	{ "fzn_relay_err_str", r_relay, 4 },
	{ "fzn_sched_err_str", r_sched, 3 },
	{ "fzn_link_err_str", r_link, 5 },
	{ "fzn_blob_err_str", r_blob, 8 },
	{ "fzn_authz_verdict_str", r_authz, 3 },
	{ "fzn_prekey_err_str", r_prekey, 7 },
	{ "fzn_ratchet_err_str", r_ratchet, 6 },
	{ "fzn_agree_err_str", r_agree, 5 },
	{ "fzn_session_err_str", r_session, 5 },
	{ "fzn_spool_err_str", r_spool, 6 },
	{ "fzn_msg_err_str", r_msg, 4 },
	{ "fzn_transfer_err_str", r_transfer, 5 },
	{ "fzn_scrub_err_str", r_scrub, 4 },
	{ "fzn_persist_err_str", r_persist, 5 },
	{ "fzn_tree_err_str", r_tree, 8 },
	{ "fzn_provision_err_str", r_provision, 6 },
	{ "fzn_disclose_err_str", r_disclose, 6 },
};

static void check_subject(const struct subject *s)
{
	const char *seen[FZN_SCAN_CAP];
	int n = 0;
	int step;

	/* WHICH WAY THIS ENUM COUNTS, ASKED RATHER THAN DECLARED. Exactly one
	 * of -1 and 1 must render something other than the fallback: an enum
	 * answering in NEITHER direction has only `OK` or does not fall back,
	 * and one answering in BOTH is mixed-sign, which this walk cannot
	 * enumerate and would silently half-cover. */
	{
		int neg = strcmp(s->render(-1), FZN_FALLBACK) != 0;
		int pos = strcmp(s->render(1), FZN_FALLBACK) != 0;

		if (neg == pos) {
			expect(0, s->name,
			       neg ? "renders codes in both directions, which this "
			             "walk cannot enumerate"
			           : "renders nothing either side of zero");
			return;
		}
		step = neg ? -1 : 1;
	}

	/* Walk until the fallback answers, which is where this type's codes
	 * stop. Capped so that a renderer which never falls back -- one that
	 * grew a `default:` returning something else -- fails here rather than
	 * looping. */
	while (n < FZN_SCAN_CAP) {
		const char *text = s->render(step * n);

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
	expect(strcmp(s->render(step * (FZN_SCAN_CAP + 1)), FZN_FALLBACK) == 0, s->name,
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
