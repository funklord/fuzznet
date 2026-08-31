/* Current values, and the ways they are allowed to change.
 *
 * The cases are chosen for what each would cost. A state that let an older
 * record win reverts a setting whenever the network re-delivers one. One that
 * resolved contention silently lets any authorised writer overwrite any
 * other's configuration with nothing to show it happened. One that evicted a
 * live setting to make room reverts it to a default nobody can trace. One
 * that erased a cleared cell instead of tombstoning it lets any replay of any
 * older record undo a revocation.
 *
 * THE PROPERTY UNDERNEATH ALL OF THEM, and the five `property_` tests at the
 * end: the value of a cell is a function of the SET of records applied to it
 * and not of their order, and where two orders must differ, the loser is
 * REFUSED so that the difference is visible. The defect that produced this
 * file's `stream` work was exactly that with a refusal missing -- stream 7
 * seq 100 then stream 9 seq 100 left stream 7's value, the reverse left
 * stream 9's, and both orders reported success.
 *
 * AND THE CLEAR PATH WAS THE HALF THAT WENT UNTESTED. The permutation
 * property was written to catch this class of defect and could not, because
 * it fed the set through `fzn_state_apply` alone: a suite proving order does
 * not matter never ordered a clear against an apply. It does now, and the
 * three properties added beside it in 2026-08-27 are the three the gap hid --
 * a revocation outrunning its grant, a revocation against a cell somebody
 * else holds, and the one order-dependence here that is NOT fixable, pinned
 * so that `state.h`'s admission of it cannot quietly stop being true.
 *
 * Every case here has been shown to fail for the reason it names, by putting
 * the defect back: a clear of an absent cell storing nothing (35 checks red,
 * the permutation property among them), the fourth entry point storing a live
 * value (5), a clear made permanent (69), the fixture ring shrunk below the
 * set it holds (1), the two contention codes folded together (10), and a
 * tombstone that forgets its sequence (18).
 */

#include "../../chain/chain.h" /* fzn_sign_ops_t */
#include "../state.h"

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

static void expect_err(fzn_state_err_t got, fzn_state_err_t want, const char *what)
{
	checks++;
	if (got != want) {
		failures++;
		fprintf(stderr, "  FAIL: %s -- got \"%s\", wanted \"%s\"\n", what, fzn_state_err_str(got),
		       fzn_state_err_str(want));
	}
}

static const uint8_t BODY_A[] = "value from alice";
static const uint8_t BODY_B[] = "value from bob";
static const uint8_t BODY_A2[] = "alice's second thought";
/* A body for the records that go through `fzn_state_clear`. This module does
 * not read it -- a clear stores absence and drops the body -- but the record
 * carries one, and giving it text that says what it is keeps a fixture honest
 * about which axis a record is on. It is also the body that showed up as a
 * LIVE SETTING when a revocation was pushed through `fzn_state_resolve`, so
 * the test for that reads a permission whose value is the word REVOKE. */
static const uint8_t BODY_REVOKE[] = "REVOKE";

/* A record, with its writer spelled in full.
 *
 * `stream` IS A PARAMETER BECAUSE IT WAS NOT ONE. This helper used to memset
 * the record and set everything but the stream, so every record the suite
 * built was stream 0 and the whole suite was blind to the field -- which is
 * why nothing here noticed that `state.c` never read it. A fixture that
 * cannot express a distinction cannot test one. */
/* A signer for the fixture. It answers for nobody in particular, which is
 * fine here: this suite never verifies. What it must do is produce a
 * signature over the bytes `fzn_record_sign` hands it, so that the records
 * below are REAL -- canonically encoded, with every field read back out of
 * the bytes the signature covers. */
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

/* Storage the views point into. A record is a VIEW now, so its bytes must
 * outlive it -- which is the property being bought: there is one
 * representation, and a field cannot disagree with the signature because
 * there is nothing for it to disagree with.
 *
 * A ring rather than one buffer, because a test holds several records at once
 * -- the conflict cases hold two, the permutation property holds eight.
 * Thirty two is far more than any case here needs.
 *
 * THAT LAST SENTENCE USED TO SAY `wire` WAS "asserted below to have wrapped
 * no further than that", AND NOTHING ASSERTED IT. There was a `wire_made`
 * counter, written on every call and read by nobody, which is what a check
 * that is not there looks like from the inside: the claim was in the comment,
 * the variable was in the file, and a set larger than the ring would have
 * been a set of records silently pointing into each other's encodings. The
 * counter is gone and the permutation property checks the thing that actually
 * matters -- that every record it holds is still open at its own sequence
 * when the set is complete. */
#define WIRE_SLOTS 32u
static uint8_t wire[WIRE_SLOTS][FZN_RECORD_MAX_LEN];
static size_t wire_next;

/* A record with its writer and its subject spelled out byte for byte.
 *
 * `make` below is this with two memsets in front of it, and the twin cases at
 * the end of `main` need what a seed cannot express: two keys that agree on
 * every byte but the last. A seed gives thirty-two copies of one byte, so any
 * two seeds differ at byte 0 -- which is what made every key comparison in
 * `state.c` unfalsifiable. */
static void make_keyed(fzn_record_t *r, const uint8_t issuer[FZN_PUBKEY_LEN],
                       const uint8_t subject[FZN_SUBJECT_LEN], uint32_t stream, uint32_t kind,
                       uint64_t seq, const uint8_t *body, size_t body_len)
{
	fzn_sign_ops_t ops;
	uint8_t *slot = wire[wire_next % WIRE_SLOTS];
	size_t wrote = 0;

	wire_next++;

	memset(&ops, 0, sizeof(ops));
	ops.sign = fixture_sign;

	if (fzn_record_sign(issuer, subject, stream, kind, seq, 1, body, body_len, &ops, slot,
	                    FZN_RECORD_MAX_LEN, &wrote) != FZN_RECORD_OK) {
		fprintf(stderr, "  FAIL: the fixture could not sign a record\n");
		failures++;
		memset(r, 0, sizeof(*r));
		return;
	}
	if (fzn_record_open(slot, wrote, r) != FZN_RECORD_OK) {
		fprintf(stderr, "  FAIL: the fixture could not open the record it signed\n");
		failures++;
		memset(r, 0, sizeof(*r));
	}
}

static void make(fzn_record_t *r, uint8_t issuer_seed, uint32_t stream, uint8_t subject_seed,
                 uint32_t kind, uint64_t seq, const uint8_t *body, size_t body_len)
{
	uint8_t issuer[FZN_PUBKEY_LEN], subject[FZN_SUBJECT_LEN];

	memset(issuer, issuer_seed, sizeof(issuer));
	memset(subject, subject_seed, sizeof(subject));
	make_keyed(r, issuer, subject, stream, kind, seq, body, body_len);
}

/* ---- the order-independence property ---------------------------------- */

#define PROBE_N 4

static const struct probe {
	uint8_t subject_seed;
	uint32_t kind;
} PROBE[PROBE_N] = {
	{ 0x51, 1 },
	{ 0x51, 2 },
	{ 0x52, 1 },
	{ 0x52, 2 },
};

/* What a state says, reduced to something two runs can be compared on. The
 * writer and the sequence are in here as well as the value, because "the same
 * state" has to mean the same cell held by the same writer at the same
 * position -- a state that agreed on bodies and disagreed on who set them
 * would answer the next record differently. */
struct cell_view {
	int present;
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint32_t stream;
	uint64_t seq;
	const uint8_t *body;
	size_t body_len;
};

struct view {
	size_t count;
	struct cell_view cell[PROBE_N];
};

static void snapshot(const fzn_state_t *st, struct view *v)
{
	memset(v, 0, sizeof(*v));
	v->count = fzn_state_count(st);

	for (int i = 0; i < PROBE_N; i++) {
		uint8_t subject[FZN_SUBJECT_LEN];
		const fzn_state_entry_t *e;

		memset(subject, PROBE[i].subject_seed, sizeof(subject));
		e = fzn_state_get(st, subject, PROBE[i].kind);
		if (!e)
			continue;

		v->cell[i].present = 1;
		memcpy(v->cell[i].issuer, e->issuer, FZN_PUBKEY_LEN);
		v->cell[i].stream = e->stream;
		v->cell[i].seq = e->seq;
		v->cell[i].body = e->body;
		v->cell[i].body_len = e->body_len;
	}
}

/* Compared field by field rather than with one memcmp: a struct has padding
 * and padding is not a value. */
static int view_eq(const struct view *a, const struct view *b)
{
	if (a->count != b->count)
		return 0;

	for (int i = 0; i < PROBE_N; i++) {
		const struct cell_view *x = &a->cell[i], *y = &b->cell[i];

		if (x->present != y->present || x->stream != y->stream || x->seq != y->seq ||
		    x->body != y->body || x->body_len != y->body_len)
			return 0;
		if (memcmp(x->issuer, y->issuer, FZN_PUBKEY_LEN) != 0)
			return 0;
	}

	return 1;
}

/* Lexicographic successor of `a`, or 0 when `a` is the last permutation. */
static int next_permutation(int *a, int n)
{
	int i = n - 2, j = n - 1, l, r, t;

	while (i >= 0 && a[i] >= a[i + 1])
		i--;
	if (i < 0)
		return 0;

	while (a[j] <= a[i])
		j--;
	t = a[i];
	a[i] = a[j];
	a[j] = t;

	for (l = i + 1, r = n - 1; l < r; l++, r--) {
		t = a[l];
		a[l] = a[r];
		a[r] = t;
	}

	return 1;
}

/* Which entry point a record in a permuted set goes through.
 *
 * IT IS A PARAMETER BECAUSE IT WAS NOT ONE, which is the same fault the
 * `stream` note above records one layer down. The permutation property below
 * called `fzn_state_apply` and nothing else, so a suite that existed to prove
 * order does not matter never once ordered a clear against an apply -- and
 * that is precisely the pair whose two orders left two different
 * permissions. A fixture that cannot express a distinction cannot test one. */
enum op {
	OP_APPLY,
	OP_CLEAR,
};

/* Run the records in this order into a fresh state. Returns the first refusal,
 * or OK if there was none -- and the refusal's identity is the point, not
 * merely that there was one. See `property_a_divergence_is_reported`.
 *
 * `FZN_STATE_ABSENT` IS NOT COUNTED AS A REFUSAL, because it is not one: the
 * record was stored. Counting it would make this function report a departure
 * from the header's invariant on exactly the orders that now uphold it -- a
 * clear arriving before the thing it supersedes -- which is the defect's own
 * shape reappearing in the instrument that measures it. */
static fzn_state_err_t run_order(const fzn_record_t *recs, const enum op *ops, const int *order,
                                  int n, fzn_state_t *st, fzn_state_entry_t *entries,
                                  size_t capacity)
{
	fzn_state_err_t first = FZN_STATE_OK;

	fzn_state_init(st, entries, capacity);

	for (int i = 0; i < n; i++) {
		int k = order[i];
		fzn_state_err_t err = (ops[k] == OP_CLEAR) ? fzn_state_clear(st, &recs[k])
		                                           : fzn_state_apply(st, &recs[k]);

		if (err != FZN_STATE_OK && err != FZN_STATE_ABSENT && first == FZN_STATE_OK)
			first = err;
	}

	return first;
}

/* ONE RECORD SET, ONE STATE, WHATEVER ORDER IT ARRIVES IN.
 *
 * Every cell here has exactly one writer, so nothing is refused for
 * contention and the property is unconditional: the cell holds whichever of
 * its writer's records carries the highest sequence -- value or absence --
 * and a re-delivery of a lower one changes nothing. The capacity is larger
 * than the number of cells on purpose: FULL is a capacity effect and would be
 * a legitimate reason for two orders to differ, so it is kept out of the way
 * of the property being measured.
 *
 * CLEARS ARE IN THE SET NOW, AND THAT IS THE WHOLE POINT OF THIS REVISION.
 * The property was written to catch exactly this class of defect and could
 * not, because it only ever called `fzn_state_apply`. A clear that outran the
 * apply it superseded stored nothing and answered ABSENT, so the apply landed
 * behind it and the grant stood -- one record set, two permissions, and the
 * fail-dangerous one reachable by nothing worse than packet reordering.
 *
 * Two of the three cells exist to hold the two halves apart, and neither is
 * redundant:
 *
 *   - `0x51/1` ends as a TOMBSTONE, its writer's last word being a clear.
 *     This is the half that diverged: with the clear dropped, the orders that
 *     delivered it first left the cell LIVE and counted. It is what fails
 *     when the defect is put back.
 *   - `0x51/2` ends LIVE, re-granted at a sequence ABOVE its clear. This is
 *     the control demanded of any fix -- "a clear is not undone" must not be
 *     satisfied by a clear that is permanent -- and it converges under the
 *     defect too, which is what makes it a control rather than a second
 *     symptom. A fix that simply froze cleared cells passes everything above
 *     and fails here. */
#define PERM_N 8

static void property_state_is_a_function_of_the_set(void)
{
	fzn_record_t recs[PERM_N];
	static const enum op OPS[PERM_N] = {
		OP_APPLY, OP_APPLY, OP_APPLY, OP_CLEAR,
		OP_APPLY, OP_CLEAR, OP_APPLY,
		OP_APPLY,
	};
	static const uint64_t SEQ[PERM_N] = { 10, 12, 11, 13, 4, 5, 6, 7 };
	int order[PERM_N] = { 0, 1, 2, 3, 4, 5, 6, 7 };
	fzn_state_t st;
	fzn_state_entry_t entries[12];
	struct view reference, current;
	int permutations = 1, divergent = 0, intact = 0;

	/* Cell `0x51/1`, one writer, written three times out of sequence order
	 * and then cleared above all three. */
	make(&recs[0], 0xa1, 1, 0x51, 1, SEQ[0], BODY_A, sizeof(BODY_A));
	make(&recs[1], 0xa1, 1, 0x51, 1, SEQ[1], BODY_A2, sizeof(BODY_A2));
	make(&recs[2], 0xa1, 1, 0x51, 1, SEQ[2], BODY_B, sizeof(BODY_B));
	make(&recs[3], 0xa1, 1, 0x51, 1, SEQ[3], BODY_REVOKE, sizeof(BODY_REVOKE));
	/* Cell `0x51/2`: the same subject, another kind, and another stream of
	 * the same issuer -- a different cell that must not contend with
	 * anything. Set, cleared, and set again above the clear. */
	make(&recs[4], 0xa1, 2, 0x51, 2, SEQ[4], BODY_A, sizeof(BODY_A));
	make(&recs[5], 0xa1, 2, 0x51, 2, SEQ[5], BODY_REVOKE, sizeof(BODY_REVOKE));
	make(&recs[6], 0xa1, 2, 0x51, 2, SEQ[6], BODY_B, sizeof(BODY_B));
	/* Cell `0x52/1`, a different issuer, set once. */
	make(&recs[7], 0xb2, 1, 0x52, 1, SEQ[7], BODY_B, sizeof(BODY_B));

	/* THE RING HELD ALL EIGHT, which the comment on `wire` claimed was
	 * asserted and which nothing checked. Every record here must still be
	 * open at its own sequence: `make` writes into a ring of WIRE_SLOTS
	 * buffers and a record is a VIEW over its bytes, so a set larger than
	 * the ring would silently be a set of records pointing at each other's
	 * encodings, and every conclusion below it would be about a fixture
	 * that had eaten itself. Verified by dropping WIRE_SLOTS to 4: this
	 * reports four intact instead of eight. */
	for (int i = 0; i < PERM_N; i++)
		intact += (fzn_record_is_open(recs[i]) && fzn_record_seq(recs[i]) == SEQ[i]) ? 1 : 0;
	expect(intact == PERM_N, "the fixture ring held every record of the set at once");

	run_order(recs, OPS, order, PERM_N, &st, entries, 12);
	snapshot(&st, &reference);

	while (next_permutation(order, PERM_N)) {
		run_order(recs, OPS, order, PERM_N, &st, entries, 12);
		snapshot(&st, &current);
		permutations++;
		if (!view_eq(&reference, &current))
			divergent++;
	}

	/* The count is checked because a loop that ran no permutations would
	 * report zero divergences just as loudly as one that ran them all. */
	expect(permutations == 40320, "eight records have 40320 orders and all of them ran");
	expect(divergent == 0, "every order of one record set leaves one state");

	expect(reference.count == 2, "two live cells and a tombstone, whatever the order");
	/* THE CELL THE DEFECT LIVED IN. A clear that failed to land leaves this
	 * one live and counted, so this pair is what turns red when the old
	 * behaviour comes back. */
	expect(reference.cell[0].present == 0,
	       "a clear above everything its writer said leaves the cell unset");
	/* THE CONTROL. A permanent clear would satisfy the line above and fail
	 * this one. */
	expect(reference.cell[1].present && reference.cell[1].seq == 6 &&
	               memcmp(reference.cell[1].body, BODY_B, reference.cell[1].body_len) == 0,
	       "and a record above the clear sets that cell again, in every order");
	expect(reference.cell[1].stream == 2, "still held by the stream that wrote it");
	expect(reference.cell[2].present && reference.cell[2].seq == 7 &&
	               memcmp(reference.cell[2].body, BODY_B, reference.cell[2].body_len) == 0,
	       "and the second subject is bob's");
}

/* WHERE TWO ORDERS MUST DIFFER, THE LOSER IS REFUSED -- AND REFUSED AS
 * CONTENTION.
 *
 * Two streams of one issuer at the SAME sequence: there is no shared zero to
 * compare them against, so whichever arrives first holds the cell. That is
 * first-writer-wins, and it is a policy -- tolerable only because the record
 * that lost is reported.
 *
 * This is the defect written out, and the ERROR IDENTITY IS THE WHOLE TEST.
 * Before `state.c` read `stream` it compared the two sequences directly, so
 * the loser came back `FZN_STATE_ERR_STALE`: the two orders left different
 * values, and each announced the difference as an echo of something the host
 * already had. A consumer cannot act on that -- a re-delivered record says
 * exactly the same thing -- so the divergence was reported in a way
 * indistinguishable from nothing having happened. Asserting merely that
 * SOMETHING was refused passes on the broken code, which is why this asks for
 * the code by name. */
static void property_a_divergence_is_reported(void)
{
	fzn_record_t recs[2];
	static const enum op OPS[2] = { OP_APPLY, OP_APPLY };
	int forward[2] = { 0, 1 }, backward[2] = { 1, 0 };
	fzn_state_t st;
	fzn_state_entry_t entries[4];
	struct view first, second;
	fzn_state_err_t err_forward, err_backward;

	make(&recs[0], 0xa1, 7, 0x51, 1, 100, BODY_A, sizeof(BODY_A));
	make(&recs[1], 0xa1, 9, 0x51, 1, 100, BODY_B, sizeof(BODY_B));

	err_forward = run_order(recs, OPS, forward, 2, &st, entries, 4);
	snapshot(&st, &first);
	err_backward = run_order(recs, OPS, backward, 2, &st, entries, 4);
	snapshot(&st, &second);

	/* Not vacuous: the two orders really do leave different values, which
	 * is what makes the refusal load-bearing rather than decorative. */
	expect(!view_eq(&first, &second), "the two orders leave different values");
	expect(first.cell[0].stream == 7 && second.cell[0].stream == 9,
	       "and each is held by whichever stream arrived first");
	expect_err(err_forward, FZN_STATE_ERR_CROSS_STREAM,
	           "so the order that lost stream 9 called it contention");
	expect_err(err_backward, FZN_STATE_ERR_CROSS_STREAM,
	           "and the order that lost stream 7 said the same");
}

/* A REVOCATION THAT OUTRUNS ITS GRANT STILL LANDS -- the defect, written out
 * with the two orders that measured it.
 *
 * The permutation property above covers this as one order among 40320. This
 * case exists beside it because a property that fails tells you a set
 * diverged and not which pair did it, and this pair is the whole reason the
 * clear path was reworked. Measured against the old code:
 *
 *	apply(5)=ok       clear(10)=ok      -> count 0, NULL    (revoked)
 *	clear(10)=ABSENT  apply(5)=ok       -> count 1, "GRANT" (granted)
 *
 * Two hosts, one record set, and one of them believes the permission is still
 * granted. Nothing forged and nothing lost: a packet arrived early.
 *
 * THE MANDATORY DISTINCTION IS CHECKED HERE TOO, and it is the reason the
 * clear does not simply answer OK. Under the old code the second line's
 * refusal was byte-identical to clearing a subject nobody had ever set, so a
 * consumer could not tell "your revocation was dropped" from "there was
 * nothing to revoke". Nothing is dropped now, but the two situations are
 * still different and a revoker still wants to know which it is in: a clear
 * that superseded a value answers OK, and a clear that got in first answers
 * ABSENT. */
static void property_a_clear_lands_before_its_grant(void)
{
	fzn_record_t grant, revoke;
	fzn_state_t st;
	fzn_state_entry_t entries[4];
	uint8_t subj[FZN_SUBJECT_LEN];
	fzn_state_err_t first, second;
	const fzn_state_entry_t *got;

	memset(subj, 0x51, sizeof(subj));
	make(&grant, 0xa1, 7, 0x51, 1, 5, BODY_A, sizeof(BODY_A));
	make(&revoke, 0xa1, 7, 0x51, 1, 10, BODY_REVOKE, sizeof(BODY_REVOKE));

	/* The order that always worked. */
	fzn_state_init(&st, entries, 4);
	first = fzn_state_apply(&st, &grant);
	second = fzn_state_clear(&st, &revoke);
	expect_err(first, FZN_STATE_OK, "the grant arrives");
	expect_err(second, FZN_STATE_OK, "and the revocation supersedes it");
	expect(fzn_state_get(&st, subj, 1) == NULL && fzn_state_count(&st) == 0,
	       "leaving the subject revoked");

	/* The order that did not. */
	fzn_state_init(&st, entries, 4);
	first = fzn_state_clear(&st, &revoke);
	second = fzn_state_apply(&st, &grant);
	expect_err(first, FZN_STATE_ABSENT,
	           "the revocation arrives first and lands on nothing");
	expect_err(second, FZN_STATE_ERR_STALE,
	           "so the grant behind it is refused as older than the revocation");
	got = fzn_state_get(&st, subj, 1);
	expect(got == NULL && fzn_state_count(&st) == 0,
	       "and the subject is revoked in this order too");

	/* THE TOMBSTONE IS THE REVOKER'S, not a blank. Without this, a clear
	 * that merely refused everything afterwards would pass the two lines
	 * above -- and it would refuse the revoker's own later re-grant as
	 * well, which is the failure the next block catches. */
	{
		const fzn_state_entry_t *cell = &st.entries[0];
		uint8_t alice[FZN_PUBKEY_LEN];

		memset(alice, 0xa1, sizeof(alice));
		expect(st.used == 1 && cell->live == 0 && cell->seq == 10 && cell->stream == 7 &&
		               memcmp(cell->issuer, alice, FZN_PUBKEY_LEN) == 0,
		       "the pre-emptive tombstone names its writer and its sequence");
		expect(cell->body == NULL && cell->body_len == 0,
		       "and holds absence rather than the revocation's body");
	}

	/* THE CONTROL FOR THE CONTROL: a clear that got in first must still be
	 * distinguishable from one that superseded a value, and it is -- the
	 * two orders above answered ABSENT and OK for the same pair of
	 * records. And the writer can still change its mind afterwards. */
	{
		fzn_record_t regrant;

		make(&regrant, 0xa1, 7, 0x51, 1, 11, BODY_B, sizeof(BODY_B));
		expect_err(fzn_state_apply(&st, &regrant), FZN_STATE_OK,
		           "a record above the pre-emptive tombstone sets the subject");
		got = fzn_state_get(&st, subj, 1);
		expect(got != NULL && got->seq == 11 && fzn_state_count(&st) == 1,
		       "and the pre-emptive tombstone was not permanent");
	}
}

/* CLEARING A CELL ANOTHER WRITER HOLDS -- the fourth entry point, and the
 * combination that did not exist.
 *
 * `fzn_state_resolve` is (override, live) and `fzn_state_clear` is (neither),
 * so bob revoking alice's grant had no correct call at all. Measured against
 * the old code:
 *
 *	fzn_state_clear   -> CONFLICT, nothing stored: the revocation is dropped
 *	fzn_state_resolve -> OK, and fzn_state_get returns a LIVE cell
 *	                     whose body is "REVOKE" and whose issuer is bob
 *
 * The second is the dangerous one and it is the one the header sent people
 * to: a consumer that "HAS a rule and applies it" calls resolve, and the
 * permission it meant to revoke reads as granted afterwards, by the revoker,
 * with the word REVOKE as its value. Both halves are asserted below, because
 * the second is still resolve's correct behaviour -- resolve sets a value and
 * a revocation is not a value -- and it is what makes the fourth name
 * necessary rather than merely tidy.
 *
 * A FLAG ON `fzn_state_clear` WOULD HAVE DONE THE SAME WORK. It is four names
 * instead for chain.h's reason: one function with an optional pin is a
 * function somebody calls without the pin. Overriding another writer is the
 * dangerous half of the axis and it has to be typed. Nothing here can test
 * that -- a name that must be typed is a compile-time property -- so it is
 * recorded rather than asserted. */
static void property_a_revocation_can_take_another_writers_cell(void)
{
	fzn_record_t grant, revoke, later;
	fzn_state_t st;
	fzn_state_entry_t entries[4];
	uint8_t subj[FZN_SUBJECT_LEN], alice[FZN_PUBKEY_LEN], bob[FZN_PUBKEY_LEN];
	const fzn_state_entry_t *got;

	memset(subj, 0x51, sizeof(subj));
	memset(alice, 0xa1, sizeof(alice));
	memset(bob, 0xb2, sizeof(bob));

	make(&grant, 0xa1, 7, 0x51, 1, 5, BODY_A, sizeof(BODY_A));
	make(&revoke, 0xb2, 3, 0x51, 1, 10, BODY_REVOKE, sizeof(BODY_REVOKE));

	/* WHAT RESOLVE DOES WITH A REVOCATION, asserted so that the reason for
	 * the fourth name is in the suite and not only in a comment. This is
	 * resolve behaving correctly and being the wrong tool. */
	fzn_state_init(&st, entries, 4);
	expect_err(fzn_state_apply(&st, &grant), FZN_STATE_OK, "alice grants");
	expect_err(fzn_state_resolve(&st, &revoke), FZN_STATE_OK, "bob resolves with a revocation");
	got = fzn_state_get(&st, subj, 1);
	expect(got != NULL && got->live && got->body_len == sizeof(BODY_REVOKE) &&
	               memcmp(got->body, BODY_REVOKE, got->body_len) == 0,
	       "and the subject reads as SET, with the revocation as its value");
	expect(got != NULL && memcmp(got->issuer, bob, FZN_PUBKEY_LEN) == 0,
	       "granted, on this reading, by the writer that meant to revoke it");

	/* WHAT THE FOURTH ENTRY POINT DOES WITH IT. */
	fzn_state_init(&st, entries, 4);
	expect_err(fzn_state_apply(&st, &grant), FZN_STATE_OK, "alice grants again");
	expect_err(fzn_state_clear(&st, &revoke), FZN_STATE_ERR_CONFLICT,
	           "bob cannot clear alice's cell without saying so");
	expect(fzn_state_get(&st, subj, 1) != NULL, "and the refused clear left the grant alone");
	expect_err(fzn_state_resolve_clear(&st, &revoke), FZN_STATE_OK,
	           "bob clearing alice's cell, deliberately");
	expect(fzn_state_get(&st, subj, 1) == NULL && fzn_state_count(&st) == 0,
	       "and the subject is revoked rather than re-granted");
	expect(st.used == 1 && st.entries[0].live == 0 && st.entries[0].seq == 10 &&
	               st.entries[0].stream == 3 &&
	               memcmp(st.entries[0].issuer, bob, FZN_PUBKEY_LEN) == 0,
	       "the tombstone is bob's, at bob's sequence and stream");
	expect(st.entries[0].body == NULL && st.entries[0].body_len == 0,
	       "holding absence, not the revocation's body");

	/* THE REVOCATION IS DURABLE AGAINST THE WRITER IT TOOK THE CELL FROM.
	 * Without this, a resolve-clear that merely emptied the cell would pass
	 * everything above and let alice's next record -- or a replay of the
	 * grant just revoked -- put the permission back. */
	expect_err(fzn_state_apply(&st, &grant), FZN_STATE_ERR_CONFLICT,
	           "a replay of the revoked grant is refused");
	make(&later, 0xa1, 7, 0x51, 1, 900, BODY_A2, sizeof(BODY_A2));
	expect_err(fzn_state_apply(&st, &later), FZN_STATE_ERR_CONFLICT,
	           "and so is alice at a far higher sequence, the cell being bob's now");
	expect(fzn_state_get(&st, subj, 1) == NULL, "the subject stays revoked");

	/* THE POSITIVE CONTROL. A resolve-clear that simply wedged the cell
	 * shut would satisfy every line above. The writer that took it must
	 * still be able to use it. */
	make(&later, 0xb2, 3, 0x51, 1, 11, BODY_B, sizeof(BODY_B));
	expect_err(fzn_state_apply(&st, &later), FZN_STATE_OK,
	           "and bob, who holds the cell, can set it again");
	got = fzn_state_get(&st, subj, 1);
	expect(got != NULL && got->seq == 11, "so the cell is not wedged");

	/* RESOLVE-CLEAR OVERRIDES CROSS-STREAM TOO, which is the other half of
	 * what its name promises: it is `fzn_state_resolve` on the clearing
	 * axis, and resolve overrides both kinds. */
	make(&later, 0xb2, 9, 0x51, 1, 2, BODY_REVOKE, sizeof(BODY_REVOKE));
	expect_err(fzn_state_clear(&st, &later), FZN_STATE_ERR_CROSS_STREAM,
	           "another stream of the holder cannot clear it by accident");
	expect_err(fzn_state_resolve_clear(&st, &later), FZN_STATE_OK, "and can when it says so");
	expect(fzn_state_get(&st, subj, 1) == NULL, "leaving the subject unset");
	expect(st.entries[0].stream == 9 && st.entries[0].seq == 2,
	       "with the clearing stream and its own sequence in the cell");

	/* IDEMPOTENT, AND STALE IS THE ORDINARY ANSWER on a host already
	 * holding the winner -- the finding the simulated network made about
	 * `fzn_state_resolve`, which applies here for the same reason: a rule
	 * is applied across a whole network and some hosts were already
	 * right. */
	expect_err(fzn_state_resolve_clear(&st, &later), FZN_STATE_ERR_STALE,
	           "resolving the same clear twice is stale, not a fault");

	/* ARGUMENTS, on the new entry point as on the other three. */
	expect_err(fzn_state_resolve_clear(&st, NULL), FZN_STATE_ERR_MALFORMED,
	           "resolve-clearing with no record");
	expect_err(fzn_state_resolve_clear(NULL, &later), FZN_STATE_ERR_MALFORMED,
	           "resolve-clearing a null state");
	{
		fzn_record_t never;

		memset(&never, 0, sizeof(never));
		expect_err(fzn_state_resolve_clear(&st, &never), FZN_STATE_ERR_MALFORMED,
		           "resolve-clearing with a record never opened");
	}
}

/* WHICH CONTENTION CODE A RECORD IS TOLD DEPENDS ON THE ORDER, AND THIS IS
 * WHAT THAT COSTS.
 *
 * Not a defect with a fix. A cell holds ONE writer, so an arriving record can
 * only be compared against that one, and which writer holds the cell is
 * first-writer-wins among writers with no shared zero -- policy `state.h`
 * documents and already lets make the VALUE order-dependent. Converging the
 * two counts needs every writer that ever contended to be remembered, which
 * is unbounded storage in a module that allocates nothing.
 *
 * SO THE HONEST THING IS TO PIN IT RATHER THAN HIDE IT. Two assertions, doing
 * different jobs:
 *
 *   - The SAFETY property, which holds in every order and is what a consumer
 *     actually depends on: exactly one record is taken, and every record from
 *     a writer other than the holder is refused as one of the two contention
 *     codes. Never STALE -- which would read as a harmless echo -- and never
 *     accepted.
 *   - The measured DIVERGENCE, pinned so that the paragraph in `state.h`
 *     saying the counts are not comparable across hosts cannot quietly stop
 *     being true. If somebody makes them converge, this fails and sends them
 *     to that paragraph.
 *
 * Measured 2026-08-27, all six orders of three records at one sequence:
 * alice on stream 1 and alice on stream 2 and bob each got ok once, and the
 * orders that seated alice first reported one CROSS_STREAM and one CONFLICT
 * while the orders that seated bob first reported two CONFLICTs. */
static void property_the_contention_alarm_is_per_host(void)
{
	static const int ORDER[6][3] = {
		{ 0, 1, 2 }, { 0, 2, 1 }, { 1, 0, 2 }, { 1, 2, 0 }, { 2, 0, 1 }, { 2, 1, 0 },
	};
	fzn_record_t recs[3];
	fzn_state_t st;
	fzn_state_entry_t entries[4];
	int conflicts[6], crosses[6];
	int sound = 0, distinct_shapes = 0;

	/* One subject, one sequence, three writers: two streams of alice and
	 * bob. Every pair of them is incomparable. */
	make(&recs[0], 0xa1, 1, 0x51, 1, 50, BODY_A, sizeof(BODY_A));
	make(&recs[1], 0xa1, 2, 0x51, 1, 50, BODY_A2, sizeof(BODY_A2));
	make(&recs[2], 0xb2, 1, 0x51, 1, 50, BODY_B, sizeof(BODY_B));

	for (int i = 0; i < 6; i++) {
		int taken = 0, other = 0;

		conflicts[i] = 0;
		crosses[i] = 0;
		fzn_state_init(&st, entries, 4);

		for (int j = 0; j < 3; j++) {
			fzn_state_err_t err = fzn_state_apply(&st, &recs[ORDER[i][j]]);

			switch (err) {
			case FZN_STATE_OK:
				taken++;
				break;
			case FZN_STATE_ERR_CONFLICT:
				conflicts[i]++;
				break;
			case FZN_STATE_ERR_CROSS_STREAM:
				crosses[i]++;
				break;
			default:
				other++;
				break;
			}
		}

		if (taken == 1 && conflicts[i] + crosses[i] == 2 && other == 0 &&
		    fzn_state_count(&st) == 1)
			sound++;
	}

	expect(sound == 6,
	       "in every order one writer is seated and the other two are refused as contention");

	for (int i = 1; i < 6; i++)
		if (conflicts[i] != conflicts[0] || crosses[i] != crosses[0])
			distinct_shapes++;
	expect(distinct_shapes > 0,
	       "and the two alarm counts are NOT the same across orders -- see state.h");
	expect(conflicts[0] == 1 && crosses[0] == 1,
	       "alice seated first: one cross-stream and one conflict");
	expect(conflicts[4] == 2 && crosses[4] == 0, "bob seated first: two conflicts");
}

int main(void)
{
	fzn_state_t st;
	fzn_state_entry_t entries[3];
	fzn_record_t rec;
	const fzn_state_entry_t *got;
	uint8_t alice[FZN_PUBKEY_LEN], bob[FZN_PUBKEY_LEN], subj[FZN_SUBJECT_LEN];

	memset(alice, 0xa1, sizeof(alice));
	memset(bob, 0xb2, sizeof(bob));
	memset(subj, 0x51, sizeof(subj));

	expect_err(fzn_state_init(NULL, entries, 3), FZN_STATE_ERR_MALFORMED, "a null state");
	expect_err(fzn_state_init(&st, NULL, 3), FZN_STATE_ERR_MALFORMED, "null entries");
	expect_err(fzn_state_init(&st, entries, 0), FZN_STATE_ERR_MALFORMED, "zero capacity");
	expect_err(fzn_state_init(&st, entries, 3), FZN_STATE_OK, "a well-formed state");
	expect(fzn_state_count(&st) == 0, "a new state holds nothing");
	expect(fzn_state_forgotten(&st) == 0, "and has forgotten nothing");
	expect(fzn_state_get(&st, subj, 1) == NULL, "nothing is set yet");

	/* SETTING, AND SUPERSEDING FROM THE SAME WRITER. */
	make(&rec, 0xa1, 1, 0x51, 1, 5, BODY_A, sizeof(BODY_A));
	expect_err(fzn_state_apply(&st, &rec), FZN_STATE_OK, "alice sets a subject");
	got = fzn_state_get(&st, subj, 1);
	expect(got != NULL && got->body_len == sizeof(BODY_A) &&
	                       memcmp(got->body, BODY_A, got->body_len) == 0, "the value is alice's");
	expect(got != NULL && got->seq == 5, "and carries her sequence");
	expect(got != NULL && got->stream == 1, "and the stream she said it on");

	make(&rec, 0xa1, 1, 0x51, 1, 6, BODY_A2, sizeof(BODY_A2));
	expect_err(fzn_state_apply(&st, &rec), FZN_STATE_OK, "alice changes her mind");
	got = fzn_state_get(&st, subj, 1);
	expect(got != NULL && got->body_len == sizeof(BODY_A2) &&
	                       memcmp(got->body, BODY_A2, got->body_len) == 0, "the newer value wins");
	expect(fzn_state_count(&st) == 1, "superseding does not add a subject");

	/* AN OLDER RECORD MUST NOT UNDO A NEWER ONE. A re-delivery is exactly
	 * this, and a state that took it would revert settings at random. */
	make(&rec, 0xa1, 1, 0x51, 1, 5, BODY_A, sizeof(BODY_A));
	expect_err(fzn_state_apply(&st, &rec), FZN_STATE_ERR_STALE, "an older record arriving late");
	got = fzn_state_get(&st, subj, 1);
	expect(got != NULL && got->body_len == sizeof(BODY_A2) &&
	                       memcmp(got->body, BODY_A2, got->body_len) == 0, "and the newer value still stands");

	make(&rec, 0xa1, 1, 0x51, 1, 6, BODY_A, sizeof(BODY_A));
	expect_err(fzn_state_apply(&st, &rec), FZN_STATE_ERR_STALE, "the same sequence again");

	/* TWO STREAMS OF ONE ISSUER ARE TWO WRITERS.
	 *
	 * Their sequences are numbered from 1 independently, so comparing them
	 * is comparing two rulers with no shared zero. Measured when `state.c`
	 * ignored the field: stream 7 seq 100 then stream 9 seq 100 left stream
	 * 7's value and the reverse left stream 9's, with no error either way.
	 *
	 * The sequence here is deliberately far HIGHER than what is held. A
	 * check that compared sequences before comparing writers would call
	 * this an ordinary supersede and take it, which is the bug wearing a
	 * larger number. */
	make(&rec, 0xa1, 2, 0x51, 1, 900, BODY_B, sizeof(BODY_B));
	expect_err(fzn_state_apply(&st, &rec), FZN_STATE_ERR_CROSS_STREAM,
	           "alice writing her own subject from another stream");
	got = fzn_state_get(&st, subj, 1);
	expect(got != NULL && got->body_len == sizeof(BODY_A2) &&
	                       memcmp(got->body, BODY_A2, got->body_len) == 0 && got->stream == 1,
	       "and a refused cross-stream record left the value alone");

	/* And far LOWER, which a sequence comparison would call stale. The two
	 * are different answers and a caller acts differently on them: a stale
	 * record is an echo, a cross-stream one is contention. */
	make(&rec, 0xa1, 2, 0x51, 1, 1, BODY_B, sizeof(BODY_B));
	expect_err(fzn_state_apply(&st, &rec), FZN_STATE_ERR_CROSS_STREAM,
	           "a lower sequence from another stream is not stale");

	/* THE POSITIVE CONTROL. A cross-stream check that refused everything
	 * would satisfy both cases above; the same writer must still be able to
	 * supersede itself. */
	make(&rec, 0xa1, 1, 0x51, 1, 7, BODY_A, sizeof(BODY_A));
	expect_err(fzn_state_apply(&st, &rec), FZN_STATE_OK,
	           "alice's own stream still supersedes");
	got = fzn_state_get(&st, subj, 1);
	expect(got != NULL && got->body_len == sizeof(BODY_A) &&
	                       memcmp(got->body, BODY_A, got->body_len) == 0 && got->seq == 7, "with the newer value");

	/* AND STALE STILL WORKS ON THAT WRITER, which is the other half of the
	 * control: a check keyed on the stream must not have stopped comparing
	 * sequences within one. */
	make(&rec, 0xa1, 1, 0x51, 1, 7, BODY_B, sizeof(BODY_B));
	expect_err(fzn_state_apply(&st, &rec), FZN_STATE_ERR_STALE,
	           "and the same stream at the same sequence is stale");

	/* A DIFFERENT ISSUER IS A CONFLICT WHATEVER STREAM IT USES.
	 *
	 * This is what a cell keyed by (subject, kind, stream) would lose: bob
	 * would land in a cell of his own and both writes would succeed, so no
	 * conflict would ever be reported again. The key is (subject, kind) and
	 * the stream is stored, not looked up by. */
	make(&rec, 0xb2, 4, 0x51, 1, 99, BODY_B, sizeof(BODY_B));
	expect_err(fzn_state_apply(&st, &rec), FZN_STATE_ERR_CONFLICT,
	           "bob writing alice's subject from a stream of his own");
	expect(fzn_state_count(&st) == 1, "and no second cell was made for him");

	/* A DIFFERENT KIND IS A DIFFERENT SUBJECT. */
	make(&rec, 0xa1, 1, 0x51, 2, 7, BODY_A, sizeof(BODY_A));
	expect_err(fzn_state_apply(&st, &rec), FZN_STATE_OK, "the same subject, another kind");
	expect(fzn_state_count(&st) == 2, "which is a second entry");

	/* CONFLICT IS REPORTED AND CHANGES NOTHING. */
	make(&rec, 0xb2, 1, 0x51, 1, 99, BODY_B, sizeof(BODY_B));
	expect_err(fzn_state_apply(&st, &rec), FZN_STATE_ERR_CONFLICT, "bob writing alice's subject");
	got = fzn_state_get(&st, subj, 1);
	expect(got != NULL && got->body_len == sizeof(BODY_A) &&
	                       memcmp(got->body, BODY_A, got->body_len) == 0, "a refused conflict left the value alone");
	expect(got != NULL && memcmp(got->issuer, alice, FZN_PUBKEY_LEN) == 0,
	       "and left the issuer alone");

	/* RESOLVING IS DELIBERATE, and then bob holds it. */
	expect_err(fzn_state_resolve(&st, &rec), FZN_STATE_OK, "resolving in bob's favour");
	got = fzn_state_get(&st, subj, 1);
	expect(got != NULL && got->body_len == sizeof(BODY_B) &&
	                       memcmp(got->body, BODY_B, got->body_len) == 0, "bob's value now stands");
	expect(got != NULL && memcmp(got->issuer, bob, FZN_PUBKEY_LEN) == 0,
	       "and bob is recorded as having set it");
	expect(got != NULL && got->stream == 1, "with his stream, not the one it replaced");
	expect(fzn_state_count(&st) == 2, "resolving did not add an entry");

	/* And now ALICE is the conflicting one, which is the direction that
	 * proves the check is about identity rather than about order. */
	make(&rec, 0xa1, 1, 0x51, 1, 100, BODY_A, sizeof(BODY_A));
	expect_err(fzn_state_apply(&st, &rec), FZN_STATE_ERR_CONFLICT,
	           "alice writing what is now bob's");

	/* RESOLVE ALSO OVERRIDES CROSS-STREAM. It is the same problem -- two
	 * writers and no way to order them -- and a consumer with a rule for
	 * one has had to answer the other. */
	make(&rec, 0xb2, 5, 0x51, 1, 3, BODY_A, sizeof(BODY_A));
	expect_err(fzn_state_apply(&st, &rec), FZN_STATE_ERR_CROSS_STREAM,
	           "bob writing his own subject from another stream");
	expect_err(fzn_state_resolve(&st, &rec), FZN_STATE_OK, "which resolve takes");
	got = fzn_state_get(&st, subj, 1);
	expect(got != NULL && got->stream == 5 && got->seq == 3,
	       "and the new stream and its sequence are what the cell now holds");

	/* CLEARING LEAVES A TOMBSTONE.
	 *
	 * The cell keeps its writer and the clearing sequence. `fzn_state_clear`
	 * used to memset the entry, and then a record fifty sequences below the
	 * clear was accepted and set the value again -- a revocation any replay
	 * undoes is not a revocation. */
	make(&rec, 0xa1, 5, 0x51, 1, 101, BODY_A, sizeof(BODY_A));
	expect_err(fzn_state_clear(&st, &rec), FZN_STATE_ERR_CONFLICT,
	           "alice clearing bob's subject");
	make(&rec, 0xb2, 6, 0x51, 1, 101, BODY_B, sizeof(BODY_B));
	expect_err(fzn_state_clear(&st, &rec), FZN_STATE_ERR_CROSS_STREAM,
	           "bob clearing his own subject from another stream");
	make(&rec, 0xb2, 5, 0x51, 1, 2, BODY_B, sizeof(BODY_B));
	expect_err(fzn_state_clear(&st, &rec), FZN_STATE_ERR_STALE,
	           "bob clearing with an older sequence");
	/* CLEARING SOMETHING NEVER SET IS NOT A REFUSAL ANY MORE. It takes a
	 * slot, leaves that writer's tombstone, and says ABSENT -- which
	 * reports what was here before rather than what was done. Read the
	 * count either side: a refusal would have left `used` where it was, so
	 * this is the assertion that the pre-emptive tombstone is real rather
	 * than the error code merely being renamed. */
	make(&rec, 0xb2, 5, 0x51, 9, 200, BODY_B, sizeof(BODY_B));
	{
		size_t before = st.used;

		expect_err(fzn_state_clear(&st, &rec), FZN_STATE_ABSENT,
		           "clearing something never set");
		expect(st.used == before + 1, "took a slot for the tombstone");
		expect(fzn_state_count(&st) == 2, "which counts as no value");
		expect(fzn_state_get(&st, subj, 9) == NULL, "and reads as unset");
	}
	/* AND THE PRE-EMPTIVE TOMBSTONE ORDERS WHAT COMES AFTER IT, which is
	 * the entire reason it costs a slot: this is the record the old code
	 * accepted, leaving the subject SET by something the revocation had
	 * already superseded. */
	make(&rec, 0xb2, 5, 0x51, 9, 199, BODY_B, sizeof(BODY_B));
	expect_err(fzn_state_apply(&st, &rec), FZN_STATE_ERR_STALE,
	           "a grant below a pre-emptive tombstone does not get in behind it");
	expect(fzn_state_get(&st, subj, 9) == NULL, "and the subject stays unset");

	make(&rec, 0xb2, 5, 0x51, 1, 200, BODY_B, sizeof(BODY_B));
	expect_err(fzn_state_clear(&st, &rec), FZN_STATE_OK, "bob clearing his own");
	expect(fzn_state_get(&st, subj, 1) == NULL, "and it reads as unset");
	expect(fzn_state_count(&st) == 1, "leaving the other kind");

	/* THE TOMBSTONE STILL ORDERS AND STILL NAMES ITS WRITER. */
	make(&rec, 0xb2, 5, 0x51, 1, 150, BODY_B, sizeof(BODY_B));
	expect_err(fzn_state_apply(&st, &rec), FZN_STATE_ERR_STALE,
	           "a record older than the clear does not undo it");
	expect(fzn_state_get(&st, subj, 1) == NULL, "and the subject is still unset");
	make(&rec, 0xa1, 5, 0x51, 1, 900, BODY_A, sizeof(BODY_A));
	expect_err(fzn_state_apply(&st, &rec), FZN_STATE_ERR_CONFLICT,
	           "and a stranger cannot take a cleared subject either");
	make(&rec, 0xb2, 8, 0x51, 1, 900, BODY_B, sizeof(BODY_B));
	expect_err(fzn_state_apply(&st, &rec), FZN_STATE_ERR_CROSS_STREAM,
	           "nor another stream of the writer that cleared it");

	/* THE POSITIVE CONTROL FOR THE TOMBSTONE. Without this, a clear that
	 * was simply permanent would satisfy everything above -- a different
	 * bug of the same size, and the one a consumer notices when a
	 * re-granted permission never comes back. */
	make(&rec, 0xb2, 5, 0x51, 1, 201, BODY_B, sizeof(BODY_B));
	expect_err(fzn_state_apply(&st, &rec), FZN_STATE_OK,
	           "a record newer than the clear sets the subject again");
	got = fzn_state_get(&st, subj, 1);
	expect(got != NULL && got->body_len == sizeof(BODY_B) &&
	                       memcmp(got->body, BODY_B, got->body_len) == 0 && got->seq == 201, "with its value back");
	expect(fzn_state_count(&st) == 2, "and counted again");

	/* A TOMBSTONE HOLDS ITS OWN SLOT, so set and clear cycles on one
	 * subject do not consume capacity: `find` hits the tombstone and the
	 * cell is written in place. */
	{
		fzn_state_t cycles;
		fzn_state_entry_t centries[2];

		expect_err(fzn_state_init(&cycles, centries, 2), FZN_STATE_OK, "a small state");
		for (uint64_t seq = 1; seq < 40; seq += 2) {
			make(&rec, 0xa1, 3, 0x70, 1, seq, BODY_A, sizeof(BODY_A));
			expect_err(fzn_state_apply(&cycles, &rec), FZN_STATE_OK, "set in a cycle");
			make(&rec, 0xa1, 3, 0x70, 1, seq + 1, BODY_A, sizeof(BODY_A));
			expect_err(fzn_state_clear(&cycles, &rec), FZN_STATE_OK,
			           "clear in a cycle");
		}
		expect(fzn_state_forgotten(&cycles) == 0,
		       "twenty set and clear cycles forget nothing");

		/* AND A TOMBSTONE IS EVICTED BEFORE A NEW SUBJECT IS REFUSED.
		 * Losing it can at worst readmit a replay the journal already
		 * refuses; refusing the new subject could drop a revocation. */
		make(&rec, 0xa1, 3, 0x71, 1, 1, BODY_A, sizeof(BODY_A));
		expect_err(fzn_state_apply(&cycles, &rec), FZN_STATE_OK, "a second subject");
		make(&rec, 0xa1, 3, 0x72, 1, 1, BODY_A, sizeof(BODY_A));
		expect_err(fzn_state_apply(&cycles, &rec), FZN_STATE_OK,
		           "a third subject takes the tombstone's slot");
		expect(fzn_state_forgotten(&cycles) == 1, "and says it forgot one");

		/* A LIVE SETTING IS STILL NEVER EVICTED. Both slots hold values
		 * now, so there is nothing left that may be forgotten. */
		make(&rec, 0xa1, 3, 0x73, 1, 1, BODY_A, sizeof(BODY_A));
		expect_err(fzn_state_apply(&cycles, &rec), FZN_STATE_ERR_FULL, "a fourth subject");
		expect(fzn_state_forgotten(&cycles) == 1, "having forgotten nothing more");
		expect(fzn_state_count(&cycles) == 2, "and both values are still there");
	}

	/* FULL IS REFUSED, NOT EVICTED.
	 *
	 * THE FIRST ONE IS TAKEN NOW, and the reason is the design change: the
	 * `0x51/9` clear above left a pre-emptive tombstone in the third slot,
	 * and a tombstone is forgotten before a new subject is refused. That is
	 * the eviction policy working, and it is exactly the answer to the
	 * objection the old design raised -- a state carrying tombstones for
	 * subjects nothing ever set still admits every live setting offered to
	 * it. The line used to read `forgotten == 0` because no tombstone
	 * existed to forget. */
	{
		uint8_t other[FZN_SUBJECT_LEN];

		expect(fzn_state_forgotten(&st) == 0, "nothing forgotten yet");
		make(&rec, 0xa1, 1, 0x60, 1, 1, BODY_A, sizeof(BODY_A));
		expect_err(fzn_state_apply(&st, &rec), FZN_STATE_OK, "a third subject");
		expect(fzn_state_forgotten(&st) == 1,
		       "which took the pre-emptive tombstone's slot");
		make(&rec, 0xa1, 1, 0x61, 1, 1, BODY_A, sizeof(BODY_A));
		expect_err(fzn_state_apply(&st, &rec), FZN_STATE_ERR_FULL, "a fourth subject");
		expect(fzn_state_forgotten(&st) == 1, "with no tombstone left to forget");

		memset(other, 0x60, sizeof(other));
		expect(fzn_state_get(&st, other, 1) != NULL,
		       "a full state must not have evicted an earlier subject");

		/* AND A CLEAR OF AN ABSENT SUBJECT CAN NOW BE REFUSED FOR
		 * CAPACITY, which is the one way left for a revocation not to
		 * land and is why `state.h` names it. Every slot here holds a
		 * LIVE setting, so there is nothing evictable; the alternative
		 * would be to evict a value, which reverts it to a consumer's
		 * default with nothing to trace. It is at least visible, which
		 * is what the invariant asks of a departure. */
		make(&rec, 0xa1, 1, 0x62, 1, 1, BODY_REVOKE, sizeof(BODY_REVOKE));
		expect_err(fzn_state_clear(&st, &rec), FZN_STATE_ERR_FULL,
		           "a clear into a state of nothing but live settings");
		expect(fzn_state_count(&st) == 3, "and it evicted no value to make room");
	}

	/* A FLOOD OF CLEARS COSTS EVICTIONS, NEVER SERVICE.
	 *
	 * This is the objection the rejected design raised -- "spending a slot
	 * to say so would let a stream of clears fill a state that holds no
	 * values" -- measured instead of assumed. Clears for distinct subjects
	 * do fill the state, and every one of those cells is a tombstone, so
	 * `slot` forgets one rather than refusing the live setting that arrives
	 * next. The old rule spent no slot on a clear and spent them freely on
	 * live records for junk subjects, which cannot be evicted at all: it
	 * was the worse denial of the two, not the safer one. */
	{
		fzn_state_t flood;
		fzn_state_entry_t fentries[2];
		uint8_t only[FZN_SUBJECT_LEN];

		expect_err(fzn_state_init(&flood, fentries, 2), FZN_STATE_OK, "a small state");
		for (uint8_t s = 0x80; s < 0x88; s++) {
			make(&rec, 0xa1, 3, s, 1, 1, BODY_REVOKE, sizeof(BODY_REVOKE));
			expect_err(fzn_state_clear(&flood, &rec), FZN_STATE_ABSENT,
			           "a clear for a subject nothing ever set");
		}
		expect(fzn_state_count(&flood) == 0, "eight clears hold no values");
		expect(fzn_state_forgotten(&flood) == 6, "and forgot the six they displaced");

		make(&rec, 0xa1, 3, 0x90, 1, 1, BODY_A, sizeof(BODY_A));
		expect_err(fzn_state_apply(&flood, &rec), FZN_STATE_OK,
		           "and a live setting is still admitted after the flood");
		memset(only, 0x90, sizeof(only));
		expect(fzn_state_get(&flood, only, 1) != NULL, "and readable");

		/* REPEATED CLEARS OF ONE SUBJECT COST NOTHING, because `find`
		 * hits the tombstone and it is rewritten in place -- the same
		 * property the set-and-clear cycle above has, on the path that
		 * never had a cell to begin with. */
		{
			uint64_t before = fzn_state_forgotten(&flood);

			for (uint64_t seq = 1; seq < 20; seq++) {
				make(&rec, 0xa1, 3, 0x91, 1, seq, BODY_REVOKE,
				     sizeof(BODY_REVOKE));
				expect_err(fzn_state_clear(&flood, &rec),
				           seq == 1 ? FZN_STATE_ABSENT : FZN_STATE_OK,
				           "clearing an already-cleared subject");
			}
			expect(fzn_state_forgotten(&flood) == before + 1,
			       "nineteen clears of one subject took one slot between them");
		}
	}

	/* Arguments. */
	expect_err(fzn_state_apply(&st, NULL), FZN_STATE_ERR_MALFORMED, "a null record");
	expect_err(fzn_state_apply(NULL, &rec), FZN_STATE_ERR_MALFORMED, "a null state to apply to");
	/* SEQUENCE ZERO AND A NULL BODY ARE NOW UNBUILDABLE, which is the
	 * change working rather than coverage lost. `fzn_record_sign` refuses
	 * sequence zero and a null body of non-zero length at the point a
	 * record is MADE, so neither state can reach `fzn_state_apply` -- and
	 * a state a caller cannot construct is one this module need not
	 * defend against. `record_test` holds those two refusals now.
	 *
	 * What a caller can still hand over is a record it never opened. */
	{
		fzn_record_t never;

		memset(&never, 0, sizeof(never));
		expect_err(fzn_state_apply(&st, &never), FZN_STATE_ERR_MALFORMED,
		           "a record never opened");
		expect_err(fzn_state_clear(&st, &never), FZN_STATE_ERR_MALFORMED,
		           "clearing with a record never opened");
	}
	expect(fzn_state_get(NULL, subj, 1) == NULL, "a null state answers nothing");
	expect(fzn_state_count(NULL) == 0, "a null state counts nothing");
	expect(fzn_state_forgotten(NULL) == 0, "a null state has forgotten nothing");
	expect_err(fzn_state_clear(&st, NULL), FZN_STATE_ERR_MALFORMED, "clearing with no record");
	expect_err(fzn_state_clear(NULL, &rec), FZN_STATE_ERR_MALFORMED,
	           "clearing a null state");

	/* TWO SUBJECTS THAT AGREE ON EVERY BYTE BUT THE LAST.
	 *
	 * Every other subject in this file is `memset(buf, seed, 32)`, so any
	 * two of them differ at byte 0 and a comparison of ONE byte separates
	 * them exactly as well as a comparison of thirty-two. That made the
	 * length in `fzn_ct_memeq(state->entries[i].subject, subject,
	 * FZN_SUBJECT_LEN)` unfalsifiable: truncating it to 1 left this whole
	 * suite green, measured before this case was written.
	 *
	 * WHAT FAILS OPEN IS TWO SUBJECTS SHARING ONE CELL. `find` is the
	 * lookup behind both `fzn_state_get` and `put`, so a short compare
	 * makes one subject's setting answer a question about another's AND
	 * lets a record for one overwrite the other's value in place -- with
	 * no CONFLICT reported, because a single writer holds both. A subject
	 * is a configuration key; this is one host's setting quietly becoming
	 * another's, which is the fault `state.h` says keying by stream would
	 * cause and is the same fault by a different route. */
	{
		uint8_t twin_a[FZN_SUBJECT_LEN], twin_b[FZN_SUBJECT_LEN];
		uint8_t writer[FZN_PUBKEY_LEN];
		fzn_state_t tst;
		fzn_state_entry_t tentries[4];
		const fzn_state_entry_t *got;
		fzn_record_t ta, tb;

		memset(twin_a, 0x5a, sizeof(twin_a));
		memset(twin_b, 0x5a, sizeof(twin_b));
		twin_b[FZN_SUBJECT_LEN - 1u] ^= 0x01u;
		memset(writer, 0xc1, sizeof(writer));

		expect(memcmp(twin_a, twin_b, FZN_SUBJECT_LEN - 1u) == 0,
		       "the twin subjects must agree on every byte but the last, or this "
		       "case is not testing what it says");
		expect(memcmp(twin_a, twin_b, FZN_SUBJECT_LEN) != 0,
		       "the twin subjects must differ somewhere, or nothing here can fail");

		expect_err(fzn_state_init(&tst, tentries, 4), FZN_STATE_OK,
		           "a state to hold the twin subjects");
		make_keyed(&ta, writer, twin_a, 3, 1, 1, BODY_A, sizeof(BODY_A));
		make_keyed(&tb, writer, twin_b, 3, 1, 2, BODY_B, sizeof(BODY_B));
		expect_err(fzn_state_apply(&tst, &ta), FZN_STATE_OK,
		           "the first twin subject is set");
		/* ONE WRITER ON ONE STREAM, so a folded lookup does not stop at
		 * a contention code: it finds the first twin's cell, agrees on
		 * the issuer and the stream, sees a higher sequence and
		 * overwrites in place, reporting OK. */
		expect_err(fzn_state_apply(&tst, &tb), FZN_STATE_OK,
		           "the second twin subject is set");

		expect(fzn_state_count(&tst) == 2,
		       "two subjects differing only in their last byte landed in one cell "
		       "-- the subject comparison is not reading the whole subject");

		got = fzn_state_get(&tst, twin_a, 1);
		expect(got != NULL && got->body_len == sizeof(BODY_A) &&
		                       memcmp(got->body, BODY_A, got->body_len) == 0,
		       "the first twin subject reads back as the second's value -- "
		       "fzn_state_get is not reading the whole subject");
		got = fzn_state_get(&tst, twin_b, 1);
		expect(got != NULL && got->body_len == sizeof(BODY_B) &&
		                       memcmp(got->body, BODY_B, got->body_len) == 0,
		       "the second twin subject is not holding its own value");
	}

	/* AND TWO WRITERS THAT AGREE ON EVERY BYTE BUT THE LAST, which is a
	 * SEPARATE COMPARISON on a separate path -- the contention test in
	 * `put`, not the lookup above. Truncating it to one byte left the case
	 * above green and the whole suite with it, so closing one says nothing
	 * about the other: the vacuity is one per comparison, not one per file.
	 *
	 * WHAT FAILS OPEN IS THE CONTENTION ALARM ITSELF. `put` reports
	 * CONFLICT when the record's issuer is not the cell's, and that
	 * refusal is the only thing standing between an authorised writer and
	 * another writer's configuration. A short compare takes a stranger for
	 * the cell's own writer, drops through to the sequence test, and
	 * overwrites the value with nothing to show it happened -- the silent
	 * resolution this file's opening paragraph names as the cost. */
	{
		uint8_t twin_a[FZN_PUBKEY_LEN], twin_b[FZN_PUBKEY_LEN];
		uint8_t subject[FZN_SUBJECT_LEN];
		fzn_state_t tst;
		fzn_state_entry_t tentries[4];
		const fzn_state_entry_t *got;
		fzn_record_t ta, tb;

		memset(twin_a, 0x3c, sizeof(twin_a));
		memset(twin_b, 0x3c, sizeof(twin_b));
		twin_b[FZN_PUBKEY_LEN - 1u] ^= 0x01u;
		memset(subject, 0x77, sizeof(subject));

		expect(memcmp(twin_a, twin_b, FZN_PUBKEY_LEN - 1u) == 0,
		       "the twin writers must agree on every byte but the last, or this "
		       "case is not testing what it says");
		expect(memcmp(twin_a, twin_b, FZN_PUBKEY_LEN) != 0,
		       "the twin writers must differ somewhere, or nothing here can fail");

		expect_err(fzn_state_init(&tst, tentries, 4), FZN_STATE_OK,
		           "a state for the twin writers");
		/* The same stream, so that a stranger reaching the sequence
		 * test is refused for being a stranger and not for being on
		 * another stream, and a higher sequence, so that nothing but
		 * the issuer comparison can refuse it. */
		make_keyed(&ta, twin_a, subject, 1, 1, 5, BODY_A, sizeof(BODY_A));
		make_keyed(&tb, twin_b, subject, 1, 1, 9, BODY_B, sizeof(BODY_B));
		expect_err(fzn_state_apply(&tst, &ta), FZN_STATE_OK,
		           "the first twin writer takes the cell");
		expect_err(fzn_state_apply(&tst, &tb), FZN_STATE_ERR_CONFLICT,
		           "a writer differing from the cell's in one key byte was taken "
		           "for the cell's own -- the issuer comparison is not reading "
		           "the whole key");
		got = fzn_state_get(&tst, subject, 1);
		expect(got != NULL && got->body_len == sizeof(BODY_A) &&
		                       memcmp(got->body, BODY_A, got->body_len) == 0,
		       "and the refused record left the first twin writer's value alone");
	}

	property_state_is_a_function_of_the_set();
	property_a_divergence_is_reported();
	property_a_clear_lands_before_its_grant();
	property_a_revocation_can_take_another_writers_cell();
	property_the_contention_alarm_is_per_host();

	/* INIT LEAVES THE CALLER'S ENTRY ARRAY IN A KNOWN STATE.
	 *
	 * No lookup in state.c can observe it -- every loop there is bounded by
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
		fzn_state_t from_dirty, from_clean;
		fzn_state_entry_t dirty_entries[3], clean_entries[3];

		memset(dirty_entries, 0xab, sizeof(dirty_entries));
		memset(clean_entries, 0, sizeof(clean_entries));
		expect(memcmp(dirty_entries, clean_entries, sizeof(dirty_entries)) != 0,
		       "the two arrays start equal, so the comparison below cannot fail");

		expect(fzn_state_init(&from_dirty, dirty_entries, 3) == FZN_STATE_OK,
		       "init refused a dirty array");
		expect(fzn_state_init(&from_clean, clean_entries, 3) == FZN_STATE_OK,
		       "init refused a clean array");
		expect(memcmp(dirty_entries, clean_entries, sizeof(dirty_entries)) == 0,
		       "init left the caller's bytes in the entry array, so what a fresh "
		       "table holds depends on what its memory held");
	}

	printf("state_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
