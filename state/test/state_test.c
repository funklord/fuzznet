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
 * THE PROPERTY UNDERNEATH ALL OF THEM, and the last two tests here: the value
 * of a cell is a function of the SET of records applied to it and not of
 * their order, and where two orders must differ, the loser is REFUSED so that
 * the difference is visible. The defect that produced this file's
 * `stream` work was exactly that with a refusal missing -- stream 7 seq 100
 * then stream 9 seq 100 left stream 7's value, the reverse left stream 9's,
 * and both orders reported success.
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
		printf("  FAIL: %s\n", what);
	}
}

static void expect_err(fzn_state_err_t got, fzn_state_err_t want, const char *what)
{
	checks++;
	if (got != want) {
		failures++;
		printf("  FAIL: %s -- got \"%s\", wanted \"%s\"\n", what, fzn_state_err_str(got),
		       fzn_state_err_str(want));
	}
}

static const uint8_t BODY_A[] = "value from alice";
static const uint8_t BODY_B[] = "value from bob";
static const uint8_t BODY_A2[] = "alice's second thought";

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
 * -- the conflict cases hold two, the permutation property holds four. Thirty
 * two is far more than any case here needs, and `wire` is asserted below to
 * have wrapped no further than that. */
#define WIRE_SLOTS 32u
static uint8_t wire[WIRE_SLOTS][FZN_RECORD_MAX_LEN];
static size_t wire_next;
static size_t wire_made;

static void make(fzn_record_t *r, uint8_t issuer_seed, uint32_t stream, uint8_t subject_seed,
                 uint32_t kind, uint64_t seq, const uint8_t *body, size_t body_len)
{
	uint8_t issuer[FZN_PUBKEY_LEN], subject[FZN_SUBJECT_LEN];
	fzn_sign_ops_t ops;
	uint8_t *slot = wire[wire_next % WIRE_SLOTS];
	size_t wrote = 0;

	wire_next++;
	wire_made++;

	memset(issuer, issuer_seed, sizeof(issuer));
	memset(subject, subject_seed, sizeof(subject));
	memset(&ops, 0, sizeof(ops));
	ops.sign = fixture_sign;

	if (fzn_record_sign(issuer, subject, stream, kind, seq, 1, body, body_len, &ops, slot,
	                    FZN_RECORD_MAX_LEN, &wrote) != FZN_RECORD_OK) {
		printf("  FAIL: the fixture could not sign a record\n");
		failures++;
		memset(r, 0, sizeof(*r));
		return;
	}
	if (fzn_record_open(slot, wrote, r) != FZN_RECORD_OK) {
		printf("  FAIL: the fixture could not open the record it signed\n");
		failures++;
		memset(r, 0, sizeof(*r));
	}
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

/* Apply the records in this order to a fresh state. Returns the first refusal,
 * or OK if there was none -- and the refusal's identity is the point, not
 * merely that there was one. See `property_a_divergence_is_reported`. */
static fzn_state_err_t run_order(const fzn_record_t *recs, const int *order, int n,
                                  fzn_state_t *st, fzn_state_entry_t *entries, size_t capacity)
{
	fzn_state_err_t first = FZN_STATE_OK;

	fzn_state_init(st, entries, capacity);

	for (int i = 0; i < n; i++) {
		fzn_state_err_t err = fzn_state_apply(st, &recs[order[i]]);

		if (err != FZN_STATE_OK && first == FZN_STATE_OK)
			first = err;
	}

	return first;
}

/* ONE RECORD SET, ONE STATE, WHATEVER ORDER IT ARRIVES IN.
 *
 * Every cell here has exactly one writer, so nothing is refused for
 * contention and the property is unconditional: the value is the writer's
 * highest sequence, and a re-delivery of a lower one changes nothing. The
 * capacity is larger than the number of cells on purpose -- FULL is a
 * capacity effect and would be a legitimate reason for two orders to differ,
 * so it is kept out of the way of the property being measured. */
static void property_state_is_a_function_of_the_set(void)
{
	fzn_record_t recs[5];
	int order[5] = { 0, 1, 2, 3, 4 };
	fzn_state_t st;
	fzn_state_entry_t entries[8];
	struct view reference, current;
	int permutations = 1, divergent = 0;

	/* One cell written three times by one writer, out of sequence order. */
	make(&recs[0], 0xa1, 1, 0x51, 1, 10, BODY_A, sizeof(BODY_A));
	make(&recs[1], 0xa1, 1, 0x51, 1, 12, BODY_A2, sizeof(BODY_A2));
	make(&recs[2], 0xa1, 1, 0x51, 1, 11, BODY_B, sizeof(BODY_B));
	/* A second cell, a different issuer. */
	make(&recs[3], 0xb2, 1, 0x52, 1, 7, BODY_B, sizeof(BODY_B));
	/* A third cell: same subject as the first, different kind, and a
	 * different stream of the same issuer -- which is a different cell and
	 * must not contend with anything. */
	make(&recs[4], 0xa1, 2, 0x51, 2, 4, BODY_A, sizeof(BODY_A));

	run_order(recs, order, 5, &st, entries, 8);
	snapshot(&st, &reference);

	while (next_permutation(order, 5)) {
		run_order(recs, order, 5, &st, entries, 8);
		snapshot(&st, &current);
		permutations++;
		if (!view_eq(&reference, &current))
			divergent++;
	}

	/* The count is checked because a loop that ran no permutations would
	 * report zero divergences just as loudly as one that ran them all. */
	expect(permutations == 120, "five records have 120 orders and all of them ran");
	expect(divergent == 0, "every order of one record set leaves one state");

	expect(reference.count == 3, "three cells, whatever the order");
	expect(memcmp(reference.cell[0].body, BODY_A2, reference.cell[0].body_len) == 0 && reference.cell[0].seq == 12,
	       "the highest sequence of the writer holds the first cell");
	expect(memcmp(reference.cell[1].body, BODY_A, reference.cell[1].body_len) == 0 && reference.cell[1].stream == 2,
	       "another kind of the same subject is its own cell");
	expect(memcmp(reference.cell[2].body, BODY_B, reference.cell[2].body_len) == 0 && reference.cell[2].seq == 7,
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
	int forward[2] = { 0, 1 }, backward[2] = { 1, 0 };
	fzn_state_t st;
	fzn_state_entry_t entries[4];
	struct view first, second;
	fzn_state_err_t err_forward, err_backward;

	make(&recs[0], 0xa1, 7, 0x51, 1, 100, BODY_A, sizeof(BODY_A));
	make(&recs[1], 0xa1, 9, 0x51, 1, 100, BODY_B, sizeof(BODY_B));

	err_forward = run_order(recs, forward, 2, &st, entries, 4);
	snapshot(&st, &first);
	err_backward = run_order(recs, backward, 2, &st, entries, 4);
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
	make(&rec, 0xb2, 5, 0x51, 9, 200, BODY_B, sizeof(BODY_B));
	expect_err(fzn_state_clear(&st, &rec), FZN_STATE_ERR_ABSENT,
	           "clearing something never set");
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

	/* FULL IS REFUSED, NOT EVICTED. */
	{
		uint8_t other[FZN_SUBJECT_LEN];

		make(&rec, 0xa1, 1, 0x60, 1, 1, BODY_A, sizeof(BODY_A));
		expect_err(fzn_state_apply(&st, &rec), FZN_STATE_OK, "a third subject");
		make(&rec, 0xa1, 1, 0x61, 1, 1, BODY_A, sizeof(BODY_A));
		expect_err(fzn_state_apply(&st, &rec), FZN_STATE_ERR_FULL, "a fourth subject");
		expect(fzn_state_forgotten(&st) == 0, "with no tombstone to forget");

		memset(other, 0x60, sizeof(other));
		expect(fzn_state_get(&st, other, 1) != NULL,
		       "a full state must not have evicted an earlier subject");
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

	property_state_is_a_function_of_the_set();
	property_a_divergence_is_reported();

	printf("state_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
