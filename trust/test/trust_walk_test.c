/*
 * Every sequence of anchoring operations, to a depth, against the table
 * `trust.h` writes out in prose.
 *
 * WHY EXHAUSTIVE AND NOT FUZZED. This state machine is four sources and three
 * operations. Sampling it would be sampling something small enough to visit
 * whole -- 3 operations over 3 keys is 9 steps, and every sequence of four is
 * 6561 walks, which runs in less time than drawing random ones would. A fuzz
 * harness reports what it happened to reach; this reports that there is
 * nothing else to reach.
 *
 * THE TABLE IS THE HEADER'S, quoted so a reader can check the model against
 * the argument rather than against the code:
 *
 *     self -> pinned     permitted; an operator said so, out of band
 *     self -> adopted    REFUSED; nothing authenticated that
 *     self -> self       refused, like any other re-anchoring
 *     pinned or adopted -> anything else    refused, as before
 *
 * plus FZN_TRUST_ERR_UNCHANGED for an anchor re-stated with the SAME key,
 * which the header calls "an echo -- a join repeated, a bundle delivered
 * twice -- and not a fault".
 *
 * THE PROPERTY THAT NEEDS NO MODEL AT ALL is asserted first and at every
 * step: a call that does not return OK leaves the anchor byte-identical. A
 * refusal that moved something would be the worst failure this module could
 * have -- the anchor is what every other decision is measured against -- and
 * it is the property `ratchet_fuzz` found a hole in when its only refusals
 * were ones that returned before the module touched anything. Here every
 * refusal is reached from every reachable state.
 *
 * WHERE THE MODEL AND THE MODULE DISAGREE, THE RUN SAYS SO AND STOPS rather
 * than the model being adjusted to match. `evidence.md`: an independent check
 * exists to disagree, and the moment it does is the moment it is most
 * tempting to edit.
 */

#include "../trust.h"

#include <stdio.h>
#include <string.h>

/* NO `CHECK` MACRO HERE, deliberately. Every assertion in this file has a
 * SEQUENCE to report -- "after [pin(0) self(1) adopt(2)] the module says ..."
 * -- and a failure naming only a line number would leave the reader to
 * reconstruct which of 6561 walks it was. The style gate's rule is that a
 * failure line names its suite; this goes further because the suite alone is
 * not enough to find the case. */
static int failures;
static int checks;

/* Three keys: this node's own, a peer's, and a third nobody has met. Three is
 * the fewest that can tell "the same key" from "a different one" while a
 * self-root is in play. */
#define KEYS 3u
#define OPS 3u
#define DEPTH 4u

static uint8_t key[KEYS][FZN_PUBKEY_LEN];

/* The model: what `trust.h` says the anchor should be. */
struct model {
	fzn_trust_source_t source;
	unsigned root; /* index into `key`, meaningless when source is NONE */
	uint64_t adopted_at;
};

/* Applies one step to the model and returns what the call must answer.
 *
 * WRITTEN FROM THE HEADER, not from trust.c. The whole value of this file is
 * that the two were arrived at separately. */
static fzn_trust_err_t model_step(struct model *m, unsigned op, unsigned k, uint64_t now)
{
	/* op 0 pin, op 1 adopt, op 2 self. */
	if (m->source == FZN_TRUST_NONE) {
		if (op == 0u) {
			m->source = FZN_TRUST_PINNED;
			m->root = k;
		} else if (op == 1u) {
			m->source = FZN_TRUST_ADOPTED;
			m->root = k;
			m->adopted_at = now;
		} else {
			m->source = FZN_TRUST_SELF;
			m->root = k;
		}
		return FZN_TRUST_OK;
	}

	/* THE SAME KEY AGAIN IS AN ECHO, whatever asked for it and whatever
	 * the anchor's source is -- the header distinguishes UNCHANGED from
	 * ANCHORED by the KEY and not by the operation. */
	if (k == m->root)
		return FZN_TRUST_ERR_UNCHANGED;

	/* A SELF-ROOT MAY BE REPLACED BY A PIN AND BY NOTHING ELSE. */
	if (m->source == FZN_TRUST_SELF && op == 0u) {
		m->source = FZN_TRUST_PINNED;
		m->root = k;
		return FZN_TRUST_OK;
	}

	return FZN_TRUST_ERR_ANCHORED;
}

static fzn_trust_err_t real_step(fzn_trust_t *t, unsigned op, unsigned k, uint64_t now)
{
	if (op == 0u)
		return fzn_trust_pin(t, key[k]);
	if (op == 1u)
		return fzn_trust_adopt(t, key[k], now);
	return fzn_trust_self(t, key[k]);
}

static const char *op_name(unsigned op)
{
	return op == 0u ? "pin" : (op == 1u ? "adopt" : "self");
}

/* How many walks reached each verdict, so a run that exercised one arm and
 * called itself exhaustive says so. */
static unsigned long saw_ok, saw_anchored, saw_unchanged, saw_self_to_pin;

static int walk(unsigned depth, char *trail, size_t trail_len)
{
	unsigned seq[DEPTH];
	unsigned i;
	unsigned long combos = 1u;

	for (i = 0; i < depth; i++)
		combos *= OPS * KEYS;

	for (unsigned long c = 0; c < combos; c++) {
		unsigned long rest = c;
		fzn_trust_t t;
		struct model m;
		size_t at = 0u;

		fzn_trust_init(&t);
		memset(&m, 0, sizeof(m));
		m.source = FZN_TRUST_NONE;
		trail[0] = '\0';

		for (i = 0; i < depth; i++) {
			seq[i] = (unsigned)(rest % (OPS * KEYS));
			rest /= OPS * KEYS;
		}

		for (i = 0; i < depth; i++) {
			unsigned op = seq[i] / KEYS;
			unsigned k = seq[i] % KEYS;
			uint64_t now = 100u + i;
			fzn_trust_t before = t;
			fzn_trust_err_t want, got;
			struct model expected = m;

			at += (size_t)snprintf(trail + at, trail_len - at, "%s%s(%u)",
			                       at ? " " : "", op_name(op), k);

			want = model_step(&expected, op, k, now);
			got = real_step(&t, op, k, now);

			if (want != got) {
				fprintf(stderr,
				        "  FAIL trust_walk_test.c: after [%s] the model says "
				        "%s and the module says %s\n",
				        trail, fzn_trust_err_str(want), fzn_trust_err_str(got));
				failures++;
				checks++;
				return 1;
			}
			checks++;

			/* THE PROPERTY THAT NEEDS NO MODEL. A refusal must have
			 * moved nothing at all -- and `log` is part of the
			 * struct, so this catches a write to any field. */
			if (got != FZN_TRUST_OK) {
				if (memcmp(&before, &t, sizeof(t)) != 0) {
					fprintf(stderr,
					        "  FAIL trust_walk_test.c: [%s] was refused "
					        "with %s and changed the anchor\n",
					        trail, fzn_trust_err_str(got));
					failures++;
					checks++;
					return 1;
				}
				checks++;
				if (got == FZN_TRUST_ERR_ANCHORED)
					saw_anchored++;
				else if (got == FZN_TRUST_ERR_UNCHANGED)
					saw_unchanged++;
			} else {
				saw_ok++;
				if (m.source == FZN_TRUST_SELF && op == 0u)
					saw_self_to_pin++;
			}

			m = expected;

			/* AND THE SOURCE THE CONSUMER READS IS THE MODEL'S. */
			if (fzn_trust_source_of(&t) != m.source) {
				fprintf(stderr,
				        "  FAIL trust_walk_test.c: after [%s] the anchor "
				        "reports %s and should be %s\n",
				        trail, fzn_trust_source_str(fzn_trust_source_of(&t)),
				        fzn_trust_source_str(m.source));
				failures++;
				checks++;
				return 1;
			}
			checks++;

			if (m.source != FZN_TRUST_NONE
			    && memcmp(t.root, key[m.root], FZN_PUBKEY_LEN) != 0) {
				fprintf(stderr,
				        "  FAIL trust_walk_test.c: after [%s] the anchor "
				        "holds a key the model did not put there\n",
				        trail);
				failures++;
				checks++;
				return 1;
			}
			checks++;
		}
	}
	return 0;
}

int main(void)
{
	char trail[256];
	unsigned i;

	for (i = 0; i < KEYS; i++)
		memset(key[i], (int)(0xa0u + i), FZN_PUBKEY_LEN);

	if (walk(DEPTH, trail, sizeof(trail))) {
		printf("trust_walk_test: %d checks, %d failure(s)\n", checks, failures);
		return 1;
	}

	/* EVERY ARM WAS REACHED, or the walk proved less than it claims. The
	 * self-to-pin one is the join the header calls the whole design, and
	 * it is the arm a shallower walk would miss. */
	if (!saw_ok || !saw_anchored || !saw_unchanged || !saw_self_to_pin) {
		printf("trust_walk_test: REACHED TOO LITTLE -- %lu ok, %lu anchored, %lu "
		       "unchanged, %lu self-to-pin\n",
		       saw_ok, saw_anchored, saw_unchanged, saw_self_to_pin);
		return 1;
	}

	printf("trust_walk_test: %d checks, %d failure(s); every sequence of %u "
	       "operations over %u keys agreed with the header's table (%lu ok, %lu "
	       "anchored, %lu unchanged, %lu self-to-pin)\n",
	       checks, failures, DEPTH, KEYS, saw_ok, saw_anchored, saw_unchanged,
	       saw_self_to_pin);
	return failures == 0 ? 0 : 1;
}
