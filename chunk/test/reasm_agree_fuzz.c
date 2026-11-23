/* THE REASSEMBLY TABLE ON SITU'S CODE AGAINST THE ONE IT REPLACED, project.md
 * sec 1404: `chunk/reassembly.c`, whose messages are assembled by the table
 * situ generates from wire/frame.situ, and `chunk/test/reasm_ref.h`, the
 * hand-written table it was until then, kept whole as the oracle. Each is
 * given the same seeded stream of pieces -- several senders, messages that
 * complete and ones that never do, resends identical and altered, pieces
 * past their count, off the stride, empty, past their expiry, forgets and
 * expiries between -- and every answer is compared code for code, every
 * completed message byte for byte, every forget and expiry count for count.
 *
 * ONE DIFFERENCE IS ACCEPTED, and counted by name: a held piece resent
 * shorter, its bytes a prefix of what is held, which the oracle took as
 * identical and the new table refuses as the conflict it is.
 *
 * Exit 0 when nothing else differed; 1 with each kind of difference, how
 * often, and its first step. `make fuzz CASES=N` asks N steps.
 */

#include "../reassembly.h"
#include "reasm_ref.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SLOTS 4u
#define CAPACITY 4096u
#define PER 2u
#define HOLD 30u
#define STEPS 20000u
#define SENDERS 3u
#define STRIDE 100u
#define CODES 10

static uint64_t rng = 0x1404u;

static uint32_t next(void)
{
	rng ^= rng << 13;
	rng ^= rng >> 7;
	rng ^= rng << 17;
	return (uint32_t)rng;
}

/* A code as an index: 0 for ok, then each error, the same for both. */
static int index_of(int code)
{
	return code <= 0 && code >= -8 ? -code : 9;
}

static fzn_partial_t partials[SLOTS];
static fzn_ref_partial_t ref_partials[SLOTS];
static uint8_t bufs[SLOTS][CAPACITY], ref_bufs[SLOTS][CAPACITY];
static unsigned seen[CODES][CODES], first_step[CODES][CODES];

int main(int argc, char **argv)
{
	fzn_reasm_t ours;
	fzn_reasm_ref_t ref;
	uint8_t senders[SENDERS][FZN_SENDER_LEN], piece[STRIDE + 8u];
	uint64_t now = 1000u;
	unsigned step, i, j, disagree = 0, completes = 0, same_bytes = 0, prefix = 0, wants = 0, wants_differ = 0;
	/* AS MANY STEPS AS `make fuzz CASES=N` asks, or STEPS. */
	const unsigned steps = argc > 1 ? (unsigned)strtoul(argv[1], NULL, 10) : STEPS;

	for (i = 0; i < SENDERS; i++)
		memset(senders[i], 0x10 + (int)i, FZN_SENDER_LEN);
	for (i = 0; i < SLOTS; i++)
		if (fzn_reasm_slot_init(&partials[i], bufs[i], CAPACITY) != FZN_REASM_OK
		    || fzn_reasm_ref_slot_init(&ref_partials[i], ref_bufs[i], CAPACITY) != FZN_REASM_REF_OK)
			return 2;
	if (fzn_reasm_init(&ours, partials, SLOTS, PER, HOLD) != FZN_REASM_OK
	    || fzn_reasm_ref_init(&ref, ref_partials, SLOTS, PER, HOLD) != FZN_REASM_REF_OK)
		return 2;
	for (step = 0; step < steps; step++) {
		const unsigned s = next() % SENDERS, roll = next() % 100u;
		const uint32_t msg = next() % 6u;
		uint16_t chunks = (uint16_t)(1u + next() % 5u), index;
		uint64_t expires = 0;
		size_t len;
		fzn_partial_t *done = NULL;
		fzn_ref_partial_t *ref_done = NULL;
		int co, cr;

		now += next() % 3u;
		if (roll < 2u) {
			size_t a = fzn_reasm_expire(&ours, now), b = fzn_reasm_ref_expire(&ref, now);

			if (a != b)
				disagree++;
			continue;
		}
		if (roll < 4u) {
			size_t a = fzn_reasm_forget(&ours, senders[s], msg), b = fzn_reasm_ref_forget(&ref, senders[s], msg);

			if (a != b)
				disagree++;
			continue;
		}
		if (roll < 6u)
			chunks = (uint16_t)(next() % 2u ? 0u : 300u + next() % 50u);
		index = (uint16_t)(chunks ? next() % chunks : 0u);
		if (roll < 9u)
			index = (uint16_t)(chunks + next() % 3u);
		len = index + 1u == chunks ? 1u + next() % STRIDE : STRIDE;
		if (roll < 12u)
			len = next() % (STRIDE + 8u);
		for (i = 0; i < len; i++)
			piece[i] = (uint8_t)(msg * 31u + index * 7u + i);
		if (roll >= 12u && roll < 15u && len)
			piece[next() % len] ^= 0x5au;
		if (roll >= 15u && roll < 30u)
			expires = now + next() % 40u;
		if (roll >= 30u && roll < 33u)
			expires = now - (next() % 5u);
		co = (int)fzn_reasm_accept(&ours, senders[s], msg, index, chunks, piece, len, expires, now, &done);
		cr = (int)fzn_reasm_ref_accept(&ref, senders[s], msg, index, chunks, piece, len, expires, now, &ref_done);
		if (done || ref_done) {
			if (done && ref_done) {
				completes++;
				if (done->bytes == ref_done->bytes && !memcmp(done->buf, ref_done->buf, done->bytes))
					same_bytes++;
			} else {
				disagree++;
			}
		}
		/* THE ORACLE'S PREFIX FAULT, sec 1404: a shorter resend it took. */
		if (co == FZN_REASM_ERR_CONFLICT && cr == FZN_REASM_REF_OK && !ref_done) {
			prefix++;
		} else if (co != cr) {
			if (!seen[index_of(co)][index_of(cr)])
				first_step[index_of(co)][index_of(cr)] = step;
			seen[index_of(co)][index_of(cr)]++;
			disagree++;
		}
		/* WHAT IS STILL MISSING, asked of both after every piece taken: the
		 * ranges, with a room and a run bound of their own. */
		if (co == FZN_REASM_OK && !done) {
			fzn_reasm_range_t got[4];
			fzn_reasm_ref_range_t ref_got[4];
			size_t n = 0, rn = 0, cap = 1u + next() % 4u, k;
			const uint16_t most = (uint16_t)(1u + next() % 3u);
			const int a = (int)fzn_reasm_plan_want(&ours, senders[s], msg, most, got, cap, &n);
			const int b = (int)fzn_reasm_ref_plan_want(&ref, senders[s], msg, most, ref_got, cap, &rn);

			if (a != b || n != rn)
				wants_differ++;
			for (k = 0; a == b && n == rn && k < n; k++)
				if (got[k].first != ref_got[k].first || got[k].count != ref_got[k].count)
					wants_differ++;
			wants++;
		}
		if (done)
			fzn_reasm_release(done);
		if (ref_done)
			fzn_reasm_ref_release(ref_done);
	}
	printf("reasm_agree_fuzz: %u steps, %u completed by both, %u of them byte for byte, %u difference(s), "
	       "%u shorter resend(s) refused that the oracle took; %u missing-piece plans, %u differing\n",
	       steps, completes, same_bytes, disagree, prefix, wants, wants_differ);
	for (i = 0; i < CODES; i++)
		for (j = 0; j < CODES; j++)
			if (seen[i][j])
				printf("  new %s, old %s: %u, first at step %u\n", fzn_reasm_err_str((fzn_reasm_err_t)-(int)i),
				       fzn_reasm_err_str((fzn_reasm_err_t)-(int)j), seen[i][j], first_step[i][j]);
	return disagree || wants_differ || same_bytes != completes ? 1 : 0;
}
