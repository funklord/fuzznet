/* THE TWO REASSEMBLY TABLES ON ONE STREAM, project.md sec 1404: fuzznet's
 * own (`chunk/reassembly.c`) and the one situ generates from
 * `wire/frame.situ`'s `reassemble pieces` (26.1123), each given the same
 * seeded stream of pieces -- several senders, messages that complete and
 * ones that never do, resends identical and altered, pieces past their
 * count, off the stride, past their expiry, forgets and expiries between --
 * and every answer compared, by the reason each gives for it, and every
 * completed message byte for byte.
 *
 * It is the evidence the move of `chunk/reassembly.c` onto the generated
 * table rests on: what this reports as disagreeing is what the move would
 * change. A completed message is released at once, as every caller here
 * does (node/serve.c, node/caller.c), since the generated table frees its
 * slot on completion.
 *
 * Exit 0 when every answer agreed; 1 with each kind of disagreement and
 * how often, and the first case of each.
 */

#include "../reassembly.h"
#include "../../wire/generated/frame_converse.h"
#include "../../wire/generated/frame_reassemble.h"

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

enum { C_PARTIAL, C_COMPLETE, C_FULL, C_PER, C_TOO_LARGE, C_EXPIRED, C_MISMATCH, C_CONFLICT, C_MALFORMED,
       C_OTHER, C_N };
static const char *const NAMES[C_N] = { "partial", "complete", "full", "per",       "too_large",
	                                "expired", "mismatch", "conflict", "malformed", "other" };

static uint64_t rng = 0x1404u;

static uint32_t next(void)
{
	rng ^= rng << 13;
	rng ^= rng >> 7;
	rng ^= rng << 17;
	return (uint32_t)rng;
}

static int ours_class(fzn_reasm_err_t e, const fzn_partial_t *done)
{
	switch (e) {
	case FZN_REASM_OK:
		return done ? C_COMPLETE : C_PARTIAL;
	case FZN_REASM_ERR_FULL:
		return C_FULL;
	case FZN_REASM_ERR_QUOTA:
		return C_PER;
	case FZN_REASM_ERR_TOO_LARGE:
		return C_TOO_LARGE;
	case FZN_REASM_ERR_EXPIRED:
		return C_EXPIRED;
	case FZN_REASM_ERR_MISMATCH:
		return C_MISMATCH;
	case FZN_REASM_ERR_CONFLICT:
		return C_CONFLICT;
	case FZN_REASM_ERR_MALFORMED:
		return C_MALFORMED;
	default:
		return C_OTHER;
	}
}

static int theirs_class(situ_err_t e, uint32_t why)
{
	if (e == SITU_OK)
		return C_COMPLETE;
	if (e == SITU_ERR_TRUNCATED)
		return C_PARTIAL;
	switch (why) {
	case SITU_PIECES_WHY_FULL:
		return C_FULL;
	case SITU_PIECES_WHY_PER:
		return C_PER;
	case SITU_PIECES_WHY_TOO_LARGE:
		return C_TOO_LARGE;
	case SITU_PIECES_WHY_EXPIRED:
		return C_EXPIRED;
	case SITU_PIECES_WHY_INDEX:
	case SITU_PIECES_WHY_COUNT:
	case SITU_PIECES_WHY_EMPTY:
	case SITU_PIECES_WHY_STRIDE:
	case SITU_PIECES_WHY_LAST_LONGER:
		return C_MISMATCH;
	case SITU_PIECES_WHY_CONFLICT:
		return C_CONFLICT;
	default:
		return C_OTHER;
	}
}

static fzn_partial_t partials[SLOTS];
static uint8_t bufs[SLOTS][CAPACITY];
static situ_pieces_slot_t slots[SLOTS];
static uint8_t bytes[SITU_PIECES_BYTES_FOR(SLOTS, CAPACITY)];
static uint8_t marks[SITU_PIECES_MARKS_FOR(SLOTS, CAPACITY)];
static unsigned seen[C_N][C_N];
static unsigned first_step[C_N][C_N];
static unsigned known[C_N][C_N];

int main(int argc, char **argv)
{
	fzn_reasm_t ours;
	situ_pieces_t theirs;
	uint8_t senders[SENDERS][FZN_SENDER_LEN], piece[STRIDE + 8u];
	uint64_t now = 1000u;
	unsigned step, i, j, disagree = 0, same_bytes = 0, completes = 0, accepted = 0;
	/* AS MANY STEPS AS `make fuzz CASES=N` asks, or STEPS. */
	const unsigned steps = argc > 1 ? (unsigned)strtoul(argv[1], NULL, 10) : STEPS;

	for (i = 0; i < SENDERS; i++)
		memset(senders[i], 0x10 + (int)i, FZN_SENDER_LEN);
	for (i = 0; i < SLOTS; i++)
		if (fzn_reasm_slot_init(&partials[i], bufs[i], CAPACITY) != FZN_REASM_OK)
			return 2;
	if (fzn_reasm_init(&ours, partials, SLOTS, PER, HOLD) != FZN_REASM_OK
	    || situ_pieces_init_in(&theirs, SLOTS, CAPACITY, HOLD, slots, bytes, marks, PER) != SITU_OK)
		return 2;
	for (step = 0; step < steps; step++) {
		const unsigned s = next() % SENDERS, roll = next() % 100u;
		const uint32_t msg = next() % 6u;
		uint16_t chunks = (uint16_t)(1u + next() % 5u), index;
		uint64_t expires = 0;
		size_t len;
		uint8_t key[36];
		fzn_partial_t *done = NULL;
		fzn_reasm_err_t eo;
		situ_err_t et;
		const uint8_t *message = NULL;
		uint32_t length = 0, deadline;
		int co, ct, pre;

		now += next() % 3u;
		if (roll < 2u) {
			(void)fzn_reasm_expire(&ours, now);
			(void)situ_pieces_expire(&theirs, (uint32_t)now);
			continue;
		}
		if (roll < 4u) {
			situ_conv_same_piece_of_key(msg, senders[s], key);
			{
				size_t fo = fzn_reasm_forget(&ours, senders[s], msg);
				uint32_t ft = situ_pieces_forget(&theirs, key);
#ifdef TRACE
				if (step < TRACE)
					printf("%u: forget s%u m%u -> %zu / %u\n", step, s, (unsigned)msg, fo, ft);
#endif
				if (fo != ft)
					disagree++;
			}
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
		eo = fzn_reasm_accept(&ours, senders[s], msg, index, chunks, piece, len, expires, now, &done);
		situ_conv_same_piece_of_key(msg, senders[s], key);
		deadline = (uint32_t)(expires ? expires : now + HOLD);
		/* FUZZNET'S ACCEPT SWEEPS what has expired before it looks; the
		 * generated table drops it only when asked, so it is asked first,
		 * as the wrapper over it does. */
		(void)situ_pieces_expire(&theirs, (uint32_t)now);
		theirs.why = SITU_PIECES_WHY_NONE;
		/* NO COUNT OR NO BYTES: refused by the wrapper before the table,
		 * as fuzznet refuses each -- an empty message included, which the
		 * table would complete. Past 256 pieces the table's own
		 * `count_max` refuses. A reason may differ from fuzznet's, which
		 * depends on whether a slot is held; that both refuse is what is
		 * compared. */
		pre = chunks == 0u || len == 0u;
		if (pre) {
			et = SITU_ERR_BOUNDS;
			theirs.why = SITU_PIECES_WHY_TOO_LARGE;
		} else {
			et = situ_pieces_add_parts(&theirs, key, index, chunks, piece, (uint32_t)len, deadline,
			                           (uint32_t)now, &message, &length);
		}
		co = ours_class(eo, done);
		ct = theirs_class(et, theirs.why);
		if (co == C_COMPLETE && ct == C_COMPLETE) {
			completes++;
			if (done->bytes == length && !memcmp(done->buf, message, length))
				same_bytes++;
		}
#ifdef TRACE
		if (step < TRACE)
			printf("%u: s%u m%u chunks %u index %u len %zu exp %llu now %llu -> %s / %s why %u\n", step, s,
			       (unsigned)msg, chunks, index, len, (unsigned long long)expires, (unsigned long long)now,
			       NAMES[co], NAMES[ct], theirs.why);
#endif
		/* KNOWN AND ACCEPTED, each a refusal where fuzznet refuses or a
		 * refusal fuzznet owed (sec 1404): a held piece resent at another
		 * length the table calls a conflict where fuzznet checks the
		 * stride first; and one resent shorter, a prefix of what is held,
		 * which fuzznet's repeat check took as identical. */
		if ((ct == C_CONFLICT && (co == C_MISMATCH || co == C_PARTIAL))
		    || ((pre || chunks > FZN_REASM_MAX_CHUNKS) && co >= C_FULL && ct >= C_FULL && co != ct)) {
			accepted++;
			known[co][ct]++;
		} else if (co != ct) {
			if (!seen[co][ct])
				first_step[co][ct] = step;
			disagree++;
		}
		seen[co][ct]++;
		if (done)
			fzn_reasm_release(done);
	}
	printf("reasm_agree_fuzz: %u steps, %u completed by both, %u of them byte for byte, %u disagreement(s), "
	       "%u known\n",
	       steps, completes, same_bytes, disagree, accepted);
	for (i = 0; i < C_N; i++) {
		for (j = 0; j < C_N; j++) {
			if (!seen[i][j])
				continue;
			if (i == j) {
				printf("  both %-9s %6u\n", NAMES[i], seen[i][j]);
				continue;
			}
			if (known[i][j] == seen[i][j])
				printf("  known    fuzznet %s, situ %s: %u\n", NAMES[i], NAMES[j], seen[i][j]);
			else
				printf("  DISAGREE fuzznet %s, situ %s: %u, first at step %u\n", NAMES[i], NAMES[j],
				       seen[i][j] - known[i][j], first_step[i][j]);
		}
	}
	return disagree || same_bytes != completes ? 1 : 0;
}
