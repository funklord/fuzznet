#include "transfer_print.h"

#include <string.h>

#define DIGITS_MAX 21u

struct sink {
	char *out;
	size_t used;
};

static void put(struct sink *s, const char *bytes, size_t len)
{
	if (s->out)
		memcpy(s->out + s->used, bytes, len);
	s->used += len;
}

static void put_str(struct sink *s, const char *text)
{
	put(s, text, strlen(text));
}

static void put_u64(struct sink *s, uint64_t value)
{
	char digits[DIGITS_MAX];
	size_t at = sizeof(digits);

	do {
		digits[--at] = (char)('0' + (value % 10u));
		value /= 10u;
	} while (value);

	put(s, digits + at, sizeof(digits) - at);
}

static void render(struct sink *s, fzn_transfer_state_t state, uint64_t held, uint64_t total,
                   size_t in_flight, size_t overdue, int scheduled)
{
	if (state == FZN_TRANSFER_NOTHING) {
		put_str(s, "no transfer\n");
		return;
	}

	put_u64(s, held);
	put_str(s, " of ");
	put_u64(s, total);
	put_str(s, " leaves; ");

	switch (state) {
	case FZN_TRANSFER_COMPLETE:
		put_str(s, "complete");
		break;
	case FZN_TRANSFER_WORKING:
		put_str(s, "working, ");
		put_u64(s, (uint64_t)in_flight);
		put_str(s, " outstanding");
		if (overdue > 0u) {
			/* RECLAIMABLE, NOT FAILED. */
			put_str(s, ", ");
			put_u64(s, (uint64_t)overdue);
			put_str(s, " past deadline and reclaimable");
		}
		break;
	case FZN_TRANSFER_IDLE:
		/* NOT STARTED. Nothing held and nothing asked for -- a
		 * different thing to tell somebody than "it stopped". */
		put_str(s, "not started");
		break;
	case FZN_TRANSFER_STALLED:
		put_str(s, "STALLED, nothing outstanding");
		break;
	case FZN_TRANSFER_NOTHING:
		/* Answered above, before the leaf counts, and it returns there.
		 * Named here so that -Wswitch refuses a state added later rather
		 * than drawing it as one of these. */
		break;
	}

	if (!scheduled)
		put_str(s, "; no scheduler");

	put_str(s, "\n");
}

fzn_transfer_err_t fzn_transfer_print(const fzn_spool_t *spool,
                                      const fzn_transfer_t *transfer, uint64_t now,
                                      char *out, size_t cap, size_t *len_out,
                                      fzn_transfer_state_t *state_out)
{
	struct sink measure;
	struct sink write;
	fzn_transfer_state_t said = FZN_TRANSFER_NOTHING;
	uint64_t held = 0;
	uint64_t total = 0;
	size_t in_flight = 0;
	size_t overdue = 0;
	int scheduled = 0;

	if (len_out)
		*len_out = 0;
	if (state_out)
		*state_out = FZN_TRANSFER_NOTHING;

	if (!out || !len_out || !state_out)
		return FZN_TRANSFER_ERR_MALFORMED;

	if (spool) {
		held = spool->have;
		total = spool->leaves;

		if (transfer) {
			size_t i;

			scheduled = 1;
			/* READ, NEVER RECLAIMED. `fzn_transfer_expire` mutates;
			 * asking for status must not change what a peer owes. */
			in_flight = fzn_transfer_in_flight(transfer);
			for (i = 0; i < transfer->cap; i++)
				if (transfer->assigns[i].live &&
				    transfer->assigns[i].deadline <= now)
					overdue++;
		}

		/* THE LIBRARY'S ANSWER, not `have == leaves`. */
		if (fzn_spool_complete(spool))
			said = FZN_TRANSFER_COMPLETE;
		else if (in_flight > 0u)
			said = FZN_TRANSFER_WORKING;
		else if (held == 0u)
			said = FZN_TRANSFER_IDLE;
		else
			said = FZN_TRANSFER_STALLED;
	}

	measure.out = NULL;
	measure.used = 0;
	render(&measure, said, held, total, in_flight, overdue, scheduled);

	if (measure.used + 1u > cap) {
		*len_out = measure.used + 1u;
		return FZN_TRANSFER_ERR_MALFORMED;
	}

	write.out = out;
	write.used = 0;
	render(&write, said, held, total, in_flight, overdue, scheduled);
	out[write.used] = '\0';
	*len_out = write.used;
	*state_out = said;

	return FZN_TRANSFER_OK;
}
