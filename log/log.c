/* See log.h. */

#include "log.h"

#include "../constant_time/constant_time.h"

#include <string.h>

static int usable(const fzn_log_t *log)
{
	return log && log->entries && log->used <= log->capacity;
}

/* Every live entry for this issuer is scanned rather than stopping at a
 * match, so a duplicate cannot make the answer depend on insertion order --
 * the argument `local/vocabulary.c` makes about rule tables. */
static fzn_log_entry_t *find(const fzn_log_t *log, const uint8_t issuer[FZN_PUBKEY_LEN],
                              uint64_t seq)
{
	fzn_log_entry_t *hit = NULL;

	for (size_t i = 0; i < log->used; i++) {
		if (log->entries[i].live && log->entries[i].seq == seq &&
		    fzn_ct_memeq(log->entries[i].issuer, issuer, FZN_PUBKEY_LEN))
			hit = &log->entries[i];
	}

	return hit;
}

fzn_log_err_t fzn_log_init(fzn_log_t *log, fzn_log_entry_t *entries, size_t capacity)
{
	if (!log || !entries || capacity == 0)
		return FZN_LOG_ERR_MALFORMED;

	memset(entries, 0, capacity * sizeof(*entries));
	log->entries = entries;
	log->capacity = capacity;
	log->used = 0;
	log->next_stamp = 1;
	log->dropped = 0;

	return FZN_LOG_OK;
}

/* The slot to write into: a dead one if there is any, otherwise the array's
 * tail, otherwise the oldest by append order -- which is the eviction. */
static fzn_log_entry_t *slot_for_append(fzn_log_t *log)
{
	fzn_log_entry_t *oldest = NULL;

	for (size_t i = 0; i < log->used; i++) {
		if (!log->entries[i].live)
			return &log->entries[i];
	}

	if (log->used < log->capacity)
		return &log->entries[log->used++];

	for (size_t i = 0; i < log->used; i++) {
		if (!oldest || log->entries[i].stamp < oldest->stamp)
			oldest = &log->entries[i];
	}

	if (oldest)
		log->dropped++;

	return oldest;
}

fzn_log_err_t fzn_log_append(fzn_log_t *log, const fzn_record_t *record)
{
	fzn_log_entry_t *e;

	if (!usable(log) || !record)
		return FZN_LOG_ERR_MALFORMED;
	if (!record->body && record->body_len != 0)
		return FZN_LOG_ERR_MALFORMED;
	/* Sequence zero is reserved (`record.h`), so a record carrying it has
	 * not been through `fzn_record_verify`. */
	if (record->seq == 0)
		return FZN_LOG_ERR_MALFORMED;

	if (find(log, record->issuer, record->seq))
		return FZN_LOG_ERR_DUPLICATE;

	e = slot_for_append(log);
	if (!e)
		return FZN_LOG_ERR_MALFORMED;

	memcpy(e->issuer, record->issuer, FZN_PUBKEY_LEN);
	e->seq = record->seq;
	e->kind = record->kind;
	e->body = record->body;
	e->body_len = record->body_len;
	e->stamp = log->next_stamp++;
	e->live = 1;

	return FZN_LOG_OK;
}

void fzn_log_range(const fzn_log_t *log, const uint8_t issuer[FZN_PUBKEY_LEN], uint64_t *first,
                   uint64_t *last)
{
	uint64_t lo = 0, hi = 0;

	if (first)
		*first = 0;
	if (last)
		*last = 0;
	if (!usable(log) || !issuer)
		return;

	for (size_t i = 0; i < log->used; i++) {
		if (!log->entries[i].live ||
		    !fzn_ct_memeq(log->entries[i].issuer, issuer, FZN_PUBKEY_LEN))
			continue;
		if (lo == 0 || log->entries[i].seq < lo)
			lo = log->entries[i].seq;
		if (log->entries[i].seq > hi)
			hi = log->entries[i].seq;
	}

	if (first)
		*first = lo;
	if (last)
		*last = hi;
}

fzn_log_err_t fzn_log_get(const fzn_log_t *log, const uint8_t issuer[FZN_PUBKEY_LEN],
                           uint64_t seq, const fzn_log_entry_t **out)
{
	const fzn_log_entry_t *e;
	uint64_t first, last;

	if (!usable(log) || !issuer || !out || seq == 0)
		return FZN_LOG_ERR_MALFORMED;

	*out = NULL;
	e = find(log, issuer, seq);
	if (e) {
		*out = e;
		return FZN_LOG_OK;
	}

	/* NOT HELD IS TWO DIFFERENT ANSWERS, and telling them apart is the
	 * reason a peer asks. Below where this log now starts, retention took
	 * it and asking again will never help; above the newest, it has simply
	 * not arrived. */
	fzn_log_range(log, issuer, &first, &last);
	if (first != 0 && seq < first)
		return FZN_LOG_ERR_GONE;

	return FZN_LOG_ERR_ABSENT;
}

size_t fzn_log_read_since(const fzn_log_t *log, const uint8_t issuer[FZN_PUBKEY_LEN],
                          uint64_t since, const fzn_log_entry_t **out, size_t out_cap)
{
	size_t n = 0;

	if (!usable(log) || !issuer || !out || out_cap == 0)
		return 0;

	/* Oldest first, by selection rather than by sorting: the array is
	 * small, bounded and unsorted, and a sort would need somewhere to put
	 * the result. Each pass takes the lowest sequence still above what has
	 * been taken. */
	for (uint64_t taken = since; n < out_cap; ) {
		const fzn_log_entry_t *best = NULL;

		for (size_t i = 0; i < log->used; i++) {
			const fzn_log_entry_t *e = &log->entries[i];

			if (!e->live || e->seq <= taken ||
			    !fzn_ct_memeq(e->issuer, issuer, FZN_PUBKEY_LEN))
				continue;
			if (!best || e->seq < best->seq)
				best = e;
		}

		if (!best)
			break;
		out[n++] = best;
		taken = best->seq;
	}

	return n;
}

uint64_t fzn_log_dropped(const fzn_log_t *log)
{
	return usable(log) ? log->dropped : 0u;
}

const char *fzn_log_err_str(fzn_log_err_t err)
{
	switch (err) {
	case FZN_LOG_OK:
		return "ok";
	case FZN_LOG_ERR_MALFORMED:
		return "malformed argument";
	case FZN_LOG_ERR_DUPLICATE:
		return "already held";
	case FZN_LOG_ERR_GONE:
		return "retention removed it";
	case FZN_LOG_ERR_ABSENT:
		return "not held yet";
	}

	return "unknown";
}
