/* See file_holds.h. */

#include "file_holds.h"

#include "../wire/bytes.h"

#include <string.h>

/* A HOLD'S ROW, by the file, the kind and the id. */
static int hold_row(const fzn_file_holds_t *h, const uint8_t root[32], fzn_file_hold_kind_t kind,
                    const uint8_t id[FZN_FILE_HOLD_ID_LEN], uint8_t row[32])
{
	static const char DOMAIN[] = "fuzznet.file.hold";
	uint8_t in[sizeof(DOMAIN) - 1u + 32u + 1u + FZN_FILE_HOLD_ID_LEN];
	size_t at = sizeof(DOMAIN) - 1u;

	memcpy(in, DOMAIN, at);
	memcpy(in + at, root, 32u);
	at += 32u;
	in[at++] = (uint8_t)kind;
	memcpy(in + at, id, FZN_FILE_HOLD_ID_LEN);
	return h->hash->hash(h->hash->ctx, row, 32u, in, sizeof(in));
}

/* A FILE'S COUNT, by its root. */
static int count_row(const fzn_file_holds_t *h, const uint8_t root[32], uint8_t row[32])
{
	static const char DOMAIN[] = "fuzznet.file.holds";
	uint8_t in[sizeof(DOMAIN) - 1u + 32u];

	memcpy(in, DOMAIN, sizeof(DOMAIN) - 1u);
	memcpy(in + sizeof(DOMAIN) - 1u, root, 32u);
	return h->hash->hash(h->hash->ctx, row, 32u, in, sizeof(in));
}

static int ready(const fzn_file_holds_t *h)
{
	return h && h->store && h->store->load && h->store->save && h->store->remove && h->hash
	       && h->hash->hash;
}

int fzn_file_hold_count(const fzn_file_holds_t *h, const uint8_t root[32], uint64_t *count)
{
	uint8_t row[32], b[8];
	size_t len = 0;

	if (count)
		*count = 0;
	if (!ready(h) || !root || !count || !count_row(h, root, row)
	    || !h->store->load(h->store->ctx, FZN_PERSIST_FILE_HOLD, row, b, sizeof(b), &len)
	    || len != sizeof(b))
		return 0;
	*count = fzn_get_be64(b);
	return 1;
}

static int count_save(const fzn_file_holds_t *h, const uint8_t root[32], uint64_t count)
{
	uint8_t row[32], b[8];

	fzn_put_be64(b, count);
	return count_row(h, root, row)
	       && h->store->save(h->store->ctx, FZN_PERSIST_FILE_HOLD, row, b, sizeof(b));
}

int fzn_file_hold_has(const fzn_file_holds_t *h, const uint8_t root[32],
                      fzn_file_hold_kind_t kind, const uint8_t id[FZN_FILE_HOLD_ID_LEN])
{
	uint8_t row[32], b[1];
	size_t len = 0;

	return ready(h) && root && id && hold_row(h, root, kind, id, row)
	       && h->store->load(h->store->ctx, FZN_PERSIST_FILE_HOLD, row, b, sizeof(b), &len)
	       && len == 1u;
}

int fzn_file_hold_claim(const fzn_file_holds_t *h, const uint8_t root[32],
                        fzn_file_hold_kind_t kind, const uint8_t id[FZN_FILE_HOLD_ID_LEN],
                        int *added)
{
	uint8_t row[32], one = 1u;
	uint64_t count = 0;

	if (added)
		*added = 0;
	if (!ready(h) || !root || !id || !added)
		return 0;
	if (fzn_file_hold_has(h, root, kind, id))
		return 1;
	/* COUNTED FIRST: a crash before the hold is written leaves the count
	 * one high, and the file kept. */
	(void)fzn_file_hold_count(h, root, &count);
	if (count == UINT64_MAX || !count_save(h, root, count + 1u) || !hold_row(h, root, kind, id, row)
	    || !h->store->save(h->store->ctx, FZN_PERSIST_FILE_HOLD, row, &one, 1u))
		return 0;
	*added = 1;
	return 1;
}

int fzn_file_hold_release(const fzn_file_holds_t *h, const uint8_t root[32],
                          fzn_file_hold_kind_t kind, const uint8_t id[FZN_FILE_HOLD_ID_LEN],
                          uint64_t *left)
{
	uint8_t row[32];
	uint64_t count = 0;

	if (left)
		*left = 0;
	if (!ready(h) || !root || !id || !left)
		return 0;
	(void)fzn_file_hold_count(h, root, &count);
	*left = count;
	if (!fzn_file_hold_has(h, root, kind, id))
		return 1;
	/* THE HOLD FIRST, then the count: a crash between leaves the count one
	 * high, and the file kept. */
	if (!hold_row(h, root, kind, id, row)
	    || !h->store->remove(h->store->ctx, FZN_PERSIST_FILE_HOLD, row))
		return 0;
	if (count && !count_save(h, root, count - 1u))
		return 0;
	*left = count ? count - 1u : 0u;
	return 1;
}

static int begun_row(const fzn_file_holds_t *h, uint8_t row[32])
{
	static const char DOMAIN[] = "fuzznet.file.holds.begun";

	return h->hash->hash(h->hash->ctx, row, 32u, (const uint8_t *)DOMAIN, sizeof(DOMAIN) - 1u);
}

int fzn_file_holds_begun(const fzn_file_holds_t *h)
{
	uint8_t row[32], b[1];
	size_t len = 0;

	return ready(h) && begun_row(h, row)
	       && h->store->load(h->store->ctx, FZN_PERSIST_FILE_HOLD, row, b, sizeof(b), &len)
	       && len == 1u;
}

int fzn_file_holds_begin(const fzn_file_holds_t *h)
{
	uint8_t row[32], one = 1u;

	return ready(h) && begun_row(h, row)
	       && h->store->save(h->store->ctx, FZN_PERSIST_FILE_HOLD, row, &one, 1u);
}
