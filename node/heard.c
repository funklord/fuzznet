/* See heard.h. */

#include "heard.h"

#include "../wire/generated/heard_row.h"
#include "../wire/generated/heard_row_build.h"

/* `node/heard_row.situ`'s fzn_heard, read and written by the code situ
 * generates from it (sec 1313): the version, then the time. */
#define HEARD_LEN FZN_HEARD_ROW_FZN_HEARD_SIZE_FIXED

const char *fzn_heard_err_str(fzn_heard_err_t err)
{
	switch (err) {
	case FZN_HEARD_OK:
		return "ok";
	case FZN_HEARD_MALFORMED:
		return "malformed";
	case FZN_HEARD_ABSENT:
		return "never heard from";
	case FZN_HEARD_BACKEND:
		return "the store would not write";
	}
	return "unknown";
}

fzn_heard_err_t fzn_heard_when(const fzn_persist_ops_t *store, const uint8_t host[32],
                               uint64_t *at_us)
{
	uint8_t row[HEARD_LEN + 1u];
	size_t len = 0;

	if (!at_us)
		return FZN_HEARD_MALFORMED;
	*at_us = 0;
	if (!store || !store->load || !host)
		return FZN_HEARD_MALFORMED;
	situ_msg_t m;
	situ_view_t v;

	if (!store->load(store->ctx, FZN_PERSIST_HOST_HEARD, host, row, sizeof(row), &len) || len != HEARD_LEN)
		return FZN_HEARD_ABSENT;
	situ_msg_init(&m, row, (uint32_t)len);
	if (fzn_heard_row_fzn_heard_view(&m, 0u, &v) != SITU_OK || fzn_heard_row_fzn_heard_validate(v) != SITU_OK)
		return FZN_HEARD_ABSENT;
	*at_us = fzn_heard_row_fzn_heard_at_us_get(v);
	return FZN_HEARD_OK;
}

fzn_heard_err_t fzn_heard_mark(const fzn_persist_ops_t *store, const uint8_t host[32],
                               uint64_t at_us)
{
	uint8_t row[HEARD_LEN];
	uint64_t was = 0;

	if (!store || !store->load || !store->save || !host)
		return FZN_HEARD_MALFORMED;
	if (fzn_heard_when(store, host, &was) == FZN_HEARD_OK && was >= at_us)
		return FZN_HEARD_OK;
	{
		uint32_t wrote = 0;

		if (fzn_heard_row_fzn_heard_build(row, sizeof(row), 1u, at_us, &wrote) != SITU_OK || wrote != HEARD_LEN)
			return FZN_HEARD_MALFORMED;
	}
	return store->save(store->ctx, FZN_PERSIST_HOST_HEARD, host, row, sizeof(row))
	               ? FZN_HEARD_OK
	               : FZN_HEARD_BACKEND;
}
