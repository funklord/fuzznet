/* See heard.h. */

#include "heard.h"

#include "../wire/bytes.h"

/* `node/heard.situ`'s fzn_heard: the version, then the time. */
#define HEARD_LEN 9u

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
	if (!store->load(store->ctx, FZN_PERSIST_HOST_HEARD, host, row, sizeof(row), &len)
	    || len != HEARD_LEN || row[0] != 1u)
		return FZN_HEARD_ABSENT;
	*at_us = fzn_get_be64(row + 1);
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
	row[0] = 1u;
	fzn_put_be64(row + 1, at_us);
	return store->save(store->ctx, FZN_PERSIST_HOST_HEARD, host, row, sizeof(row))
	               ? FZN_HEARD_OK
	               : FZN_HEARD_BACKEND;
}
