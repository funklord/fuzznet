/* The one search in binary on the local leg: search_binary.h, sec 1293. */
#include "search_binary.h"

#include <string.h>

#include "../wire/cmd.h"
#include "../wire/generated/search_local.h"
#include "../wire/generated/search_local_build.h"
#include "../wire/status.h"

static int status(fzn_node_search_put_t put, void *ctx, fzn_status_t code, const char *why)
{
	uint8_t out[FZN_STATUS_LEN_MAX];
	size_t n = fzn_status_write(out, sizeof(out), code, why);

	return n && put(ctx, out, n);
}

/* A PAGE: its head, then a message a hit, then ok. */
static int page(fzn_node_search_put_t put, void *ctx, const fzn_search_hit_t *hits, size_t count, int more,
                size_t asked, size_t answered, size_t late)
{
	uint8_t body[16], out[FZN_NODE_SEARCH_BINARY_MAX];
	uint32_t body_len = 0, n = 0;
	size_t i;

	if (fzn_search_local_page_build(body, sizeof(body), (uint8_t)count, (uint8_t)(more ? 1 : 0),
	                                (uint8_t)(asked > 255u ? 255u : asked), (uint8_t)(answered > 255u ? 255u : answered),
	                                (uint8_t)(late > 255u ? 255u : late), &body_len)
	            != SITU_OK
	    || fzn_search_local_message_build_page(out, sizeof(out), (uint8_t)FZN_CMD_SEARCH, body, body_len, &n)
	               != SITU_OK
	    || !put(ctx, out, n))
		return 0;
	for (i = 0; i < count; i++) {
		const fzn_search_hit_t *h = &hits[i];
		uint8_t hit[FZN_NODE_SEARCH_BINARY_MAX], store[1u + FZN_SEARCH_STORE_NAME_MAX];
		size_t store_len = strlen(h->store);
		uint32_t hit_len = 0;

		store[0] = (uint8_t)store_len;
		memcpy(store + 1, h->store, store_len);
		if (fzn_search_local_hit_build(hit, sizeof(hit), store, (uint32_t)(1u + store_len), h->key,
		                               (uint32_t)h->key_len, (uint32_t)h->score, h->time_ms,
		                               (const uint8_t *)h->snippet, (uint32_t)h->snippet_len, &hit_len)
		            != SITU_OK
		    || fzn_search_local_message_build_hit(out, sizeof(out), (uint8_t)FZN_CMD_SEARCH, hit, hit_len, &n)
		               != SITU_OK
		    || !put(ctx, out, n))
			return 0;
	}
	return status(put, ctx, FZN_STATUS_OK, NULL);
}

int fzn_node_search_binary(fzn_node_search_t *s, const uint8_t *msg, size_t len, fzn_node_search_put_t put,
                           void *put_ctx)
{
	static uint8_t copy[FZN_LOCAL_BINARY_MAX + 2u], ask[FZN_LOCAL_BINARY_MAX + 2u];
	static fzn_search_hit_t hits[FZN_SEARCH_K_MAX];
	situ_msg_t m;
	situ_view_t v, b;
	size_t count = 0, asked = 0, answered = 0, late = 0;
	uint32_t ask_len;
	int more = 0;
	uint8_t op;
	const uint8_t *with = NULL;

	if (!put)
		return 0;
	if (!s || !msg || len < 2u || len > sizeof(copy))
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a search request");
	memcpy(copy, msg, len);
	situ_msg_init(&m, copy, (uint32_t)len);
	if (fzn_search_local_message_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_search_local_message_validate(v) != SITU_OK)
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a search request");
	op = fzn_search_local_message_op_get(v);
	if (op == FZN_SEARCH_LOCAL_OP_GET) {
		if (!fzn_node_search_held(s, hits, &count, &more, &asked, &answered, &late))
			return status(put, put_ctx, FZN_STATUS_ERROR, "no search asked");
		return page(put, put_ctx, hits, count, more, asked, answered, late);
	}
	if (op != FZN_SEARCH_LOCAL_OP_LIST && op != FZN_SEARCH_LOCAL_OP_FETCH)
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a search request");
	if ((op == FZN_SEARCH_LOCAL_OP_LIST ? fzn_search_local_message_body_list_view(v, &b)
	                                    : fzn_search_local_message_body_fetch_view(v, &b))
	    != SITU_OK)
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a search request");
	if (fzn_search_local_local_ask_has_with_get(b))
		with = fzn_search_local_local_ask_with_ptr(b);
	/* THE ASK, as one host asks another: held whole past WITH and already
	 * checked as `search/search_ask.situ` lays it out (situ's `holds`, sec
	 * 1316), so it is handed on as its bytes. */
	ask_len = fzn_search_local_local_ask_ask_len(b);
	if (!ask_len || 2u + (size_t)ask_len > sizeof(ask))
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a search request");
	ask[0] = FZN_CMD_SEARCH;
	ask[1] = 1u; /* search_wire.situ's ask */
	memcpy(ask + 2, fzn_search_local_local_ask_ask_ptr(b), ask_len);
	if (with && !fzn_node_search_is_contact(s, with))
		return status(put, put_ctx, FZN_STATUS_ERROR, "no such contact here");
	if (op == FZN_SEARCH_LOCAL_OP_FETCH) {
		uint8_t body[4], out[16];
		uint32_t body_len = 0, n = 0;

		if (!fzn_node_search_fetch(s, ask, 2u + (size_t)ask_len, with, &asked))
			return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a search the stores could run");
		return fzn_search_local_fetched_build(body, sizeof(body), (uint8_t)(asked > 255u ? 255u : asked), &body_len)
		               == SITU_OK
		       && fzn_search_local_message_build_fetched(out, sizeof(out), (uint8_t)FZN_CMD_SEARCH, body, body_len,
		                                                 &n)
		                  == SITU_OK
		       && put(put_ctx, out, n) && status(put, put_ctx, FZN_STATUS_OK, NULL);
	}
	if (!fzn_node_search_list(s, ask, 2u + (size_t)ask_len, with, hits, &count, &more))
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a search the stores could run");
	return page(put, put_ctx, hits, count, more, 0u, 0u, 0u);
}
