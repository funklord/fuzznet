/* One search asked of another host, and its answer, sec 1287 step 2. */
#include "remote.h"

#include <string.h>

#include "../facet/codec.h"
#include "../wire/cmd.h"
#include "../wire/generated/search_wire.h"
#include "../wire/generated/search_wire_build.h"

/* A STORE'S NAME as the wire carries it: 1 to 16 bytes, none below a space. */
static int name_ok(const uint8_t *name, size_t len)
{
	size_t i;

	if (!len || len > FZN_SEARCH_STORE_NAME_MAX)
		return 0;
	for (i = 0; i < len; i++)
		if (name[i] < 0x20u || name[i] == 0x7fu)
			return 0;
	return 1;
}

/* A HIT KEPT BY THE FILTER: its facets as the nodes it is at. */
static int filter_keep(void *ctx, const fzn_search_hit_t *hit)
{
	const fzn_search_ask_t *a = ctx;
	fzn_facet_node_t at[FZN_SEARCH_FACETS_MAX];
	size_t i, n = hit->n_facets < FZN_SEARCH_FACETS_MAX ? hit->n_facets : FZN_SEARCH_FACETS_MAX;
	int selected = 0;

	for (i = 0; i < n; i++) {
		at[i].dim = (const uint8_t *)hit->facets[i].dim;
		at[i].dim_len = hit->facets[i].dim_len;
		at[i].id = (const uint8_t *)hit->facets[i].value;
		at[i].id_len = hit->facets[i].value_len;
	}
	return fzn_facet_entity_matches(&a->expr, at, n, &selected) == FZN_FACET_OK && selected;
}

int fzn_search_ask_filter(fzn_search_ask_t *a, const uint8_t *filter, size_t len)
{
	int selected = 0;

	if (!a || (len && !filter) || len > sizeof(a->filter))
		return 0;
	a->query.filter = NULL;
	a->query.filter_len = 0;
	a->query.keep = NULL;
	a->query.keep_ctx = NULL;
	a->filter_len = 0;
	if (!len)
		return 1;
	memcpy(a->filter, filter, len);
	/* WHOLE, AND ANSWERABLE OF ONE HIT: a RANGE is refused here, once,
	 * rather than at every hit. */
	if (fzn_facet_expr_decode(a->filter, len, a->pos, FZN_SEARCH_FILTER_TERMS, a->neg, FZN_SEARCH_FILTER_TERMS,
	                          a->members, FZN_SEARCH_FILTER_MEMBERS, &a->expr, NULL)
	            != FZN_FACET_OK
	    || fzn_facet_entity_matches(&a->expr, NULL, 0, &selected) != FZN_FACET_OK)
		return 0;
	a->filter_len = len;
	a->query.filter = a->filter;
	a->query.filter_len = len;
	a->query.keep = filter_keep;
	a->query.keep_ctx = a;
	return 1;
}

size_t fzn_search_ask_write(const char *words, size_t words_len, const fzn_search_query_t *q, uint8_t *out,
                            size_t cap)
{
	uint8_t stores[FZN_SEARCH_ASK_STORES_MAX * (1u + FZN_SEARCH_STORE_NAME_MAX)];
	uint8_t body[1u + FZN_SEARCH_TEXT_MAX + sizeof(stores) + 8u + 8u + 1u + 1u + 4u + 8u + 1u
	             + FZN_SEARCH_STORE_NAME_MAX + 1u + FZN_SEARCH_KEY_MAX + 2u + FZN_SEARCH_FILTER_MAX];
	const fzn_search_hit_t *after = q ? q->after : NULL;
	uint32_t at = 0, wrote = 0;
	size_t i, after_store_len = after ? strlen(after->store) : 0u;

	if (!words || !words_len || words_len > FZN_SEARCH_TEXT_MAX || !q || q->n_stores > FZN_SEARCH_ASK_STORES_MAX
	    || !q->k || q->k > FZN_SEARCH_K_MAX || !out
	    || q->filter_len > FZN_SEARCH_FILTER_MAX || (q->filter_len && !q->filter)
	    || (after && (!name_ok((const uint8_t *)after->store, after_store_len) || !after->key_len
	                  || after->key_len > FZN_SEARCH_KEY_MAX)))
		return 0;
	for (i = 0; i < q->n_stores; i++) {
		const size_t n = q->stores[i] ? strlen(q->stores[i]) : 0u;

		if (!name_ok((const uint8_t *)q->stores[i], n)
		    || fzn_search_wire_store_build(stores + at, (uint32_t)(sizeof(stores) - at),
		                                   (const uint8_t *)q->stores[i], (uint32_t)n, &wrote)
		               != SITU_OK)
			return 0;
		at += wrote;
	}
	if (fzn_search_wire_ask_build(body, sizeof(body), (const uint8_t *)words, (uint32_t)words_len, stores, at,
	                              q->from_ms, q->to_ms, (uint8_t)q->k, after ? 1u : 0u,
	                              after ? (uint32_t)after->score : 0u, after ? after->time_ms : 0u,
	                              after ? (const uint8_t *)after->store : NULL, (uint32_t)after_store_len,
	                              after ? after->key : NULL, after ? (uint32_t)after->key_len : 0u,
	                              q->filter_len ? q->filter : NULL, (uint32_t)q->filter_len, &wrote)
	            != SITU_OK
	    || fzn_search_wire_message_build_ask(out, cap > UINT32_MAX ? UINT32_MAX : (uint32_t)cap, FZN_CMD_SEARCH,
	                                         body, wrote, &at)
	               != SITU_OK)
		return 0;
	return at;
}

int fzn_search_ask_read(const uint8_t *in, size_t len, fzn_search_ask_t *out)
{
	static uint8_t copy[2u * (1u + FZN_SEARCH_TEXT_MAX) + 256u + 2u + FZN_SEARCH_FILTER_MAX];
	situ_msg_t m;
	situ_view_t v, b, s;
	uint32_t i, n;
	size_t k;

	if (!in || !out || len < 2u || len > sizeof(copy) || in[0] != FZN_CMD_SEARCH)
		return 0;
	memset(out, 0, sizeof(*out));
	memcpy(copy, in, len);
	situ_msg_init(&m, copy, (uint32_t)len);
	if (fzn_search_wire_message_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_search_wire_message_validate(v) != SITU_OK || fzn_search_wire_message_op_get(v) != FZN_SEARCH_WIRE_OP_ASK
	    || fzn_search_wire_message_body_ask_view(v, &b) != SITU_OK)
		return 0;
	out->words_len = fzn_search_wire_ask_words_len_get(b);
	memcpy(out->words, fzn_search_wire_ask_words_ptr(b), out->words_len);
	n = fzn_search_wire_ask_store_count_get(b);
	if (n > FZN_SEARCH_ASK_STORES_MAX)
		return 0;
	for (i = 0; i < n; i++) {
		if (fzn_search_wire_ask_stores_at(b, i, &s) != SITU_OK)
			return 0;
		k = fzn_search_wire_store_len_get(s);
		if (!name_ok(fzn_search_wire_store_name_ptr(s), k))
			return 0;
		memcpy(out->names[i], fzn_search_wire_store_name_ptr(s), k);
		out->stores[i] = out->names[i];
	}
	if (!fzn_search_query_init(&out->query, out->words, out->words_len, fzn_search_wire_ask_k_get(b)))
		return 0;
	out->query.from_ms = fzn_search_wire_ask_since_ms_get(b);
	out->query.to_ms = fzn_search_wire_ask_until_ms_get(b);
	out->query.stores = n ? out->stores : NULL;
	out->query.n_stores = n;
	k = fzn_search_wire_ask_after_store_len_get(b);
	out->after.key_len = fzn_search_wire_ask_after_key_len_get(b);
	if (fzn_search_wire_ask_has_after_get(b)) {
		if (!name_ok(fzn_search_wire_ask_after_store_ptr(b), k) || !out->after.key_len)
			return 0;
		memcpy(out->after.store, fzn_search_wire_ask_after_store_ptr(b), k);
		memcpy(out->after.key, fzn_search_wire_ask_after_key_ptr(b), out->after.key_len);
		out->after.score = fzn_search_wire_ask_after_score_get(b);
		out->after.time_ms = fzn_search_wire_ask_after_time_ms_get(b);
		out->query.after = &out->after;
	} else if (k || out->after.key_len) {
		return 0;
	}
	return fzn_search_ask_filter(out, fzn_search_wire_ask_filter_ptr(b), fzn_search_wire_ask_filter_len_get(b));
}

size_t fzn_search_answer_write(const fzn_search_hit_t *hits, size_t n, int more, uint8_t *out, size_t cap)
{
	static uint8_t run[FZN_SEARCH_ANSWER_MAX], body[FZN_SEARCH_ANSWER_MAX];
	uint32_t at = 0, wrote = 0;
	size_t i;

	if (n > FZN_SEARCH_K_MAX || (n && !hits) || !out)
		return 0;
	for (i = 0; i < n; i++) {
		uint8_t store[1u + FZN_SEARCH_STORE_NAME_MAX];
		uint32_t store_len = 0;
		const size_t name_len = strlen(hits[i].store);

		if (!name_ok((const uint8_t *)hits[i].store, name_len) || !hits[i].key_len
		    || hits[i].key_len > FZN_SEARCH_KEY_MAX || hits[i].snippet_len > FZN_SEARCH_SNIPPET_MAX
		    || fzn_search_wire_store_build(store, sizeof(store), (const uint8_t *)hits[i].store,
		                                   (uint32_t)name_len, &store_len)
		               != SITU_OK
		    || fzn_search_wire_hit_build(run + at, (uint32_t)(sizeof(run) - at), store, store_len,
		                                 hits[i].key, (uint32_t)hits[i].key_len, (uint32_t)hits[i].score,
		                                 hits[i].time_ms, (const uint8_t *)hits[i].snippet,
		                                 (uint32_t)hits[i].snippet_len, &wrote)
		               != SITU_OK)
			return 0;
		at += wrote;
	}
	if (fzn_search_wire_answer_build(body, sizeof(body), (more & 1) ? 1u : 0u, (more & 2) ? 1u : 0u, run, at,
	                                 &wrote)
	            != SITU_OK
	    || fzn_search_wire_message_build_answer(out, cap > UINT32_MAX ? UINT32_MAX : (uint32_t)cap, FZN_CMD_SEARCH,
	                                            body, wrote, &at)
	               != SITU_OK)
		return 0;
	return at;
}

int fzn_search_answer_read(const uint8_t *in, size_t len, fzn_search_hit_t *hits, size_t cap, size_t *n,
                           int *more)
{
	static uint8_t copy[FZN_SEARCH_ANSWER_MAX + 2u];
	situ_msg_t m;
	situ_view_t v, b, h, s;
	uint32_t i, count;
	size_t k;

	if (!in || !hits || !n || !more || len < 2u || len > sizeof(copy) || in[0] != FZN_CMD_SEARCH)
		return 0;
	*n = 0;
	memcpy(copy, in, len);
	situ_msg_init(&m, copy, (uint32_t)len);
	if (fzn_search_wire_message_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_search_wire_message_validate(v) != SITU_OK
	    || fzn_search_wire_message_op_get(v) != FZN_SEARCH_WIRE_OP_ANSWER
	    || fzn_search_wire_message_body_answer_view(v, &b) != SITU_OK)
		return 0;
	count = fzn_search_wire_answer_count_get(b);
	if (count > cap)
		return 0;
	for (i = 0; i < count; i++) {
		fzn_search_hit_t *o = &hits[i];

		memset(o, 0, sizeof(*o));
		if (fzn_search_wire_answer_hits_at(b, i, &h) != SITU_OK || fzn_search_wire_hit_store_view(h, &s) != SITU_OK)
			return 0;
		k = fzn_search_wire_store_len_get(s);
		if (!name_ok(fzn_search_wire_store_name_ptr(s), k))
			return 0;
		memcpy(o->store, fzn_search_wire_store_name_ptr(s), k);
		o->key_len = fzn_search_wire_hit_key_len_get(h);
		memcpy(o->key, fzn_search_wire_hit_key_ptr(h), o->key_len);
		o->score = fzn_search_wire_hit_score_get(h);
		o->time_ms = fzn_search_wire_hit_time_ms_get(h);
		o->snippet_len = fzn_search_wire_hit_snippet_len_get(h);
		memcpy(o->snippet, fzn_search_wire_hit_snippet_ptr(h), o->snippet_len);
	}
	*n = count;
	*more = fzn_search_wire_answer_more_get(b) | (fzn_search_wire_answer_partial_get(b) << 1);
	return 1;
}

size_t fzn_search_answer_ask(const fzn_search_store_t *stores, size_t n_stores, const uint8_t *ask,
                             size_t ask_len, const uint8_t *asker, uint8_t *out, size_t cap)
{
	static fzn_search_ask_t read;
	static fzn_search_hit_t hits[FZN_SEARCH_K_MAX];
	size_t n = 0;
	int more = 0, partial = 0;

	if (!fzn_search_ask_read(ask, ask_len, &read)
	    || !fzn_search_run_partial(stores, n_stores, &read.query, asker, hits, &n, &more, &partial))
		return 0;
	return fzn_search_answer_write(hits, n, (more ? 1 : 0) | (partial ? 2 : 0), out, cap);
}
