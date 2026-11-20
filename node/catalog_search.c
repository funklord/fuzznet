/* The library's files as a store of the one search: catalog_search.h, sec 1299. */
#include "catalog_search.h"

#include <string.h>

static int named(const fzn_node_catalog_entry_t *e, const char *name, size_t len)
{
	return e->name_len == len && memcmp(e->name, name, len) == 0;
}

/* THE FILE'S NAME, a live `name` claim about `entity`: 1 with `*name`,
 * `*len`, borrowed from `c`, or 0. */
static int name_of(const fzn_node_catalog_t *c, const uint8_t *entity, const uint8_t **name, size_t *len)
{
	static fzn_catalog_assertion_t about[256];
	const size_t n = fzn_node_catalog_assertions(c, entity, about, sizeof(about) / sizeof(about[0]));
	size_t k;

	for (k = 0; k < n; k++)
		if (about[k].live && about[k].name_len == 4u && memcmp(about[k].name, "name", 4u) == 0
		    && about[k].value_len) {
			*name = about[k].value;
			*len = about[k].value_len;
			return 1;
		}
	return 0;
}

int fzn_node_catalog_search(void *ctx, const fzn_search_query_t *q, const uint8_t *asker, fzn_search_emit_t emit,
                            void *emit_ctx)
{
	const fzn_node_catalog_t *c = ctx;
	size_t i;

	if (!c || !q || !emit)
		return 0;
	if (asker)
		return 1;
	for (i = 0; i < c->count; i++) {
		const fzn_node_catalog_entry_t *e = &c->entries[i];
		const uint8_t *shown;
		size_t shown_len;
		fzn_search_hit_t h;
		unsigned s;

		if (!e->live || !e->value_len || (!named(e, "name", 4u) && !named(e, "kind", 4u)))
			continue;
		s = fzn_search_score(&q->words, (const char *)e->value, e->value_len);
		if (!s)
			continue;
		memset(&h, 0, sizeof(h));
		memcpy(h.store, "files", 6u);
		memcpy(h.key, e->entity, 32u);
		h.key_len = 32u;
		h.score = s;
		/* SHOWN BY ITS NAME, whichever claim was found. */
		if (!name_of(c, e->entity, &shown, &shown_len)) {
			shown = e->value;
			shown_len = e->value_len;
		}
		fzn_search_snippet(q, (const char *)shown, shown_len, &h);
		if (!emit(emit_ctx, &h))
			return 1;
	}
	return 1;
}
