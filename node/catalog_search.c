/* The library's files as a store of the one search: catalog_search.h, sec 1299. */
#include "catalog_search.h"

#include <string.h>

static int named(const fzn_node_catalog_entry_t *e, const char *name, size_t len)
{
	return e->name_len == len && memcmp(e->name, name, len) == 0;
}

/* WHAT THE WORDS READ, sec 1453's correction of sec 1447: a file's name and
 * kind, and what it says of itself in words (sec 1447's names) -- so music
 * is found by its artist or album and a photograph by its camera. Numbers,
 * sizes, places and times are facets to filter by, not words to find. */
static int searched(const fzn_node_catalog_entry_t *e)
{
	static const char *const words[] = { "name", "kind", "title", "artist", "album",
		                             "album_artist", "genre", "composer", "camera" };
	size_t i;

	for (i = 0; i < sizeof(words) / sizeof(words[0]); i++)
		if (named(e, words[i], strlen(words[i])))
			return 1;
	return 0;
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

/* ITS FACETS, sec 1331: the file's live claims, each a dimension and its
 * value as the catalogue keeps them -- `kind` first, then the rest while
 * the hit has room (FZN_SEARCH_FACETS_MAX) -- so a search filters the
 * library by the dimensions `facet` was made for. Its name is no facet:
 * the words find it. */
static void facets_of(const fzn_node_catalog_t *c, const uint8_t *entity, fzn_search_hit_t *h)
{
	static fzn_catalog_assertion_t about[256];
	const size_t n = fzn_node_catalog_assertions(c, entity, about, sizeof(about) / sizeof(about[0]));
	size_t k;
	int pass;

	for (pass = 0; pass < 2; pass++)
		for (k = 0; k < n; k++) {
			const int kind = about[k].name_len == 4u && memcmp(about[k].name, "kind", 4u) == 0;
			char dim[FZN_SEARCH_FACET_DIM_MAX + 1u];

			if (!about[k].live || (pass == 0) != kind || (about[k].name_len == 4u && !memcmp(about[k].name, "name", 4u))
			    || about[k].name_len > FZN_SEARCH_FACET_DIM_MAX || about[k].value_len > FZN_SEARCH_FACET_VALUE_MAX)
				continue;
			memcpy(dim, about[k].name, about[k].name_len);
			dim[about[k].name_len] = '\0';
			(void)fzn_search_facet_add(h, dim, (const char *)about[k].value, about[k].value_len);
		}
}

int fzn_node_catalog_search(void *ctx, const fzn_search_query_t *q, const uint8_t *asker, fzn_search_emit_t emit,
                            void *emit_ctx)
{
	const fzn_node_catalog_t *c = ctx;
	size_t i;

	if (!c || !q || !emit)
		return 0;
	/* NOTHING FOR A CONTACT, nor within a conversation (sec 1400): a
	 * library file is in none. */
	if (asker || q->within)
		return 1;
	for (i = 0; i < c->count; i++) {
		const fzn_node_catalog_entry_t *e = &c->entries[i];
		const uint8_t *shown;
		size_t shown_len;
		fzn_search_hit_t h;
		unsigned s;

		if (!e->live || !e->value_len || !searched(e))
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
		facets_of(c, e->entity, &h);
		if (!emit(emit_ctx, &h))
			return 1;
	}
	return 1;
}
