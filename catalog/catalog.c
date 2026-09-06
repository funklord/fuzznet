#include "catalog.h"

#include <string.h>

static int same_id(const fzn_catalog_id_t *a, const fzn_catalog_id_t *b)
{
	return memcmp(a->b, b->b, FZN_CATALOG_ID_LEN) == 0;
}

/* The row for an edge, or NULL. Linear, because a catalogue is a caller-owned
 * table like every other in this library and the caller sizes it: an index
 * would be mutable shared state, which project.md sec 135 records as the
 * thing that ends the one-lock property sec 132 rests on. */
static fzn_catalog_edge_t *find(const fzn_catalog_t *catalog, const fzn_catalog_id_t *parent,
                                const fzn_catalog_id_t *child)
{
	size_t i;

	for (i = 0; i < catalog->used; i++) {
		if (same_id(&catalog->edges[i].parent, parent)
		    && same_id(&catalog->edges[i].child, child))
			return &catalog->edges[i];
	}
	return NULL;
}

static int usable(const fzn_catalog_t *catalog)
{
	return catalog && catalog->edges && catalog->capacity > 0
	       && catalog->used <= catalog->capacity;
}

int fzn_catalog_add_wins(void *ctx, const fzn_catalog_edge_t *held,
                         const fzn_catalog_edge_t *offered)
{
	(void)ctx;
	if (!held || !offered)
		return 0;

	/* ONE ISSUER RESTATING ITS OWN EDGE IS NOT A CONFLICT, and this order
	 * is the whole correction. A sequence orders that issuer's statements,
	 * so a later one simply supersedes -- including a later UNLINK.
	 *
	 * Checking presence first, as the first version did, made a removal
	 * impossible: the holder asked for a structure that is easy to edit and
	 * got one nothing could be taken out of. See catalog.h. */
	if (memcmp(held->issuer, offered->issuer, FZN_PUBKEY_LEN) == 0)
		return offered->seq > held->seq ? 1 : 0;

	/* ACROSS ISSUERS, PRESENCE WINS, and that is where "add wins" means
	 * something: two hosts adding a member reach the same answer whatever
	 * order the assertions arrive in, so most of a catalogue needs no
	 * agreement at all. */
	if (held->present != offered->present)
		return offered->present ? 1 : 0;

	/* Two issuers agreeing: keep what is held, so the answer does not
	 * depend on arrival order. */
	return 0;
}

fzn_catalog_err_t fzn_catalog_init(fzn_catalog_t *catalog, fzn_catalog_edge_t *edges,
                                   size_t capacity, const fzn_catalog_resolve_ops_t *resolve)
{
	if (!catalog || !edges || capacity == 0)
		return FZN_CATALOG_ERR_MALFORMED;
	if (!resolve || !resolve->prefer)
		return FZN_CATALOG_ERR_MALFORMED;

	/* Zeroed, which project.md sec 39 settled for this family: what a fresh
	 * table holds must not depend on what its memory held. */
	memset(edges, 0, capacity * sizeof(*edges));
	catalog->edges = edges;
	catalog->capacity = capacity;
	catalog->used = 0;
	catalog->resolve = resolve;
	/* The content table starts absent, so a catalogue used purely as
	 * structure refuses every content call rather than appearing to accept
	 * one and doing nothing. `fzn_catalog_content_init` is what supplies
	 * it.
	 *
	 * BOTH LINES GUARD AND NEITHER IS DEAD, which took two sabotages to
	 * establish and is worth writing down because it looks like redundancy.
	 * `content_usable` requires a non-null table AND a non-zero capacity,
	 * so breaking either one alone leaves the other refusing -- both
	 * sabotages SURVIVED, and the first reading of that was that the
	 * pointer was hygiene. It is not: it is what refuses when the capacity
	 * is garbage, and the capacity is what refuses when the pointer is.
	 *
	 * So there is no sabotage entry for this pair, because no single-line
	 * one can fail. project.md sec 145 records that rather than leaving a
	 * later reader to rediscover it and delete a line as dead. */
	catalog->entries = NULL;
	catalog->entry_capacity = 0;
	catalog->entry_used = 0;
	catalog->content_resolve = NULL;
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_assert(fzn_catalog_t *catalog, const fzn_catalog_id_t *parent,
                                     const fzn_catalog_id_t *child,
                                     const uint8_t issuer[FZN_PUBKEY_LEN], uint64_t seq,
                                     int present)
{
	fzn_catalog_edge_t offered;
	fzn_catalog_edge_t *held;

	if (!usable(catalog) || !parent || !child || !issuer)
		return FZN_CATALOG_ERR_MALFORMED;
	/* A set cannot contain itself. Refused rather than stored, because the
	 * one query that would then be wrong -- `fzn_catalog_members` listing a
	 * set among its own members -- is wrong in a way a caller cannot tell
	 * from a genuine member. */
	if (same_id(parent, child))
		return FZN_CATALOG_ERR_MALFORMED;

	memset(&offered, 0, sizeof(offered));
	offered.parent = *parent;
	offered.child = *child;
	memcpy(offered.issuer, issuer, FZN_PUBKEY_LEN);
	offered.seq = seq;
	offered.present = present ? 1 : 0;

	held = find(catalog, parent, child);
	if (held) {
		if (!catalog->resolve->prefer(catalog->resolve->ctx, held, &offered))
			return FZN_CATALOG_ERR_STALE;
		*held = offered;
		return FZN_CATALOG_OK;
	}

	/* A TOMBSTONE COSTS A ROW, AND IT IS THE ROW THAT MAKES A REMOVAL
	 * STICK. An unlink for an edge nobody has asserted is still stored, so
	 * that a stale link arriving afterwards meets it rather than creating
	 * the edge afresh -- `chain/revocation.c` keeps a withdrawal for a
	 * triple it has never held for exactly this reason. */
	if (catalog->used == catalog->capacity)
		return FZN_CATALOG_ERR_FULL;

	catalog->edges[catalog->used] = offered;
	catalog->used++;
	return FZN_CATALOG_OK;
}

const fzn_catalog_edge_t *fzn_catalog_edge_of(const fzn_catalog_t *catalog,
                                              const fzn_catalog_id_t *parent,
                                              const fzn_catalog_id_t *child)
{
	if (!usable(catalog) || !parent || !child)
		return NULL;
	return find(catalog, parent, child);
}

int fzn_catalog_linked(const fzn_catalog_t *catalog, const fzn_catalog_id_t *parent,
                       const fzn_catalog_id_t *child)
{
	const fzn_catalog_edge_t *edge = fzn_catalog_edge_of(catalog, parent, child);

	return edge ? edge->present : 0;
}

size_t fzn_catalog_members(const fzn_catalog_t *catalog, const fzn_catalog_id_t *parent,
                           fzn_catalog_id_t *out, size_t cap)
{
	size_t i;
	size_t at = 0;

	if (!usable(catalog) || !parent || !out)
		return 0;

	for (i = 0; i < catalog->used && at < cap; i++) {
		if (!catalog->edges[i].present)
			continue;
		if (!same_id(&catalog->edges[i].parent, parent))
			continue;
		out[at++] = catalog->edges[i].child;
	}
	return at;
}

size_t fzn_catalog_parents(const fzn_catalog_t *catalog, const fzn_catalog_id_t *child,
                           fzn_catalog_id_t *out, size_t cap)
{
	size_t i;
	size_t at = 0;

	if (!usable(catalog) || !child || !out)
		return 0;

	for (i = 0; i < catalog->used && at < cap; i++) {
		if (!catalog->edges[i].present)
			continue;
		if (!same_id(&catalog->edges[i].child, child))
			continue;
		out[at++] = catalog->edges[i].parent;
	}
	return at;
}

size_t fzn_catalog_intersect(const fzn_catalog_t *catalog, const fzn_catalog_id_t *parents,
                             size_t parent_count, fzn_catalog_id_t *out, size_t cap)
{
	size_t i, j;
	size_t at = 0;

	if (!usable(catalog) || !parents || !out || parent_count == 0)
		return 0;

	/* Walk the first term's members and keep those in every other term.
	 * The first term bounds the work, so intersecting a narrow directory
	 * with a wide one costs the narrow one -- which is the order a caller
	 * would choose by hand and does not have to. */
	for (i = 0; i < catalog->used && at < cap; i++) {
		const fzn_catalog_edge_t *edge = &catalog->edges[i];
		int in_all = 1;

		if (!edge->present || !same_id(&edge->parent, &parents[0]))
			continue;
		for (j = 1; j < parent_count; j++) {
			if (!fzn_catalog_linked(catalog, &parents[j], &edge->child)) {
				in_all = 0;
				break;
			}
		}
		if (in_all)
			out[at++] = edge->child;
	}
	return at;
}

const char *fzn_catalog_err_str(fzn_catalog_err_t err)
{
	switch (err) {
	case FZN_CATALOG_OK:
		return "ok";
	case FZN_CATALOG_ERR_MALFORMED:
		return "malformed";
	case FZN_CATALOG_ERR_FULL:
		return "no room for another edge";
	case FZN_CATALOG_ERR_STALE:
		return "the assertion already held stands";
	}
	return "unknown";
}

/* ---- what a node holds -------------------------------------------------- */

static fzn_catalog_entry_t *find_entry(const fzn_catalog_t *catalog,
                                       const fzn_catalog_id_t *id)
{
	size_t i;

	for (i = 0; i < catalog->entry_used; i++) {
		if (same_id(&catalog->entries[i].id, id))
			return &catalog->entries[i];
	}
	return NULL;
}

static int content_usable(const fzn_catalog_t *catalog)
{
	return catalog && catalog->entries && catalog->entry_capacity > 0
	       && catalog->entry_used <= catalog->entry_capacity && catalog->content_resolve
	       && catalog->content_resolve->prefer;
}

int fzn_catalog_content_held_wins(void *ctx, const fzn_catalog_entry_t *held,
                                  const fzn_catalog_entry_t *offered)
{
	(void)ctx;
	if (!held || !offered)
		return 0;

	/* One issuer restating its own content is not a conflict, just a later
	 * statement -- the same correction sec 144 records for edges, and the
	 * reason a node's content can be edited at all. */
	if (memcmp(held->issuer, offered->issuer, FZN_PUBKEY_LEN) == 0)
		return offered->seq > held->seq ? 1 : 0;

	/* Across issuers there is no "later" to appeal to, so what is held
	 * stands. That is not a preference for the first writer; it is the only
	 * answer that does not depend on which arrived first. */
	return 0;
}

fzn_catalog_err_t fzn_catalog_content_init(fzn_catalog_t *catalog,
                                           fzn_catalog_entry_t *entries, size_t capacity,
                                           const fzn_catalog_content_ops_t *resolve)
{
	if (!catalog || !entries || capacity == 0)
		return FZN_CATALOG_ERR_MALFORMED;
	if (!resolve || !resolve->prefer)
		return FZN_CATALOG_ERR_MALFORMED;

	memset(entries, 0, capacity * sizeof(*entries));
	catalog->entries = entries;
	catalog->entry_capacity = capacity;
	catalog->entry_used = 0;
	catalog->content_resolve = resolve;
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_content_set(fzn_catalog_t *catalog,
                                          const fzn_catalog_entry_t *entry)
{
	fzn_catalog_entry_t *held;

	if (!content_usable(catalog) || !entry)
		return FZN_CATALOG_ERR_MALFORMED;

	switch (entry->kind) {
	case FZN_CATALOG_CONTENT_NONE:
		break;
	case FZN_CATALOG_CONTENT_INLINE:
		/* A LENGTH PAST WHAT A RECORD BODY CARRIES is a caller
		 * describing something it could never send, so it is refused
		 * here rather than at the moment somebody tries. */
		if (entry->len > FZN_RECORD_BODY_MAX)
			return FZN_CATALOG_ERR_MALFORMED;
		if (entry->len > 0 && !entry->bytes)
			return FZN_CATALOG_ERR_MALFORMED;
		break;
	case FZN_CATALOG_CONTENT_BLOB:
		/* A BLOB OF ZERO LENGTH IS A NAME FOR NOTHING. An empty value
		 * is expressible -- it is an INLINE of length zero -- so a
		 * zero-length blob is a caller that filled in half a row. */
		if (entry->blob_len == 0)
			return FZN_CATALOG_ERR_MALFORMED;
		break;
	default:
		return FZN_CATALOG_ERR_MALFORMED;
	}

	held = find_entry(catalog, &entry->id);
	if (held) {
		if (!catalog->content_resolve->prefer(catalog->content_resolve->ctx, held, entry))
			return FZN_CATALOG_ERR_STALE;
		*held = *entry;
		return FZN_CATALOG_OK;
	}

	if (catalog->entry_used == catalog->entry_capacity)
		return FZN_CATALOG_ERR_FULL;

	catalog->entries[catalog->entry_used] = *entry;
	catalog->entry_used++;
	return FZN_CATALOG_OK;
}

const fzn_catalog_entry_t *fzn_catalog_content_of(const fzn_catalog_t *catalog,
                                                  const fzn_catalog_id_t *id)
{
	if (!content_usable(catalog) || !id)
		return NULL;
	return find_entry(catalog, id);
}

const char *fzn_catalog_content_str(fzn_catalog_content_t kind)
{
	switch (kind) {
	case FZN_CATALOG_CONTENT_NONE:
		return "a set, holding no bytes";
	case FZN_CATALOG_CONTENT_INLINE:
		return "bytes carried here";
	case FZN_CATALOG_CONTENT_BLOB:
		return "a blob fetched separately";
	}
	return "unknown";
}
