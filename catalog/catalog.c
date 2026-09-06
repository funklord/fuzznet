#include "catalog.h"

#include "../wire/bytes.h"

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
	/* No filing root until a caller names one, so every path query refuses
	 * rather than this module inventing one. */
	catalog->refiling = 0;
	catalog->holds = NULL;
	catalog->hold_capacity = 0;
	catalog->hold_used = 0;
	/* A catalogue keeps nothing until a caller says so: a default of
	 * keeping would make adopting a stranger's catalogue fill this host's
	 * disk. */
	catalog->retain_default = 0;
	catalog->names = NULL;
	catalog->name_capacity = 0;
	catalog->name_used = 0;
	catalog->name_resolve = NULL;
	catalog->filing_root_set = 0;
	memset(&catalog->filing_root, 0, sizeof(catalog->filing_root));
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
	if (catalog->refiling)
		return FZN_CATALOG_ERR_BUSY;
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
		/* THE FILING MARK SURVIVES A RE-ASSERTION AND NOT A REMOVAL. It
		 * is this host's and is not in `offered`, which came off the
		 * wire or from a caller that has no business setting it -- so
		 * carry it across rather than letting an ordinary link wipe
		 * where the host keeps its bytes. An unlink is the one case
		 * that clears it: a node filed under a directory it has left is
		 * a path to a place the catalogue no longer says it belongs. */
		offered.filed = offered.present ? held->filed : 0;
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
	if (catalog && catalog->refiling)
		return NULL;
	if (!usable(catalog) || !parent || !child)
		return NULL;
	return find(catalog, parent, child);
}

int fzn_catalog_linked(const fzn_catalog_t *catalog, const fzn_catalog_id_t *parent,
                       const fzn_catalog_id_t *child)
{
	/* Even a read: the holder's requirement is that the only thing a
	 * catalogue answers mid-refile is progress, so a consumer draws a bar
	 * rather than a tree that is half moved. */
	if (catalog && catalog->refiling)
		return 0;
	const fzn_catalog_edge_t *edge = fzn_catalog_edge_of(catalog, parent, child);

	return edge ? edge->present : 0;
}

size_t fzn_catalog_members(const fzn_catalog_t *catalog, const fzn_catalog_id_t *parent,
                           fzn_catalog_id_t *out, size_t cap)
{
	size_t i;
	size_t at = 0;

	if (catalog && catalog->refiling)
		return 0;
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

	if (catalog && catalog->refiling)
		return 0;
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

	if (catalog && catalog->refiling)
		return 0;
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
	case FZN_CATALOG_ERR_SHAPE:
		return "not a catalogue assertion";
	case FZN_CATALOG_ERR_ABSENT:
		return "no such membership";
	case FZN_CATALOG_ERR_BUSY:
		return "a refile is under way";
	case FZN_CATALOG_ERR_BACKEND:
		return "the filesystem seam refused";
	case FZN_CATALOG_ERR_PATH:
		return "not a usable path";
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
	if (catalog->refiling)
		return FZN_CATALOG_ERR_BUSY;

	switch (entry->kind) {
	case FZN_CATALOG_CONTENT_NONE:
		break;
	case FZN_CATALOG_CONTENT_INLINE:
		/* A LENGTH PAST WHAT A RECORD BODY CARRIES is a caller
		 * describing something it could never send, so it is refused
		 * here rather than at the moment somebody tries. */
		/* THE WIRE BOUND, NOT THE RECORD BODY'S. This said
		 * FZN_RECORD_BODY_MAX until sec 146 built the encoder, and
		 * admitted a value that no record could ever carry: an inline
		 * body is the value plus a 34-byte head. A table that accepts
		 * what the wire refuses is a table whose contents cannot be
		 * sent, discovered at the moment somebody tries. */
		if (entry->len > FZN_CATALOG_INLINE_MAX)
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
	if (catalog && catalog->refiling)
		return NULL;
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

/* ---- the wire form ------------------------------------------------------ */

fzn_catalog_err_t fzn_catalog_edge_encode(const fzn_catalog_id_t *parent,
                                          const fzn_catalog_id_t *child, int present,
                                          uint8_t *out, size_t cap, size_t *len_out)
{
	if (!parent || !child || !out || !len_out)
		return FZN_CATALOG_ERR_MALFORMED;
	/* Nothing is written unless all of it fits, so a short buffer leaves
	 * the caller's as it found it rather than holding half an assertion. */
	if (cap < FZN_CATALOG_EDGE_BODY_LEN)
		return FZN_CATALOG_ERR_MALFORMED;

	out[0] = (uint8_t)FZN_CATALOG_OBJECT_EDGE;
	memcpy(out + 1, parent->b, FZN_CATALOG_ID_LEN);
	memcpy(out + 1 + FZN_CATALOG_ID_LEN, child->b, FZN_CATALOG_ID_LEN);
	/* CANONICAL, not "any nonzero is true". See the header on why one
	 * encoding of one statement is the whole point. */
	out[FZN_CATALOG_EDGE_BODY_LEN - 1u] = present ? 1u : 0u;
	*len_out = FZN_CATALOG_EDGE_BODY_LEN;
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_content_encode(const fzn_catalog_entry_t *entry, uint8_t *out,
                                             size_t cap, size_t *len_out)
{
	size_t need;

	if (!entry || !out || !len_out)
		return FZN_CATALOG_ERR_MALFORMED;

	switch (entry->kind) {
	case FZN_CATALOG_CONTENT_NONE:
		need = FZN_CATALOG_CONTENT_HEAD_LEN;
		break;
	case FZN_CATALOG_CONTENT_INLINE:
		if (entry->len > FZN_CATALOG_INLINE_MAX)
			return FZN_CATALOG_ERR_MALFORMED;
		if (entry->len > 0 && !entry->bytes)
			return FZN_CATALOG_ERR_MALFORMED;
		need = FZN_CATALOG_CONTENT_HEAD_LEN + entry->len;
		break;
	case FZN_CATALOG_CONTENT_BLOB:
		if (entry->blob_len == 0)
			return FZN_CATALOG_ERR_MALFORMED;
		need = FZN_CATALOG_BLOB_BODY_LEN;
		break;
	default:
		return FZN_CATALOG_ERR_MALFORMED;
	}
	if (cap < need)
		return FZN_CATALOG_ERR_MALFORMED;

	out[0] = (uint8_t)FZN_CATALOG_OBJECT_CONTENT;
	memcpy(out + 1, entry->id.b, FZN_CATALOG_ID_LEN);
	out[FZN_CATALOG_CONTENT_HEAD_LEN - 1u] = (uint8_t)entry->kind;

	if (entry->kind == FZN_CATALOG_CONTENT_INLINE && entry->len > 0)
		memcpy(out + FZN_CATALOG_CONTENT_HEAD_LEN, entry->bytes, entry->len);
	if (entry->kind == FZN_CATALOG_CONTENT_BLOB) {
		memcpy(out + FZN_CATALOG_CONTENT_HEAD_LEN, entry->root, FZN_BLOB_HASH_LEN);
		fzn_put_be64(out + FZN_CATALOG_CONTENT_HEAD_LEN + FZN_BLOB_HASH_LEN,
		             entry->blob_len);
	}

	*len_out = need;
	return FZN_CATALOG_OK;
}

static fzn_catalog_err_t apply_edge(fzn_catalog_t *catalog, const uint8_t *body, size_t len,
                                    const uint8_t *issuer, uint64_t seq)
{
	fzn_catalog_id_t parent, child;
	uint8_t present;

	/* An edge body is one length and no other, so a shorter or longer one
	 * is not a truncated edge -- it is not an edge. */
	if (len != FZN_CATALOG_EDGE_BODY_LEN)
		return FZN_CATALOG_ERR_SHAPE;
	present = body[FZN_CATALOG_EDGE_BODY_LEN - 1u];
	if (present > 1u)
		return FZN_CATALOG_ERR_SHAPE;

	memcpy(parent.b, body + 1, FZN_CATALOG_ID_LEN);
	memcpy(child.b, body + 1 + FZN_CATALOG_ID_LEN, FZN_CATALOG_ID_LEN);
	return fzn_catalog_assert(catalog, &parent, &child, issuer, seq, present);
}

static fzn_catalog_err_t apply_content(fzn_catalog_t *catalog, const uint8_t *body, size_t len,
                                       const uint8_t *issuer, uint64_t seq)
{
	fzn_catalog_entry_t entry;

	if (len < FZN_CATALOG_CONTENT_HEAD_LEN)
		return FZN_CATALOG_ERR_SHAPE;

	memset(&entry, 0, sizeof(entry));
	memcpy(entry.id.b, body + 1, FZN_CATALOG_ID_LEN);
	entry.kind = (fzn_catalog_content_t)body[FZN_CATALOG_CONTENT_HEAD_LEN - 1u];
	/* THE ISSUER AND SEQUENCE COME FROM THE RECORD, never from the body --
	 * there is no field for them, so an assertion cannot be attributed to
	 * somebody who did not make it. */
	memcpy(entry.issuer, issuer, FZN_PUBKEY_LEN);
	entry.seq = seq;

	switch (entry.kind) {
	case FZN_CATALOG_CONTENT_NONE:
		if (len != FZN_CATALOG_CONTENT_HEAD_LEN)
			return FZN_CATALOG_ERR_SHAPE;
		break;
	case FZN_CATALOG_CONTENT_INLINE:
		entry.len = len - FZN_CATALOG_CONTENT_HEAD_LEN;
		/* A VIEW INTO THE RECORD, not a copy. The record's buffer must
		 * outlive the row, which the header says and nothing here can
		 * enforce. */
		entry.bytes = entry.len > 0 ? body + FZN_CATALOG_CONTENT_HEAD_LEN : NULL;
		break;
	case FZN_CATALOG_CONTENT_BLOB:
		if (len != FZN_CATALOG_BLOB_BODY_LEN)
			return FZN_CATALOG_ERR_SHAPE;
		memcpy(entry.root, body + FZN_CATALOG_CONTENT_HEAD_LEN, FZN_BLOB_HASH_LEN);
		entry.blob_len = fzn_get_be64(body + FZN_CATALOG_CONTENT_HEAD_LEN
		                              + FZN_BLOB_HASH_LEN);
		if (entry.blob_len == 0)
			return FZN_CATALOG_ERR_SHAPE;
		break;
	default:
		return FZN_CATALOG_ERR_SHAPE;
	}

	return fzn_catalog_content_set(catalog, &entry);
}

/* Defined with the rest of the name code below, because a name is its own
 * subsystem here rather than a field on a content body. */
static fzn_catalog_err_t apply_name(fzn_catalog_t *catalog, const uint8_t *body, size_t len,
                                    const uint8_t *issuer, uint64_t seq);

fzn_catalog_err_t fzn_catalog_apply(fzn_catalog_t *catalog, fzn_record_t record)
{
	const uint8_t *body;
	size_t len;

	if (!catalog)
		return FZN_CATALOG_ERR_MALFORMED;
	/* A PEER'S RECORD WAITS. The catalogue is being rearranged on disk and
	 * a membership arriving mid-refile would change the set the cursor is
	 * counting through. A consumer holds it and applies it after. */
	if (catalog->refiling)
		return FZN_CATALOG_ERR_BUSY;
	/* A view that was never opened has no accessors to read, so this is
	 * refused before any of them is called. */
	if (!fzn_record_is_open(record))
		return FZN_CATALOG_ERR_MALFORMED;

	len = fzn_record_body_len(record);
	body = fzn_record_body(record);
	if (len == 0 || !body)
		return FZN_CATALOG_ERR_SHAPE;

	switch (body[0]) {
	case FZN_CATALOG_OBJECT_EDGE:
		return apply_edge(catalog, body, len, fzn_record_issuer(record),
		                  fzn_record_seq(record));
	case FZN_CATALOG_OBJECT_CONTENT:
		return apply_content(catalog, body, len, fzn_record_issuer(record),
		                     fzn_record_seq(record));
	case FZN_CATALOG_OBJECT_NAME:
		return apply_name(catalog, body, len, fzn_record_issuer(record),
		                  fzn_record_seq(record));
	default:
		/* Somebody else's body in a stream this catalogue follows. Not
		 * ours, and saying so is different from calling it broken. */
		return FZN_CATALOG_ERR_SHAPE;
	}
}

/* ---- the filing --------------------------------------------------------- */

fzn_catalog_err_t fzn_catalog_filing_root(fzn_catalog_t *catalog,
                                          const fzn_catalog_id_t *root)
{
	if (!usable(catalog) || !root)
		return FZN_CATALOG_ERR_MALFORMED;
	if (catalog->refiling)
		return FZN_CATALOG_ERR_BUSY;

	catalog->filing_root = *root;
	catalog->filing_root_set = 1;
	return FZN_CATALOG_OK;
}

const fzn_catalog_id_t *fzn_catalog_filing_root_of(const fzn_catalog_t *catalog)
{
	if (!usable(catalog) || !catalog->filing_root_set)
		return NULL;
	return &catalog->filing_root;
}

fzn_catalog_err_t fzn_catalog_file_under(fzn_catalog_t *catalog,
                                         const fzn_catalog_id_t *parent,
                                         const fzn_catalog_id_t *child)
{
	fzn_catalog_edge_t *edge;
	size_t i;

	if (!usable(catalog) || !parent || !child)
		return FZN_CATALOG_ERR_MALFORMED;
	if (catalog->refiling)
		return FZN_CATALOG_ERR_BUSY;

	edge = find(catalog, parent, child);
	/* A FILING IS A SUBSET OF THE MEMBERSHIP, so there must be an edge to
	 * mark. Refused rather than created: a caller filing under a directory
	 * the node does not belong to has the two out of step, and creating the
	 * membership silently would make the disk layout the thing that decides
	 * what the catalogue says. */
	if (!edge || !edge->present)
		return FZN_CATALOG_ERR_ABSENT;

	/* EXACTLY ONCE, STRUCTURALLY. Every other filing of this child is
	 * cleared as this one is set, so the invariant cannot be violated
	 * rather than being checked afterwards by something somebody has to
	 * remember to run. */
	for (i = 0; i < catalog->used; i++) {
		if (same_id(&catalog->edges[i].child, child))
			catalog->edges[i].filed = 0;
	}
	edge->filed = 1;
	return FZN_CATALOG_OK;
}

const fzn_catalog_id_t *fzn_catalog_filed_under(const fzn_catalog_t *catalog,
                                                const fzn_catalog_id_t *child)
{
	size_t i;

	if (!usable(catalog) || !child)
		return NULL;

	for (i = 0; i < catalog->used; i++) {
		if (catalog->edges[i].filed && catalog->edges[i].present
		    && same_id(&catalog->edges[i].child, child))
			return &catalog->edges[i].parent;
	}
	return NULL;
}

/* The walk itself, reachable by the refile while the catalogue is locked: a
 * refile asking where a node now belongs is the refile doing its job, not a
 * consumer reading a tree that is half moved. */
static size_t filed_path_locked(const fzn_catalog_t *catalog, const fzn_catalog_id_t *node,
                                fzn_catalog_id_t *out, size_t cap)
{
	fzn_catalog_id_t walk[FZN_CATALOG_FILING_MAX_DEPTH];
	const fzn_catalog_id_t *at;
	size_t depth = 0;
	size_t i;

	if (!usable(catalog) || !node || !out || cap == 0)
		return 0;
	if (!catalog->filing_root_set)
		return 0;

	/* Up from the node, collecting; the walk is BOUNDED rather than
	 * trusted, because one filing slot per node makes a cycle expressible
	 * and a bound cannot be forgotten the way a cycle check can. */
	walk[depth++] = *node;
	while (!same_id(&walk[depth - 1u], &catalog->filing_root)) {
		at = fzn_catalog_filed_under(catalog, &walk[depth - 1u]);
		if (!at)
			return 0;
		if (depth == FZN_CATALOG_FILING_MAX_DEPTH)
			return 0;
		walk[depth++] = *at;
	}

	/* Root first, which is the order a path is written and the order a
	 * caller creates directories in. */
	for (i = 0; i < depth && i < cap; i++)
		out[i] = walk[depth - 1u - i];
	return i;
}

size_t fzn_catalog_filed_path(const fzn_catalog_t *catalog, const fzn_catalog_id_t *node,
                              fzn_catalog_id_t *out, size_t cap)
{
	if (catalog && catalog->refiling)
		return 0;
	return filed_path_locked(catalog, node, out, cap);
}

/* ---- the refile --------------------------------------------------------- */

/* Ascending by id, so the order of the moves is the same on every machine and
 * after every restart -- whatever order the edge table happens to be in. The
 * cursor is a count into this order, so the order is what makes a restart
 * resume rather than begin again somewhere arbitrary. */
static int id_before(const fzn_catalog_id_t *a, const fzn_catalog_id_t *b)
{
	return memcmp(a->b, b->b, FZN_CATALOG_ID_LEN) < 0;
}

fzn_catalog_err_t fzn_catalog_refile_capture(const fzn_catalog_t *catalog,
                                             fzn_catalog_refile_t *job,
                                             fzn_catalog_move_t *moves, size_t capacity)
{
	size_t i, j;

	if (!usable(catalog) || !job || !moves || capacity == 0)
		return FZN_CATALOG_ERR_MALFORMED;
	if (catalog->refiling)
		return FZN_CATALOG_ERR_BUSY;
	/* Nothing to move files FROM. A capture without a root would produce a
	 * job whose old paths are all empty, which reads as "every file is
	 * misplaced" rather than as the missing root it is. */
	if (!catalog->filing_root_set)
		return FZN_CATALOG_ERR_ABSENT;

	memset(job, 0, sizeof(*job));
	job->moves = moves;
	job->capacity = capacity;
	job->was_root = catalog->filing_root;

	for (i = 0; i < catalog->used; i++) {
		fzn_catalog_move_t entry;

		if (!catalog->edges[i].filed || !catalog->edges[i].present)
			continue;
		/* FULL IS LOUD. A capture that quietly held some of the filed
		 * nodes would move some of the files and leave the rest where a
		 * path nobody holds any more says they are. */
		if (job->used == capacity)
			return FZN_CATALOG_ERR_FULL;

		entry.node = catalog->edges[i].child;
		entry.was_under = catalog->edges[i].parent;
		/* Insertion sort: the table is a caller's and is small enough
		 * that a sort with no scratch beats one that needs some. */
		for (j = job->used; j > 0 && id_before(&entry.node, &moves[j - 1u].node); j--)
			moves[j] = moves[j - 1u];
		moves[j] = entry;
		job->used++;
	}

	job->captured = 1;
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_refile_begin(fzn_catalog_t *catalog, fzn_catalog_refile_t *job)
{
	if (!usable(catalog) || !job || !job->captured)
		return FZN_CATALOG_ERR_MALFORMED;

	/* IDEMPOTENT, BECAUSE A RESTART CALLS IT AGAIN. A consumer that
	 * crashed mid-refile reloads the job from disk and begins the same one;
	 * refusing here would make a crash unrecoverable by the very path that
	 * exists to recover from it. */
	catalog->refiling = 1;
	return FZN_CATALOG_OK;
}

/* Walk up through the CAPTURED filing, which is the arrangement the files are
 * actually in. The catalogue now holds the new one. */
static size_t was_path(const fzn_catalog_refile_t *job, const fzn_catalog_id_t *node,
                       fzn_catalog_id_t *out, size_t cap)
{
	fzn_catalog_id_t walk[FZN_CATALOG_FILING_MAX_DEPTH];
	size_t depth = 0;
	size_t i, j;

	if (cap == 0)
		return 0;
	walk[depth++] = *node;
	while (!same_id(&walk[depth - 1u], &job->was_root)) {
		for (i = 0; i < job->used; i++) {
			if (same_id(&job->moves[i].node, &walk[depth - 1u]))
				break;
		}
		if (i == job->used)
			return 0;
		if (depth == FZN_CATALOG_FILING_MAX_DEPTH)
			return 0;
		walk[depth++] = job->moves[i].was_under;
	}

	for (j = 0; j < depth && j < cap; j++)
		out[j] = walk[depth - 1u - j];
	return j;
}

fzn_catalog_err_t fzn_catalog_refile_at(const fzn_catalog_t *catalog,
                                        const fzn_catalog_refile_t *job,
                                        fzn_catalog_id_t *node_out,
                                        fzn_catalog_id_t *was_out, size_t was_cap,
                                        size_t *was_len, fzn_catalog_id_t *now_out,
                                        size_t now_cap, size_t *now_len)
{
	const fzn_catalog_id_t *node;

	if (!catalog || !catalog->edges || !job || !job->captured || !node_out || !was_out
	    || !was_len || !now_out || !now_len)
		return FZN_CATALOG_ERR_MALFORMED;
	/* Past the last move is how a caller learns the work is finished. */
	if (job->done >= job->used)
		return FZN_CATALOG_ERR_ABSENT;

	node = &job->moves[job->done].node;
	*node_out = *node;
	*was_len = was_path(job, node, was_out, was_cap);
	/* The new path comes from the catalogue, and reaches past the busy
	 * guard deliberately: a refile asking where a node now belongs is the
	 * refile doing its job rather than a consumer reading a half-moved
	 * tree. */
	*now_len = filed_path_locked(catalog, node, now_out, now_cap);
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_refile_advance(fzn_catalog_refile_t *job)
{
	if (!job || !job->captured)
		return FZN_CATALOG_ERR_MALFORMED;
	if (job->done >= job->used)
		return FZN_CATALOG_ERR_ABSENT;

	job->done++;
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_refile_progress(const fzn_catalog_refile_t *job,
                                              size_t *done_out, size_t *total_out)
{
	if (!job || !job->captured || !done_out || !total_out)
		return FZN_CATALOG_ERR_MALFORMED;

	*done_out = job->done;
	*total_out = job->used;
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_refile_end(fzn_catalog_t *catalog, fzn_catalog_refile_t *job)
{
	if (!catalog || !catalog->edges || !job || !job->captured)
		return FZN_CATALOG_ERR_MALFORMED;
	/* REFUSED WHILE WORK REMAINS. Ending an abandoned refile would unlock a
	 * catalogue whose files are half under paths it no longer describes,
	 * and the next reader would be told a tree that is not on the disk. */
	if (job->done < job->used)
		return FZN_CATALOG_ERR_BUSY;

	catalog->refiling = 0;
	return FZN_CATALOG_OK;
}

/* ---- the filesystem seam ------------------------------------------------ */

/* A segment a path may be built from.
 *
 * REFUSED, NOT SANITISED. A consumer naming a node from data hands back
 * whatever it was told, and quietly rewriting a name would put a file
 * somewhere neither the consumer nor the catalogue describes. Saying no is
 * the answer a caller can act on. */
static fzn_catalog_err_t usable_segment(const char *seg)
{
	size_t i;

	if (!seg || !*seg)
		return FZN_CATALOG_ERR_PATH;
	/* A SEPARATOR WOULD FORGE A LEVEL OF THE TREE that nobody asserted --
	 * `log/log.h` refuses a newline in a body for the same reason, where an
	 * unescaped one draws an entry nobody signed. */
	for (i = 0; seg[i]; i++) {
		if (seg[i] == '/')
			return FZN_CATALOG_ERR_PATH;
		if (i >= FZN_CATALOG_SEGMENT_MAX)
			return FZN_CATALOG_ERR_PATH;
	}
	/* A TRAVERSAL WALKS OUT OF THE FILING ROOT ENTIRELY, which is the same
	 * defect pointed at the rest of the disk rather than at the tree. */
	if (strcmp(seg, ".") == 0 || strcmp(seg, "..") == 0)
		return FZN_CATALOG_ERR_PATH;
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_path_of(const fzn_catalog_id_t *ids, size_t count,
                                      const fzn_catalog_fs_ops_t *ops, char *out, size_t cap)
{
	char segment[FZN_CATALOG_SEGMENT_MAX + 1u];
	/* ASSEMBLED HERE AND COPIED OUT ONLY ON SUCCESS. Written straight into
	 * the caller's buffer, a path refused at its third segment would leave
	 * the first two there -- and the header promises that a refusal leaves
	 * the buffer as it found it. The suite caught the difference, which is
	 * the version of this that says a comment is a check a reader runs. */
	char built[FZN_CATALOG_PATH_MAX];
	fzn_catalog_err_t err;
	size_t at = 0;
	size_t i, len;

	if (!ids || !ops || !ops->name || !out || cap == 0)
		return FZN_CATALOG_ERR_MALFORMED;
	/* An empty run is not an empty path, it is no path -- and returning ""
	 * would hand a consumer a name for the working directory. */
	if (count == 0)
		return FZN_CATALOG_ERR_PATH;

	for (i = 0; i < count; i++) {
		memset(segment, 0, sizeof(segment));
		if (!ops->name(ops->ctx, &ids[i], segment, sizeof(segment)))
			return FZN_CATALOG_ERR_BACKEND;
		/* A backend that filled the buffer without terminating it would
		 * otherwise be read past its end. */
		segment[FZN_CATALOG_SEGMENT_MAX] = '\0';

		err = usable_segment(segment);
		if (err != FZN_CATALOG_OK)
			return err;

		len = strlen(segment);
		/* The separator, the segment and the terminator, checked before
		 * any of it is written so a refusal leaves the caller's buffer
		 * as it found it rather than holding half a path. */
		if (at + (i > 0 ? 1u : 0u) + len + 1u > cap
		    || at + (i > 0 ? 1u : 0u) + len + 1u > sizeof(built))
			return FZN_CATALOG_ERR_PATH;
		if (i > 0)
			built[at++] = '/';
		memcpy(built + at, segment, len);
		at += len;
	}
	built[at] = '\0';
	/* UNCONDITIONAL, AND SAFE BY THE CHECK ABOVE: every segment's bound
	 * test includes `cap`, so `at + 1` cannot exceed it here. Clamping this
	 * would be unreachable code -- the sabotage harness confirmed no
	 * mutation of it can fail -- and there is no entry for it, which sec
	 * 149 records so a later reader does not add one and find it survives. */
	memcpy(out, built, at + 1u);
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_refile_step(const fzn_catalog_t *catalog,
                                          fzn_catalog_refile_t *job,
                                          const fzn_catalog_fs_ops_t *ops)
{
	fzn_catalog_id_t node;
	fzn_catalog_id_t was_ids[FZN_CATALOG_FILING_MAX_DEPTH];
	fzn_catalog_id_t now_ids[FZN_CATALOG_FILING_MAX_DEPTH];
	char was[FZN_CATALOG_PATH_MAX];
	char now[FZN_CATALOG_PATH_MAX];
	size_t was_len = 0, now_len = 0;
	fzn_catalog_err_t err;

	if (!ops || !ops->name || !ops->move)
		return FZN_CATALOG_ERR_MALFORMED;

	err = fzn_catalog_refile_at(catalog, job, &node, was_ids, FZN_CATALOG_FILING_MAX_DEPTH,
	                            &was_len, now_ids, FZN_CATALOG_FILING_MAX_DEPTH, &now_len);
	if (err != FZN_CATALOG_OK)
		return err;

	err = fzn_catalog_path_of(was_ids, was_len, ops, was, sizeof(was));
	if (err != FZN_CATALOG_OK)
		return err;
	err = fzn_catalog_path_of(now_ids, now_len, ops, now, sizeof(now));
	if (err != FZN_CATALOG_OK)
		return err;

	if (!ops->move(ops->ctx, was, now))
		return FZN_CATALOG_ERR_BACKEND;

	/* THE ORDER IS THE WHOLE POINT OF THIS FUNCTION. sec 148 chose to
	 * advance after the file has moved so that a crash repeats a step
	 * rather than skipping one, and here that stops being a sentence a
	 * consumer has to read and becomes the shape of the code: a failed move
	 * leaves the cursor where it was. */
	return fzn_catalog_refile_advance(job);
}

/* ---- names -------------------------------------------------------------- */

static fzn_catalog_name_t *find_name(const fzn_catalog_t *catalog, const fzn_catalog_id_t *id)
{
	size_t i;

	for (i = 0; i < catalog->name_used; i++) {
		if (same_id(&catalog->names[i].id, id))
			return &catalog->names[i];
	}
	return NULL;
}

static int name_usable(const fzn_catalog_t *catalog)
{
	return catalog && catalog->names && catalog->name_capacity > 0
	       && catalog->name_used <= catalog->name_capacity && catalog->name_resolve
	       && catalog->name_resolve->prefer;
}

/* Any byte from 0x20 up except DEL: every UTF-8 sequence passes and the C0
 * controls do not. A newline breaks any listing that puts one name per line
 * and an escape byte drives the terminal it is drawn on -- `log/log.h`'s
 * argument, met where the bytes are stored rather than where they are shown. */
static fzn_catalog_err_t usable_name(const uint8_t *text, size_t len)
{
	size_t i;

	if (!text || len == 0 || len > FZN_CATALOG_NAME_MAX)
		return FZN_CATALOG_ERR_PATH;
	for (i = 0; i < len; i++) {
		if (text[i] < 0x20u || text[i] == 0x7fu)
			return FZN_CATALOG_ERR_PATH;
	}
	return FZN_CATALOG_OK;
}

int fzn_catalog_name_held_wins(void *ctx, const fzn_catalog_name_t *held,
                               const fzn_catalog_name_t *offered)
{
	(void)ctx;
	if (!held || !offered)
		return 0;
	if (memcmp(held->issuer, offered->issuer, FZN_PUBKEY_LEN) == 0)
		return offered->seq > held->seq ? 1 : 0;
	return 0;
}

fzn_catalog_err_t fzn_catalog_name_init(fzn_catalog_t *catalog, fzn_catalog_name_t *names,
                                        size_t capacity, const fzn_catalog_name_ops_t *resolve)
{
	if (!catalog || !names || capacity == 0)
		return FZN_CATALOG_ERR_MALFORMED;
	if (!resolve || !resolve->prefer)
		return FZN_CATALOG_ERR_MALFORMED;

	memset(names, 0, capacity * sizeof(*names));
	catalog->names = names;
	catalog->name_capacity = capacity;
	catalog->name_used = 0;
	catalog->name_resolve = resolve;
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_name_set(fzn_catalog_t *catalog, const fzn_catalog_name_t *name)
{
	fzn_catalog_name_t *held;
	fzn_catalog_err_t err;

	if (!name_usable(catalog) || !name)
		return FZN_CATALOG_ERR_MALFORMED;
	if (catalog->refiling)
		return FZN_CATALOG_ERR_BUSY;

	err = usable_name(name->text, name->len);
	if (err != FZN_CATALOG_OK)
		return err;

	held = find_name(catalog, &name->id);
	if (held) {
		if (!catalog->name_resolve->prefer(catalog->name_resolve->ctx, held, name))
			return FZN_CATALOG_ERR_STALE;
		*held = *name;
		return FZN_CATALOG_OK;
	}
	if (catalog->name_used == catalog->name_capacity)
		return FZN_CATALOG_ERR_FULL;

	catalog->names[catalog->name_used] = *name;
	catalog->name_used++;
	return FZN_CATALOG_OK;
}

const fzn_catalog_name_t *fzn_catalog_name_of(const fzn_catalog_t *catalog,
                                              const fzn_catalog_id_t *id)
{
	if (!name_usable(catalog) || !id)
		return NULL;
	if (catalog->refiling)
		return NULL;
	return find_name(catalog, id);
}

fzn_catalog_err_t fzn_catalog_name_encode(const fzn_catalog_name_t *name, uint8_t *out,
                                          size_t cap, size_t *len_out)
{
	fzn_catalog_err_t err;
	size_t need;

	if (!name || !out || !len_out)
		return FZN_CATALOG_ERR_MALFORMED;
	err = usable_name(name->text, name->len);
	if (err != FZN_CATALOG_OK)
		return err;

	need = FZN_CATALOG_CONTENT_HEAD_LEN + name->len;
	if (cap < need)
		return FZN_CATALOG_ERR_MALFORMED;

	out[0] = (uint8_t)FZN_CATALOG_OBJECT_NAME;
	memcpy(out + 1, name->id.b, FZN_CATALOG_ID_LEN);
	out[FZN_CATALOG_CONTENT_HEAD_LEN - 1u] = (uint8_t)name->len;
	memcpy(out + FZN_CATALOG_CONTENT_HEAD_LEN, name->text, name->len);
	*len_out = need;
	return FZN_CATALOG_OK;
}

static fzn_catalog_err_t apply_name(fzn_catalog_t *catalog, const uint8_t *body, size_t len,
                                    const uint8_t *issuer, uint64_t seq)
{
	fzn_catalog_name_t name;

	if (len < FZN_CATALOG_CONTENT_HEAD_LEN)
		return FZN_CATALOG_ERR_SHAPE;

	memset(&name, 0, sizeof(name));
	memcpy(name.id.b, body + 1, FZN_CATALOG_ID_LEN);
	name.len = (size_t)body[FZN_CATALOG_CONTENT_HEAD_LEN - 1u];
	/* THE DECLARED LENGTH MUST BE THE BODY'S, exactly. A shorter body would
	 * read past what was signed and a longer one is a second encoding of
	 * the same name. */
	if (len != FZN_CATALOG_CONTENT_HEAD_LEN + name.len)
		return FZN_CATALOG_ERR_SHAPE;
	name.text = name.len > 0 ? body + FZN_CATALOG_CONTENT_HEAD_LEN : NULL;
	memcpy(name.issuer, issuer, FZN_PUBKEY_LEN);
	name.seq = seq;

	if (usable_name(name.text, name.len) != FZN_CATALOG_OK)
		return FZN_CATALOG_ERR_SHAPE;
	return fzn_catalog_name_set(catalog, &name);
}

fzn_catalog_err_t fzn_catalog_name_segment(const fzn_catalog_name_t *name, char *out,
                                           size_t cap)
{
	fzn_catalog_err_t err;

	if (!name || !out || cap == 0)
		return FZN_CATALOG_ERR_MALFORMED;
	err = usable_name(name->text, name->len);
	if (err != FZN_CATALOG_OK)
		return err;

	/* THE NAME, UNCHANGED. What a person wrote is what goes on the disk;
	 * `fzn_catalog_path_of` refuses only what would break a path, and a
	 * space is not one of those. sec 151. */
	if (name->len + 1u > cap)
		return FZN_CATALOG_ERR_PATH;
	memcpy(out, name->text, name->len);
	out[name->len] = '\0';
	return FZN_CATALOG_OK;
}

/* ---- retention ---------------------------------------------------------- */

static fzn_catalog_hold_t *find_hold(const fzn_catalog_t *catalog,
                                     const fzn_catalog_id_t *node)
{
	size_t i;

	for (i = 0; i < catalog->hold_used; i++) {
		if (same_id(&catalog->holds[i].id, node))
			return &catalog->holds[i];
	}
	return NULL;
}

static int hold_usable(const fzn_catalog_t *catalog)
{
	return catalog && catalog->holds && catalog->hold_capacity > 0
	       && catalog->hold_used <= catalog->hold_capacity;
}

const char *fzn_catalog_retention_str(fzn_catalog_retention_t mode)
{
	switch (mode) {
	case FZN_CATALOG_RETAIN_DEFAULT:
		return "as the catalogue says";
	case FZN_CATALOG_RETAIN_KEEP:
		return "kept here";
	case FZN_CATALOG_RETAIN_DROP:
		return "not kept here";
	}
	return "unknown";
}

fzn_catalog_err_t fzn_catalog_hold_init(fzn_catalog_t *catalog, fzn_catalog_hold_t *holds,
                                        size_t capacity)
{
	if (!catalog || !holds || capacity == 0)
		return FZN_CATALOG_ERR_MALFORMED;

	memset(holds, 0, capacity * sizeof(*holds));
	catalog->holds = holds;
	catalog->hold_capacity = capacity;
	catalog->hold_used = 0;
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_retain_all(fzn_catalog_t *catalog, int keep)
{
	if (!usable(catalog))
		return FZN_CATALOG_ERR_MALFORMED;
	if (catalog->refiling)
		return FZN_CATALOG_ERR_BUSY;

	catalog->retain_default = keep ? 1 : 0;
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_retain(fzn_catalog_t *catalog, const fzn_catalog_id_t *node,
                                     fzn_catalog_retention_t mode)
{
	fzn_catalog_hold_t *held;

	if (!hold_usable(catalog) || !node)
		return FZN_CATALOG_ERR_MALFORMED;
	if (catalog->refiling)
		return FZN_CATALOG_ERR_BUSY;
	if (mode != FZN_CATALOG_RETAIN_DEFAULT && mode != FZN_CATALOG_RETAIN_KEEP
	    && mode != FZN_CATALOG_RETAIN_DROP)
		return FZN_CATALOG_ERR_MALFORMED;

	held = find_hold(catalog, node);

	if (mode == FZN_CATALOG_RETAIN_DEFAULT) {
		/* DEFAULT GIVES THE ROW BACK rather than storing one. A table
		 * filling with nodes that say "whatever the catalogue says" is
		 * a table that runs out for the overrides that mean something. */
		if (!held)
			return FZN_CATALOG_OK;
		*held = catalog->holds[catalog->hold_used - 1u];
		catalog->hold_used--;
		return FZN_CATALOG_OK;
	}

	if (held) {
		held->mode = mode;
		return FZN_CATALOG_OK;
	}
	if (catalog->hold_used == catalog->hold_capacity)
		return FZN_CATALOG_ERR_FULL;

	catalog->holds[catalog->hold_used].id = *node;
	catalog->holds[catalog->hold_used].mode = mode;
	catalog->hold_used++;
	return FZN_CATALOG_OK;
}

fzn_catalog_retention_t fzn_catalog_retention_of(const fzn_catalog_t *catalog,
                                                 const fzn_catalog_id_t *node)
{
	const fzn_catalog_hold_t *held;

	if (!hold_usable(catalog) || !node)
		return FZN_CATALOG_RETAIN_DEFAULT;
	held = find_hold(catalog, node);
	return held ? held->mode : FZN_CATALOG_RETAIN_DEFAULT;
}

int fzn_catalog_keeps(const fzn_catalog_t *catalog, const fzn_catalog_id_t *node)
{
	fzn_catalog_retention_t mode;

	if (!catalog)
		return 0;
	/* A NODE'S OWN WORD BEATS THE CATALOGUE'S, in both directions: a host
	 * that keeps a library and drops four things says so, and one that
	 * keeps nothing and wants four says so the same way. A bit could only
	 * express one of those. */
	mode = fzn_catalog_retention_of(catalog, node);
	if (mode == FZN_CATALOG_RETAIN_KEEP)
		return 1;
	if (mode == FZN_CATALOG_RETAIN_DROP)
		return 0;
	return catalog->retain_default ? 1 : 0;
}

size_t fzn_catalog_hold_count(const fzn_catalog_t *catalog)
{
	return hold_usable(catalog) ? catalog->hold_used : 0;
}
