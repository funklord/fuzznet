#include "tree.h"

#include "../wire/bytes.h"

#include <string.h>

/* THE TABLE, PINNED AT COMPILE TIME, which `record/record.c` has had since it
 * was written and this module did not. `tree/test/tree_kat_test.c` catches a
 * moved field when it runs; these catch it when it builds, which is earlier
 * and cheaper, and the two are not redundant: an assertion cannot check the
 * BYTES a field produces and a vector cannot fail before a consumer has
 * compiled. Found missing on 2026-09-02 while writing record/'s vector --
 * permuting record/'s offsets would not compile, and permuting this module's
 * had built happily an hour earlier. */
_Static_assert(FZN_TREE_OFF_PARENT == 0u, "tree layout: parent moved");
_Static_assert(FZN_TREE_OFF_ORDER == 32u, "tree layout: order moved");
_Static_assert(FZN_TREE_OFF_CONTENT_TYPE == 40u, "tree layout: content_type moved");
_Static_assert(FZN_TREE_OFF_CONTENT == 42u, "tree layout: content moved");
_Static_assert(FZN_TREE_BODY_HEADER_LEN == 42u,
               "tree layout: the body header is not 42 bytes");
_Static_assert(FZN_TREE_CONTENT_MAX == 470u,
               "tree layout: content max is not 470 bytes");
_Static_assert(FZN_TREE_ID_LEN == 32u, "tree layout: a node id is not 32 bytes");

/* Constant-time is not a property this file needs: a node id is public, a
 * parent pointer is public, and sibling order is public. `memcmp` is
 * therefore the right comparison here, and saying so stops the next reader
 * assuming it was an oversight -- `constant_time/` exists for the places
 * where it is not. */

int fzn_tree_is_root(const uint8_t id[FZN_TREE_ID_LEN])
{
	size_t i;

	if (id == NULL)
		return 0;
	for (i = 0; i < (size_t)FZN_TREE_ID_LEN; i++) {
		if (id[i] != 0u)
			return 0;
	}
	return 1;
}

fzn_tree_err_t fzn_tree_open(fzn_record_t record, fzn_tree_node_t *out)
{
	const uint8_t *body;
	size_t body_len;

	if (out == NULL)
		return FZN_TREE_ERR_NULL;
	if (!fzn_record_is_open(record))
		return FZN_TREE_ERR_CLOSED;

	body_len = fzn_record_body_len(record);
	if (body_len < (size_t)FZN_TREE_BODY_HEADER_LEN)
		return FZN_TREE_ERR_SHORT_BODY;

	body = fzn_record_body(record);
	if (body == NULL)
		return FZN_TREE_ERR_NULL;

	out->id = fzn_record_subject(record);
	out->parent = body + FZN_TREE_OFF_PARENT;
	out->order = fzn_get_be64(body + FZN_TREE_OFF_ORDER);
	out->content_type = fzn_get_be16(body + FZN_TREE_OFF_CONTENT_TYPE);
	out->content_len = body_len - (size_t)FZN_TREE_BODY_HEADER_LEN;
	/* A zero-length content still points somewhere valid: one past the
	 * header, which is inside the body buffer whenever body_len equals
	 * the header length exactly. Never NULL, so a caller need not branch
	 * on emptiness before reading `content_len` bytes from it. */
	out->content = body + FZN_TREE_OFF_CONTENT;
	return FZN_TREE_OK;
}

fzn_tree_err_t fzn_tree_body(const uint8_t parent[FZN_TREE_ID_LEN],
                             uint64_t order,
                             uint16_t content_type,
                             const uint8_t *content, size_t content_len,
                             uint8_t *out, size_t out_cap, size_t *out_len)
{
	size_t need;

	if (parent == NULL || out == NULL || out_len == NULL)
		return FZN_TREE_ERR_NULL;
	if (content == NULL && content_len != 0u)
		return FZN_TREE_ERR_NULL;
	if (content_len > FZN_TREE_CONTENT_MAX)
		return FZN_TREE_ERR_CONTENT_LEN;

	need = (size_t)FZN_TREE_BODY_HEADER_LEN + content_len;
	if (out_cap < need)
		return FZN_TREE_ERR_CAPACITY;

	memcpy(out + FZN_TREE_OFF_PARENT, parent, (size_t)FZN_TREE_ID_LEN);
	fzn_put_be64(out + FZN_TREE_OFF_ORDER, order);
	fzn_put_be16(out + FZN_TREE_OFF_CONTENT_TYPE, content_type);
	if (content_len != 0u)
		memcpy(out + FZN_TREE_OFF_CONTENT, content, content_len);

	*out_len = need;
	return FZN_TREE_OK;
}

fzn_tree_err_t fzn_tree_order_between(uint64_t lo, uint64_t hi, uint64_t *out)
{
	if (out == NULL)
		return FZN_TREE_ERR_NULL;

	/* Refused rather than swapped, and it writes nothing: the `ERR_`
	 * spelling is a promise that no output was produced, which is
	 * `state/state.h`'s rule and the reason FZN_TREE_ORDER_EXHAUSTED
	 * below is not spelled that way. */
	if (lo > hi)
		return FZN_TREE_ERR_RANGE;

	/* lo + (hi - lo) / 2 rather than (lo + hi) / 2: the second overflows
	 * for neighbours in the top half of the range, which is exactly where
	 * a list that has been appended to for a long time lives. */
	*out = lo + (hi - lo) / 2u;

	/* Strictly between, or there was no room. The midpoint equals `lo`
	 * precisely when hi - lo is 0 or 1, so this is the whole exhaustion
	 * test and it needs no separate arithmetic. */
	if (*out == lo && hi - lo <= 1u)
		return FZN_TREE_ORDER_EXHAUSTED;
	return FZN_TREE_OK;
}

int fzn_tree_cmp(const fzn_tree_node_t *a, const fzn_tree_node_t *b)
{
	if (a->order < b->order)
		return -1;
	if (a->order > b->order)
		return 1;
	return memcmp(a->id, b->id, (size_t)FZN_TREE_ID_LEN);
}

fzn_tree_err_t fzn_tree_children(const fzn_tree_node_t *nodes, size_t count,
                                 const uint8_t parent[FZN_TREE_ID_LEN],
                                 const fzn_tree_node_t **out, size_t out_cap,
                                 fzn_tree_walk_t *walk)
{
	size_t i;

	if (parent == NULL || walk == NULL)
		return FZN_TREE_ERR_NULL;
	if (nodes == NULL && count != 0u)
		return FZN_TREE_ERR_NULL;
	if (out == NULL && out_cap != 0u)
		return FZN_TREE_ERR_NULL;

	walk->emitted = 0u;
	walk->examined = 0u;
	walk->truncated = 0;

	for (i = 0; i < count; i++) {
		size_t j;

		walk->examined++;
		if (memcmp(nodes[i].parent, parent,
		           (size_t)FZN_TREE_ID_LEN) != 0)
			continue;

		if (walk->emitted == out_cap) {
			/* THE OUTPUT IS FULL AND THE ANSWER IS NOW WRONG,
			 * not merely short: a later node may sort before one
			 * already written, so what is in the array is not the
			 * first `out_cap` children. `truncated` is the only
			 * honest thing to report and the caller must not read
			 * the array as a prefix of the ordered list. */
			walk->truncated = 1;
			continue;
		}

		/* Insertion sort into the output. The sibling counts this
		 * serves are small, and it needs no scratch beyond the array
		 * the caller already supplied -- sec 2. */
		for (j = walk->emitted; j > 0u; j--) {
			if (fzn_tree_cmp(out[j - 1u], &nodes[i]) <= 0)
				break;
			out[j] = out[j - 1u];
		}
		out[j] = &nodes[i];
		walk->emitted++;
	}

	return FZN_TREE_OK;
}

fzn_tree_err_t fzn_tree_reachable(const fzn_tree_node_t *nodes, size_t count,
                                  uint8_t *mark, size_t mark_cap,
                                  fzn_tree_walk_t *walk)
{
	size_t i;
	int changed;

	if (walk == NULL)
		return FZN_TREE_ERR_NULL;
	if (nodes == NULL && count != 0u)
		return FZN_TREE_ERR_NULL;
	if (mark == NULL && count != 0u)
		return FZN_TREE_ERR_NULL;
	if (mark_cap < count)
		return FZN_TREE_ERR_CAPACITY;

	walk->emitted = 0u;
	walk->examined = 0u;
	walk->truncated = 0;

	for (i = 0; i < count; i++)
		mark[i] = 0u;

	/* A FIXED POINT RATHER THAN A STACK, and that is the whole reason it
	 * is written this way. A depth-first walk needs somewhere to push,
	 * and sec 2 says nothing here allocates, so the choice is a caller's
	 * stack buffer -- a second capacity argument and a second truncation
	 * answer -- or this. Each pass marks at least one new node or is the
	 * last, so it runs at most depth+1 times and terminates on a cyclic
	 * set for a structural reason rather than a checked one: a node in a
	 * cycle is never reached from the root, so nothing ever marks it and
	 * no pass revisits it.
	 *
	 * The cost is O(count * depth) comparisons. Stated rather than
	 * measured-and-forgotten: for the sibling counts a notes tree has
	 * this is nothing, and if a consumer ever holds a deep tree of many
	 * thousands of nodes it is the number to come back to. */
	do {
		changed = 0;
		for (i = 0; i < count; i++) {
			size_t j;

			if (mark[i] != 0u)
				continue;
			walk->examined++;

			if (fzn_tree_is_root(nodes[i].parent)) {
				mark[i] = 1u;
				changed = 1;
				continue;
			}

			for (j = 0; j < count; j++) {
				if (mark[j] == 0u)
					continue;
				if (memcmp(nodes[j].id, nodes[i].parent,
				           (size_t)FZN_TREE_ID_LEN) == 0) {
					mark[i] = 1u;
					changed = 1;
					break;
				}
			}
		}
	} while (changed != 0);

	for (i = 0; i < count; i++) {
		if (mark[i] != 0u)
			walk->emitted++;
	}

	return FZN_TREE_OK;
}

const char *fzn_tree_err_str(fzn_tree_err_t err)
{
	switch (err) {
	case FZN_TREE_OK:
		return "ok";
	case FZN_TREE_ERR_SHORT_BODY:
		return "body too short to hold a node";
	case FZN_TREE_ERR_CONTENT_LEN:
		return "content longer than a record body";
	case FZN_TREE_ERR_NULL:
		return "null pointer";
	case FZN_TREE_ERR_CAPACITY:
		return "output buffer too small";
	case FZN_TREE_ERR_RANGE:
		return "order neighbours are the wrong way round";
	case FZN_TREE_ERR_CLOSED:
		return "record is not open";
	case FZN_TREE_ORDER_EXHAUSTED:
		return "no order key between these neighbours";
	}
	return "unknown";
}
