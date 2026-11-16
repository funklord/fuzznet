/* The library in binary: library_binary.h, sec 1174. */
#include "library_binary.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../wire/cmd.h"
#include "../wire/generated/files_local.h"
#include "../wire/generated/files_local_build.h"
#include "../wire/status.h"

/* A label's name, as `add catalog` writes it. */
static int named(const fzn_catalog_assertion_t *a, const char *name, size_t name_len)
{
	return a->name_len == name_len && memcmp(a->name, name, name_len) == 0;
}

/* A duration in milliseconds, as decimal digits and nothing else. */
static int decimal(const uint8_t *p, size_t len, uint64_t *out)
{
	uint64_t v = 0;
	size_t i;

	if (!len || len > 20u)
		return 0;
	for (i = 0; i < len; i++) {
		uint64_t d;

		if (p[i] < '0' || p[i] > '9')
			return 0;
		d = (uint64_t)(p[i] - '0');
		if (v > (UINT64_MAX - d) / 10u)
			return 0;
		v = v * 10u + d;
	}
	*out = v;
	return 1;
}

/* ONE FILE'S ROW from its claims, `set` the `n` of them in the order taken. */
static void row_of(const fzn_catalog_assertion_t *set, size_t n, const uint8_t root[32],
                   const uint8_t *host, fzn_node_library_file_t file, void *file_ctx,
                   fzn_node_library_row_t *r)
{
	size_t holders = 0, k, j;
	int claimed = 0, whole = 0;
	uint64_t length = 0;
	uint16_t arriving = 0;

	memset(r, 0, sizeof(*r));
	memcpy(r->root, root, 32u);
	for (k = 0; k < n; k++) {
		const fzn_catalog_assertion_t *a = &set[k];
		int seen = 0;

		if (!a->live)
			continue;
		if (named(a, "name", 4u) && !r->name_len && a->value_len) {
			r->name_len = a->value_len < sizeof(r->name) ? a->value_len : sizeof(r->name);
			memcpy(r->name, a->value, r->name_len);
		} else if (named(a, "kind", 4u) && !r->kind_len && a->value_len) {
			r->kind_len = a->value_len < sizeof(r->kind) ? a->value_len : sizeof(r->kind);
			memcpy(r->kind, a->value, r->kind_len);
		} else if (named(a, "duration", 8u) && !r->duration_ms) {
			uint64_t ms = 0;

			if (decimal(a->value, a->value_len, &ms))
				r->duration_ms = ms;
		}
		/* A HOLDER IS AN ISSUER, by its first eight bytes, counted once. */
		if (a->issuer_len < 8u)
			continue;
		for (j = 0; j < k && !seen; j++)
			seen = set[j].live && set[j].issuer_len >= 8u
			       && memcmp(set[j].issuer, a->issuer, 8u) == 0;
		if (!seen)
			holders++;
		if (memcmp(a->issuer, host, 8u) == 0)
			claimed = 1;
	}
	r->holders = (uint16_t)(holders > 0xffffu ? 0xffffu : holders);
	if (!file || !file(file_ctx, root, &length, &whole, &arriving))
		return;
	r->size = length;
	/* HELD HERE IS THE BYTES, NOT THE CLAIM (local/rpc.c's one-file path
	 * says why): whole here and unclaimed, this host is a holder too. */
	if (whole) {
		r->held_here = 1;
		if (!claimed && r->holders < 0xffffu)
			r->holders++;
	} else {
		r->arriving = arriving ? arriving : 1u;
	}
}

int fzn_node_library_each(const fzn_node_catalog_t *cat, const uint8_t *host,
                          fzn_node_library_file_t file, void *file_ctx,
                          fzn_node_library_each_t each, void *each_ctx)
{
	fzn_catalog_assertion_t *set = NULL;
	size_t cap = 0, i;
	int ok = 1;

	if (!cat || !host || !each)
		return 0;
	for (i = 0; i < cat->count && ok; i++) {
		const fzn_node_catalog_entry_t *e = &cat->entries[i];
		fzn_node_library_row_t row;
		size_t j, n;
		int earlier = 0;

		if (!e->live)
			continue;
		/* THE FILE'S FIRST LIVE CLAIM opens its row: any earlier one live,
		 * and the row was given there. */
		for (j = e->same_entity; j != SIZE_MAX && j < i && !earlier; j = cat->entries[j].same_entity)
			earlier = cat->entries[j].live;
		if (earlier)
			continue;
		n = fzn_node_catalog_count_of(cat, e->entity);
		if (n > cap) {
			fzn_catalog_assertion_t *more = realloc(set, n * sizeof(*set));

			if (!more) {
				ok = 0;
				break;
			}
			set = more;
			cap = n;
		}
		n = fzn_node_catalog_assertions(cat, e->entity, set, n);
		row_of(set, n, e->entity, host, file, file_ctx, &row);
		each(each_ctx, &row);
	}
	free(set);
	return ok;
}

static int status(fzn_node_library_put_t put, void *ctx, fzn_status_t code, const char *why)
{
	uint8_t out[FZN_STATUS_LEN_MAX];
	size_t n = fzn_status_write(out, sizeof(out), code, why);

	return n && put(ctx, out, n);
}

struct rows {
	fzn_node_library_put_t put;
	void *ctx;
	int ok;
};

static void row_one(void *ctx, const fzn_node_library_row_t *r)
{
	struct rows *w = ctx;
	uint8_t row[FZN_NODE_LIBRARY_BINARY_MAX], out[FZN_NODE_LIBRARY_BINARY_MAX + 8u];
	uint32_t row_len = 0, n = 0;

	if (!w->ok)
		return;
	w->ok = fzn_files_local_library_row_build(row, sizeof(row), r->root, r->size, r->duration_ms,
	                                          r->holders, r->held_here, r->arriving, r->kind,
	                                          (uint32_t)r->kind_len, r->name, (uint32_t)r->name_len,
	                                          &row_len)
	                == SITU_OK
	        && fzn_files_local_message_build_library_row(out, sizeof(out), (uint8_t)FZN_CMD_FILES, row,
	                                                     row_len, &n)
	                   == SITU_OK
	        && w->put(w->ctx, out, n);
}

int fzn_node_library_binary(const fzn_node_catalog_t *cat, const uint8_t *host,
                            fzn_node_library_file_t file, void *file_ctx, const uint8_t *msg,
                            size_t len, fzn_node_library_put_t put, void *put_ctx)
{
	situ_msg_t m;
	situ_view_t v;
	struct rows w = { put, put_ctx, 1 };

	if (!put)
		return 0;
	if (!cat || !host || !msg || len > UINT32_MAX)
		return status(put, put_ctx, FZN_STATUS_ERROR, "no library here");
	situ_msg_init(&m, (uint8_t *)(uintptr_t)msg, (uint32_t)len);
	if (fzn_files_local_message_view(&m, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_files_local_message_validate(v) != SITU_OK
	    || fzn_files_local_message_op_get(v) != FZN_FILES_LOCAL_OP_LIBRARY)
		return status(put, put_ctx, FZN_STATUS_MALFORMED, "not a library request");
	/* A ROW EACH, then a STATUS ok: an ended list told from a cut one. */
	if (!fzn_node_library_each(cat, host, file, file_ctx, row_one, &w))
		return w.ok && status(put, put_ctx, FZN_STATUS_ERROR, "the library did not list");
	return w.ok && status(put, put_ctx, FZN_STATUS_OK, NULL);
}
