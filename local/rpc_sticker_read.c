#include "rpc_sticker_read.h"

#include <stdlib.h>
#include <string.h>

#include "rpc_err.h"

/* Most packs hold fewer; a larger one costs one more read. */
#define FIRST_GUESS 64

void fzn_rpc_sticker_manifest_init(fzn_sticker_manifest_t *m, fzn_sticker_entry_t *entries, size_t cap) {
	memset(m, 0, sizeof(*m));
	m->entries = entries;
	m->cap = cap;
}

static int grow(fzn_sticker_manifest_t *m, size_t cap) {
	/* A failed allocation is room that could not be made, which is what
	 * FZN_RPC_ERR_BUFFER_TOO_SMALL says; there is no out-of-memory code. */
	fzn_sticker_entry_t *entries = calloc(cap, sizeof(*entries));
	if (!entries) return FZN_RPC_ERR_BUFFER_TOO_SMALL;
	free(m->entries);
	fzn_rpc_sticker_manifest_init(m, entries, cap);
	return FZN_RPC_OK;
}

/* Fuzznet's spec parser (its sticker/pack.c, sec 680): 1 when the spec read,
 * 0 when it did not -- with the line and why in `err`, or with more stickers
 * than the room, FZN_STICKER_TOO_SMALL, the count being how many it held. */
int fzn_rpc_sticker_spec_read(const char *text, size_t len, fzn_sticker_manifest_t *out, char *err,
                          size_t err_cap) {
	fzn_rpc_sticker_manifest_init(out, NULL, 0);
	int rc = grow(out, FIRST_GUESS);
	if (rc != FZN_RPC_OK) return rc;
	if (fzn_sticker_spec_parse(text, len, out, err, err_cap)) return FZN_RPC_OK;
	if (!FZN_STICKER_TOO_SMALL(out)) return FZN_RPC_ERR_MALFORMED;
	const size_t need = out->count;
	if ((rc = grow(out, need)) != FZN_RPC_OK) return rc;
	return fzn_sticker_spec_parse(text, len, out, err, err_cap) ? FZN_RPC_OK : FZN_RPC_ERR_MALFORMED;
}

void fzn_rpc_sticker_manifest_release(fzn_sticker_manifest_t *m) {
	free(m->entries);
	fzn_rpc_sticker_manifest_init(m, NULL, 0);
}
