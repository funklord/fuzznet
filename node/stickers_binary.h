/*
 * The sticker packs this user keeps, asked in binary on the local leg:
 * fuzznet sec 1172, its messages node/stickers_local.situ's -- what the
 * sticker picker lists each time it opens.
 *
 * A request is FZN_CMD_STICKERS (22) with `packs`; the answer is a row per
 * pack -- root, length, held, estate, name -- and then a STATUS ok, or a
 * STATUS refusing it. The text verb (`list sticker`) stays beside it. Who
 * may ask is the caller's to judge: this node's own user, as the verb
 * allows.
 */
#ifndef FZN_NODE_STICKERS_BINARY_H
#define FZN_NODE_STICKERS_BINARY_H

#include <stddef.h>
#include <stdint.h>

#include "stickers.h"

/* The most bytes one answer message takes: a row at its widest, a
 * reference's (sec 1304) -- 512 bytes of it, its length and the head. */
#define FZN_NODE_STICKERS_BINARY_MAX 520u

/* Each answer message, whole, for the caller to frame and write; nonzero
 * when it was written. */
typedef int (*fzn_node_stickers_put_t)(void *ctx, const uint8_t *msg, size_t len);

/* Answers MSG, a FZN_CMD_STICKERS request, through `put`: 1 once answered,
 * every refusal included, and 0 when an answer could not be written. */
int fzn_node_stickers_binary(const fzn_node_stickers_t *st, const uint8_t *msg, size_t len,
                             fzn_node_stickers_put_t put, void *put_ctx);

#endif /* FZN_NODE_STICKERS_BINARY_H */
