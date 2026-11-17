/*
 * The library in binary, on the local leg: fuzznet sec 1174, its messages
 * node/files_local.situ's -- every file this user's hosts describe, a row
 * each, what a media library lists each time it opens.
 *
 * A request is FZN_CMD_FILES (1) with `library`; the answer is a row per
 * file and then a STATUS ok, or a STATUS refusing it. The text listings it
 * replaces (`list catalog`, `list file`) stay beside it. Who may ask is the
 * caller's to judge: this node's own user, as `list catalog` allows.
 *
 * THE JOIN IS THE CLIENT'S, moved, rule for rule (local/rpc.c's
 * node_catalog_take and node_library_fill_many):
 *
 *  - only live claims count, as `list catalog` lists no other;
 *  - name, kind and duration each take the first live value, in the
 *    catalogue's order, that says anything -- an empty value, or a duration
 *    that is not a number, is passed over;
 *  - the holders are the distinct issuers of the file's live claims, by the
 *    first eight bytes of their key, as `get identity`'s HOST is compared;
 *  - held here is the bytes whole here, not this host's claim, and a file
 *    whole here that this host has not claimed counts it a holder;
 *  - size and arrival are the file's state here, arrival only while it is
 *    being fetched: held * 1000 / total, at least 1;
 *  - rows in the order a file first appears among the live claims.
 *
 * The file's state comes through a callback so the walk is tested without
 * a spool, and fuzznetd answers it from node/files.h.
 */
#ifndef FZN_NODE_LIBRARY_BINARY_H
#define FZN_NODE_LIBRARY_BINARY_H

#include <stddef.h>
#include <stdint.h>

#include "catalog.h"

#define FZN_NODE_LIBRARY_NAME_MAX 255u
#define FZN_NODE_LIBRARY_KIND_MAX 64u

/* The most bytes one answer message takes: a row at its widest. */
#define FZN_NODE_LIBRARY_BINARY_MAX 384u

typedef struct fzn_node_library_row {
	uint8_t root[32];
	uint64_t size;
	uint64_t duration_ms;
	uint16_t holders;
	uint8_t held_here;
	uint16_t arriving; /* per mille, 0 when not being fetched */
	uint8_t kind[FZN_NODE_LIBRARY_KIND_MAX];
	size_t kind_len;
	uint8_t name[FZN_NODE_LIBRARY_NAME_MAX];
	size_t name_len;
} fzn_node_library_row_t;

/* THE FILE `root` HERE: 1 with its length, whether it is whole, and while
 * it is not, how much has arrived per mille (at least 1); 0 when this host
 * neither holds it nor is fetching it. */
typedef int (*fzn_node_library_file_t)(void *ctx, const uint8_t root[32], uint64_t *length,
                                       int *whole, uint16_t *arriving);

typedef void (*fzn_node_library_each_t)(void *ctx, const fzn_node_library_row_t *row);

/* Every file's row, in order, to `each`. `host` is this host's key, at
 * least eight bytes; `file` may be NULL, for a host holding nothing. 1 when
 * the walk finished, 0 when memory ran out part way. */
int fzn_node_library_each(const fzn_node_catalog_t *cat, const uint8_t *host,
                          fzn_node_library_file_t file, void *file_ctx,
                          fzn_node_library_each_t each, void *each_ctx);

/* ONE FILE's row, as `fzn_node_library_each` gives it: 1 with `row`
 * filled, 0 when no live claim names `root`, -1 when memory ran out. */
int fzn_node_library_one(const fzn_node_catalog_t *cat, const uint8_t root[32], const uint8_t *host,
                         fzn_node_library_file_t file, void *file_ctx, fzn_node_library_row_t *row);

/* Each answer message, whole, for the caller to frame and write; nonzero
 * when it was written. */
typedef int (*fzn_node_library_put_t)(void *ctx, const uint8_t *msg, size_t len);

/* Answers MSG, a FZN_CMD_FILES `library` or `library_file` request,
 * through `put`: 1 once answered, every refusal included, and 0 when an
 * answer could not be written. */
int fzn_node_library_binary(const fzn_node_catalog_t *cat, const uint8_t *host,
                            fzn_node_library_file_t file, void *file_ctx, const uint8_t *msg,
                            size_t len, fzn_node_library_put_t put, void *put_ctx);

/* WHERE ONE FILE STANDS HERE, sec 1203, as `get file ROOT` says it:
 * catalogued or not, so a note's attachment is asked after too. */
typedef struct fzn_node_file_here {
	uint64_t held;   /* leaves here */
	uint64_t total;  /* leaves in all */
	uint64_t length; /* bytes */
	uint8_t state;   /* 0 asked for and nothing in, 1 part here, 2 whole */
	uint8_t to_everyone;
	uint32_t shares;
	uint8_t busy;
} fzn_node_file_here_t;

/* `root` here: 1 with `out` filled, 0 when this host neither holds it nor
 * is fetching it, -1 when it could not say. */
typedef int (*fzn_node_file_here_get_t)(void *ctx, const uint8_t root[32], fzn_node_file_here_t *out);

/* Answers MSG, a FZN_CMD_FILES `file` request, through `put`: a `file_row`
 * and a STATUS ok, a STATUS ok alone for a file not here, or a STATUS
 * refusing it. 1 once answered, 0 when an answer could not be written. */
int fzn_node_file_binary(fzn_node_file_here_get_t get, void *get_ctx, const uint8_t *msg, size_t len,
                         fzn_node_library_put_t put, void *put_ctx);

#endif /* FZN_NODE_LIBRARY_BINARY_H */
