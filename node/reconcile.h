/*
 * RECONCILIATION: one node bringing what it holds of the estate's state up
 * to what a peer holds. project.md sec 551; `node/reconcile.situ` is the
 * wire contract.
 *
 * Every round, with every pull peer -- the holder's "never merely a one-shot
 * process" (sec 550). A class whose digest agrees costs one message. One
 * that does not has its ids paged, and the objects this node lacks fetched
 * by id and applied by `fzn_node_apply_object`, which judges each exactly
 * as a journal record is judged. An object whose signer's chain is not here
 * yet is not kept, so it is lacked again and fetched again next round:
 * waiting is the steady state of an object that arrived early, not an
 * error.
 *
 * WHAT THIS CANNOT DO is take anything away. Reconciliation is a union of
 * signed objects, and what is superseded is decided by each class's own
 * rules where it is applied -- a newer setting over an older, a withdrawal
 * over its revocation. A peer holding less is never a reason to hold less.
 */
#ifndef FZN_NODE_RECONCILE_H
#define FZN_NODE_RECONCILE_H

#include <stddef.h>
#include <stdint.h>

#include "apply.h"
#include "holdings.h"

#define FZN_RECONCILE_VERSION 6u

typedef enum fzn_reconcile_type {
	FZN_RECONCILE_DIGEST_QUERY = 1,
	FZN_RECONCILE_DIGEST = 2,
	FZN_RECONCILE_IDS_QUERY = 3,
	FZN_RECONCILE_IDS = 4,
	FZN_RECONCILE_OBJECTS_QUERY = 5,
	FZN_RECONCILE_OBJECTS = 6
} fzn_reconcile_type_t;

/* The fixed parts, from `node/reconcile.situ.map`. */
#define FZN_RECONCILE_DIGEST_QUERY_LEN 2u
#define FZN_RECONCILE_DIGEST_HEAD_LEN 3u
#define FZN_RECONCILE_CLASS_LEN 37u
#define FZN_RECONCILE_IDS_QUERY_LEN 7u
#define FZN_RECONCILE_IDS_HEAD_LEN 13u
#define FZN_RECONCILE_OBJECTS_QUERY_HEAD_LEN 4u
#define FZN_RECONCILE_OBJECTS_HEAD_LEN 5u
#define FZN_RECONCILE_OBJECT_MAX 2048u

/* The most ids one OBJECTS_QUERY names. */
#define FZN_RECONCILE_ASK_MAX 32u

/* The smallest reply buffer either side may use: a DIGEST of every class,
 * or one whole object of the largest size. */
#define FZN_RECONCILE_REPLY_MIN (FZN_RECONCILE_OBJECTS_HEAD_LEN + 2u + FZN_RECONCILE_OBJECT_MAX)

typedef enum fzn_reconcile_err {
	FZN_RECONCILE_OK = 0,
	/* A null argument, or a reply buffer under FZN_RECONCILE_REPLY_MIN. */
	FZN_RECONCILE_ERR_MALFORMED = -1,
	/* The peer did not answer. */
	FZN_RECONCILE_ERR_NO_ANSWER = -2,
	/* The peer answered something that is not one of these messages. */
	FZN_RECONCILE_ERR_SHAPE = -3,
	/* This node's own store would not list or keep. */
	FZN_RECONCILE_ERR_STORE = -4
} fzn_reconcile_err_t;

const char *fzn_reconcile_err_str(fzn_reconcile_err_t err);

/* THE SERVER: answer one message from what `store` holds. 0 when `request`
 * is not one of these messages, so a caller dispatching on the first byte
 * falls through. */
size_t fzn_reconcile_answer(const fzn_persist_ops_t *store, const fzn_hash_ops_t *hash,
                            const uint8_t *request, size_t request_len, uint8_t *reply,
                            size_t reply_cap);

/* How a node reaches its peer: send `request`, fill `reply`, 1 for an
 * answer. The shape every pull here takes. */
typedef int (*fzn_reconcile_ask_t)(void *ctx, const uint8_t *request, size_t request_len,
                                   uint8_t *reply, size_t reply_cap, size_t *reply_len);

typedef struct fzn_reconcile_tally {
	size_t classes;  /* classes whose digest differed */
	size_t lacked;   /* ids the peer holds and this node does not */
	size_t applied;  /* objects fetched and applied */
	size_t waiting;  /* objects whose signer's chain is not here yet */
	size_t refused;  /* objects judged and refused, or not of their class */
	size_t full;     /* classes too large to list, here or there */
} fzn_reconcile_tally_t;

/* ONE ROUND WITH ONE PEER: every class, in the order of
 * `fzn_holdings_class_t` -- grants first, so a chain is here before what it
 * entitles -- compared and, where it differs, brought up to the peer's.
 * `reply` is the caller's, at least FZN_RECONCILE_REPLY_MIN. */
fzn_reconcile_err_t fzn_reconcile_round(fzn_node_apply_t *ap, fzn_reconcile_ask_t ask,
                                        void *ask_ctx, uint8_t *reply, size_t reply_cap,
                                        fzn_reconcile_tally_t *tally);

#endif /* FZN_NODE_RECONCILE_H */
