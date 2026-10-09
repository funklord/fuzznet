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
#include "buckets.h"
#include "holdings.h"

#define FZN_RECONCILE_VERSION 6u

typedef enum fzn_reconcile_type {
	FZN_RECONCILE_DIGEST_QUERY = 1,
	FZN_RECONCILE_DIGEST = 2,
	FZN_RECONCILE_IDS_QUERY = 3,
	FZN_RECONCILE_IDS = 4,
	FZN_RECONCILE_OBJECTS_QUERY = 5,
	FZN_RECONCILE_OBJECTS = 6,
	FZN_RECONCILE_BASE_QUERY = 7,
	FZN_RECONCILE_BASE = 8,
	/* Append-only kinds by bucket, sec 564. */
	FZN_RECONCILE_BUCKETS_QUERY = 9,
	FZN_RECONCILE_BUCKETS = 10,
	FZN_RECONCILE_BUCKET_IDS_QUERY = 11,
	FZN_RECONCILE_BUCKET_IDS = 12,
	FZN_RECONCILE_ITEM_QUERY = 13,
	FZN_RECONCILE_ITEM = 14,
	/* The same items pushed, sec 569. */
	FZN_RECONCILE_ITEM_PUT = 15,
	FZN_RECONCILE_ITEM_TOOK = 16
} fzn_reconcile_type_t;

/* What a receiver says of a pushed item: `node/reconcile.situ`'s
 * fzn_reconcile_took. */
typedef enum fzn_reconcile_took {
	FZN_RECONCILE_TOOK_MORE = 0,
	FZN_RECONCILE_TOOK_KEPT = 1,
	FZN_RECONCILE_TOOK_HELD = 2,
	FZN_RECONCILE_TOOK_REFUSED = 3,
	FZN_RECONCILE_TOOK_NOT_WANTED = 4
} fzn_reconcile_took_t;

/* The fixed parts, from `node/reconcile.situ.map`. */
#define FZN_RECONCILE_DIGEST_QUERY_LEN 2u
#define FZN_RECONCILE_DIGEST_HEAD_LEN 3u
#define FZN_RECONCILE_CLASS_LEN 37u
#define FZN_RECONCILE_IDS_QUERY_LEN 7u
#define FZN_RECONCILE_IDS_HEAD_LEN 13u
#define FZN_RECONCILE_OBJECTS_QUERY_HEAD_LEN 4u
#define FZN_RECONCILE_OBJECTS_HEAD_LEN 5u
#define FZN_RECONCILE_OBJECT_MAX 2048u
#define FZN_RECONCILE_BASE_QUERY_LEN 46u
#define FZN_RECONCILE_BASE_HEAD_LEN 52u
#define FZN_RECONCILE_BUCKETS_QUERY_LEN 7u
#define FZN_RECONCILE_BUCKETS_HEAD_LEN 13u
#define FZN_RECONCILE_BUCKET_LEN 76u
#define FZN_RECONCILE_BUCKET_IDS_QUERY_LEN 43u
#define FZN_RECONCILE_BUCKET_IDS_HEAD_LEN 49u
#define FZN_RECONCILE_ITEM_QUERY_LEN 39u
#define FZN_RECONCILE_ITEM_HEAD_LEN 45u
#define FZN_RECONCILE_ITEM_PUT_HEAD_LEN 81u
#define FZN_RECONCILE_ITEM_TOOK_LEN 40u
/* The most bytes one pushed piece carries: a request is put back together
 * up to 32 KiB (sec 447), and this leaves its head and envelope room. */
#define FZN_RECONCILE_PIECE_MAX 2048u
/* Pushes a receiver holds part of at once, one per sender and item; past
 * it the oldest is let go and resent from its start. */
#define FZN_RECONCILE_STAGED_MAX 8u
/* The most ids of one bucket a pusher compares with its own. */
#define FZN_RECONCILE_PEER_IDS_MAX 16384u
/* The longest bridge of spine entries a rebase takes. */
#define FZN_RECONCILE_BRIDGE_MAX 4096u

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
	FZN_RECONCILE_ERR_STORE = -4,
	/* A witness gave a different entry for a sequence of a bridge, sec
	 * 557: one of the two peers is not telling the stream as it was, and
	 * nothing moved. */
	FZN_RECONCILE_ERR_CONFLICT = -5
} fzn_reconcile_err_t;

const char *fzn_reconcile_err_str(fzn_reconcile_err_t err);

/* THE SERVER: answer one message from what `store` holds, and a stream's
 * base and spine from `journal` (NULL answers no BASE_QUERY). 0 when
 * `request` is not one of these messages, so a caller dispatching on the
 * first byte falls through. */
size_t fzn_reconcile_answer(const fzn_persist_ops_t *store, const fzn_hash_ops_t *hash,
                            fzn_node_journal_t *journal, const uint8_t *request,
                            size_t request_len, uint8_t *reply, size_t reply_cap);

/* WHICH BUCKETS ONE CALLER IS SERVED, sec 567: nonzero for a bucket of
 * `kind` about `subject` it may hold. A caller holding the retention
 * capability is served every bucket; one without it, only its own. */
typedef struct fzn_reconcile_gate {
	int (*serves)(void *ctx, fzn_buckets_kind_t kind, const uint8_t subject[FZN_PUBKEY_LEN]);
	void *ctx;
} fzn_reconcile_gate_t;

/* `fzn_reconcile_answer`, with the buckets of append-only kinds answered
 * through `gate` (NULL serves every one): a bucket the caller may not hold
 * is not listed, names no ids, and its items answer as not held -- the
 * same answers a node that holds none of it gives. */
size_t fzn_reconcile_answer_gated(const fzn_persist_ops_t *store, const fzn_hash_ops_t *hash,
                                  fzn_node_journal_t *journal, const fzn_reconcile_gate_t *gate,
                                  const uint8_t *request, size_t request_len, uint8_t *reply,
                                  size_t reply_cap);

/* WHERE AN APPEND-ONLY KIND'S ITEM GOES, declared below; a server taking
 * pushed items files them through it. */
struct fzn_reconcile_filer;

/* EVERYTHING ONE CALLER'S REQUEST IS ANSWERED FROM, sec 569: the store,
 * the journal (NULL answers no BASE_QUERY), the gate (NULL serves every
 * bucket), and for pushed items the kind's filer -- NULL takes none -- and
 * the sender, whose pieces are staged apart from any other's. */
typedef struct fzn_reconcile_server {
	const fzn_persist_ops_t *store;
	const fzn_hash_ops_t *hash;
	fzn_node_journal_t *journal;
	const fzn_reconcile_gate_t *gate;
	const struct fzn_reconcile_filer *taker;
	const uint8_t *sender;
} fzn_reconcile_server_t;

/* EVERY MESSAGE OF THE EXCHANGE, answered: the classes, the bases, the
 * buckets through the gate, and a pushed item staged, checked and filed
 * once whole. 0 for what is none of them. */
size_t fzn_reconcile_serve(const fzn_reconcile_server_t *srv, const uint8_t *request,
                           size_t request_len, uint8_t *reply, size_t reply_cap);

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

/* WHERE A NOTE CLAIM GOES, sec 555: one note record, filed by the notes
 * store's own path (`fzn_node_notes_file`), answered as an object applied
 * would be -- WAITING for a writer not admitted yet. */
typedef struct fzn_reconcile_notes {
	fzn_node_apply_outcome_t (*file)(void *ctx, const uint8_t *record, size_t len);
	void *ctx;
} fzn_reconcile_notes_t;

/* WHERE AN APPEND-ONLY KIND'S ITEM GOES, sec 564: one item of (subject,
 * month), judged and filed by its kind's own path -- a message line by its
 * writer's signature and the messages store (`fzn_node_messages_file`) --
 * answered as an object applied would be. WANTED (may be NULL) says
 * whether this node would hold a bucket, its retention rules asked (sec
 * 566); asked only of a bucket that differs from the peer's, and one not
 * wanted is neither listed nor fetched. */
typedef struct fzn_reconcile_filer {
	fzn_node_apply_outcome_t (*file)(void *ctx, const uint8_t subject[FZN_PUBKEY_LEN],
	                                 uint32_t month, const uint8_t *item, size_t len);
	int (*wanted)(void *ctx, const uint8_t subject[FZN_PUBKEY_LEN], uint32_t month);
	void *ctx;
} fzn_reconcile_filer_t;

typedef struct fzn_reconcile_bucket_tally {
	size_t buckets;  /* buckets whose digest differed */
	size_t sent;     /* items pushed whole and kept there (push) */
	size_t held;     /* items the peer said it held already (push) */
	size_t passed;   /* buckets gone here, or not wanted */
	size_t lacked;   /* items the peer holds and this node does not */
	size_t applied;  /* items fetched and filed */
	size_t waiting;  /* items filed whose key, or writer, is not here yet */
	size_t refused;  /* items judged and refused, or not their id */
	size_t full;     /* 1 when either side has too many buckets to list */
} fzn_reconcile_bucket_tally_t;

/* ONE KIND WITH ONE PEER: its buckets compared, and where one differs, its
 * ids paged and the items this node lacks fetched -- whole, in pieces of
 * whatever fits a reply -- each hashed to the id it was asked by and handed
 * to `filer`. Only adds, as a class round does. */
fzn_reconcile_err_t fzn_reconcile_buckets(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                                          const fzn_reconcile_filer_t *filer,
                                          fzn_reconcile_ask_t ask, void *ask_ctx,
                                          uint8_t *reply, size_t reply_cap,
                                          fzn_reconcile_bucket_tally_t *tally);

/* THE SAME KIND PUSHED, sec 569: for a peer that cannot reach this node.
 * The peer's buckets are listed once and each of this node's compared with
 * them; where the peer lacks a bucket or it differs, the peer's ids are
 * paged and each item it lacks is sent in pieces, resumed from what it
 * says it holds. `gate` (NULL for every bucket) is this node's view of
 * what the peer may be given -- the same gate a peer asking would meet.
 * The peer judges each item as one it fetched: tally's `sent` it kept,
 * `held` it had, `refused`, and `passed` its rules would not hold. */
/* WHAT A PUSHER IS TOLD OF EACH ITEM THE PEER KEPT, sec 569: what the
 * kind owes beside it -- for a line, its month's key, which the peer has
 * no stream of this node's to learn it from. */
typedef struct fzn_reconcile_sent {
	void (*kept)(void *ctx, const uint8_t subject[FZN_PUBKEY_LEN], uint32_t month,
	             const uint8_t *item, size_t len);
	void *ctx;
} fzn_reconcile_sent_t;

fzn_reconcile_err_t fzn_reconcile_push(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                                       const fzn_reconcile_gate_t *gate,
                                       const fzn_reconcile_sent_t *sent,
                                       fzn_reconcile_ask_t ask, void *ask_ctx, uint8_t *reply,
                                       size_t reply_cap, fzn_reconcile_bucket_tally_t *tally);

/* ONE ROUND WITH ONE PEER: every class, in the order of
 * `fzn_holdings_class_t` -- grants first, so a chain is here before what it
 * entitles, and note claims last -- compared and, where it differs, brought
 * up to the peer's. `notes` NULL passes the note claims over. `reply` is
 * the caller's, at least FZN_RECONCILE_REPLY_MIN. */
fzn_reconcile_err_t fzn_reconcile_round(fzn_node_apply_t *ap, const fzn_reconcile_notes_t *notes,
                                        fzn_reconcile_ask_t ask, void *ask_ctx, uint8_t *reply,
                                        size_t reply_cap, fzn_reconcile_tally_t *tally);

/* ANOTHER PEER TO ASK the same bridge of: how, and its context. */
typedef struct fzn_reconcile_witness {
	fzn_reconcile_ask_t ask;
	void *ctx;
} fzn_reconcile_witness_t;

/*
 * A STREAM THIS NODE IS BEHIND A PEER'S BASE ON, sec 552: the peer's base,
 * the id below it, and -- for the estate stream -- its spine from this
 * journal's received + 1 up to it, paged, handed to
 * `fzn_node_journal_rebase`, which checks the bridge at both ends. `*base`
 * (may be NULL) is where the stream now starts, or 0 when nothing moved:
 * the peer is not ahead of this journal's position, or nothing was cut.
 *
 * THE SUBJECTS BETWEEN THE ENDS ARE CHECKED AGAINST `witnesses`, sec 557:
 * each other peer is asked for the same sequences, from its spine or from
 * the records it still holds, and every entry it gives must be the same.
 * CONFLICT, and nothing moved, when one is not. `*confirmed` (may be NULL)
 * counts the witnesses that gave at least one entry and agreed: 0 means the
 * bridge stood on the peer's word alone. STORE when the journal refused
 * the bridge; SHAPE for a reply that is not a BASE of the stream asked
 * about.
 */
fzn_reconcile_err_t fzn_reconcile_rebase(fzn_node_journal_t *journal, fzn_reconcile_ask_t ask,
                                         void *ask_ctx, const fzn_reconcile_witness_t *witnesses,
                                         size_t n_witnesses, const uint8_t issuer[FZN_PUBKEY_LEN],
                                         uint32_t stream, uint8_t *reply, size_t reply_cap,
                                         uint64_t *base, size_t *confirmed);

#endif /* FZN_NODE_RECONCILE_H */
