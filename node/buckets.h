/*
 * WHAT A NODE HOLDS OF AN APPEND-ONLY KIND, by bucket: project.md sec 564.
 *
 * The estate's state reconciles by class (`node/holdings.h`), every object
 * listed. Message lines, logs and telemetry cannot be: they grow without a
 * bound, and the holder's "we follow retention rules for how much to
 * fetch" means each node holds its own share of them. So they are held in
 * BUCKETS -- a kind, a subject and a month -- compared one bucket at a time
 * and listed only where two nodes differ.
 *
 * AN ITEM is a signed artifact kept whole, as its writer signed it -- for a
 * message line, its one or two records -- and its ID is the hash of its
 * bytes. Whoever hands it on hands on the writer's word, never its own.
 *
 * A BUCKET'S DIGEST is the hash of its kind, subject, month, count, and its
 * ids' sum modulo 2^256. The sum is kept as items are taken, so a digest
 * costs one row and no listing, and it does not depend on the order items
 * were learned in. It decides only whether two nodes differ: what a peer
 * holds is fetched and checked item by item, so a peer that lies about a
 * digest costs a listing and nothing else.
 *
 * GONE: a bucket this node's own rules let go is marked so, its items
 * removed, and it is never taken again nor offered. A peer that still
 * holds it is no reason to hold it here.
 */
#ifndef FZN_NODE_BUCKETS_H
#define FZN_NODE_BUCKETS_H

#include <stddef.h>
#include <stdint.h>

#include "../persist/persist.h"
#include "../session/commitment.h"

#define FZN_BUCKETS_ID_LEN 32u
/* The largest item a row keeps: a two-part line's records with room. */
#define FZN_BUCKETS_ITEM_MAX 4096u
/* Ids per chunk row. */
#define FZN_BUCKETS_CHUNK 64u
/* The most buckets of one kind a node lists: past it the kind is FULL. */
#define FZN_BUCKETS_MAX 4096u

/* `node/buckets.situ`'s fzn_buckets_kind. Logs and telemetry join here. */
typedef enum fzn_buckets_kind {
	FZN_BUCKETS_MESSAGES = 0,
	FZN_BUCKETS_KINDS = 1
} fzn_buckets_kind_t;

typedef enum fzn_buckets_err {
	FZN_BUCKETS_OK = 0,
	FZN_BUCKETS_MALFORMED = -1,
	/* The store would not list, load or keep. */
	FZN_BUCKETS_BACKEND = -2,
	/* More buckets of the kind than FZN_BUCKETS_MAX. */
	FZN_BUCKETS_FULL = -3,
	/* The bucket was let go here. */
	FZN_BUCKETS_GONE = -4,
	/* No such item here. */
	FZN_BUCKETS_ABSENT = -5
} fzn_buckets_err_t;

const char *fzn_buckets_err_str(fzn_buckets_err_t err);

typedef struct fzn_buckets {
	const fzn_persist_ops_t *store;
	const fzn_hash_ops_t *hash;
} fzn_buckets_t;

/* One bucket as a node holds it. */
typedef struct fzn_bucket {
	uint8_t subject[FZN_PUBKEY_LEN];
	uint32_t month;
	uint64_t count;
	uint8_t digest[FZN_BUCKETS_ID_LEN];
} fzn_bucket_t;

/* An item's id: the hash of its bytes. */
int fzn_buckets_id(const fzn_hash_ops_t *hash, const uint8_t *item, size_t len,
                   uint8_t id[FZN_BUCKETS_ID_LEN]);

/* TAKE AN ITEM into (kind, subject, month). `*added` (may be NULL) is 1
 * when it was not held, 0 when it was. GONE for a bucket let go, nothing
 * kept. The caller has judged the item: this keeps bytes. */
fzn_buckets_err_t fzn_buckets_add(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                                  const uint8_t subject[FZN_PUBKEY_LEN], uint32_t month,
                                  const uint8_t *item, size_t len, int *added);

/* Whether the item `id` of `kind` is held, indexed. */
int fzn_buckets_has(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                    const uint8_t id[FZN_BUCKETS_ID_LEN]);

/* THE ITEM `id`, into `out` (room for `cap`), `*len` bytes, and its
 * bucket's subject and month (either may be NULL). ABSENT when not held. */
fzn_buckets_err_t fzn_buckets_item(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                                   const uint8_t id[FZN_BUCKETS_ID_LEN], uint8_t *out,
                                   size_t cap, size_t *len, uint8_t subject[FZN_PUBKEY_LEN],
                                   uint32_t *month);

/* THE BUCKET (kind, subject, month), its count 0 when nothing is held. */
fzn_buckets_err_t fzn_buckets_bucket(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                                     const uint8_t subject[FZN_PUBKEY_LEN], uint32_t month,
                                     fzn_bucket_t *out);

/* EVERY BUCKET OF `kind` held and not gone, ascending by subject and then
 * month, into `out` (room for `max`). FULL past `max`. */
fzn_buckets_err_t fzn_buckets_list(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                                   fzn_bucket_t *out, size_t max, size_t *count);

/* THE IDS of a bucket from position `from`, in the order they were taken,
 * at most `max` into `ids`; `*total` is how many the bucket holds. */
fzn_buckets_err_t fzn_buckets_ids(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                                  const uint8_t subject[FZN_PUBKEY_LEN], uint32_t month,
                                  uint64_t from, uint8_t (*ids)[FZN_BUCKETS_ID_LEN], size_t max,
                                  size_t *count, uint64_t *total);

/* LET A BUCKET GO: marked gone first, so a crash part way never has it
 * fetched again, then its items, ids and count removed. */
fzn_buckets_err_t fzn_buckets_drop(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                                   const uint8_t subject[FZN_PUBKEY_LEN], uint32_t month);

/* Whether (kind, subject, month) was let go here. */
int fzn_buckets_gone(const fzn_buckets_t *b, fzn_buckets_kind_t kind,
                     const uint8_t subject[FZN_PUBKEY_LEN], uint32_t month);

#endif /* FZN_NODE_BUCKETS_H */
