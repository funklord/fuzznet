/*
 * ERASURE-CODED PIECES AS BUCKET ITEMS: the pieces kind of `node/buckets.h`,
 * project.md sec 597, the third stage of the erasure coding planned in sec
 * 594. POSIX, built with FZN_LOG_PACK.
 *
 * AN ITEM is one piece's file whole, `chunk/piece.situ`: its head names the
 * item it is a piece of, so whoever keeps it keeps it as itself. Its
 * SUBJECT is the host that is to KEEP it -- not the host whose segment it is
 * -- and its MONTH the segment's. So a host wants exactly the buckets whose
 * subject it is, and a piece goes to the one host it was placed on rather
 * than to every host that holds the segment's month: pieces spread one to a
 * host, which is what makes them cheaper than replicas.
 *
 * PLACED by the host whose segment it is, once, when it cuts its fossil
 * (`node/pieces.h`): piece i to the i-th of the estate's hosts in rendezvous
 * order for the segment -- hosts ranked by the hash of the segment's id and
 * the host's key -- so each piece lands on a distinct host, and an estate
 * that gains or loses a host moves only the pieces placed on it.
 *
 * KEPT where `fzn_pieces_cut` keeps them, `IDHEX.INDEX.piece` in the pieces
 * directory, under the ref `p/IDHEX.INDEX`. A piece fetched or pushed is
 * kept only when it is for this host and its head is a piece's
 * (`fzn_pieces_keep`); whether it belongs to its item is the rebuild's to
 * find, by the item's id, and a wrong one is outvoted there.
 */
#ifndef FZN_NODE_PIECE_BUCKETS_H
#define FZN_NODE_PIECE_BUCKETS_H

#include <stddef.h>
#include <stdint.h>

#include "buckets.h"
#include "reconcile.h"

/* The most hosts one item's pieces are ranked over. */
#define FZN_PIECE_BUCKETS_HOSTS_MAX 64u

typedef struct fzn_piece_buckets {
	const fzn_buckets_t *b;
	/* The pieces directory: this host's archive's `pieces/`. */
	char dir[512];
	const fzn_hash_ops_t *hash;
	uint8_t self[32];
	/* A piece being fetched or pushed here, held whole until checked. */
	uint8_t *staging;
	size_t staging_cap, staged;
	uint64_t stage_total;
	uint8_t stage_id[FZN_BUCKETS_ID_LEN];
} fzn_piece_buckets_t;

/* Point `pb` at its store, its pieces directory and this host's key. All
 * borrowed but the directory's name, which is copied. 0 for a name that
 * does not fit. */
int fzn_piece_buckets_init(fzn_piece_buckets_t *pb, const fzn_buckets_t *b, const char *dir,
                           const fzn_hash_ops_t *hash, const uint8_t self[32]);

/* Let go of the staging memory. */
void fzn_piece_buckets_close(fzn_piece_buckets_t *pb);

/* THE RENDEZVOUS ORDER of `n` hosts for the item `id`: `order[0]` the index
 * of the host to keep piece 0, and so on -- descending by the hash of the
 * id and the host's key, a tie by the key. 0 on a hash failure. */
int fzn_piece_buckets_rank(const fzn_hash_ops_t *hash, const uint8_t id[FZN_BUCKETS_ID_LEN],
                           const uint8_t (*hosts)[32], size_t n, size_t *order);

/* PLACE the pieces of `id` already cut `k` + `m` into the pieces
 * directory: the placement recorded first, as `IDHEX.cut`
 * (`chunk/piece.situ`'s fzn_erasure_cut), then piece i taken into the
 * bucket (pieces, `keepers[i]`, `month`), each read and hashed for its id.
 * `*placed` counts those newly taken; 0 when a piece is missing, the
 * record would not be written, or the store refused. */
int fzn_piece_buckets_place(fzn_piece_buckets_t *pb, const uint8_t id[FZN_BUCKETS_ID_LEN],
                            uint32_t month, unsigned k, unsigned m,
                            const uint8_t (*keepers)[32], size_t *placed);

/* THE PLACEMENT OF `id`, sec 599, as this host recorded it when it cut
 * it: k, m and the keeper of each piece. 0 when it cut none of it, or the
 * record is not one. */
int fzn_piece_buckets_cut_of(const fzn_piece_buckets_t *pb, const uint8_t id[FZN_BUCKETS_ID_LEN],
                             unsigned *k, unsigned *m, uint8_t (*keepers)[32]);

/* PIECE `index` OF `id`'s own id, as it was placed, and its length into
 * `*size` (may be NULL): what a keeper is asked for. Read from the ref it
 * was taken under, which outlives letting it go. 0 when none was placed. */
int fzn_piece_buckets_piece_id(const fzn_piece_buckets_t *pb, const uint8_t id[FZN_BUCKETS_ID_LEN],
                               unsigned index, uint8_t piece_id[FZN_BUCKETS_ID_LEN],
                               uint64_t *size);

/* WHOSE ITEM the held piece `piece_id` is a piece of, from its head: the
 * host its pieces are served to besides their keepers. 0 when not held
 * here. */
int fzn_piece_buckets_host(const fzn_piece_buckets_t *pb,
                           const uint8_t piece_id[FZN_BUCKETS_ID_LEN], uint8_t host[32]);

/* LET GO OF PIECE `index` OF `id` here: its file removed and its item let
 * go, its id left in its bucket. For a piece its keeper holds. 0 on a store
 * that refused or a file that would not go. */
int fzn_piece_buckets_let_go(fzn_piece_buckets_t *pb, const uint8_t id[FZN_BUCKETS_ID_LEN],
                             unsigned index);

/* The filer the reconcile exchange takes, reads and serves this kind
 * through. */
void fzn_piece_buckets_filer(fzn_piece_buckets_t *pb, fzn_reconcile_filer_t *out);

#endif /* FZN_NODE_PIECE_BUCKETS_H */
