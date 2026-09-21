/* THE SIGNED SHARD INDEX: what travels so a host can find a key. C23/C26, and
 * project.md sec 341.
 *
 * C23 imports a register as SHARDS -- "an ordinary blob per key-range, with a
 * signed index mapping range to blob root, the index replicated to every host
 * while the shards are fetched on demand". shard.h plans where the cuts fall;
 * this is the wire form of the sentence above.
 *
 * "INDEX" HERE IS C23'S WORD FOR THIS OBJECT AND NOTHING ELSE. `wire/seal.h`
 * has an `index` field meaning which chunk of a frame, which is the ordinary
 * English word inside another module's prefix rather than a second concept
 * wearing this one's name. Said out loud because sec 339 is what a collision
 * costs once it is a type name.
 *
 * ---------------------------------------------------------------------------
 * THE INDEX IS ITSELF A BLOB, AND A MEASUREMENT DECIDED THAT.
 * ---------------------------------------------------------------------------
 *
 * An index entry is a 32-byte first key and a 32-byte blob root, so 64 bytes.
 * FZN_RECORD_BODY_MAX is 512, which leaves room for SEVEN entries in a record
 * after a head. A five-million-entry register at the default floor is about
 * 4883 shards -- roughly 700 records, each separately signed, to say one
 * thing.
 *
 * So the index does not go in records. It goes in an ordinary blob, exactly
 * as every shard does, and ONE record signs its root. That is one mechanism
 * rather than two: the fetch, the Merkle verification, the relay that serves
 * bytes it cannot read and the cache are all the paths a shard already uses,
 * and sec 315's "the direction is toward LESS wire, not more" is satisfied by
 * a 41-byte body rather than by seven hundred records.
 *
 * The signature is over the record, the record names the root, and the Merkle
 * tree carries the integrity of everything under it. A host that holds the
 * record can refuse a wrong index without holding the index.
 *
 * ---------------------------------------------------------------------------
 * WHAT THE RECORD CARRIES, AND WHAT IT DELIBERATELY DOES NOT.
 * ---------------------------------------------------------------------------
 *
 *     0   object   FZN_CATALOG_OBJECT_INDEX
 *     1   floor    u32, entries per shard -- C26's one number
 *     5   shards   u32, how many entries the index blob holds
 *     9   root     FZN_CATALOG_INDEX_ROOT_LEN bytes, the index blob's root
 *
 * Big-endian, the endianness `catalog/attribute.situ` declares, and the
 * canonical-encoding rules are the attribute codec's: a trailing byte is
 * refused rather than ignored, because the signature is over these bytes and
 * two spellings of one index would let a peer re-sign a different one.
 *
 * THE FLOOR TRAVELS BECAUSE IT IS THE PRIVACY CONTROL. C26 makes the shard
 * size the anonymity set, so a host deciding whether to reveal interest in a
 * range can read what it is getting from the replicated, signed part without
 * fetching anything. It is a FLOOR and says so: shard.h absorbs the remainder
 * into the last shard, which therefore holds between `floor` and `2 * floor -
 * 1` entries.
 *
 * AND THE PER-SHARD ENTRY COUNT DOES NOT TRAVEL, although `fzn_catalog_shard_t`
 * carries one. The blob is what says how many entries a shard has; an index
 * repeating it would be a second copy of the same fact, free to disagree with
 * the first and believed by whoever read it. Routing needs the first key and
 * the root, and C26's guarantee is the floor, which is in the head.
 *
 * NEITHER IS THE REGISTER NAMED. C26a keeps the register out of this library
 * -- "what this library carries is the mechanism ... and never which authority
 * is right about what" -- so which register an index is OF is the record's
 * subject, as an attribute's entity is, and not a field here.
 *
 * ---------------------------------------------------------------------------
 * THE INDEX BLOB'S OWN LAYOUT.
 * ---------------------------------------------------------------------------
 *
 *     entry[i]   first  FZN_CATALOG_SHARD_KEY_LEN bytes
 *                root   FZN_CATALOG_INDEX_ROOT_LEN bytes
 *
 * Ascending by `first`, exactly `shards` of them, nothing else. A range runs
 * from its own first key up to the next entry's, and the last runs to the end
 * of the key space -- shard.h's rule unchanged, so no end key is stored and
 * none can disagree with the next entry's start.
 */

#ifndef FZN_CATALOG_INDEX_H
#define FZN_CATALOG_INDEX_H

#include <stddef.h>
#include <stdint.h>

#include "catalog.h"
#include "shard.h"

/* The object tag. ATTRIBUTE is 1, PURGE is 2; this is the third and, like the
 * second, exists because what it carries is not an assertion about an entity. */
#define FZN_CATALOG_OBJECT_INDEX 3u

/* A blob root, by value. Its own type for the reason `fzn_catalog_host_t` and
 * `fzn_catalog_shard_key_t` have theirs: a fourth 32-byte thing that is not
 * any of the other three. */
#define FZN_CATALOG_INDEX_ROOT_LEN 32u

typedef struct fzn_catalog_blob_root {
	uint8_t b[FZN_CATALOG_INDEX_ROOT_LEN];
} fzn_catalog_blob_root_t;

/* object + floor + shards + root. */
#define FZN_CATALOG_INDEX_HEAD_LEN (1u + 4u + 4u + FZN_CATALOG_INDEX_ROOT_LEN)

/* One entry of the index blob: a first key and the root of the shard. */
#define FZN_CATALOG_INDEX_ENTRY_LEN \
	(FZN_CATALOG_SHARD_KEY_LEN + FZN_CATALOG_INDEX_ROOT_LEN)

/* The head, decoded. */
typedef struct fzn_catalog_index {
	size_t floor;   /* entries per shard; C26's number, and a floor. */
	size_t shards;  /* entries in the index blob. */
	fzn_catalog_blob_root_t root;
} fzn_catalog_index_t;

/*
 * Lay out the index record's body.
 *
 * FZN_CATALOG_ERR_MALFORMED for a null, a floor of zero or a shard count of
 * zero -- an index over no shards routes nothing, and an index whose floor is
 * zero makes C26's claim about an empty anonymity set. FZN_CATALOG_ERR_RANGE
 * when either number does not fit its field, or the body does not fit `cap`
 * or a record body. Writes nothing unless the whole body fits.
 */
fzn_catalog_err_t fzn_catalog_index_encode(const fzn_catalog_index_t *ix,
                                           uint8_t *out, size_t cap,
                                           size_t *len_out);

/*
 * Read an index record's body.
 *
 * Enforces the one canonical encoding: FZN_CATALOG_ERR_MALFORMED for a wrong
 * object tag, a truncated head, a zero floor or a zero shard count, and for a
 * TRAILING BYTE -- refused rather than ignored, for the reason the purge codec
 * gives. FZN_CATALOG_ERR_RANGE when the shard count is one whose index blob
 * could not be addressed on this host (see `fzn_catalog_index_body_len`).
 */
fzn_catalog_err_t fzn_catalog_index_decode(const uint8_t *body, size_t body_len,
                                           fzn_catalog_index_t *out);

/*
 * How long the index blob for `shards` entries is.
 *
 * FZN_CATALOG_ERR_RANGE when the product overflows `size_t`, which is not
 * theoretical on a 32-bit host: the count arrives over the wire, and a peer
 * naming 2^26 shards would otherwise wrap the length to something small and
 * plausible. The multiplication is guarded rather than the result checked,
 * because a wrapped result cannot be checked afterwards.
 */
fzn_catalog_err_t fzn_catalog_index_body_len(size_t shards, size_t *len_out);

/*
 * Lay out the index blob from a plan and the shards' roots.
 *
 * `plan` is what `fzn_catalog_shard_plan` produced and `roots[i]` is the root
 * of the blob holding shard `i`. Only the first key is taken from each shard;
 * the entry count is deliberately not carried (see the header).
 *
 * FZN_CATALOG_ERR_MALFORMED for a null, a zero count, or first keys not
 * ASCENDING -- the same refusal `fzn_catalog_shard_plan` makes and for the
 * same reason: ranges that overlap cannot say which blob holds a key, and the
 * failure is silent. FZN_CATALOG_ERR_RANGE when the body does not fit `cap`.
 */
fzn_catalog_err_t fzn_catalog_index_body_encode(const fzn_catalog_shard_t *plan,
                                                const fzn_catalog_blob_root_t *roots,
                                                size_t count, uint8_t *out,
                                                size_t cap, size_t *len_out);

/*
 * Is `body` a well-formed index blob: a whole number of entries, at least one,
 * and first keys strictly ascending?
 *
 * RUN THIS ONCE WHEN THE BLOB ARRIVES. `fzn_catalog_index_lookup` binary-
 * searches and therefore cannot notice that the thing it is searching is out
 * of order -- it would return a confident wrong shard. Stating the
 * precondition here rather than leaving it true-and-unwritten is deliberate:
 * from outside, an unstated precondition and an absent one look the same.
 *
 * Returns 1 when well formed, 0 otherwise. Pass `expect` as the head's shard
 * count to require that too, or 0 to accept any count.
 */
int fzn_catalog_index_body_ok(const uint8_t *body, size_t body_len, size_t expect);

/* Read entry `i` without copying the rest. Either output may be NULL.
 * FZN_CATALOG_ERR_RANGE when `i` is past the end or the body is not a whole
 * number of entries. */
fzn_catalog_err_t fzn_catalog_index_entry_at(const uint8_t *body, size_t body_len,
                                             size_t i,
                                             fzn_catalog_shard_key_t *first_out,
                                             fzn_catalog_blob_root_t *root_out);

/*
 * Which shard holds `key`, searched in the encoded index itself so a consumer
 * need not decode five thousand entries to route one key.
 *
 * A key before the first entry's start belongs to the first shard, because the
 * ranges together cover the whole key space -- `fzn_catalog_shard_of`'s rule,
 * unchanged. THE BODY MUST HAVE PASSED `fzn_catalog_index_body_ok`; see there.
 * FZN_CATALOG_ERR_MALFORMED for a null, FZN_CATALOG_ERR_ABSENT for an empty
 * body, FZN_CATALOG_ERR_RANGE when the body is not a whole number of entries.
 */
fzn_catalog_err_t fzn_catalog_index_lookup(const uint8_t *body, size_t body_len,
                                           const fzn_catalog_shard_key_t *key,
                                           size_t *index_out);

#endif /* FZN_CATALOG_INDEX_H */
