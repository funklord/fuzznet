/* SHARDING A REGISTER: where the key-range boundaries fall. C26, and
 * project.md sec 337.
 *
 * C23 imports a register as SHARDS -- an ordinary blob per key-range, with a
 * signed index mapping range to blob root, the index replicated to every host
 * while the shards are fetched on demand. C26 says the shard size is the
 * PRIVACY CONTROL and is one number, because a fetch reveals interest in a key
 * RANGE rather than an entry, which makes the estate the anonymity set as well
 * as the cache.
 *
 * THE NUMBER IS ENTRIES PER SHARD, settled by the copyright holder on
 * 2026-09-21, and it is the anonymity set directly: a fetch could have been
 * about any of `min_entries` entries. The alternatives measured something else
 * and let the privacy vary -- a fixed key-prefix gives 24 entries a shard on a
 * small register and 12000 on a large one, and a byte target makes the
 * anonymity set a function of how big a register's entries happen to be. Both
 * are proxies for the quantity C26 names.
 *
 * WHAT A KEY IS, THIS LIBRARY DOES NOT SAY. C26a keeps the register out of
 * here -- MusicBrainz, AcoustID, No-Intro, TMDB are a consumer's choice and
 * "what this library carries is the mechanism ... and never which authority is
 * right about what". A key here is 32 bytes and the importer decides what it
 * is a key OF.
 *
 * THIS PLANS BOUNDARIES AND NOTHING ELSE. It does not build the shards, sign
 * the index or fetch one; `catalog/index.h` is the wire form of the index and
 * `blob/` owns the bytes.
 *
 * This paragraph used to restate what the encoding was waiting on, and went
 * stale three times in two days as the answers landed -- once within an hour
 * of being corrected. It names the module now and nothing else: a dependency
 * list belongs in the one place that tracks it, which is catalog.h's
 * section 7, and a second copy is a second thing to be wrong.
 */

#ifndef FZN_CATALOG_SHARD_H
#define FZN_CATALOG_SHARD_H

#include <stddef.h>
#include <stdint.h>

#include "catalog.h"

/* A register key, by value. Its own type for the reason `fzn_catalog_host_t`
 * has one, and distinct from both for the reason they are distinct from each
 * other: three things that are 32 bytes and are not the same thing. */
#define FZN_CATALOG_SHARD_KEY_LEN 32u

typedef struct fzn_catalog_shard_key {
	uint8_t b[FZN_CATALOG_SHARD_KEY_LEN];
} fzn_catalog_shard_key_t;

/* THE PRIVACY CONTROL, and the one number C26 says it is. A fetch could have
 * been about any of these entries.
 *
 * 1024 rather than a round 1000 because the arithmetic below is in powers of
 * two and nothing is gained by the decimal. For scale, at a typical ~250-byte
 * signed entry this makes a shard about 256KB and, over a five-million-entry
 * register, an index of about 195KB -- and the index is smallest exactly where
 * the register is largest, which is the right way round. */
#define FZN_CATALOG_SHARD_ENTRIES_MIN 1024u

/* One shard: where it starts, and how many entries it holds. The range runs
 * from `first` up to the next shard's `first`, and the last runs to the end of
 * the key space -- so a consumer needs no end key and cannot record one that
 * disagrees with the next shard's start. */
typedef struct fzn_catalog_shard {
	fzn_catalog_shard_key_t first;
	size_t entries;
} fzn_catalog_shard_t;

/*
 * Cut `keys` into shards of at least `min_entries` each.
 *
 * `keys` must be SORTED ASCENDING and is refused otherwise, because a shard is
 * a key RANGE: cutting an unsorted list produces ranges that overlap, and an
 * index mapping overlapping ranges to blobs cannot say which blob holds a key.
 * Checked rather than assumed -- it is one pass over data already in hand, and
 * the failure it prevents is silent.
 *
 * THE REMAINDER GOES INTO THE LAST SHARD, which is the whole reason this is a
 * function rather than a division. A count that does not divide evenly leaves
 * a tail, and giving that tail its own shard makes the LAST range smaller than
 * every other -- so the end of the key space has a weaker anonymity set than
 * the rest, and a fetch landing there reveals more. The tail is absorbed
 * instead, making the last shard between `min_entries` and `2 * min_entries -
 * 1` entries.
 *
 * A REGISTER SMALLER THAN ONE SHARD IS ONE SHARD, not a shard of fewer
 * entries: the whole register is then the anonymity set, which is the best
 * available and is what a fetch already reveals.
 *
 * FZN_CATALOG_ERR_MALFORMED for a null, for `min_entries` of zero, or for keys
 * out of order. FZN_CATALOG_ERR_RANGE when more shards result than `out_cap`
 * holds -- loudly, because a truncated plan silently drops the tail of the key
 * space and a consumer would build an index that answers for part of it.
 */
fzn_catalog_err_t fzn_catalog_shard_plan(const fzn_catalog_shard_key_t *keys,
                                         size_t count, size_t min_entries,
                                         fzn_catalog_shard_t *out, size_t out_cap,
                                         size_t *out_count);

/* Which shard holds `key`, or FZN_CATALOG_ERR_ABSENT when the plan is empty.
 * The plan must be one `fzn_catalog_shard_plan` produced; a key before the
 * first shard's start belongs to the first shard, because the ranges together
 * cover the whole key space. */
fzn_catalog_err_t fzn_catalog_shard_of(const fzn_catalog_shard_t *plan, size_t count,
                                       const fzn_catalog_shard_key_t *key,
                                       size_t *index_out);

#endif /* FZN_CATALOG_SHARD_H */
