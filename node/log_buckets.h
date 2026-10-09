/*
 * A HOST'S PACKED LOG SEGMENTS AS BUCKET ITEMS: the logs kind of
 * `node/buckets.h`, project.md sec 571. POSIX, built with FZN_LOG_PACK.
 *
 * AN ITEM is one packed segment whole, its name in front so whoever keeps
 * it keeps it as itself: [name length][name][the .zst file's bytes]. Its
 * SUBJECT is the host whose log it is, and its MONTH the UTC month of the
 * segment's closing time, read from its name. A segment is at most 64 MiB,
 * as a log copy is (sec 483), so it is one of the layer's large items: the
 * row names the file, and this module reads, stages and keeps the bytes.
 *
 * THIS HOST'S OWN SEGMENTS are taken by a scan of its log directory, `o/`
 * and the name being their ref; a file is hashed only when its ref is new
 * or its length moved. ANOTHER HOST'S are kept as copies, where sec 483
 * keeps them -- `copy/HOSTHEX/` under the log directory -- and their ref is
 * `c/HOSTHEX/NAME`. One of this host's own coming back from a peer is kept
 * there too, under its own key, and never written into the live log.
 *
 * A SEGMENT IS KEPT ONLY SIGNED BY ITS SUBJECT, the host whose log it is,
 * as a pulled copy always was: it is written beside the copies, checked --
 * it decompresses, its trailer verifies from the prev it names, and its
 * signature holds and is the subject's -- and only then renamed into place
 * and taken into its bucket. Its chain to the segment before is not asked:
 * a month arrives in any order, so whether a copy's chain is whole is
 * `fzn_log_pack_check`'s to report, not a gate on taking it.
 *
 * WANTED, before a segment is fetched, by the rules that reach this node:
 * the copy rules and the log policy for another host's, its own rules for
 * this host's. A bucket is not one program's, so only what does not
 * depend on the program is asked -- a policy, an age prune naming every
 * program, and an age keep of any program, which protects. A count or size
 * rule is not weighed: it needs the segments newer than this one, and a
 * month refused that the trim would keep is lost, where one fetched and
 * then trimmed costs a fetch.
 */
#ifndef FZN_NODE_LOG_BUCKETS_H
#define FZN_NODE_LOG_BUCKETS_H

#include <stddef.h>
#include <stdint.h>

#include "buckets.h"
#include "reconcile.h"
#include "../log/retain.h"

/* The longest segment name an item carries. */
#define FZN_LOG_BUCKETS_NAME_MAX 200u

typedef struct fzn_log_buckets {
	const fzn_buckets_t *b;
	/* The log directory: this host's segments, and `copy/` below it. */
	char dir[512];
	const fzn_hash_ops_t *hash;
	const fzn_sign_ops_t *sign;
	uint8_t self[32];
	/* THE RULES A FETCH ASKS, the caller's to gather: this host's own log
	 * rules, and the copy rules -- each with the log policies that reach
	 * here -- and the time. */
	const fzn_retain_rule_t *own_rules;
	size_t n_own;
	const fzn_retain_rule_t *copy_rules;
	size_t n_copy;
	uint64_t now_us;
	/* A segment being fetched or pushed here, held whole until checked. */
	uint8_t *staging;
	size_t staging_cap, staged;
	uint64_t stage_total;
	uint8_t stage_id[FZN_BUCKETS_ID_LEN];
} fzn_log_buckets_t;

/* Point `lb` at its store, its log directory and this host's key. All
 * borrowed but the directory's name, which is copied. 0 for a name that
 * does not fit. */
int fzn_log_buckets_init(fzn_log_buckets_t *lb, const fzn_buckets_t *b, const char *dir,
                         const fzn_hash_ops_t *hash, const fzn_sign_ops_t *sign,
                         const uint8_t self[32]);

/* Let go of the staging memory. */
void fzn_log_buckets_close(fzn_log_buckets_t *lb);

/* THIS HOST'S PACKED SEGMENTS, taken into its buckets: each new one, or
 * one whose length moved, read, hashed and taken. `*taken` how many; 0 when
 * the directory would not read or a store refused. */
int fzn_log_buckets_scan(fzn_log_buckets_t *lb, size_t *taken);

/* The filer the reconcile exchange takes, reads and serves this kind
 * through. */
void fzn_log_buckets_filer(fzn_log_buckets_t *lb, fzn_reconcile_filer_t *out);

#endif /* FZN_NODE_LOG_BUCKETS_H */
