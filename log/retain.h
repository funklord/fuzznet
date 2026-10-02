/* Which closed log segments to remove: the prune and keep rules. sec 460,
 * the holder's retention of sec 456, and the last of step 3.
 *
 * TWO KINDS OF RULE, as the holder put it (sec 456): a PRUNE rule limits --
 * "prune older than 7 days" -- and a KEEP rule expands -- "keep 7 days". So
 * every matching prune rule applies, and a matching keep rule protects what
 * it covers from all of them:
 *
 *     a segment goes  <=>  some matching prune rule marks it
 *                          and no matching keep rule protects it
 *
 * Each rule has one limit, over a program's closed segments, newest first:
 *
 *     age N    prune: closed longer than N ago      keep: closed within N
 *     size N   prune: past the newest N bytes       keep: within the newest N bytes
 *     count N  prune: past the newest N segments    keep: the newest N segments
 *
 * A segment straddling a size limit is inside it: the newest N bytes keep
 * every segment that begins within them.
 *
 * WHOLE SEGMENTS, AND BY PROGRAM ONLY, in this version. Sec 428 has rules
 * select entries by estate, machine, user, subsystem, level or text. A
 * machine and a user are the directory's already (sec 458); the rest select
 * entries inside a segment, and removing some entries of a segment means
 * rewriting it -- and its packed form and its place in the chain. That is a
 * later version; a rule here names a program, or `*` for every one.
 *
 * THE CURRENT FILE IS NEVER A CANDIDATE: only closed segments, packed or
 * not, are planned over. Removing the oldest packed segments leaves the
 * chain verifiable from the oldest one kept, whose trailer names its prev.
 *
 * A RULE AS TEXT, one line, for configuration:
 *
 *     prune|keep PROGRAM|* age|size|count N[unit]
 *
 * age units s, m, h, d (bare is seconds); size units K, M, G (bare is
 * bytes, powers of 1024); count takes no unit.
 *
 * The plan is pure -- no clock, no files -- and the logger's backend does
 * the removing (`fzn_logger_retain`).
 */

#ifndef FZN_LOG_RETAIN_H
#define FZN_LOG_RETAIN_H

#include <stddef.h>
#include <stdint.h>

#include "entry.h"

typedef enum fzn_retain_err {
	FZN_RETAIN_OK = 0,
	FZN_RETAIN_ERR_MALFORMED = -1 /* a null, a rule that is not one */
} fzn_retain_err_t;

const char *fzn_retain_err_str(fzn_retain_err_t err);

typedef enum fzn_retain_kind {
	FZN_RETAIN_PRUNE = 1,
	FZN_RETAIN_KEEP = 2
} fzn_retain_kind_t;

typedef enum fzn_retain_limit {
	FZN_RETAIN_AGE = 1,   /* microseconds */
	FZN_RETAIN_SIZE = 2,  /* bytes */
	FZN_RETAIN_COUNT = 3  /* segments */
} fzn_retain_limit_t;

typedef struct fzn_retain_rule {
	fzn_retain_kind_t kind;
	char program[FZN_ENTRY_WORD_MAX + 1u]; /* "*" for every program */
	fzn_retain_limit_t limit;
	uint64_t value;
} fzn_retain_rule_t;

/* One closed segment of one program. */
typedef struct fzn_retain_segment {
	uint64_t closed_us; /* when it was closed */
	uint64_t bytes;     /* its size on disk */
} fzn_retain_segment_t;

/* A rule from its line. */
fzn_retain_err_t fzn_retain_parse(const char *line, size_t len, fzn_retain_rule_t *out);

/* THE PLAN for `program`'s `n` segments at `now_us`: `remove[i]` set to 1
 * for each that goes, 0 for each that stays. The segments may come in any
 * order. */
fzn_retain_err_t fzn_retain_plan(const char *program, const fzn_retain_segment_t *segments,
                                 size_t n, const fzn_retain_rule_t *rules, size_t n_rules,
                                 uint64_t now_us, uint8_t *remove);

#endif /* FZN_LOG_RETAIN_H */
