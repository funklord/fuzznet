/* Which closed log segments to remove, and which entries of them: the
 * prune and keep rules. sec 460, the holder's retention of sec 456, and
 * the last of step 3; entries since sec 474.
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
 * ENTRIES, BY LEVEL AND SUBSYSTEM, since sec 474 -- the holder's "stay
 * granular" of 2026-10-03. A rule naming a level set or a subsystem SELECTS
 * ENTRIES; one naming neither is a SEGMENT rule, as before. Over entries:
 *
 *     age N    prune: written longer than N ago     keep: written within N
 *     size N   prune: past the newest N bytes of    keep: within them
 *                     the entries it selects
 *     count N  prune: past the newest N entries     keep: the newest N
 *                     it selects
 *
 * and the two kinds combine as one rule does: an entry goes when a segment
 * rule prunes its segment or an entry rule prunes it, and no keep rule of
 * either kind protects it. A segment every entry of which goes is removed;
 * one some of which go is REWRITTEN without them (`log/pack.h`'s repack,
 * which keeps the chain). With no entry rule a segment goes whole or not at
 * all, exactly as before. A machine and a user are the directory's already
 * (sec 458), and text is not a selector yet.
 *
 * THE CURRENT FILE IS NEVER A CANDIDATE: only closed segments, packed or
 * not, are planned over. Removing the oldest packed segments leaves the
 * chain verifiable from the oldest one kept, whose trailer names its prev.
 *
 * A RULE AS TEXT, one line, for configuration:
 *
 *     prune|keep PROGRAM|* [level=LETTERS] [subsystem=PATH] age|size|count N[unit]
 *
 * LETTERS from `CEWNIVDT` (`level=DT`, debug and trace); PATH a subsystem
 * and everything below it (`subsystem=notes` is `notes` and `notes/sync`).
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

/* Rules one plan or walk weighs: a command line's, a node's own and the
 * estate's (secs 475, 476). */
#define FZN_RETAIN_RULES_MAX 64u

typedef struct fzn_retain_rule {
	fzn_retain_kind_t kind;
	char program[FZN_ENTRY_WORD_MAX + 1u]; /* "*" for every program */
	/* ENTRY SELECTORS, sec 474: bit `1 << level` per level, 0 for none
	 * named; a subsystem path, "" for none. Neither named: a segment rule. */
	uint16_t levels;
	char subsystem[FZN_ENTRY_SUBSYSTEM_MAX + 1u];
	fzn_retain_limit_t limit;
	uint64_t value;
} fzn_retain_rule_t;

/* Whether `rule` selects entries rather than segments. */
int fzn_retain_rule_selects_entries(const fzn_retain_rule_t *rule);

/* One closed segment of one program. */
typedef struct fzn_retain_segment {
	uint64_t closed_us; /* when it was closed */
	uint64_t bytes;     /* its size on disk */
} fzn_retain_segment_t;

/* A rule from its line. */
fzn_retain_err_t fzn_retain_parse(const char *line, size_t len, fzn_retain_rule_t *out);

/* The longest line `fzn_retain_text` writes, its NUL included. */
#define FZN_RETAIN_TEXT_MAX 256u

/* A rule as its line, in one spelling: the selectors in the order the
 * syntax gives them, the levels in `CEWNIVDT` order, and the number in the
 * largest unit that divides it. Two lines naming one rule -- `30d` and
 * `720h` -- give one text, so a rule kept under its text is kept once
 * (sec 475). NUL-terminated; its length in `*len`. */
fzn_retain_err_t fzn_retain_text(const fzn_retain_rule_t *rule, char *out, size_t cap,
                                 size_t *len);

/* THE PLAN for `program`'s `n` segments at `now_us`: `remove[i]` set to 1
 * for each that goes, 0 for each that stays. The segments may come in any
 * order. Segment rules only: an entry rule is not weighed here. */
fzn_retain_err_t fzn_retain_plan(const char *program, const fzn_retain_segment_t *segments,
                                 size_t n, const fzn_retain_rule_t *rules, size_t n_rules,
                                 uint64_t now_us, uint8_t *remove);

/* What the segment rules say of each segment, for the entry walk:
 * FZN_RETAIN_MARK_PRUNED when one prunes it, FZN_RETAIN_MARK_KEPT when one
 * keeps it, both or neither. */
#define FZN_RETAIN_MARK_PRUNED 1u
#define FZN_RETAIN_MARK_KEPT 2u
fzn_retain_err_t fzn_retain_marks(const char *program, const fzn_retain_segment_t *segments,
                                  size_t n, const fzn_retain_rule_t *rules, size_t n_rules,
                                  uint64_t now_us, uint8_t *marks);

/* Whether any rule for `program` selects entries: without one, no segment
 * need be read. */
int fzn_retain_reads_entries(const char *program, const fzn_retain_rule_t *rules,
                             size_t n_rules);

/* THE ENTRY WALK: one program's entries, NEWEST FIRST across its segments
 * -- a segment's in reverse file order, the segments newest first -- each
 * judged by `fzn_retain_walk_entry`, which counts what each entry rule has
 * seen so a size or count limit falls where the newest N end. */
typedef struct fzn_retain_walk {
	const fzn_retain_rule_t *rules;
	size_t n_rules;
	uint64_t now_us;
	int applies[FZN_RETAIN_RULES_MAX];
	uint64_t seen[FZN_RETAIN_RULES_MAX];  /* entries the rule selected so far */
	uint64_t bytes[FZN_RETAIN_RULES_MAX]; /* and their bytes */
} fzn_retain_walk_t;

fzn_retain_err_t fzn_retain_walk_init(fzn_retain_walk_t *walk, const char *program,
                                      const fzn_retain_rule_t *rules, size_t n_rules,
                                      uint64_t now_us);

/* 1 when the entry written at `time_us` at `level` by `subsystem`, `bytes`
 * long as a line, in a segment the segment rules marked `mark`, goes. */
int fzn_retain_walk_entry(fzn_retain_walk_t *walk, uint8_t mark, uint64_t time_us,
                          fzn_entry_level_t level, const char *subsystem, uint64_t bytes);

#endif /* FZN_LOG_RETAIN_H */
