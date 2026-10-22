/*
 * A SETTING DECLARED, sec 686: fzpd's registry (their `common/settings.h`,
 * read at their b4ed30b) as fuzznet's, so a client walks the declared keys
 * rather than hard-coding them, and a key keeps its name when its owner
 * moves from an extension into fuzznet (sec 672's point 5).
 *
 * AN ENTRY says what a cell's value is -- its type, its bounds, its default
 * as it would be written, its unit -- and where it may stand: an estate
 * cell, a host cell, or either. fzpd's three other axes (what a setting is
 * about, how far it travels, what may change it) are one thing here: every
 * node holds every cell (sec 540), and a rank is judged from the setter's
 * standing, never declared.
 *
 * A KEY ENDING IN `/` DECLARES A FAMILY: the key, then one word of a-z and
 * 0-9 -- a retention rule's hash, a sticker pack's root. A family's cells
 * are usually written by their own verb, and say so (FZN_SCHEMA_VERB).
 *
 * THE PARSERS ARE THE READERS' TOO. A value is checked when this node's own
 * user writes it (`set setting`) by the same call that reads it, so what is
 * refused is exactly what a reader would have ignored. A record another
 * host wrote is never refused for its value: a host whose declarations are
 * older or newer would otherwise diverge from the estate, and an
 * undeclared key is carried as stage 5 carries an unknown kind.
 */
#ifndef FZN_STATE_SCHEMA_H
#define FZN_STATE_SCHEMA_H

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_schema_type {
	/* `on` or `off`; `1` and `0` read alike, the spellings cells were
	 * written with before sec 686. */
	FZN_SCHEMA_FLAG = 1,
	/* Decimal digits, `min` to `max`. */
	FZN_SCHEMA_COUNT = 2,
	/* A count and one unit of d, h, m or s; `min` to `max` seconds. */
	FZN_SCHEMA_DURATION = 3,
	/* `HOST PORT`: a host of letters, digits and `.-:`, at most `max`
	 * bytes when `max` is set, and a port 1 to 65535. */
	FZN_SCHEMA_ADDRESS = 4,
	/* Printable text of `min` to `max` bytes, and `check`'s grammar when
	 * the entry has one. */
	FZN_SCHEMA_TEXT = 5
} fzn_schema_type_t;

/* Where a cell may stand. */
#define FZN_SCHEMA_ESTATE 1u
#define FZN_SCHEMA_HOST 2u

/* What a client shows. */
#define FZN_SCHEMA_RESTART 1u   /* read at start: a change waits for one */
#define FZN_SCHEMA_SENSITIVE 2u /* a value worth not showing over a shoulder */
#define FZN_SCHEMA_ADVANCED 4u  /* hidden until asked for */
#define FZN_SCHEMA_VERB 8u      /* written by its own verb, not `set setting` */

typedef struct fzn_schema_entry {
	const char *key;
	fzn_schema_type_t type;
	unsigned scopes;
	uint64_t min, max;
	const char *def;	/* as it would be written; "" for none */
	const char *unit;	/* shown, never parsed; "" for none */
	unsigned flags;
	const char *summary;
	/* TEXT's own grammar: NULL to accept, or why not. */
	const char *(*check)(const uint8_t *value, size_t len);
} fzn_schema_entry_t;

/* THE ENTRY `key` IS, in `table` of `n`: exact, or a family's instance. */
const fzn_schema_entry_t *fzn_schema_find(const fzn_schema_entry_t *table, size_t n,
                                          const uint8_t *key, size_t len);

/* WHETHER TWO DECLARATIONS CLAIM ONE CELL: the same key, or a family and
 * a key or family inside it. */
int fzn_schema_overlap(const char *a, const char *b);

/* `value` against `e`: NULL when it is one, or why not. */
const char *fzn_schema_check(const fzn_schema_entry_t *e, const uint8_t *value, size_t len);

/* The type's name as `list schema` says it. */
const char *fzn_schema_type_name(fzn_schema_type_t type);

/* THE PARSERS, readers' and writers' alike. */

/* 1 on, 0 off, -1 neither. */
int fzn_schema_flag(const uint8_t *value, size_t len);

/* 1 with `*out`, or 0: digits only, no more of them than `max` has, so
 * nothing overflows, and `min` to `max`. */
int fzn_schema_count(const uint8_t *value, size_t len, uint64_t min, uint64_t max, uint64_t *out);

/* 1 with `*seconds`, or 0: a count of the unit its last byte names, d, h,
 * m or s, `min` to `max` seconds. */
int fzn_schema_duration(const uint8_t *value, size_t len, uint64_t min, uint64_t max,
                        uint64_t *seconds);

/* 1 with the host (`host_cap` bytes, NUL ended) and the port, or 0. A
 * `host` of NULL still has its length bounded by a nonzero `host_cap`. */
int fzn_schema_address(const uint8_t *value, size_t len, char *host, size_t host_cap,
                       uint16_t *port);

#endif /* FZN_STATE_SCHEMA_H */
