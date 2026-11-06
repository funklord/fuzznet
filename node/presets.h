/*
 * A PROFILE, project.md sec 908: a named preset of what a kind of host starts
 * with, and which of those values its user may change. The holder's: applied at
 * the start, and again during an update, and the consumer's to change after. So
 * it is values and nothing running: what it sets are the host's own settings.
 *
 * EACH VALUE SAYS WHO MAY CHANGE IT, the lowest rank `set setting` takes for it on
 * this host (`state/setting.h`):
 *
 *   HOST    its user, by any local client.
 *   ADMIN   a host holding an admin's standing.
 *   ROOT    a root.
 *   NOBODY  none: it is the profile's, written whenever the profile is applied.
 *   VOTE    k admins of the estate, counted by this host, or a root alone, as a
 *           revocation takes (`node/votes.h`). Never `set setting` below a root.
 *
 * All but NOBODY are configurable, and written only where the cell has no value,
 * so a value somebody chose outlives an update. A key the profile does not name is
 * the user's, as it always was.
 *
 * ON AN UPDATE the preset is applied, then the consumer's own values over it, so
 * the consumer's stand. `preset/applied` says what was last applied, and a change
 * of the name or either revision is what applies it again.
 *
 * WHAT IT BINDS: `set setting` and `remove setting` on this host's own cell, by this
 * host's rank. A write from another host's admin is judged there, by that host,
 * which holds no profile of this one's, so it is not bound.
 *
 * A PRESET NAMES ITS BUILD, sec 908: what `make PRESET=NAME` compiled in. A daemon
 * refuses a preset of another build. Presets of one build differ only in values,
 * so those marked `user` can be switched between with no rebuild: `set preset NAME`
 * by this host's user, kept in `preset/chosen`. A client's preset is written to its
 * own configuration file (`local/client_config.h`), having no store.
 *
 * THE VERBS:
 *
 *     set preset NAME     a user preset of this build, chosen and applied
 *     get preset     ok NAME, or ok none
 *     list preset    ok N, then each value as KEY,host|admin|root|nobody|vote,VALUE
 */

#ifndef FZN_NODE_PRESETS_H
#define FZN_NODE_PRESETS_H

#include <stddef.h>
#include <stdint.h>

/* The first three are `fzn_setting_rank_t`'s. */
#define FZN_PRESET_HOST 0
#define FZN_PRESET_ADMIN 1
#define FZN_PRESET_ROOT 2
#define FZN_PRESET_NOBODY 3
#define FZN_PRESET_VOTE 4
#define FZN_PRESET_APPLIED_KEY "preset/applied"
#define FZN_PRESET_CHOSEN_KEY "preset/chosen"

/* WHAT THIS BINARY WAS BUILT AS: `full`, `small` or `client`. */
#ifndef FZN_PRESET_BUILD
#define FZN_PRESET_BUILD "full"
#endif

typedef struct fzn_preset_value {
	const char *key;
	const char *value;
	int who; /* FZN_PRESET_HOST .. FZN_PRESET_VOTE */
} fzn_preset_value_t;

typedef struct fzn_preset {
	const char *name;
	uint32_t revision;
	const char *build; /* the build it needs */
	int user;          /* a user may switch to it */
	const fzn_preset_value_t *values;
	size_t n_values;
} fzn_preset_t;

/* What a preset is written through: the host's own cells. */
typedef struct fzn_preset_ops {
	void *ctx;
	/* 1 with the value in force, or 0 with none. */
	int (*get)(void *ctx, const char *key, char *value, size_t cap, size_t *len);
	/* 1 written. */
	int (*set)(void *ctx, const char *key, const char *value);
} fzn_preset_ops_t;

/* THE PRESET NAMED `name`, or NULL. */
const fzn_preset_t *fzn_preset_find(const char *name, size_t len);

/* WHETHER THIS BINARY CAN BE `p`. */
int fzn_preset_fits(const fzn_preset_t *p);

/* THE PRESETS THERE ARE, by index: NULL past the last. */
const fzn_preset_t *fzn_preset_at(size_t i);

/* THE VALUE `key` HAS IN THIS PROFILE: the consumer's `extra` first, then
 * `preset`, either of which may be nothing. NULL for a key neither names. */
const fzn_preset_value_t *fzn_preset_value_of(const fzn_preset_t *preset,
                                              const fzn_preset_value_t *extra, size_t n_extra,
                                              const char *key, size_t key_len);

/* WHETHER A WRITER OF `rank` MAY CHANGE `key` HERE: 1 for a key neither names. */
int fzn_preset_may(const fzn_preset_t *preset, const fzn_preset_value_t *extra, size_t n_extra,
                   const char *key, size_t key_len, int rank);

/* The word `list preset` says for `who`. */
const char *fzn_preset_who_word(int who);

/* APPLIED: `preset`, then `extra` over it, each value by who may change it. The
 * values written, or -1 at the first write refused. */
long fzn_preset_apply(const fzn_preset_t *preset, const fzn_preset_value_t *extra, size_t n_extra,
                      const fzn_preset_ops_t *ops);

#endif /* FZN_NODE_PRESETS_H */
