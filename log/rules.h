/* The retention rules a node keeps, set while it runs. sec 475.
 *
 * THE HOLDER'S "DYNAMIC RETENTION AMOUNTS" (sec 474), the local half: a
 * rule (`log/retain.h`) set by the node's own user through admin, kept in
 * the store, and read again by the writer on every pass, so a change takes
 * effect at the next rotation or round with no restart. Rules given on a
 * command line stay beside these; both apply.
 *
 * ONE RULE ONE ENTRY, filed under a hash of its canonical text
 * (`fzn_retain_text`), so `age 30d` and `age 720h` are one rule, added
 * once and removed by either spelling.
 *
 * NOT CORE (persist slot 26). Lost, a rule stops applying and logs are kept
 * longer; rolled back, a removed rule applies again and prunes what it
 * pruned before. Neither opens a door: retention decides how long this
 * host's own logs stay, not who reads them.
 *
 * Rules as estate state -- replicated and scoped as sec 428 has them -- are
 * not this; they wait on the holder's say over who may set them.
 */

#ifndef FZN_LOG_RULES_H
#define FZN_LOG_RULES_H

#include <stddef.h>
#include <stdint.h>

#include "retain.h"
#include "../persist/persist.h"
#include "../session/commitment.h"

/* Rules a node keeps: half of what one plan weighs, leaving the other half
 * to a command line. */
#define FZN_LOG_RULES_MAX 16u

typedef enum fzn_log_rules_err {
	FZN_LOG_RULES_OK = 0,
	FZN_LOG_RULES_ERR_MALFORMED = -1, /* a null, a rule that is not one */
	FZN_LOG_RULES_ERR_TAKEN = -2,     /* the rule is held already */
	FZN_LOG_RULES_ERR_ABSENT = -3,    /* no such rule */
	FZN_LOG_RULES_ERR_FULL = -4,      /* FZN_LOG_RULES_MAX are held */
	FZN_LOG_RULES_ERR_BACKEND = -5,   /* the store or the hash refused */
	FZN_LOG_RULES_ERR_SHAPE = -6      /* a held entry will not read */
} fzn_log_rules_err_t;

const char *fzn_log_rules_err_str(fzn_log_rules_err_t err);

fzn_log_rules_err_t fzn_log_rules_add(const fzn_persist_ops_t *store, const fzn_hash_ops_t *hash,
                                      const fzn_retain_rule_t *rule, uint64_t now_ms);

fzn_log_rules_err_t fzn_log_rules_remove(const fzn_persist_ops_t *store,
                                         const fzn_hash_ops_t *hash,
                                         const fzn_retain_rule_t *rule);

/* Every rule held, in the order of their canonical texts, `cap` of them. An
 * entry that will not read is SHAPE rather than skipped: a rule silently
 * missing is a log kept or pruned against the user's word. */
fzn_log_rules_err_t fzn_log_rules_list(const fzn_persist_ops_t *store, fzn_retain_rule_t *out,
                                       size_t cap, size_t *count);

#endif /* FZN_LOG_RULES_H */
