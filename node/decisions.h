/*
 * WHAT WAS DECIDED WHILE HOSTS WERE APART, project.md sec 895.
 *
 * A setting resolves to one value a cell (sec 728), so of two writes made
 * apart the later stands and the earlier is gone with nothing said. Two hosts
 * of an estate are usually one person, who made both on purpose and is owed
 * being told. So a person's write to an estate cell, a contact's name among
 * them, is also written as a DECISION: the record
 * (`node/records.h`) `decided/SUBJECT`, saying what was decided and what its
 * writer had seen when it did.
 *
 *     SELF BASES GROUNDS VALUE
 *
 * SELF is this decision's name and BASES those it supersedes, comma-separated,
 * `-` for none, each NUM.HOST: a number and the first 8 hex of its writer's
 * key. For a decision that wrote a setting, NUM is that setting's version, so
 * a host that has the setting and not yet this record still names it. GROUNDS
 * is one word, the decider's own, `-` for a person's. VALUE is the rest, and
 * empty for something removed.
 *
 * THE HEADS OF A SUBJECT are the decisions no other held supersedes. They are
 * worked out from the records alone, so every host holding the same records
 * finds the same heads, and nothing has to be agreed or sent. A FORK is a
 * subject whose heads disagree. Heads of one value are no fork: two writers
 * who reach the same answer have agreed, whatever they started from.
 *
 * A FORK CLOSES BY A DECISION: a write naming every head as a base. A person
 * who saw both does that by making the change again. Deciders that are
 * programs need no person: each, told of a fork, decides again from the
 * grounds of both sides, and two that run one matrix over one set of grounds
 * write one value, whose heads are no fork. That is the whole of the mechanism
 * for reconciling them; it asks of a decider only that it be a function of its
 * grounds.
 *
 * A DECISION SAYS, IT DOES NOT RULE: what stands is the setting's, by rank and
 * version, and a fork is only shown. A record is kept as any is, so `policy
 * records drop` on a host forgets its forks there.
 *
 * THE VERBS, this node's own user only:
 *
 *     list fork [FROM]        ok FROM SHOWN MORE, then each head of each fork
 *                             as SUBJECT,HOST,AT,GROUNDS,VALUE, by subject
 *     get decided SUBJECT     ok COUNT, then its heads as HOST,AT,GROUNDS,VALUE,
 *                             newest first; ok absent when none is held
 *     add decided SUBJECT [grounds=WORD] VALUE
 *                             a decision with no setting behind it: what a
 *                             program writes, having seen the heads held
 *
 * Strings are %XX escaped as a record's are.
 */

#ifndef FZN_NODE_DECISIONS_H
#define FZN_NODE_DECISIONS_H

#include <stddef.h>
#include <stdint.h>

#include "records.h"

#define FZN_NODE_DECIDED_PREFIX "decided/"
#define FZN_NODE_DECIDED_PREFIX_LEN 8u
#define FZN_NODE_DECIDED_SUBJECT_MAX (FZN_SETTING_KEY_MAX - FZN_NODE_DECIDED_PREFIX_LEN)
#define FZN_NODE_DECIDED_GROUNDS_MAX 64u

typedef struct fzn_node_decision {
	uint8_t subject[FZN_NODE_DECIDED_SUBJECT_MAX];
	size_t subject_len;
	uint8_t host[FZN_PUBKEY_LEN]; /* who decided */
	uint64_t at;                  /* its record's version, ms */
	uint8_t grounds[FZN_NODE_DECIDED_GROUNDS_MAX];
	size_t grounds_len;
	uint8_t value[FZN_SETTING_VALUE_MAX];
	size_t value_len;
} fzn_node_decision_t;

/* A BASE NAMED BY WHAT IT WROTE: a setting's version and its setter. */
typedef struct fzn_node_decision_ref {
	uint64_t number;
	uint8_t host[FZN_PUBKEY_LEN];
} fzn_node_decision_ref_t;

/*
 * THIS HOST DECIDES `value` OF `subject`, having seen every head held and
 * `seen`, when not NULL. `self` is the decision's own number: the version of
 * the setting it wrote, or 0 for the time now. `grounds` may be NULL for a
 * person's. A base past the room a record has is left out, which leaves a fork
 * open rather than hiding one.
 */
fzn_node_records_err_t fzn_node_decisions_write(const fzn_node_records_t *nr,
                                                const uint8_t *subject, size_t subject_len,
                                                uint64_t self,
                                                const fzn_node_decision_ref_t *seen,
                                                const uint8_t *grounds, size_t grounds_len,
                                                const uint8_t *value, size_t value_len);

/* THE HEADS OF `subject` to `each`, newest first, ties by the greater host.
 * The count, or -1 when the records could not be read. */
long fzn_node_decisions_heads(const fzn_node_records_t *nr, const uint8_t *subject,
                              size_t subject_len,
                              void (*each)(void *ctx, const fzn_node_decision_t *d), void *ctx);

/* EVERY HEAD OF EVERY FORK to `each`, by subject: the number of forks, or -1. */
long fzn_node_decisions_forks(const fzn_node_records_t *nr,
                              void (*each)(void *ctx, const fzn_node_decision_t *d), void *ctx);

/* The verbs above, as a local handler: 0 for a request that is not one. */
size_t fzn_node_decisions_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                                char *reply, size_t reply_cap);

#endif /* FZN_NODE_DECISIONS_H */
