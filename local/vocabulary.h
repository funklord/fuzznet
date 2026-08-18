/* Bounding what a peer may ask for, once its group has let it in.
 *
 * raidcfgd's requirement, stated in its own project.md (2026-08-18) and not
 * negotiable there: **a gid check that gates a connection is not enough; what
 * a member of that group may then ask for has to be bounded, or the group
 * boundary is a root boundary wearing a different name.** Its reasoning is the
 * docker-group lesson -- a group that can destroy arrays *is* root for that
 * group -- and it left the choice of where the bound lives to this library.
 *
 * It lives here, and sec 5 is why it can. That section keeps COMMAND
 * VOCABULARIES out of the core: fuzzypickles' 4718 lines of encoders are its
 * own, and a project's verbs are its own. What this module carries is the
 * MECHANISM and never the meaning -- the same split `chain.h` already makes,
 * where a capability is 32 opaque bytes and the library verifies the chain
 * without ever learning what the capability permits.
 *
 * So a verb here is bytes with a length. This library cannot tell `status`
 * from `destroy` and must not learn: the consumer supplies the table, and the
 * table is what says which group may ask for what.
 *
 * THE TRI-STATE IS peer.h's, AND FOR THE SAME REASON. A peer whose
 * supplementary groups could not be read is UNKNOWN, not "in no groups", and
 * both deny -- raidcfgd says the same thing in its own words: "an empty group
 * list means could not tell, not none", and treating a failed read as an empty
 * membership turns a read that failed into an allow.
 *
 * WHAT THIS IS NOT. It is not authorisation over the network path -- that is
 * `chain.h`'s capability chain, against a pinned root. This is the LOCAL
 * socket, where the peer is a process on the same machine and the evidence is
 * its credentials rather than a signature. A consumer needs both, for the two
 * different questions they answer.
 */

#ifndef FZN_VOCABULARY_H
#define FZN_VOCABULARY_H

#include <stddef.h>
#include <stdint.h>

#include "peer.h"

/* The longest verb this will consider. A hard bound rather than a suggestion:
 * raidcfgd adopts netcfgd's newline-delimited JSON and records that the
 * mitigations for a text protocol -- "a hard bound on framing, and both
 * parsers fuzzed" -- are the other half of that choice rather than optional
 * extras of it. This is the framing half for the verb.
 *
 * Longer is REFUSED rather than truncated. Truncating would let `statusXXXX`
 * match a rule for `status`, which is the whole failure this bound exists to
 * prevent. */
#define FZN_VERB_MAX 32u

/* One entry of a consumer's table: this group may ask for this verb. */
typedef struct fzn_verb_rule {
	uint32_t gid;
	const uint8_t *verb;
	size_t verb_len;
} fzn_verb_rule_t;

/* May this peer ask for this verb?
 *
 *   FZN_PEER_MEMBER     -- yes: a rule names this verb for a group it holds.
 *   FZN_PEER_NOT_MEMBER -- no, definitely: no rule names this verb for any
 *                          group, or the verb is not one a rule could name.
 *   FZN_PEER_UNKNOWN    -- cannot tell: a rule names this verb for some group,
 *                          and whether this peer holds it is unknowable
 *                          because its supplementary list could not be read.
 *
 * The third is the one worth having and the reason this returns a verdict
 * rather than a boolean. `fzn_peer_is_member` collapses UNKNOWN to a denial
 * for callers who want a boolean, and the same is available here by comparing
 * against FZN_PEER_MEMBER -- but a daemon that wants to log "I could not read
 * your groups" differently from "you are not in that group" can.
 */
fzn_peer_verdict_t fzn_vocabulary_admit(const fzn_peer_t *peer, const uint8_t *verb,
                                         size_t verb_len, const fzn_verb_rule_t *rules,
                                         size_t rule_count);

#endif /* FZN_VOCABULARY_H */
