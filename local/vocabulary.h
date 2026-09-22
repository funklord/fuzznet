/* Bounding what a peer may ask for, once its group has let it in.
 *
 * raidcfgd's requirement, stated in its own project.md (2026-08-18) and not
 * negotiable there: **a gid check that gates a connection is not enough; what
 * a member of that group may then ask for has to be bounded, or the group
 * boundary is a root boundary wearing a different name.** Its reasoning is the
 * docker-group lesson -- a group that can destroy arrays *is* root for that
 * group -- and it left the choice of where the bound lives to this library.
 *
 * It lives here, and THIS HEADER USED TO CITE SEC 5 FOR THE OPPOSITE REASON.
 * It said that section "keeps COMMAND VOCABULARIES out of the core", that a
 * project's verbs are its own, and that "this library cannot tell `status`
 * from `destroy` and must not learn". Sec 5's own opening says that claim was
 * overturned on 2026-08-26 and warns in as many words that quoting it as
 * current is the "claim that outlived its subject"; sec 298 names this module
 * as the seam the reversal lands in. The correction is the copyright
 * holder's, stated 2026-09-22: everything required to use fuzznet is part of
 * fuzznet, and fuzznet is useless without a vocabulary.
 *
 * SO THE VERBS ARE HERE, and the mechanism keeps working exactly as it did.
 * `fzn_vocabulary_admit` still takes bytes and a length, because a consumer
 * with a verb of its own must still be able to bound it -- sec 298 sanctions
 * bypassing what fuzznet does not yet offer. What is new is that fuzznet
 * offers a set, so three consumers do not each invent `get` and spell it
 * differently.
 *
 * THE VERBS NAME FUZZNET'S OWN FEATURES, which is the test for adding one. A
 * verb that names nothing this library does is a promise rather than a
 * capability, and the bound below would gate something no node can serve.
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

/* THE VERBS FUZZNET OFFERS.
 *
 * An OPERATION, with the subject carried as the request's argument. That
 * split is what keeps the set small and orthogonal: three consumers that each
 * invented a verb per subject would share nothing, and the same operation
 * would arrive as `gethost`, `host-get` and `read_host`.
 *
 * Every one names something this library does, and the module that does it:
 *
 *     STATUS   the node itself                  node/
 *     LOG      the log subsystem                log/, flog/
 *     GET      read a stored value              record/, state/
 *     SET      write one                        record/, state/
 *     LIST     enumerate a subject              catalog/, record/
 *     ADD      create one                       catalog/, provision/
 *     REMOVE   delete one                       catalog/
 *     FETCH    pull bytes                       spool/, chunk/, blob/
 *     PUT      push bytes                       spool/, chunk/, blob/
 *     GRANT    issue a capability               chain/
 *     REVOKE   withdraw one                     chain/revocation.h
 *
 * NOT ON THE WIRE AS NUMBERS. A request carries the verb as TEXT, and this
 * enum is an internal handle for it, so a value here may be renumbered
 * without breaking a peer. `fzn_verb_name` is the spelling that travels and
 * it is the only one: a second spelling is a second verb.
 *
 * FZN_VERB_NONE IS "NOT ONE OF FUZZNET'S", NOT "INVALID". A consumer's own
 * verb parses to NONE and is still a verb -- `fzn_vocabulary_admit` takes
 * bytes and will bound it against a rule the consumer wrote. Reading NONE as
 * a refusal would make sec 298's bypass-until-gained impossible. */
typedef enum fzn_verb {
	FZN_VERB_NONE = 0,
	FZN_VERB_STATUS,
	FZN_VERB_LOG,
	FZN_VERB_GET,
	FZN_VERB_SET,
	FZN_VERB_LIST,
	FZN_VERB_ADD,
	FZN_VERB_REMOVE,
	FZN_VERB_FETCH,
	FZN_VERB_PUT,
	FZN_VERB_GRANT,
	FZN_VERB_REVOKE
} fzn_verb_t;

/* One past the last verb, for a caller walking the set. Not a verb. */
#define FZN_VERB_COUNT ((size_t)FZN_VERB_REVOKE + 1u)

/* The canonical spelling, lowercase ASCII, NUL-terminated; NULL for
 * FZN_VERB_NONE and for a value outside the enum. `fzn_verb_name_len` is the
 * same string's length, so a caller matching bytes needs no `strlen`. */
const char *fzn_verb_name(fzn_verb_t verb);
size_t fzn_verb_name_len(fzn_verb_t verb);

/* Bytes to verb, or FZN_VERB_NONE for one this library does not offer.
 *
 * EXACT AND CASE-SENSITIVE. A verb is a protocol token rather than something
 * a person types, and case folding would need a locale-independent one --
 * `cli/cli.c` records the same refusal about `strtoul` taking its digits from
 * the locale. A caller wanting to be generous folds before asking. */
fzn_verb_t fzn_verb_parse(const uint8_t *verb, size_t verb_len);

/* Does this verb change state? 1 for SET, ADD, REMOVE, PUT, GRANT and
 * REVOKE; 0 for the rest and for NONE.
 *
 * IT IS HERE BECAUSE ALL THREE CONSUMERS NEED IT AND NONE SHOULD DERIVE IT.
 * A daemon deciding whether to require a stronger origin, whether to log at a
 * higher severity, or whether to refuse while read-only is asking exactly
 * this, and a list of mutating verbs maintained in three trees is three lists
 * that drift the first time a verb is added here. 0 for NONE is the
 * conservative answer only in appearance -- a consumer's own verb is not
 * described by this function at all, and a caller must decide for its own
 * verbs rather than read NONE as "harmless". */
int fzn_verb_mutates(fzn_verb_t verb);

/* A rule admitting `gid` to ask for one of fuzznet's verbs, so a consumer
 * writes `fzn_verb_rule(cfg.service_gid, FZN_VERB_STATUS)` rather than
 * spelling the bytes out. A rule for FZN_VERB_NONE names nothing and is
 * refused by the table functions, which is what makes a mistyped enum value
 * fail closed rather than matching everything. */
fzn_verb_rule_t fzn_verb_rule(uint32_t gid, fzn_verb_t verb);

/* THE LONGEST REQUEST LINE, terminator excluded.
 *
 * It lived in `node/local.c` as a private `FZN_NODE_REQUEST_CAP` until a
 * CLIENT needed it. A client that does not know the server's bound sends a
 * line the server refuses, and the refusal arrives as a denial rather than
 * as "that was too long" -- so the one number has to be visible to both
 * halves, and it belongs with the grammar rather than with either end of it.
 *
 * 512 is the number `node/local.c` has always read with. It bounds the LINE;
 * FZN_VERB_MAX bounds the verb within it, so an argument may be up to
 * FZN_REQUEST_MAX - FZN_VERB_MAX - 1. */
#define FZN_REQUEST_MAX 512u

/* A request as this library reads one: the verb, and the rest of the line.
 *
 * The bytes are BORROWED from the caller's line and are not copied, so this
 * lives no longer than the buffer it was split from. `verb`/`verb_len` are
 * the text as it arrived, which is what `fzn_vocabulary_admit` bounds --
 * `parsed` is the same thing as a handle, and is FZN_VERB_NONE for a verb
 * fuzznet does not offer. */
typedef struct fzn_request {
	fzn_verb_t parsed;
	const uint8_t *verb;
	size_t verb_len;
	const uint8_t *arg;
	size_t arg_len;
} fzn_request_t;

/* Split one request line into a verb and its argument.
 *
 * The grammar is deliberately the smallest thing that can carry an argument:
 * a verb, one space, and the rest of the line unexamined. Everything after
 * that first space is the argument including any further spaces, because a
 * library that tokenised further would be deciding the shape of arguments it
 * cannot know the meaning of -- and sec 298 puts the VOCABULARY here, not a
 * parser for every consumer's operands.
 *
 * `line` is one framed line with its terminator already removed, as
 * `local/line.h` hands it over. Returns 1 on a line carrying a verb, 0 for a
 * NULL or empty line, a line that is only spaces, or a verb longer than
 * FZN_VERB_MAX -- the same bound the table functions apply, so a verb this
 * refuses is also a verb no rule could name. `out` is left zeroed on 0 rather
 * than half-filled. An absent argument is NULL with a zero length, which a
 * caller must not confuse with an empty one: `get` and `get ` differ, and the
 * second is a caller asking for the empty subject. */
int fzn_vocabulary_split(const uint8_t *line, size_t line_len, fzn_request_t *out);

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

/* Does the table name this verb for ANY group? 1 or 0, and it says nothing
 * about who is asking -- it takes no peer.
 *
 * IT EXISTS BECAUSE `admit` RETURNS FZN_PEER_NOT_MEMBER FOR TWO SITUATIONS
 * THAT WANT OPPOSITE RESPONSES, and the verdict cannot tell them apart:
 *
 *   - no rule names this verb at all, so the policy does not cover it. A
 *     typo, a verb the consumer forgot to add, or a client asking for
 *     something this daemon does not do.
 *   - rules DO name it, and this peer holds none of those groups. The policy
 *     covers the verb and is denying this person.
 *
 * The first is a configuration finding and the second is an access decision.
 * A daemon that logs both as "denied" sends an operator to the wrong half of
 * the system, which is the same shape as peer.h's own "empty is not unknown"
 * -- and it was found by writing sec 204's `cli/peer_print`, which had to
 * report the reason and could not.
 *
 * SEPARATE RATHER THAN A FOURTH VERDICT VALUE, because it is orthogonal:
 * `admit` can return UNKNOWN while the table does name the verb, and both
 * facts matter to the caller at once. Folding it into the enum would force a
 * choice between them.
 *
 * DO NOT USE IT TO AUTHORISE ANYTHING. It answers a question about the
 * TABLE, and a caller that treated a named verb as an admitted one would have
 * inverted the whole module. `fzn_vocabulary_admit` is the only function here
 * that looks at a peer.
 *
 * 0 for a NULL verb or table, and 0 for a verb of zero length or longer than
 * FZN_VERB_MAX -- the same bound `admit` applies, because a verb the policy
 * cannot express is not one it names. */
int fzn_vocabulary_names(const uint8_t *verb, size_t verb_len, const fzn_verb_rule_t *rules,
                          size_t rule_count);

#endif /* FZN_VOCABULARY_H */
