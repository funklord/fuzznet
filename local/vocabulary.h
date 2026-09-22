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

/* THE ANSWERS FUZZNET OFFERS, and the other half of sec 361.
 *
 * A daemon has to say whether it did the thing, and every consumer would
 * invent `ok` and `error` and a spelling for the rest. The set is small on
 * purpose: these are the answers a REQUEST can get, not a description of what
 * went wrong, which is the detail's job.
 *
 * FOUR REFUSALS RATHER THAN ONE, because they send a reader to different
 * places and the daemon already knows which it means:
 *
 *     OK           it was done; the detail is the answer
 *     DENIED       policy refused YOU -- an access decision
 *     UNSUPPORTED  this daemon does not serve that verb at all
 *     ERROR        understood, attempted, failed
 *     MALFORMED    could not be read as a request
 *
 * DENIED and UNSUPPORTED are the distinction `fzn_vocabulary_names` exists
 * for, arriving on the wire. That function was written because
 * `fzn_vocabulary_admit` returns NOT_MEMBER both when no rule names a verb
 * and when rules name it and this peer holds none of those groups -- "a
 * configuration finding and an access decision", and a daemon reporting both
 * as denied sends an operator to the wrong half of the system. The server has
 * been able to tell them apart since that function existed and has had no way
 * to SAY which. Now it has.
 *
 * NOT ON THE WIRE AS NUMBERS, the same as `fzn_verb_t`: a reply carries the
 * token as text and this enum is a handle for it. */
typedef enum fzn_reply {
	FZN_REPLY_NONE = 0,
	FZN_REPLY_OK,
	FZN_REPLY_DENIED,
	FZN_REPLY_UNSUPPORTED,
	FZN_REPLY_ERROR,
	FZN_REPLY_MALFORMED
} fzn_reply_t;

#define FZN_REPLY_COUNT ((size_t)FZN_REPLY_MALFORMED + 1u)

/* The longest reply line, terminator excluded. The request's bound and this
 * one are separate numbers because they bound different things and there is
 * no reason an answer should be as long as a question or the reverse. */
#define FZN_REPLY_MAX 512u

/* The canonical spelling, NUL-terminated; NULL for FZN_REPLY_NONE and for a
 * value outside the enum. As with verbs, one spelling only. */
const char *fzn_reply_name(fzn_reply_t reply);
size_t fzn_reply_name_len(fzn_reply_t reply);

/* Bytes to reply token, or FZN_REPLY_NONE for one this library does not
 * offer. Exact and case-sensitive, for `fzn_verb_parse`'s reasons. */
fzn_reply_t fzn_reply_parse(const uint8_t *token, size_t token_len);

/* Did the request succeed? 1 for OK and 0 for everything else INCLUDING
 * FZN_REPLY_NONE.
 *
 * A reply this library does not offer is a reply it cannot vouch for, and
 * answering 1 for one would make a consumer's unrecognised token read as
 * success -- which is the direction that matters, since the failure is a
 * caller carrying on after something did not happen. */
int fzn_reply_ok(fzn_reply_t reply);

/* Why a line could not be composed. `cap` is the caller's buffer and `limit`
 * is the protocol's bound, and they fail differently on purpose: too long for
 * the WIRE is a fact about the request, and too long for the BUFFER is a fact
 * about the caller. A function that collapsed them would leave a caller
 * unable to tell "ask for less" from "give me a bigger buffer". */
typedef enum fzn_compose_err {
	FZN_COMPOSE_OK = 0,
	FZN_COMPOSE_ERR_MALFORMED = -1,
	FZN_COMPOSE_ERR_TOO_LONG = -2,
	FZN_COMPOSE_ERR_NO_ROOM = -3
} fzn_compose_err_t;

/* Compose one line -- `token SP argument LF` -- into `out`, terminator
 * included.
 *
 * ONE FUNCTION FOR BOTH DIRECTIONS. A request line and a reply line are the
 * same grammar with different vocabularies, and this is the only place that
 * grammar is written: `local/client.h` composes requests with it and a
 * daemon's handler composes replies. `fzn_vocabulary_split` reads either.
 * Two composers would be two statements of one format, and the second would
 * drift in the direction nobody tests.
 *
 * Refuses an empty token, one longer than FZN_VERB_MAX, and one containing a
 * space or a newline -- the first would arrive as a shorter token with an
 * argument, past any rule written for the whole string, and the second would
 * make one line into two.
 *
 * A NULL `arg` with zero length writes `token LF`. A non-NULL `arg` of zero
 * length writes `token SP LF`, which is a different line and one `split`
 * reads back as an empty argument rather than an absent one. */
fzn_compose_err_t fzn_vocabulary_compose(uint8_t *out, size_t cap, size_t limit,
                                         size_t *out_len, const uint8_t *token,
                                         size_t token_len, const uint8_t *arg,
                                         size_t arg_len);

/* Compose a reply, which is `fzn_vocabulary_compose` with the token spelled
 * from the enum. FZN_REPLY_NONE is refused: it names nothing to say. */
fzn_compose_err_t fzn_reply_compose(uint8_t *out, size_t cap, size_t *out_len,
                                    fzn_reply_t reply, const uint8_t *detail,
                                    size_t detail_len);

/* Read a reply line: the token as an `fzn_reply_t`, and the rest of the line
 * pointed at through `detail`. Borrowed from `line`, so it lives no longer.
 *
 * FZN_REPLY_NONE for a line this library cannot read as a reply -- empty, all
 * spaces, an overlong token, or a token it does not offer. `fzn_reply_ok`
 * answers 0 for that, so a caller that checks the one thing worth checking
 * does not carry on after an answer it did not understand. */
fzn_reply_t fzn_reply_of(const uint8_t *line, size_t line_len,
                         const uint8_t **detail, size_t *detail_len);

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
