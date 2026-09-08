/*
 * Who is on the other end of a local socket, what they asked for, and which
 * kind of "no" this is.
 *
 * project.md sec 204. `gui/peer_view` is the same facts for a screen and
 * shows this file's line, per sec 193.
 *
 * TWO KINDS OF DENIAL, WHICH `fzn_vocabulary_admit` CANNOT SEPARATE. It
 * returns FZN_PEER_NOT_MEMBER both when no rule names the verb at all and
 * when rules name it and this peer holds none of those groups. The first is a
 * configuration finding -- a typo, a verb nobody added, a client asking for
 * something this daemon does not do -- and the second is an access decision
 * about a person. A daemon logging both as "denied" sends an operator to the
 * wrong half of the system. `fzn_vocabulary_names` was added to `local/` for
 * this, rather than the walk being repeated here: two implementations of "does
 * a rule name this verb" is exactly the duplication sec 200 draws the line
 * against, and they would disagree the first time one forgot that a rule
 * longer than FZN_VERB_MAX is one the module ignores.
 *
 * THE VERB IS ESCAPED, AND THAT IS NOT COSMETIC. `vocabulary.h` is explicit
 * that this library "cannot tell `status` from `destroy` and must not learn":
 * a verb is opaque bytes off a socket, chosen by whoever connected. Writing
 * them into a line unexamined lets a peer put a newline in a verb and forge
 * a second log entry underneath its own denial -- a peer that cannot run the
 * command writing the record that says somebody did. So every byte outside
 * printable ASCII becomes `\xNN`, and so do the quote and the backslash, or
 * the escaping would itself be forgeable.
 *
 * THE VERDICT IS THE LIBRARY'S OWN ENUM, not a parallel one. `local/peer.h`
 * already has exactly the three values this reports and has thought about
 * their naming harder than a printer should -- sec 200's line is that two
 * callers asking one library is not duplication, and inventing
 * `fzn_peer_line_t` here would be a second vocabulary for one fact.
 *
 * `named_out` IS THE SECOND CHANNEL AND `groups_known` IS NOT. Whether the
 * table names the verb takes a walk over the table, so a caller cannot get it
 * without asking. Whether the supplementary list was readable is a field of
 * the `fzn_peer_t` the caller is holding as it calls -- reporting it back
 * would be handing somebody their own struct. It is in the sentence, because
 * a reader of the sentence may not have the struct.
 *
 * NOTHING HERE AUTHORISES ANYTHING. It renders a decision `local/` made. A
 * caller that took the rendering as the decision would have put a formatter
 * in the authorisation path.
 */

#ifndef FZN_CLI_PEER_PRINT_H
#define FZN_CLI_PEER_PRINT_H

#include "../local/peer.h"
#include "../local/vocabulary.h"

#include <stddef.h>
#include <stdint.h>

/* Room for the longest line this writes. A verb is at most FZN_VERB_MAX
 * bytes and every one of them can escape to four characters, so the verb
 * alone can reach 128. */
#define FZN_PEER_PRINT_MAX 448u

/*
 * Render one admission decision.
 *
 * `peer` may be NULL, which `fzn_vocabulary_admit` answers FZN_PEER_UNKNOWN
 * -- nothing is known about a peer that was not supplied, and unknown denies.
 *
 * `verb` may be NULL or of any length; the bounds are the library's and are
 * applied by it. A verb longer than FZN_VERB_MAX is NOT_MEMBER and not named,
 * which is the pair saying "the policy cannot express this at all".
 *
 * `verdict_out` and `named_out` are both REQUIRED, on `fzn_manifest_deficit`'s
 * argument for its own `dropped`. On any refusal `verdict_out` is left
 * FZN_PEER_UNKNOWN and `named_out` zero, which denies and claims no knowledge
 * of the table.
 *
 * NOTHING HERE MUTATES, sec 181.
 */
int fzn_peer_print(const fzn_peer_t *peer, const uint8_t *verb, size_t verb_len,
                   const fzn_verb_rule_t *rules, size_t rule_count, char *out, size_t cap,
                   size_t *len_out, fzn_peer_verdict_t *verdict_out, int *named_out);

#endif /* FZN_CLI_PEER_PRINT_H */
