/*
 * LOCAL PERMISSIONS, sec 852: which other local users may use which of the
 * node's verbs, given by the node's own user.
 *
 * A node serves its own user, and with `--group` one service group (sec
 * 4.x). A root daemon -- netcfgd, raidcfgd -- serves people who are not
 * fuzznet users at all: a desktop's GUI, an operator's shell. The holder:
 * their "local auth is gated by their resp. groups", and "we should avoid
 * storing anything on users that aren't full fuzznet users".
 *
 * So a grant names a SUBJECT -- the word after a verb: `record` in `list
 * record`, `status` in netcfgd's `get status` -- and who may READ it (`get`,
 * `list`, `status`), also CHANGE it (`w`, every other verb, and never
 * without `r`), or CALL it as a procedure (`x`, sec 853). It is the host
 * setting `local/permit/SUBJECT`, whose value is one or more grants:
 *
 *     group:netcfgd=r user:alice=rw user:#1001=r
 *
 * A name is a user's or group's as this machine's databases say; `#N` is a
 * numeric id. A caller so permitted is served that subject's verbs as the
 * node's own user is; nothing is kept for it, and it subscribes to nothing.
 *
 * NOT GRANTABLE: the subjects that are the estate's trust -- identity,
 * backup, join, root, admin, peer, grant, capability, revocation, events,
 * and setting and schema, since a grant on settings would let its holder
 * write its own --
 * which a person outside fuzznet must never reach by a line in a setting.
 */
#ifndef FZN_NODE_PERMIT_H
#define FZN_NODE_PERMIT_H

#include <stddef.h>
#include <stdint.h>

#include "../local/peer.h"

#define FZN_PERMIT_READ 1u
#define FZN_PERMIT_CHANGE 2u
/* A CALL of the subject as a procedure, sec 853: only the procedure knows
 * whether it reads or changes, so it is a right of its own, `x`. */
#define FZN_PERMIT_CALL 4u

/* The setting's family: `local/permit/` and the subject. */
#define FZN_PERMIT_KEY_PREFIX "local/permit/"
#define FZN_PERMIT_SUBJECT_MAX 32u

/* 1 when `subject`, `n` bytes, may be granted: a word of a-z and 0-9, as a
 * setting family's word is,
 * not one of the trust subjects above. */
int fzn_node_permit_subject_ok(const char *subject, size_t n);

/* NULL when `value` is a well-formed list of grants, or why it is not:
 * the schema's check, and so the reader's. */
const char *fzn_node_permit_check(const uint8_t *value, size_t len);

/* 1 when `peer` holds `right` (FZN_PERMIT_READ or FZN_PERMIT_CHANGE) by
 * the grants in `value`. A peer whose group list could not be read is
 * matched by its user and primary group alone. Names are looked up in
 * this machine's databases; a name that does not resolve grants nothing. */
int fzn_node_permit_allows(const uint8_t *value, size_t len, const fzn_peer_t *peer,
                           unsigned right);
/* (`right` is one of FZN_PERMIT_READ, _CHANGE and _CALL.) */

#endif /* FZN_NODE_PERMIT_H */
