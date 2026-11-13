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
 *     local:@netcfgd=r local:alice=rw local:#1001=r
 *
 * `local:NAME` is a local user as a principal, `local:@NAME` a group of them
 * (sec 904); `user:NAME` and `group:NAME`, as first written, mean the same. A
 * name is a user's or group's as this machine's databases say; `#N` is a
 * numeric id. `any=x` lets every local user call the subject (sec 883): a
 * call only, for a procedure judges its own caller, and no fuzznet verb
 * does. A caller so permitted is served that subject's verbs as the
 * node's own user is; nothing is kept for it. The host setting `local/events`,
 * of the same grants, lets a caller hold `get events` (sec 899), hearing what
 * the application publishes, and it subscribes to nothing else. There alone,
 * `any=r` lets every local user hear it (sec 933): fuzznet's own events never
 * reach that stream, so it says only what the application chose to publish.
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
#include "../state/setting.h"

#define FZN_PERMIT_READ 1u
#define FZN_PERMIT_CHANGE 2u
/* A CALL of the subject as a procedure, sec 853: only the procedure knows
 * whether it reads or changes, so it is a right of its own, `x`. */
#define FZN_PERMIT_RRPC 4u

/* The setting's family: `local/permit/` and the subject. */
#define FZN_PERMIT_KEY_PREFIX "local/permit/"
#define FZN_PERMIT_SUBJECT_MAX 32u

/* 1 when `subject`, `n` bytes, may be granted: a word of a-z and 0-9, as a
 * setting family's word is,
 * not one of the trust subjects above. */
int fzn_node_permit_subject_ok(const char *subject, size_t n);

/* `local/events`: NULL when `value` is well-formed, or why it is not. */
const char *fzn_node_permit_events_check(const uint8_t *value, size_t len);

/* 1 WHEN `local/events`'S `value` LETS `peer` HEAR the application. */
int fzn_node_permit_hears(const uint8_t *value, size_t len, const fzn_peer_t *peer);

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

/*
 * WHO MAY CALL A PROCEDURE FROM ANOTHER HOST, sec 921, the holder's: "each call
 * should probably be gated by the permission system". A rule is a host's setting,
 * `remote/permit/NAME` for one procedure and `remote/permit` for every procedure
 * with no rule of its own; none set is `member`, as it was.
 *
 *     member     any host with standing in this estate
 *     admin      a host of admin rank or above
 *     root       the root's
 *     host:HEX   this host, by its key
 *     none       nobody
 *
 * Words apart by spaces, and any word that names the caller lets it in, so a rule
 * is a list of who, and a button is `host:HEX`. A stranger is refused before a rule
 * is read. A value that does not parse lets nobody in, not even by its first half.
 */
#define FZN_REMOTE_PERMIT_KEY "remote/permit"
#define FZN_REMOTE_PERMIT_KEY_PREFIX "remote/permit/"

/* NULL when `value` is a well-formed rule, or why it is not. */
const char *fzn_node_remote_permit_check(const uint8_t *value, size_t len);

/* 1 when the member `host`, of `rank`, is let in by the rule in `value`. */
int fzn_node_remote_permit_allows(const uint8_t *value, size_t len,
                                  const uint8_t host[FZN_PUBKEY_LEN], fzn_setting_rank_t rank);

#endif /* FZN_NODE_PERMIT_H */
