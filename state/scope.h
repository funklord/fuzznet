/* How far a value travels: the scope vocabulary. project.md sec 420.
 *
 * WHOSE IT IS. netcfgd's holder set the scopes as a general feature of this
 * library rather than of any consumer (sec 402), and netcfgd holds a
 * placeholder enum to be deleted when this lands. What stays each consumer's
 * is the TABLE -- which of its values has which scope. This file is the
 * vocabulary and its semantics, and classifies nothing.
 *
 * THE FOUR, and the set is open -- "probably more than these":
 *
 *     host-private   never replicated, and there is no cell at all
 *     host           about one host, replicated so the estate can see it
 *     group          less than the estate: a zone, a building, a VLAN domain
 *     estate         all of it
 *
 * A SCOPE IS A KIND OF SUBJECT. `state/` is (issuer, subject, kind) -> value,
 * so a host-scoped cell's subject names the host, a group-scoped one's the
 * group and an estate-scoped one's the estate. `fzn_scope_subject` derives it,
 * hashed under a label with the scope, so a host-scoped cell and a group whose
 * id happens to equal a host key never share a subject. Adding a scope is
 * adding a kind of subject, not a mechanism.
 *
 * HOST-PRIVATE IS THE SCOPE WITH NO CELL, and it is load-bearing: a machine
 * that never joins an estate has no subject and no cells, just the file on its
 * disk. `fzn_scope_subject` refuses it with its own code rather than inventing
 * a subject for it, so "this never leaves" is checkable rather than expressed
 * by absence.
 *
 * THE NARROWEST SCOPE AT ZERO, the one property netcfgd asked be designed in.
 * Widening a scope publishes what its author never offered anybody; narrowing
 * one only fails to share. So a zeroed field -- a value nobody classified, or
 * a caller that predates a scope added later -- is host-private. And a value
 * outside the set is read as host-private too, for the same reason: a byte
 * this build does not know is an omission, and an omission travels least.
 *
 * REACH IS NOT THE ORDER OF THE NAMES. A host-scoped value is about one host
 * and seen by the whole estate; a group-scoped one is about many hosts and
 * seen only by the group. So the reach sets are
 *
 *     host-private  nobody else    group  the group's members
 *     host          every host     estate every host
 *
 * and `fzn_scope_widens` answers from them, not from the enum's numbers.
 */

#ifndef FZN_SCOPE_H
#define FZN_SCOPE_H

#include <stddef.h>
#include <stdint.h>

#include "../record/record.h"
#include "../session/commitment.h"

typedef enum fzn_scope {
	FZN_SCOPE_HOST_PRIVATE = 0,
	FZN_SCOPE_HOST = 1,
	FZN_SCOPE_GROUP = 2,
	FZN_SCOPE_ESTATE = 3
} fzn_scope_t;

/* One past the last scope this build knows. Not a scope. */
#define FZN_SCOPE_COUNT 4u

typedef enum fzn_scope_err {
	FZN_SCOPE_OK = 0,
	FZN_SCOPE_ERR_MALFORMED = -1,
	/* A host-private value has no cell, so no subject to derive. */
	FZN_SCOPE_ERR_PRIVATE = -2
} fzn_scope_err_t;

const char *fzn_scope_err_str(fzn_scope_err_t err);

/* A scope byte as this build reads it: itself when known, host-private when
 * not -- the narrowest, so an unknown value travels least. */
fzn_scope_t fzn_scope_read(uint8_t byte);

/* Whether this build knows `byte` as a scope. */
int fzn_scope_known(uint8_t byte);

/* The canonical spelling, "host-private", "host", "group", "estate"; NULL for
 * a value this build does not know. */
const char *fzn_scope_name(fzn_scope_t scope);

/* Bytes to scope, exactly and case-sensitively, as `fzn_verb_parse` does. 1
 * and `*out` set when `text` names one; 0 and `*out` untouched when not. */
int fzn_scope_parse(const uint8_t *text, size_t len, fzn_scope_t *out);

/* Whether a value of `scope` leaves its host at all: 0 for host-private and
 * anything unknown. */
int fzn_scope_replicates(fzn_scope_t scope);

/* Whether a value of `scope` reaches a host, `in_group` saying whether that
 * host is a member of the value's group (read only for a group scope). */
int fzn_scope_reaches(fzn_scope_t scope, int in_group);

/* Whether moving a value from `from` to `to` can reach a host `from` did not:
 * the change that publishes something, and so the one a consumer should make
 * deliberately. By reach, not by number: group to host widens, host to estate
 * does not. */
int fzn_scope_widens(fzn_scope_t from, fzn_scope_t to);

/* The `state/` subject of a value of `scope` about `id` -- the host's key for
 * a host scope, the group's id for a group, the estate root for the estate --
 * into `out`. PRIVATE for host-private, MALFORMED for a scope this build does
 * not know or a missing argument; `out` is untouched unless OK. */
fzn_scope_err_t fzn_scope_subject(fzn_scope_t scope, const uint8_t id[FZN_SUBJECT_LEN],
                                  const fzn_hash_ops_t *hash, uint8_t out[FZN_SUBJECT_LEN]);

#endif /* FZN_SCOPE_H */
