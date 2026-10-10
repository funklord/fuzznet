/*
 * SIBLINGS: the other members of this node's estate, as this node reaches
 * them. sec 579.
 *
 * A member fetches from the peers it has an address for and a pairing to,
 * and siblings are paired with each other by hand or not at all. The holder
 * decided 2026-10-10 that siblings pair one another through the estate:
 * each member carries its own prekey record in its estate stream, and every
 * member keeps the newest one each sibling carried. This module keeps them.
 *
 * A PREKEY RECORD IS PUBLIC BY DESIGN -- a host's agreement key, signed by
 * the host -- so carrying it costs nothing a stranger could use. What makes
 * one worth keeping is who carried it: the record's host must be the key
 * whose stream it is in, and that key a member, which the caller judges
 * (`fzn_node_apply_rank`, as a member setting its own host cell).
 *
 * THE NEWEST PER HOST, by the record's own `created_at`: a clock the host
 * stated about itself, which `prekey/prekey.h` trusts only to order two of
 * one host's records, and that is all it is asked here. An older record
 * arriving late is STALE and changes nothing.
 *
 * Kept in persist slot FZN_PERSIST_SIBLING_PREKEY, one row per host keyed by
 * its key, holding the record as its host signed it (`prekey/prekey.situ`),
 * so the bytes kept are the bytes verified.
 */
#ifndef FZN_NODE_SIBLINGS_H
#define FZN_NODE_SIBLINGS_H

#include <stddef.h>
#include <stdint.h>

#include "../persist/persist.h"
#include "../prekey/prekey.h"
#include "../chain/chain.h" /* fzn_sign_ops_t, FZN_PUBKEY_LEN */

typedef enum fzn_node_siblings_err {
	FZN_NODE_SIBLINGS_OK = 0,
	/* A null argument, or a store without load, save or list. */
	FZN_NODE_SIBLINGS_MALFORMED = -1,
	/* Not a prekey record, its signature does not verify, or its host is
	 * not the key that carried it. */
	FZN_NODE_SIBLINGS_REFUSED = -2,
	/* A record no newer than the one kept for its host. */
	FZN_NODE_SIBLINGS_STALE = -3,
	/* The store would not read, write or list. */
	FZN_NODE_SIBLINGS_BACKEND = -4
} fzn_node_siblings_err_t;

const char *fzn_node_siblings_err_str(fzn_node_siblings_err_t err);

/* How many siblings' prekeys `fzn_node_siblings_list` reads at once. */
#define FZN_NODE_SIBLINGS_MAX 64u

/*
 * KEEP `bytes`, a prekey record carried by `carrier`: OK when it is now the
 * one kept for its host, or is that very record; STALE when the one kept is
 * newer; REFUSED for bytes that are not a record signed by `carrier` about
 * itself.
 */
fzn_node_siblings_err_t fzn_node_siblings_learn(const fzn_persist_ops_t *store,
                                                const fzn_sign_ops_t *verify,
                                                const uint8_t *bytes, size_t len,
                                                const uint8_t carrier[FZN_PUBKEY_LEN]);

/* The prekey record kept for `host`, into `out`: OK, or BACKEND when none is
 * kept or it would not read whole. */
fzn_node_siblings_err_t fzn_node_siblings_prekey(const fzn_persist_ops_t *store,
                                                 const uint8_t host[FZN_PUBKEY_LEN],
                                                 uint8_t out[FZN_PREKEY_LEN_TOTAL]);

/* Every host whose prekey is kept, into `hosts` (at most `cap`): BACKEND when
 * the store will not list, or holds more than `cap`. */
fzn_node_siblings_err_t fzn_node_siblings_list(const fzn_persist_ops_t *store,
                                               uint8_t (*hosts)[FZN_PUBKEY_LEN], size_t cap,
                                               size_t *count);

#endif /* FZN_NODE_SIBLINGS_H */
