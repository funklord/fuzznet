/*
 * WHO IS RESPONSIBLE FOR A KEY: the primitive netcfgd asked for in sec 396,
 * built in sec 820. "Given a set of members and a key, every member
 * independently computes the same ordered list of who is responsible" --
 * with no controller and no round trip, so a site with no single point of
 * failure still agrees on who does a job, and on who takes it over.
 *
 * RENDEZVOUS ORDER (highest random weight): each member is scored by the
 * hash of a label, the key and the member's own key, and the members are
 * ranked by score, highest first, a tie by the greater member key. So:
 *   - every member holding the same set and key computes the same list;
 *   - a member joining or leaving moves only the keys it ranks first for,
 *     and every other key keeps its order of the rest;
 *   - the list is whole, so the second is who takes over when the first
 *     has failed, by whatever a caller judges failure to be (`claim/`'s
 *     observed death, sec 398).
 *
 * The same order erasure pieces are placed by (`fzn_piece_buckets_rank`,
 * sec 597), under a label of its own: that one ranks an item id, and its
 * placements, already on disk, must not move.
 *
 * THE VERB, this node's own user only, over the estate's hosts -- this
 * node and every sibling it lists:
 *
 *     list responsible KEY [FROM]   ok TOTAL FROM SHOWN MORE HOST ...
 *
 * KEY a word of the caller's (at most FZN_RESPONSIBLE_KEY_MAX bytes,
 * %XX undone); the hosts in order, first the one responsible.
 */

#ifndef FZN_NODE_RESPONSIBLE_H
#define FZN_NODE_RESPONSIBLE_H

#include <stddef.h>
#include <stdint.h>

#include "../session/commitment.h"
#include "../local/vocabulary.h"
#include "../chain/authz.h"

#define FZN_RESPONSIBLE_KEY_MAX 256u

/* THE ORDER of `n` members for `key` (`key_len` bytes, at most
 * FZN_RESPONSIBLE_KEY_MAX): `order[0]` the index of the one responsible,
 * and so on. Any `n`; its scores on the heap. 1, or 0 for a null, a key
 * too long, no memory or a hash refused. */
int fzn_responsible_order(const fzn_hash_ops_t *hash, const uint8_t *key, size_t key_len,
                          const uint8_t (*members)[32], size_t n, size_t *order);

typedef struct fzn_node_responsible {
	const fzn_hash_ops_t *hash;
	/* THE ESTATE'S HOSTS, this node among them: the i'th into `host`, 0
	 * past the last. */
	int (*host_at)(void *ctx, size_t i, uint8_t host[32]);
	void *ctx;
} fzn_node_responsible_t;

/* The verb above, as a local handler: 0 for a request that is not one. */
size_t fzn_node_responsible_local(const fzn_node_responsible_t *nr, fzn_origin_t origin,
                                   const fzn_request_t *request, char *reply, size_t reply_cap);

#endif /* FZN_NODE_RESPONSIBLE_H */
