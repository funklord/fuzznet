/* Notes between nodes: one node pulls what another holds. sec 432, phase 4
 * of the notes move.
 *
 * The bytes are `notes/sync.situ`'s, encoded here by hand as spool/message.c
 * encodes its own. A pull asks a peer for the INDEX of what it holds -- each
 * claim's key and sequence -- and then for the RECORDS of only the claims it
 * lacks or holds older. Every record that arrives goes through `fzn_notes_put`,
 * the same admission and supersession a locally written note goes through,
 * so a peer can offer anything and this node keeps only what its policy
 * admits and nothing older than it has.
 *
 * NEITHER SIDE CARRIES A NOTE PENDING PURGE, which is the rule sec 427 left to
 * carriage. A server leaves such a note out of its index, so a sibling that
 * has just consented to erasing it is not handed it again in the same round
 * -- fuzzypickles' resurrection defect -- and a puller refuses one arriving,
 * since this node has already asked for it to go.
 *
 * WHO MAY BE ASKED is the transport's question: the remote hop has already
 * authenticated the asker under its session. What a node serves is records
 * its own store admitted, each signed by its writer, so serving one tells a
 * peer nothing it could not verify for itself.
 */

#ifndef FZN_NOTES_SYNC_H
#define FZN_NOTES_SYNC_H

#include <stddef.h>
#include <stdint.h>

#include "purge.h"

#define FZN_NOTES_SYNC_VERSION 2u

enum fzn_notes_sync_type {
	FZN_NOTES_SYNC_INDEX_QUERY = 1,
	FZN_NOTES_SYNC_INDEX = 2,
	FZN_NOTES_SYNC_RECORDS_QUERY = 3,
	FZN_NOTES_SYNC_RECORDS = 4
};

#define FZN_NOTES_SYNC_HEAD_LEN 2u
#define FZN_NOTES_SYNC_INDEX_QUERY_LEN 4u
#define FZN_NOTES_SYNC_INDEX_HEAD_LEN 8u
#define FZN_NOTES_SYNC_CLAIM_LEN (FZN_PUBKEY_LEN + 8u)
#define FZN_NOTES_SYNC_LIST_HEAD_LEN 3u
/* Records asked for, and sent, at once. */
#define FZN_NOTES_SYNC_KEYS_MAX 16u

/* The largest RECORDS a server sends, and so the reply buffer a puller needs
 * to take one whole. */
#define FZN_NOTES_SYNC_REPLY_MAX                                                               \
	((size_t)FZN_NOTES_SYNC_LIST_HEAD_LEN                                                  \
	 + ((size_t)FZN_NOTES_SYNC_KEYS_MAX * (2u + FZN_RECORD_MAX_LEN)))

/* THE SERVER: answer an INDEX_QUERY with a page of the index, and a
 * RECORDS_QUERY with as many of the records asked for as fit `reply_cap`.
 * 0 when `request` is no notes sync message, so a caller dispatching on the
 * first byte can fall through. */
size_t fzn_notes_sync_answer(const fzn_notes_store_t *store, const uint8_t *request,
                             size_t request_len, uint8_t *reply, size_t reply_cap);

/* How a puller asks a peer: send `request`, fill `reply`. Nonzero on an
 * answer. A test's is another store's `fzn_notes_sync_answer`. */
typedef int (*fzn_notes_sync_ask_t)(void *ctx, const uint8_t *request, size_t request_len,
                                    uint8_t *reply, size_t reply_cap, size_t *reply_len);

typedef struct fzn_notes_sync_tally {
	size_t offered;  /* claims the peer's index named */
	size_t fetched;  /* records asked for and received */
	size_t learned;  /* records the store took */
	size_t refused;  /* records the store refused, or pending purge here */
} fzn_notes_sync_tally_t;

typedef enum fzn_notes_sync_err {
	FZN_NOTES_SYNC_OK = 0,
	FZN_NOTES_SYNC_MALFORMED = -1,
	FZN_NOTES_SYNC_NO_ANSWER = -2, /* the peer did not answer */
	FZN_NOTES_SYNC_SHAPE = -3,     /* the peer answered with something else */
	FZN_NOTES_SYNC_STORE = -4      /* this node's store would not list or read */
} fzn_notes_sync_err_t;

const char *fzn_notes_sync_err_str(fzn_notes_sync_err_t err);

/* THE PULLER: take from the peer `ask` reaches every claim this store lacks
 * or holds older, admitted by `policy` as any record is. A record a peer
 * sends that it was not asked for is refused, so a peer cannot use a pull to
 * push. */
fzn_notes_sync_err_t fzn_notes_sync_pull(const fzn_notes_store_t *store,
                                         fzn_notes_policy_t policy, const fzn_sign_ops_t *sign,
                                         fzn_notes_sync_ask_t ask, void *ask_ctx,
                                         fzn_notes_sync_tally_t *tally);

#endif /* FZN_NOTES_SYNC_H */
