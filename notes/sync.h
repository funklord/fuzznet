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
 *
 * THE PURGE CONVERSATION, sec 433, IS DRIVEN BY THE PULLER, both ways,
 * because only the puller can reach the other: a node that serves and pulls
 * from nobody has no way to open a conversation.
 *
 *   - Its own purges: the puller sends PURGE, "erase this note", for each
 *     purge that pins the server, and the server answers PURGE_ACK.
 *   - The server's purges: the puller asks PURGES_QUERY, "which of yours pin
 *     me?", erases each, and tells the server with PURGE_ACK, which the
 *     server records and echoes.
 *
 * So a server must know who pulls from it, since they hold copies a purge
 * must ask about: an INDEX_QUERY from a node the server admits records it as
 * a PARTNER, and `fzn_notes_partners` lists them for a purge's pinned set.
 *
 * Erasing changes the erasing node, so each side erases only for a node its
 * own policy admits as a writer -- the hosts that could have written a note
 * are the hosts that may ask for it to go. A refusal, or a store that cannot
 * remove, is answered "not erased", never silence, so the asker learns why
 * it is still waiting rather than timing out.
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
	FZN_NOTES_SYNC_RECORDS = 4,
	FZN_NOTES_SYNC_PURGE = 5,
	FZN_NOTES_SYNC_PURGE_ACK = 6,
	FZN_NOTES_SYNC_PURGES_QUERY = 7,
	FZN_NOTES_SYNC_PURGES = 8,
	FZN_NOTES_SYNC_WRITERS_QUERY = 9,
	FZN_NOTES_SYNC_WRITERS = 10,
	/* 11 and 12 are `node/members.h`'s. */
	FZN_NOTES_SYNC_PUSH = 13,
	FZN_NOTES_SYNC_PUSHED = 14
};

/* PUSHING, sec 446: a record the sender holds and the server lacks, one a
 * message, so a push fits one frame. PUSH is version | type | len u16 |
 * record; PUSHED is version | type | outcome. */
#define FZN_NOTES_SYNC_PUSH_HEAD_LEN 4u
#define FZN_NOTES_SYNC_PUSHED_LEN 3u
#define FZN_NOTES_SYNC_PUSH_REFUSED 0u /* not admitted, malformed, or pending purge here */
#define FZN_NOTES_SYNC_PUSH_TAKEN 1u
#define FZN_NOTES_SYNC_PUSH_HELD 2u    /* this one or a newer was held already */

/* WHO WROTE WHAT IS SHARED, sec 437: the distinct writers of the notes a
 * share reaches, which a recipient admits in that sharer's tree and nowhere
 * else. At most FZN_NOTES_SYNC_WRITERS_MAX; a share written by more is not
 * answered, since a short list would refuse some writers' notes with nothing
 * saying why. */
#define FZN_NOTES_SYNC_WRITERS_QUERY_LEN 2u
#define FZN_NOTES_SYNC_WRITERS_MAX 64u

#define FZN_NOTES_SYNC_PURGE_LEN (2u + FZN_TREE_ID_LEN)
#define FZN_NOTES_SYNC_PURGE_ACK_LEN (2u + FZN_TREE_ID_LEN + 1u)
/* A PURGE_ACK's answer: erased, which counts toward consent, or not. */
#define FZN_NOTES_SYNC_NOT_ERASED 0u
#define FZN_NOTES_SYNC_ERASED 1u
#define FZN_NOTES_SYNC_PURGES_QUERY_LEN 2u
/* Purges a PURGES names at once; the rest come the next round. */
#define FZN_NOTES_SYNC_PURGES_MAX 16u

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

/* THE SERVER: answer an INDEX_QUERY with a page of the index, a
 * RECORDS_QUERY with as many of the records asked for as fit `reply_cap`, and
 * a PURGE from `sender` -- erased only when `policy` admits `sender`. 0 when
 * `request` is no notes sync message, so a caller dispatching on the first
 * byte can fall through. `sender` may be NULL, and then nothing is erased. */
size_t fzn_notes_sync_answer(const fzn_notes_store_t *store, fzn_notes_policy_t policy,
                             const uint8_t *sender, uint64_t now_ms, const uint8_t *request,
                             size_t request_len, uint8_t *reply, size_t reply_cap);

/* What a SHARE reaches (sec 436): the note ids a contact's request may see. */
typedef struct fzn_notes_sync_scope {
	const uint8_t (*ids)[FZN_TREE_ID_LEN];
	size_t count;
} fzn_notes_sync_scope_t;

/* THE SERVER FOR A SHARE: the index, the records and the writers of only
 * the notes in `scope`, and nothing else -- no purge message is answered and
 * no partner recorded, since a contact is not a member and holds no copy a
 * purge is this node's to ask about. 0 for anything else. */
size_t fzn_notes_sync_answer_scoped(const fzn_notes_store_t *store,
                                    const fzn_notes_sync_scope_t *scope, const uint8_t *request,
                                    size_t request_len, uint8_t *reply, size_t reply_cap);

/* The nodes that pull notes from this one, `cap` of them. */
fzn_notes_err_t fzn_notes_partners(const fzn_notes_store_t *store,
                                   uint8_t (*keys)[FZN_PUBKEY_LEN], size_t cap, size_t *count);

/* When the partner `key` last pulled, by the clock of the node it pulled
 * from. ABSENT when it is no partner, SHAPE when its record will not read. */
fzn_notes_err_t fzn_notes_partner_seen_at(const fzn_notes_store_t *store,
                                          const uint8_t key[FZN_PUBKEY_LEN], uint64_t *ms);

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

/* THE RECIPIENT OF A SHARE, sec 437: ask the sharer who wrote what it
 * shares, then pull as `fzn_notes_sync_pull` does with exactly those writers
 * admitted. `store` is the sharer's tree (`notes/received.h`), so the writers
 * a sharer names are admitted there and nowhere else: the tree is the
 * boundary, and the sharer's node, which the share's grant names, is the
 * authority on who writes in it. SHAPE for a writers answer that will not
 * read. */
fzn_notes_sync_err_t fzn_notes_sync_pull_shared(const fzn_notes_store_t *store,
                                                const fzn_sign_ops_t *sign,
                                                fzn_notes_sync_ask_t ask, void *ask_ctx,
                                                fzn_notes_sync_tally_t *tally);

/* THE SERVER OF A PUSH, sec 446: take the one record a PUSH carries from
 * `sender`, admitted by `policy` as any record is, and only when `policy`
 * admits `sender` itself -- the node pushing is the node vouched for, as a
 * node pulled from is. A note pending purge here is refused, as a pull
 * refuses one. 0 for anything that is not a PUSH. */
size_t fzn_notes_sync_take(const fzn_notes_store_t *store, fzn_notes_policy_t policy,
                           const fzn_sign_ops_t *sign, const uint8_t *sender,
                           const uint8_t *request, size_t request_len, uint8_t *reply,
                           size_t reply_cap);

typedef struct fzn_notes_push_tally {
	size_t offered; /* claims held here that the peer lacked or held older */
	size_t taken;
	size_t held;    /* the peer had it, or newer, by the time it was pushed */
	size_t refused;
} fzn_notes_push_tally_t;

/* THE PUSHER, sec 446: ask the peer `ask` reaches for its index, and push
 * every claim this store holds that the peer lacks or holds older, one
 * record a message. Pulling alone carries a note only to a node that pulls
 * from its writer; a hub pulls from nobody it is not paired to, so without
 * this a member's note reached no one. A note pending purge here is not
 * pushed. */
fzn_notes_sync_err_t fzn_notes_sync_push(const fzn_notes_store_t *store,
                                         fzn_notes_sync_ask_t ask, void *ask_ctx,
                                         fzn_notes_push_tally_t *tally);

/* What one round of the purge conversation did. */
typedef struct fzn_notes_purge_tally {
	size_t asked;    /* own purges sent to the host */
	size_t erased;   /* of those, answered erased */
	size_t refused;  /* of those, answered not erased */
	size_t finished; /* own purges whose consent completed, erased here too */
	size_t taken;    /* the host's purges this node erased and acknowledged */
	size_t declined; /* the host's purges this node would not erase */
} fzn_notes_purge_tally_t;

/* One round of the conversation with the node `host`, reached by `ask`: ask
 * it to erase each note this store has a purge pinning it for, finishing each
 * purge whose consent completes; then take its purges that pin this node,
 * erasing each when `policy` admits `host`, and acknowledge them. */
fzn_notes_sync_err_t fzn_notes_sync_purges(const fzn_notes_store_t *store,
                                           fzn_notes_policy_t policy,
                                           const uint8_t host[FZN_PUBKEY_LEN],
                                           fzn_notes_sync_ask_t ask, void *ask_ctx,
                                           fzn_notes_purge_tally_t *tally);

#endif /* FZN_NOTES_SYNC_H */
