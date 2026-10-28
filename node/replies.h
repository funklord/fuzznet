/*
 * THE REPLIES A NODE SENT, kept a few seconds, sec 737: so a request its
 * caller resent -- the first or its answer lost -- is answered again
 * without running its handler again. A handler that writes (a gift of
 * keys, a vote, a pairing) would otherwise act twice.
 *
 * A REQUEST IS THE SAME ONE when its sender, its message number and its
 * bytes match. The bytes are in the key, by hash, because a caller made
 * afresh numbers its messages from 0: a host started again would
 * otherwise be answered its last run's reply to a different request.
 *
 * A PIECE OF A REQUEST ANSWERED ALREADY, sec 741, is known by its sender,
 * its message number and its expiry, a piece carrying no bytes of the
 * whole to hash: a resend keeps its expiry, and a host started again
 * stamps a later one. Without it a late piece opened a partial nothing
 * finished, holding its sender's one reassembly slot for the hold.
 *
 * BOUNDED IN ENTRIES AND IN BYTES, the oldest let go first. Letting one
 * go loses nothing but the saving: a resend of it runs its handler.
 */
#ifndef FZN_NODE_REPLIES_H
#define FZN_NODE_REPLIES_H

#include <stddef.h>
#include <stdint.h>

#include "../session/commitment.h"

#define FZN_NODE_REPLIES_DIGEST_LEN 32u
/* LONGER THAN A CALLER WAITS, 3 s, so a resend near its deadline still
 * finds its reply; short, so a host started again that asks the same
 * thing a few seconds later is not answered from its last run. */
#define FZN_NODE_REPLIES_TTL_S 6u

typedef struct fzn_node_reply_kept {
	uint8_t sender[32];
	uint32_t msg;
	uint64_t expires_at;
	uint8_t digest[FZN_NODE_REPLIES_DIGEST_LEN];
	uint64_t at;
	size_t len;
	uint8_t *bytes;
} fzn_node_reply_kept_t;

typedef struct fzn_node_replies {
	fzn_node_reply_kept_t *kept;
	size_t cap;
	size_t n;
	size_t bytes;
	size_t bytes_max;
	uint64_t ttl_s;
	const fzn_hash_ops_t *hash;
} fzn_node_replies_t;

/* Over `cap` entries the caller gives, at most `bytes_max` of replies
 * held, each kept `ttl_s` seconds. 0 for a null or a zero. */
int fzn_node_replies_init(fzn_node_replies_t *r, fzn_node_reply_kept_t *kept, size_t cap,
                          size_t bytes_max, uint64_t ttl_s, const fzn_hash_ops_t *hash);

/* THE REPLY KEPT for this request at `now` (seconds), `*len` of it; NULL
 * when none is, or it has expired. */
const uint8_t *fzn_node_replies_find(fzn_node_replies_t *r, const uint8_t sender[32],
                                     uint32_t msg, const uint8_t *request, size_t request_len,
                                     uint64_t now, size_t *len);

/* THE REPLY KEPT for a request of which a piece came, by sender, message
 * and expiry, sec 741; NULL as above, and for an expiry of 0, which tells
 * no request from another. */
const uint8_t *fzn_node_replies_find_piece(fzn_node_replies_t *r, const uint8_t sender[32],
                                           uint32_t msg, uint64_t expires_at, uint64_t now,
                                           size_t *len);

/* KEEP `reply` for this request, which expires at `expires_at`, at `now`.
 * Quietly not, when it is larger than the whole bound or memory is short. */
void fzn_node_replies_keep(fzn_node_replies_t *r, const uint8_t sender[32], uint32_t msg,
                           uint64_t expires_at, const uint8_t *request, size_t request_len,
                           uint64_t now, const uint8_t *reply, size_t reply_len);

/* Every reply let go. */
void fzn_node_replies_free(fzn_node_replies_t *r);

#endif /* FZN_NODE_REPLIES_H */
