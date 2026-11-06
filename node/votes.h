/*
 * A VALUE CHANGED BY THE ESTATE'S k, project.md sec 909, the holder's: a profile
 * may say a value is changed by k admins of the estate, or a root alone, as a
 * revocation is (sec 403).
 *
 * A VOTE IS A RECORD (`node/records.h`), so it is signed by its voter and reaches
 * every host as a record does: `vote/HOST/KEY` = VALUE, HOST the first 16 hex of the
 * host the value is on. A voter's newest record for a cell is its vote, so voting
 * again replaces it.
 *
 * THE HOST THE VALUE IS ON COUNTS, and writes its own cell at k. It takes nobody's
 * word that k was reached, only the votes, each judged by the standing of who
 * signed it. A vote older than the value in force counts for nothing, so a value
 * changed once cannot be changed back by the same votes.
 *
 * THE VERB:
 *
 *     add vote HOST KEY VALUE    an admin's vote; HOST 64 hex or `self`
 */
#ifndef FZN_NODE_VOTES_H
#define FZN_NODE_VOTES_H

#include <stddef.h>
#include <stdint.h>

#include "records.h"

#define FZN_NODE_VOTE_PREFIX "vote/"
#define FZN_NODE_VOTE_PREFIX_LEN 5u
#define FZN_NODE_VOTE_HOST_HEX 16u
/* What is left of a record's key for the setting's. */
#define FZN_NODE_VOTE_KEY_MAX \
	(FZN_SETTING_KEY_MAX - FZN_NODE_VOTE_PREFIX_LEN - FZN_NODE_VOTE_HOST_HEX - 1u)

/* THIS HOST VOTES `value` FOR `key` ON `host`. MALFORMED past a key's room. */
fzn_node_records_err_t fzn_node_vote(const fzn_node_records_t *nr,
                                     const uint8_t host[FZN_PUBKEY_LEN], const uint8_t *key,
                                     size_t key_len, const uint8_t *value, size_t value_len);

/* WHAT THE COUNT ASKS OF ITS HOST. */
typedef struct fzn_node_vote_ops {
	void *ctx;
	/* 1 when `voter` stands as an admin or a root now. */
	int (*stands)(void *ctx, const uint8_t voter[FZN_PUBKEY_LEN]);
	/* The version, in ms, of the value in force for `key`, 0 for none; and 1
	 * when this value is one the profile gives to a vote. */
	int (*votable)(void *ctx, const uint8_t *key, size_t key_len, uint64_t *in_force_ms);
	/* k reached: the cell written. */
	void (*carried)(void *ctx, const uint8_t *key, size_t key_len, const uint8_t *value,
	                size_t value_len);
} fzn_node_vote_ops_t;

/* THE VOTES HELD FOR THIS HOST, counted against `k`. How many values carried, or -1
 * when the records could not be read. */
long fzn_node_votes_count(const fzn_node_records_t *nr, const uint8_t host[FZN_PUBKEY_LEN],
                          size_t k, const fzn_node_vote_ops_t *ops);

#endif /* FZN_NODE_VOTES_H */
