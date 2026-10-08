/* A node's conversations: `messages/messages.h` behind the daemon's verbs,
 * its devices' streams followed, and conversation keys carried between the
 * user's devices. project.md sec 527, phase 2 of the message move.
 *
 * THE DEVICES are this node and the estate's other nodes -- the user's
 * devices -- whose FZN_MESSAGE_STREAM the journal follows here, so the
 * journal's own pull and push carry their lines and marks both ways. A
 * listing merges them.
 *
 * WHAT A PULL BRINGS IS ABSORBED (`fzn_node_messages_absorb`) from where the
 * last absorb left each device's stream, from the beginning at start: marks
 * become line states, and each line's key is noted -- a key this node lacks
 * is asked for, and one this node drew is given.
 *
 * KEYS TRAVEL MEMBER TO MEMBER, over the authenticated remote hop, in the
 * four messages of `messages/keys.situ`: GIVE (a device's own keys, which is
 * how a hub that pulls from nobody comes by them), GIVEN, WANT (keys for
 * lines this node holds and cannot open) and KEYS. A key given is taken only
 * as the giver's own; the first key held stands. A contact's request never
 * reaches here.
 *
 * NOTHING IS DELETED, as sec 526 records the holder deciding: there is no
 * verb that removes or trims a line.
 */

#ifndef FZN_NODE_MESSAGES_H
#define FZN_NODE_MESSAGES_H

#include <stddef.h>
#include <stdint.h>

#include "../chain/authz.h"
#include "../local/vocabulary.h"
#include "../messages/messages.h"

/* `messages/keys.situ`: notes-sync's version byte, types after notes' 22. */
#define FZN_NODE_MESSAGES_VERSION 2u
#define FZN_NODE_MESSAGES_GIVE 23u
#define FZN_NODE_MESSAGES_GIVEN 24u
#define FZN_NODE_MESSAGES_WANT 25u
#define FZN_NODE_MESSAGES_KEYS 26u
#define FZN_NODE_MESSAGES_PER 8u
#define FZN_NODE_MESSAGES_HEAD_LEN 3u
#define FZN_NODE_MESSAGES_GIVEN_LEN 4u
#define FZN_NODE_MESSAGES_ENTRY_LEN (FZN_PUBKEY_LEN + 4u + FZN_PUBKEY_LEN)
#define FZN_NODE_MESSAGES_HELD_LEN (FZN_NODE_MESSAGES_ENTRY_LEN + FZN_CONVERSATION_KEY_LEN)
#define FZN_NODE_MESSAGES_REQUEST_MAX                                                          \
	(FZN_NODE_MESSAGES_HEAD_LEN + FZN_NODE_MESSAGES_PER * FZN_NODE_MESSAGES_ENTRY_LEN)
#define FZN_NODE_MESSAGES_REPLY_MAX                                                            \
	(FZN_NODE_MESSAGES_HEAD_LEN + FZN_NODE_MESSAGES_PER * FZN_NODE_MESSAGES_HELD_LEN)

/* The keys remembered between absorbs: lacked, and this node's own to give.
 * Past these, the rest are learned again at the next start. */
#define FZN_NODE_MESSAGES_KEYS_MAX 64u

/* One conversation key's place: whose lines, which month, which device. */
typedef struct fzn_node_message_key {
	uint8_t contact[FZN_PUBKEY_LEN];
	uint32_t epoch;
	uint8_t device[FZN_PUBKEY_LEN];
} fzn_node_message_key_t;

typedef struct fzn_node_messages {
	fzn_messages_t m;
	uint8_t devices[FZN_MESSAGES_DEVICES_MAX][FZN_PUBKEY_LEN];
	/* Where each device's stream was last absorbed to. */
	struct {
		uint8_t key[FZN_PUBKEY_LEN];
		uint64_t at;
	} cursors[FZN_MESSAGES_DEVICES_MAX];
	size_t n_cursors;
	fzn_node_message_key_t lacks[FZN_NODE_MESSAGES_KEYS_MAX];
	size_t n_lacks;
	fzn_node_message_key_t gives[FZN_NODE_MESSAGES_KEYS_MAX];
	size_t n_gives;
	/* Keys noted past the room above. */
	size_t dropped;
} fzn_node_messages_t;

typedef struct fzn_node_messages_tally {
	size_t marks;    /* marks absorbed */
	size_t given;    /* keys a peer took */
	size_t refused;  /* keys a peer refused, another being held there */
	size_t taken;    /* keys taken from a peer */
	size_t lacking;  /* keys still lacked */
} fzn_node_messages_tally_t;

/* Point `nm` at its store, journal and this node's key. All borrowed. */
fzn_messages_err_t fzn_node_messages_init(fzn_node_messages_t *nm,
                                          const fzn_persist_ops_t *store,
                                          fzn_node_journal_t *journal, const uint8_t *issuer,
                                          const fzn_sign_ops_t *sign,
                                          const fzn_random_ops_t *rng,
                                          const fzn_aead_ops_t *aead,
                                          const fzn_hash_ops_t *hash, uint64_t (*now)(void));

/* THE DEVICES: this node first, then `keys` (`n` of them) not already
 * listed, each one's FZN_MESSAGE_STREAM followed in the journal. How many
 * are listed; a device past FZN_MESSAGES_DEVICES_MAX, or one the journal
 * has no room to follow, is left out. */
size_t fzn_node_messages_devices(fzn_node_messages_t *nm, const uint8_t (*keys)[FZN_PUBKEY_LEN],
                                 size_t n);

/* ABSORB every device's stream from where it was last absorbed. */
fzn_messages_err_t fzn_node_messages_absorb(fzn_node_messages_t *nm,
                                            fzn_node_messages_tally_t *tally);

/* How a node asks a member: send `request`, fill `reply`. Nonzero on an
 * answer. */
typedef int (*fzn_node_messages_ask_t)(void *ctx, const uint8_t *request, size_t request_len,
                                       uint8_t *reply, size_t reply_cap, size_t *reply_len);

/* ONE ROUND WITH A MEMBER: give it this node's keys, and ask it for those
 * lacked. A key it takes or refuses is given no more; one it supplies is
 * lacked no more. 0 when it would not answer. */
int fzn_node_messages_round(fzn_node_messages_t *nm, fzn_node_messages_ask_t ask, void *ctx,
                            fzn_node_messages_tally_t *tally);

/* A MEMBER'S GIVE or WANT, answered; 0 for anything else, so a caller
 * dispatching on the first bytes falls through. `sender` is the member. */
size_t fzn_node_messages_remote(void *ctx, const uint8_t *sender, const uint8_t *request,
                                size_t request_len, uint8_t *reply, size_t reply_cap);

/*
 * THE VERBS, for this node's own user only; 0 for what is not one. WHO is a
 * contact's name or its key in hex, ID 32 hex digits, the text the rest of
 * the line with %XX undone (so a newline is %0a) or `file PATH`:
 *
 *   add message WHO out|in ID [at MS] TEXT | file PATH
 *   set message WHO out|in ID delivered|settled|handed-over|not-delivered
 *   list message [WHO] [FROM]
 *
 * A listing answers `ok FROM SHOWN MORE` then each line as
 * KEY,NAME,ID,DIRECTION,STATE,STIME,WRITTEN,READABLE,TEXT -- NAME `-` for a
 * key no contact holds, STATE `-` for none, TEXT escaped -- as many as fit;
 * the next page is asked FROM + SHOWN.
 */
size_t fzn_node_messages_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                               char *reply, size_t reply_cap);

#endif /* FZN_NODE_MESSAGES_H */
