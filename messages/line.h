/* A conversation line and a mark on one: the record bodies, and the sealing
 * of a line's text. project.md sec 526; `messages/line.situ` is the
 * contract.
 *
 * A LINE IS A RECORD on the writing device's FZN_MESSAGE_STREAM, its subject
 * the contact's key, so a user's devices carry each other's lines by the one
 * journal sync and the direction travels with the line. Its text is sealed
 * under the conversation's key for the month it was written in (its epoch),
 * which is kept beside the store and never in the journal: a record is
 * never forgotten, so a rule that trims a month (none is built, and none
 * runs by default -- the holder, 2026-10-08) destroys that month's key and
 * leaves the records as shells.
 *
 * A TEXT LONGER THAN ONE RECORD HOLDS IS TWO PARTS, each its own record, its
 * own nonce and its own tag, written one after the other. The additional
 * data binds each part to its conversation, its id, its direction, its
 * place among the parts and its sender's time, so no part opens anywhere it
 * was not sealed for.
 *
 * A MARK sets a line's state after it was written: delivered, settled,
 * handed over to another of the user's devices, or not delivered. The
 * latest mark is the line's state.
 *
 * A READ POSITION, sec 528, says a conversation was read up to a line; the
 * latest is the conversation's, wherever it was written.
 */

#ifndef FZN_MESSAGES_LINE_H
#define FZN_MESSAGES_LINE_H

#include <stddef.h>
#include <stdint.h>

#include "../record/record.h"
#include "../session/aead.h"

/* The stream, in fuzznet's reserved range: 0 notes, 1 estate, 2 the
 * operation journal's own. */
#define FZN_MESSAGE_STREAM 3u
#define FZN_MESSAGE_LINE_KIND 0x37u
#define FZN_MESSAGE_MARK_KIND 0x137u
/* A conversation read up to a line, sec 528. */
#define FZN_MESSAGE_READ_KIND 0x237u

#define FZN_MESSAGE_VERSION 1u
#define FZN_MESSAGE_ID_LEN 16u
/* fuzzypickles' FZP_PEER_TEXT_MAX: a line holds what a peer may send. */
#define FZN_MESSAGE_TEXT_MAX 512u

#define FZN_MESSAGE_OUT 1u
#define FZN_MESSAGE_IN 2u

#define FZN_MESSAGE_DELIVERED 1u
#define FZN_MESSAGE_SETTLED 2u
#define FZN_MESSAGE_HANDED_OVER 3u
#define FZN_MESSAGE_NOT_DELIVERED 4u

/* `messages/line.situ`. */
#define FZN_MESSAGE_LINE_OFF_VERSION 0u
#define FZN_MESSAGE_LINE_OFF_DIRECTION 1u
#define FZN_MESSAGE_LINE_OFF_PART 2u
#define FZN_MESSAGE_LINE_OFF_PARTS 3u
#define FZN_MESSAGE_LINE_OFF_ID 4u
#define FZN_MESSAGE_LINE_OFF_STIME 20u
#define FZN_MESSAGE_LINE_OFF_EPOCH 28u
#define FZN_MESSAGE_LINE_OFF_NONCE 32u
#define FZN_MESSAGE_LINE_OFF_TAG 56u
#define FZN_MESSAGE_LINE_HEAD 72u
/* The most sealed text one record carries, and so the parts a text takes. */
#define FZN_MESSAGE_PART_MAX (FZN_RECORD_BODY_MAX - FZN_MESSAGE_LINE_HEAD)
#define FZN_MESSAGE_PARTS_MAX 2u

#define FZN_MESSAGE_MARK_OFF_VERSION 0u
#define FZN_MESSAGE_MARK_OFF_DIRECTION 1u
#define FZN_MESSAGE_MARK_OFF_STATE 2u
#define FZN_MESSAGE_MARK_OFF_ID 3u
#define FZN_MESSAGE_MARK_LEN 19u

#define FZN_MESSAGE_READ_OFF_VERSION 0u
#define FZN_MESSAGE_READ_OFF_ID 1u
#define FZN_MESSAGE_READ_LEN 17u

/* A conversation's key for one epoch. */
#define FZN_CONVERSATION_KEY_LEN FZN_AEAD_KEY_LEN

/* One part of a line, as its record body says. `text` points into the
 * body it was opened from, sealed. */
typedef struct fzn_message_part {
	uint8_t direction;
	uint8_t part;
	uint8_t parts;
	uint8_t id[FZN_MESSAGE_ID_LEN];
	uint64_t stime;
	uint32_t epoch;
	uint8_t nonce[FZN_AEAD_NONCE_LEN];
	uint8_t tag[FZN_AEAD_TAG_LEN];
	const uint8_t *text;
	size_t text_len;
} fzn_message_part_t;

typedef struct fzn_message_mark {
	uint8_t direction;
	uint8_t state;
	uint8_t id[FZN_MESSAGE_ID_LEN];
} fzn_message_mark_t;

/* How many parts a text of `len` bytes takes: 1 or 2, 0 past the most. */
size_t fzn_message_parts_for(size_t len);

/* THE EPOCH of a time: whole months since January 1970, UTC. A month
 * because "keep a year" is the shape a trimming rule takes, and the key it
 * destroys must not hold anything younger than what the rule names. */
uint32_t fzn_message_epoch_of(uint64_t ms);

/* When epoch `epoch` begins: its month's first millisecond, UTC. */
uint64_t fzn_message_epoch_start(uint32_t epoch);

/*
 * SEAL part `part` of `parts` of `text` (`len` bytes in all) into `body`,
 * FZN_RECORD_BODY_MAX bytes, `*body_len` of them, under `key` for `contact`
 * and `nonce`. Nonzero on success; zero for a malformed part or a seal that
 * refused, `body` wiped.
 */
int fzn_message_line_seal(const fzn_aead_ops_t *aead, const uint8_t key[FZN_CONVERSATION_KEY_LEN],
                           const uint8_t contact[FZN_PUBKEY_LEN], uint8_t direction,
                           const uint8_t id[FZN_MESSAGE_ID_LEN], uint64_t stime, uint32_t epoch,
                           const uint8_t nonce[FZN_AEAD_NONCE_LEN], const uint8_t *text,
                           size_t len, uint8_t part, uint8_t parts, uint8_t *body,
                           size_t *body_len);

/* Read a line record's body. Nonzero when it is a line part this version
 * writes; the text stays sealed. */
int fzn_message_line_read(const uint8_t *body, size_t len, fzn_message_part_t *out);

/* Open one part's text into `out`, `cap` bytes, `*out_len` of them, under
 * `key` for `contact`. Nonzero only when it opens. */
int fzn_message_line_open(const fzn_aead_ops_t *aead, const uint8_t key[FZN_CONVERSATION_KEY_LEN],
                          const uint8_t contact[FZN_PUBKEY_LEN], const fzn_message_part_t *p,
                          uint8_t *out, size_t cap, size_t *out_len);

int fzn_message_mark_write(const fzn_message_mark_t *m, uint8_t out[FZN_MESSAGE_MARK_LEN]);
int fzn_message_mark_read(const uint8_t *body, size_t len, fzn_message_mark_t *out);

/* A read position's body: the id of the line read up to. */
int fzn_message_position_write(const uint8_t id[FZN_MESSAGE_ID_LEN],
                               uint8_t out[FZN_MESSAGE_READ_LEN]);
int fzn_message_position_read(const uint8_t *body, size_t len, uint8_t id[FZN_MESSAGE_ID_LEN]);

#endif /* FZN_MESSAGES_LINE_H */
