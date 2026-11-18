/*
 * A LINE ABOUT ANOTHER LINE, sec 1282: a reply, which answers one, and a
 * reaction, which marks one. Each names the line by the 16-byte id both
 * ends of a conversation hold for it -- the id a line is delivered under
 * (`messages/deliver.situ`) and a group's line is filed under
 * (`node/group_line.situ`) -- and rides the ordinary text, as a sticker's
 * and an attachment's references do:
 *
 *     fzn:reply/<id hex> <text>
 *     fzn:react/<id hex> <reaction>
 *     fzn:react/<id hex>
 *
 * So both inherit delivery, settlement, a group's sealing and the buckets,
 * and nothing a node stores or lists changes. THE CLIENT READS THEM: a
 * reply is shown with the line it answers, when that line is at hand, and
 * a reaction is folded under the line it names rather than shown as a line
 * of its own -- each sender's newest reaction to a line standing, and one
 * with no reaction taking the sender's back. A client that knows neither
 * shows the text as it is, prefix and all.
 *
 * ONE SPELLING: the id in lower-case hex, one space before what follows.
 * A REPLY'S TEXT is whatever follows, at least one byte, which may itself
 * be a sticker's reference. A REACTION is 1 to FZN_MESSAGE_REACTION_MAX bytes with
 * no space and no control byte -- an emoji, or a short word.
 */
#ifndef FZN_MESSAGES_REPLY_H
#define FZN_MESSAGES_REPLY_H

#include <stddef.h>
#include <stdint.h>

#include "line.h"

#define FZN_MESSAGE_REPLY_SCHEME "fzn:reply/"
#define FZN_MESSAGE_REACTION_SCHEME "fzn:react/"
/* The scheme, the id in hex and the space before the text. */
#define FZN_MESSAGE_REPLY_HEAD_LEN (10u + 2u * FZN_MESSAGE_ID_LEN + 1u)
#define FZN_MESSAGE_REACTION_MAX 32u

/* A REPLY TO `id`: `fzn:reply/ID TEXT` into `out`, NUL ended -- its length,
 * or 0 for no text or a room too small. */
size_t fzn_message_reply_write(const uint8_t id[FZN_MESSAGE_ID_LEN], const char *text, size_t text_len,
                               char *out, size_t cap);

/* `text` READ AS A REPLY: 1 with the line answered in `id` and its own
 * text from `*at`, or 0 -- the text is then the ordinary line it is. */
int fzn_message_reply_parse(const char *text, size_t len, uint8_t id[FZN_MESSAGE_ID_LEN], size_t *at);

/* A REACTION TO `id`: `fzn:react/ID REACTION` into `out`, NUL ended, or with
 * no reaction (`reaction_len` 0) the sender's taken back -- its length, or 0
 * for a reaction this format does not carry or a room too small. */
size_t fzn_message_reaction_write(const uint8_t id[FZN_MESSAGE_ID_LEN], const char *reaction,
                                  size_t reaction_len, char *out, size_t cap);

/* `text` READ AS A REACTION: 1 with the line in `id` and the reaction from
 * `*at`, `*reaction_len` bytes, 0 of them for one taken back; or 0. */
int fzn_message_reaction_parse(const char *text, size_t len, uint8_t id[FZN_MESSAGE_ID_LEN], size_t *at,
                               size_t *reaction_len);

#endif /* FZN_MESSAGES_REPLY_H */
