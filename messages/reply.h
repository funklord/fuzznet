/*
 * A LINE ABOUT ANOTHER LINE, sec 1282: a reply, which answers one, and a
 * reaction, which marks one; and sec 1284's unsend, which takes one back.
 * Each names the line by its 16-byte id -- one to one, the id both ends
 * hold, the one a line is delivered under (`messages/deliver_wire.situ`). IN A
 * GROUP the ids differ, sec 1284: a member's line is filed on every other
 * member's node under a hash of its sealing host and its id
 * (`fzn_group_lines_filed_id`), while its author's devices hold it by the
 * id itself, so a reference to an author's own line and one to another's
 * do not yet resolve alike. They ride the ordinary text, as a sticker's
 * and an attachment's references do:
 *
 *     fzn:reply/<id hex> <text>
 *     fzn:react/<id hex> <reaction>
 *     fzn:react/<id hex>
 *     fzn:unsend/<id hex>
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
#define FZN_MESSAGE_UNSEND_SCHEME "fzn:unsend/"
#define FZN_MESSAGE_UNSEND_LEN (11u + 2u * FZN_MESSAGE_ID_LEN)
/* HOW LONG AFTER IT WAS SENT A LINE MAY BE TAKEN BACK, sec 1284, the
 * holder's: an hour, by the sender's own times for both. */
#define FZN_MESSAGE_UNSEND_WINDOW_MS (60u * 60u * 1000u)

/* A REPLY TO `id`: `fzn:reply/ID TEXT` into `out`, NUL ended -- its length,
 * or 0 for no text or a room too small. */
size_t fzn_message_reply_write(const uint8_t id[FZN_MESSAGE_ID_LEN], const char *text, size_t text_len,
                               char *out, size_t cap);

/* `text` READ AS A REPLY: 1 with the line answered in `id` and its own
 * text from `*at`, or 0 -- the text is then the ordinary line it is. */
int fzn_message_reply_parse(const char *text, size_t len, uint8_t id[FZN_MESSAGE_ID_LEN], size_t *at);

/* A LINE'S OWN TEXT, sec 1355: a reply's after its head, any other line's
 * whole -- what a sticker's or a file's reference is read from, so a reply
 * carrying one is granted and fetched as the plain line is. A reaction's
 * text is never a reference, and is handed back whole. */
const char *fzn_message_own_text(const char *text, size_t len, size_t *own_len);

/* A REACTION TO `id`: `fzn:react/ID REACTION` into `out`, NUL ended, or with
 * no reaction (`reaction_len` 0) the sender's taken back -- its length, or 0
 * for a reaction this format does not carry or a room too small. */
size_t fzn_message_reaction_write(const uint8_t id[FZN_MESSAGE_ID_LEN], const char *reaction,
                                  size_t reaction_len, char *out, size_t cap);

/* `text` READ AS A REACTION: 1 with the line in `id` and the reaction from
 * `*at`, `*reaction_len` bytes, 0 of them for one taken back; or 0. */
int fzn_message_reaction_parse(const char *text, size_t len, uint8_t id[FZN_MESSAGE_ID_LEN], size_t *at,
                               size_t *reaction_len);

/* AN UNSEND, sec 1284: unlike a reply or a reaction it is NOT the client's
 * to read. It asks the node that receives it to let the line `id` go -- the
 * sender's own, sent within FZN_MESSAGE_UNSEND_WINDOW_MS of it -- and that
 * node honours it only where its user has unsend on (`message/unsend`); it
 * is never filed or listed as a line. `fzn:unsend/ID` into `out`, NUL
 * ended: its length, or 0 for a room too small. */
size_t fzn_message_unsend_write(const uint8_t id[FZN_MESSAGE_ID_LEN], char *out, size_t cap);

/* `text` READ AS AN UNSEND, exactly: 1 with the line in `id`, or 0. */
int fzn_message_unsend_parse(const char *text, size_t len, uint8_t id[FZN_MESSAGE_ID_LEN]);

#endif /* FZN_MESSAGES_REPLY_H */
