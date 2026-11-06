/*
 * AN INVITE: one code a host shows, and a device that reads it joins, project.md
 * sec 896. netcfgd's: a phone has a camera and a host has none, so of a join's
 * two carries (`get prekey` to the host, a card back) only one has a road. An
 * invite makes that one enough. The other goes over the network, sealed.
 *
 * WHAT THE TEXT SAYS: `FZI1:` and RFC 4648 base32, upper case with no padding,
 * so a QR code takes it in its alphanumeric mode:
 *
 *     host   32    the inviting host's key: whose card to accept
 *     agree  32    its box key: what the device seals to
 *     secret 16    one use, what lets a stranger's box through
 *     port    2
 *     where        the rest, its address, letters, digits and `.-:`
 *
 * THE EXCHANGE, each a box (`session/box.h`) in one datagram, sent again by the
 * device until it is answered or the invite lapses:
 *
 *     ask     `FZI` 1, the secret, the device's prekey record
 *     answer  `FZI` 2, the secret, this part, the parts, a piece of the card
 *
 * A card can pass a datagram, so it goes in parts. The ask is safe to repeat:
 * the same device is answered the same card, and any other refused.
 *
 * WHO IS BELIEVED. The device believes a card signed by `host`, as a card says of
 * its sponsor, so a person who photographed the text cannot answer with a card of
 * their own. The host, by one of two kinds of invite, the holder's of 2026-11-05:
 *
 *   OPEN      the secret alone: whoever holds the text joins.
 *   CONFIRMED the first device to ask waits, named to the host's user, until
 *             `grant invite KEY`; `remove invite KEY` turns it away. Its asks go
 *             on meanwhile, and the first after the grant is answered the card.
 *
 * `add invite` says which, or the host setting `invite/confirm` does.
 */

#ifndef FZN_NODE_INVITE_H
#define FZN_NODE_INVITE_H

#include <stddef.h>
#include <stdint.h>

#include "../prekey/prekey.h"
#include "../provision/provision.h"

#define FZN_INVITE_TEXT_PREFIX "FZI1:"
#define FZN_INVITE_TEXT_PREFIX_LEN 5u
#define FZN_INVITE_SECRET_LEN 16u
#define FZN_INVITE_WHERE_MAX 45u
#define FZN_INVITE_FIXED_LEN (2u * FZN_PUBKEY_LEN + FZN_INVITE_SECRET_LEN + 2u)
#define FZN_INVITE_TEXT_MAX \
	(FZN_INVITE_TEXT_PREFIX_LEN + ((FZN_INVITE_FIXED_LEN + FZN_INVITE_WHERE_MAX) * 8u + 4u) / 5u + 1u)
/* THE SECRET IS KEPT IN MEMORY ALONE, so a restart ends every invite. As many
 * may be open as a host's user makes, sec 903. */
#define FZN_INVITE_LIFE_S 600u
#define FZN_INVITE_LIFE_MAX_S 86400u

#define FZN_INVITE_MARK_LEN 4u
#define FZN_INVITE_ASK_LEN (FZN_INVITE_MARK_LEN + FZN_INVITE_SECRET_LEN + FZN_PREKEY_LEN_TOTAL)
#define FZN_INVITE_PART_MAX 900u
#define FZN_INVITE_ANSWER_HEAD (FZN_INVITE_MARK_LEN + FZN_INVITE_SECRET_LEN + 2u)
#define FZN_INVITE_ANSWER_MAX (FZN_INVITE_ANSWER_HEAD + FZN_INVITE_PART_MAX)
#define FZN_INVITE_PARTS(len) (((len) + FZN_INVITE_PART_MAX - 1u) / FZN_INVITE_PART_MAX)

typedef struct fzn_invite {
	uint8_t host[FZN_PUBKEY_LEN];
	uint8_t agree[FZN_PUBKEY_LEN];
	uint8_t secret[FZN_INVITE_SECRET_LEN];
	char where[FZN_INVITE_WHERE_MAX + 1u];
	size_t where_len;
	uint16_t port;
} fzn_invite_t;

/* AS TEXT into `out`, FZN_INVITE_TEXT_MAX bytes, NUL-ended: its length, or 0
 * for an address past its bound or out of shape. */
size_t fzn_invite_text(const fzn_invite_t *in, char *out, size_t cap);

/* FROM TEXT: 1, or 0 for what is no invite. */
int fzn_invite_parse(const char *text, size_t len, fzn_invite_t *out);

/* WHAT A BOX HOLDS: 1 for an ask, 2 for an answer, 0 for neither. */
int fzn_invite_kind(const uint8_t *plain, size_t len);

/* THE ASK: FZN_INVITE_ASK_LEN bytes into `out`. */
void fzn_invite_ask(const uint8_t secret[FZN_INVITE_SECRET_LEN],
                    const uint8_t record[FZN_PREKEY_LEN_TOTAL], uint8_t out[FZN_INVITE_ASK_LEN]);

/* ANSWER PART `part` of a card of `card_len` bytes, into `out`
 * (FZN_INVITE_ANSWER_MAX): its length, or 0 past the last part. */
size_t fzn_invite_answer(const uint8_t secret[FZN_INVITE_SECRET_LEN], const uint8_t *card,
                         size_t card_len, size_t part, uint8_t *out);

/* ---- what a device gathers ------------------------------------------------ */

typedef struct fzn_invite_card {
	uint8_t bytes[FZN_PROVISION_MAX_LEN];
	uint8_t have[(FZN_PROVISION_MAX_LEN / FZN_INVITE_PART_MAX) + 2u];
	size_t parts, len;
} fzn_invite_card_t;

/* AN ANSWER TAKEN INTO `c`, for the invite of `secret`: 1 when the card is
 * whole, 0 while parts are wanted or this was none of it. */
int fzn_invite_card_take(fzn_invite_card_t *c, const uint8_t secret[FZN_INVITE_SECRET_LEN],
                         const uint8_t *plain, size_t len);

/* ---- what a host keeps ---------------------------------------------------- */

typedef struct fzn_invite_open {
	int used;                               /* the row is taken */
	uint8_t secret[FZN_INVITE_SECRET_LEN];
	uint64_t expires_at;
	int delegable;
	int confirm;                            /* a person says yes first */
	int asked;                              /* `device` waits on that */
	int approved;                           /* and has it */
	int claimed;                            /* a device has it */
	uint8_t device[FZN_PUBKEY_LEN];
	uint8_t card[FZN_PROVISION_MAX_LEN];
	size_t card_len;
} fzn_invite_open_t;

typedef struct fzn_invites {
	fzn_invite_open_t *rows;
	size_t cap;
} fzn_invites_t;

/* A NEW ONE: its row, a lapsed one's where there is one, or NULL with no
 * memory. A row is good until the next add. */
fzn_invite_open_t *fzn_invites_add(fzn_invites_t *t, const uint8_t secret[FZN_INVITE_SECRET_LEN],
                                   int delegable, int confirm, uint64_t now, uint64_t expires_at);

/* THE ROW OF `secret` THAT `device` MAY HAVE: unclaimed and not lapsed, or
 * claimed by this device, which is the ask sent again and may outlast the
 * invite's life while its card is fetched. One waiting on a person is this
 * device's alone. NULL otherwise. */
fzn_invite_open_t *fzn_invites_find(fzn_invites_t *t, const uint8_t secret[FZN_INVITE_SECRET_LEN],
                                    const uint8_t device[FZN_PUBKEY_LEN], uint64_t now);

/* THE ROW WHERE `device` WAITS ON A PERSON, or NULL. */
fzn_invite_open_t *fzn_invites_waiting(fzn_invites_t *t, const uint8_t device[FZN_PUBKEY_LEN],
                                       uint64_t now);

/* EVERY INVITE ENDED, secret and card wiped: how many were live. */
size_t fzn_invites_clear(fzn_invites_t *t, uint64_t now);

/* HOW MANY ARE LIVE. */
size_t fzn_invites_live(const fzn_invites_t *t, uint64_t now);

#endif /* FZN_NODE_INVITE_H */
