/*
 * A CONTACT CARD, project.md sec 617: what a user hands a stranger so that
 * the stranger can ask for contact -- fuzzypickles' contact card (its
 * `fzp_contact_card_t`, sec 10's neighbour) brought into fuzznet as step 3
 * of sec 608, laid out as `node/contact_card.situ`.
 *
 * WHAT IT SAYS, all of it signed by the host it names:
 *
 *   - THE HOST AND WHOSE IT IS: a `node/contact_devices.h` entry -- the
 *     user's root, the host's prekey record, the root's chain to it for the
 *     member capability, and where it is reached. fuzzypickles calls this
 *     the host proof. The root is the contact's key from then on (sec 614:
 *     a contact is added by its user's root).
 *   - SEEDS: up to four more places the user's hosts are reached, each as a
 *     routing manifest's entry is (sec 611) -- address, port, transport,
 *     metric -- "the per-entry shape reused verbatim, NOT the manifest
 *     mechanism itself", as fuzzypickles put it.
 *   - A NAME the user offers, a contact name or none; presentation only.
 *   - WHEN IT EXPIRES, or 0 for never, fuzzypickles' default.
 *
 * NOT PINNED: a card is a first contact, so its root is adopted -- there is
 * nothing to compare it with. What a card proves is that whoever holds the
 * host key signed it and the root's chain names that host; that the root is
 * the person meant is the scan's, as it is for every card here.
 *
 * TEXT is `FZC1:` and unpadded uppercase base32, as `provision/` writes its
 * cards, so a QR code carries it in alphanumeric mode.
 */
#ifndef FZN_NODE_CONTACT_CARD_H
#define FZN_NODE_CONTACT_CARD_H

#include <stddef.h>
#include <stdint.h>

#include "contact_devices.h"

#define FZN_CONTACT_CARD_VERSION 1u
#define FZN_CONTACT_CARD_SEEDS_MAX 4u
#define FZN_CONTACT_CARD_NAME_MAX 32u
#define FZN_CONTACT_CARD_SEED_MAX (1u + FZN_CONTACT_DEVICE_ADDRESS_MAX + 2u + 1u + 1u)
#define FZN_CONTACT_CARD_MAX                                                                  \
	(2u + 2u + FZN_CONTACT_DEVICE_MAX + 1u                                                   \
	 + FZN_CONTACT_CARD_SEEDS_MAX * FZN_CONTACT_CARD_SEED_MAX + 1u + FZN_CONTACT_CARD_NAME_MAX \
	 + 8u + FZN_SIG_LEN)
#define FZN_CONTACT_CARD_TEXT_PREFIX "FZC1:"
#define FZN_CONTACT_CARD_TEXT_PREFIX_LEN 5u
#define FZN_CONTACT_CARD_TEXT_MAX                                                             \
	(FZN_CONTACT_CARD_TEXT_PREFIX_LEN + (FZN_CONTACT_CARD_MAX * 8u + 4u) / 5u + 1u)

typedef enum fzn_contact_card_err {
	FZN_CONTACT_CARD_OK = 0,
	FZN_CONTACT_CARD_ERR_MALFORMED = -1, /* a null, or a field out of range */
	FZN_CONTACT_CARD_ERR_SHAPE = -2,     /* bytes or text that are not a card */
	FZN_CONTACT_CARD_ERR_REFUSED = -3,   /* its signature, record or chain does not hold */
	FZN_CONTACT_CARD_ERR_EXPIRED = -4    /* past its expiry */
} fzn_contact_card_err_t;

const char *fzn_contact_card_err_str(fzn_contact_card_err_t err);

typedef struct fzn_contact_card_seed {
	char address[FZN_CONTACT_DEVICE_ADDRESS_MAX + 1u];
	size_t address_len;
	uint16_t port;
	uint8_t transport;
	uint8_t metric;
} fzn_contact_card_seed_t;

typedef struct fzn_contact_card {
	fzn_contact_device_t host;
	fzn_contact_card_seed_t seeds[FZN_CONTACT_CARD_SEEDS_MAX];
	size_t n_seeds;
	char name[FZN_CONTACT_CARD_NAME_MAX + 1u];
	size_t name_len;
	uint64_t expires_at;
	uint8_t sig[FZN_SIG_LEN];
} fzn_contact_card_t;

/* SIGN `card` as its host, whose secret is behind `sign`: everything but
 * the signature must be filled, the host's key being its record's host.
 * MALFORMED for a field out of range: a name that is not a contact name, a
 * seed with no port, an address of the wrong letters, more than four seeds,
 * or neither the host's address nor a seed to reach it at. */
fzn_contact_card_err_t fzn_contact_card_sign(fzn_contact_card_t *card, const fzn_sign_ops_t *sign);

fzn_contact_card_err_t fzn_contact_card_encode(const fzn_contact_card_t *card, uint8_t *out,
                                               size_t cap, size_t *len);
fzn_contact_card_err_t fzn_contact_card_decode(const uint8_t *bytes, size_t len,
                                               fzn_contact_card_t *out);

/* WHETHER `card` HOLDS at `now` (seconds; 0 skips expiry): its host entry
 * holds (`fzn_contact_device_verify` for `member`) and the host signed the
 * card. REFUSED or EXPIRED otherwise. */
fzn_contact_card_err_t fzn_contact_card_verify(const fzn_contact_card_t *card,
                                               const fzn_sign_ops_t *sign,
                                               const fzn_cap_id_t *member, uint64_t now);

/* The card as text, NUL ended, in `out` of FZN_CONTACT_CARD_TEXT_MAX. */
fzn_contact_card_err_t fzn_contact_card_text(const uint8_t *bytes, size_t len, char *out,
                                             size_t cap);

/* Text back to card bytes: SHAPE for a string not `FZC1:` and base32, or
 * one whose spare bits are not zero -- two strings must not name one card. */
fzn_contact_card_err_t fzn_contact_card_from_text(const char *text, size_t text_len,
                                                  uint8_t *out, size_t cap, size_t *len);

#endif /* FZN_NODE_CONTACT_CARD_H */
