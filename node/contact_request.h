/*
 * A CONTACT REQUEST, project.md sec 619: fuzzypickles' pairing request
 * (`fzp_pairing_request_t`) brought into fuzznet as step 3c of sec 608,
 * laid out as `node/contact_request.situ`.
 *
 * WHAT IT SAYS, signed by the asker's host: the asker's own contact card
 * (sec 617) -- its user's root, the host and its proof, where it is
 * reached -- the ONE host it is for, a nonce, and when it expires. Sent in
 * a sealed box to that host's prekey (`session/box.h`), which hides it and
 * says nothing about who sent it: what makes a request the asker's is its
 * card holding and the card's host having signed the request.
 *
 * THE TWO QUEUES, both here:
 *
 *   - ASKED OF THIS USER, persist slot FZN_PERSIST_CONTACT_REQUEST, keyed
 *     by the asker's root: what the user approves or rejects. At most
 *     FZN_CONTACT_REQUESTS_MAX; a newer request from the same root replaces
 *     the older, and when full the oldest is let go -- the input is a
 *     stranger's, so it may not fill the store (fuzzypickles' rule).
 *   - ASKED BY THIS USER, persist slot FZN_PERSIST_CONTACT_ASKED, keyed by
 *     the other user's root: the request sent, and the card it was sent
 *     on, so it is sent again until it is answered or expires. The answer
 *     is the other user's first offer of its devices (sec 614), not a
 *     message of its own.
 */
#ifndef FZN_NODE_CONTACT_REQUEST_H
#define FZN_NODE_CONTACT_REQUEST_H

#include <stddef.h>
#include <stdint.h>

#include "contact_card.h"
#include "../persist/persist.h"

#define FZN_CONTACT_REQUEST_VERSION 1u
#define FZN_CONTACT_REQUEST_NONCE_LEN 16u
#define FZN_CONTACT_REQUEST_MAX                                                          \
	(2u + FZN_PUBKEY_LEN + 2u + FZN_CONTACT_CARD_MAX + FZN_CONTACT_REQUEST_NONCE_LEN + 8u \
	 + FZN_SIG_LEN)
/* Requests held at once, of strangers. */
#define FZN_CONTACT_REQUESTS_MAX 16u
/* Requests this user has outstanding. */
#define FZN_CONTACT_ASKED_MAX 16u
/* The furthest ahead a request may say it expires, in seconds: fuzzypickles'
 * default lifetime is about a week, and one claiming more is held no
 * longer. */
#define FZN_CONTACT_REQUEST_LIFE_MAX (30u * 86400u)

typedef enum fzn_contact_request_err {
	FZN_CONTACT_REQUEST_OK = 0,
	FZN_CONTACT_REQUEST_ERR_MALFORMED = -1, /* a null, or a field out of range */
	FZN_CONTACT_REQUEST_ERR_SHAPE = -2,     /* bytes that are not a request */
	FZN_CONTACT_REQUEST_ERR_REFUSED = -3,   /* its card or signature does not hold */
	FZN_CONTACT_REQUEST_ERR_NOT_HERE = -4,  /* for another host */
	FZN_CONTACT_REQUEST_ERR_EXPIRED = -5,   /* past its expiry, or too far ahead */
	FZN_CONTACT_REQUEST_ERR_ABSENT = -6,    /* none held */
	FZN_CONTACT_REQUEST_ERR_BACKEND = -7    /* the store refused, or cannot list */
} fzn_contact_request_err_t;

const char *fzn_contact_request_err_str(fzn_contact_request_err_t err);

typedef struct fzn_contact_request {
	fzn_contact_card_t card;
	uint8_t target[FZN_PUBKEY_LEN];
	uint8_t nonce[FZN_CONTACT_REQUEST_NONCE_LEN];
	uint64_t expires_at;
	uint8_t sig[FZN_SIG_LEN];
} fzn_contact_request_t;

/* SIGN `r` as its card's host, whose secret is behind `sign`. */
fzn_contact_request_err_t fzn_contact_request_sign(fzn_contact_request_t *r,
                                                   const fzn_sign_ops_t *sign);

fzn_contact_request_err_t fzn_contact_request_encode(const fzn_contact_request_t *r,
                                                     uint8_t *out, size_t cap, size_t *len);
fzn_contact_request_err_t fzn_contact_request_decode(const uint8_t *bytes, size_t len,
                                                     fzn_contact_request_t *out);

/* WHETHER `r` HOLDS AS A REQUEST TO `self` at `now` (seconds): its card
 * holds (`fzn_contact_card_verify` for `member`), its card's host signed
 * it, it names `self`, and it has neither expired nor claims to last past
 * FZN_CONTACT_REQUEST_LIFE_MAX. */
fzn_contact_request_err_t fzn_contact_request_verify(const fzn_contact_request_t *r,
                                                     const fzn_sign_ops_t *sign,
                                                     const fzn_cap_id_t *member,
                                                     const uint8_t self[FZN_PUBKEY_LEN],
                                                     uint64_t now);

/* ---- asked of this user ------------------------------------------------- */

typedef struct fzn_contact_request_held {
	fzn_contact_request_t request;
	uint64_t received_at; /* seconds */
} fzn_contact_request_held_t;

/* KEEP `r`, verified, received at `now`: replacing one from the same root,
 * and letting the oldest go when FZN_CONTACT_REQUESTS_MAX are held. */
fzn_contact_request_err_t fzn_contact_request_keep(const fzn_persist_ops_t *store,
                                                   const fzn_contact_request_t *r, uint64_t now);

/* The request held from the user whose root is `root`. */
fzn_contact_request_err_t fzn_contact_request_get(const fzn_persist_ops_t *store,
                                                  const uint8_t root[FZN_PUBKEY_LEN],
                                                  fzn_contact_request_held_t *out);

/* Every request held, oldest first, `cap` of them. */
fzn_contact_request_err_t fzn_contact_request_list(const fzn_persist_ops_t *store,
                                                   fzn_contact_request_held_t *out, size_t cap,
                                                   size_t *count);

/* Let the request from `root` go: approved or rejected. ABSENT when none. */
fzn_contact_request_err_t fzn_contact_request_drop(const fzn_persist_ops_t *store,
                                                   const uint8_t root[FZN_PUBKEY_LEN]);

/* ---- asked by this user ------------------------------------------------- */

typedef struct fzn_contact_asked {
	fzn_contact_card_t card;       /* the other user's, as scanned */
	fzn_contact_request_t request; /* as sent, signed */
	int answered;
} fzn_contact_asked_t;

/* KEEP a request sent on `card`, keyed by the card's root, replacing one
 * held for it. FULL is BACKEND past FZN_CONTACT_ASKED_MAX. */
fzn_contact_request_err_t fzn_contact_asked_keep(const fzn_persist_ops_t *store,
                                                 const fzn_contact_asked_t *a);

fzn_contact_request_err_t fzn_contact_asked_get(const fzn_persist_ops_t *store,
                                                const uint8_t root[FZN_PUBKEY_LEN],
                                                fzn_contact_asked_t *out);

fzn_contact_request_err_t fzn_contact_asked_list(const fzn_persist_ops_t *store,
                                                 fzn_contact_asked_t *out, size_t cap,
                                                 size_t *count);

/* The request to `root` was answered: kept, and sent no more. ABSENT when
 * none was sent. */
fzn_contact_request_err_t fzn_contact_asked_answered(const fzn_persist_ops_t *store,
                                                     const uint8_t root[FZN_PUBKEY_LEN]);

#endif /* FZN_NODE_CONTACT_REQUEST_H */
