/*
 * A PROVISIONING CARD: the bytes one device hands another out of band.
 *
 * The software half of scanning a code. A device holding no anchor, no
 * capability and no session is handed one object, and afterwards can verify a
 * chain, establish a session and be authorised. project.md sec 71.
 *
 * WHY THIS IS THE LIBRARY'S AND NOT A CONSUMER'S. It was a test's encoding
 * first, on a misreading of sec 2 -- that section scopes its exclusion to THE
 * LOCAL HOP, the AF_UNIX socket between a consumer's own CLI and its own
 * daemon, where two consumers disagree about the encoding and both
 * disagreements are load-bearing. Its test is "is this anybody's
 * APPLICATION", not "is this an encoding". A provisioning card is neither
 * local nor anybody's application: it crosses the trust boundary, which sec 2
 * says is the shared half, and every consumer that provisions a device needs
 * the same bytes. Four consumers hand-rolling one framing is the duplication
 * sec 15 says this library exists to remove.
 *
 * WHAT IT CARRIES, and why each part is there:
 *
 *   root        the anchor to pin. Shipped rather than read out of the hop,
 *               even though the hop's grantor field holds the same key,
 *               because taking the anchor out of the object it is about to
 *               authenticate is circular -- trust on first use with extra
 *               steps. Shipped, the pin is auditable: a device compares what
 *               it pinned against what the hop claims.
 *   hop         the grant naming this device as grantee. It is what lets the
 *               device ACT rather than merely listen.
 *   prekey      the sponsor's prekey record, so a session can be established
 *               from published keys alone with no further round trip.
 *   expires_at  a card is a reusable credential, so it is bounded. 0 is
 *               never, which a card printed on a machine's case wants and a
 *               card mailed to somebody does not.
 *
 * THE OUTER SIGNATURE BINDS THE PARTS, AND THAT IS ITS WHOLE JOB. Each of the
 * three inner objects is independently signed already and stays that way.
 * What none of them says is that they belong together. Without the envelope a
 * stranger takes a genuine hop -- public, and minted for a device the sponsor
 * really did grant -- and pairs it with their OWN prekey record, which is
 * self-signed and therefore perfectly valid. The device pins the attacker as
 * its sponsor, establishes a session with them, and holds a genuine grant
 * while doing it. The signature over the concatenation is what refuses that,
 * and it is signed by the root, which is the one key the scan authenticates.
 *
 * WHAT IT IS NOT. It is not an image. There is no QR encoder, no decoder, no
 * bitmap and no camera here: `fzn_provision_text` produces the STRING a code
 * would carry and stops there. Turning a string into a photograph is a
 * barcode library's job and not a protocol library's, and fuzzypickles
 * already vendors quirc for the other direction.
 *
 * THE EXCHANGE IS TWO-WAY, WHICH IS ARITHMETIC RATHER THAN A CHOICE. A hop
 * names its grantee, so a sponsor cannot mint one until it knows the device's
 * identity key: a one-way card cannot provision a device the sponsor has
 * never seen. The device shows its own prekey record first -- 138 bytes,
 * self-signed, already a "here is me" object -- and the sponsor answers with
 * a card. Nothing new was needed for that leg.
 */

#ifndef FZN_PROVISION_H
#define FZN_PROVISION_H

#include <stddef.h>
#include <stdint.h>

#include "../chain/chain.h"
#include "../prekey/prekey.h"

/* THE CARD LAYOUT. Big-endian, fixed width, no padding, fixed fields first --
 * `wire/bytes.h`'s rule, and for its reason: two implementations that agree
 * on this table cannot produce different bytes for the same card, which is
 * what a signature over them requires.
 *
 *     offset  size  field
 *          0     1  version    (= FZN_SIGNED_VERSION)
 *          1     1  object     (= FZN_OBJECT_PROVISION)
 *          2    32  root
 *         34   179  hop
 *        213   138  prekey record
 *        351     8  expires_at
 *        359    64  signature
 *
 * Every field is fixed length, so the card is self-delimiting and needs no
 * length prefixes: a reader slices at these offsets and hands each slice to
 * the call that owns it. `fzn_hop_open` and `fzn_prekey_open` both refuse a
 * wrong length outright, so a mis-slice fails at a parser rather than
 * becoming a subtly wrong grant. */
#define FZN_PROVISION_OFF_VERSION    0u
#define FZN_PROVISION_OFF_OBJECT     (FZN_PROVISION_OFF_VERSION + 1u)
#define FZN_PROVISION_OFF_ROOT       (FZN_PROVISION_OFF_OBJECT + 1u)
#define FZN_PROVISION_OFF_HOP        (FZN_PROVISION_OFF_ROOT + FZN_PUBKEY_LEN)
#define FZN_PROVISION_OFF_PREKEY     (FZN_PROVISION_OFF_HOP + FZN_HOP_LEN)
#define FZN_PROVISION_OFF_EXPIRES_AT (FZN_PROVISION_OFF_PREKEY + FZN_PREKEY_LEN_TOTAL)
#define FZN_PROVISION_OFF_SIGNATURE  (FZN_PROVISION_OFF_EXPIRES_AT + 8u)

/* The bytes the signature covers: everything before it. */
#define FZN_PROVISION_BODY_LEN FZN_PROVISION_OFF_SIGNATURE
#define FZN_PROVISION_LEN_TOTAL (FZN_PROVISION_BODY_LEN + FZN_SIG_LEN)

/* A card as text, which is what a code actually carries.
 *
 * RFC 4648 base32, uppercase, unpadded, behind a version prefix. Base32 and
 * not base64 because QR alphanumeric mode covers 0-9, A-Z and a handful of
 * symbols including `:` -- so an uppercase base32 card encodes in that mode
 * rather than falling back to byte mode, which costs about 45% more bits per
 * character. Unpadded because `=` is not in that alphabet and the length is
 * fixed anyway, so padding would carry no information at the price of leaving
 * the mode.
 *
 * The prefix is a version rather than decoration: a scanner meeting a string
 * it does not understand should say so rather than base32-decoding whatever
 * it was handed into a card-shaped buffer. */
#define FZN_PROVISION_TEXT_PREFIX "FZN1:"
#define FZN_PROVISION_TEXT_PREFIX_LEN 5u
/* The UNPADDED length: five bits per character over the whole card, rounded
 * up. Written `((LEN + 4) / 5) * 8` first, which is the length base32 has WITH
 * padding -- a multiple of eight characters -- and so three too long. The
 * decoder would have run three characters past the card and refused every
 * genuine one. Caught by deriving the spare-bit count for the test rather than
 * by the arithmetic looking wrong, which it did not. */
#define FZN_PROVISION_TEXT_BODY_LEN ((FZN_PROVISION_LEN_TOTAL * 8u + 4u) / 5u)
/* Plus the terminating NUL, which `fzn_provision_text` writes. */
#define FZN_PROVISION_TEXT_LEN \
	(FZN_PROVISION_TEXT_PREFIX_LEN + FZN_PROVISION_TEXT_BODY_LEN + 1u)

typedef enum fzn_provision_err {
	FZN_PROVISION_OK = 0,
	/* The caller's bug: a null, a buffer too small. */
	FZN_PROVISION_ERR_MALFORMED = 1,
	/* Somebody's bytes are not this shape: a wrong length, a version or an
	 * object tag that is not ours, a prefix that is not ours, a character
	 * outside the alphabet. */
	FZN_PROVISION_ERR_SHAPE = 2,
	/* The envelope signature does not verify under the root the card
	 * names. The parts may each be genuine and not belong together. */
	FZN_PROVISION_ERR_SIGNATURE = 3,
	/* The signer refused, or was absent. */
	FZN_PROVISION_ERR_SIGNER = 4,
	/* The card's expiry has passed. Separate from SHAPE because a card
	 * that was valid and is not any more is an ordinary thing to meet and
	 * an unremarkable thing to say to a user, where a malformed one is a
	 * fault somewhere. */
	FZN_PROVISION_ERR_EXPIRED = 5
} fzn_provision_err_t;

/* A card opened, as views over the caller's bytes.
 *
 * A VIEW RATHER THAN A COPY, on `chain.h`'s reasoning for hops: the bytes the
 * signature covered are the bytes the reader sees, so a field cannot disagree
 * with what was verified. The buffer must outlive the record. */
typedef struct fzn_provision_card {
	const uint8_t *base;
	const uint8_t *root;   /* FZN_PUBKEY_LEN */
	const uint8_t *hop;    /* FZN_HOP_LEN, still to be opened */
	const uint8_t *prekey; /* FZN_PREKEY_LEN_TOTAL, still to be opened */
	uint64_t expires_at;
} fzn_provision_card_t;

/* Lay out and sign a card. `out` receives FZN_PROVISION_LEN_TOTAL bytes.
 *
 * `sign` must sign as the root: the envelope's whole job is to say that these
 * three objects were put together by the key the device is about to pin, and
 * a card signed by anything else says nothing. This cannot be checked here --
 * the signer takes no key, by design -- so being wrong about it produces a
 * card that fails to verify rather than one that lies, which is
 * `fzn_chain_mint`'s bargain and for its reason. */
fzn_provision_err_t fzn_provision_pack(const uint8_t root[FZN_PUBKEY_LEN],
                                       const uint8_t hop[FZN_HOP_LEN],
                                       const uint8_t prekey[FZN_PREKEY_LEN_TOTAL],
                                       uint64_t expires_at, const fzn_sign_ops_t *sign,
                                       uint8_t *out, size_t out_cap, size_t *out_len);

/* Parse a card. Shape only -- this never touches a key.
 *
 * Split from the verification for `record.h`'s reason: a reader that cannot
 * tell "these bytes are not a card" from "this card is not signed by who it
 * says" cannot report either usefully. */
fzn_provision_err_t fzn_provision_open(const uint8_t *bytes, size_t len,
                                       fzn_provision_card_t *out);

/* Check the envelope signature against the root the card names, and the
 * expiry against `now`.
 *
 * `now` of 0 skips the expiry check, for a caller that has no clock -- which
 * is a real state on a device being provisioned, since it may not have talked
 * to anything yet. A card with `expires_at` of 0 never expires. */
fzn_provision_err_t fzn_provision_verify(fzn_provision_card_t card,
                                         const fzn_sign_ops_t *verifier, uint64_t now);

/* The card as the string a code carries. `out` receives at most
 * FZN_PROVISION_TEXT_LEN bytes including the NUL. */
fzn_provision_err_t fzn_provision_text(const uint8_t *bytes, size_t len, char *out,
                                       size_t out_cap);

/* The reverse: a scanned string back to card bytes. */
fzn_provision_err_t fzn_provision_from_text(const char *text, uint8_t *out, size_t out_cap,
                                            size_t *out_len);

/* A short name for `fzn_provision_err_t`. Never NULL. */
const char *fzn_provision_err_str(fzn_provision_err_t err);

#endif /* FZN_PROVISION_H */
