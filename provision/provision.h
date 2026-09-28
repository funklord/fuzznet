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
 *   root        the anchor to pin: the ESTATE's root. Shipped rather than read
 *               out of the chain, even though the first hop's grantor holds
 *               the same key, because taking the anchor out of the object it
 *               is about to authenticate is circular. Shipped, the pin is
 *               auditable: a device compares what it pinned against what the
 *               chain claims, and `fzn_provision_verify` refuses a card whose
 *               first hop was not granted by it.
 *   chain       the hops from the root to this device, 1 to FZN_CHAIN_MAX_HOPS.
 *               The last names the device as grantee and is what lets it ACT;
 *               the ones before it are the sponsor's own standing. A card from
 *               the root carries one hop; a card from a member carries the
 *               member's chain as well, which is what lets any member entitled
 *               to admit do so while the root stays offline (project.md sec
 *               389, decisions 1 and 5; sec 391).
 *   prekey      the SPONSOR's prekey record -- the host that granted the last
 *               hop -- so a session can be established from published keys
 *               alone with no further round trip.
 *   expires_at  a card is a reusable credential, so it is bounded. 0 is
 *               never, which a card printed on a machine's case wants and a
 *               card mailed to somebody does not.
 *
 * THE OUTER SIGNATURE BINDS THE PARTS, AND THAT IS ITS WHOLE JOB. Each inner
 * object is independently signed already and stays that way. What none of
 * them says is that they belong together. Without the envelope a stranger
 * takes a genuine chain -- public, and minted for a device the sponsor really
 * did grant -- and pairs it with their OWN prekey record, which is
 * self-signed and therefore perfectly valid. The device would pin the right
 * root and establish a session with the attacker while holding a genuine
 * grant. The envelope is signed by the SPONSOR, and the card is refused
 * unless the sponsor is both the grantor of the last hop and the host of the
 * prekey record: the three facts have to name one key.
 *
 * IT WAS SIGNED BY THE ROOT UNTIL sec 391, when the root was the sponsor by
 * construction. Under an offline root that cannot sign anything, so the
 * signature moved to the one key that is present at every pairing, and the
 * binding moved with it from "the root says so" to "the sponsor, whose chain
 * reaches the root, says so".
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

/* THE CARD LAYOUT. Big-endian, no padding, fixed fields first -- `wire/bytes.h`'s
 * rule, and for its reason: two implementations that agree on this table
 * cannot produce different bytes for the same card, which is what a signature
 * over them requires. `provision/provision.situ` states it too.
 *
 *     offset       size   field
 *          0          1   version    (= FZN_SIGNED_VERSION)
 *          1          1   object     (= FZN_OBJECT_CARD)
 *          2         32   root       the estate's
 *         34          1   hop_count  1 .. FZN_CHAIN_MAX_HOPS
 *         35    179 * n   chain      root -> ... -> sponsor -> device
 *     35+179n       138   prekey     the sponsor's record
 *    173+179n         8   expires_at
 *    181+179n        64   signature  by the sponsor, over everything before
 *
 * The length is exact for its hop count, so a card is self-delimiting: a
 * reader slices and hands each slice to the call that owns it, and
 * `fzn_hop_open` and `fzn_prekey_open` both refuse a wrong length outright. */
#define FZN_PROVISION_OFF_VERSION    0u
#define FZN_PROVISION_OFF_OBJECT     (FZN_PROVISION_OFF_VERSION + 1u)
#define FZN_PROVISION_OFF_ROOT       (FZN_PROVISION_OFF_OBJECT + 1u)
#define FZN_PROVISION_OFF_HOP_COUNT  (FZN_PROVISION_OFF_ROOT + FZN_PUBKEY_LEN)
#define FZN_PROVISION_OFF_CHAIN      (FZN_PROVISION_OFF_HOP_COUNT + 1u)
#define FZN_PROVISION_OFF_PREKEY(n)  (FZN_PROVISION_OFF_CHAIN + (size_t)(n) * FZN_HOP_LEN)
#define FZN_PROVISION_OFF_EXPIRES_AT(n) (FZN_PROVISION_OFF_PREKEY(n) + FZN_PREKEY_LEN_TOTAL)
#define FZN_PROVISION_OFF_SIGNATURE(n) (FZN_PROVISION_OFF_EXPIRES_AT(n) + 8u)

/* The bytes the signature covers, and the whole card, for `n` hops. */
#define FZN_PROVISION_BODY_LEN(n) FZN_PROVISION_OFF_SIGNATURE(n)
#define FZN_PROVISION_LEN(n) (FZN_PROVISION_BODY_LEN(n) + FZN_SIG_LEN)
#define FZN_PROVISION_MIN_LEN FZN_PROVISION_LEN(1)
#define FZN_PROVISION_MAX_LEN FZN_PROVISION_LEN(FZN_CHAIN_MAX_HOPS)

/* A card as text, which is what a code actually carries.
 *
 * RFC 4648 base32, uppercase, unpadded, behind a version prefix. Base32 and
 * not base64 because QR alphanumeric mode covers 0-9, A-Z and a handful of
 * symbols including `:` -- so an uppercase base32 card encodes in that mode
 * rather than falling back to byte mode, which costs about 45% more bits per
 * character. Unpadded because `=` is not in that alphabet and the length is
 * implied by the character count, so padding would carry no information.
 *
 * The prefix is a version rather than decoration: a scanner meeting a string
 * it does not understand should say so rather than base32-decoding whatever
 * it was handed into a card-shaped buffer. `FZN1:` named the one-hop card
 * signed by the root, retired in sec 391; a `FZN1:` string is refused as not
 * this card rather than read as one. */
#define FZN_PROVISION_TEXT_PREFIX "FZN2:"
#define FZN_PROVISION_TEXT_PREFIX_LEN 5u
/* The UNPADDED length of `bytes` of card: five bits per character, rounded
 * up. `((LEN + 4) / 5) * 8` would be base32's padded length and three too
 * long for the one-hop card, which is how the first version of this was
 * wrong. */
#define FZN_PROVISION_TEXT_BODY_LEN(bytes) (((size_t)(bytes) * 8u + 4u) / 5u)
/* Room for the longest card as text, plus the terminating NUL. */
#define FZN_PROVISION_TEXT_MAX_LEN \
	(FZN_PROVISION_TEXT_PREFIX_LEN + FZN_PROVISION_TEXT_BODY_LEN(FZN_PROVISION_MAX_LEN) + 1u)

typedef enum fzn_provision_err {
	FZN_PROVISION_OK = 0,
	/* The caller's bug: a null, a buffer too small. */
	FZN_PROVISION_ERR_MALFORMED = 1,
	/* Somebody's bytes are not this shape: a wrong length, a version or an
	 * object tag that is not ours, a prefix that is not ours, a character
	 * outside the alphabet. */
	FZN_PROVISION_ERR_SHAPE = 2,
	/* The parts do not name one sponsor, the chain does not start at
	 * the root, or the envelope does not verify under the sponsor. The
	 * parts may each be genuine and not belong together. */
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
	size_t len;
	const uint8_t *root;   /* FZN_PUBKEY_LEN: the estate's root */
	size_t hop_count;      /* 1 .. FZN_CHAIN_MAX_HOPS */
	const uint8_t *chain;  /* hop_count * FZN_HOP_LEN, root first, still to be opened */
	const uint8_t *hop;    /* the LAST hop, this device's own grant */
	const uint8_t *prekey; /* FZN_PREKEY_LEN_TOTAL, the sponsor's, still to be opened */
	uint64_t expires_at;
} fzn_provision_card_t;

/* Lay out and sign a card. `chain` is `hop_count` encoded hops, root first,
 * the last naming the device. `out` receives FZN_PROVISION_LEN(hop_count)
 * bytes.
 *
 * `sign` must sign as the SPONSOR -- the grantor of the last hop and the host
 * of `prekey`. This cannot be checked here, the signer taking no key by
 * design, so being wrong about it produces a card that fails to verify rather
 * than one that lies: `fzn_chain_mint`'s bargain, for its reason. */
fzn_provision_err_t fzn_provision_pack(const uint8_t root[FZN_PUBKEY_LEN],
                                       const uint8_t (*chain)[FZN_HOP_LEN], size_t hop_count,
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

/* Check that the card's parts name one sponsor and belong together, then the
 * expiry against `now`:
 *
 *   - every hop opens, the first was granted by `root`, and each grantee is
 *     the next hop's grantor -- the chain is unbroken from the root;
 *   - the prekey record opens, and its host is the last hop's grantor;
 *   - the envelope verifies under that sponsor.
 *
 * WHAT IT DOES NOT CHECK is every hop's own signature and capability, which
 * is `fzn_chain_verify`'s question and needs a capability and a clock this
 * call does not have. The pairing that consumes the card asks it
 * (`node/pair.h`). A card that passes here is one whose parts were put
 * together by the sponsor it names; whether that sponsor's standing holds is
 * the chain's to answer.
 *
 * `now` of 0 skips the expiry check, for a caller that has no clock -- which
 * is a real state on a device being provisioned. A card with `expires_at` of
 * 0 never expires. */
fzn_provision_err_t fzn_provision_verify(fzn_provision_card_t card,
                                         const fzn_sign_ops_t *verifier, uint64_t now);

/* The card as the string a code carries. `out` receives at most
 * FZN_PROVISION_TEXT_MAX_LEN bytes including the NUL. */
fzn_provision_err_t fzn_provision_text(const uint8_t *bytes, size_t len, char *out,
                                       size_t out_cap);

/* The reverse: a scanned string back to card bytes. */
fzn_provision_err_t fzn_provision_from_text(const char *text, uint8_t *out, size_t out_cap,
                                            size_t *out_len);

/* A short name for `fzn_provision_err_t`. Never NULL. */
const char *fzn_provision_err_str(fzn_provision_err_t err);

#endif /* FZN_PROVISION_H */
