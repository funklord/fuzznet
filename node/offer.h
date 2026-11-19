/*
 * A HOST FOUND BY A DEVICE THAT KNOWS NOTHING OF IT, sec 1288: join by
 * request's discovery (sec 1216, the holder's "we implement the join by
 * request", 2026-11-19). The two datagrams; the host's offer window and the
 * device's listing are the daemon's.
 *
 * The host's user opens an OFFER for a few minutes: the host makes a
 * confirmed invite (sec 896) and, while the window is open, listens on
 * FZN_OFFER_PORT. A device that wants to join broadcasts a PROBE to that
 * port; each offering host answers with its name and its invite's code; the
 * device lists them, its user picks one, and the device joins by that code
 * as it would by one read off a screen -- held until the host's user lets it
 * in by name, comparing the key each side shows. A stranger on the network
 * can see the offer and ask too, and is shown to that user as one more
 * waiting device, never let in by itself.
 *
 * THE PORT IS FIXED AND PUBLIC: a device that knows nothing has nowhere
 * else to send. Open only while an offer is, and nothing but a probe is
 * read on it.
 *
 * NO AMPLIFICATION (sec 624's rule): a probe is padded to
 * FZN_OFFER_PROBE_LEN, and an answer never exceeds it.
 *
 *     probe   0xFD  version  nonce[8]  zero padding to FZN_OFFER_PROBE_LEN
 *     answer  0xFE  version  nonce[8]  name_len u8  name  code_len u16  code
 *
 * The answer echoes the probe's nonce, so a device takes only answers to
 * its own probe. Big-endian.
 */
#ifndef FZN_NODE_OFFER_H
#define FZN_NODE_OFFER_H

#include <stddef.h>
#include <stdint.h>

#include "invite.h"
#include "../net/ports.h"

#define FZN_OFFER_PROBE_MARK 0xFDu
#define FZN_OFFER_ANSWER_MARK 0xFEu
#define FZN_OFFER_VERSION 1u
/* THE DISCOVERY PORT, beside the user span (`net/ports.h`, sec 1289). */
#define FZN_OFFER_PORT FZN_PORTS_DISCOVERY
#define FZN_OFFER_NONCE_LEN 8u
#define FZN_OFFER_PROBE_LEN 512u
#define FZN_OFFER_NAME_MAX 64u
/* AN OFFER'S LONGEST LIFE and its usual one, in seconds. */
#define FZN_OFFER_LIFE_S 300u
#define FZN_OFFER_LIFE_MAX_S 900u

typedef struct fzn_offer {
	uint8_t nonce[FZN_OFFER_NONCE_LEN];
	char name[FZN_OFFER_NAME_MAX + 1u];
	size_t name_len;
	char code[FZN_INVITE_TEXT_MAX + 1u];
	size_t code_len;
} fzn_offer_t;

/* A PROBE with `nonce` into `out`, FZN_OFFER_PROBE_LEN bytes. */
void fzn_offer_probe(const uint8_t nonce[FZN_OFFER_NONCE_LEN], uint8_t out[FZN_OFFER_PROBE_LEN]);

/* `len` bytes READ AS A PROBE, exactly: 1 with its nonce, or 0. */
int fzn_offer_probe_read(const uint8_t *in, size_t len, uint8_t nonce[FZN_OFFER_NONCE_LEN]);

/* AN ANSWER into `out`: its length, never past FZN_OFFER_PROBE_LEN, or 0 for
 * a name or a code this format does not carry -- a name of 1 to 64 bytes
 * with no control byte, a code that reads as an invite. */
size_t fzn_offer_answer(const fzn_offer_t *o, uint8_t *out, size_t cap);

/* `len` bytes READ AS AN ANSWER to the probe of `nonce`: 1 with it, or 0 --
 * another probe's, malformed, or carrying no invite. */
int fzn_offer_answer_read(const uint8_t *in, size_t len, const uint8_t nonce[FZN_OFFER_NONCE_LEN], fzn_offer_t *out);

#endif /* FZN_NODE_OFFER_H */
