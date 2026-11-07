/*
 * THE SESSION FRAME, project.md secs 924 and 932: a frame for two ends that are
 * both awake. 33 bytes where the full frame takes 144, so a call on LoRa is one
 * radio unit rather than four, and each unit lost costs one try.
 *
 * WHAT IT DROPS, AND WHAT STANDS IN ITS PLACE:
 *
 *   sender, capability  named once, in the full frame that asked for the
 *                       session, and found by `handle`, which is the
 *                       receiver's own number for the session. No key on the
 *                       air, so an onlooker no longer reads who is speaking.
 *                       A revoked host's next frame is still refused: the
 *                       capability is judged per frame, from what the handle
 *                       finds.
 *   nonce               a counter, under keys only this session ever had.
 *   commitment          none needed: one key opens this frame, and both ends
 *                       agreed it, so no frame can mean two things.
 *   chunk fields        a session frame is one whole unit. Longer goes full.
 *
 * WHAT NOTHING STORED OR RELAYED MAY USE. It needs a live session at both ends,
 * so sec 8's sleeping peer keeps the full frame, always, and so does everything
 * first: a session is asked for in full frames.
 *
 *     mark 0xFA | handle 4 | counter 4 | SEALED: msg 4, expires 4, payload | tag 16
 *
 * The mark is one no frame's version is, as FZN_BOX_MARK is. `handle` and
 * `counter` are authenticated, not hidden. `expires` is the full frame's, in
 * seconds, 0 for none, sealed: so its check comes after the decryption.
 * `wire/session_frame.situ` is the contract.
 *
 * ASKED FOR AND GRANTED IN FULL FRAMES, under the pair's key. Each end draws a
 * random and names the handle it hears under; both sides' keys are a hash of
 * the pair's key and all four, one key a direction.
 *
 *   - BOTH RANDOMS, so neither end can be made to use a key twice: a device that
 *     crashed counts from 1 again, and a key it has never used is why that is
 *     safe. A counter reused under one key would break the seal.
 *   - NO FORWARD SECRECY of its own. A device runs no agreement, so this is
 *     exactly the pair key's strength, as its full frames are.
 *   - THE GRANT SAYS THE TIME, so a device with no clock learns it from the one
 *     exchange it needs anyway (sec 912).
 *
 * THE COUNTER STOPS. `sent` reaching its top is an answer to ask again, never a
 * wrap: there is no second lap under one key.
 *
 * NO ALLOCATION, NO SYSTEM HEADER: a board links this (`make device-check`).
 */
#ifndef FZN_SESSION_FRAME_H
#define FZN_SESSION_FRAME_H

#include <stddef.h>
#include <stdint.h>

#include "../session/aead.h"
#include "../session/commitment.h"

#define FZN_SESSION_FRAME_MARK 0xFAu
#define FZN_SESSION_FRAME_HEAD_LEN 9u
#define FZN_SESSION_FRAME_SEALED_HEAD_LEN 8u
/* BYTES BEFORE ANY PAYLOAD, as FZN_SEAL_OVERHEAD says of the full frame. */
#define FZN_SESSION_FRAME_OVERHEAD \
	(FZN_SESSION_FRAME_HEAD_LEN + FZN_SESSION_FRAME_SEALED_HEAD_LEN + FZN_AEAD_TAG_LEN)
/* THE MOST ONE CARRIES: a full frame's payload, so an answer that fits one fits
 * the other, and what does not goes in pieces, in full frames. */
#define FZN_SESSION_FRAME_PAYLOAD_MAX 1024u
#define FZN_SESSION_FRAME_MAX (FZN_SESSION_FRAME_OVERHEAD + FZN_SESSION_FRAME_PAYLOAD_MAX)

/* WHAT EACH END DRAWS. */
#define FZN_SESSION_RANDOM_LEN 16u
/* THE BODIES OF THE TWO FULL FRAMES, after a payload's version and type: a
 * random and the handle its sender hears under, and the grant the time, ms. */
#define FZN_SESSION_ASK_LEN (FZN_SESSION_RANDOM_LEN + 4u)
#define FZN_SESSION_GRANT_LEN (FZN_SESSION_RANDOM_LEN + 4u + 8u)

/* HOW FAR BEHIND THE NEWEST A FRAME MAY ARRIVE AND STILL BE TAKEN. */
#define FZN_SESSION_WINDOW 64u

typedef enum fzn_session_frame_err {
	FZN_SESSION_FRAME_OK = 0,
	FZN_SESSION_FRAME_ERR_MALFORMED = -1, /* a null, or a payload past the most */
	FZN_SESSION_FRAME_ERR_SHAPE = -2,     /* not a session frame, or not this end's */
	FZN_SESSION_FRAME_ERR_REPLAY = -3,    /* a counter heard, or past the window */
	FZN_SESSION_FRAME_ERR_TAG = -4,       /* did not open */
	FZN_SESSION_FRAME_ERR_SPENT = -5,     /* the counter is at its top: ask again */
	FZN_SESSION_FRAME_ERR_CAPACITY = -6,  /* the caller's buffer is too small */
	FZN_SESSION_FRAME_ERR_AEAD = -7       /* the AEAD seam refused while sealing */
} fzn_session_frame_err_t;

/* ONE END OF A SESSION. Plain bytes, the caller's to place. */
typedef struct fzn_session_end {
	uint8_t send_key[FZN_AEAD_KEY_LEN];
	uint8_t recv_key[FZN_AEAD_KEY_LEN];
	uint32_t hears_as; /* the handle this end hears under */
	uint32_t speaks_to; /* the handle the other end hears under */
	uint32_t sent;     /* the last counter sealed under */
	uint32_t newest;   /* the highest counter opened */
	uint64_t heard;    /* bit i: `newest - i` was opened */
} fzn_session_end_t;

/* WHAT OPENING ONE YIELDS, pointing into the caller's frame. */
typedef struct fzn_session_opened {
	const uint8_t *payload;
	size_t payload_len;
	uint32_t msg;
	uint32_t counter;
	uint32_t expires_at;
} fzn_session_opened_t;

/* BOTH ENDS' KEYS, for one end. `root` is the key the initiator sends full
 * frames under, and `initiator` 1 on that end. `ask` and `grant` are the bodies
 * as they travelled. 1, or 0 when the hash refused, with `end` wiped. */
int fzn_session_end_derive(fzn_session_end_t *end, const fzn_hash_ops_t *hash,
                           const uint8_t root[FZN_AEAD_KEY_LEN],
                           const uint8_t ask[FZN_SESSION_ASK_LEN],
                           const uint8_t grant[FZN_SESSION_GRANT_LEN], int initiator);

/* WHETHER `frame` IS ONE, and the handle it names. */
int fzn_session_frame_handle(const uint8_t *frame, size_t frame_len, uint32_t *handle);

/* `payload` SEALED, the next counter spent, into `frame`. `payload` may be NULL
 * with a `payload_len` of 0. A frame refused spends no counter, unless the AEAD
 * refused, when a counter it may have used is not offered again. */
fzn_session_frame_err_t fzn_session_frame_seal(fzn_session_end_t *end, uint32_t msg,
                                               uint32_t expires_at, const uint8_t *payload,
                                               size_t payload_len, uint8_t *frame,
                                               size_t frame_cap, size_t *frame_len,
                                               const fzn_aead_ops_t *aead);

/* A FRAME OPENED IN PLACE. In order: shape, that it is this end's, that its
 * counter is unheard, the tag, and only then is the counter marked heard: a
 * forgery moves nothing. The buffer may be changed whatever the answer. */
fzn_session_frame_err_t fzn_session_frame_open(fzn_session_end_t *end, uint8_t *frame,
                                               size_t frame_len, const fzn_aead_ops_t *aead,
                                               fzn_session_opened_t *out);

#endif /* FZN_SESSION_FRAME_H */
