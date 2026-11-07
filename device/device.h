/*
 * THE SMALLEST HOST, project.md sec 912: a device with a button, a light or a
 * small display, there to control or show something on the fuzznet. The
 * holder's, 2026-11-06: "It is very minimal, but has communication, possibly
 * not via ethernet at all. Could be LoRa or manual key exchanges even."
 *
 * A HOST LIKE ANY OTHER, with almost everything hardcoded out:
 * no store, no relay, no rounds, no listening, no local socket. It asks one
 * host, its GATEWAY, by `call NAME ARGS`, and shows what it is answered. A
 * button is a call; a light is a call asked on a timer.
 *
 * THE IMAGE IS THE MANUAL KEY EXCHANGE. Everything that needs a signature or a
 * key agreement happens once, off the device: a store is paired to the gateway
 * as any device is (`--prekey`, `--pair`, `--accept`), and `--device-image`
 * writes what that left, as text to type or flash. So the
 * device runs no Ed25519 and no X25519, only a hash, the AEAD and a random
 * source. Its session is the pairing's, as a caller's is. It can be revoked as
 * any host is, and a device stolen is a host revoked.
 *
 * NO CLOCK NEEDED. An expiry is judged by the gateway's clock, so a device
 * counts time from its start and learns what time that is from the grant of
 * its session (sec 932), which a host answers whatever a frame's expiry. Its
 * only clock is `uptime_ms`, which needs to tick and need not be set.
 *
 * NO ALLOCATION, NO POSIX: `fzn_device_t` and its bearer's one slot are 2.8 KB
 * and all it holds. `make device-check` compiles this for a board, with no
 * system header, and it needs five functions of a C library.
 *
 * WHAT IT CANNOT DO: read an answer past one frame, 1024 bytes less the
 * call's three. That is a call the device should not make, and its gateway's
 * procedure is the one to page it.
 */
#ifndef FZN_DEVICE_H
#define FZN_DEVICE_H

#include <stddef.h>
#include <stdint.h>

#include "../chain/chain.h"
#include "../net/bearer.h"
#include "../session/aead.h"
#include "../session/commitment.h"
#include "../session/random.h"
#include "../wire/seal.h"
#include "../wire/session_frame.h"

/* THE IMAGE: what a device holds, and all of it secret but its key. */
#define FZN_DEVICE_IMAGE_VERSION 1u
#define FZN_DEVICE_IMAGE_LEN \
	(1u + FZN_PUBKEY_LEN + FZN_CAP_ID_LEN + FZN_AEAD_KEY_LEN + FZN_COMMITMENT_KEY_LEN)
#define FZN_DEVICE_IMAGE_PREFIX "FZD1:"
#define FZN_DEVICE_IMAGE_PREFIX_LEN 5u
#define FZN_DEVICE_IMAGE_TEXT_LEN (FZN_DEVICE_IMAGE_PREFIX_LEN + (FZN_DEVICE_IMAGE_LEN * 2u))

typedef struct fzn_device_image {
	uint8_t sender[FZN_PUBKEY_LEN];
	uint8_t capability[FZN_CAP_ID_LEN];
	uint8_t send_key[FZN_AEAD_KEY_LEN];
	uint8_t send_ckey[FZN_COMMITMENT_KEY_LEN];
} fzn_device_image_t;

/* `image` as text into `out` of FZN_DEVICE_IMAGE_TEXT_LEN + 1, NUL-ended. */
void fzn_device_image_text(const fzn_device_image_t *image, char *out);

/* TEXT TAKEN BACK, `len` bytes. 1, or 0 for what is not an image. */
int fzn_device_image_from_text(const char *text, size_t len, fzn_device_image_t *out);

typedef enum fzn_device_err {
	FZN_DEVICE_OK = 0,
	FZN_DEVICE_ERR_MALFORMED = -1, /* a null, a name out of shape, too long a call */
	FZN_DEVICE_ERR_SEAL = -2,      /* no frame could be made: the random source */
	FZN_DEVICE_ERR_SEND = -3,      /* the bearer would not take it */
	FZN_DEVICE_ERR_SILENT = -4,    /* every try went unanswered */
	FZN_DEVICE_ERR_ANSWER = -5     /* the answer opened and is not one, or too long */
} fzn_device_err_t;

const char *fzn_device_err_str(fzn_device_err_t err);

typedef struct fzn_device {
	fzn_device_image_t image;
	const fzn_hash_ops_t *hash;
	const fzn_aead_ops_t *aead;
	const fzn_random_ops_t *rng;
	const fzn_bearer_t *bearer;
	fzn_bearer_join_t *join; /* with one slot, its `unit` the bearer's */
	/* HOW LONG SINCE IT STARTED, ms. Its only clock. */
	uint64_t (*uptime_ms)(void *ctx);
	void *uptime_ctx;
	/* A TRY: how long a call waits, and how many times it goes. A radio
	 * under a duty cycle wants these long and few. */
	unsigned wait_ms;
	unsigned tries;
	/* HOW LONG A REQUEST LIVES, seconds. */
	unsigned life_s;
	/* THE GATEWAY'S CLOCK LESS `uptime_ms`, once a grant has said it. */
	int64_t clock_offset_ms;
	uint32_t next_msg; /* 0 until the first, then drawn: sec 910 */
	/* THE SESSION WITH THE GATEWAY, sec 932: what a call goes in, while
	 * `session_up`. An ask goes out in full and lives until it is answered. */
	fzn_session_end_t session;
	int session_up;
	unsigned silent; /* tries in a row that heard nothing */
	uint8_t ask[FZN_SESSION_ASK_LEN];
	uint32_t ask_msg;
	int asking;
	uint8_t frame[FZN_BEARER_FRAME_MAX];
} fzn_device_t;

/* A SESSION WITH THE GATEWAY, which also says the time. `fzn_device_call` does this
 * when it must; OK at once while one stands. */
fzn_device_err_t fzn_device_open(fzn_device_t *d);

/* `call NAME ARGS` OF THE GATEWAY: `*status` its FZN_CALL_* and its answer's
 * bytes in `answer`, `*answer_len` of them. Sent in the session, one radio unit
 * where it fits, and again until answered, the gateway keeping its reply, so a
 * button pressed once is one press (sec 900), under whichever session it took:
 * tries that hear nothing give up the session and ask for another. */
fzn_device_err_t fzn_device_call(fzn_device_t *d, const char *name, const uint8_t *args,
                                 size_t args_len, uint8_t *answer, size_t cap,
                                 size_t *answer_len, unsigned *status);

#endif /* FZN_DEVICE_H */
