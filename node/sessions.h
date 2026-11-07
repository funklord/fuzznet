/*
 * THE SESSIONS THIS HOST GRANTED, sec 932: who a session frame's handle means.
 * `wire/session_frame.h` is the frame; this is the table a host keeps of them.
 *
 * ASKED IN A FULL FRAME and granted in one, so a session's sender is one whose
 * frame opened, and its capability the one that frame named. Nothing here says
 * whether either still stands: that is judged for each frame, from the peer as
 * it now is, as a full frame's is. A session outlives no revocation.
 *
 * AT MOST TWO A SENDER, so a table grows with the peers and no further: one
 * confirmed, and one granted and unused. No stranger can add one, and a caller
 * has no limit to reach but its own peers.
 *
 * A REPLAY MOVES NOTHING. An ask heard again is answered with the grant it had
 * while that grant stands. An old ask, replayed, gets a grant whose keys its
 * replayer cannot derive, and the session in use is not touched: a granted
 * session replaces the one before only when its first frame opens, which only
 * the asker can make.
 *
 * LOST WITH THE HOST: a table is memory. A session frame then finds nothing and
 * is met with silence, as nothing may be said to a sender nobody can name, and
 * the sender asks again.
 *
 * THE HANDLE IS THE PLACE: its low bits a slot, its high bits drawn, so a frame
 * finds its session in one step and a slot reused does not answer to the old
 * handle. The tag is what proves anything; the high bits only keep a stale
 * frame from spending a decryption.
 */
#ifndef FZN_NODE_SESSIONS_H
#define FZN_NODE_SESSIONS_H

#include <stddef.h>
#include <stdint.h>

#include "../chain/chain.h"
#include "../session/random.h"
#include "../wire/session_frame.h"

#define FZN_NODE_SESSION_SLOT_BITS 24u
#define FZN_NODE_SESSION_SLOT_MASK ((1u << FZN_NODE_SESSION_SLOT_BITS) - 1u)

typedef struct fzn_node_session {
	fzn_session_end_t end;
	uint8_t sender[FZN_PUBKEY_LEN];
	uint8_t capability[FZN_CAP_ID_LEN];
	/* THE KEY IT WAS DERIVED FROM: a peer paired afresh has no such session. */
	uint8_t root[FZN_AEAD_KEY_LEN];
	/* THE EXCHANGE AS IT WENT, so an ask heard again is granted the same. */
	uint8_t ask[FZN_SESSION_ASK_LEN];
	uint8_t grant[FZN_SESSION_GRANT_LEN];
	uint8_t used;
	uint8_t confirmed; /* a frame of it has opened */
} fzn_node_session_t;

typedef struct fzn_node_sessions {
	fzn_node_session_t *table;
	size_t cap;
} fzn_node_sessions_t;

/* AN ASK ANSWERED: `grant_out` the body to send, kept in the table. `root` the
 * key `sender` sends under, `now_ms` this host's clock. 1, or 0 when no room or
 * no random could be had, and the caller answers nothing: the sender stays on
 * full frames. */
int fzn_node_sessions_grant(fzn_node_sessions_t *t, const uint8_t sender[FZN_PUBKEY_LEN],
                            const uint8_t capability[FZN_CAP_ID_LEN],
                            const uint8_t root[FZN_AEAD_KEY_LEN],
                            const uint8_t ask[FZN_SESSION_ASK_LEN], uint64_t now_ms,
                            const fzn_hash_ops_t *hash, const fzn_random_ops_t *rng,
                            uint8_t grant_out[FZN_SESSION_GRANT_LEN]);

/* WHAT `handle` NAMES, or NULL. Good until the table next grants. */
fzn_node_session_t *fzn_node_sessions_find(fzn_node_sessions_t *t, uint32_t handle);

/* `s`'S FIRST FRAME OPENED: it stands, and whatever `sender` held before goes. */
void fzn_node_sessions_confirm(fzn_node_sessions_t *t, fzn_node_session_t *s);

/* `s` WIPED AND ITS SLOT FREE. */
void fzn_node_sessions_drop(fzn_node_session_t *s);

/* THE TABLE WIPED AND LET GO. */
void fzn_node_sessions_release(fzn_node_sessions_t *t);

#endif /* FZN_NODE_SESSIONS_H */
