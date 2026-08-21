/* Freshness: command expiry, and the replay window that expiry pays for.
 *
 * project.md sec 4.3 is the policy and sec 7a is why this half is ours: of
 * the freshness rule it says "the field is schema, the policy is ours". The
 * bytes that carry an expiry and a nonce are wire/frame.situ's; what a
 * receiver must do about them is here, and needs no generated code.
 *
 * sec 4.4a raises the stakes above a chat program's. This library carries
 * traffic that reconfigures infrastructure across untrusted networks, so
 * "replay is a configuration change, and freshness is load-bearing rather
 * than hygienic". A replayed command is not a duplicated message; it is a
 * router being reconfigured a second time by somebody who recorded the
 * first.
 *
 * ONE MECHANISM, NOT TWO, and noticing that is the whole design here.
 *
 * Expiry and replay look like separate defences and are not. Remembering
 * every nonce ever seen is unbounded memory, which sec 4.4 forbids in the
 * reassembly path for the same reason it is wrong here -- a stranger can
 * exhaust it. But a command that has expired can no longer be replayed to
 * any effect, because the expiry check refuses it whether or not its nonce
 * is remembered. So a nonce only has to be remembered until its own expiry
 * passes, and sec 4.3's MANDATORY expiry on commands is exactly what makes
 * that bound exist.
 *
 * Which gives the sizing rule, and it is the one thing a consumer must get
 * right: the window must hold as many entries as can arrive within the
 * longest expiry it will accept. Under that, replay is closed. Over it, the
 * window fills.
 */

#ifndef FZN_FRESHNESS_H
#define FZN_FRESHNESS_H

#include <stddef.h>
#include <stdint.h>

/* XChaCha's nonce, which is what wire/frame.situ carries and why: 24 bytes
 * is what makes a RANDOM nonce safe without a counter negotiated per
 * session, and a self-contained frame (sec 13) cannot negotiate one. */
#define FZN_NONCE_LEN 24

/* Shared with chain.h deliberately -- the same values, because these are
 * one library's errors and not one module's. */
typedef enum fzn_fresh_err {
	FZN_FRESH_OK = 0,
	FZN_FRESH_ERR_MALFORMED = -1,
	/* The expiry has passed. */
	FZN_FRESH_ERR_EXPIRED = -2,
	/* A command carrying no expiry at all. sec 4.3: a receiver refuses
	 * one that has passed OR THAT CARRIES NONE, and the second half is
	 * the one an implementation forgets. Its own error, because "you sent
	 * a stale command" and "your sender does not set expiries" are
	 * different bugs in different places. */
	FZN_FRESH_ERR_NO_EXPIRY = -3,
	/* This nonce has been seen before, within its own lifetime. */
	FZN_FRESH_ERR_REPLAY = -4,
	/* The window is full of entries that have not yet expired. See
	 * fzn_replay_admit -- this is a refusal on purpose and not a
	 * capacity bug to paper over. */
	FZN_FRESH_ERR_WINDOW_FULL = -5,
} fzn_fresh_err_t;

/* What a frame is being treated as, which decides how its expiry is read.
 *
 * sec 4.3 reads as a conflict between the two consumers until you see that
 * they are talking about different objects: GRANTS DO NOT EXPIRE, COMMANDS
 * DO. fuzzypickles is emphatic that authority is not ended by a clock, so
 * that no expiry can silently disconnect a host; netcfgd needs commands
 * that go stale, because one arriving an hour late was computed against a
 * machine that no longer exists.
 *
 * THIS LIBRARY CANNOT TELL WHICH A FRAME IS, and must not try. sec 5 keeps
 * command vocabularies out of the core, so what a payload means is the
 * consumer's -- and whether a given message is a command is a fact about
 * its meaning. The consumer says which, per frame, and that is the whole of
 * the coupling. */
typedef enum fzn_frame_kind {
	/* Expiry mandatory. Absent or passed, the frame is refused. */
	FZN_FRAME_COMMAND,
	/* Expiry optional and by default absent. An absent expiry is not a
	 * refusal, and a grant is ended by revocation instead (chain.h). */
	FZN_FRAME_GRANT,
} fzn_frame_kind_t;

/* Is this frame fresh enough to act on? `now` is the caller's clock --
 * nothing here reads one, for the reason chain.h gives at more length.
 *
 * `expires_at` of 0 means "no expiry stated", which is a refusal for a
 * command and the default for a grant. */
fzn_fresh_err_t fzn_freshness_check(uint64_t expires_at, fzn_frame_kind_t kind, uint64_t now);

/* One remembered nonce and the moment it stops mattering. */
typedef struct fzn_replay_entry {
	uint8_t nonce[FZN_NONCE_LEN];
	uint64_t expires_at;
} fzn_replay_entry_t;

/* A bounded set of nonces still inside their own lifetime.
 *
 * The caller owns the storage and there is no allocation anywhere in this
 * library. That is not only sec 4.4's memory bound: it is what makes this
 * testable, in the same way situ/suggestions/fuzznet.md argues for protocol
 * state generally -- a window is a VALUE, so a test can construct one
 * directly, including states normal operation cannot reach, copy it, and
 * compare two with memcmp. */
typedef struct fzn_replay_window {
	fzn_replay_entry_t *entries;
	size_t capacity;
	size_t used;
} fzn_replay_window_t;

/* Point a window at caller-owned storage. `entries` must have room for
 * `capacity`. Returns FZN_FRESH_ERR_MALFORMED on a null or zero-capacity
 * argument rather than producing a window that silently accepts everything. */
fzn_fresh_err_t fzn_replay_init(fzn_replay_window_t *window, fzn_replay_entry_t *entries,
                                 size_t capacity);

/* Admit a nonce, or say why not.
 *
 * Checks freshness first, then replay, and records the nonce only if both
 * pass -- so a rejected frame never occupies a slot. Otherwise a stranger
 * would fill the window with expired rubbish, which is the denial of
 * service this bound exists to prevent rather than one it introduces.
 *
 * A FULL WINDOW IS REFUSED, NOT MADE ROOM IN, and this is the decision
 * worth arguing with before changing. Evicting the oldest live entry to fit
 * a new one is the obvious move and it silently reopens replay: whatever
 * was evicted is accepted again the moment it is retransmitted, so an
 * attacker who can generate traffic can flush the window and then replay
 * anything they recorded. Refusing keeps replay closed and turns the
 * failure into a visible refusal a consumer can log, alarm on and size
 * against -- and sec 4.4a would rather a configuration change did not
 * happen than happen twice.
 *
 * Expired entries are reclaimed on every call, so a window only fills when
 * genuine traffic within one expiry window exceeds its capacity. See the
 * sizing rule at the top of this file. */
fzn_fresh_err_t fzn_replay_admit(fzn_replay_window_t *window,
                                  const uint8_t nonce[FZN_NONCE_LEN], uint64_t expires_at,
                                  fzn_frame_kind_t kind, uint64_t now);

/* Drop entries whose expiry has passed, and report how many went.
 *
 * Called by admit, and exported because a receiver that has gone quiet
 * should be able to hand memory back without waiting for a frame to arrive
 * -- the alternative is a window that stays full precisely when nothing is
 * happening. */
size_t fzn_replay_expire(fzn_replay_window_t *window, uint64_t now);

/* A short name for `fzn_fresh_err_t`, for a log line or a message to a user.
 *
 * NEVER NULL, including for a value that is not one of the enumerators, so
 * that a caller may pass the result straight to a printf without a check.
 * An unrecognised value renders as "unknown", which is deliberately not any
 * real code's text -- a caller that cannot tell "we do not know" from a
 * genuine answer is the failure this whole library is careful about
 * elsewhere.
 *
 * The strings are lowercase, carry no trailing punctuation and name the
 * condition rather than restating the constant, on the same reasoning as
 * strerror: the caller supplies the sentence, this supplies the noun. */
const char *fzn_fresh_err_str(fzn_fresh_err_t err);

#endif /* FZN_FRESHNESS_H */
