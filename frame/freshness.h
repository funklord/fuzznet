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
 * right. It is a formula rather than advice:
 *
 *     capacity >= peak arrival rate x max_ahead
 *
 * with every term defined, because a rule whose terms are not is a rule
 * nobody can be shown to have broken:
 *
 *   - `capacity` is the number of entries handed to `fzn_replay_init`.
 *   - `peak arrival rate` is the greatest number of DISTINCT nonces this
 *     receiver can be offered per unit of time. It counts a stranger's
 *     traffic as well as a peer's, because freshness runs BEFORE signature
 *     verification (sec 4.7) and an unauthenticated frame therefore takes a
 *     slot. It is a property of the link and of whatever rate limiting sits
 *     in front of this, not of the protocol, so only the consumer knows it.
 *   - `max_ahead` is the furthest ahead of `now` an expiry may be and still
 *     be accepted. It is stated per window at `fzn_replay_init` and enforced
 *     on every frame. Its unit is the caller's clock's, since nothing here
 *     reads one.
 *
 * Under that, replay is closed. Over it, the window fills.
 *
 * `max_ahead` IS A LIFETIME PLUS A SKEW, and this is the term a consumer
 * gets wrong in the direction that looks safe. Set it to the longest
 * legitimate command lifetime alone and the receiver refuses every frame
 * from a peer whose clock runs fast: that peer stamps `now_theirs +
 * lifetime`, which is past `now_ours + lifetime` by the skew, and lands
 * outside the horizon. So it is the longest legitimate command lifetime PLUS
 * the largest clock skew the receiver is willing to tolerate.
 *
 * THE RULE USED TO READ AS ADVICE BECAUSE NOTHING COULD CHECK IT. It said
 * the window must hold what can arrive within "the longest expiry it will
 * accept", and there was no API by which a receiver stated one -- so the
 * bound this whole module rests on was unenforceable, and nobody could fail
 * it. Measured: 4096 frames carrying `expires_at = UINT64_MAX` filled a
 * 4096-entry window, a sweep a hundred years later dropped none of them, and
 * every genuine frame after that was refused FZN_FRESH_ERR_WINDOW_FULL. The
 * refusal is right -- see `fzn_replay_admit`, where evicting is argued
 * against at length -- which is exactly why the outage never ended.
 *
 * So the horizon: for any frame stating a NONZERO expiry, `now < expires_at
 * <= now + max_ahead`, and anything further out is FZN_FRESH_ERR_HORIZON.
 * `expires_at == 0` stays outside the horizon entirely, because nothing is
 * remembered for it and there is therefore nothing to bound -- the grant
 * rule below is untouched.
 */

#ifndef FZN_FRESHNESS_H
#define FZN_FRESHNESS_H

#include <stddef.h>
#include <stdint.h>

/* No expiry stated. This header spelled it as a bare 0 in prose and left the
 * name to `chain/chain.h`, which declares the same value for a hop -- so a
 * consumer using only the replay window had no name for it, and one using
 * both had to notice they meant the same thing.
 *
 * Defined in BOTH headers rather than moved to one, because neither module
 * may depend on the other: `frame/` must not pull in the capability model to
 * ask about a clock, and the dependency-direction argument in
 * `constant_time/constant_time.h` is the same one.
 *
 * SO THE VALUE CARRIES THIS MODULE'S NAME AND THE PUBLIC NAME IS AN ALIAS.
 * `FZN_FRESH_NO_EXPIRY` is defined unconditionally and is therefore always
 * the number this header wrote; `FZN_NO_EXPIRY` is the public spelling and
 * is guarded, so including both headers in either order stays harmless.
 *
 * The two copies are held together in `wire/test/constants_test.c`, and the
 * prefixed names are what it compares. Asserting on `FZN_NO_EXPIRY` could
 * not do it: the guard means one header's definition never compiles, so the
 * assertion saw whichever header that translation unit read first and the
 * other copy was unwitnessed. Setting this one to 1 left the build silent.
 * `FZN_FRESH_NO_EXPIRY` against `FZN_CHAIN_NO_EXPIRY` is the same shape as
 * `FZN_NONCE_LEN` against `FZN_AEAD_NONCE_LEN`, one file up. */
#define FZN_FRESH_NO_EXPIRY 0u
#ifndef FZN_NO_EXPIRY
#define FZN_NO_EXPIRY FZN_FRESH_NO_EXPIRY
#endif

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
	/* The expiry is further ahead than this receiver will remember a
	 * nonce for -- past `now + max_ahead`. See the sizing rule at the top
	 * of this file.
	 *
	 * ITS OWN CODE RATHER THAN EXPIRED, on exactly the reasoning that
	 * splits EXPIRED from NO_EXPIRY above: "your command is stale" and
	 * "your expiry is further out than I will remember a nonce for" are
	 * different faults in different places. The first is the sender's
	 * clock or the network; the second is a sender asking for a lifetime
	 * this receiver did not size for, or a stranger trying to pin a slot.
	 * A receiver that cannot tell them apart cannot tell a slow link from
	 * an attack, and cannot tell either from its own `max_ahead` being
	 * set too tight.
	 *
	 * REFUSED RATHER THAN CLAMPED, and that is a hole rather than a
	 * matter of taste. Recording the entry under a clamped deadline of
	 * `now + max_ahead` while still treating the frame as fresh until its
	 * STATED expiry forgets the nonce at the clamp and leaves the frame
	 * passing freshness for the whole gap between the two -- so it
	 * replays successfully, which is the one thing this module exists to
	 * prevent. */
	FZN_FRESH_ERR_HORIZON = -6,
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
/* WHETHER AN EXPIRY IS REQUIRED OF THIS FRAME.
 *
 * A RECEIVER'S POLICY, NOT A FIELD. Nothing on the wire carries it: the
 * caller decides, per frame, which rule applies -- because sec 4.3 puts that
 * decision with the consumer, since only it knows which of its messages are
 * commands.
 *
 * RENAMED 2026-08-26, from `fzn_frame_kind_t { FZN_FRAME_COMMAND,
 * FZN_FRAME_GRANT }`, and the reason is a trap rather than taste. The wire
 * has its OWN `fzn_kind` -- `nop | unit | chunk | ack` -- reported as
 * `fzn_opened_t.kind`, and the two enums overlapped: 0 and 1 were valid in
 * both. A consumer holding `opened.kind` and passing it here would have been
 * silently misclassifying, with wire `unit` (1) reading as the old
 * `FZN_FRAME_GRANT` (1) -- so a unit frame's expiry became optional, which
 * inverts the rule this file exists to enforce. Nothing did it, and three
 * consumers were about to arrive.
 *
 * The name says what it decides rather than what it is about, which is also
 * why it can no longer be confused with a property of the frame. The values
 * are unchanged in order and therefore in number. */
typedef enum fzn_expiry_rule {
	/* Expiry mandatory. Absent or passed, the frame is refused. */
	FZN_EXPIRY_REQUIRED,
	/* Expiry optional and by default absent. An absent expiry is not a
	 * refusal, and a grant is ended by revocation instead (chain.h). */
	FZN_EXPIRY_OPTIONAL,
} fzn_expiry_rule_t;

/* Is this frame fresh enough to act on? `now` is the caller's clock --
 * nothing here reads one, for the reason chain.h gives at more length.
 *
 * `expires_at` of 0 means "no expiry stated", which is a refusal for a
 * command and the default for a grant.
 *
 * `max_ahead` is the horizon, in the same units as `now`: a nonzero expiry
 * must satisfy `now < expires_at <= now + max_ahead`, or the frame is
 * FZN_FRESH_ERR_HORIZON. It is NOT KEYED ON `kind`, and that is the half a
 * reader expects to be there and should not look for. An OPTIONAL frame
 * carrying a nonzero far-future expiry is recorded in the window exactly as
 * a REQUIRED one is -- `fzn_replay_admit` branches on `expires_at`, not on
 * the rule -- so the optional path wedges the window by precisely the same
 * route. A horizon that applied to commands only would have left the hole
 * open under a different label.
 *
 * `max_ahead` OF 0 IS FZN_FRESH_ERR_MALFORMED, for every argument, before
 * anything else is looked at. Reading it as "no horizon" would make the
 * unbounded behaviour the one a caller gets by forgetting the field, which
 * is the argument `chunk/reassembly.h` gives for refusing `per_sender_max ==
 * 0`. There is no valid call with 0, so the fault is in the argument rather
 * than in the frame, and saying MALFORMED rather than HORIZON says which. */
fzn_fresh_err_t fzn_freshness_check(uint64_t expires_at, fzn_expiry_rule_t kind, uint64_t now,
                                     uint64_t max_ahead);

/* One remembered nonce and the moment it stops mattering. */
typedef struct fzn_replay_entry {
	uint8_t nonce[FZN_NONCE_LEN];
	uint64_t expires_at;
} fzn_replay_entry_t;

/* A bounded set of nonces still inside their own lifetime.
 *
 * The caller owns the storage and there is no allocation anywhere in this
 * library. That is not only sec 4.4's memory bound: it is what makes this
 * testable, in the same way situ/suggestion/fuzznet.md argues for protocol
 * state generally -- a window is a VALUE, so a test can construct one
 * directly, including states normal operation cannot reach, copy it, and
 * compare two with memcmp. */
typedef struct fzn_replay_window {
	fzn_replay_entry_t *entries;
	size_t capacity;
	size_t used;
	/* The horizon, in the caller's clock's units. See the sizing rule at
	 * the top of this file.
	 *
	 * IT LIVES HERE, ON THE WINDOW, rather than being handed to
	 * `fzn_replay_admit` per frame. The horizon and the capacity are two
	 * halves of ONE sizing decision -- `capacity >= peak arrival rate x
	 * max_ahead` relates them and neither is meaningful alone -- so
	 * making them settable independently would let a caller widen the
	 * horizon without touching the storage and wedge the window while
	 * every individual call looked reasonable. Setting both at
	 * `fzn_replay_init` and nowhere else is what makes the formula an
	 * invariant of the window rather than a thing to remember at each
	 * call site. */
	uint64_t max_ahead;
} fzn_replay_window_t;

/* Point a window at caller-owned storage. `entries` must have room for
 * `capacity`. Returns FZN_FRESH_ERR_MALFORMED on a null or zero-capacity
 * argument rather than producing a window that silently accepts everything.
 *
 * `max_ahead` OF 0 IS REFUSED, not read as "no horizon", for the same reason
 * `capacity` of 0 is: an unlimited default is the one a caller gets by
 * forgetting the field, which is `chunk/reassembly.h`'s own argument against
 * `per_sender_max == 0`. A window with no horizon is the state the wedge
 * measured at the top of this file needs, so the one way to reach it is the
 * one way that must not be an accident. */
fzn_fresh_err_t fzn_replay_init(fzn_replay_window_t *window, fzn_replay_entry_t *entries,
                                 size_t capacity, uint64_t max_ahead);

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
 * sizing rule at the top of this file.
 *
 * NO `max_ahead` ARGUMENT, deliberately: the horizon is the window's, set
 * once at `fzn_replay_init`, and the field's comment says why it must not be
 * settable per call. The refusal it produces is FZN_FRESH_ERR_HORIZON, and
 * it costs no slot, like every other refusal here. */
fzn_fresh_err_t fzn_replay_admit(fzn_replay_window_t *window,
                                  const uint8_t nonce[FZN_NONCE_LEN], uint64_t expires_at,
                                  fzn_expiry_rule_t kind, uint64_t now);

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
