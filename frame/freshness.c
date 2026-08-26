/* Command expiry and the replay window. See freshness.h. */

#include "freshness.h"

#include <string.h>

/* Nonces are compared with plain memcmp, deliberately, and the reason is
 * worth writing down because the rest of this library is careful about it.
 *
 * chain.c uses a constant-time comparison because sec 4.4a requires one and
 * names tag comparison specifically. Here there is nothing to leak: a nonce
 * travels in the CLEAR in the frame header (wire/frame.situ puts it outside
 * the seal, because a receiver must have it before it can decrypt
 * anything), so an attacker comparing against one already knows it. And the
 * membership of the window is not secret either -- the return value says
 * whether a nonce was present, which is strictly more than any timing
 * signal would.
 *
 * Using the constant-time helper anyway would cost nothing and read as
 * cargo cult. Saying which comparisons are load-bearing is the more useful
 * habit, since a reader who finds memcmp here and cannot see why will
 * eventually "fix" it somewhere it matters. */
static int nonce_eq(const uint8_t *a, const uint8_t *b)
{
	return memcmp(a, b, FZN_NONCE_LEN) == 0;
}

/* The far edge of what this receiver will remember a nonce for.
 *
 * SATURATING, because `now + max_ahead` is arithmetic on two values the
 * caller chose and uint64 wraps silently. A wrapped horizon is small, so
 * every legitimate expiry lands past it and the receiver refuses everything
 * -- an outage with no visible cause, near the top of the clock's range where
 * nobody tests. Saturating at UINT64_MAX means a caller who asks for a
 * horizon wider than the clock gets one exactly that wide, which is what they
 * asked for and is still bounded by the sweep. */
static uint64_t horizon_of(uint64_t now, uint64_t max_ahead)
{
	return max_ahead > UINT64_MAX - now ? UINT64_MAX : now + max_ahead;
}

fzn_fresh_err_t fzn_freshness_check(uint64_t expires_at, fzn_expiry_rule_t kind, uint64_t now,
                                     uint64_t max_ahead)
{
	/* Before anything else, and for every argument. See freshness.h: a
	 * `max_ahead` of 0 is a broken caller rather than a broken frame, and
	 * reading it as "no horizon" would make the unbounded behaviour the
	 * one somebody gets by forgetting the field. */
	if (max_ahead == 0)
		return FZN_FRESH_ERR_MALFORMED;

	/* THE ONLY THING `kind` DECIDES IS WHAT AN ABSENT EXPIRY MEANS, which
	 * is why it is tested here and nowhere below.
	 *
	 * sec 4.3: a grant's expiry is optional and absent by default, and
	 * authority is ended by revocation rather than by a clock. For a
	 * command both halves are mandatory, and the second is the one an
	 * implementation forgets -- refusing a passed expiry while accepting
	 * an absent one exempts anybody who omits the field, which is worse
	 * than not having the rule. */
	if (expires_at == 0)
		return kind == FZN_EXPIRY_OPTIONAL ? FZN_FRESH_OK : FZN_FRESH_ERR_NO_EXPIRY;

	/* A STATED EXPIRY IS HELD TO THE SAME TWO BOUNDS WHATEVER THE RULE
	 * WAS, and the structure says so rather than repeating itself in two
	 * branches.
	 *
	 * A grant that DOES state an expiry is still held to it -- see sec 14,
	 * where the wording is recorded as ambiguous and this reading chosen
	 * because it fails closed. And the horizon is not keyed on the rule
	 * either, which is the half a reader expects to find: `fzn_replay_admit`
	 * records anything carrying a nonzero expiry, branching on
	 * `expires_at` and not on `kind`, so an OPTIONAL frame with a
	 * far-future expiry pins a slot exactly as a REQUIRED one does. A
	 * horizon that applied to commands alone would have left the wedge
	 * open under a different label. */
	if (expires_at <= now)
		return FZN_FRESH_ERR_EXPIRED;

	/* STRICTLY GREATER THAN, so an expiry landing exactly on the horizon
	 * is admitted. `now + max_ahead` is the last instant this receiver
	 * sized itself to remember, and a sender computing its expiry from the
	 * agreed lifetime hits it exactly whenever the clocks agree -- so `>=`
	 * here would refuse the ordinary case and leave the horizon usable
	 * only by senders that undershoot it. */
	if (expires_at > horizon_of(now, max_ahead))
		return FZN_FRESH_ERR_HORIZON;

	return FZN_FRESH_OK;
}

fzn_fresh_err_t fzn_replay_init(fzn_replay_window_t *window, fzn_replay_entry_t *entries,
                                 size_t capacity, uint64_t max_ahead)
{
	/* `max_ahead == 0` beside `capacity == 0` because they fail the same
	 * way and the header says so: both are a field somebody forgot, and
	 * reading either as "unlimited" hands the caller the unbounded window
	 * as a default. */
	if (!window || !entries || capacity == 0 || max_ahead == 0)
		return FZN_FRESH_ERR_MALFORMED;

	window->entries = entries;
	window->capacity = capacity;
	window->used = 0;
	window->max_ahead = max_ahead;

	return FZN_FRESH_OK;
}

size_t fzn_replay_expire(fzn_replay_window_t *window, uint64_t now)
{
	size_t kept = 0;
	size_t dropped;

	if (!window || !window->entries)
		return 0;

	/* The worst of the three, because this loop WRITES: it compacts in
	 * place with `entries[kept] = entries[i]` over a range bounded by
	 * `used`. A `used` past `capacity` therefore reads outside the array
	 * and can write outside it too. Refuse to touch a window whose fields
	 * disagree rather than compacting one. */
	if (window->used > window->capacity)
		return 0;

	/* Compact in place, preserving order. Order is not required by
	 * anything here, but a stable window is one a test can compare with
	 * memcmp, and that property is cheap to keep and annoying to
	 * reintroduce.
	 *
	 * `> now` KEEPS, so an entry expiring exactly at `now` is dropped. It
	 * has to be the same boundary `fzn_freshness_check` draws, where
	 * `expires_at <= now` is EXPIRED: an entry the freshness check would
	 * refuse anyway is memory held for nothing, and keeping it costs a slot
	 * the sizing formula already spent. `>= now` here would hold every
	 * entry one tick longer than the horizon it was admitted under, which
	 * is the formula quietly being wrong by one. */
	for (size_t i = 0; i < window->used; i++) {
		if (window->entries[i].expires_at > now) {
			if (kept != i)
				window->entries[kept] = window->entries[i];
			kept++;
		}
	}

	dropped = window->used - kept;
	window->used = kept;

	return dropped;
}

fzn_fresh_err_t fzn_replay_admit(fzn_replay_window_t *window,
                                  const uint8_t nonce[FZN_NONCE_LEN], uint64_t expires_at,
                                  fzn_expiry_rule_t kind, uint64_t now)
{
	fzn_fresh_err_t err;

	if (!window || !window->entries || !nonce)
		return FZN_FRESH_ERR_MALFORMED;

	/* Checked here as well as in the sweep below, and not left to it.
	 * `fzn_replay_expire` refuses a window whose fields disagree rather
	 * than compacting one, which is right -- but refusing means it returns
	 * without repairing anything, so the scan further down would still run
	 * over the bad range. The guard has to be at each entry point that
	 * reads `used`, not at one of them. */
	if (window->used > window->capacity)
		return FZN_FRESH_ERR_MALFORMED;

	/* Before anything that can return early, so "reclaimed on every call"
	 * is true rather than nearly true.
	 *
	 * It used to sit below the two returns beneath this, which meant a
	 * refused frame and an unexpiring grant both skipped it -- so traffic
	 * made entirely of grants, or entirely of stale commands, left dead
	 * entries holding slots indefinitely. Found by frame/test/
	 * freshness_fuzz on its first run, against the invariant that every
	 * live entry is unexpired.
	 *
	 * The consequence was memory rather than a hole: the path that
	 * matters, a fresh command meeting a full window, always swept before
	 * the capacity check. But `fzn_replay_expire` is exported precisely so
	 * a quiet receiver can hand memory back, and a claim in a header that
	 * is only usually true is the kind that gets relied on. */
	(void)fzn_replay_expire(window, now);

	/* Freshness first, so a stale frame never costs a slot. Doing it the
	 * other way round lets a stranger fill the window with rubbish that
	 * was going to be refused anyway -- the denial of service this bound
	 * exists to prevent, introduced by the bound itself.
	 *
	 * THE WINDOW'S OWN HORIZON, not one this call was handed. See
	 * freshness.h: the horizon and the capacity are two halves of one
	 * sizing decision, so a per-call horizon would let a caller widen what
	 * it must remember without widening the storage that holds it.
	 *
	 * A window built by hand rather than by `fzn_replay_init` -- which the
	 * header invites, since a window is a VALUE a test may construct
	 * directly -- reaches this with `max_ahead == 0` and is refused
	 * FZN_FRESH_ERR_MALFORMED by the check itself. That is the same answer
	 * `fzn_replay_init` would have given, at the other entry point, which
	 * is the rule the two guards above this already follow. */
	err = fzn_freshness_check(expires_at, kind, now, window->max_ahead);
	if (err != FZN_FRESH_OK)
		return err;

	/* A grant may legitimately carry no expiry, and there is nothing to
	 * remember it until. It is also not the thing replay protection is
	 * for: sec 4.3 has authority ended by revocation, and re-presenting a
	 * grant is how a chain is verified rather than an attack. Recording
	 * one would fill the window with entries that never expire, which is
	 * exactly the unbounded set this design avoids. */
	if (expires_at == 0)
		return FZN_FRESH_OK;

	for (size_t i = 0; i < window->used; i++) {
		if (nonce_eq(window->entries[i].nonce, nonce))
			return FZN_FRESH_ERR_REPLAY;
	}

	/* Refused rather than evicted. Making room by dropping the oldest
	 * LIVE entry would reopen it to replay, so an attacker who can
	 * generate traffic could flush the window and then replay anything
	 * recorded. See freshness.h. */
	/* >= rather than ==, for the reason chain/revocation.c gives at the
	 * same place: the append below writes at `entries[used]`, and an
	 * equality test lets a corrupt `used` through. */
	if (window->used >= window->capacity)
		return FZN_FRESH_ERR_WINDOW_FULL;

	memcpy(window->entries[window->used].nonce, nonce, FZN_NONCE_LEN);
	window->entries[window->used].expires_at = expires_at;
	window->used++;

	return FZN_FRESH_OK;
}

/* See freshness.h.
 *
 * NO `default:` LABEL, and that is the mechanism rather than an oversight.
 * `-Wswitch` -- which `-Wall` turns on -- warns about an enumerated switch
 * that omits a case only when there is no default, so leaving it out is what
 * makes the compiler notice a code added to fzn_fresh_err_t and not rendered here. A
 * default would silence exactly the warning worth having and turn a new code
 * into a silent "unknown" in somebody's log.
 *
 * The fallback then lives after the switch, where it catches a value that is
 * not an enumerator at all -- which no amount of compiler help can rule out,
 * since the argument may have come from a cast or from the wire. */
const char *fzn_fresh_err_str(fzn_fresh_err_t err)
{
	switch (err) {
	case FZN_FRESH_OK:
		return "ok";
	case FZN_FRESH_ERR_MALFORMED:
		return "malformed argument";
	case FZN_FRESH_ERR_EXPIRED:
		return "expiry has passed";
	case FZN_FRESH_ERR_NO_EXPIRY:
		return "command carries no expiry";
	case FZN_FRESH_ERR_REPLAY:
		return "nonce already seen";
	case FZN_FRESH_ERR_WINDOW_FULL:
		return "replay window full of live entries";
	case FZN_FRESH_ERR_HORIZON:
		return "expiry beyond the replay horizon";
	}

	return "unknown";
}
