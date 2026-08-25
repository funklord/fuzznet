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

fzn_fresh_err_t fzn_freshness_check(uint64_t expires_at, fzn_frame_kind_t kind, uint64_t now)
{
	if (kind == FZN_FRAME_GRANT) {
		/* sec 4.3: a grant's expiry is optional and absent by default,
		 * and authority is ended by revocation rather than by a clock.
		 * A grant that DOES state one is still held to it -- see sec 14,
		 * where the wording is recorded as ambiguous and this reading
		 * chosen because it fails closed. */
		if (expires_at == 0)
			return FZN_FRESH_OK;
		return expires_at <= now ? FZN_FRESH_ERR_EXPIRED : FZN_FRESH_OK;
	}

	/* A command. Both halves are mandatory, and the second is the one an
	 * implementation forgets: refusing a passed expiry while accepting an
	 * absent one means anybody who omits the field is exempt from the
	 * rule, which is worse than not having it. */
	if (expires_at == 0)
		return FZN_FRESH_ERR_NO_EXPIRY;
	if (expires_at <= now)
		return FZN_FRESH_ERR_EXPIRED;

	return FZN_FRESH_OK;
}

fzn_fresh_err_t fzn_replay_init(fzn_replay_window_t *window, fzn_replay_entry_t *entries,
                                 size_t capacity)
{
	if (!window || !entries || capacity == 0)
		return FZN_FRESH_ERR_MALFORMED;

	window->entries = entries;
	window->capacity = capacity;
	window->used = 0;

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
	 * reintroduce. */
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
                                  fzn_frame_kind_t kind, uint64_t now)
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
	 * exists to prevent, introduced by the bound itself. */
	err = fzn_freshness_check(expires_at, kind, now);
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
	}

	return "unknown";
}
