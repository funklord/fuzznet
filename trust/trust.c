/* See trust.h. */

#include "trust.h"

/* Diagnostics through flog, vendored and possibly absent. sec 209. */
#ifdef FZN_FLOG_ON
#include "flog.h"
#define TRUST_LOG(t, sub, sev, ...)                                                        \
	do {                                                                               \
		if ((t) && (t)->log)                                                       \
			flog_printf((t)->log, sub, sev, FLOG_MSG_NONE, __VA_ARGS__);        \
	} while (0)
#else
#define TRUST_LOG(t, sub, sev, ...) ((void)0)
#endif

#include "../constant_time/constant_time.h"

#include <string.h>

void fzn_trust_set_log(fzn_trust_t *trust, struct flog_t *log)
{
	if (!trust)
		return;

	trust->log = log;
}

void fzn_trust_init(fzn_trust_t *trust)
{
	if (!trust)
		return;

	/* THIS CLEARS THE LOG TOO, and the header says why that is right and
	 * where it is a trap: a restore goes through here, so it is silent,
	 * and a caller that set a log before a restore has to set it again. */
	memset(trust, 0, sizeof(*trust));
	trust->source = FZN_TRUST_NONE;
}

/* Both entry points differ only in what they record about provenance, so the
 * anchoring rule lives in one place and cannot come to differ between them. */
static fzn_trust_err_t anchor(fzn_trust_t *trust, const uint8_t root[FZN_PUBKEY_LEN],
                               fzn_trust_source_t source, uint64_t now)
{
	fzn_trust_source_t replacing;

	if (!trust || !root)
		return FZN_TRUST_ERR_MALFORMED;
	/* AN ALL-ZERO ROOT IS REFUSED, and the header already argued for this
	 * without the code doing it.
	 *
	 * `trust.h` says `fzn_trust_root` returns NULL rather than a zero key
	 * "because `fzn_chain_verify` refuses NULL and would happily verify
	 * against a key of zeroes -- and an anchor nobody set must fail closed
	 * rather than match whatever an attacker can also produce". That guard
	 * was keyed on `source`, not on the BYTES, so anchoring all zeroes
	 * succeeded and `fzn_trust_root` then handed them to `fzn_chain_verify`
	 * as a real root. Measured: adopt returns ok, and the accessor returns
	 * non-NULL and all zero.
	 *
	 * The way in is not exotic: a caller anchoring from a join message it
	 * parsed only partly, whose root field was never filled, gets a
	 * permanent successful anchor to a key nobody holds -- and it is
	 * permanent, because the next anchor is refused as ANCHORED.
	 *
	 * MALFORMED rather than a new code: an all-zero key is the caller
	 * handing over a buffer it did not fill, which is what MALFORMED means
	 * throughout this library.
	 *
	 * BRANCH-FREE, THOUGH IT NEED NOT BE. The loop accumulates with `|`
	 * over all 32 bytes and never returns early, so it takes the same time
	 * whatever the key holds -- which is the constant-time idiom, arrived
	 * at because it is also the plainest way to ask "is any byte set".
	 *
	 * This comment used to claim the opposite: "not constant time,
	 * deliberately". That was wrong about the code beneath it, and the
	 * reasoning it offered was sound for a decision nobody had made -- the
	 * comparison is against a constant, so an early exit WOULD have been
	 * fine here, and the code does not take one.
	 *
	 * Left as it is rather than made to match the comment. A branch-free
	 * loop over 32 bytes costs nothing worth measuring, and rewriting
	 * correct code to satisfy a description of it is the wrong direction
	 * -- `evidence.md` says to suspect the check before the code, and a
	 * comment is a check a reader runs. */
	{
		uint8_t any = 0;
		size_t i;

		for (i = 0; i < FZN_PUBKEY_LEN; i++)
			any = (uint8_t)(any | root[i]);
		if (any == 0) {
			/* WHICH MALFORMED, since a null argument returns the
			 * same code. An all-zero root is a caller handing over
			 * a buffer it never filled -- from a join message it
			 * parsed only partly, say -- and the comment above
			 * says what accepting it would have cost: a permanent
			 * successful anchor to a key nobody holds. A consumer
			 * developer wants to be told which of the two it
			 * did. */
			TRUST_LOG(trust, "trust/anchor", FLOG_WARN,
			          "refusing an all-zero root offered as %s, which is a buffer "
			          "the caller never filled rather than a key",
			          fzn_trust_source_str(source));
			return FZN_TRUST_ERR_MALFORMED;
		}
	}

	if (trust->source != FZN_TRUST_NONE) {
		/* Constant time, because the comparison is against a value an
		 * attacker chooses and repeats: telling them how much of their
		 * guess matched is the one thing this must not do. */
		if (fzn_ct_memeq(trust->root, root, FZN_PUBKEY_LEN))
			return FZN_TRUST_ERR_UNCHANGED;
		/* THE ONE PERMITTED REPLACEMENT, and the asymmetry is the point.
		 * A self-root is a node trusting itself for want of anybody
		 * else, so an operator pinning a real root is a join. An ADOPT
		 * over it is refused like any other, which is what stops a
		 * self-rooted node being taken by whoever answers first --
		 * see `trust.h`, which sets out the whole table. */
		if (!(trust->source == FZN_TRUST_SELF && source == FZN_TRUST_PINNED)) {
			/* THE TRANSITION, which FZN_TRUST_ERR_ANCHORED cannot
			 * carry. `self -> adopted` is an attempt on the one
			 * window this design closes, and `pinned -> pinned`
			 * with a different key is usually a misconfiguration;
			 * the code is the same and the stories are not. Both
			 * words come from this module's own
			 * `fzn_trust_source_str`, so a reader of a log and a
			 * reader of a screen are told the same thing. */
			TRUST_LOG(trust, "trust/anchor", FLOG_WARN,
			          "refusing to re-anchor: this host's root is %s and a "
			          "different one arrived as %s, which a consumer should "
			          "treat as hostile rather than as a retry",
			          fzn_trust_source_str(trust->source),
			          fzn_trust_source_str(source));
			return FZN_TRUST_ERR_ANCHORED;
		}
	}

	replacing = trust->source;
	memcpy(trust->root, root, FZN_PUBKEY_LEN);
	trust->source = source;
	trust->adopted_at = (source == FZN_TRUST_ADOPTED) ? now : 0u;

	/* AN ANCHOR TAKEN, which no return value reports because nothing went
	 * wrong. This header asked for the line before there was anywhere to
	 * put it: "A library cannot make first contact safe; it can refuse to
	 * hide when it happened."
	 *
	 * THE FINGERPRINT GOES LAST. sec 207: a terminal clips from the right,
	 * so how the anchor arrived has to precede 79 characters of hex that a
	 * person is comparing by eye. A whole one or none -- `fingerprint`
	 * writes nothing unless all of it fits, and a prefix is the comparison
	 * this library refuses to invite. */
	/* GUARDED ON THE LOG ITSELF, not left to the macro. The macro's own
	 * test comes too late: the fingerprint below is 79 characters of hex
	 * built before the call, so without this it is computed on every anchor
	 * whether anybody is listening or not. It also keeps `replacing` read
	 * in the arrangement without flog, where the macro expands to nothing
	 * and a set-but-unused variable is a warning. */
	if (trust->log) {
		char print[FZN_TRUST_FINGERPRINT_LEN];

		/* DISCARDED EXPLICITLY, the second instance of this after
		 * `persist/persist_file.c`'s helper: with flog absent the macro
		 * expands to nothing, the ternaries below it vanish with it, and
		 * `replacing` is written and never read. See sec 222 -- the
		 * pattern is that a value computed ONLY to be logged needs one
		 * of these, and the emit sites that name struct fields the
		 * surrounding code uses anyway need none. */
		(void)replacing;

		if (fzn_trust_fingerprint(trust->root, print, sizeof(print)) != FZN_TRUST_OK)
			print[0] = '\0';
		TRUST_LOG(trust, "trust/anchor", FLOG_NOTE,
		          "anchored: %s%s%s, fingerprint %s", fzn_trust_source_str(source),
		          replacing == FZN_TRUST_NONE ? "" : ", replacing ",
		          replacing == FZN_TRUST_NONE ? ""
		                                      : fzn_trust_source_str(replacing),
		          print);
	}

	return FZN_TRUST_OK;
}

fzn_trust_err_t fzn_trust_pin(fzn_trust_t *trust, const uint8_t root[FZN_PUBKEY_LEN])
{
	return anchor(trust, root, FZN_TRUST_PINNED, 0);
}

fzn_trust_err_t fzn_trust_adopt(fzn_trust_t *trust, const uint8_t root[FZN_PUBKEY_LEN],
                                 uint64_t now)
{
	return anchor(trust, root, FZN_TRUST_ADOPTED, now);
}

fzn_trust_err_t fzn_trust_self(fzn_trust_t *trust, const uint8_t own[FZN_PUBKEY_LEN])
{
	return anchor(trust, own, FZN_TRUST_SELF, 0);
}

const uint8_t *fzn_trust_root(const fzn_trust_t *trust)
{
	if (!trust || trust->source == FZN_TRUST_NONE)
		return NULL;

	return trust->root;
}

fzn_trust_source_t fzn_trust_source_of(const fzn_trust_t *trust)
{
	return trust ? trust->source : FZN_TRUST_NONE;
}

uint64_t fzn_trust_adopted_at(const fzn_trust_t *trust)
{
	return trust ? trust->adopted_at : 0u;
}

const char *fzn_trust_err_str(fzn_trust_err_t err)
{
	switch (err) {
	case FZN_TRUST_OK:
		return "ok";
	case FZN_TRUST_ERR_MALFORMED:
		return "malformed argument";
	case FZN_TRUST_ERR_ANCHORED:
		return "already anchored to a different root";
	case FZN_TRUST_ERR_UNCHANGED:
		return "already anchored to this root";
	}

	return "unknown";
}

const char *fzn_trust_source_str(fzn_trust_source_t source)
{
	switch (source) {
	case FZN_TRUST_NONE:
		return "no anchor";
	case FZN_TRUST_PINNED:
		return "configured out of band";
	case FZN_TRUST_ADOPTED:
		return "adopted on first contact";
	case FZN_TRUST_SELF:
		return "this node's own key";
	}

	return "unknown";
}

fzn_trust_err_t fzn_trust_fingerprint(const uint8_t key[FZN_PUBKEY_LEN], char *out,
                                       size_t cap)
{
	static const char DIGITS[] = "0123456789abcdef";
	size_t i;
	size_t at = 0;

	if (!key || !out)
		return FZN_TRUST_ERR_MALFORMED;
	/* NOTHING IS WRITTEN UNLESS ALL OF IT FITS. A truncated fingerprint is
	 * the one output this must never produce: it is indistinguishable from
	 * a whole one at a glance, and comparing a prefix is the security
	 * decision the header refuses to take quietly. */
	if (cap < FZN_TRUST_FINGERPRINT_LEN)
		return FZN_TRUST_ERR_MALFORMED;

	for (i = 0; i < FZN_PUBKEY_LEN; i++) {
		/* A space before every group but the first: groups are two
		 * bytes, so the separator falls on even indices past zero. */
		if (i != 0 && (i % 2u) == 0u)
			out[at++] = ' ';
		out[at++] = DIGITS[key[i] >> 4];
		out[at++] = DIGITS[key[i] & 0x0fu];
	}
	out[at] = '\0';

	return FZN_TRUST_OK;
}
