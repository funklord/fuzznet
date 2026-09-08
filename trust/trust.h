/* Where a pinned root comes from, including trust on first use.
 *
 * sec 4.2 said the root is "pinned rather than adopted" and `chain/chain.h`
 * still says so, with an argument worth keeping: **there is no nullable-root
 * variant on purpose, because one function with an optional pin is a function
 * somebody calls without the pin.** That remains true and is not weakened
 * here.
 *
 * WHAT CHANGED (2026-08-26, at the copyright holder's instruction) is that
 * fuzzypickles needs TOFU and this library is absorbing its host management.
 * A joining host has no anchor and must get one somehow; refusing to have a
 * path meant the path existed anyway, in the consumer, written three times.
 *
 * NOT YET INCLUDED BY THAT CONSUMER, as of 2026-09-03. fuzzypickles reported
 * -- unprompted, having audited the headers it does not use -- that it
 * includes nothing from here for TOFU and its own implementation is still
 * the one running.
 *
 * Recorded as a fact and nothing more. The instruction above stands; this
 * says only that the adoption it anticipated has not happened yet, so
 * nothing in this file has been exercised by the consumer it was written
 * for. That matters to a reader deciding how much this design has been
 * tested by contact rather than by argument. Whether and when it is adopted
 * is the copyright holder's, and fuzzypickles has raised it with them
 * directly.
 *
 * HOW BOTH HOLD AT ONCE. `fzn_chain_verify` is untouched: it still takes a
 * root and still refuses a chain rooted anywhere else. This file is only
 * about how a host CAME to have that root, and it hands one over through
 * `fzn_trust_root`, which returns NULL when there is none -- so a consumer
 * that has not anchored cannot accidentally verify against nothing. The
 * verification-time property is unchanged; the bootstrap is now named.
 *
 * TRUST ON FIRST USE IS EXACTLY THAT, AND ITS WEAKNESS IS THE FIRST CONTACT.
 * Nothing authenticates the key adopted at that moment -- whoever answers
 * first is trusted, and an attacker in position then is trusted for ever
 * after. What TOFU buys is that every LATER contact is authenticated, so an
 * attacker who arrives afterwards is refused. That is a real property and a
 * narrow one.
 *
 * So a consumer using `fzn_trust_adopt` **owes its user a way to check the
 * anchor out of band** -- a fingerprint to compare, a confirmation step,
 * something. This module records the moment of adoption (`adopted_at`) and
 * how the anchor arrived (`fzn_trust_source`) precisely so that a consumer
 * can show it. A library cannot make first contact safe; it can refuse to
 * hide when it happened.
 *
 * ONCE ANCHORED, A DIFFERENT KEY IS REFUSED. That is the whole security
 * content of "first". Re-anchoring to something else would make it trust on
 * EVERY use, which is no trust at all, so a second key is an error a consumer
 * should treat as an attack rather than as a retry. A caller that genuinely
 * must start again wants a new `fzn_trust_t`, on the same reasoning
 * `record/journal.h` gives for never rewinding an anchor.
 */

#ifndef FZN_TRUST_H
#define FZN_TRUST_H

#include "../chain/chain.h"

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_trust_err {
	FZN_TRUST_OK = 0,
	FZN_TRUST_ERR_MALFORMED = -1,
	/* Anchored already, to a DIFFERENT key. The one error here that a
	 * consumer should treat as hostile rather than as a condition. */
	FZN_TRUST_ERR_ANCHORED = -2,
	/* Anchored already, to the SAME key. An echo -- a join repeated, a
	 * bundle delivered twice -- and not a fault. Distinguished from OK so
	 * that a caller can tell a first adoption from a repeat, which is
	 * exactly what it needs to know before telling a user anything. */
	FZN_TRUST_ERR_UNCHANGED = -3,
} fzn_trust_err_t;

/* How the anchor arrived, so a consumer can say so. */
typedef enum fzn_trust_source {
	FZN_TRUST_NONE = 0,
	/* Configured out of band: an operator typed it, a package shipped it.
	 * Authenticated by whatever put it there. */
	FZN_TRUST_PINNED = 1,
	/* Adopted on first contact. Authenticated by nothing; see above. */
	FZN_TRUST_ADOPTED = 2,
	/*
	 * The node is its own root. project.md sec 136.
	 *
	 * A NODE ALONE IS A COMPLETE ESTATE OF ONE -- it can issue, sign and
	 * serve itself -- so this is a working state rather than a placeholder
	 * waiting to be filled. The alternative considered and rejected was
	 * shipping a node with no anchor at all, and the difference is not
	 * tidiness: an unanchored node adopts the next root offered, so
	 * whoever reaches it first owns it.
	 *
	 * THIS IS THE ONE SOURCE A JOIN MAY REPLACE, AND ONLY BY A PIN. See
	 * `fzn_trust_self` for the rule and for why adopting over it is
	 * refused.
	 */
	FZN_TRUST_SELF = 3,
} fzn_trust_source_t;

/* Declared, not included. sec 209. */
struct flog_t;

typedef struct fzn_trust {
	uint8_t root[FZN_PUBKEY_LEN];
	uint64_t adopted_at;
	fzn_trust_source_t source;
	/* Where this anchor says what happened, or NULL for silence. */
	struct flog_t *log;
} fzn_trust_t;

/*
 * Give this anchor somewhere to say what happened, or NULL to silence it.
 *
 * sec 222. THIS HEADER ASKED FOR IT BEFORE THERE WAS ANYWHERE TO PUT IT:
 * "A library cannot make first contact safe; it can refuse to hide when it
 * happened." Three lines, on subsystem `trust/anchor`:
 *
 *   NOTE  an anchor taken, naming HOW it arrived and its fingerprint
 *   WARN  a re-anchor refused, naming the transition that was attempted
 *   WARN  an all-zero root refused
 *
 * THE REFUSAL IS THE ONE A CONSUMER SHOULD TREAT AS HOSTILE, and
 * FZN_TRUST_ERR_ANCHORED cannot say WHICH refusal it was. `self -> adopted`
 * is an attempt on the one window this design closes -- whoever answers first
 * becoming the root -- while `pinned -> pinned` with a different key is
 * usually a misconfiguration. Same code, different stories, and the line
 * carries both source words from `fzn_trust_source_str` rather than inventing
 * a second vocabulary for them.
 *
 * THE FINGERPRINT IS IN THE SUCCESS LINE, and it goes LAST. sec 207's rule:
 * a terminal clips from the right, so the verdict -- how this anchor arrived
 * -- must precede 79 characters of hex that a reader is comparing by eye.
 * It is a public key, so there is nothing here to withhold, and this module
 * exists precisely so a consumer can show it.
 *
 * FZN_TRUST_ERR_UNCHANGED IS DELIBERATELY NOT LOGGED. This header calls it
 * "an echo -- a join repeated, a bundle delivered twice -- and not a fault",
 * the return value says exactly that, and there is nothing the line would add
 * that the code cannot already say. sec 201's rule: a line added so that
 * every branch has one is symmetry rather than merit.
 *
 * AND A RESTORE IS SILENT, which is correct and is worth knowing.
 * `fzn_persist_trust_open` rebuilds an anchor by calling `fzn_trust_init` and
 * then `fzn_trust_pin` or `fzn_trust_adopt` -- so it goes through the anchoring
 * rule on purpose, to refuse laundering a provenance. The init clears this
 * field, so a restored anchor emits nothing: coming back from disk is not a
 * first contact and must not read like one. THE COROLLARY IS A TRAP TO KNOW
 * ABOUT: that same init clears a log a caller had already set, so set it
 * AFTER any call that re-initialises the anchor, `fzn_persist_trust_open`
 * included.
 */
void fzn_trust_set_log(fzn_trust_t *trust, struct flog_t *log);

/* An anchor with nothing in it. */
void fzn_trust_init(fzn_trust_t *trust);

/* Anchor to a root that arrived out of band. */
fzn_trust_err_t fzn_trust_pin(fzn_trust_t *trust, const uint8_t root[FZN_PUBKEY_LEN]);

/* Anchor to a root on first contact, recording when.
 *
 * `now` is stored rather than checked: this module has no opinion about
 * clocks, and the timestamp exists so a consumer can tell a user when its
 * trust was established. */
fzn_trust_err_t fzn_trust_adopt(fzn_trust_t *trust, const uint8_t root[FZN_PUBKEY_LEN],
                                 uint64_t now);

/*
 * Anchor to this node's OWN key, so that a node with nobody to trust yet
 * trusts itself rather than nothing. project.md sec 136.
 *
 * WHAT IT BUYS, AND IT IS NOT BOOKKEEPING: a self-rooted node CANNOT BE
 * TAKEN BY TRUST ON FIRST USE. `fzn_trust_adopt` over any existing anchor is
 * refused, this one included, so the window in which whoever answers first
 * becomes the root never opens. An unanchored node has that window from the
 * moment it boots.
 *
 * AND A PIN MAY STILL REPLACE IT, WHICH IS THE JOIN. That asymmetry is the
 * whole design:
 *
 *     self -> pinned     permitted; an operator said so, out of band
 *     self -> adopted    REFUSED; nothing authenticated that
 *     self -> self       refused, like any other re-anchoring
 *     pinned or adopted -> anything else    refused, as before
 *
 * A pin is authenticated by whoever typed it and an adopt by nothing at all,
 * so allowing the first and refusing the second is what makes a self-root a
 * protection rather than a formality. A caller that genuinely must start
 * over wants a new `fzn_trust_t`, as it always did.
 *
 * `own` is this node's own public key. Nothing here checks that it IS the
 * caller's -- this module never sees a private key and could not -- so a
 * caller passing somebody else's key has pinned it under a name that says
 * otherwise. That is why the accessor exists: `fzn_trust_source_of` is what
 * a consumer shows a user, and it is only as true as the caller made it.
 */
fzn_trust_err_t fzn_trust_self(fzn_trust_t *trust, const uint8_t own[FZN_PUBKEY_LEN]);

/* The root to verify against, or NULL when there is none.
 *
 * NULL rather than a zero key, because `fzn_chain_verify` refuses NULL and
 * would happily verify against a key of zeroes -- and an anchor nobody set
 * must fail closed rather than match whatever an attacker can also produce. */
const uint8_t *fzn_trust_root(const fzn_trust_t *trust);

/* How this anchor arrived. `FZN_TRUST_NONE` when there is none. */
fzn_trust_source_t fzn_trust_source_of(const fzn_trust_t *trust);

/* When it was adopted, or 0 if it was pinned, self-rooted or absent. */
uint64_t fzn_trust_adopted_at(const fzn_trust_t *trust);

/* A short name for `fzn_trust_err_t`. Never NULL. */
const char *fzn_trust_err_str(fzn_trust_err_t err);

/* How this anchor arrived, in words for a person. Never NULL.
 *
 * THIS IS THE SENTENCE THE HEADER ABOVE SAYS A CONSUMER OWES ITS USER. TOFU's
 * weakness is the first contact and its strength is every contact after, and
 * those are different things to be told -- so "adopted on first contact" and
 * "configured out of band" must not read alike, and neither may be confused
 * with a node that has simply rooted itself. Every consumer would otherwise
 * write these four strings, four times, in four wordings. */
const char *fzn_trust_source_str(fzn_trust_source_t source);

/* Bytes a fingerprint needs: 32 bytes as 16 groups of four hex digits,
 * single-spaced, and a terminator. */
#define FZN_TRUST_FINGERPRINT_LEN 80u

/*
 * Format a public key for a person to compare out of band.
 *
 * `trust.h` says at length that a consumer using `fzn_trust_adopt` owes its
 * user a way to check the anchor -- "a fingerprint to compare, a confirmation
 * step, something" -- and then left every consumer to invent the format. Four
 * spellings of one fingerprint is four things a user cannot compare against
 * each other, which is the whole purpose defeated.
 *
 * IT IS THE KEY ITSELF, NOT A HASH OF IT, and that is why this needs no hash
 * seam. A fingerprint is a digest elsewhere because keys are large; this one
 * is already 32 bytes of public data, so hashing would add a step, a
 * dependency and a second thing to agree about, and subtract nothing.
 *
 * ALL OF IT, NEVER TRUNCATED. Showing a prefix is a security decision -- it
 * is what makes two keys comparable that are not equal -- and a library must
 * not take it quietly on a caller's behalf. Sixteen groups fit two terminal
 * lines and a caller that wants fewer is choosing to, in the open.
 *
 * TAKES A KEY RATHER THAN AN ANCHOR, deliberately: an unanchored trust has no
 * root, and `fzn_trust_root` already returns NULL for exactly that. A caller
 * passes what that gave it, so the unanchored case goes through the existing
 * fail-closed path instead of a second one invented here -- and the same
 * function then serves a peer's key, a grantee's, or any other.
 *
 * `cap` must be at least FZN_TRUST_FINGERPRINT_LEN. Nothing is written unless
 * the whole string fits. */
fzn_trust_err_t fzn_trust_fingerprint(const uint8_t key[FZN_PUBKEY_LEN], char *out,
                                       size_t cap);

#endif /* FZN_TRUST_H */
