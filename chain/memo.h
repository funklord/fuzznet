/* A CHAIN VERDICT, REMEMBERED. project.md sec 4.7c, and sec 354.
 *
 * sec 4.7c names one optimisation and calls it the only real latency win in
 * the receive path: "memoizing a verdict on (sender, capability), invalidated
 * by a generation counter on the revocation store". The number behind it is
 * that a naive loop verifies the SAME chain once per chunk -- 256 times for
 * one chunked message, 51 to 487 ms of Ed25519 -- to reach the same answer
 * every time.
 *
 * ---------------------------------------------------------------------------
 * A CACHE IS A PLACE TO PUT A WRONG ANSWER, SO WHAT IT REFUSES MATTERS MORE
 * THAN WHAT IT REMEMBERS.
 * ---------------------------------------------------------------------------
 *
 * ONLY AFFIRMATIVE VERDICTS ARE KEPT. A refusal is not cached, and that is not
 * an omission: a chain that arrives a moment later would be invisible for as
 * long as a cached refusal lived, and the cost of not caching one is a single
 * verification on a path that is already refusing. The asymmetry is the same
 * one F24 makes -- an answer that under-permits is visible and recoverable,
 * one that over-permits is neither.
 *
 * A HIT REQUIRES THE GENERATION TO MATCH EXACTLY, which invalidates every
 * entry at once the moment any revocation lands. That is coarse on purpose:
 * the alternative is deciding per entry whether a particular revocation could
 * have affected a particular chain, which is the verification this cache
 * exists to avoid. Throwing the table away costs one re-verification per live
 * peer and happens once per revocation, which is rare; being clever here
 * costs a wrong answer when the cleverness is wrong.
 *
 * A HIT REQUIRES THE CHAIN NOT TO HAVE EXPIRED, AND sec 4.7c DOES NOT SAY SO.
 * It names the revocation generation as the invalidator and stops there. But a
 * verdict is a function of `now` as well: `fzn_chain_verify` refuses
 * FZN_CHAIN_ERR_EXPIRED for a hop whose expiry has passed, so a memo built to
 * that description alone would go on authorising a chain after it died, and
 * no revocation need ever land for that to happen. The entry therefore carries
 * the chain's soonest real expiry -- `fzn_chain_t.expires_at`, which
 * `fzn_chain_verify` already computes -- and a hit is refused once `now`
 * reaches it. Recorded because the gap is in the specification rather than in
 * an implementation of it.
 *
 * IT IS KEYED BY AN AUTHENTICATED IDENTITY AND MUST BE CONSULTED AFTER THE
 * TAG. sec 4.7c: "a verdict cached AFTER the tag and keyed by an authenticated
 * identity is safe; the same cache before the tag is the same bug in a new
 * place." The plaintext `sender` a frame claims is anybody's to write, so a
 * cache consulted at step 2 would let a stranger choose which verdict it gets.
 * `admit/admit.c` consults this at step 7, which is four steps below the
 * pivot; a consumer running the steps itself owes the same discipline.
 *
 * THE STORAGE IS THE CALLER'S, like every other table here. A cache is memory
 * somebody has to size, and this library does not allocate -- so a consumer
 * that wants none simply passes none, and `fzn_admit` verifies every time.
 */

#ifndef FZN_CHAIN_MEMO_H
#define FZN_CHAIN_MEMO_H

#include <stddef.h>
#include <stdint.h>

#include "chain.h"

typedef struct fzn_chain_memo_entry {
	uint8_t      root[FZN_PUBKEY_LEN];
	uint8_t      grantee[FZN_PUBKEY_LEN];
	fzn_cap_id_t capability;
	/* The revocation store's generation when this was recorded. ZERO
	 * means the slot was never written: a store's generation starts at
	 * one, so a memset table can never be mistaken for a recorded one. */
	uint64_t     generation;
	/* The chain's soonest real expiry, or FZN_NO_EXPIRY. */
	uint64_t     expires_at;
} fzn_chain_memo_entry_t;

typedef struct fzn_chain_memo {
	fzn_chain_memo_entry_t *entries;
	size_t capacity;
	/* Where the next overwrite lands when every slot is live. */
	size_t cursor;
	/* So a consumer can see whether it is paying for nothing. A cache with
	 * no hit counter is a cache nobody can size. */
	size_t hits;
	size_t misses;
} fzn_chain_memo_t;

/* Point a memo at caller-owned entries, zeroing them. A zero capacity is
 * legal and gives a memo that never hits, which is the honest shape for a
 * consumer that wants the code path without the memory. */
fzn_chain_err_t fzn_chain_memo_init(fzn_chain_memo_t *memo,
                                    fzn_chain_memo_entry_t *entries,
                                    size_t capacity);

/*
 * Has this (root, grantee, capability) been verified, under this generation,
 * and not yet expired?
 *
 * Returns non-zero for a hit. A hit means `fzn_chain_verify` returned
 * FZN_CHAIN_OK for exactly this triple while the revocation store was at
 * exactly this generation, and the chain's expiry has not passed.
 *
 * ANY DOUBT IS A MISS. An unknown triple, a stale generation, a passed expiry
 * and a null argument all answer the same way, and the caller verifies. The
 * counters move, so a consumer can tell a cold cache from a useless one.
 */
int fzn_chain_memo_allows(fzn_chain_memo_t *memo, const uint8_t root[FZN_PUBKEY_LEN],
                          const uint8_t grantee[FZN_PUBKEY_LEN],
                          const fzn_cap_id_t *capability, uint64_t generation,
                          uint64_t now);

/*
 * Remember an affirmative verdict.
 *
 * `verdict` is what `fzn_chain_verify` filled on FZN_CHAIN_OK, and passing one
 * from a refused verification is the caller's bug rather than something this
 * can detect -- the struct carries no status. `generation` is the revocation
 * store's at the moment of that verification, and taking it from AFTER the
 * verification rather than before is the caller's job: a revocation landing
 * mid-verification must invalidate the entry, and recording the earlier
 * number would hide it.
 *
 * FZN_CHAIN_ERR_MALFORMED for a null or a generation of zero. A full memo
 * overwrites rather than refusing, because a cache that stops caching when it
 * fills is a cache that stops working exactly when it is busiest.
 */
fzn_chain_err_t fzn_chain_memo_record(fzn_chain_memo_t *memo,
                                      const fzn_chain_t *verdict,
                                      uint64_t generation);

/* How many slots hold a verdict that could still hit at `generation`. */
size_t fzn_chain_memo_live(const fzn_chain_memo_t *memo, uint64_t generation);

#endif /* FZN_CHAIN_MEMO_H */
