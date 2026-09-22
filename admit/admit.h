/* THE RECEIVE SEQUENCE, RUN IN ORDER. project.md sec 4.7, and sec 350.
 *
 * sec 4.7 states the order a receiver runs its checks in, and sec 4.7c says
 * why that was prose for a month: "An `fzn_admit()` that ran these in order
 * would make the sequence unrepresentable-to-get-wrong, which is the shape
 * this library prefers and uses in `chain.h`." The three things it waited on
 * are answered (secs 345, 348, 349). This is that function.
 *
 * THE NAME IS THE SPECIFICATION'S, AND "ADMIT" IS ALREADY A BUSY WORD HERE.
 * sec 4.7c names the function -- "an `fzn_admit()` that ran these in order" --
 * so the bare form is the document's choice rather than this file's. It sits
 * beside three QUALIFIED uses of the same verb: `fzn_vocabulary_admit` (may
 * this peer say this), `fzn_replay_admit` (has this nonce been seen) and
 * `fzn_chain_store_admit` (take this chain). Each is one layer's admission
 * and this is the sequence that runs several of them, which is why the bare
 * name is right and also why a reader meets the word four times.
 *
 * The suite beside this file is `sequence_test` and not `admit_test` for that
 * reason: `local/test/admit_test.c` already exists and tests
 * `fzn_vocabulary_admit`. Two binaries of one name printing one label into
 * one check log is the collision sec 339 paid for, and it was walked into
 * here on the same day -- caught by `make check` printing "admit_test:" twice
 * with different counts.
 *
 * WHAT IT IS FOR is not convenience. A consumer deriving the sequence from
 * six headers "would be inventing a security property" -- sec 4.7's own
 * words -- and the order is not arbitrary: each step refuses work the next
 * would otherwise do on a stranger's say-so, and two of the steps mutate
 * receiver state. Getting it wrong is not slow, it is a denial of service an
 * off-path attacker can mount with no key.
 *
 *     1  SHAPE        situ's layout check, via `fzn_seal_peek`
 *     2  KEY SELECT   the CLAIMED sender to candidate keys
 *     3  COMMITMENT   derive per candidate and compare; the cheap filter
 *     4  TAG          `fzn_seal_open` -- THE PIVOT
 *     5  FRESHNESS    below the tag, where sec 4.7b moved it
 *     6  REPLAY       the first mutation
 *     7  CHAIN        after replay, which is where measurement beat taste
 *     8  REASSEMBLY   last, the largest and longest-lived mutation
 *
 * Step 0 of sec 4.7, peer credentials, is NOT here and is not step 1 by
 * another name: it is a different channel on a different process, and
 * numbering them together "invites the reading that a frame may arrive
 * authenticated by either, which is a downgrade path in a threat model that
 * forbids one".
 *
 * ---------------------------------------------------------------------------
 * THE TWO RULES THAT ARE NOT ORDERINGS.
 * ---------------------------------------------------------------------------
 *
 * A REFUSAL AT ANY STEP MUST NOT HAVE COST A SLOT AT A LATER ONE. Here that
 * is structural rather than checked: a step that refuses returns immediately,
 * and the two steps that mutate are the last two that run. There is no path
 * on which replay takes an entry and the chain then refuses.
 *
 * AN UNKNOWN SENDER MUST PRODUCE A DROP, NOT AN OBJECT. sec 4.7 calls this
 * "the one a consumer is likeliest to get wrong": no session record, no
 * pending-peer entry, no negative cache, because "every one of those is an
 * unauthenticated write, and they are the natural thing to write". This
 * module cannot stop a `keys` implementation writing one -- it can refuse to
 * give it a reason to, which is why the callback is asked only for keys and
 * is handed nothing to remember.
 *
 * ---------------------------------------------------------------------------
 * THE RESULT CARRIES THE STEP AND THAT STEP'S OWN ERROR.
 * ---------------------------------------------------------------------------
 *
 * sec 4.7c: a consumer sequencing these by hand "handles six error
 * vocabularies ... each module's errors say what that module knows, and
 * collapsing them early would lose distinctions the modules were built to
 * make". So nothing is collapsed. `fzn_admit_result_t` carries the step
 * that refused and that module's own code verbatim: step FRESHNESS carries
 * an `fzn_fresh_err_t`, step CHAIN an `fzn_chain_err_t`, and so on.
 *
 * THE VOCABULARY IS A FIELD AND NOT A FUNCTION OF THE STEP, which the first
 * draft got wrong. Two of the eight steps can refuse BEFORE reaching their
 * module -- an unknown sender at KEY SELECT, and an unprovable capability at
 * CHAIN -- so a step-to-vocabulary table has to name a code from a module
 * that was never called. It did, and it named a chain error whose own
 * comment warns against exactly that use. The result says which vocabulary
 * its `err` belongs to, so the two cannot disagree.
 *
 * THE STEPS ARE NAMED AND NOT NUMBERED, which is sec 348's lesson applied on
 * the day it was learned: a step number is a line number into a list, and
 * sec 4.7's list has been renumbered once already -- a claim that said "step
 * 5 does not exist" went on reading as a statement about whatever later sat
 * at 5. The enumerators carry sec 4.7's current numbers as their VALUES
 * because a reader will want to line the two up, and the NAME is what code
 * should say.
 *
 * ---------------------------------------------------------------------------
 * WHAT IT DOES NOT DO.
 * ---------------------------------------------------------------------------
 *
 * NO CHAIN MEMO. sec 4.7c names one available optimisation -- "memoizing a
 * verdict on (sender, capability), invalidated by a generation counter on the
 * revocation store" -- and calls it the one real latency win, a naive loop
 * verifying the same chain 256 times for one chunked message, 51-487 ms of
 * signature checking. It is not here because a cache is memory a consumer
 * sizes and a lifetime a consumer owns, and because the same cache one step
 * earlier is a verdict an attacker chose. A consumer that wants it holds it
 * outside and passes a store whose lookups are already cheap.
 *
 * NO POLICY ABOUT WHICH KINDS NEED WHAT. Whether a kind is a command that
 * must carry an expiry is the consumer's vocabulary (sec 5), so the rule
 * arrives through `expiry_rule` rather than being decided here. Whether a
 * kind needs a capability at all is `chain/authz.h`'s question; THIS function
 * is the strict sequence and verifies a chain for every frame. A consumer
 * wanting the nuance runs the steps itself -- and then owns the order again,
 * which is the trade this function exists to offer.
 */

#ifndef FZN_ADMIT_H
#define FZN_ADMIT_H

#include <stddef.h>
#include <stdint.h>

#include "../chain/chain.h"
#include "../chain/chain_store.h"
#include "../chain/memo.h"
#include "../chunk/reassembly.h"
#include "../frame/freshness.h"
#include "../session/commitment.h"
#include "../wire/seal.h"

/* sec 4.7's steps, by name. The values are that list's current numbers. */
typedef enum fzn_admit_step {
	FZN_ADMIT_ADMITTED   = 0,
	FZN_ADMIT_SHAPE      = 1,
	FZN_ADMIT_KEY_SELECT = 2,
	FZN_ADMIT_COMMITMENT = 3,
	FZN_ADMIT_TAG        = 4,
	FZN_ADMIT_FRESHNESS  = 5,
	FZN_ADMIT_REPLAY     = 6,
	FZN_ADMIT_CHAIN      = 7,
	FZN_ADMIT_REASSEMBLY = 8
} fzn_admit_step_t;

/* Which error vocabulary a step's `err` belongs to, so a caller can render it
 * without a table of its own. */
typedef enum fzn_admit_vocab {
	FZN_ADMIT_VOCAB_NONE = 0,
	FZN_ADMIT_VOCAB_SEAL,
	FZN_ADMIT_VOCAB_COMMITMENT,
	FZN_ADMIT_VOCAB_FRESH,
	FZN_ADMIT_VOCAB_CHAIN,
	FZN_ADMIT_VOCAB_REASM,
	/* Step 2 refused before reaching any module: an unknown sender is a
	 * drop, and a drop has nothing to say. */
	FZN_ADMIT_VOCAB_UNKNOWN_SENDER,
	/* Step 7 refused before reaching `chain/`: either no root anchors this
	 * sender, or this host holds no live chain for (root, capability,
	 * sender). Neither is a chain ERROR -- no chain was opened -- and
	 * borrowing one would be the mistake `chain.h` warns about at
	 * FZN_CHAIN_ERR_UNKNOWN_TARGET, where folding an ordinary absence into
	 * a specific code "would make ordinary propagation look like an
	 * attack". This host cannot prove the frame's authority, and fails
	 * closed. */
	FZN_ADMIT_VOCAB_NO_CHAIN
} fzn_admit_vocab_t;

/* A stable, allocation-free name for a vocabulary. */
const char *fzn_admit_vocab_str(fzn_admit_vocab_t vocab);

/* A stable, allocation-free name for a step. */
const char *fzn_admit_step_str(fzn_admit_step_t step);

/* One candidate key pair for a sender: what opens the seal, and what the
 * commitment is derived under. */
typedef struct fzn_admit_key {
	uint8_t aead[FZN_AEAD_KEY_LEN];
	uint8_t commitment[FZN_COMMITMENT_KEY_LEN];
} fzn_admit_key_t;

/* The two questions this library cannot answer, as a vtable -- the same seam
 * shape `chain.h`'s signer and `facet.h`'s index use. */
typedef struct fzn_admit_ops {
	void *ctx;

	/* Step 2. Fill `out` with the keys held for the CLAIMED `sender` and
	 * return how many. Zero is an ordinary answer and means DROP.
	 *
	 * `sender` IS A CLAIM AND NOT A FACT -- the head is plaintext, so
	 * anyone can write any sender into a frame. It is safe for choosing
	 * which key to try and for nothing else: do not log it, count it,
	 * rate-limit on it, or create anything keyed by it. Nothing is
	 * authenticated until step 4. */
	size_t (*keys)(void *ctx, const uint8_t *sender, fzn_admit_key_t *out,
	               size_t out_cap);

	/* Step 5. The expiry rule for a frame of this kind: whether a frame of
	 * this kind is a command that must carry an expiry (sec 4.3). The
	 * consumer's vocabulary, which sec 5 keeps out of the core.
	 *
	 * Called with the kind from the OPENED frame, so by then it is
	 * authenticated. */
	fzn_expiry_rule_t (*expiry_rule)(void *ctx, uint8_t kind);

	/* Step 7. The root this host anchors `sender` to, written to `out`.
	 * Return zero when there is none, which refuses the frame: a sender
	 * whose authority hangs from no root this host trusts is not one whose
	 * capability can be proven here.
	 *
	 * Called with the AUTHENTICATED sender. */
	int (*root_for)(void *ctx, const uint8_t *sender, uint8_t out[FZN_PUBKEY_LEN]);
} fzn_admit_ops_t;

/* Everything the sequence touches, gathered so a caller cannot pass half of
 * it. Each is the caller's and outlives the call. */
typedef struct fzn_admit_env {
	const fzn_admit_ops_t   *ops;
	const fzn_hash_ops_t    *hash;
	const fzn_aead_ops_t    *aead;
	const fzn_sign_ops_t    *sign;
	fzn_replay_window_t     *replay;
	const fzn_chain_store_t *chains;
	const fzn_revocation_store_t *revocations;
	const fzn_manifest_state_t   *manifest;  /* optional; sec 13d stage 2 */
	/* Optional. When given, step 7 asks it before verifying and records
	 * an affirmative verdict after -- sec 4.7c's one real latency win,
	 * a chunked message otherwise verifying one chain 256 times.
	 *
	 * IT IS CONSULTED AT STEP 7, WHICH IS FOUR STEPS BELOW THE PIVOT, and
	 * that placement is the whole of its safety: the sender it is keyed by
	 * is authenticated. The same cache at step 2 would be keyed by a
	 * plaintext claim anybody can write.
	 *
	 * NO REVOCATION STORE MEANS NO CACHING, and that falls out rather than
	 * being enforced: the generation of a null store is zero, and a memo
	 * refuses to record or match on zero. A cache nothing can invalidate
	 * is a permanent authorisation, so the degenerate case fails safe. */
	fzn_chain_memo_t        *memo;
	/* Optional. When NULL the sequence ends after step 7 and the opened
	 * frame is the result -- a consumer that does not chunk needs no
	 * table, and inventing one for it would be inventing a memory bound. */
	fzn_reasm_t             *reassembly;
	/* Freshness's horizon (sec 4.3): how far ahead an expiry may sit. */
	uint64_t                 max_ahead;
} fzn_admit_env_t;

typedef struct fzn_admit_result {
	/* Where it stopped, or FZN_ADMIT_ADMITTED. */
	fzn_admit_step_t step;
	/* Which vocabulary `err` belongs to. NONE, UNKNOWN_SENDER and NO_CHAIN
	 * all mean `err` says nothing and must not be rendered as a code. */
	fzn_admit_vocab_t vocab;
	/* That module's own code, verbatim and uncollapsed. */
	int err;
	/* Valid from step 4 onward -- that is, whenever `step` is TAG or
	 * later, including when admitted. Points into `frame`. */
	fzn_opened_t opened;
	/* Set when step 8 ran and completed a message; NULL otherwise,
	 * including for a chunk that was accepted and is not yet whole. */
	fzn_partial_t *message;
} fzn_admit_result_t;

/*
 * Run sec 4.7's steps 1 to 8 over one datagram.
 *
 * `frame` is decrypted IN PLACE by step 4, as `fzn_seal_open` documents, so
 * it is the caller's mutable buffer and holds plaintext afterwards.
 * `candidates`/`candidate_cap` is scratch for step 2's key set; a caller with
 * one key per sender passes one slot.
 *
 * Returns FZN_ADMIT_ADMITTED in `out->step` when every step passed. Any other
 * value is the step that refused, with `out->err` carrying that module's own
 * code. `*out` is always written.
 *
 * A fault in the arguments themselves is reported as step FZN_ADMIT_SHAPE
 * with the seal vocabulary, and a null environment is refused before anything
 * runs.
 */
void fzn_admit(uint8_t *frame, size_t frame_len, uint64_t now,
               const fzn_admit_env_t *env, fzn_admit_key_t *candidates,
               size_t candidate_cap, fzn_admit_result_t *out);

#endif /* FZN_ADMIT_H */
