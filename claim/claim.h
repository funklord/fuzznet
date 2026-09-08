/*
 * Which process owns the identity's mutable state, and how it stops owning
 * it.
 *
 * project.md sec 132. Several processes of one user share one identity, one
 * store and one job. Most of what they share is immutable and needs no
 * arbitration -- records are append-only and a blob leaf is named by its own
 * digest. Four things are not, and `persist/persist.h`'s table names them:
 * the trust anchor, the prekey secret, the pinned peers and the ratchet
 * chains. Those are mutable and not derivable from records, so exactly one
 * process may hold them.
 *
 * THE RATCHET IS WHAT FORCES THIS, not efficiency. `fzn_ratchet_chain_t` is
 * per direction per peer and persist.h singles it out as the one where
 * persisting at the wrong moment is worse than not persisting at all. Two
 * processes advancing one chain desynchronise it, which is the failure a
 * ratchet cannot survive. Sequence allocation then rides along on the same
 * ownership rather than needing a second mechanism -- one writer per
 * (issuer, stream) is a consequence of there being one owner.
 *
 * WHY A CLAIM RATHER THAN AN ELECTION. The processes are interchangeable:
 * the same software with the same job, so it does not matter which one wins.
 * There is no better and worse candidate to choose between, which is what
 * makes this a mutex over a job rather than a leadership protocol.
 *
 * WHY IT MUST BE RELEASED BY SOMETHING OTHER THAN A TIMEOUT. A heartbeat can
 * declare a slow or paused holder dead while it is still running, and two
 * processes then advance one ratchet chain. A claim whose release is the
 * holder's death -- observed rather than inferred -- cannot produce that
 * false positive, which is why taking a released claim is safe enough to
 * resume somebody else's sessions with. `claim/claim_file.h` is that
 * backend; the seam is here so the discipline can be tested without one.
 *
 * WHAT THIS DOES NOT DO, AND CANNOT. It detects DEATH, not HANG. A holder
 * wedged in a spin or blocked on a socket with no timeout still holds its
 * claim, and no backend can tell that from a holder doing slow work. The
 * escalation is a watchdog that KILLS, because killing converts the guess
 * into a fact -- after that the holder is genuinely gone and there is no
 * false failover left to have. Stealing a claim from a live holder is the
 * one thing this must never offer, so there is no function for it.
 */
#ifndef FZN_CLAIM_H
#define FZN_CLAIM_H

#include <stddef.h>

typedef enum fzn_claim_err {
	FZN_CLAIM_OK = 0,
	/* A null argument or a claim that was never initialised: the caller's
	 * bug rather than a contended claim. */
	FZN_CLAIM_ERR_MALFORMED = -1,
	/* Somebody else holds it. AN ANSWER RATHER THAN A FAULT -- it is the
	 * expected result for every process but one, and a caller that logs it
	 * as an error will fill a log on a working host. */
	FZN_CLAIM_ERR_HELD = -2,
	/* The backend could not answer: the file would not open, the lock call
	 * failed for a reason other than contention. Kept apart from HELD
	 * because "somebody else is the owner" and "this host cannot arbitrate
	 * ownership at all" want different responses -- the first is normal and
	 * the second means the store is unusable. */
	FZN_CLAIM_ERR_BACKEND = -3,
	/* Taking a claim this process already holds, or releasing one it does
	 * not. Reported rather than absorbed: both mean the caller has lost
	 * track of which process it is, which is the bug sec 132 predicts. */
	FZN_CLAIM_ERR_STATE = -4,
} fzn_claim_err_t;

const char *fzn_claim_err_str(fzn_claim_err_t err);

/*
 * The backend.
 *
 * `take` returns NONZERO when the claim was taken, following this library's
 * seam convention. It reports the two failures apart through `held_out`,
 * which is set to nonzero when the reason was contention: "somebody else has
 * it" is the normal outcome and "the lock could not be attempted" is not,
 * and a backend that collapsed them would make a broken store look like a
 * busy one.
 *
 * `release` returns NONZERO on success. A backend whose release cannot fail
 * returns nonzero always, and says so.
 */
typedef struct fzn_claim_ops {
	int (*take)(void *ctx, int *held_out);
	int (*release)(void *ctx);
	void *ctx;
} fzn_claim_ops_t;

/* Declared, not included. sec 209. */
struct flog_t;

typedef struct fzn_claim {
	const fzn_claim_ops_t *ops;
	int held;
	/* Where this claim says what happened, or NULL for silence. */
	struct flog_t *log;
} fzn_claim_t;

/*
 * Give this claim somewhere to say what happened, or NULL to silence it.
 *
 * sec 216. A RELEASE that the backend refuses is the one worth having: `held`
 * is already cleared when it happens, so this object believes the claim is
 * gone and the world may disagree. Nothing later in this process will retry
 * it, and FZN_CLAIM_ERR_BACKEND reaches a caller unwinding a failure path
 * that is unlikely to look.
 *
 * Subsystem `claim/hold`. The log is borrowed and must outlive the claim.
 */
void fzn_claim_set_log(fzn_claim_t *claim, struct flog_t *log);

/* Point a claim at a backend. Does not take it: a process decides when to
 * try, and a constructor that took one would make "am I the owner" true
 * before the caller had asked for it. */
fzn_claim_err_t fzn_claim_init(fzn_claim_t *claim, const fzn_claim_ops_t *ops);

/* Try to become the owner, without blocking.
 *
 * NON-BLOCKING, DELIBERATELY, AND THERE IS NO BLOCKING FORM HERE. A process
 * that cannot take the claim has work to do -- it reads the shared store and
 * submits through the owner -- so blocking until the owner dies would stop
 * it doing the job it is there for. Waiting for the claim is a thing a
 * caller arranges around its own event loop, not a call that parks a thread.
 *
 * FZN_CLAIM_ERR_HELD means somebody else owns it and everything is working. */
fzn_claim_err_t fzn_claim_take(fzn_claim_t *claim);

/* Give it up. The backend releases on process death whether or not this is
 * called; calling it is how a process that stays alive hands over. */
fzn_claim_err_t fzn_claim_release(fzn_claim_t *claim);

/* Whether THIS process holds it.
 *
 * THE DEADLOCK IN sec 132 IS PREVENTED BY CALLING THIS. A shared "submit a
 * record" path that opens a socket to the owner blocks for ever when the
 * caller IS the owner -- it waits on itself. The submit path asks this first
 * and takes the local path when the answer is yes. It reads as an absurd
 * mistake and is entirely natural to write, because the point of a shared
 * path is that the caller does not think about which process it is in.
 *
 * Total, and answers zero for a null or uninitialised claim: a process that
 * does not know whether it is the owner is not the owner. */
int fzn_claim_held(const fzn_claim_t *claim);

#endif
