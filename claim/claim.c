#include "claim.h"

fzn_claim_err_t fzn_claim_init(fzn_claim_t *claim, const fzn_claim_ops_t *ops)
{
	if (!claim || !ops || !ops->take || !ops->release)
		return FZN_CLAIM_ERR_MALFORMED;

	claim->ops = ops;
	claim->held = 0;
	return FZN_CLAIM_OK;
}

fzn_claim_err_t fzn_claim_take(fzn_claim_t *claim)
{
	int held = 0;

	if (!claim || !claim->ops)
		return FZN_CLAIM_ERR_MALFORMED;
	/* TAKING IT TWICE IS A LOST TRACK, NOT A NO-OP. A backend whose lock is
	 * per open-file-description would report success for a second take and
	 * leave the caller believing two takes need two releases. */
	if (claim->held)
		return FZN_CLAIM_ERR_STATE;

	if (claim->ops->take(claim->ops->ctx, &held)) {
		claim->held = 1;
		return FZN_CLAIM_OK;
	}

	/* The backend distinguishes these and this must not collapse them: a
	 * host that cannot arbitrate at all is a broken store, and a host whose
	 * claim is held is a working one. */
	return held ? FZN_CLAIM_ERR_HELD : FZN_CLAIM_ERR_BACKEND;
}

fzn_claim_err_t fzn_claim_release(fzn_claim_t *claim)
{
	if (!claim || !claim->ops)
		return FZN_CLAIM_ERR_MALFORMED;
	if (!claim->held)
		return FZN_CLAIM_ERR_STATE;

	/* HELD IS CLEARED WHETHER OR NOT THE BACKEND SUCCEEDS. A release that
	 * failed leaves this process unable to say it still owns anything --
	 * and the alternative, staying held after a failed release, is a
	 * process that believes it owns state the kernel may have handed on. Of
	 * the two wrong answers, refusing to act is the one that cannot
	 * desynchronise a ratchet. */
	claim->held = 0;
	if (!claim->ops->release(claim->ops->ctx))
		return FZN_CLAIM_ERR_BACKEND;
	return FZN_CLAIM_OK;
}

int fzn_claim_held(const fzn_claim_t *claim)
{
	if (!claim || !claim->ops)
		return 0;
	return claim->held;
}

const char *fzn_claim_err_str(fzn_claim_err_t err)
{
	switch (err) {
	case FZN_CLAIM_OK:
		return "ok";
	case FZN_CLAIM_ERR_MALFORMED:
		return "malformed";
	case FZN_CLAIM_ERR_HELD:
		return "held by another process";
	case FZN_CLAIM_ERR_BACKEND:
		return "backend refused";
	case FZN_CLAIM_ERR_STATE:
		return "wrong state";
	}
	return "unknown";
}
