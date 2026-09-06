#define _POSIX_C_SOURCE 200809L

#include "claim_file.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

static int claim_file_take(void *ctx, int *held_out)
{
	fzn_claim_file_t *cf = (fzn_claim_file_t *)ctx;

	if (held_out)
		*held_out = 0;
	if (!cf || cf->fd < 0)
		return 0;

	if (flock(cf->fd, LOCK_EX | LOCK_NB) == 0)
		return 1;

	/* EWOULDBLOCK IS THE ONLY CONTENTION ANSWER, and everything else is a
	 * broken store rather than a busy one. Reporting them apart is the
	 * whole reason `held_out` exists: a caller that read EACCES as "somebody
	 * else owns it" would wait for ever for an owner that does not exist. */
	if (held_out && (errno == EWOULDBLOCK || errno == EINTR))
		*held_out = 1;
	return 0;
}

static int claim_file_release(void *ctx)
{
	fzn_claim_file_t *cf = (fzn_claim_file_t *)ctx;

	if (!cf || cf->fd < 0)
		return 0;
	return flock(cf->fd, LOCK_UN) == 0 ? 1 : 0;
}

static const fzn_claim_ops_t CLAIM_FILE_OPS = {
	claim_file_take,
	claim_file_release,
	NULL,
};

fzn_claim_err_t fzn_claim_file_open(fzn_claim_file_t *claim_file, const char *path,
                                    fzn_claim_ops_t *ops_out)
{
	int fd;

	if (!claim_file || !path || !ops_out)
		return FZN_CLAIM_ERR_MALFORMED;

	/* O_CLOEXEC so an exec'd child does not inherit the claim -- see the
	 * header on the fork hazard, which this covers only half of. */
	fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (fd < 0)
		return FZN_CLAIM_ERR_BACKEND;

	claim_file->fd = fd;
	*ops_out = CLAIM_FILE_OPS;
	ops_out->ctx = claim_file;
	return FZN_CLAIM_OK;
}

fzn_claim_err_t fzn_claim_file_close(fzn_claim_file_t *claim_file)
{
	int fd;

	if (!claim_file)
		return FZN_CLAIM_ERR_MALFORMED;
	if (claim_file->fd < 0)
		return FZN_CLAIM_OK;

	fd = claim_file->fd;
	/* CLEARED BEFORE THE CLOSE, so a failing close cannot leave a
	 * descriptor number here that another open may since have reused --
	 * which would point this backend at somebody else's file. */
	claim_file->fd = -1;
	return close(fd) == 0 ? FZN_CLAIM_OK : FZN_CLAIM_ERR_BACKEND;
}
