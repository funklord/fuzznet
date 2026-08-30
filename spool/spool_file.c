#define _POSIX_C_SOURCE 200809L
/* A sparse-file backend for spool/. See spool_file.h for why it is pwrite
 * rather than mmap.
 *
 * SHORT READS AND SHORT WRITES ARE LOOPED, NOT TREATED AS FAILURE. `pwrite`
 * is permitted to write less than asked -- a signal arriving mid-call is
 * enough -- and code that checks `== len` works until the day it does not,
 * on a machine nobody can reproduce. The loop is four lines and removes the
 * class.
 *
 * WHAT THE TESTS DO AND DO NOT HOLD, measured by mutation rather than
 * asserted, so that a later reader knows which lines are defended:
 *
 *   HELD -- the absent O_TRUNC (adding one fails the resume case), both
 *   offsets (dropping `offset` from either pread or pwrite fails), the
 *   refusal of a read past the end, and the 0600 mode.
 *
 *   NOT HELD, and prospective rather than load-bearing: the `fd < 0` guards
 *   in all three ops. Removing them changes no result, because pread, pwrite
 *   and fsync all refuse a negative descriptor with the same failure the
 *   guard produces. They are kept because they say what the function
 *   expects, not because anything would break -- and this note is here so
 *   that nobody later cites them as tested.
 *
 *   NOT HELD, and not testable from here: the short-read and short-write
 *   loops, and that `sync` reaches the disk at all. Inducing a short pwrite
 *   needs a signal delivered mid-syscall, and proving an fsync needs the
 *   power cut. A backend that faked either would pass this suite. That is
 *   the honest limit of a test that runs on a working filesystem.
 */

#include "spool_file.h"

#include <fcntl.h>
#include <unistd.h>

static int file_read(void *ctx, uint64_t offset, uint8_t *out, size_t len)
{
	const fzn_spool_file_t *file = (const fzn_spool_file_t *)ctx;
	size_t done = 0;

	if (!file || file->fd < 0 || !out)
		return 0;
	while (done < len) {
		ssize_t got = pread(file->fd, out + done, len - done, (off_t)(offset + done));

		/* A READ SHORT OF THE REQUEST IS A FAILURE HERE, not a partial
		 * success, because the caller asked for a leaf and half a leaf
		 * is not one. Zero means end of file: the leaf is not there,
		 * which the bitmap should already have said, so a caller
		 * reaching this has a bitmap disagreeing with its file. */
		if (got <= 0)
			return 0;
		done += (size_t)got;
	}
	return 1;
}

static int file_write(void *ctx, uint64_t offset, const uint8_t *bytes, size_t len)
{
	const fzn_spool_file_t *file = (const fzn_spool_file_t *)ctx;
	size_t done = 0;

	if (!file || file->fd < 0 || !bytes)
		return 0;
	while (done < len) {
		ssize_t put = pwrite(file->fd, bytes + done, len - done, (off_t)(offset + done));

		if (put <= 0)
			return 0;
		done += (size_t)put;
	}
	return 1;
}

static int file_sync(void *ctx)
{
	const fzn_spool_file_t *file = (const fzn_spool_file_t *)ctx;

	if (!file || file->fd < 0)
		return 0;
	return fsync(file->fd) == 0;
}

const fzn_spool_ops_t *fzn_spool_file_open(fzn_spool_file_t *file, const char *path)
{
	if (!file || !path)
		return NULL;

	/* NOT O_TRUNC. Opening an existing spool must not empty it -- that is
	 * the resume path, and truncating here would turn every restart into
	 * a transfer starting over while the bitmap still claimed the leaves
	 * were present. The bitmap and the file are restored together or the
	 * store is wrong about itself. */
	file->fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (file->fd < 0)
		return NULL;

	file->ops.read_at = file_read;
	file->ops.write_at = file_write;
	file->ops.sync = file_sync;
	file->ops.ctx = file;
	return &file->ops;
}

void fzn_spool_file_close(fzn_spool_file_t *file)
{
	if (!file || file->fd < 0)
		return;
	(void)close(file->fd);
	file->fd = -1;
}
