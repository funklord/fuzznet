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
 *   HELD, on the sidecar: the version byte, the whole root (a prefix
 *   comparison is caught), the leaf count, the pre-zero of the caller's
 *   buffer, the discard of a partly-read bitmap, and the refusal to
 *   checkpoint through a closed descriptor.
 *
 *   NOT HELD, and not testable from here: the short-read and short-write
 *   loops, that `sync` reaches the disk at all, that the data fsync really
 *   precedes the sidecar write, and that the sidecar is renamed into place
 *   rather than written over. Inducing a short pwrite needs a signal
 *   delivered mid-syscall, and the last three all need the power cut --
 *   surviving one is their entire purpose. A backend faking any of them
 *   would pass this suite. That is the honest limit of a test that runs on
 *   a working filesystem, and the reason those lines carry their argument
 *   in prose beside them rather than resting on a green run.
 */

#include "spool_file.h"

#include "../wire/bytes.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* The sidecar's header: a version, the root it belongs to, and the leaf
 * count. Everything after it is the bitmap.
 *
 * THE ROOT AND THE COUNT ARE THE POINT. Without them the file is opaque bits
 * that any blob will accept -- see spool_file.h. With them a resume onto the
 * wrong blob is a comparison rather than a corrupt transfer. */
#define BITS_VERSION 1u
#define BITS_OFF_ROOT 1u
#define BITS_OFF_LEAVES (BITS_OFF_ROOT + FZN_BLOB_HASH_LEN)
#define BITS_HEAD_LEN (BITS_OFF_LEAVES + 8u)

/* THE SIDECAR'S HEADER, ASSERTED FIELD BY FIELD.
 *
 * MEASURED: exchanging BITS_OFF_ROOT and BITS_OFF_LEAVES, with BITS_HEAD_LEN
 * kept at 41 so the file is the same size, left the whole suite green. The
 * header is written in one place and read in one place, so a permutation
 * moves both and nothing downstream can tell -- the same blindness
 * project.md sec 45 records for the wire layouts and for `persist/`.
 *
 * `bits_read` already checks the version byte, that the root matches and that
 * the leaf count matches, which is most of what can go wrong. What it cannot
 * see is the layout moving underneath all three, and the party that disagrees
 * is this host after an upgrade -- a spool is RESUMED rather than re-fetched,
 * so a misread sidecar loses leaves that will never be asked for again.
 *
 * Literals, because a constant checked against itself checks nothing.
 */
_Static_assert(BITS_VERSION == 1u, "sidecar layout: the version byte moved");
_Static_assert(BITS_OFF_ROOT == 1u, "sidecar layout: the root moved");
_Static_assert(BITS_OFF_LEAVES == 33u, "sidecar layout: the leaf count moved");
_Static_assert(BITS_HEAD_LEN == 41u, "sidecar layout: the header is not 41 bytes");

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
	/* The sidecar's name is derived once, and its length is checked BEFORE
	 * the data file is created -- a path that fits but whose sidecar does
	 * not would otherwise leave a spool nothing could ever checkpoint, and
	 * the caller would learn at the first pause rather than at start-up. */
	if ((size_t)snprintf(file->bits, sizeof(file->bits), "%s.bits", path) >= sizeof(file->bits))
		return NULL;

	file->fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (file->fd < 0)
		return NULL;

	file->ops.read_at = file_read;
	file->ops.write_at = file_write;
	file->ops.sync = file_sync;
	file->ops.ctx = file;
	return &file->ops;
}

fzn_spool_err_t fzn_spool_file_resume(const fzn_spool_file_t *file,
                                      const uint8_t root[FZN_BLOB_HASH_LEN], uint64_t leaves,
                                      uint8_t *present, size_t present_len)
{
	uint8_t head[BITS_HEAD_LEN];
	size_t want;
	FILE *f;

	if (!file || !root || !present || leaves == 0u)
		return FZN_SPOOL_ERR_MALFORMED;
	if (leaves > (uint64_t)FZN_SPOOL_MAX_LEAVES)
		return FZN_SPOOL_ERR_TOO_LARGE;
	want = FZN_SPOOL_BITMAP_LEN(leaves);
	if (present_len < want)
		return FZN_SPOOL_ERR_MALFORMED;

	/* ZEROED BEFORE ANYTHING IS READ, so that every path out of here --
	 * absent, mismatched, truncated, refused -- leaves the caller with a
	 * fresh transfer rather than with whatever the buffer held. A caller
	 * ignoring the return value gets the safe answer. */
	memset(present, 0, want);

	f = fopen(file->bits, "rb");
	if (!f)
		return FZN_SPOOL_ERR_ABSENT;

	if (fread(head, 1u, sizeof(head), f) != sizeof(head)) {
		(void)fclose(f);
		return FZN_SPOOL_ERR_ABSENT;
	}
	/* A MISMATCH IS "ABSENT", NOT AN ERROR, deliberately. A sidecar from
	 * another blob is not a fault a caller can repair -- it means the path
	 * was reused -- and the correct response is the same as having no
	 * sidecar at all: start over. Reporting it as a failure would tempt a
	 * caller into treating a reused path as fatal. */
	if (head[0] != BITS_VERSION || memcmp(head + BITS_OFF_ROOT, root, FZN_BLOB_HASH_LEN) != 0
	    || fzn_get_be64(head + BITS_OFF_LEAVES) != leaves) {
		(void)fclose(f);
		return FZN_SPOOL_ERR_ABSENT;
	}

	if (fread(present, 1u, want, f) != want) {
		/* A TRUNCATED SIDECAR IS DISCARDED RATHER THAN PARTLY USED.
		 * The bits that did arrive are real, but the ones that did not
		 * read as zero -- which is stale-fewer and therefore safe --
		 * and half a bitmap is not worth the branch it costs to reason
		 * about later. */
		memset(present, 0, want);
		(void)fclose(f);
		return FZN_SPOOL_ERR_ABSENT;
	}
	(void)fclose(f);
	return FZN_SPOOL_OK;
}

fzn_spool_err_t fzn_spool_file_checkpoint(const fzn_spool_file_t *file, const fzn_spool_t *spool)
{
	char temp[FZN_SPOOL_FILE_PATH_MAX];
	uint8_t head[BITS_HEAD_LEN];
	size_t want;
	FILE *f;
	int fd;
	int ok;

	if (!file || file->fd < 0 || !spool || !spool->present || spool->leaves == 0u)
		return FZN_SPOOL_ERR_MALFORMED;
	want = FZN_SPOOL_BITMAP_LEN(spool->leaves);
	if (spool->present_len < want)
		return FZN_SPOOL_ERR_MALFORMED;
	if ((size_t)snprintf(temp, sizeof(temp), "%s.tmp", file->bits) >= sizeof(temp))
		return FZN_SPOOL_ERR_MALFORMED;

	/* THE DATA IS SYNCED BEFORE THE BITMAP IS WRITTEN. See spool_file.h:
	 * stale-fewer costs a re-request, stale-more loses leaves for good, so
	 * the order is the guarantee and it is enforced here rather than asked
	 * of a caller. */
	if (fsync(file->fd) != 0)
		return FZN_SPOOL_ERR_BACKEND;

	head[0] = (uint8_t)BITS_VERSION;
	memcpy(head + BITS_OFF_ROOT, spool->root, FZN_BLOB_HASH_LEN);
	fzn_put_be64(head + BITS_OFF_LEAVES, spool->leaves);

	fd = open(temp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return FZN_SPOOL_ERR_BACKEND;
	f = fdopen(fd, "wb");
	if (!f) {
		(void)close(fd);
		(void)unlink(temp);
		return FZN_SPOOL_ERR_BACKEND;
	}

	ok = fwrite(head, 1u, sizeof(head), f) == sizeof(head);
	if (ok)
		ok = fwrite(spool->present, 1u, want, f) == want;
	if (ok)
		ok = fflush(f) == 0;
	if (ok)
		ok = fsync(fileno(f)) == 0;
	if (fclose(f) != 0)
		ok = 0;

	if (!ok) {
		(void)unlink(temp);
		return FZN_SPOOL_ERR_BACKEND;
	}
	/* RENAMED OVER, so a crash mid-write leaves the PREVIOUS bitmap rather
	 * than a torn one. A torn bitmap is the stale-more case arriving by
	 * accident: garbage bits set over leaves that are not there. */
	if (rename(temp, file->bits) != 0) {
		(void)unlink(temp);
		return FZN_SPOOL_ERR_BACKEND;
	}
	return FZN_SPOOL_OK;
}

void fzn_spool_file_close(fzn_spool_file_t *file)
{
	if (!file || file->fd < 0)
		return;
	(void)close(file->fd);
	file->fd = -1;
}
