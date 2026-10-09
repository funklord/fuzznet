#define _POSIX_C_SOURCE 200809L
/* For `fallocate`'s hole punching, where there is one: sec 548. */
#if defined(__linux__)
#define _GNU_SOURCE
#endif

#include "store_file.h"

#include "../wire/bytes.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* The highest sequence whose slot offset still fits. A sequence is a uint64
 * and an offset is not, so this is checked rather than assumed: without it a
 * high sequence wraps and lands on another record's slot, which is the
 * misplacement the seam exists to catch -- caught, but produced here. */
#define SLOT ((uint64_t)FZN_RECORD_STORE_FILE_SLOT)
#define MAX_SEQ ((uint64_t)0x7fffffffffffffffull / SLOT)

static void hex(char *out, const uint8_t *bytes, size_t len)
{
	static const char DIGITS[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < len; i++) {
		out[i * 2u] = DIGITS[bytes[i] >> 4];
		out[i * 2u + 1u] = DIGITS[bytes[i] & 0x0fu];
	}
	out[len * 2u] = '\0';
}

/* The path of one (issuer, stream)'s file. Nonzero on success. */
static int stream_path(const fzn_record_store_file_t *file, const uint8_t issuer[FZN_PUBKEY_LEN],
                       uint32_t stream, char path[FZN_RECORD_STORE_FILE_PATH_MAX])
{
	char issuer_hex[FZN_PUBKEY_LEN * 2u + 1u];
	int wrote;

	hex(issuer_hex, issuer, FZN_PUBKEY_LEN);
	wrote = snprintf(path, FZN_RECORD_STORE_FILE_PATH_MAX, "%s/%s-%08lx.rec", file->dir, issuer_hex,
	                 (unsigned long)stream);
	/* UNREACHABLE BY CONSTRUCTION, AND KEPT. `fzn_record_store_file_open`
	 * refuses a directory that leaves less than FZN_RECORD_STORE_FILE_NAME_LEN
	 * of room, so this cannot fire -- and it is what would catch a future
	 * change to either constant that stopped that being true. It is
	 * deliberately not covered by a test, since covering it would mean
	 * removing the bound that makes it unreachable; project.md sec 135
	 * records that rather than leaving it to be discovered. */
	return wrote >= 0 && (size_t)wrote < FZN_RECORD_STORE_FILE_PATH_MAX;
}

/* Open the file for one (issuer, stream), reusing the cached descriptor when
 * it is already the right one. Returns the descriptor or -1. */
static int stream_fd(fzn_record_store_file_t *file, const uint8_t issuer[FZN_PUBKEY_LEN],
                     uint32_t stream)
{
	char path[FZN_RECORD_STORE_FILE_PATH_MAX];
	int fd;

	if (file->cached && file->stream == stream
	    && memcmp(file->issuer, issuer, FZN_PUBKEY_LEN) == 0)
		return file->fd;
	if (!stream_path(file, issuer, stream, path))
		return -1;

	fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (fd < 0)
		return -1;

	if (file->cached && file->fd >= 0)
		(void)close(file->fd);
	file->fd = fd;
	memcpy(file->issuer, issuer, FZN_PUBKEY_LEN);
	file->stream = stream;
	file->cached = 1;
	return fd;
}

static int store_file_put(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream,
                          uint64_t seq, const uint8_t *bytes, size_t len)
{
	fzn_record_store_file_t *file = (fzn_record_store_file_t *)ctx;
	uint8_t prefix[2];
	off_t at;
	int fd;

	if (!file || !issuer || !bytes)
		return 0;
	if (len == 0 || len > FZN_RECORD_MAX_LEN)
		return 0;
	if (seq == 0u || seq > MAX_SEQ)
		return 0;

	fd = stream_fd(file, issuer, stream);
	if (fd < 0)
		return 0;

	at = (off_t)((seq - 1u) * SLOT);

	/* THE RECORD FIRST, THE LENGTH SECOND. A process that dies between them
	 * leaves a slot whose length is still zero -- absent, with rubbish
	 * behind it that the next writer overwrites and no reader can see. */
	if (pwrite(fd, bytes, len, at + 2) != (ssize_t)len)
		return 0;
	fzn_put_be16(prefix, (uint16_t)len);
	if (pwrite(fd, prefix, sizeof(prefix), at) != (ssize_t)sizeof(prefix))
		return 0;
	return 1;
}

static int store_file_get(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream,
                          uint64_t seq, uint8_t *out, size_t cap, size_t *len_out,
                          int *found_out)
{
	fzn_record_store_file_t *file = (fzn_record_store_file_t *)ctx;
	uint8_t prefix[2];
	size_t len;
	ssize_t got;
	off_t at;
	int fd;

	if (found_out)
		*found_out = 0;
	if (!file || !issuer || !out || !len_out)
		return 0;
	/* Past the addressable range is ABSENT rather than an error: nothing was
	 * ever stored there and nothing could have been. */
	if (seq == 0u || seq > MAX_SEQ)
		return 0;

	fd = stream_fd(file, issuer, stream);
	if (fd < 0) {
		/* The file could not be opened at all, which is a broken store
		 * rather than a missing record -- see `record/store.h` on why
		 * those must not be collapsed. */
		if (found_out)
			*found_out = 1;
		return 0;
	}

	at = (off_t)((seq - 1u) * SLOT);
	got = pread(fd, prefix, sizeof(prefix), at);
	/* A SHORT READ AT THE PREFIX IS THE END OF THE FILE, so nothing has been
	 * stored this far along: absent, not broken. */
	if (got != (ssize_t)sizeof(prefix))
		return 0;

	len = (size_t)fzn_get_be16(prefix);
	/* A hole reads as zeros, so an unwritten slot arrives here as length
	 * zero -- which is how absence costs nothing to record. */
	if (len == 0u)
		return 0;

	/* Anything past this point IS a slot somebody wrote, so a failure to
	 * produce it is the store failing rather than the record being absent. */
	if (found_out)
		*found_out = 1;
	if (len > FZN_RECORD_MAX_LEN || len > cap)
		return 0;

	got = pread(fd, out, len, at + 2);
	if (got != (ssize_t)len)
		return 0;

	*len_out = len;
	return 1;
}

/* CUT [from, below): each slot's length zeroed, from the top down, so every
 * one reads as absent whatever happens next; then the range's blocks given
 * back where the system punches holes. Zeroing is the cut and punching only
 * the space, so a filesystem that will not punch still cuts. A build with
 * FZN_RECORD_STORE_FILE_NO_PUNCH is that system, which is how the suite sees
 * the zeroing alone (sec 563). */
static int store_file_cut(void *ctx, const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream,
                          uint64_t from, uint64_t below)
{
	fzn_record_store_file_t *file = (fzn_record_store_file_t *)ctx;
	static const uint8_t zero[2];
	uint64_t seq;
	int fd;

	if (!file || !issuer || from == 0u || below <= from || below - 1u > MAX_SEQ)
		return 0;
	fd = stream_fd(file, issuer, stream);
	if (fd < 0)
		return 0;
	for (seq = below - 1u; seq >= from; seq--)
		if (pwrite(fd, zero, sizeof(zero), (off_t)((seq - 1u) * SLOT)) != (ssize_t)sizeof(zero))
			return 0;
#if defined(FALLOC_FL_PUNCH_HOLE) && !defined(FZN_RECORD_STORE_FILE_NO_PUNCH)
	(void)fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
	                (off_t)((from - 1u) * SLOT), (off_t)((below - from) * SLOT));
#endif
	return 1;
}

static const fzn_record_store_ops_t STORE_FILE_OPS = { store_file_put, store_file_get, NULL,
	                                               store_file_cut };

const fzn_record_store_ops_t *fzn_record_store_file_open(fzn_record_store_file_t *file,
                                                         const char *dir)
{
	size_t len;

	if (!file || !dir)
		return NULL;
	len = strlen(dir);
	if (len == 0u || len >= sizeof(file->dir))
		return NULL;
	/* Room for the name this backend appends, so no path it builds can be
	 * truncated -- see the header on why a truncated path is worse than a
	 * refused one. */
	if (len + FZN_RECORD_STORE_FILE_NAME_LEN > sizeof(file->dir))
		return NULL;

	memset(file, 0, sizeof(*file));
	memcpy(file->dir, dir, len + 1u);
	file->fd = -1;
	file->ops = STORE_FILE_OPS;
	file->ops.ctx = file;
	return &file->ops;
}

int fzn_record_store_file_forget(fzn_record_store_file_t *file,
                                 const uint8_t issuer[FZN_PUBKEY_LEN], uint32_t stream)
{
	char path[FZN_RECORD_STORE_FILE_PATH_MAX];

	if (!file || !issuer || !stream_path(file, issuer, stream, path))
		return 0;
	if (file->cached && file->stream == stream
	    && memcmp(file->issuer, issuer, FZN_PUBKEY_LEN) == 0)
		fzn_record_store_file_close(file);
	return unlink(path) == 0 || errno == ENOENT;
}

void fzn_record_store_file_close(fzn_record_store_file_t *file)
{
	int fd;

	if (!file || !file->cached || file->fd < 0)
		return;

	fd = file->fd;
	/* Cleared before the close, so a failing close cannot leave a descriptor
	 * number here that another open may since have reused. */
	file->fd = -1;
	file->cached = 0;
	(void)close(fd);
}
