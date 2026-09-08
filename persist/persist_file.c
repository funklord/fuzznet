#define _POSIX_C_SOURCE 200809L
/* A POSIX file-backed store. See persist_file.h for the seam it fills.
 *
 * WHY THIS SHIPS RATHER THAN BEING LEFT TO CONSUMERS. Three consumers each
 * writing "open a file, read it, write it atomically, mode 0600" is three
 * chances to get the atomic part wrong, and the thing being written is a
 * trust anchor and a prekey secret. The library that says what must be
 * persisted should carry one working way to persist it.
 *
 * WRITES ARE ATOMIC BY RENAME, and that is the whole reason this file is
 * longer than fopen and fwrite. A torn trust anchor is worse than an absent
 * one: absent is refused loudly by `fzn_persist_trust_open` and a host stops,
 * while half a key is bytes that parse. So a save writes a temporary in the
 * same directory, flushes it to disk, and renames over the target -- rename
 * within a directory being the one filesystem operation that is atomic for
 * a reader.
 *
 * MODE 0600 ON THE TEMPORARY, BEFORE ANY BYTES REACH IT. Creating
 * world-readable and chmod'ing afterwards leaves a window in which a prekey
 * secret is readable, and the window is exactly as long as the write.
 *
 * NOTHING HERE ALLOCATES. Paths are built into a bounded buffer and a path
 * that will not fit is refused rather than truncated -- a truncated path
 * names a different file, which is the quiet way two slots become one.
 */

#include "persist_file.h"

/* Diagnostics through flog, vendored and possibly absent. sec 209. */
#ifdef FZN_FLOG_ON
#include "flog.h"
#define PERSIST_LOG(s, sub, sev, ...)                                                      \
	do {                                                                               \
		if ((s) && (s)->log)                                                       \
			flog_printf((s)->log, sub, sev, FLOG_MSG_NONE, __VA_ARGS__);        \
	} while (0)
#else
#define PERSIST_LOG(s, sub, sev, ...) ((void)0)
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*
 * WHY errno IS READ HERE AND NOWHERE ELSE IN THE LIBRARY. This translation
 * unit is the only POSIX-only one besides `session/random_linux.c`, which
 * reads errno for the same reason -- it is where the operating system says
 * what went wrong, and everything above this seam takes an `int`. flog's own
 * stdio backend spells it `strerror(errno)`, which is what this follows.
 *
 * CAPTURED BEFORE ANY OTHER CALL, always. `fclose` and `unlink` set errno
 * too, so reading it after the cleanup reports the cleanup's luck rather than
 * the failure's cause.
 */

/* Enough for a directory, a separator, a slot digit, 64 hex characters and a
 * suffix. A caller with a deeper directory is told, not truncated. */
#define PATH_MAX_LEN 512u
#define NAME_MAX_LEN 80u

static int name_for(char *out, size_t cap, fzn_persist_slot_t slot, const uint8_t *subject)
{
	static const char HEX[] = "0123456789abcdef";
	size_t at = 0;
	unsigned i;

	if (cap < NAME_MAX_LEN)
		return 0;
	out[at++] = (char)('0' + ((unsigned)slot % 10u));
	out[at++] = '-';
	if (subject) {
		/* THE WHOLE SUBJECT, not a prefix. Two peers sharing a prefix
		 * would share a file, which is the same class as a comparison
		 * that reads a prefix -- and this tree has already had one. */
		for (i = 0; i < 32u; i++) {
			out[at++] = HEX[(subject[i] >> 4) & 0x0fu];
			out[at++] = HEX[subject[i] & 0x0fu];
		}
	} else {
		out[at++] = 'h';
	}
	out[at] = '\0';
	return 1;
}

static int path_for(char *out, size_t cap, const char *dir, fzn_persist_slot_t slot,
                    const uint8_t *subject, const char *suffix)
{
	char name[NAME_MAX_LEN];
	size_t dir_len, name_len, suffix_len;

	if (!dir || !name_for(name, sizeof(name), slot, subject))
		return 0;
	dir_len = strlen(dir);
	name_len = strlen(name);
	suffix_len = suffix ? strlen(suffix) : 0u;
	if (dir_len + 1u + name_len + suffix_len + 1u > cap)
		return 0;

	memcpy(out, dir, dir_len);
	out[dir_len] = '/';
	memcpy(out + dir_len + 1u, name, name_len);
	if (suffix_len)
		memcpy(out + dir_len + 1u + name_len, suffix, suffix_len);
	out[dir_len + 1u + name_len + suffix_len] = '\0';
	return 1;
}

/* The failure of a named step, with the reason the operating system gave.
 *
 * One helper rather than a line at each `return 0`, because what differs
 * between the eleven of them is a verb and everything else is the same
 * sentence -- and a caller reading `0` needs the verb most: a refused `open`
 * is a permission or a path problem, a refused `fwrite` is usually space, and
 * a refused `rename` means the temporary was written and the target still
 * holds the old bytes. */
static void say_failed(const fzn_persist_file_t *store, const char *what, const char *path,
                       int err)
{
	/* DISCARDED EXPLICITLY, because with flog absent PERSIST_LOG expands to
	 * nothing and all four of these become unused parameters -- which is a
	 * warning, and the arrangement without flog is one this library builds
	 * and ships. The other emit sites need no such line: they name struct
	 * fields the surrounding code uses anyway, and this is the first helper
	 * whose whole body is a log. */
	(void)store;
	(void)what;
	(void)path;
	(void)err;

	PERSIST_LOG(store, "persist/file", FLOG_ERR, "%s failed for %s: %s", what, path,
	            strerror(err));
}

static int file_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                     size_t cap, size_t *len)
{
	const fzn_persist_file_t *store = (const fzn_persist_file_t *)ctx;
	char path[PATH_MAX_LEN];
	FILE *f;
	size_t got;
	int extra;

	if (!store || !out || !len)
		return 0;
	if (!path_for(path, sizeof(path), store->dir, slot, subject, NULL)) {
		PERSIST_LOG(store, "persist/file", FLOG_ERR,
		            "a bounded path for slot %u will not fit in %u bytes under "
		            "this directory, so nothing was read",
		            (unsigned)slot, (unsigned)PATH_MAX_LEN);
		return 0;
	}

	f = fopen(path, "rb");
	if (!f) {
		int err = errno;

		/* ABSENT IS NOT A FAULT, and it is the case that shares its
		 * return value with every fault. A host's first run reads
		 * every slot and finds nothing; a host whose directory has
		 * become unreadable reads the same `0`. */
		if (err == ENOENT)
			PERSIST_LOG(store, "persist/file", FLOG_INFO,
			            "nothing stored for slot %u yet (%s)", (unsigned)slot,
			            path);
		else
			say_failed(store, "open for reading", path, err);
		return 0;
	}
	got = fread(out, 1u, cap, f);
	/* A FILE LARGER THAN THE CALLER'S BUFFER IS A REFUSAL, not a
	 * truncation. `persist.c` checks an exact length, so a truncated read
	 * would be refused there anyway -- but refusing here says which layer
	 * found it, and a caller sizing at FZN_PERSIST_MAX should never see
	 * this unless the file is not ours. */
	extra = fgetc(f) != EOF;
	fclose(f);
	if (extra || got == 0u) {
		/* A FILE THIS LIBRARY DID NOT WRITE, in this store's directory
		 * and under this store's naming. The refusal above says a
		 * caller sizing at FZN_PERSIST_MAX should never see it
		 * otherwise, and an empty file is not what a crash leaves
		 * either -- the save below flushes and syncs before it
		 * renames, precisely so that it cannot. */
		PERSIST_LOG(store, "persist/file", FLOG_WARN,
		            "%s for slot %u, so it is not one this library wrote: %s",
		            extra ? "a file longer than the caller's buffer"
		                  : "an empty file",
		            (unsigned)slot, path);
		return 0;
	}

	*len = got;
	return 1;
}

static int file_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                     const uint8_t *bytes, size_t len)
{
	const fzn_persist_file_t *store = (const fzn_persist_file_t *)ctx;
	char path[PATH_MAX_LEN];
	char temp[PATH_MAX_LEN];
	FILE *f;
	const char *what;
	int fd;
	int ok;

	if (!store || !bytes || len == 0u)
		return 0;
	if (!path_for(path, sizeof(path), store->dir, slot, subject, NULL)
	    || !path_for(temp, sizeof(temp), store->dir, slot, subject, ".tmp")) {
		PERSIST_LOG(store, "persist/file", FLOG_ERR,
		            "a bounded path for slot %u will not fit in %u bytes under "
		            "this directory, so nothing was saved",
		            (unsigned)slot, (unsigned)PATH_MAX_LEN);
		return 0;
	}

	/* 0600 AT CREATION. `fopen` would use the umask, which a daemon does
	 * not control and which has left secrets group-readable in worse
	 * places than this. */
	fd = open(temp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0) {
		say_failed(store, "create at mode 0600", temp, errno);
		return 0;
	}
	f = fdopen(fd, "wb");
	if (!f) {
		int err = errno;

		(void)close(fd);
		(void)unlink(temp);
		say_failed(store, "wrap a descriptor for buffered writing", temp, err);
		return 0;
	}

	/* THE VERB IS CARRIED SO THE LINE CAN NAME IT, and the four steps fail
	 * for different reasons a person acts on differently: a short write is
	 * usually space, a refused fsync can be a filesystem that has none,
	 * and a failing fclose is the one that reports a write nobody had
	 * noticed failing yet. */
	what = "write";
	ok = fwrite(bytes, 1u, len, f) == len;
	/* FLUSHED AND SYNCED BEFORE THE RENAME. Renaming over the target with
	 * the new bytes still in a buffer gives a crash the chance to leave
	 * the name pointing at an empty file -- which parses as nothing and
	 * reads as absent, so a host quietly re-anchors. */
	if (ok) {
		what = "flush";
		ok = fflush(f) == 0;
	}
	if (ok) {
		what = "sync to disk";
		ok = fsync(fileno(f)) == 0;
	}
	if (fclose(f) != 0) {
		if (ok)
			what = "close";
		ok = 0;
	}

	if (!ok) {
		int err = errno;

		(void)unlink(temp);
		say_failed(store, what, temp, err);
		return 0;
	}
	if (rename(temp, path) != 0) {
		int err = errno;

		(void)unlink(temp);
		/* THE ONE FAILURE WHERE THE BYTES WERE GOOD. Everything above
		 * left nothing behind; here a complete, synced temporary could
		 * not be moved over the target, so the target still holds the
		 * PREVIOUS state and a caller reading `0` cannot tell that
		 * from having written nothing at all. */
		say_failed(store, "rename over the target, so the previous bytes remain",
		           path, err);
		return 0;
	}
	return 1;
}

void fzn_persist_file_set_log(fzn_persist_file_t *store, struct flog_t *log)
{
	if (!store)
		return;

	store->log = log;
}

const fzn_persist_ops_t *fzn_persist_file_init(fzn_persist_file_t *store, const char *dir)
{
	char probe[PATH_MAX_LEN];

	if (!store || !dir)
		return NULL;
	/* Refused HERE rather than at the first save, so a caller learns at
	 * start-up that its directory is too deep instead of on the day it
	 * first pins a peer. */
	if (!path_for(probe, sizeof(probe), dir, FZN_PERSIST_PEER, NULL, ".tmp"))
		return NULL;

	store->dir = dir;
	/* Quiet unless somebody asks. The header says why an init failure
	 * above cannot be reported through this field. */
	store->log = NULL;
	store->ops.load = file_load;
	store->ops.save = file_save;
	store->ops.ctx = store;
	return &store->ops;
}
