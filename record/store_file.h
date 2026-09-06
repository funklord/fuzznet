/*
 * The record store, as one sparse file per (issuer, stream).
 *
 * project.md sec 135. `record/store.h` is the seam and says nothing about
 * storage; this is the arrangement project.md sec 132 needs -- one writer,
 * several readers, no coordination between them beyond the claim that decides
 * which process writes.
 *
 * FIXED SLOTS, ADDRESSED BY SEQUENCE, AND NO INDEX. A record for sequence N
 * lives at `(N - 1) * FZN_RECORD_STORE_FILE_SLOT`, so finding one is
 * arithmetic rather than a lookup.
 *
 *     [0 .. 2)   the record's length, big-endian; ZERO MEANS EMPTY
 *     [2 .. )    the record's bytes
 *
 * THE ABSENCE OF AN INDEX IS THE WHOLE DESIGN, not a simplification. sec 132
 * establishes that this arrangement is free of deadlock because there is
 * exactly ONE lock -- the claim -- and nothing else blocks while it is held,
 * which holds only while everything shared is immutable. A variable-length
 * log would need an offset index; an index is mutable shared state; mutable
 * shared state needs a second lock, and a second lock is the AB-BA cycle that
 * section rules out. **The compact layout costs the property the design is
 * built on**, so the slot wastes space instead.
 *
 * WHAT IT WASTES, MEASURED RATHER THAN WAVED AT. A slot is 670 bytes and a
 * record is between 156 and 668, so a minimal record occupies about four
 * times its length and a full one wastes two bytes. That is paid only on
 * slots actually written: the file is SPARSE, and a sequence never received
 * occupies no blocks at all. sec 132 also classifies this store as a cache --
 * `persist/persist.h` puts the journal and the state among the recoverable
 * types -- so the thing being spent is the cheap resource.
 *
 * A HOLE READS AS ABSENT, FOR FREE. An unwritten slot in a sparse file reads
 * as zeros, so its length is zero and `fzn_record_store_get` answers
 * FZN_RECORD_STORE_ERR_ABSENT without anything having to record what is
 * missing. The empty state and the never-written state are the same bytes,
 * which is why no initialisation step exists.
 *
 * THE LENGTH IS WRITTEN LAST, AND THAT IS THE CRASH ORDER. A `put` writes the
 * record's bytes first and the length prefix second, so a process that dies
 * between them leaves a slot whose length is still zero -- an absent record
 * with rubbish behind it, which the next writer overwrites and no reader can
 * see. Written the other way round, a crash would leave a length promising
 * bytes that were never stored.
 *
 * AND THE SEAM'S GUARDS ARE WHY THAT IS ENOUGH. A torn two-byte length is not
 * ruled out on every filesystem, and it does not have to be: a wrong length
 * makes `fzn_record_store_get` fail to open the bytes and answer
 * FZN_RECORD_STORE_ERR_SHAPE, and a length that happened to frame some other
 * record answers FZN_RECORD_STORE_ERR_MISPLACED. Both are refusals. **The
 * checks in the seam are what let this backend be simple**, rather than
 * needing a checksum of its own.
 *
 * READS DO NOT DISTURB EACH OTHER. `pread` and `pwrite` carry their offset
 * rather than moving a shared file position, so several processes reading one
 * file cannot interfere, and the single writer sec 132 requires is the only
 * thing that needs the claim.
 *
 * ON A FILESYSTEM WITHOUT SPARSE SUPPORT the file is as large as its highest
 * sequence implies -- 670 bytes times that sequence -- which is the same
 * caution `spool/spool_file.h` records for a preallocated blob. Nothing here
 * can check it, so it is written down.
 */
#ifndef FZN_RECORD_STORE_FILE_H
#define FZN_RECORD_STORE_FILE_H

#include "store.h"

#define FZN_RECORD_STORE_FILE_PATH_MAX 512u

/* Two bytes of length, then the record. */
#define FZN_RECORD_STORE_FILE_SLOT (2u + FZN_RECORD_MAX_LEN)

/* What this backend adds to a directory to name one stream's file:
 * "/<64 hex of issuer>-<8 hex of stream>.rec", and the terminator.
 *
 * IT IS CHECKED AT OPEN RATHER THAN AT EVERY PATH BUILD, so a caller learns
 * its directory is too long immediately instead of on first use -- and so
 * that the check is one a test can reach. A truncated path is not a shorter
 * path: a directory long enough to cut the issuer off would put several
 * issuers' records in ONE file, where each would overwrite the last. */
#define FZN_RECORD_STORE_FILE_NAME_LEN 79u

typedef struct fzn_record_store_file {
	/* The directory, held rather than recomputed, for the reason
	 * `spool/spool_file.h` holds its sidecar path: a caller passing a
	 * different string the second time must not be able to point this
	 * somewhere else. */
	char dir[FZN_RECORD_STORE_FILE_PATH_MAX];
	/*
	 * ONE STREAM'S FILE, CACHED, because the loop this exists to serve
	 * reads consecutive sequences of one stream: a replay that reopened per
	 * record would pay an open and a close for every one of them. The
	 * identity of the cached file is held beside the descriptor and
	 * compared before use, so a request for another stream closes this and
	 * opens that rather than reading the wrong file.
	 */
	int fd;
	uint8_t issuer[FZN_PUBKEY_LEN];
	uint32_t stream;
	int cached;
	fzn_record_store_ops_t ops;
} fzn_record_store_file_t;

/*
 * Point a backend at an existing directory. Returns its ops, or NULL.
 *
 * A directory longer than FZN_RECORD_STORE_FILE_PATH_MAX minus
 * FZN_RECORD_STORE_FILE_NAME_LEN is refused here, because a path this backend
 * had to truncate would merge issuers into one file.
 *
 * THE DIRECTORY IS NOT CREATED. Where a store lives is a consumer's decision
 * -- sec 129 records the holder's expectation that data locations will need
 * later correction -- and a library that quietly makes directories decides it
 * for them. A missing directory surfaces as FZN_RECORD_STORE_ERR_BACKEND on
 * first use.
 *
 * Files are created 0600. A record is signed rather than secret, so this is
 * not the secret a prekey is; but what a host holds says what it follows, and
 * a consumer that wants it group-readable -- which sec 132's arrangement
 * needs -- widens the directory rather than having this widen the files.
 */
const fzn_record_store_ops_t *fzn_record_store_file_open(fzn_record_store_file_t *file,
                                                         const char *dir);

/* Close whatever stream file is cached. Idempotent, so a cleanup path may
 * call it without asking whether an open succeeded. */
void fzn_record_store_file_close(fzn_record_store_file_t *file);

#endif
