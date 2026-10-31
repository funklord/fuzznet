/*
 * WHAT HOLDS A FILE, sec 795: the holder's decision of 2026-10-31 that a
 * file a retention rule would let go is removed only when nothing else
 * holds it. Each hold is a kind and an id -- an attachment by the line
 * that sent it, or LEGACY for every file held before this record began --
 * kept as a row, with a count per file.
 *
 * A file this record does not know, its count never written, is held by
 * something older than the record, and nothing here removes it. The
 * catalogue and saved sticker packs are asked at the moment of removal
 * (`node/attachments.h`) rather than mirrored here: they are their own
 * authorities, and two lists kept in step by hand drift.
 *
 * EVERY WRITE ERRS TOWARD KEEPING. A claim counts before it writes its
 * hold, and a release removes its hold before it counts down, so a crash
 * between leaves the count one high and the file kept.
 *
 * Persist slot FZN_PERSIST_FILE_HOLD: a hold's row keyed by a hash of the
 * file's root, the kind and the id; a file's count keyed by a hash of the
 * root. Not core: a hold lost errs toward keeping, as above.
 */
#ifndef FZN_NODE_FILE_HOLDS_H
#define FZN_NODE_FILE_HOLDS_H

#include <stddef.h>
#include <stdint.h>

#include "../persist/persist.h"
#include "../session/commitment.h"

#define FZN_FILE_HOLD_ID_LEN 32u

typedef enum fzn_file_hold_kind {
	/* Held before this record began: never released. */
	FZN_FILE_HOLD_LEGACY = 1,
	/* Sent in a conversation, by the line that sent it. */
	FZN_FILE_HOLD_ATTACHMENT = 2
} fzn_file_hold_kind_t;

typedef struct fzn_file_holds {
	const fzn_persist_ops_t *store;
	const fzn_hash_ops_t *hash;
} fzn_file_holds_t;

/* CLAIM `root` for (`kind`, `id`): `*added` 1 when this hold is new, 0 when
 * it was held already. 1 on success. */
int fzn_file_hold_claim(const fzn_file_holds_t *h, const uint8_t root[32],
                        fzn_file_hold_kind_t kind, const uint8_t id[FZN_FILE_HOLD_ID_LEN],
                        int *added);

/* RELEASE that hold: `*left` the holds left after it. One not held changes
 * nothing. 1 on success. */
int fzn_file_hold_release(const fzn_file_holds_t *h, const uint8_t root[32],
                          fzn_file_hold_kind_t kind, const uint8_t id[FZN_FILE_HOLD_ID_LEN],
                          uint64_t *left);

/* THE HOLDS ON `root`: 1 with `*count` when the record knows the file, 0
 * when it never has -- a file the record does not know is never removed
 * by anything that asks here. */
int fzn_file_hold_count(const fzn_file_holds_t *h, const uint8_t root[32], uint64_t *count);

/* Whether `root` is held by (`kind`, `id`). */
int fzn_file_hold_has(const fzn_file_holds_t *h, const uint8_t root[32],
                      fzn_file_hold_kind_t kind, const uint8_t id[FZN_FILE_HOLD_ID_LEN]);

/* WHETHER THE RECORD HAS BEGUN here, and begin it: a node begins once,
 * claiming LEGACY on every file it holds then, so nothing older than the
 * record is ever let go by a rule. */
int fzn_file_holds_begun(const fzn_file_holds_t *h);
int fzn_file_holds_begin(const fzn_file_holds_t *h);

#endif /* FZN_NODE_FILE_HOLDS_H */
