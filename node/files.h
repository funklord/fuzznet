/* The node's files: blobs of any size, kept sealed in spool files. sec 490.
 *
 * WHAT IT IS FOR. The holder decided 2026-10-06 that fuzzypickles' file
 * storage moves onto fuzznet's `spool/` and `blob/`, reversing the decline
 * of 2026-09-01, and that a file referenced by an old-shape root is
 * invalidated rather than translated. This module is that store's first
 * half: putting a file, exporting it, listing what is held and deleting it.
 * Carrying files between hosts, tiers and the scrub follow (sec 490).
 *
 * IT IS THE SHELF'S SHAPE MADE TO SCALE. `node/shelf.h` keeps note texts of
 * at most 256 KiB, whose every leaf hash fits in memory. A file goes to
 * FZN_SPOOL_MAX_LEAVES leaves, 4 GiB, so its tree is kept on disk beside it
 * (`blob/levels.h`) and a file is sealed by streaming it twice: once to the
 * root, once to place every leaf through the spool's own verification.
 *
 * ON DISK, under one directory, one blob per root:
 *
 *     <root hex>        the sealed leaves       (`spool/spool_file.h`)
 *     <root hex>.bits   which are present       (its sidecar)
 *     <root hex>.len    the file's length, be64
 *     <root hex>.tree   its perfect subtrees    (`blob/levels.h`)
 *
 * A BLOB IS HELD WHEN ITS SIDECAR SAYS IT IS WHOLE. The sidecar is written
 * last when a file is put, and removed first when one is deleted, so a blob
 * is never held without its leaves, length and tree.
 *
 * THE CONTENT KEY IS NOT HERE. A put answers a reference -- root, key and
 * length, the 72 bytes `notes/note.h` lays out for a text -- and whoever
 * keeps the reference can open the file. The store holds ciphertext.
 *
 * DELETION, the holder's sixth requirement, as fuzzypickles stated it: one
 * device at a time, every file of the blob gone, never while a transfer of
 * it is running, and nothing done to whatever references it elsewhere. A
 * transfer marks its root busy for as long as it runs.
 */

#ifndef FZN_NODE_FILES_H
#define FZN_NODE_FILES_H

#include <stddef.h>
#include <stdint.h>

#include "../local/vocabulary.h"
#include "../chain/authz.h"
#include "../blob/blob.h"
#include "../session/aead.h"
#include "../session/random.h"
#include "../spool/spool_file.h"

/* The directory's length, leaving room for "/<64 hex>.bits" and more. */
#define FZN_NODE_FILES_DIR_MAX (FZN_SPOOL_FILE_PATH_MAX - 80u)
/* A file's reference: root, content key, length. */
#define FZN_NODE_FILE_REF_LEN (FZN_BLOB_HASH_LEN + FZN_BLOB_KEY_LEN + 8u)
/* The largest file: as many leaves as a spool holds. */
#define FZN_NODE_FILE_MAX ((uint64_t)FZN_SPOOL_MAX_LEAVES * FZN_BLOB_LEAF_SIZE)
/* Roots a transfer may hold busy at once. */
#define FZN_NODE_FILES_BUSY_MAX 16u

typedef enum fzn_node_files_err {
	FZN_NODE_FILES_OK = 0,
	FZN_NODE_FILES_ERR_MALFORMED = -1,
	/* Not held here, or not all of it. */
	FZN_NODE_FILES_ERR_ABSENT = -2,
	/* The disk refused. */
	FZN_NODE_FILES_ERR_STORE = -3,
	/* Empty, or past FZN_NODE_FILE_MAX. */
	FZN_NODE_FILES_ERR_SIZE = -4,
	/* Sealing or opening refused: the key is not this file's, or a leaf
	 * on disk is not what was sealed. */
	FZN_NODE_FILES_ERR_CRYPTO = -5,
	/* A transfer of the blob is running. */
	FZN_NODE_FILES_ERR_BUSY = -6,
	/* An export's destination exists already. */
	FZN_NODE_FILES_ERR_EXISTS = -7
} fzn_node_files_err_t;

const char *fzn_node_files_err_str(fzn_node_files_err_t err);

typedef struct fzn_node_file_ref {
	uint8_t root[FZN_BLOB_HASH_LEN];
	uint8_t key[FZN_BLOB_KEY_LEN];
	uint64_t length;
} fzn_node_file_ref_t;

/* The 72 bytes, root then key then length big-endian, and back. */
void fzn_node_file_ref_write(const fzn_node_file_ref_t *ref, uint8_t out[FZN_NODE_FILE_REF_LEN]);
int fzn_node_file_ref_read(const uint8_t in[FZN_NODE_FILE_REF_LEN], fzn_node_file_ref_t *ref);

typedef struct fzn_node_files {
	char dir[FZN_NODE_FILES_DIR_MAX];
	const fzn_hash_ops_t *hash;
	const fzn_aead_ops_t *aead;
	const fzn_random_ops_t *rng;
	uint8_t busy[FZN_NODE_FILES_BUSY_MAX][FZN_BLOB_HASH_LEN];
	size_t n_busy;
} fzn_node_files_t;

/* Over `dir`, created mode 0700 when it is not there. */
fzn_node_files_err_t fzn_node_files_init(fzn_node_files_t *files, const char *dir,
                                         const fzn_hash_ops_t *hash, const fzn_aead_ops_t *aead,
                                         const fzn_random_ops_t *rng);

/* SEAL THE FILE AT `path` under a fresh key, and say what references it. A
 * working name holds it until it is whole and named by its root, so a crash
 * leaves the working name, which the next put replaces. */
fzn_node_files_err_t fzn_node_files_put(fzn_node_files_t *files, const char *path,
                                        fzn_node_file_ref_t *ref);

/* Whether the whole of `root` is here, and its length. */
fzn_node_files_err_t fzn_node_files_held(const fzn_node_files_t *files,
                                         const uint8_t root[FZN_BLOB_HASH_LEN],
                                         uint64_t *length);

/* EXPORT the file `ref` names to a new file at `path`, opening every leaf
 * with its key. EXISTS when `path` does; a partial export is removed. */
fzn_node_files_err_t fzn_node_files_export(const fzn_node_files_t *files,
                                           const fzn_node_file_ref_t *ref, const char *path);

/* DELETE every file of `root`: the sidecar first, so it stops being held
 * before its leaves go. ABSENT when nothing of it is here; BUSY while a
 * transfer of it runs. */
fzn_node_files_err_t fzn_node_files_remove(fzn_node_files_t *files,
                                           const uint8_t root[FZN_BLOB_HASH_LEN]);

/* The whole blobs held, `cap` at most, in order of root; `*count` how many
 * there are in all. */
fzn_node_files_err_t fzn_node_files_list(const fzn_node_files_t *files,
                                         uint8_t (*roots)[FZN_BLOB_HASH_LEN], size_t cap,
                                         size_t *count);

/* A TRANSFER'S ROOT, held busy while it runs so it is not deleted under it,
 * and let go. FULL past FZN_NODE_FILES_BUSY_MAX is MALFORMED. */
fzn_node_files_err_t fzn_node_files_busy(fzn_node_files_t *files,
                                         const uint8_t root[FZN_BLOB_HASH_LEN], int busy);

/* THE NODE'S VERBS, for `node/admin.h`'s hook; 0 when `request` is not one:
 *
 *     put file PATH          seal the file at PATH; answers its reference
 *     get file REF PATH      export it to PATH, a file that is not there
 *     remove file ROOT       delete it here
 *     list file [FROM]       `ok TOTAL FROM ROOT,LENGTH ...`
 *
 * REF is the reference in hex, ROOT the root. All need this node's own
 * user: a put reads a file as the node, an export writes one. */
size_t fzn_node_files_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                            char *reply, size_t reply_cap);

#endif /* FZN_NODE_FILES_H */
