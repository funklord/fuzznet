/* See files.h. */

#define _POSIX_C_SOURCE 200809L

#include "files.h"

#include "../blob/levels.h"
#include "../constant_time/constant_time.h"
#include "../wire/bytes.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ROOT_HEX (FZN_BLOB_HASH_LEN * 2u)
#define REF_HEX (FZN_NODE_FILE_REF_LEN * 2u)
/* Leaves placed under one proof when a file is put: a span is proved as a
 * whole, so the proof is read once for each (`spool/spool.h`). */
#define PUT_SPAN 64u

static const char HEX[] = "0123456789abcdef";

const char *fzn_node_files_err_str(fzn_node_files_err_t err)
{
	switch (err) {
	case FZN_NODE_FILES_OK:
		return "ok";
	case FZN_NODE_FILES_ERR_MALFORMED:
		return "malformed";
	case FZN_NODE_FILES_ERR_ABSENT:
		return "not all here";
	case FZN_NODE_FILES_ERR_STORE:
		return "the disk refused";
	case FZN_NODE_FILES_ERR_SIZE:
		return "empty, or past the largest file a spool holds";
	case FZN_NODE_FILES_ERR_CRYPTO:
		return "the key does not open it, or a leaf is not what was sealed";
	case FZN_NODE_FILES_ERR_BUSY:
		return "a transfer of it is running";
	case FZN_NODE_FILES_ERR_EXISTS:
		return "the destination exists";
	}
	return "unknown";
}

void fzn_node_file_ref_write(const fzn_node_file_ref_t *ref, uint8_t out[FZN_NODE_FILE_REF_LEN])
{
	memcpy(out, ref->root, FZN_BLOB_HASH_LEN);
	memcpy(out + FZN_BLOB_HASH_LEN, ref->key, FZN_BLOB_KEY_LEN);
	fzn_put_be64(out + FZN_BLOB_HASH_LEN + FZN_BLOB_KEY_LEN, ref->length);
}

int fzn_node_file_ref_read(const uint8_t in[FZN_NODE_FILE_REF_LEN], fzn_node_file_ref_t *ref)
{
	if (!in || !ref)
		return 0;
	memcpy(ref->root, in, FZN_BLOB_HASH_LEN);
	memcpy(ref->key, in + FZN_BLOB_HASH_LEN, FZN_BLOB_KEY_LEN);
	ref->length = fzn_get_be64(in + FZN_BLOB_HASH_LEN + FZN_BLOB_KEY_LEN);
	return ref->length > 0u && ref->length <= FZN_NODE_FILE_MAX;
}

static void to_hex(const uint8_t *bytes, size_t len, char *out)
{
	size_t i;

	for (i = 0; i < len; i++) {
		out[i * 2u] = HEX[bytes[i] >> 4];
		out[(i * 2u) + 1u] = HEX[bytes[i] & 15u];
	}
	out[len * 2u] = '\0';
}

static int from_hex(const uint8_t *text, size_t text_len, uint8_t *out, size_t len)
{
	size_t i;

	if (text_len != len * 2u)
		return 0;
	for (i = 0; i < text_len; i++) {
		const char *at = text[i] ? memchr(HEX, text[i], 16u) : NULL;

		if (!at)
			return 0;
		if (i % 2u == 0u)
			out[i / 2u] = (uint8_t)((at - HEX) << 4);
		else
			out[i / 2u] |= (uint8_t)(at - HEX);
	}
	return 1;
}

/* `<dir>/<root hex><suffix>`, or `<dir>/<name>` with no root. */
static int path_of(const fzn_node_files_t *files, const uint8_t *root, const char *suffix,
                   char out[FZN_SPOOL_FILE_PATH_MAX])
{
	char hex[ROOT_HEX + 1u];
	int n;

	if (root)
		to_hex(root, FZN_BLOB_HASH_LEN, hex);
	n = snprintf(out, FZN_SPOOL_FILE_PATH_MAX, "%s/%s%s", files->dir, root ? hex : "",
	             suffix);
	return n > 0 && (size_t)n < FZN_SPOOL_FILE_PATH_MAX;
}

fzn_node_files_err_t fzn_node_files_init(fzn_node_files_t *files, const char *dir,
                                         const fzn_hash_ops_t *hash, const fzn_aead_ops_t *aead,
                                         const fzn_random_ops_t *rng)
{
	size_t n;

	if (!files || !dir || !hash || !hash->hash || !aead || !rng || !rng->fill)
		return FZN_NODE_FILES_ERR_MALFORMED;
	n = strlen(dir);
	if (n == 0u || n >= sizeof(files->dir))
		return FZN_NODE_FILES_ERR_MALFORMED;
	memset(files, 0, sizeof(*files));
	memcpy(files->dir, dir, n + 1u);
	files->hash = hash;
	files->aead = aead;
	files->rng = rng;
	/* Owner-only: what a host stores says what it holds. */
	if (mkdir(dir, 0700) != 0 && errno != EEXIST)
		return FZN_NODE_FILES_ERR_STORE;
	return FZN_NODE_FILES_OK;
}

/* ---- a file descriptor as the levels' storage --------------------------- */

static int fd_read(void *ctx, uint64_t offset, uint8_t *out, size_t len)
{
	int fd = *(const int *)ctx;
	size_t at = 0;

	while (at < len) {
		ssize_t n = pread(fd, out + at, len - at, (off_t)(offset + at));

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return 0;
		at += (size_t)n;
	}
	return 1;
}

static int fd_write(void *ctx, uint64_t offset, const uint8_t *in, size_t len)
{
	int fd = *(const int *)ctx;
	size_t at = 0;

	while (at < len) {
		ssize_t n = pwrite(fd, in + at, len - at, (off_t)(offset + at));

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			return 0;
		at += (size_t)n;
	}
	return 1;
}

static int write_length(const fzn_node_files_t *files, const uint8_t *root, uint64_t length)
{
	char path[FZN_SPOOL_FILE_PATH_MAX], tmp[FZN_SPOOL_FILE_PATH_MAX];
	uint8_t bytes[8];
	int fd, ok;

	if (!path_of(files, root, ".len", path) || !path_of(files, root, ".len.new", tmp))
		return 0;
	fzn_put_be64(bytes, length);
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return 0;
	ok = fd_write(&fd, 0, bytes, sizeof(bytes)) && fsync(fd) == 0;
	ok = (close(fd) == 0) && ok;
	return ok && rename(tmp, path) == 0;
}

static int read_length(const char *path, uint64_t *length)
{
	uint8_t bytes[8];
	int fd = open(path, O_RDONLY), ok;

	if (fd < 0)
		return 0;
	ok = fd_read(&fd, 0, bytes, sizeof(bytes));
	(void)close(fd);
	if (ok)
		*length = fzn_get_be64(bytes);
	return ok;
}

/* The bitmap a whole blob of FZN_SPOOL_MAX_LEAVES needs: 512 KiB, kept once
 * rather than on the stack. One operation at a time uses it. */
static uint8_t present[FZN_SPOOL_BITMAP_LEN(FZN_SPOOL_MAX_LEAVES)];

typedef struct held {
	fzn_spool_file_t file;
	fzn_spool_t spool;
	uint64_t length;
	uint64_t leaves;
	size_t last;
} held_t;

/* The blob `root` opened for reading, WHOLE: its sidecar, its length and
 * its tree agreeing with each other. ABSENT without opening anything when
 * any of it is missing or disagrees. */
static fzn_node_files_err_t open_whole(const fzn_node_files_t *files,
                                       const uint8_t root[FZN_BLOB_HASH_LEN], held_t *h)
{
	char path[FZN_SPOOL_FILE_PATH_MAX], len_path[FZN_SPOOL_FILE_PATH_MAX];
	char tree_path[FZN_SPOOL_FILE_PATH_MAX];
	const fzn_spool_ops_t *ops;
	uint64_t leaves = 0;
	struct stat st;

	memset(h, 0, sizeof(*h));
	h->file.fd = -1;
	if (!path_of(files, root, "", path) || !path_of(files, root, ".len", len_path)
	    || !path_of(files, root, ".tree", tree_path))
		return FZN_NODE_FILES_ERR_MALFORMED;
	if (fzn_spool_file_leaves(path, root, &leaves) != FZN_SPOOL_OK
	    || !read_length(len_path, &h->length) || h->length == 0u
	    || h->length > FZN_NODE_FILE_MAX
	    || fzn_blob_geometry(h->length, &h->leaves, &h->last) != FZN_BLOB_OK
	    || h->leaves != leaves || stat(tree_path, &st) != 0
	    || (uint64_t)st.st_size != fzn_blob_levels_bytes(leaves))
		return FZN_NODE_FILES_ERR_ABSENT;
	ops = fzn_spool_file_open(&h->file, path);
	if (!ops)
		return FZN_NODE_FILES_ERR_STORE;
	(void)fzn_spool_file_resume(&h->file, root, leaves, present,
	                            FZN_SPOOL_BITMAP_LEN(leaves));
	if (fzn_spool_open(&h->spool, root, leaves, present, FZN_SPOOL_BITMAP_LEN(leaves), ops)
	            != FZN_SPOOL_OK
	    || !fzn_spool_complete(&h->spool)) {
		fzn_spool_file_close(&h->file);
		return FZN_NODE_FILES_ERR_ABSENT;
	}
	return FZN_NODE_FILES_OK;
}

static int is_busy(const fzn_node_files_t *files, const uint8_t root[FZN_BLOB_HASH_LEN])
{
	size_t i;

	for (i = 0; i < files->n_busy; i++)
		if (memcmp(files->busy[i], root, FZN_BLOB_HASH_LEN) == 0)
			return 1;
	return 0;
}

fzn_node_files_err_t fzn_node_files_busy(fzn_node_files_t *files,
                                         const uint8_t root[FZN_BLOB_HASH_LEN], int busy)
{
	size_t i;

	if (!files || !root)
		return FZN_NODE_FILES_ERR_MALFORMED;
	for (i = 0; i < files->n_busy; i++)
		if (memcmp(files->busy[i], root, FZN_BLOB_HASH_LEN) == 0)
			break;
	if (busy) {
		if (i < files->n_busy)
			return FZN_NODE_FILES_OK;
		if (files->n_busy >= FZN_NODE_FILES_BUSY_MAX)
			return FZN_NODE_FILES_ERR_MALFORMED;
		memcpy(files->busy[files->n_busy++], root, FZN_BLOB_HASH_LEN);
	} else if (i < files->n_busy) {
		memmove(files->busy[i], files->busy[i + 1u],
		        (files->n_busy - i - 1u) * (size_t)FZN_BLOB_HASH_LEN);
		files->n_busy--;
	}
	return FZN_NODE_FILES_OK;
}

/* ---- putting a file ---------------------------------------------------- */

/* Leaf `index` of the file behind `fd`, `length` long, sealed under `key`. */
static int seal_at(const fzn_node_files_t *files, int fd, uint64_t length, const uint8_t *key,
                   uint64_t index, uint8_t out[FZN_BLOB_SEALED_MAX], size_t *out_len)
{
	uint8_t plain[FZN_BLOB_LEAF_SIZE];
	uint64_t at = index * FZN_BLOB_LEAF_SIZE;
	size_t take = length - at < FZN_BLOB_LEAF_SIZE ? (size_t)(length - at)
	                                               : (size_t)FZN_BLOB_LEAF_SIZE;
	int ok;

	ok = fd_read(&fd, at, plain, take)
	     && fzn_blob_leaf_seal(files->hash, files->aead, key, index, plain, take, out,
	                           FZN_BLOB_SEALED_MAX, out_len) == FZN_BLOB_OK;
	fzn_wipe(plain, sizeof(plain));
	return ok;
}

fzn_node_files_err_t fzn_node_files_put(fzn_node_files_t *files, const char *path,
                                        fzn_node_file_ref_t *ref)
{
	static uint8_t sealed[PUT_SPAN][FZN_BLOB_SEALED_MAX];
	const uint8_t *spans[PUT_SPAN];
	size_t span_len[PUT_SPAN];
	char work[FZN_SPOOL_FILE_PATH_MAX], work_bits[FZN_SPOOL_FILE_PATH_MAX];
	char work_tree[FZN_SPOOL_FILE_PATH_MAX], name[FZN_SPOOL_FILE_PATH_MAX];
	char bits[FZN_SPOOL_FILE_PATH_MAX], tree_name[FZN_SPOOL_FILE_PATH_MAX];
	uint8_t key[FZN_BLOB_KEY_LEN], root[FZN_BLOB_HASH_LEN], leaf[FZN_BLOB_HASH_LEN];
	uint8_t proof[FZN_BLOB_MAX_DEPTH * FZN_BLOB_HASH_LEN];
	fzn_blob_levels_builder_t builder;
	fzn_blob_levels_io_t io;
	fzn_blob_levels_t levels;
	fzn_blob_tree_t tree;
	fzn_spool_file_t file;
	fzn_spool_t spool;
	const fzn_spool_ops_t *ops;
	fzn_node_files_err_t err = FZN_NODE_FILES_ERR_STORE;
	uint64_t length, leaves = 0, i, n;
	size_t last = 0, sealed_len = 0;
	unsigned siblings = 0;
	struct stat st;
	int fd, tree_fd = -1;

	if (!files || !path || !ref)
		return FZN_NODE_FILES_ERR_MALFORMED;
	if (!path_of(files, NULL, "put", work) || !path_of(files, NULL, "put.bits", work_bits)
	    || !path_of(files, NULL, "put.tree", work_tree))
		return FZN_NODE_FILES_ERR_MALFORMED;
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return FZN_NODE_FILES_ERR_ABSENT;
	if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
		(void)close(fd);
		return FZN_NODE_FILES_ERR_ABSENT;
	}
	length = (uint64_t)st.st_size;
	if (length == 0u || length > FZN_NODE_FILE_MAX
	    || fzn_blob_geometry(length, &leaves, &last) != FZN_BLOB_OK || leaves == 0u
	    || leaves > FZN_SPOOL_MAX_LEAVES) {
		(void)close(fd);
		return FZN_NODE_FILES_ERR_SIZE;
	}
	/* A WORKING NAME LEFT BY A CRASH is replaced, never resumed: it is a
	 * blob under a key nobody kept. */
	(void)remove(work);
	(void)remove(work_bits);
	(void)remove(work_tree);
	file.fd = -1;
	/* A FRESH KEY: one key over two files breaks the AEAD (`blob.h`). */
	if (!files->rng->fill(files->rng->ctx, key, sizeof(key))) {
		(void)close(fd);
		return FZN_NODE_FILES_ERR_CRYPTO;
	}
	tree_fd = open(work_tree, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (tree_fd < 0)
		goto out;
	io.read = fd_read;
	io.write = fd_write;
	io.ctx = &tree_fd;

	/* THE ROOT AND THE TREE, one pass: every leaf sealed and hashed, the
	 * root folded and the perfect subtrees written. */
	err = FZN_NODE_FILES_ERR_CRYPTO;
	fzn_blob_tree_init(&tree);
	if (fzn_blob_levels_begin(&builder, leaves) != FZN_BLOB_OK)
		goto out;
	for (i = 0; i < leaves; i++) {
		if (!seal_at(files, fd, length, key, i, sealed[0], &sealed_len)
		    || fzn_blob_leaf_hash(files->hash, sealed[0], sealed_len, leaf) != FZN_BLOB_OK
		    || fzn_blob_tree_push(files->hash, &tree, leaf) != FZN_BLOB_OK)
			goto out;
		if (fzn_blob_levels_push(files->hash, &builder, &io, leaf) != FZN_BLOB_OK) {
			err = FZN_NODE_FILES_ERR_STORE;
			goto out;
		}
	}
	if (fzn_blob_tree_root(files->hash, &tree, root) != FZN_BLOB_OK)
		goto out;

	/* EVERY LEAF PLACED AS A STRANGER'S WOULD BE, a span at a time under
	 * the proof the tree on disk gives: through the spool's verification
	 * against the root, so neither a sealing bug nor a tree written wrong
	 * can put down a leaf that would not prove. */
	err = FZN_NODE_FILES_ERR_STORE;
	ops = fzn_spool_file_open(&file, work);
	if (!ops)
		goto out;
	memset(present, 0, FZN_SPOOL_BITMAP_LEN(leaves));
	if (fzn_spool_open(&spool, root, leaves, present, FZN_SPOOL_BITMAP_LEN(leaves), ops)
	    != FZN_SPOOL_OK)
		goto out;
	levels.hash = files->hash;
	levels.io = &io;
	levels.leaves = leaves;
	for (i = 0; i < leaves; i += n) {
		uint64_t k;

		n = fzn_blob_span_largest_at(leaves, i, PUT_SPAN);
		if (n == 0u)
			goto out;
		for (k = 0; k < n; k++) {
			if (!seal_at(files, fd, length, key, i + k, sealed[k], &span_len[k])) {
				err = FZN_NODE_FILES_ERR_CRYPTO;
				goto out;
			}
			spans[k] = sealed[k];
		}
		if (fzn_blob_levels_span_proof(&levels, i, n, proof, sizeof(proof), &siblings)
		            != FZN_BLOB_OK
		    || fzn_spool_place_span(&spool, files->hash, i, n, spans, span_len, proof,
		                            siblings)
		               != FZN_SPOOL_OK) {
			err = FZN_NODE_FILES_ERR_CRYPTO;
			goto out;
		}
	}
	if (!fzn_spool_complete(&spool) || fzn_spool_file_checkpoint(&file, &spool) != FZN_SPOOL_OK
	    || fsync(tree_fd) != 0)
		goto out;

	/* THE LENGTH, THE TREE AND THE LEAVES, THEN THE SIDECAR: a blob is held
	 * from the moment its sidecar appears under its root, so that is last. */
	if (!path_of(files, root, "", name) || !path_of(files, root, ".bits", bits)
	    || !path_of(files, root, ".tree", tree_name) || !write_length(files, root, length)
	    || rename(work_tree, tree_name) != 0 || rename(work, name) != 0
	    || rename(work_bits, bits) != 0)
		goto out;
	memcpy(ref->root, root, sizeof(root));
	memcpy(ref->key, key, sizeof(key));
	ref->length = length;
	err = FZN_NODE_FILES_OK;
out:
	fzn_wipe(key, sizeof(key));
	fzn_spool_file_close(&file);
	if (tree_fd >= 0)
		(void)close(tree_fd);
	(void)close(fd);
	if (err != FZN_NODE_FILES_OK) {
		(void)remove(work);
		(void)remove(work_bits);
		(void)remove(work_tree);
	}
	return err;
}

/* ---- reading, exporting, deleting -------------------------------------- */

fzn_node_files_err_t fzn_node_files_held(const fzn_node_files_t *files,
                                         const uint8_t root[FZN_BLOB_HASH_LEN],
                                         uint64_t *length)
{
	static held_t h;
	fzn_node_files_err_t err;

	if (!files || !root || !length)
		return FZN_NODE_FILES_ERR_MALFORMED;
	err = open_whole(files, root, &h);
	if (err != FZN_NODE_FILES_OK)
		return err;
	*length = h.length;
	fzn_spool_file_close(&h.file);
	return FZN_NODE_FILES_OK;
}

fzn_node_files_err_t fzn_node_files_export(const fzn_node_files_t *files,
                                           const fzn_node_file_ref_t *ref, const char *path)
{
	static held_t h;
	uint8_t sealed[FZN_BLOB_SEALED_MAX], plain[FZN_BLOB_LEAF_SIZE];
	fzn_node_files_err_t err;
	uint64_t i;
	int fd;

	if (!files || !ref || !path)
		return FZN_NODE_FILES_ERR_MALFORMED;
	err = open_whole(files, ref->root, &h);
	if (err != FZN_NODE_FILES_OK)
		return err;
	if (h.length != ref->length) {
		fzn_spool_file_close(&h.file);
		return FZN_NODE_FILES_ERR_ABSENT;
	}
	/* A NEW FILE, never one written over. */
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) {
		fzn_spool_file_close(&h.file);
		return errno == EEXIST ? FZN_NODE_FILES_ERR_EXISTS : FZN_NODE_FILES_ERR_STORE;
	}
	for (i = 0; i < h.leaves && err == FZN_NODE_FILES_OK; i++) {
		size_t want = (i + 1u == h.leaves ? h.last : (size_t)FZN_BLOB_LEAF_SIZE)
		              + FZN_BLOB_LEAF_OVERHEAD;
		size_t got = 0, opened = 0;

		if (fzn_spool_read(&h.spool, i, sealed, sizeof(sealed), &got) != FZN_SPOOL_OK
		    || got < want)
			err = FZN_NODE_FILES_ERR_STORE;
		else if (fzn_blob_leaf_open(files->hash, files->aead, ref->key, i, sealed, want, plain,
		                            sizeof(plain), &opened)
		         != FZN_BLOB_OK)
			err = FZN_NODE_FILES_ERR_CRYPTO;
		else if (!fd_write(&fd, i * FZN_BLOB_LEAF_SIZE, plain, opened))
			err = FZN_NODE_FILES_ERR_STORE;
	}
	fzn_wipe(plain, sizeof(plain));
	fzn_spool_file_close(&h.file);
	if (err == FZN_NODE_FILES_OK && fsync(fd) != 0)
		err = FZN_NODE_FILES_ERR_STORE;
	if (close(fd) != 0 && err == FZN_NODE_FILES_OK)
		err = FZN_NODE_FILES_ERR_STORE;
	/* NOTHING HALF-EXPORTED is left at the destination. */
	if (err != FZN_NODE_FILES_OK)
		(void)remove(path);
	return err;
}

fzn_node_files_err_t fzn_node_files_remove(fzn_node_files_t *files,
                                           const uint8_t root[FZN_BLOB_HASH_LEN])
{
	static const char *const AFTER[] = { "", ".tree", ".len" };
	char path[FZN_SPOOL_FILE_PATH_MAX];
	size_t i;

	if (!files || !root)
		return FZN_NODE_FILES_ERR_MALFORMED;
	if (is_busy(files, root))
		return FZN_NODE_FILES_ERR_BUSY;
	/* THE SIDECAR FIRST: once it is gone the blob is not held, not
	 * served and not opened, whatever happens to the rest. */
	if (!path_of(files, root, ".bits", path))
		return FZN_NODE_FILES_ERR_MALFORMED;
	if (remove(path) != 0)
		return errno == ENOENT ? FZN_NODE_FILES_ERR_ABSENT : FZN_NODE_FILES_ERR_STORE;
	for (i = 0; i < sizeof(AFTER) / sizeof(AFTER[0]); i++)
		if (!path_of(files, root, AFTER[i], path)
		    || (remove(path) != 0 && errno != ENOENT))
			return FZN_NODE_FILES_ERR_STORE;
	return FZN_NODE_FILES_OK;
}

static int by_root(const void *a, const void *b)
{
	return memcmp(a, b, FZN_BLOB_HASH_LEN);
}

fzn_node_files_err_t fzn_node_files_list(const fzn_node_files_t *files,
                                         uint8_t (*roots)[FZN_BLOB_HASH_LEN], size_t cap,
                                         size_t *count)
{
	static uint8_t found[1024][FZN_BLOB_HASH_LEN];
	struct dirent *e;
	size_t n = 0, i;
	DIR *d;

	if (!files || (cap && !roots) || !count)
		return FZN_NODE_FILES_ERR_MALFORMED;
	*count = 0;
	d = opendir(files->dir);
	if (!d)
		return FZN_NODE_FILES_ERR_STORE;
	/* A NAME OF THE STORE'S OWN SHAPE, `<64 hex>.bits`, and only those
	 * whole: a blob part way through a transfer is not listed. */
	while ((e = readdir(d)) != NULL && n < sizeof(found) / sizeof(found[0])) {
		uint64_t length = 0;

		if (strlen(e->d_name) != ROOT_HEX + 5u || strcmp(e->d_name + ROOT_HEX, ".bits") != 0
		    || !from_hex((const uint8_t *)e->d_name, ROOT_HEX, found[n], FZN_BLOB_HASH_LEN)
		    || fzn_node_files_held(files, found[n], &length) != FZN_NODE_FILES_OK)
			continue;
		n++;
	}
	(void)closedir(d);
	qsort(found, n, sizeof(found[0]), by_root);
	for (i = 0; i < n && i < cap; i++)
		memcpy(roots[i], found[i], FZN_BLOB_HASH_LEN);
	*count = n;
	return FZN_NODE_FILES_OK;
}

/* ---- the verbs ---------------------------------------------------------- */

static size_t answer(char *reply, size_t cap, fzn_reply_t kind, const char *detail)
{
	size_t len = 0;

	if (fzn_reply_compose((uint8_t *)reply, cap, &len, kind, (const uint8_t *)detail,
	                      detail ? strlen(detail) : 0u)
	    != FZN_COMPOSE_OK)
		return 0;
	return len;
}

static size_t refused(char *reply, size_t cap, fzn_node_files_err_t err)
{
	return answer(reply, cap,
	              err == FZN_NODE_FILES_ERR_MALFORMED ? FZN_REPLY_MALFORMED : FZN_REPLY_ERROR,
	              fzn_node_files_err_str(err));
}

/* `arg` as a NUL-terminated path in `out`. */
static int path_arg(const uint8_t *arg, size_t len, char out[FZN_SPOOL_FILE_PATH_MAX])
{
	if (len == 0u || len >= FZN_SPOOL_FILE_PATH_MAX || memchr(arg, '\0', len))
		return 0;
	memcpy(out, arg, len);
	out[len] = '\0';
	return 1;
}

static size_t list_files(const fzn_node_files_t *files, const uint8_t *arg, size_t arg_len,
                         char *reply, size_t cap)
{
	static uint8_t roots[1024][FZN_BLOB_HASH_LEN];
	char detail[FZN_REPLY_MAX + 1u];
	size_t limit = (cap > 0u && cap - 1u < FZN_REPLY_MAX) ? cap - 1u : FZN_REPLY_MAX;
	size_t count = 0, from = 0, used, i;
	fzn_node_files_err_t err;
	int n;

	for (i = 0; i < arg_len; i++) {
		if (arg[i] < '0' || arg[i] > '9' || from > 1024u)
			return answer(reply, cap, FZN_REPLY_MALFORMED, "not an index");
		from = (from * 10u) + (size_t)(arg[i] - '0');
	}
	err = fzn_node_files_list(files, roots, sizeof(roots) / sizeof(roots[0]), &count);
	if (err != FZN_NODE_FILES_OK)
		return refused(reply, cap, err);
	if (from > count)
		return answer(reply, cap, FZN_REPLY_MALFORMED, "past the last file");
	n = snprintf(detail, sizeof(detail), "%zu %zu", count, from);
	if (n < 0 || (size_t)n >= limit)
		return 0;
	used = (size_t)n;
	for (i = from; i < count && i < sizeof(roots) / sizeof(roots[0]); i++) {
		char hex[ROOT_HEX + 1u], item[ROOT_HEX + 24u];
		uint64_t length = 0;
		int m;

		if (fzn_node_files_held(files, roots[i], &length) != FZN_NODE_FILES_OK)
			continue;
		to_hex(roots[i], FZN_BLOB_HASH_LEN, hex);
		m = snprintf(item, sizeof(item), " %s,%llu", hex, (unsigned long long)length);
		if (m < 0 || limit - used < (size_t)m)
			break;
		memcpy(detail + used, item, (size_t)m);
		used += (size_t)m;
	}
	detail[used] = '\0';
	return answer(reply, cap, FZN_REPLY_OK, detail);
}

size_t fzn_node_files_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                            char *reply, size_t reply_cap)
{
	static const uint8_t FILE_[] = "file";
	fzn_node_files_t *files = (fzn_node_files_t *)ctx;
	const uint8_t *arg;
	size_t arg_len;
	char path[FZN_SPOOL_FILE_PATH_MAX];
	fzn_node_file_ref_t ref;
	fzn_node_files_err_t err;

	if (!files || !request || !reply || !request->arg
	    || request->arg_len < sizeof(FILE_) - 1u
	    || memcmp(request->arg, FILE_, sizeof(FILE_) - 1u) != 0
	    || (request->arg_len > sizeof(FILE_) - 1u && request->arg[sizeof(FILE_) - 1u] != ' '))
		return 0;
	if (request->parsed != FZN_VERB_PUT && request->parsed != FZN_VERB_GET
	    && request->parsed != FZN_VERB_REMOVE && request->parsed != FZN_VERB_LIST)
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return answer(reply, reply_cap, FZN_REPLY_DENIED, "a file needs this node's own user");
	arg = request->arg + sizeof(FILE_) - 1u;
	arg_len = request->arg_len - (sizeof(FILE_) - 1u);
	if (arg_len) {
		arg++;
		arg_len--;
	}
	if (request->parsed == FZN_VERB_LIST)
		return list_files(files, arg, arg_len, reply, reply_cap);
	if (request->parsed == FZN_VERB_PUT) {
		uint8_t bytes[FZN_NODE_FILE_REF_LEN];
		char hex[REF_HEX + 1u];

		if (!path_arg(arg, arg_len, path))
			return answer(reply, reply_cap, FZN_REPLY_MALFORMED, "put file PATH");
		err = fzn_node_files_put(files, path, &ref);
		if (err != FZN_NODE_FILES_OK)
			return refused(reply, reply_cap, err);
		fzn_node_file_ref_write(&ref, bytes);
		fzn_wipe(&ref, sizeof(ref));
		to_hex(bytes, sizeof(bytes), hex);
		fzn_wipe(bytes, sizeof(bytes));
		return answer(reply, reply_cap, FZN_REPLY_OK, hex);
	}
	if (request->parsed == FZN_VERB_REMOVE) {
		uint8_t root[FZN_BLOB_HASH_LEN];

		if (!from_hex(arg, arg_len, root, sizeof(root)))
			return answer(reply, reply_cap, FZN_REPLY_MALFORMED, "remove file ROOT");
		err = fzn_node_files_remove(files, root);
		return err == FZN_NODE_FILES_OK ? answer(reply, reply_cap, FZN_REPLY_OK, NULL)
		                                : refused(reply, reply_cap, err);
	}
	/* `get file REF PATH`. */
	{
		uint8_t bytes[FZN_NODE_FILE_REF_LEN];

		if (arg_len < REF_HEX + 2u || arg[REF_HEX] != ' '
		    || !from_hex(arg, REF_HEX, bytes, sizeof(bytes)) || !fzn_node_file_ref_read(bytes, &ref)
		    || !path_arg(arg + REF_HEX + 1u, arg_len - REF_HEX - 1u, path)) {
			fzn_wipe(bytes, sizeof(bytes));
			return answer(reply, reply_cap, FZN_REPLY_MALFORMED, "get file REF PATH");
		}
		fzn_wipe(bytes, sizeof(bytes));
		err = fzn_node_files_export(files, &ref, path);
		fzn_wipe(&ref, sizeof(ref));
		return err == FZN_NODE_FILES_OK ? answer(reply, reply_cap, FZN_REPLY_OK, NULL)
		                                : refused(reply, reply_cap, err);
	}
}
