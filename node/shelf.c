/* See shelf.h. */

#define _POSIX_C_SOURCE 200809L

#include "shelf.h"

#include "../wire/bytes.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

_Static_assert(FZN_NODE_SHELF_SPAN <= FZN_MSG_MAX_SPAN,
               "a shelf span is past what one DATA may carry");
_Static_assert(FZN_NODE_SHELF_WANTS > 0u, "a shelf remembers no wants");

#define ROOT_HEX (FZN_BLOB_HASH_LEN * 2u)
#define REF_HEX (FZN_NOTE_BLOB_REF_LEN * 2u)

static const char HEX[] = "0123456789abcdef";

/* One blob held open: the file, the spool over it, its bitmap. */
typedef struct held {
	fzn_spool_file_t file;
	fzn_spool_t spool;
	uint8_t present[FZN_NOTE_TEXT_PRESENT_LEN];
	uint64_t length;
	uint64_t leaves;
	size_t last;
} held_t;

const char *fzn_node_shelf_err_str(fzn_node_shelf_err_t err)
{
	switch (err) {
	case FZN_NODE_SHELF_OK:
		return "ok";
	case FZN_NODE_SHELF_ERR_MALFORMED:
		return "malformed";
	case FZN_NODE_SHELF_ERR_ABSENT:
		return "not all here";
	case FZN_NODE_SHELF_ERR_STORE:
		return "the disk refused";
	case FZN_NODE_SHELF_ERR_NO_ANSWER:
		return "the peer did not answer";
	case FZN_NODE_SHELF_ERR_SHAPE:
		return "the peer's answer does not parse";
	case FZN_NODE_SHELF_ERR_UNVERIFIED:
		return "the peer's leaves do not prove";
	case FZN_NODE_SHELF_ERR_TEXT:
		return "the text refused";
	case FZN_NODE_SHELF_ERR_FULL:
		return "no room for another want";
	}
	return "unknown";
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
		const char *at = memchr(HEX, text[i], 16u);

		if (!at)
			return 0;
		if (i % 2u == 0u)
			out[i / 2u] = (uint8_t)((at - HEX) << 4);
		else
			out[i / 2u] |= (uint8_t)(at - HEX);
	}
	return 1;
}

/* `<dir>/<root hex><suffix>`. */
static int path_of(const fzn_node_shelf_t *shelf, const uint8_t root[FZN_BLOB_HASH_LEN],
                   const char *suffix, char out[FZN_SPOOL_FILE_PATH_MAX])
{
	char hex[ROOT_HEX + 1u];
	int n;

	to_hex(root, FZN_BLOB_HASH_LEN, hex);
	n = snprintf(out, FZN_SPOOL_FILE_PATH_MAX, "%s/%s%s", shelf->dir, hex, suffix);
	return n > 0 && (size_t)n < FZN_SPOOL_FILE_PATH_MAX;
}

static int read_length(const char *path, uint64_t *length)
{
	uint8_t bytes[8];
	FILE *f = fopen(path, "rb");
	size_t got;

	if (!f)
		return 0;
	got = fread(bytes, 1u, sizeof(bytes), f);
	(void)fclose(f);
	if (got != sizeof(bytes))
		return 0;
	*length = fzn_get_be64(bytes);
	return 1;
}

/* Written aside and renamed, so a reader never sees half a length. */
static int write_length(const fzn_node_shelf_t *shelf, const uint8_t root[FZN_BLOB_HASH_LEN],
                        uint64_t length)
{
	char path[FZN_SPOOL_FILE_PATH_MAX], tmp[FZN_SPOOL_FILE_PATH_MAX];
	uint8_t bytes[8];
	int fd, ok;

	if (!path_of(shelf, root, ".len", path) || !path_of(shelf, root, ".len.new", tmp))
		return 0;
	fzn_put_be64(bytes, length);
	/* 0600, as the spool beside it is (`spool/spool_file.h`). */
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return 0;
	ok = write(fd, bytes, sizeof(bytes)) == (ssize_t)sizeof(bytes);
	ok = (close(fd) == 0) && ok;
	return ok && rename(tmp, path) == 0;
}

/* The text length's geometry, within what the shelf holds. */
static int geometry(uint64_t length, uint64_t *leaves, size_t *last)
{
	return length > 0u && length <= FZN_NOTE_TEXT_MAX
	       && fzn_blob_geometry(length, leaves, last) == FZN_BLOB_OK && *leaves > 0u
	       && *leaves <= FZN_NOTE_TEXT_LEAVES_MAX;
}

/* A leaf's true sealed length, which a spool does not keep. */
static size_t sealed_len_of(const held_t *h, uint64_t index)
{
	return (index + 1u == h->leaves ? h->last : (size_t)FZN_BLOB_LEAF_SIZE)
	       + FZN_BLOB_LEAF_OVERHEAD;
}

/* Open the blob `root` for reading, whole or not. ABSENT without opening
 * anything when there is no sidecar for it, or its length is missing or
 * disagrees with the sidecar about the leaf count. */
static fzn_node_shelf_err_t open_held(const fzn_node_shelf_t *shelf,
                                      const uint8_t root[FZN_BLOB_HASH_LEN], held_t *h)
{
	char path[FZN_SPOOL_FILE_PATH_MAX], len_path[FZN_SPOOL_FILE_PATH_MAX];
	const fzn_spool_ops_t *ops;
	uint64_t leaves = 0;

	memset(h, 0, sizeof(*h));
	h->file.fd = -1;
	if (!path_of(shelf, root, "", path) || !path_of(shelf, root, ".len", len_path))
		return FZN_NODE_SHELF_ERR_MALFORMED;
	if (fzn_spool_file_leaves(path, root, &leaves) != FZN_SPOOL_OK
	    || !read_length(len_path, &h->length) || !geometry(h->length, &h->leaves, &h->last)
	    || h->leaves != leaves)
		return FZN_NODE_SHELF_ERR_ABSENT;
	ops = fzn_spool_file_open(&h->file, path);
	if (!ops)
		return FZN_NODE_SHELF_ERR_STORE;
	(void)fzn_spool_file_resume(&h->file, root, leaves, h->present, sizeof(h->present));
	if (fzn_spool_open(&h->spool, root, leaves, h->present, sizeof(h->present), ops)
	    != FZN_SPOOL_OK) {
		fzn_spool_file_close(&h->file);
		return FZN_NODE_SHELF_ERR_STORE;
	}
	return FZN_NODE_SHELF_OK;
}

/* open_held, and only when every leaf is here. */
static fzn_node_shelf_err_t open_whole(const fzn_node_shelf_t *shelf,
                                       const uint8_t root[FZN_BLOB_HASH_LEN], held_t *h)
{
	fzn_node_shelf_err_t err = open_held(shelf, root, h);

	if (err != FZN_NODE_SHELF_OK)
		return err;
	if (!fzn_spool_complete(&h->spool)) {
		fzn_spool_file_close(&h->file);
		return FZN_NODE_SHELF_ERR_ABSENT;
	}
	return FZN_NODE_SHELF_OK;
}

fzn_node_shelf_err_t fzn_node_shelf_init(fzn_node_shelf_t *shelf, const char *dir,
                                         const fzn_hash_ops_t *hash, const fzn_aead_ops_t *aead,
                                         const fzn_random_ops_t *rng)
{
	size_t n;

	if (!shelf || !dir || !hash || !hash->hash || !aead || !rng)
		return FZN_NODE_SHELF_ERR_MALFORMED;
	n = strlen(dir);
	if (n == 0u || n >= sizeof(shelf->dir))
		return FZN_NODE_SHELF_ERR_MALFORMED;
	memset(shelf, 0, sizeof(*shelf));
	memcpy(shelf->dir, dir, n + 1u);
	shelf->hash = hash;
	shelf->aead = aead;
	shelf->rng = rng;
	if (mkdir(dir, 0700) != 0 && errno != EEXIST)
		return FZN_NODE_SHELF_ERR_STORE;
	return FZN_NODE_SHELF_OK;
}

fzn_node_shelf_err_t fzn_node_shelf_put(fzn_node_shelf_t *shelf, const uint8_t *text, size_t len,
                                        fzn_note_blob_ref_t *ref)
{
	static uint8_t present[FZN_NOTE_TEXT_PRESENT_LEN];
	char work[FZN_SPOOL_FILE_PATH_MAX], work_bits[FZN_SPOOL_FILE_PATH_MAX];
	char path[FZN_SPOOL_FILE_PATH_MAX], bits[FZN_SPOOL_FILE_PATH_MAX];
	fzn_spool_file_t file;
	fzn_spool_t spool;
	const fzn_spool_ops_t *ops;
	fzn_note_err_t err;
	int n, m;

	if (!shelf || !text || !ref)
		return FZN_NODE_SHELF_ERR_MALFORMED;
	n = snprintf(work, sizeof(work), "%s/put", shelf->dir);
	m = snprintf(work_bits, sizeof(work_bits), "%s/put.bits", shelf->dir);
	if (n <= 0 || (size_t)n >= sizeof(work) || m <= 0 || (size_t)m >= sizeof(work_bits))
		return FZN_NODE_SHELF_ERR_MALFORMED;
	/* A WORKING NAME LEFT BY A CRASH is replaced, never resumed: it is a
	 * blob under a key nobody kept. */
	(void)remove(work);
	(void)remove(work_bits);
	file.fd = -1;
	ops = fzn_spool_file_open(&file, work);
	if (!ops)
		return FZN_NODE_SHELF_ERR_STORE;
	err = fzn_note_text_seal(shelf->hash, shelf->aead, shelf->rng, text, len, ops, present,
	                         sizeof(present), &spool, ref);
	if (err != FZN_NOTE_OK) {
		fzn_spool_file_close(&file);
		(void)remove(work);
		return err == FZN_NOTE_ERR_STORE ? FZN_NODE_SHELF_ERR_STORE : FZN_NODE_SHELF_ERR_TEXT;
	}
	if (fzn_spool_file_checkpoint(&file, &spool) != FZN_SPOOL_OK) {
		fzn_spool_file_close(&file);
		return FZN_NODE_SHELF_ERR_STORE;
	}
	fzn_spool_file_close(&file);
	/* THE LENGTH, THEN THE LEAVES, THEN THE SIDECAR: a blob is held from
	 * the moment its sidecar appears under its root, so that is last. */
	if (!path_of(shelf, ref->root, "", path) || !path_of(shelf, ref->root, ".bits", bits)
	    || !write_length(shelf, ref->root, len) || rename(work, path) != 0
	    || rename(work_bits, bits) != 0)
		return FZN_NODE_SHELF_ERR_STORE;
	return FZN_NODE_SHELF_OK;
}

fzn_node_shelf_err_t fzn_node_shelf_held(const fzn_node_shelf_t *shelf,
                                         const uint8_t root[FZN_BLOB_HASH_LEN],
                                         uint64_t *length)
{
	static held_t h;
	fzn_node_shelf_err_t err;

	if (!shelf || !root || !length)
		return FZN_NODE_SHELF_ERR_MALFORMED;
	err = open_whole(shelf, root, &h);
	if (err != FZN_NODE_SHELF_OK)
		return err;
	*length = h.length;
	fzn_spool_file_close(&h.file);
	return FZN_NODE_SHELF_OK;
}

fzn_node_shelf_err_t fzn_node_shelf_open(const fzn_node_shelf_t *shelf,
                                         const fzn_note_blob_ref_t *ref, uint8_t *out,
                                         size_t out_cap, size_t *out_len,
                                         fzn_note_err_t *text_err)
{
	static held_t h;
	fzn_node_shelf_err_t err;
	fzn_note_err_t terr;

	if (!shelf || !ref || !out || !out_len || !text_err)
		return FZN_NODE_SHELF_ERR_MALFORMED;
	*text_err = FZN_NOTE_OK;
	err = open_whole(shelf, ref->root, &h);
	if (err != FZN_NODE_SHELF_OK)
		return err;
	terr = fzn_note_text_open(shelf->hash, shelf->aead, &h.spool, ref, out, out_cap, out_len);
	fzn_spool_file_close(&h.file);
	if (terr != FZN_NOTE_OK) {
		*text_err = terr;
		return FZN_NODE_SHELF_ERR_TEXT;
	}
	return FZN_NODE_SHELF_OK;
}

/* ---- the server -------------------------------------------------------- */

static size_t say_absent(uint8_t *reply, size_t reply_cap)
{
	static const char ABSENT[] = "absent";

	if (reply_cap < sizeof(ABSENT) - 1u)
		return 0;
	memcpy(reply, ABSENT, sizeof(ABSENT) - 1u);
	return sizeof(ABSENT) - 1u;
}

static size_t answer_have(const fzn_node_shelf_t *shelf, const uint8_t root[FZN_BLOB_HASH_LEN],
                          uint8_t *reply, size_t reply_cap)
{
	static held_t h;
	/* THE COOKIE CARRIES NOTHING: the remote hop authenticated the asker
	 * under its session, so a spoofer cannot ask (shelf.h). */
	static const uint8_t cookie[FZN_MSG_COOKIE_LEN];
	fzn_spool_range_t all;
	size_t len = 0;

	if (open_whole(shelf, root, &h) != FZN_NODE_SHELF_OK)
		return say_absent(reply, reply_cap);
	all.first = 0;
	all.count = h.leaves;
	if (fzn_msg_have_encode(root, h.leaves, cookie, &all, 1u, reply, reply_cap, &len)
	    != FZN_MSG_OK)
		len = 0;
	fzn_spool_file_close(&h.file);
	return len;
}

static size_t answer_want(const fzn_node_shelf_t *shelf, const uint8_t *request,
                          size_t request_len, uint8_t *reply, size_t reply_cap)
{
	static held_t h;
	static uint8_t hashes[FZN_NOTE_TEXT_LEAVES_MAX][FZN_BLOB_HASH_LEN];
	static uint8_t leaves[FZN_NODE_SHELF_SPAN][FZN_BLOB_SEALED_MAX];
	const uint8_t *sealed[FZN_NODE_SHELF_SPAN];
	size_t sealed_len[FZN_NODE_SHELF_SPAN];
	uint8_t proof[FZN_MSG_MAX_PROOF * FZN_BLOB_HASH_LEN];
	uint8_t cookie[FZN_MSG_COOKIE_LEN], root[FZN_BLOB_HASH_LEN];
	uint8_t slot[FZN_BLOB_SEALED_MAX];
	uint64_t first = 0, count = 0, i, n;
	uint32_t transfer = 0;
	unsigned siblings = 0;
	size_t len = 0, got = 0;

	if (fzn_msg_want_parse(request, request_len, &transfer, cookie, root, &first, &count)
	    != FZN_MSG_OK)
		return 0;
	if (open_whole(shelf, root, &h) != FZN_NODE_SHELF_OK)
		return say_absent(reply, reply_cap);
	/* EVERY LEAF'S HASH, at its true length: the proof's siblings are
	 * hashes of leaves the asker did not ask for. */
	for (i = 0; i < h.leaves; i++)
		if (fzn_spool_read(&h.spool, i, slot, sizeof(slot), &got) != FZN_SPOOL_OK
		    || got < sealed_len_of(&h, i)
		    || fzn_blob_leaf_hash(shelf->hash, slot, sealed_len_of(&h, i), hashes[i])
		               != FZN_BLOB_OK)
			goto absent;
	/* THE LARGEST CANONICAL SPAN at `first` that the asker asked for, the
	 * shelf's span allows, and the reply holds -- halved until it fits. */
	n = fzn_blob_span_largest_at(h.leaves, first,
	                             count < FZN_NODE_SHELF_SPAN ? count : FZN_NODE_SHELF_SPAN);
	for (; n > 0u; n = fzn_blob_span_largest_at(h.leaves, first, n / 2u)) {
		fzn_msg_err_t err;

		for (i = 0; i < n; i++) {
			if (fzn_spool_read(&h.spool, first + i, leaves[i], sizeof(leaves[i]), &got)
			    != FZN_SPOOL_OK)
				goto absent;
			sealed[i] = leaves[i];
			sealed_len[i] = sealed_len_of(&h, first + i);
		}
		if (fzn_blob_span_proof_build(shelf->hash, (const uint8_t *)hashes, h.leaves, first,
		                              n, proof, sizeof(proof), &siblings)
		    != FZN_BLOB_OK)
			goto absent;
		err = fzn_msg_data_encode(transfer, first, n, proof, siblings, sealed, sealed_len,
		                          reply, reply_cap, &len);
		if (err == FZN_MSG_OK) {
			fzn_spool_file_close(&h.file);
			return len;
		}
		if (err != FZN_MSG_ERR_TOO_LARGE)
			break;
	}
absent:
	fzn_spool_file_close(&h.file);
	return say_absent(reply, reply_cap);
}

size_t fzn_node_shelf_answer(const fzn_node_shelf_t *shelf, const uint8_t *request,
                             size_t request_len, uint8_t *reply, size_t reply_cap)
{
	fzn_msg_type_t type;
	uint8_t root[FZN_BLOB_HASH_LEN];

	if (!shelf || !request || !reply
	    || fzn_msg_peek(request, request_len, &type) != FZN_MSG_OK)
		return 0;
	if (type == FZN_MSG_HAVE_QUERY) {
		if (fzn_msg_have_query_parse(request, request_len, root) != FZN_MSG_OK)
			return 0;
		return answer_have(shelf, root, reply, reply_cap);
	}
	if (type == FZN_MSG_WANT)
		return answer_want(shelf, request, request_len, reply, reply_cap);
	/* A HAVE or a DATA is an answer, not a question. */
	return 0;
}

size_t fzn_node_shelf_answer_permitted(const fzn_node_shelf_t *shelf,
                                       fzn_node_shelf_permit_t permit, void *permit_ctx,
                                       const uint8_t *request, size_t request_len,
                                       uint8_t *reply, size_t reply_cap)
{
	fzn_msg_type_t type;
	uint8_t root[FZN_BLOB_HASH_LEN], cookie[FZN_MSG_COOKIE_LEN];
	uint64_t first = 0, count = 0;
	uint32_t transfer = 0;

	if (!shelf || !permit || !request || !reply
	    || fzn_msg_peek(request, request_len, &type) != FZN_MSG_OK)
		return 0;
	if (type == FZN_MSG_HAVE_QUERY) {
		if (fzn_msg_have_query_parse(request, request_len, root) != FZN_MSG_OK)
			return 0;
	} else if (type == FZN_MSG_WANT) {
		if (fzn_msg_want_parse(request, request_len, &transfer, cookie, root, &first, &count)
		    != FZN_MSG_OK)
			return 0;
	} else {
		return 0;
	}
	if (!permit(permit_ctx, root))
		return 0;
	return fzn_node_shelf_answer(shelf, request, request_len, reply, reply_cap);
}

static int wanted(const fzn_node_shelf_t *shelf, const uint8_t root[FZN_BLOB_HASH_LEN])
{
	size_t i;

	for (i = 0; i < FZN_NODE_SHELF_WANTS; i++)
		if (shelf->wants[i].live
		    && memcmp(shelf->wants[i].root, root, FZN_BLOB_HASH_LEN) == 0)
			return 1;
	return 0;
}

/* Remove `path`, and say whether it is gone: absent already counts. */
static int gone(const char *path)
{
	return remove(path) == 0 || errno == ENOENT;
}

fzn_node_shelf_err_t fzn_node_shelf_collect(fzn_node_shelf_t *shelf, fzn_node_shelf_keep_t keep,
                                            void *keep_ctx, size_t *kept, size_t *removed)
{
	DIR *dir;
	struct dirent *e;
	fzn_node_shelf_err_t err = FZN_NODE_SHELF_OK;

	if (!shelf || !keep || !kept || !removed)
		return FZN_NODE_SHELF_ERR_MALFORMED;
	*kept = 0;
	*removed = 0;
	dir = opendir(shelf->dir);
	if (!dir)
		return FZN_NODE_SHELF_ERR_STORE;
	while ((e = readdir(dir)) != NULL) {
		char bits[FZN_SPOOL_FILE_PATH_MAX], leaves[FZN_SPOOL_FILE_PATH_MAX];
		char len[FZN_SPOOL_FILE_PATH_MAX];
		uint8_t root[FZN_BLOB_HASH_LEN];

		/* ONE NAME A BLOB: its sidecar, `<root hex>.bits`. Anything else
		 * in the directory is not this function's. */
		if (strlen(e->d_name) != ROOT_HEX + 5u || strcmp(e->d_name + ROOT_HEX, ".bits") != 0
		    || !from_hex((const uint8_t *)e->d_name, ROOT_HEX, root, sizeof(root)))
			continue;
		/* A TEXT ASKED FOR is kept though no note names it yet: the note
		 * naming it is what made the want. */
		if (wanted(shelf, root) || keep(keep_ctx, root)) {
			(*kept)++;
			continue;
		}
		if (!path_of(shelf, root, ".bits", bits) || !path_of(shelf, root, "", leaves)
		    || !path_of(shelf, root, ".len", len) || !gone(bits) || !gone(leaves)
		    || !gone(len)) {
			err = FZN_NODE_SHELF_ERR_STORE;
			break;
		}
		(*removed)++;
	}
	(void)closedir(dir);
	return err;
}

size_t fzn_node_shelf_remote(void *ctx, const uint8_t *request, size_t request_len,
                             uint8_t *reply, size_t reply_cap)
{
	return fzn_node_shelf_answer((const fzn_node_shelf_t *)ctx, request, request_len, reply,
	                             reply_cap);
}

/* ---- the fetcher ------------------------------------------------------- */

static fzn_node_shelf_err_t fetch_spans(fzn_node_shelf_t *shelf, held_t *h,
                                        const uint8_t root[FZN_BLOB_HASH_LEN],
                                        fzn_node_shelf_ask_t ask, void *ask_ctx)
{
	static uint8_t reply[FZN_NODE_SHELF_REPLY_MAX];
	fzn_spool_range_t ranges[1];
	uint8_t request[FZN_MSG_WANT_LEN];
	uint8_t cookie[FZN_MSG_COOKIE_LEN], their_root[FZN_BLOB_HASH_LEN];
	uint64_t their_leaves = 0, round;
	size_t len = 0, reply_len = 0, offered = 0;
	fzn_msg_type_t type;

	/* DO YOU HAVE IT: one question, so a peer holding nothing costs one
	 * round trip and not a WANT per span. */
	if (fzn_msg_have_query_encode(root, request, sizeof(request), &len) != FZN_MSG_OK)
		return FZN_NODE_SHELF_ERR_MALFORMED;
	if (!ask(ask_ctx, request, len, reply, sizeof(reply), &reply_len))
		return FZN_NODE_SHELF_ERR_NO_ANSWER;
	if (fzn_msg_peek(reply, reply_len, &type) != FZN_MSG_OK)
		return FZN_NODE_SHELF_ERR_ABSENT;
	if (type != FZN_MSG_HAVE
	    || fzn_msg_have_parse(reply, reply_len, their_root, &their_leaves, cookie, ranges, 1u,
	                          &offered)
	               != FZN_MSG_OK
	    || memcmp(their_root, root, FZN_BLOB_HASH_LEN) != 0 || their_leaves != h->leaves)
		return FZN_NODE_SHELF_ERR_SHAPE;

	/* ONE SPAN A ROUND, at most one round a leaf: every DATA places at
	 * least one leaf or ends the fetch, so this bound is never the one
	 * that stops it. */
	for (round = 0; round < h->leaves; round++) {
		const uint8_t *proof = NULL, *sealed[FZN_NODE_SHELF_SPAN];
		size_t sealed_len[FZN_NODE_SHELF_SPAN], planned = 0;
		uint64_t first = 0, count = 0, i;
		uint32_t transfer = 0;
		unsigned siblings = 0;

		if (fzn_spool_plan_want(&h->spool, 0, FZN_NODE_SHELF_SPAN, ranges, 1u, &planned)
		    != FZN_SPOOL_OK)
			return FZN_NODE_SHELF_ERR_STORE;
		if (planned == 0u)
			return FZN_NODE_SHELF_OK;
		if (fzn_msg_want_encode((uint32_t)round, cookie, root, ranges[0].first,
		                        ranges[0].count, request, sizeof(request), &len)
		    != FZN_MSG_OK)
			return FZN_NODE_SHELF_ERR_MALFORMED;
		if (!ask(ask_ctx, request, len, reply, sizeof(reply), &reply_len))
			return FZN_NODE_SHELF_ERR_NO_ANSWER;
		if (fzn_msg_peek(reply, reply_len, &type) != FZN_MSG_OK)
			return FZN_NODE_SHELF_ERR_ABSENT;
		if (type != FZN_MSG_DATA
		    || fzn_msg_data_parse(reply, reply_len, &transfer, &first, &count, &proof,
		                          &siblings, sealed, sealed_len, FZN_NODE_SHELF_SPAN)
		               != FZN_MSG_OK
		    || transfer != (uint32_t)round || first != ranges[0].first || count == 0u
		    || count > ranges[0].count)
			return FZN_NODE_SHELF_ERR_SHAPE;
		/* EVERY LEAF AT THE LENGTH THE NOTE'S LENGTH GIVES IT. The proof
		 * binds the lengths the peer sent, so a span proving at these
		 * lengths proves the length this host wrote down -- which is
		 * what it will hash at when it serves the text on. */
		for (i = 0; i < count; i++)
			if (sealed_len[i] != sealed_len_of(h, first + i))
				return FZN_NODE_SHELF_ERR_UNVERIFIED;
		if (fzn_spool_place_span(&h->spool, shelf->hash, first, count, sealed, sealed_len,
		                         proof, siblings)
		    != FZN_SPOOL_OK)
			return FZN_NODE_SHELF_ERR_UNVERIFIED;
		if (fzn_spool_file_checkpoint(&h->file, &h->spool) != FZN_SPOOL_OK)
			return FZN_NODE_SHELF_ERR_STORE;
	}
	return fzn_spool_complete(&h->spool) ? FZN_NODE_SHELF_OK : FZN_NODE_SHELF_ERR_SHAPE;
}

fzn_node_shelf_err_t fzn_node_shelf_fetch(fzn_node_shelf_t *shelf,
                                          const uint8_t root[FZN_BLOB_HASH_LEN], uint64_t length,
                                          fzn_node_shelf_ask_t ask, void *ask_ctx)
{
	static held_t h;
	char path[FZN_SPOOL_FILE_PATH_MAX], len_path[FZN_SPOOL_FILE_PATH_MAX];
	const fzn_spool_ops_t *ops;
	fzn_node_shelf_err_t err;
	uint64_t have = 0, before = 0;
	int had_length;

	if (!shelf || !root || !ask)
		return FZN_NODE_SHELF_ERR_MALFORMED;
	memset(&h, 0, sizeof(h));
	h.file.fd = -1;
	if (!geometry(length, &h.leaves, &h.last))
		return FZN_NODE_SHELF_ERR_MALFORMED;
	if (fzn_node_shelf_held(shelf, root, &have) == FZN_NODE_SHELF_OK)
		return have == length ? FZN_NODE_SHELF_OK : FZN_NODE_SHELF_ERR_MALFORMED;
	h.length = length;
	if (!path_of(shelf, root, "", path) || !path_of(shelf, root, ".len", len_path))
		return FZN_NODE_SHELF_ERR_MALFORMED;
	had_length = read_length(len_path, &before);
	ops = fzn_spool_file_open(&h.file, path);
	if (!ops)
		return FZN_NODE_SHELF_ERR_STORE;
	/* RESUMED, so a fetch cut off part way asks only for the rest. */
	(void)fzn_spool_file_resume(&h.file, root, h.leaves, h.present, sizeof(h.present));
	if (fzn_spool_open(&h.spool, root, h.leaves, h.present, sizeof(h.present), ops)
	    != FZN_SPOOL_OK) {
		fzn_spool_file_close(&h.file);
		return FZN_NODE_SHELF_ERR_STORE;
	}
	/* A LAST LEAF ALREADY HERE PROVED THE LENGTH IT WAS PLACED AT, so a
	 * note naming another length for the same root is wrong, and writing
	 * it down would have this host serve proofs that do not verify. A
	 * length written by a fetch that never placed the last leaf proved
	 * nothing and is replaced. */
	if (had_length && before != length && fzn_spool_has(&h.spool, h.leaves - 1u)) {
		fzn_spool_file_close(&h.file);
		return FZN_NODE_SHELF_ERR_MALFORMED;
	}
	if (!write_length(shelf, root, length)) {
		fzn_spool_file_close(&h.file);
		return FZN_NODE_SHELF_ERR_STORE;
	}
	err = fetch_spans(shelf, &h, root, ask, ask_ctx);
	if (fzn_spool_file_checkpoint(&h.file, &h.spool) != FZN_SPOOL_OK
	    && err == FZN_NODE_SHELF_OK)
		err = FZN_NODE_SHELF_ERR_STORE;
	fzn_spool_file_close(&h.file);
	return err;
}

fzn_node_shelf_err_t fzn_node_shelf_want(fzn_node_shelf_t *shelf,
                                         const uint8_t root[FZN_BLOB_HASH_LEN], uint64_t length)
{
	uint64_t leaves = 0, have = 0;
	size_t last = 0, i, free_slot = FZN_NODE_SHELF_WANTS;

	if (!shelf || !root || !geometry(length, &leaves, &last))
		return FZN_NODE_SHELF_ERR_MALFORMED;
	if (fzn_node_shelf_held(shelf, root, &have) == FZN_NODE_SHELF_OK)
		return have == length ? FZN_NODE_SHELF_OK : FZN_NODE_SHELF_ERR_MALFORMED;
	for (i = 0; i < FZN_NODE_SHELF_WANTS; i++) {
		if (shelf->wants[i].live
		    && memcmp(shelf->wants[i].root, root, FZN_BLOB_HASH_LEN) == 0) {
			shelf->wants[i].length = length;
			return FZN_NODE_SHELF_OK;
		}
		if (!shelf->wants[i].live && free_slot == FZN_NODE_SHELF_WANTS)
			free_slot = i;
	}
	if (free_slot == FZN_NODE_SHELF_WANTS)
		return FZN_NODE_SHELF_ERR_FULL;
	memcpy(shelf->wants[free_slot].root, root, FZN_BLOB_HASH_LEN);
	shelf->wants[free_slot].length = length;
	shelf->wants[free_slot].live = 1;
	shelf->fresh = 1;
	return FZN_NODE_SHELF_OK;
}

size_t fzn_node_shelf_fetch_wants(fzn_node_shelf_t *shelf, fzn_node_shelf_ask_t ask,
                                  void *ask_ctx)
{
	size_t i, done = 0;

	if (!shelf || !ask)
		return 0;
	for (i = 0; i < FZN_NODE_SHELF_WANTS; i++) {
		fzn_node_shelf_want_t *w = &shelf->wants[i];

		if (w->live && fzn_node_shelf_fetch(shelf, w->root, w->length, ask, ask_ctx)
		                       == FZN_NODE_SHELF_OK) {
			w->live = 0;
			done++;
		}
	}
	return done;
}

/* ---- the verbs --------------------------------------------------------- */

static size_t answer(char *reply, size_t cap, fzn_reply_t kind, const char *detail)
{
	size_t len = 0;

	if (fzn_reply_compose((uint8_t *)reply, cap, &len, kind, (const uint8_t *)detail,
	                      detail ? strlen(detail) : 0u)
	    != FZN_COMPOSE_OK)
		return 0;
	return len;
}

/* A reference from its hex: the bytes `notes/note.h` lays out, read the way a
 * note's own text field is read. */
static int ref_from_hex(const uint8_t *text, size_t text_len, fzn_note_blob_ref_t *ref)
{
	uint8_t bytes[FZN_NOTE_BLOB_REF_LEN];
	fzn_note_t note;

	if (!from_hex(text, text_len, bytes, sizeof(bytes)))
		return 0;
	memset(&note, 0, sizeof(note));
	note.flags = FZN_NOTE_FLAG_TEXT_IS_BLOB;
	note.text = bytes;
	note.text_len = sizeof(bytes);
	return fzn_note_blob_ref(&note, ref) == FZN_NOTE_OK && ref->length > 0u;
}

static size_t put_text(fzn_node_shelf_t *shelf, const uint8_t *arg, size_t arg_len, char *reply,
                       size_t cap)
{
	static uint8_t text[FZN_NOTE_TEXT_MAX + 1u];
	char path[FZN_SPOOL_FILE_PATH_MAX], hex[REF_HEX + 1u];
	uint8_t bytes[FZN_NOTE_BLOB_REF_LEN];
	fzn_note_blob_ref_t ref;
	fzn_node_shelf_err_t err;
	size_t len;
	FILE *f;

	if (arg_len == 0u || arg_len >= sizeof(path) || memchr(arg, '\0', arg_len))
		return answer(reply, cap, FZN_REPLY_MALFORMED, "put text PATH");
	memcpy(path, arg, arg_len);
	path[arg_len] = '\0';
	f = fopen(path, "rb");
	if (!f)
		return answer(reply, cap, FZN_REPLY_ERROR, "cannot read that file");
	len = fread(text, 1u, sizeof(text), f);
	(void)fclose(f);
	/* ONE BYTE PAST THE BOUND was read, so a file at the bound and a file
	 * past it are told apart. */
	if (len == 0u || len > FZN_NOTE_TEXT_MAX)
		return answer(reply, cap, FZN_REPLY_ERROR, "empty, or past 256 KiB");
	err = fzn_node_shelf_put(shelf, text, len, &ref);
	if (err != FZN_NODE_SHELF_OK)
		return answer(reply, cap, FZN_REPLY_ERROR, fzn_node_shelf_err_str(err));
	if (fzn_note_blob_ref_write(&ref, bytes) != FZN_NOTE_OK)
		return answer(reply, cap, FZN_REPLY_ERROR, "no reference");
	to_hex(bytes, sizeof(bytes), hex);
	return answer(reply, cap, FZN_REPLY_OK, hex);
}

static size_t get_text(const fzn_node_shelf_t *shelf, const fzn_note_blob_ref_t *ref,
                       char *reply, size_t cap)
{
	static uint8_t text[FZN_NOTE_TEXT_MAX];
	fzn_note_err_t text_err = FZN_NOTE_OK;
	fzn_node_shelf_err_t err;
	char detail[48];
	size_t len = 0;

	err = fzn_node_shelf_open(shelf, ref, text, sizeof(text), &len, &text_err);
	if (err == FZN_NODE_SHELF_ERR_ABSENT)
		return answer(reply, cap, FZN_REPLY_OK, "pending");
	if (err == FZN_NODE_SHELF_ERR_TEXT)
		return answer(reply, cap, FZN_REPLY_ERROR, fzn_note_err_str(text_err));
	if (err != FZN_NODE_SHELF_OK)
		return answer(reply, cap, FZN_REPLY_ERROR, fzn_node_shelf_err_str(err));
	(void)snprintf(detail, sizeof(detail), "here %zu", len);
	return answer(reply, cap, FZN_REPLY_OK, detail);
}

size_t fzn_node_shelf_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                            char *reply, size_t reply_cap)
{
	static const uint8_t TEXT[] = "text ";
	fzn_node_shelf_t *shelf = (fzn_node_shelf_t *)ctx;
	const uint8_t *arg;
	size_t arg_len;
	fzn_note_blob_ref_t ref;
	fzn_node_shelf_err_t err;

	if (!shelf || !request || !reply || !request->arg
	    || request->arg_len < sizeof(TEXT) - 1u
	    || memcmp(request->arg, TEXT, sizeof(TEXT) - 1u) != 0)
		return 0;
	if (request->parsed != FZN_VERB_PUT && request->parsed != FZN_VERB_FETCH
	    && request->parsed != FZN_VERB_GET)
		return 0;
	if (origin != FZN_ORIGIN_SAME_USER)
		return answer(reply, reply_cap, FZN_REPLY_DENIED, "a text needs this node's own user");
	arg = request->arg + sizeof(TEXT) - 1u;
	arg_len = request->arg_len - (sizeof(TEXT) - 1u);
	if (request->parsed == FZN_VERB_PUT)
		return put_text(shelf, arg, arg_len, reply, reply_cap);
	if (!ref_from_hex(arg, arg_len, &ref))
		return answer(reply, reply_cap, FZN_REPLY_MALFORMED, "a reference, in hex");
	if (request->parsed == FZN_VERB_GET)
		return get_text(shelf, &ref, reply, reply_cap);
	err = fzn_node_shelf_want(shelf, ref.root, ref.length);
	if (err != FZN_NODE_SHELF_OK)
		return answer(reply, reply_cap, FZN_REPLY_ERROR, fzn_node_shelf_err_str(err));
	return answer(reply, reply_cap, FZN_REPLY_OK, NULL);
}
