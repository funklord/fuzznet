/* See piece_buckets.h. */

#define _POSIX_C_SOURCE 200809L

#include "piece_buckets.h"

#include "pieces.h"
#include "../chunk/erasure.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PATH_MAX_ 1024u

static const char HEX[] = "0123456789abcdef";

static void hex_of(const uint8_t *in, size_t n, char *out)
{
	size_t i;

	for (i = 0; i < n; i++) {
		out[2u * i] = HEX[in[i] >> 4];
		out[(2u * i) + 1u] = HEX[in[i] & 15u];
	}
	out[2u * n] = '\0';
}

int fzn_piece_buckets_init(fzn_piece_buckets_t *pb, const fzn_buckets_t *b, const char *dir,
                           const fzn_hash_ops_t *hash, const uint8_t self[32])
{
	size_t n;

	if (!pb || !b || !dir || !hash || !hash->hash || !self)
		return 0;
	n = strlen(dir);
	if (n == 0u || n >= sizeof(pb->dir))
		return 0;
	memset(pb, 0, sizeof(*pb));
	pb->b = b;
	memcpy(pb->dir, dir, n + 1u);
	pb->hash = hash;
	memcpy(pb->self, self, 32u);
	return 1;
}

void fzn_piece_buckets_close(fzn_piece_buckets_t *pb)
{
	if (!pb)
		return;
	free(pb->staging);
	pb->staging = NULL;
	pb->staging_cap = pb->staged = 0;
}

/* ---- placing ------------------------------------------------------------------ */

int fzn_piece_buckets_rank(const fzn_hash_ops_t *hash, const uint8_t id[FZN_BUCKETS_ID_LEN],
                           const uint8_t (*hosts)[32], size_t n, size_t *order)
{
	uint8_t scores[FZN_PIECE_BUCKETS_HOSTS_MAX][32], in[FZN_BUCKETS_ID_LEN + 32u];
	size_t i, j;

	if (!hash || !hash->hash || !id || !hosts || !order || n > FZN_PIECE_BUCKETS_HOSTS_MAX)
		return 0;
	for (i = 0; i < n; i++) {
		memcpy(in, id, FZN_BUCKETS_ID_LEN);
		memcpy(in + FZN_BUCKETS_ID_LEN, hosts[i], 32u);
		if (!hash->hash(hash->ctx, scores[i], 32u, in, sizeof(in)))
			return 0;
		order[i] = i;
	}
	/* DESCENDING BY SCORE, a tie by the key: an insertion sort, n is a
	 * handful of hosts. */
	for (i = 1; i < n; i++)
		for (j = i; j > 0; j--) {
			size_t a = order[j - 1u], c = order[j];
			int by = memcmp(scores[a], scores[c], 32u);

			if (by > 0 || (by == 0 && memcmp(hosts[a], hosts[c], 32u) <= 0))
				break;
			order[j - 1u] = c;
			order[j] = a;
		}
	return 1;
}

/* A piece's ref and path: `p/IDHEX.INDEX`, `DIR/IDHEX.INDEX.piece`. */
static int piece_ref(const fzn_piece_buckets_t *pb, const uint8_t id[FZN_BUCKETS_ID_LEN],
                     unsigned index, char ref[FZN_BUCKETS_REF_MAX + 1u], char path[PATH_MAX_])
{
	char hex[2u * FZN_BUCKETS_ID_LEN + 1u];
	int k;

	hex_of(id, FZN_BUCKETS_ID_LEN, hex);
	k = snprintf(ref, FZN_BUCKETS_REF_MAX + 1u, "p/%s.%u", hex, index);
	if (k <= 0 || k > (int)FZN_BUCKETS_REF_MAX)
		return 0;
	k = snprintf(path, PATH_MAX_, "%s/%s.%u.piece", pb->dir, hex, index);
	return k > 0 && (size_t)k < PATH_MAX_;
}

/* The whole file at `path` into a buffer this allocates, `*len` bytes. */
static uint8_t *file_bytes(const char *path, size_t *len)
{
	struct stat st;
	uint8_t *out;
	size_t got = 0;
	ssize_t r;
	int fd = open(path, O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		return NULL;
	if (fstat(fd, &st) != 0 || st.st_size <= 0
	    || (uint64_t)st.st_size > FZN_BUCKETS_LARGE_MAX
	    || (out = malloc((size_t)st.st_size)) == NULL) {
		(void)close(fd);
		return NULL;
	}
	while (got < (size_t)st.st_size && (r = read(fd, out + got, (size_t)st.st_size - got)) > 0)
		got += (size_t)r;
	(void)close(fd);
	if (got != (size_t)st.st_size) {
		free(out);
		return NULL;
	}
	*len = got;
	return out;
}

int fzn_piece_buckets_place(fzn_piece_buckets_t *pb, const uint8_t id[FZN_BUCKETS_ID_LEN],
                            uint32_t month, const uint8_t (*keepers)[32], size_t n,
                            size_t *placed)
{
	size_t i;

	if (placed)
		*placed = 0;
	if (!pb || !pb->b || !id || !keepers || n > FZN_ERASURE_PIECES_MAX)
		return 0;
	for (i = 0; i < n; i++) {
		char ref[FZN_BUCKETS_REF_MAX + 1u], path[PATH_MAX_];
		uint8_t piece_id[FZN_BUCKETS_ID_LEN], *bytes;
		size_t len = 0;
		int added = 0, ok;

		if (!piece_ref(pb, id, (unsigned)i, ref, path))
			return 0;
		bytes = file_bytes(path, &len);
		if (!bytes)
			return 0;
		ok = fzn_buckets_id(pb->hash, bytes, len, piece_id)
		     && fzn_buckets_add_ref(pb->b, FZN_BUCKETS_PIECES, keepers[i], month, piece_id,
		                            len, (const uint8_t *)ref, strlen(ref), &added)
		                == FZN_BUCKETS_OK;
		free(bytes);
		if (!ok)
			return 0;
		if (placed && added)
			(*placed)++;
	}
	return 1;
}

/* ---- reading ------------------------------------------------------------------ */

/* A REF, read: `p/IDHEX.INDEX`, its path into `path`. 0 for anything else. */
static int ref_path(const fzn_piece_buckets_t *pb, const uint8_t *ref, size_t ref_len,
                    char path[PATH_MAX_])
{
	char r[FZN_BUCKETS_REF_MAX + 1u];
	unsigned index = 0;
	size_t i;
	int k;

	if (ref_len < 2u + 64u + 2u || ref_len > 2u + 64u + 3u || ref[0] != 'p' || ref[1] != '/'
	    || ref[66] != '.')
		return 0;
	memcpy(r, ref, ref_len);
	r[ref_len] = '\0';
	for (i = 2; i < 66u; i++)
		if (!r[i] || !strchr(HEX, r[i]))
			return 0;
	for (i = 67; i < ref_len; i++) {
		if (r[i] < '0' || r[i] > '9')
			return 0;
		index = index * 10u + (unsigned)(r[i] - '0');
	}
	if (index >= FZN_ERASURE_PIECES_MAX || (ref_len == 69u && r[67] == '0'))
		return 0;
	r[66] = '\0';
	k = snprintf(path, PATH_MAX_, "%s/%s.%u.piece", pb->dir, r + 2, index);
	return k > 0 && (size_t)k < PATH_MAX_;
}

static int item_read(void *ctx, const uint8_t *ref, size_t ref_len, uint64_t offset,
                     uint8_t *out, size_t n)
{
	fzn_piece_buckets_t *pb = (fzn_piece_buckets_t *)ctx;
	char path[PATH_MAX_];
	int fd;

	if (!pb || !out || !ref_path(pb, ref, ref_len, path))
		return 0;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	while (n) {
		ssize_t got = pread(fd, out, n, (off_t)offset);

		if (got <= 0) {
			(void)close(fd);
			return 0;
		}
		out += got;
		offset += (uint64_t)got;
		n -= (size_t)got;
	}
	return close(fd) == 0;
}

/* ---- keeping ------------------------------------------------------------------ */

/* KEEP `item`, a piece placed on `subject`: only one placed on this host,
 * and only a piece's shape -- kept under its own name and taken. */
static fzn_node_apply_outcome_t keep(fzn_piece_buckets_t *pb, const uint8_t subject[32],
                                     uint32_t month, const uint8_t *item, size_t len,
                                     const uint8_t id[FZN_BUCKETS_ID_LEN])
{
	char ref[FZN_BUCKETS_REF_MAX + 1u], path[PATH_MAX_];
	uint8_t of[FZN_BUCKETS_ID_LEN];
	unsigned index = 0;

	if (memcmp(subject, pb->self, 32u) != 0)
		return FZN_NODE_APPLY_REFUSED;
	switch (fzn_pieces_keep(pb->dir, item, len, of, &index)) {
	case FZN_PIECES_OK:
		break;
	case FZN_PIECES_ERR_FILE:
		return FZN_NODE_APPLY_NOT_SAVED;
	default:
		return FZN_NODE_APPLY_REFUSED;
	}
	if (!piece_ref(pb, of, index, ref, path))
		return FZN_NODE_APPLY_REFUSED;
	return fzn_buckets_add_ref(pb->b, FZN_BUCKETS_PIECES, subject, month, id, len,
	                           (const uint8_t *)ref, strlen(ref), NULL)
	                       == FZN_BUCKETS_OK
	               ? FZN_NODE_APPLY_APPLIED
	               : FZN_NODE_APPLY_NOT_SAVED;
}

static fzn_node_apply_outcome_t item_file(void *ctx, const uint8_t subject[FZN_PUBKEY_LEN],
                                          uint32_t month, const uint8_t *item, size_t len)
{
	fzn_piece_buckets_t *pb = (fzn_piece_buckets_t *)ctx;
	uint8_t id[FZN_BUCKETS_ID_LEN];

	if (!pb || !fzn_buckets_id(pb->hash, item, len, id))
		return FZN_NODE_APPLY_REFUSED;
	return keep(pb, subject, month, item, len, id);
}

static int item_stage(void *ctx, const uint8_t id[FZN_BUCKETS_ID_LEN], uint64_t total,
                      uint64_t offset, const uint8_t *bytes, size_t n)
{
	fzn_piece_buckets_t *pb = (fzn_piece_buckets_t *)ctx;

	if (!pb || total == 0u || total > FZN_BUCKETS_LARGE_MAX)
		return 0;
	/* A PART AT 0 BEGINS AN ITEM afresh, whatever was staged. */
	if (offset == 0u) {
		if (pb->staging_cap < total) {
			uint8_t *grown = realloc(pb->staging, (size_t)total);

			if (!grown)
				return 0;
			pb->staging = grown;
			pb->staging_cap = (size_t)total;
		}
		memcpy(pb->stage_id, id, FZN_BUCKETS_ID_LEN);
		pb->stage_total = total;
		pb->staged = 0;
	}
	if (memcmp(pb->stage_id, id, FZN_BUCKETS_ID_LEN) != 0 || total != pb->stage_total
	    || offset != pb->staged || n > total - offset)
		return 0;
	memcpy(pb->staging + offset, bytes, n);
	pb->staged += n;
	return 1;
}

static fzn_node_apply_outcome_t item_finish(void *ctx, const uint8_t subject[FZN_PUBKEY_LEN],
                                            uint32_t month, const uint8_t id[FZN_BUCKETS_ID_LEN],
                                            uint64_t total)
{
	fzn_piece_buckets_t *pb = (fzn_piece_buckets_t *)ctx;
	uint8_t got[FZN_BUCKETS_ID_LEN];

	if (!pb || pb->staged != total || pb->stage_total != total
	    || memcmp(pb->stage_id, id, FZN_BUCKETS_ID_LEN) != 0
	    || !fzn_buckets_id(pb->hash, pb->staging, pb->staged, got)
	    || memcmp(got, id, FZN_BUCKETS_ID_LEN) != 0)
		return FZN_NODE_APPLY_REFUSED;
	pb->staged = 0;
	return keep(pb, subject, month, pb->staging, (size_t)total, id);
}

/* ---- wanted -------------------------------------------------------------------- */

/* THE PIECES PLACED ON THIS HOST, and no others. */
static int item_wanted(void *ctx, const uint8_t subject[FZN_PUBKEY_LEN], uint32_t month)
{
	fzn_piece_buckets_t *pb = (fzn_piece_buckets_t *)ctx;

	(void)month;
	return pb && memcmp(subject, pb->self, 32u) == 0;
}

void fzn_piece_buckets_filer(fzn_piece_buckets_t *pb, fzn_reconcile_filer_t *out)
{
	if (!out)
		return;
	memset(out, 0, sizeof(*out));
	out->file = item_file;
	out->wanted = item_wanted;
	out->ctx = pb;
	out->stage = item_stage;
	out->finish = item_finish;
	out->read = item_read;
}
