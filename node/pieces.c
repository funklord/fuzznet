#define _POSIX_C_SOURCE 200809L

#include "pieces.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../chunk/erasure.h"
#include "../wire/bytes.h"

const char *fzn_pieces_err_str(fzn_pieces_err_t err)
{
	switch (err) {
	case FZN_PIECES_OK:
		return "ok";
	case FZN_PIECES_ERR_MALFORMED:
		return "malformed";
	case FZN_PIECES_ERR_FILE:
		return "a piece's file would not be made, written or read";
	case FZN_PIECES_ERR_TOO_FEW:
		return "fewer pieces than it takes to rebuild";
	case FZN_PIECES_ERR_NO_MATCH:
		return "no set of the pieces rebuilds the item";
	}
	return "unknown";
}

/* `chunk/piece.situ`'s offsets. */
#define OFF_VERSION 0u
#define OFF_KIND 1u
#define OFF_ID 2u
#define OFF_HOST 34u
#define OFF_LEN 66u
#define OFF_K 74u
#define OFF_M 75u
#define OFF_INDEX 76u
#define OFF_KEEPER 77u
#define OFF_PIECE_LEN 109u
#define LARGE_MAX (64u * 1024u * 1024u)
#define PATH_MAX_ 640u

static const char HEX[] = "0123456789abcdef";

/* A piece's path: `dir/IDHEX.INDEX.piece`; 0 when it will not fit. */
static int piece_path(char *out, size_t cap, const char *dir,
                      const uint8_t id[FZN_BUCKETS_ID_LEN], unsigned index, const char *tail)
{
	char hex[2u * FZN_BUCKETS_ID_LEN + 1u];
	size_t i;
	int k;

	for (i = 0; i < FZN_BUCKETS_ID_LEN; i++) {
		hex[2u * i] = HEX[id[i] >> 4];
		hex[2u * i + 1u] = HEX[id[i] & 15u];
	}
	hex[2u * FZN_BUCKETS_ID_LEN] = '\0';
	k = snprintf(out, cap, "%s/%s.%u.piece%s", dir, hex, index, tail);
	return k > 0 && (size_t)k < cap;
}

/* `dir` made 0700 where absent, and each directory above it that is: a
 * host that never archived has no archive to make `pieces/` in. 0 on a
 * failure, or a name too long. */
static int make_dir(const char *dir)
{
	char path[PATH_MAX_];
	size_t i, n = strlen(dir);

	if (n == 0u || n >= sizeof(path))
		return 0;
	memcpy(path, dir, n + 1u);
	for (i = 1; i <= n; i++) {
		if (path[i] != '/' && path[i] != '\0')
			continue;
		path[i] = '\0';
		if (mkdir(path, 0700) != 0 && errno != EEXIST)
			return 0;
		if (i < n)
			path[i] = '/';
	}
	return 1;
}

fzn_pieces_err_t fzn_pieces_cut(const char *dir, uint8_t kind,
                                const uint8_t id[FZN_BUCKETS_ID_LEN], const uint8_t host[32],
                                const uint8_t (*keepers)[32], const uint8_t *item, size_t len,
                                unsigned k, unsigned m, size_t *written)
{
	size_t plen = fzn_erasure_piece_len(len, k);
	uint8_t head[FZN_PIECE_HEAD_LEN];
	char path[PATH_MAX_], tmp[PATH_MAX_];
	uint8_t *pieces;
	unsigned i;
	fzn_pieces_err_t err = FZN_PIECES_OK;

	if (!written)
		return FZN_PIECES_ERR_MALFORMED;
	*written = 0;
	if (!dir || !dir[0] || !id || !host || !keepers || !item || len == 0u || len > LARGE_MAX
	    || !k || !m || k + m > FZN_ERASURE_PIECES_MAX || kind > FZN_BUCKETS_LOGS)
		return FZN_PIECES_ERR_MALFORMED;
	pieces = malloc((size_t)(k + m) * plen);
	if (!pieces)
		return FZN_PIECES_ERR_FILE;
	if (fzn_erasure_encode(k, m, item, len, pieces) != FZN_ERASURE_OK) {
		free(pieces);
		return FZN_PIECES_ERR_MALFORMED;
	}
	if (!make_dir(dir)) {
		free(pieces);
		return FZN_PIECES_ERR_FILE;
	}
	head[OFF_VERSION] = 1u;
	head[OFF_KIND] = kind;
	memcpy(head + OFF_ID, id, FZN_BUCKETS_ID_LEN);
	memcpy(head + OFF_HOST, host, 32u);
	fzn_put_be64(head + OFF_LEN, (uint64_t)len);
	head[OFF_K] = (uint8_t)k;
	head[OFF_M] = (uint8_t)m;
	fzn_put_be32(head + OFF_PIECE_LEN, (uint32_t)plen);
	for (i = 0; i < k + m && err == FZN_PIECES_OK; i++) {
		int fd, ok;

		head[OFF_INDEX] = (uint8_t)i;
		memcpy(head + OFF_KEEPER, keepers[i], 32u);
		if (!piece_path(path, sizeof(path), dir, id, i, "")
		    || !piece_path(tmp, sizeof(tmp), dir, id, i, ".new")) {
			err = FZN_PIECES_ERR_MALFORMED;
			break;
		}
		fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
		if (fd < 0) {
			err = FZN_PIECES_ERR_FILE;
			break;
		}
		ok = write(fd, head, sizeof(head)) == (ssize_t)sizeof(head)
		     && write(fd, pieces + (size_t)i * plen, plen) == (ssize_t)plen;
		ok = fsync(fd) == 0 && ok;
		ok = (close(fd) == 0) && ok;
		if (!ok || rename(tmp, path) != 0) {
			(void)remove(tmp);
			err = FZN_PIECES_ERR_FILE;
			break;
		}
		(*written)++;
	}
	free(pieces);
	return err;
}

fzn_pieces_err_t fzn_pieces_held(const char *dir, const uint8_t id[FZN_BUCKETS_ID_LEN],
                                 uint32_t *mask)
{
	char path[PATH_MAX_];
	unsigned i;

	if (!mask)
		return FZN_PIECES_ERR_MALFORMED;
	*mask = 0;
	if (!dir || !id)
		return FZN_PIECES_ERR_MALFORMED;
	for (i = 0; i < FZN_ERASURE_PIECES_MAX; i++) {
		if (!piece_path(path, sizeof(path), dir, id, i, ""))
			return FZN_PIECES_ERR_MALFORMED;
		if (access(path, F_OK) == 0)
			*mask |= 1u << i;
	}
	return FZN_PIECES_OK;
}

/* WHETHER `head` IS A PIECE'S: its fields within their bounds and agreeing
 * with one another, as `chunk/piece.situ` says and the codec needs. The
 * kinds whose items are cut are the messages' and the logs'; a piece is
 * not cut again. */
static int head_ok(const uint8_t head[FZN_PIECE_HEAD_LEN])
{
	uint64_t len = fzn_get_be64(head + OFF_LEN);
	unsigned k = head[OFF_K], m = head[OFF_M];

	return head[OFF_VERSION] == 1u && head[OFF_KIND] <= FZN_BUCKETS_LOGS && len != 0u
	       && len <= LARGE_MAX && k && m && k + m <= FZN_ERASURE_PIECES_MAX
	       && head[OFF_INDEX] < k + m
	       && fzn_get_be32(head + OFF_PIECE_LEN) == fzn_erasure_piece_len((size_t)len, k);
}

fzn_pieces_err_t fzn_pieces_keep(const char *dir, const uint8_t *bytes, size_t len,
                                 uint8_t item_id[FZN_BUCKETS_ID_LEN], unsigned *index)
{
	char path[PATH_MAX_], tmp[PATH_MAX_];
	int fd, ok;

	if (!dir || !dir[0] || !bytes || !item_id || !index || len < FZN_PIECE_HEAD_LEN
	    || !head_ok(bytes)
	    || len - FZN_PIECE_HEAD_LEN != fzn_get_be32(bytes + OFF_PIECE_LEN))
		return FZN_PIECES_ERR_MALFORMED;
	memcpy(item_id, bytes + OFF_ID, FZN_BUCKETS_ID_LEN);
	*index = bytes[OFF_INDEX];
	if (!piece_path(path, sizeof(path), dir, item_id, *index, "")
	    || !piece_path(tmp, sizeof(tmp), dir, item_id, *index, ".new"))
		return FZN_PIECES_ERR_MALFORMED;
	if (!make_dir(dir))
		return FZN_PIECES_ERR_FILE;
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return FZN_PIECES_ERR_FILE;
	ok = write(fd, bytes, len) == (ssize_t)len;
	ok = fsync(fd) == 0 && ok;
	ok = (close(fd) == 0) && ok;
	if (!ok || rename(tmp, path) != 0) {
		(void)remove(tmp);
		return FZN_PIECES_ERR_FILE;
	}
	return FZN_PIECES_OK;
}

/* One piece's file read whole into a fresh buffer, its head checked against
 * its name and, once one is held, against the first; 0 when it does not
 * read or does not agree. */
static uint8_t *read_piece(const char *path, uint8_t kind, const uint8_t id[FZN_BUCKETS_ID_LEN],
                           unsigned index, uint8_t first[FZN_PIECE_HEAD_LEN], int *have_first)
{
	uint8_t head[FZN_PIECE_HEAD_LEN], *piece;
	size_t plen, got = 0;
	ssize_t r;
	int fd = open(path, O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		return NULL;
	if (read(fd, head, sizeof(head)) != (ssize_t)sizeof(head)) {
		(void)close(fd);
		return NULL;
	}
	plen = fzn_get_be32(head + OFF_PIECE_LEN);
	if (head[OFF_KIND] != kind || !head_ok(head)
	    || memcmp(head + OFF_ID, id, FZN_BUCKETS_ID_LEN) != 0 || head[OFF_INDEX] != index
	    || (*have_first && (memcmp(head, first, OFF_INDEX) != 0
	                        || memcmp(head + OFF_PIECE_LEN, first + OFF_PIECE_LEN, 4u) != 0))) {
		(void)close(fd);
		return NULL;
	}
	piece = malloc(plen);
	while (piece && got < plen && (r = read(fd, piece + got, plen - got)) > 0)
		got += (size_t)r;
	(void)close(fd);
	if (!piece || got != plen) {
		free(piece);
		return NULL;
	}
	if (!*have_first) {
		memcpy(first, head, sizeof(head));
		*have_first = 1;
	}
	return piece;
}

fzn_pieces_err_t fzn_pieces_item_len(const char *dir, const uint8_t id[FZN_BUCKETS_ID_LEN],
                                     size_t *len)
{
	uint8_t head[FZN_PIECE_HEAD_LEN];
	char path[PATH_MAX_];
	unsigned i;

	if (!len)
		return FZN_PIECES_ERR_MALFORMED;
	*len = 0;
	if (!dir || !id)
		return FZN_PIECES_ERR_MALFORMED;
	for (i = 0; i < FZN_ERASURE_PIECES_MAX; i++) {
		int fd;
		ssize_t got;

		if (!piece_path(path, sizeof(path), dir, id, i, ""))
			return FZN_PIECES_ERR_MALFORMED;
		fd = open(path, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			continue;
		got = read(fd, head, sizeof(head));
		(void)close(fd);
		/* THE LARGEST any piece's head says, sec 748: a head bent in the
		 * first piece read would otherwise size the room for every other,
		 * and the rebuild skips a lead whose item will not fit. */
		if (got == (ssize_t)sizeof(head) && head_ok(head)
		    && memcmp(head + OFF_ID, id, FZN_BUCKETS_ID_LEN) == 0 && head[OFF_INDEX] == i
		    && (size_t)fzn_get_be64(head + OFF_LEN) > *len)
			*len = (size_t)fzn_get_be64(head + OFF_LEN);
	}
	return *len ? FZN_PIECES_OK : FZN_PIECES_ERR_TOO_FEW;
}

/* WHETHER TWO HEADS DESCRIBE ONE CUT: all but the index, the keeper and the
 * piece itself, as `read_piece` holds a piece to its lead. */
static int same_cut(const uint8_t *a, const uint8_t *b)
{
	return memcmp(a, b, OFF_INDEX) == 0 && memcmp(a + OFF_PIECE_LEN, b + OFF_PIECE_LEN, 4u) == 0;
}

/* ONE LEAD'S REBUILD: every k of the pieces `held` that agree with `first`,
 * the first k first, until one rebuilds to the id. */
static fzn_pieces_err_t rebuild_led(uint8_t *const held[FZN_ERASURE_PIECES_MAX],
                                    const uint8_t first[FZN_PIECE_HEAD_LEN], unsigned n_held,
                                    const uint8_t id[FZN_BUCKETS_ID_LEN],
                                    const fzn_hash_ops_t *hash, uint8_t *out, size_t cap,
                                    size_t *len, uint32_t *used)
{
	const uint8_t *chosen[FZN_ERASURE_PIECES_MAX];
	uint8_t check[FZN_BUCKETS_ID_LEN];
	unsigned i, k = first[OFF_K], m = first[OFF_M];
	uint32_t mask, tries = 0;
	size_t item_len = (size_t)fzn_get_be64(first + OFF_LEN);

	if (n_held < k)
		return FZN_PIECES_ERR_TOO_FEW;
	if (item_len > cap)
		return FZN_PIECES_ERR_MALFORMED;
	/* A set of k is a mask of k bits among those held. Past 20 pieces the
	 * masks are too many to walk, and the first k held are the one set
	 * tried. */
	if (k + m > 20u) {
		for (mask = 0, i = 0, tries = 0; i < k + m && tries < k; i++)
			if (held[i]) {
				mask |= 1u << i;
				tries++;
			}
		for (i = 0; i < k + m; i++)
			chosen[i] = (mask >> i) & 1u ? held[i] : NULL;
		if (fzn_erasure_decode(k, m, chosen, item_len, out) == FZN_ERASURE_OK
		    && fzn_buckets_id(hash, out, item_len, check)
		    && memcmp(check, id, FZN_BUCKETS_ID_LEN) == 0) {
			*len = item_len;
			if (used)
				*used = mask;
			return FZN_PIECES_OK;
		}
		return FZN_PIECES_ERR_NO_MATCH;
	}
	for (mask = 0; mask < (1u << (k + m)) && tries < 1024u; mask++) {
		unsigned bits = 0;

		for (i = 0; i < k + m; i++)
			if ((mask >> i) & 1u)
				bits += held[i] != NULL ? 1u : 100u;
		if (bits != k)
			continue;
		tries++;
		for (i = 0; i < k + m; i++)
			chosen[i] = (mask >> i) & 1u ? held[i] : NULL;
		if (fzn_erasure_decode(k, m, chosen, item_len, out) == FZN_ERASURE_OK
		    && fzn_buckets_id(hash, out, item_len, check)
		    && memcmp(check, id, FZN_BUCKETS_ID_LEN) == 0) {
			*len = item_len;
			if (used)
				*used = mask;
			return FZN_PIECES_OK;
		}
	}
	return FZN_PIECES_ERR_NO_MATCH;
}

fzn_pieces_err_t fzn_pieces_rebuild(const char *dir, uint8_t kind,
                                    const uint8_t id[FZN_BUCKETS_ID_LEN],
                                    const fzn_hash_ops_t *hash, uint8_t *out, size_t cap,
                                    size_t *len, uint32_t *used)
{
	static uint8_t led[FZN_ERASURE_PIECES_MAX][FZN_PIECE_HEAD_LEN];
	uint8_t *held[FZN_ERASURE_PIECES_MAX] = { 0 };
	uint8_t first[FZN_PIECE_HEAD_LEN];
	char path[PATH_MAX_];
	unsigned lead, i, j, n_led = 0, n_held;
	int have_first, path_ok = 1;
	fzn_pieces_err_t err = FZN_PIECES_ERR_TOO_FEW, e;

	if (len)
		*len = 0;
	if (used)
		*used = 0;
	if (!dir || !id || !hash || !out || !len)
		return FZN_PIECES_ERR_MALFORMED;
	/* EACH CUT THE PIECES DESCRIBE LEADS IN TURN, sec 748: a piece is held
	 * to the head of the one that leads, and a head bent in a byte -- the
	 * host's, say, which no shape check reads -- led every rebuild when the
	 * first piece read was the lead, and k whole pieces then disagreed with
	 * it. The first lead is the first piece read, so a store whose pieces
	 * agree reads them once. */
	for (lead = 0; lead < FZN_ERASURE_PIECES_MAX && err != FZN_PIECES_OK; lead++) {
		have_first = 0;
		if (!piece_path(path, sizeof(path), dir, id, lead, ""))
			return FZN_PIECES_ERR_MALFORMED;
		held[lead] = read_piece(path, kind, id, lead, first, &have_first);
		if (!held[lead])
			continue;
		for (j = 0; j < n_led && !same_cut(led[j], first); j++)
			;
		if (j < n_led) {
			free(held[lead]);
			held[lead] = NULL;
			continue;
		}
		memcpy(led[n_led++], first, sizeof(first));
		n_held = 1;
		for (i = lead + 1u; i < FZN_ERASURE_PIECES_MAX && path_ok; i++) {
			path_ok = piece_path(path, sizeof(path), dir, id, i, "");
			held[i] = path_ok ? read_piece(path, kind, id, i, first, &have_first) : NULL;
			n_held += held[i] != NULL;
		}
		e = path_ok ? rebuild_led(held, first, n_held, id, hash, out, cap, len, used)
		            : FZN_PIECES_ERR_MALFORMED;
		for (i = 0; i < FZN_ERASURE_PIECES_MAX; i++) {
			free(held[i]);
			held[i] = NULL;
		}
		if (!path_ok)
			return e;
		/* THE NEAREST MISS IS SAID: no k rebuilding outranks too large,
		 * which outranks too few. */
		if (e == FZN_PIECES_OK || e == FZN_PIECES_ERR_NO_MATCH
		    || (e == FZN_PIECES_ERR_MALFORMED && err == FZN_PIECES_ERR_TOO_FEW))
			err = e;
	}
	return err;
}
