/* See pack.h. */

#define _POSIX_C_SOURCE 200809L

#include "pack.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zstd.h>

#define PATH_MAX_ 512u
/* Segments one pass packs at most; the rest wait for the next. */
#define SEGMENTS_MAX 256u

static const char HEX[] = "0123456789abcdef";

/* One chunk read and one zstd buffer out, held for the process: a packer
 * runs one segment at a time. */
static uint8_t chunk[FZN_LOG_PACK_CHUNK];
static uint8_t fold[FZN_LOG_PACK_HASH_LEN + FZN_LOG_PACK_CHUNK];

const char *fzn_log_pack_err_str(fzn_log_pack_err_t err)
{
	switch (err) {
	case FZN_LOG_PACK_OK:
		return "ok";
	case FZN_LOG_PACK_ERR_MALFORMED:
		return "malformed";
	case FZN_LOG_PACK_ERR_FILE:
		return "a log file would not read, write or rename";
	case FZN_LOG_PACK_ERR_ZSTD:
		return "zstd refused, or the packed bytes are not a frame";
	case FZN_LOG_PACK_ERR_CHAIN:
		return "the trailer is missing or does not verify";
	}
	return "unknown";
}

static void to_hex(const uint8_t *in, size_t n, char *out)
{
	size_t i;

	for (i = 0; i < n; i++) {
		out[i * 2u] = HEX[in[i] >> 4];
		out[(i * 2u) + 1u] = HEX[in[i] & 0x0fu];
	}
	out[n * 2u] = '\0';
}

static int from_hex(const char *t, uint8_t *out, size_t n)
{
	size_t i;

	for (i = 0; i < n * 2u; i++) {
		const char *h = t[i] ? strchr(HEX, t[i]) : NULL;

		if (!h)
			return 0;
		if (i % 2u == 0u)
			out[i / 2u] = (uint8_t)((h - HEX) << 4);
		else
			out[i / 2u] = (uint8_t)(out[i / 2u] | (uint8_t)(h - HEX));
	}
	return 1;
}

/* state = H(state || c). */
static int fold_chunk(const fzn_hash_ops_t *hash, uint8_t state[FZN_LOG_PACK_HASH_LEN],
                      const uint8_t *c, size_t n)
{
	memcpy(fold, state, FZN_LOG_PACK_HASH_LEN);
	memcpy(fold + FZN_LOG_PACK_HASH_LEN, c, n);
	return hash->hash(hash->ctx, state, FZN_LOG_PACK_HASH_LEN, fold, FZN_LOG_PACK_HASH_LEN + n)
	       == 0;
}

/* ---- packing one segment -------------------------------------------------- */

static int compress_into(ZSTD_CCtx *cc, FILE *out, const uint8_t *in, size_t n,
                         ZSTD_EndDirective end)
{
	static uint8_t buf[1u << 16];
	ZSTD_inBuffer src = { in, n, 0 };
	size_t left;

	do {
		ZSTD_outBuffer dst = { buf, sizeof(buf), 0 };

		left = ZSTD_compressStream2(cc, &dst, &src, end);
		if (ZSTD_isError(left) || fwrite(buf, 1u, dst.pos, out) != dst.pos)
			return 0;
	} while (end == ZSTD_e_end ? left != 0u : src.pos < src.size);
	return 1;
}

fzn_log_pack_err_t fzn_log_pack_segment(const char *log_path, const char *zst_path,
                                        const uint8_t prev[FZN_LOG_PACK_HASH_LEN],
                                        const fzn_hash_ops_t *hash,
                                        uint8_t hash_out[FZN_LOG_PACK_HASH_LEN])
{
	uint8_t state[FZN_LOG_PACK_HASH_LEN];
	char trailer[64 + (4u * FZN_LOG_PACK_HASH_LEN)], ph[(FZN_LOG_PACK_HASH_LEN * 2u) + 1u],
	        hh[(FZN_LOG_PACK_HASH_LEN * 2u) + 1u];
	fzn_log_pack_err_t err = FZN_LOG_PACK_ERR_FILE;
	FILE *in = NULL, *out = NULL;
	ZSTD_CCtx *cc = NULL;
	size_t n;
	int k;

	if (!log_path || !zst_path || !prev || !hash || !hash->hash || !hash_out)
		return FZN_LOG_PACK_ERR_MALFORMED;
	in = fopen(log_path, "rb");
	out = in ? fopen(zst_path, "wb") : NULL;
	cc = ZSTD_createCCtx();
	if (!in || !out)
		goto done;
	err = FZN_LOG_PACK_ERR_ZSTD;
	if (!cc || ZSTD_isError(ZSTD_CCtx_setParameter(cc, ZSTD_c_checksumFlag, 1)))
		goto done;
	memcpy(state, prev, sizeof(state));
	while ((n = fread(chunk, 1u, sizeof(chunk), in)) > 0u) {
		if (!fold_chunk(hash, state, chunk, n)) {
			err = FZN_LOG_PACK_ERR_CHAIN;
			goto done;
		}
		if (!compress_into(cc, out, chunk, n, ZSTD_e_continue))
			goto done;
	}
	if (ferror(in)) {
		err = FZN_LOG_PACK_ERR_FILE;
		goto done;
	}
	to_hex(prev, FZN_LOG_PACK_HASH_LEN, ph);
	to_hex(state, FZN_LOG_PACK_HASH_LEN, hh);
	k = snprintf(trailer, sizeof(trailer), "#fuzznet-log-trailer 1 prev=%s hash=%s\n", ph, hh);
	if (k <= 0 || (size_t)k >= sizeof(trailer)
	    || !compress_into(cc, out, (const uint8_t *)trailer, (size_t)k, ZSTD_e_end))
		goto done;
	err = FZN_LOG_PACK_ERR_FILE;
	if (fflush(out) != 0 || fsync(fileno(out)) != 0)
		goto done;
	memcpy(hash_out, state, FZN_LOG_PACK_HASH_LEN);
	err = FZN_LOG_PACK_OK;
done:
	ZSTD_freeCCtx(cc);
	if (in)
		(void)fclose(in);
	if (out && fclose(out) != 0 && err == FZN_LOG_PACK_OK)
		err = FZN_LOG_PACK_ERR_FILE;
	return err;
}

/* ---- verifying one ------------------------------------------------------- */

/* The trailer is the last line, and it is held back from the chain: the
 * stream's bytes are folded in chunks only once the next ones show they
 * are not the trailer. */
fzn_log_pack_err_t fzn_log_pack_verify(const char *zst_path,
                                       const uint8_t prev[FZN_LOG_PACK_HASH_LEN],
                                       const fzn_hash_ops_t *hash,
                                       uint8_t hash_out[FZN_LOG_PACK_HASH_LEN])
{
	static uint8_t inbuf[1u << 16], outbuf[1u << 16];
	/* A pending window: plain bytes not yet folded, at most one chunk
	 * and the longest trailer. */
	static uint8_t pending[FZN_LOG_PACK_CHUNK + 256u];
	uint8_t state[FZN_LOG_PACK_HASH_LEN], got_prev[FZN_LOG_PACK_HASH_LEN],
	        got_hash[FZN_LOG_PACK_HASH_LEN];
	static const char HEAD[] = "#fuzznet-log-trailer 1 prev=";
	const size_t trailer_len = (sizeof(HEAD) - 1u) + 64u + 6u + 64u + 1u;
	fzn_log_pack_err_t err = FZN_LOG_PACK_ERR_ZSTD;
	ZSTD_DCtx *dc = NULL;
	FILE *in = NULL;
	size_t have = 0, n, last = 1;
	const uint8_t *t;

	if (!zst_path || !prev || !hash || !hash->hash || !hash_out)
		return FZN_LOG_PACK_ERR_MALFORMED;
	in = fopen(zst_path, "rb");
	if (!in)
		return FZN_LOG_PACK_ERR_FILE;
	dc = ZSTD_createDCtx();
	if (!dc)
		goto done;
	memcpy(state, prev, sizeof(state));
	while ((n = fread(inbuf, 1u, sizeof(inbuf), in)) > 0u) {
		ZSTD_inBuffer src = { inbuf, n, 0 };

		while (src.pos < src.size) {
			ZSTD_outBuffer dst = { outbuf, sizeof(outbuf), 0 };
			size_t off = 0;

			last = ZSTD_decompressStream(dc, &dst, &src);
			if (ZSTD_isError(last))
				goto done;
			/* KEEP THE TAIL BACK: fold whole chunks only while more
			 * than a trailer's worth stays pending. */
			while (off < dst.pos) {
				size_t take = dst.pos - off;

				if (take > sizeof(pending) - have)
					take = sizeof(pending) - have;
				memcpy(pending + have, outbuf + off, take);
				have += take;
				off += take;
				if (have >= FZN_LOG_PACK_CHUNK + trailer_len) {
					if (!fold_chunk(hash, state, pending, FZN_LOG_PACK_CHUNK)) {
						err = FZN_LOG_PACK_ERR_CHAIN;
						goto done;
					}
					memmove(pending, pending + FZN_LOG_PACK_CHUNK,
					        have - FZN_LOG_PACK_CHUNK);
					have -= FZN_LOG_PACK_CHUNK;
				}
			}
		}
	}
	/* A FRAME CUT SHORT leaves zstd wanting more. */
	if (ferror(in) || last != 0u)
		goto done;
	err = FZN_LOG_PACK_ERR_CHAIN;
	if (have < trailer_len)
		goto done;
	t = pending + have - trailer_len;
	if (memcmp(t, HEAD, sizeof(HEAD) - 1u) != 0 || !from_hex((const char *)t + 28, got_prev, 32u)
	    || memcmp(t + 92, " hash=", 6u) != 0
	    || !from_hex((const char *)t + 98, got_hash, 32u) || t[trailer_len - 1u] != '\n'
	    || (have > trailer_len && pending[have - trailer_len - 1u] != '\n'))
		goto done;
	/* THE REST, in the same chunks the packer folded. */
	n = have - trailer_len;
	if (n > FZN_LOG_PACK_CHUNK)
		goto done;
	if (n && !fold_chunk(hash, state, pending, n))
		goto done;
	if (memcmp(got_prev, prev, FZN_LOG_PACK_HASH_LEN) != 0
	    || memcmp(got_hash, state, FZN_LOG_PACK_HASH_LEN) != 0)
		goto done;
	memcpy(hash_out, state, FZN_LOG_PACK_HASH_LEN);
	err = FZN_LOG_PACK_OK;
done:
	ZSTD_freeDCtx(dc);
	(void)fclose(in);
	return err;
}

/* ---- packing a directory ------------------------------------------------- */

/* `PROGRAM.TIME.PID.log`: the closing time, or 0 for any other name. */
static uint64_t closed_at(const char *name, const char *program)
{
	size_t plen = strlen(program), i;
	const char *t, *dot;
	uint64_t v = 0;

	if (strncmp(name, program, plen) != 0 || name[plen] != '.')
		return 0;
	t = name + plen + 1u;
	dot = strchr(t, '.');
	if (!dot || dot == t)
		return 0;
	for (i = 0; t + i < dot; i++) {
		if (t[i] < '0' || t[i] > '9' || v > (UINT64_MAX - 9u) / 10u)
			return 0;
		v = (v * 10u) + (uint64_t)(t[i] - '0');
	}
	t = dot + 1;
	dot = strchr(t, '.');
	if (!dot || dot == t || strcmp(dot, ".log") != 0)
		return 0;
	for (; t < dot; t++)
		if (*t < '0' || *t > '9')
			return 0;
	return v;
}

struct segment {
	uint64_t at;
	char name[256];
};

static int by_time(const void *a, const void *b)
{
	const struct segment *x = a, *y = b;

	if (x->at != y->at)
		return x->at < y->at ? -1 : 1;
	return strcmp(x->name, y->name);
}

static int read_chain(int fd, uint8_t prev[FZN_LOG_PACK_HASH_LEN])
{
	char t[(FZN_LOG_PACK_HASH_LEN * 2u) + 2u];
	ssize_t n = pread(fd, t, sizeof(t), 0);

	if (n == 0) {
		memset(prev, 0, FZN_LOG_PACK_HASH_LEN);
		return 1;
	}
	/* 64 HEX DIGITS AND A NEWLINE, and nothing after: the buffer is one
	 * longer, so a longer file reads as one. */
	return n == 65 && t[64] == '\n' && from_hex(t, prev, 32u);
}

static int write_chain(int fd, const uint8_t hash[FZN_LOG_PACK_HASH_LEN])
{
	char t[(FZN_LOG_PACK_HASH_LEN * 2u) + 2u];

	to_hex(hash, FZN_LOG_PACK_HASH_LEN, t);
	t[64] = '\n';
	return pwrite(fd, t, 65u, 0) == 65 && ftruncate(fd, 65) == 0 && fsync(fd) == 0;
}

fzn_log_pack_err_t fzn_log_pack_dir(const char *dir, const char *program,
                                    const fzn_hash_ops_t *hash, uint64_t now_us,
                                    uint64_t settle_us, size_t *packed)
{
	static struct segment segs[SEGMENTS_MAX];
	char chain_path[PATH_MAX_], from[PATH_MAX_], to[PATH_MAX_], tmp[PATH_MAX_];
	uint8_t prev[FZN_LOG_PACK_HASH_LEN], next[FZN_LOG_PACK_HASH_LEN];
	fzn_log_pack_err_t err = FZN_LOG_PACK_OK;
	struct flock lk;
	struct dirent *e;
	size_t n = 0, i;
	DIR *d;
	int fd, k;

	if (!dir || !program || !program[0] || strchr(program, '/') || !hash || !packed)
		return FZN_LOG_PACK_ERR_MALFORMED;
	*packed = 0;
	k = snprintf(chain_path, sizeof(chain_path), "%s/%s.chain", dir, program);
	if (k <= 0 || (size_t)k >= sizeof(chain_path))
		return FZN_LOG_PACK_ERR_MALFORMED;
	fd = open(chain_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (fd < 0)
		return FZN_LOG_PACK_ERR_FILE;
	memset(&lk, 0, sizeof(lk));
	lk.l_type = F_WRLCK;
	lk.l_whence = SEEK_SET;
	/* ANOTHER INSTANCE PACKING is not an error: it will pack these. */
	if (fcntl(fd, F_SETLK, &lk) != 0) {
		(void)close(fd);
		return (errno == EACCES || errno == EAGAIN) ? FZN_LOG_PACK_OK : FZN_LOG_PACK_ERR_FILE;
	}
	if (!read_chain(fd, prev)) {
		err = FZN_LOG_PACK_ERR_CHAIN;
		goto done;
	}
	d = opendir(dir);
	if (!d) {
		err = FZN_LOG_PACK_ERR_FILE;
		goto done;
	}
	while ((e = readdir(d)) != NULL && n < SEGMENTS_MAX) {
		uint64_t at = closed_at(e->d_name, program);

		if (at == 0u || strlen(e->d_name) >= sizeof(segs[0].name))
			continue;
		/* NOT YET SETTLED: a line may still be on its way in. A closing
		 * time more than a settle period AHEAD of the clock was stamped by
		 * a clock since set back, and is settled: waiting for it would
		 * leave the segment unpacked for as long as the clock was wrong.
		 * sec 470. */
		if (at <= now_us + settle_us && (now_us < at || now_us - at < settle_us))
			continue;
		segs[n].at = at;
		strcpy(segs[n].name, e->d_name);
		n++;
	}
	(void)closedir(d);
	qsort(segs, n, sizeof(segs[0]), by_time);
	for (i = 0; i < n; i++) {
		if (snprintf(from, sizeof(from), "%s/%s", dir, segs[i].name) >= (int)sizeof(from)
		    || snprintf(to, sizeof(to), "%s/%s.zst", dir, segs[i].name) >= (int)sizeof(to)
		    || snprintf(tmp, sizeof(tmp), "%s/%s.zst.new", dir, segs[i].name)
		               >= (int)sizeof(tmp)) {
			err = FZN_LOG_PACK_ERR_MALFORMED;
			break;
		}
		err = fzn_log_pack_segment(from, tmp, prev, hash, next);
		if (err == FZN_LOG_PACK_OK && fzn_log_pack_verify(tmp, prev, hash, next) != FZN_LOG_PACK_OK)
			err = FZN_LOG_PACK_ERR_CHAIN;
		/* THE CHAIN MOVES ONLY WITH THE FILE: renamed into place, the
		 * chain written, and only then the segment removed. */
		if (err == FZN_LOG_PACK_OK
		    && (rename(tmp, to) != 0 || !write_chain(fd, next) || remove(from) != 0))
			err = FZN_LOG_PACK_ERR_FILE;
		if (err != FZN_LOG_PACK_OK) {
			(void)remove(tmp);
			break;
		}
		memcpy(prev, next, sizeof(prev));
		(*packed)++;
	}
done:
	lk.l_type = F_UNLCK;
	(void)fcntl(fd, F_SETLK, &lk);
	(void)close(fd);
	return err;
}
