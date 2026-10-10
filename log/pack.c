/* See pack.h. */

#define _POSIX_C_SOURCE 200809L

#include "pack.h"
#include "entry.h"

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
	case FZN_LOG_PACK_ERR_SIGNATURE:
		return "a trailer's signature would not sign, or does not hold";
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

/* state = H(state || c). NONZERO IS SUCCESS on this seam, as
 * `session/commitment.h` says; read the other way, every real hash refused
 * the first chunk and nothing ever packed. */
static int fold_chunk(const fzn_hash_ops_t *hash, uint8_t state[FZN_LOG_PACK_HASH_LEN],
                      const uint8_t *c, size_t n)
{
	memcpy(fold, state, FZN_LOG_PACK_HASH_LEN);
	memcpy(fold + FZN_LOG_PACK_HASH_LEN, c, n);
	return hash->hash(hash->ctx, state, FZN_LOG_PACK_HASH_LEN, fold, FZN_LOG_PACK_HASH_LEN + n)
	       != 0;
}

/* ---- signing a trailer, sec 482 ----------------------------------------- */

/* A trailer's signature suffix: ` key=HEX sig=HEX`, 202 characters. */
#define SIG_SUFFIX_LEN (5u + 64u + 5u + 128u)
#define SIG_LABEL "fuzznet.log.trailer"

/* `base`, a trailer line without its newline, signed by `signer` as
 * `SIG_LABEL\0 || base`, its suffix into `out` (SIG_SUFFIX_LEN + 1). */
static int sign_line(const fzn_log_pack_signer_t *signer, const char *base, size_t n,
                     char *out)
{
	static uint8_t msg[sizeof(SIG_LABEL) + 640u];
	uint8_t sig[FZN_SIG_LEN];

	if (!signer || !signer->sign || !signer->sign->sign || n > sizeof(msg) - sizeof(SIG_LABEL))
		return 0;
	memcpy(msg, SIG_LABEL, sizeof(SIG_LABEL));
	memcpy(msg + sizeof(SIG_LABEL), base, n);
	if (!signer->sign->sign(signer->sign->ctx, sig, msg, sizeof(SIG_LABEL) + n))
		return 0;
	memcpy(out, " key=", 5u);
	to_hex(signer->key, 32u, out + 5u);
	memcpy(out + 69u, " sig=", 5u);
	to_hex(sig, FZN_SIG_LEN, out + 74u);
	return 1;
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
                                        const fzn_log_pack_signer_t *signer,
                                        uint8_t hash_out[FZN_LOG_PACK_HASH_LEN])
{
	uint8_t state[FZN_LOG_PACK_HASH_LEN];
	char trailer[64u + (4u * FZN_LOG_PACK_HASH_LEN) + SIG_SUFFIX_LEN + 2u],
	        ph[(FZN_LOG_PACK_HASH_LEN * 2u) + 1u],
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
	k = snprintf(trailer, sizeof(trailer), "#fuzznet-log-trailer 1 prev=%s hash=%s", ph, hh);
	if (k <= 0 || (size_t)k + SIG_SUFFIX_LEN + 2u > sizeof(trailer))
		goto done;
	/* SIGNED WHEN A SIGNER IS GIVEN, sec 482. */
	if (signer) {
		if (!sign_line(signer, trailer, (size_t)k, trailer + k)) {
			err = FZN_LOG_PACK_ERR_SIGNATURE;
			goto done;
		}
		k += (int)SIG_SUFFIX_LEN;
	}
	trailer[k++] = '\n';
	if (!compress_into(cc, out, (const uint8_t *)trailer, (size_t)k, ZSTD_e_end))
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

/* ---- trailers ---------------------------------------------------------- */

/* The longest trailer: version 2 with every field at its widest. */
#define TRAILER_MAX 576u

typedef struct trailer {
	uint8_t prev[FZN_LOG_PACK_HASH_LEN];
	uint8_t hash[FZN_LOG_PACK_HASH_LEN];
	/* VERSION 2, sec 474: a segment repacked without some of its lines.
	 * `was` is its hash as first packed, which the next segment's `prev`
	 * names, so the chain still runs through it. */
	int repacked;
	uint8_t was[FZN_LOG_PACK_HASH_LEN];
	uint64_t dropped;
	/* SIGNED, sec 482: by `key`, over the line before ` key=`. */
	int has_sig;
	uint8_t key[32];
	uint8_t sig[FZN_SIG_LEN];
	char base[TRAILER_MAX];
	size_t base_len;
} trailer_t;

static int parse_base(const uint8_t *t, size_t len, trailer_t *out);

/* `t`, `len` bytes ending in its newline, as a trailer of either version,
 * signed or not. */
static int parse_trailer(const uint8_t *t, size_t len, trailer_t *out)
{
	uint8_t line[TRAILER_MAX + 1u];
	size_t k, base;
	int has_sig = 0;
	uint8_t key[32], sig[FZN_SIG_LEN];

	if (len < 2u || len > TRAILER_MAX || t[len - 1u] != '\n')
		return 0;
	base = len - 1u;
	for (k = 0; k + 5u <= len; k++)
		if (memcmp(t + k, " key=", 5u) == 0)
			break;
	if (k + 5u <= len) {
		if (k + SIG_SUFFIX_LEN != len - 1u || !from_hex((const char *)t + k + 5u, key, 32u)
		    || memcmp(t + k + 69u, " sig=", 5u) != 0
		    || !from_hex((const char *)t + k + 74u, sig, FZN_SIG_LEN))
			return 0;
		base = k;
		has_sig = 1;
	}
	memcpy(line, t, base);
	line[base] = '\n';
	if (!parse_base(line, base + 1u, out))
		return 0;
	out->has_sig = has_sig;
	if (has_sig) {
		memcpy(out->key, key, sizeof(key));
		memcpy(out->sig, sig, sizeof(sig));
	}
	memcpy(out->base, t, base);
	out->base_len = base;
	return 1;
}

/* The line before any signature, newline-terminated. */
static int parse_base(const uint8_t *t, size_t len, trailer_t *out)
{
	static const char V1[] = "#fuzznet-log-trailer 1 prev=";
	static const char V2[] = "#fuzznet-log-trailer 2 prev=";
	const size_t head = sizeof(V1) - 1u, v1_len = head + 64u + 6u + 64u + 1u;
	size_t at, i;

	memset(out, 0, sizeof(*out));
	if (len < v1_len || t[len - 1u] != '\n')
		return 0;
	if (memcmp(t, V1, head) == 0)
		out->repacked = 0;
	else if (memcmp(t, V2, head) == 0)
		out->repacked = 1;
	else
		return 0;
	if (!from_hex((const char *)t + head, out->prev, 32u)
	    || memcmp(t + head + 64u, " hash=", 6u) != 0
	    || !from_hex((const char *)t + head + 70u, out->hash, 32u))
		return 0;
	at = head + 134u;
	if (!out->repacked)
		return len == v1_len;
	if (len < at + 5u + 64u + 9u + 2u || memcmp(t + at, " was=", 5u) != 0
	    || !from_hex((const char *)t + at + 5u, out->was, 32u)
	    || memcmp(t + at + 69u, " dropped=", 9u) != 0)
		return 0;
	at += 78u;
	if (len - 1u - at > 20u || len - 1u == at)
		return 0;
	for (i = at; i < len - 1u; i++) {
		unsigned d = (unsigned)(t[i] - '0');

		if (t[i] < '0' || t[i] > '9' || out->dropped > (UINT64_MAX - d) / 10u)
			return 0;
		out->dropped = (out->dropped * 10u) + d;
	}
	return 1;
}

/* What the next segment's prev names: the hash as first packed. */
static const uint8_t *carried(const trailer_t *t)
{
	return t->repacked ? t->was : t->hash;
}

/* ---- verifying one ------------------------------------------------------- */

/* The trailer is the last line, and it is held back from the chain: the
 * stream's bytes are folded in chunks only once more than the longest
 * trailer follows them, so they cannot be the trailer. */
static fzn_log_pack_err_t verify_core(const char *zst_path,
                                      const uint8_t *prev, const fzn_hash_ops_t *hash,
                                      uint8_t hash_out[FZN_LOG_PACK_HASH_LEN], trailer_t *tr_out);

fzn_log_pack_err_t fzn_log_pack_verify(const char *zst_path,
                                       const uint8_t prev[FZN_LOG_PACK_HASH_LEN],
                                       const fzn_hash_ops_t *hash,
                                       uint8_t hash_out[FZN_LOG_PACK_HASH_LEN])
{
	static trailer_t tr;

	if (!prev)
		return FZN_LOG_PACK_ERR_MALFORMED;
	return verify_core(zst_path, prev, hash, hash_out, &tr);
}

/* A trailer's signature over its line. */
static int signature_holds(const trailer_t *tr, const fzn_sign_ops_t *sign)
{
	static uint8_t msg[sizeof(SIG_LABEL) + TRAILER_MAX];

	if (!tr->has_sig || !sign || !sign->verify || tr->base_len > TRAILER_MAX)
		return 0;
	memcpy(msg, SIG_LABEL, sizeof(SIG_LABEL));
	memcpy(msg + sizeof(SIG_LABEL), tr->base, tr->base_len);
	return sign->verify(sign->ctx, tr->key, msg, sizeof(SIG_LABEL) + tr->base_len, tr->sig);
}

fzn_log_pack_err_t fzn_log_pack_verify_signed(const char *zst_path,
                                              const uint8_t prev[FZN_LOG_PACK_HASH_LEN],
                                              const fzn_hash_ops_t *hash,
                                              const fzn_sign_ops_t *sign,
                                              uint8_t hash_out[FZN_LOG_PACK_HASH_LEN],
                                              int *is_signed,
                                              uint8_t signer_out[FZN_LOG_PACK_HASH_LEN])
{
	static trailer_t tr;
	fzn_log_pack_err_t err;

	if (!sign || !is_signed)
		return FZN_LOG_PACK_ERR_MALFORMED;
	*is_signed = 0;
	err = verify_core(zst_path, prev, hash, hash_out, &tr);
	if (err != FZN_LOG_PACK_OK)
		return err;
	if (!tr.has_sig)
		return FZN_LOG_PACK_OK;
	/* A SIGNATURE THAT DOES NOT HOLD is worse than none: somebody changed a
	 * signed line, and the chain alone could not tell. */
	if (!signature_holds(&tr, sign))
		return FZN_LOG_PACK_ERR_SIGNATURE;
	*is_signed = 1;
	if (signer_out)
		memcpy(signer_out, tr.key, sizeof(tr.key));
	return FZN_LOG_PACK_OK;
}

/* The chain check, and the trailer it read into `tr_out`. */
static fzn_log_pack_err_t verify_core(const char *zst_path,
                                      const uint8_t *prev_in, const fzn_hash_ops_t *hash,
                                      uint8_t hash_out[FZN_LOG_PACK_HASH_LEN], trailer_t *tr_out)
{
	static uint8_t inbuf[1u << 16], outbuf[1u << 16];
	static uint8_t pending[FZN_LOG_PACK_CHUNK + TRAILER_MAX];
	uint8_t state[FZN_LOG_PACK_HASH_LEN];
	fzn_log_pack_err_t err = FZN_LOG_PACK_ERR_ZSTD;
	ZSTD_DCtx *dc = NULL;
	FILE *in = NULL;
	size_t have = 0, n, last = 1, start;
	int folded = 0;
	trailer_t tr;
	const uint8_t *prev = prev_in;

	if (!zst_path || !prev || !hash || !hash->hash || !hash_out || !tr_out)
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
			while (off < dst.pos) {
				size_t take = dst.pos - off;

				if (take > sizeof(pending) - have)
					take = sizeof(pending) - have;
				memcpy(pending + have, outbuf + off, take);
				have += take;
				off += take;
				if (have == sizeof(pending)) {
					if (!fold_chunk(hash, state, pending, FZN_LOG_PACK_CHUNK)) {
						err = FZN_LOG_PACK_ERR_CHAIN;
						goto done;
					}
					memmove(pending, pending + FZN_LOG_PACK_CHUNK,
					        have - FZN_LOG_PACK_CHUNK);
					have -= FZN_LOG_PACK_CHUNK;
					folded = 1;
				}
			}
		}
	}
	/* A FRAME CUT SHORT leaves zstd wanting more. */
	if (ferror(in) || last != 0u)
		goto done;
	err = FZN_LOG_PACK_ERR_CHAIN;
	/* THE LAST LINE: after the newline before the final one, which a
	 * segment folded already must have left in the window. */
	if (have < 2u)
		goto done;
	for (start = have - 1u; start > 0u && pending[start - 1u] != '\n'; start--)
		;
	if ((start == 0u && folded) || have - start > TRAILER_MAX
	    || !parse_trailer(pending + start, have - start, &tr))
		goto done;
	/* THE REST, in the same chunks the packer folded: at most two. */
	if (start > FZN_LOG_PACK_CHUNK) {
		if (!fold_chunk(hash, state, pending, FZN_LOG_PACK_CHUNK)
		    || !fold_chunk(hash, state, pending + FZN_LOG_PACK_CHUNK,
		                   start - FZN_LOG_PACK_CHUNK))
			goto done;
	} else if (start && !fold_chunk(hash, state, pending, start)) {
		goto done;
	}
	if (memcmp(tr.prev, prev, FZN_LOG_PACK_HASH_LEN) != 0
	    || memcmp(tr.hash, state, FZN_LOG_PACK_HASH_LEN) != 0)
		goto done;
	memcpy(hash_out, carried(&tr), FZN_LOG_PACK_HASH_LEN);
	*tr_out = tr;
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
                                    const fzn_hash_ops_t *hash,
                                    const fzn_log_pack_signer_t *signer, uint64_t now_us,
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
		err = fzn_log_pack_segment(from, tmp, prev, hash, signer, next);
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

/* ---- the rules over entries, sec 474 ------------------------------------- */

/* `PROGRAM.TIME.PID.log` or its `.zst`: the closing time, or 0. */
static uint64_t segment_at(const char *name, const char *program, int *packed)
{
	char plain[256];
	size_t n = strlen(name);

	*packed = n > 4u && strcmp(name + n - 4u, ".zst") == 0;
	if (n >= sizeof(plain))
		return 0;
	memcpy(plain, name, n + 1u);
	if (*packed)
		plain[n - 4u] = '\0';
	return closed_at(plain, program);
}

/* A whole segment into a buffer of its own, decompressed when packed: at
 * most FZN_LOG_PACK_RETAIN_READ_MAX. 0, and nothing held, otherwise. */
static int read_all(const char *path, int packed, uint8_t **out, size_t *len)
{
	static uint8_t inbuf[1u << 16];
	size_t cap = 1u << 16, have = 0, n, last = 0;
	ZSTD_DCtx *dc = NULL;
	uint8_t *buf = malloc(cap);
	FILE *in = fopen(path, "rb");
	int ok = 0;

	if (!buf || !in || (packed && !(dc = ZSTD_createDCtx())))
		goto done;
	while ((n = fread(inbuf, 1u, sizeof(inbuf), in)) > 0u) {
		ZSTD_inBuffer src = { inbuf, n, 0 };

		while (src.pos < src.size) {
			uint8_t *grown;

			if (have == cap) {
				if (cap >= FZN_LOG_PACK_RETAIN_READ_MAX)
					goto done;
				grown = realloc(buf, cap * 2u);
				if (!grown)
					goto done;
				buf = grown;
				cap *= 2u;
			}
			if (packed) {
				ZSTD_outBuffer dst = { buf + have, cap - have, 0 };

				last = ZSTD_decompressStream(dc, &dst, &src);
				if (ZSTD_isError(last))
					goto done;
				have += dst.pos;
			} else {
				size_t take = src.size - src.pos;

				if (take > cap - have)
					take = cap - have;
				memcpy(buf + have, inbuf + src.pos, take);
				src.pos += take;
				have += take;
			}
		}
	}
	ok = !ferror(in) && (!packed || last == 0u);
done:
	ZSTD_freeDCtx(dc);
	if (in)
		(void)fclose(in);
	if (!ok) {
		free(buf);
		return 0;
	}
	*out = buf;
	*len = have;
	return 1;
}

/* The chain over `n` bytes from `prev`, in the packer's chunks. */
static int chain_over(const fzn_hash_ops_t *hash, const uint8_t prev[FZN_LOG_PACK_HASH_LEN],
                      const uint8_t *b, size_t n, uint8_t out[FZN_LOG_PACK_HASH_LEN])
{
	size_t at = 0;

	memcpy(out, prev, FZN_LOG_PACK_HASH_LEN);
	while (at < n) {
		size_t take = n - at < FZN_LOG_PACK_CHUNK ? n - at : FZN_LOG_PACK_CHUNK;

		if (!fold_chunk(hash, out, b + at, take))
			return 0;
		at += take;
	}
	return 1;
}

/* `content` and a version-2 trailer packed into `tmp`. */
static int write_repacked(const char *tmp, const uint8_t *content, size_t n, const trailer_t *tr,
                          const fzn_log_pack_signer_t *signer)
{
	char line[TRAILER_MAX], ph[65], hh[65], wh[65];
	ZSTD_CCtx *cc = ZSTD_createCCtx();
	FILE *out = fopen(tmp, "wb");
	int ok = 0, k;

	to_hex(tr->prev, FZN_LOG_PACK_HASH_LEN, ph);
	to_hex(tr->hash, FZN_LOG_PACK_HASH_LEN, hh);
	to_hex(tr->was, FZN_LOG_PACK_HASH_LEN, wh);
	k = snprintf(line, sizeof(line), "#fuzznet-log-trailer 2 prev=%s hash=%s was=%s dropped=%llu",
	             ph, hh, wh, (unsigned long long)tr->dropped);
	if (k <= 0 || (size_t)k + SIG_SUFFIX_LEN + 2u > sizeof(line))
		k = -1;
	/* RE-SIGNED BY THE REPACKER, sec 482: the old signature was over the
	 * old line, and the host that thinned its own log signs what is left. */
	else if (signer && !sign_line(signer, line, (size_t)k, line + k))
		k = -1;
	else if (signer)
		k += (int)SIG_SUFFIX_LEN;
	if (k > 0)
		line[k++] = '\n';
	if (cc && out && k > 0 && (size_t)k < sizeof(line)
	    && !ZSTD_isError(ZSTD_CCtx_setParameter(cc, ZSTD_c_checksumFlag, 1))
	    && compress_into(cc, out, content, n, ZSTD_e_continue)
	    && compress_into(cc, out, (const uint8_t *)line, (size_t)k, ZSTD_e_end)
	    && fflush(out) == 0 && fsync(fileno(out)) == 0)
		ok = 1;
	ZSTD_freeCCtx(cc);
	if (out && fclose(out) != 0)
		ok = 0;
	return ok;
}

struct held {
	uint64_t at;
	int packed;
	char name[256];
};

/* Newest first, ties by name so the order is total. */
static int newest_first(const void *a, const void *b)
{
	const struct held *x = a, *y = b;

	if (x->at != y->at)
		return x->at > y->at ? -1 : 1;
	return -strcmp(x->name, y->name);
}

/* One segment's lines judged, newest first; `drop[i]` per line. 1 when
 * every line goes. Headers go only with the whole. */
static int judge(fzn_retain_walk_t *walk, uint8_t mark, const uint8_t *b, size_t n,
                 const size_t *starts, size_t lines, uint8_t *drop, size_t *dropped)
{
	static uint8_t text[FZN_ENTRY_TEXT_MAX];
	static const uint8_t no_machine[FZN_ENTRY_MACHINE_LEN] = { 0 };
	const int whole = mark == FZN_RETAIN_MARK_PRUNED;
	size_t i, kept_other = 0;

	*dropped = 0;
	for (i = lines; i-- > 0u;) {
		size_t end = i + 1u < lines ? starts[i + 1u] : n, len = end - starts[i];
		const char *line = (const char *)b + starts[i];
		char host[FZN_ENTRY_WORD_MAX + 1u];
		fzn_entry_t e;

		drop[i] = 0;
		if (line[0] == '#')
			continue;
		if (fzn_entry_classic_parse(line, len, no_machine, &e, host, text, sizeof(text))
		    == FZN_ENTRY_OK)
			drop[i] = (uint8_t)fzn_retain_walk_entry(walk, mark, e.time_us, e.level,
			                                         e.subsystem, e.text, e.text_len, len);
		else
			drop[i] = (uint8_t)whole;
		if (drop[i])
			(*dropped)++;
		else
			kept_other++;
	}
	return kept_other == 0u && (*dropped > 0u || whole);
}

/* A packed segment repacked without the lines `drop` names. */
static fzn_log_pack_err_t repack(const char *path, const char *tmp, const uint8_t *b, size_t n,
                                 size_t body, const size_t *starts, size_t lines,
                                 const uint8_t *drop, size_t dropped, const trailer_t *old,
                                 const fzn_hash_ops_t *hash,
                                 const fzn_log_pack_signer_t *signer)
{
	uint8_t *kept = malloc(body ? body : 1u), carry[FZN_LOG_PACK_HASH_LEN];
	size_t used = 0, i;
	trailer_t tr;

	if (!kept)
		return FZN_LOG_PACK_ERR_FILE;
	for (i = 0; i < lines; i++) {
		size_t end = i + 1u < lines ? starts[i + 1u] : body;

		if (!drop[i]) {
			memcpy(kept + used, b + starts[i], end - starts[i]);
			used += end - starts[i];
		}
	}
	(void)n;
	memset(&tr, 0, sizeof(tr));
	tr.repacked = 1;
	memcpy(tr.prev, old->prev, FZN_LOG_PACK_HASH_LEN);
	memcpy(tr.was, carried(old), FZN_LOG_PACK_HASH_LEN);
	tr.dropped = old->dropped + dropped;
	if (!chain_over(hash, tr.prev, kept, used, tr.hash)) {
		free(kept);
		return FZN_LOG_PACK_ERR_CHAIN;
	}
	/* WRITTEN BESIDE, VERIFIED, RENAMED: the chain it carries must be the
	 * one it carried before. */
	if (!write_repacked(tmp, kept, used, &tr, signer)) {
		free(kept);
		(void)remove(tmp);
		return FZN_LOG_PACK_ERR_FILE;
	}
	free(kept);
	if (fzn_log_pack_verify(tmp, tr.prev, hash, carry) != FZN_LOG_PACK_OK
	    || memcmp(carry, carried(old), FZN_LOG_PACK_HASH_LEN) != 0) {
		(void)remove(tmp);
		return FZN_LOG_PACK_ERR_CHAIN;
	}
	if (rename(tmp, path) != 0) {
		(void)remove(tmp);
		return FZN_LOG_PACK_ERR_FILE;
	}
	return FZN_LOG_PACK_OK;
}

fzn_log_pack_err_t fzn_log_pack_retain(const char *dir, const char *program,
                                       const fzn_retain_rule_t *rules, size_t n_rules,
                                       const fzn_hash_ops_t *hash,
                                       const fzn_log_pack_signer_t *signer, uint64_t now_us,
                                       size_t *removed, size_t *repacked)
{
	static struct held segs[SEGMENTS_MAX];
	static fzn_retain_segment_t sizes[SEGMENTS_MAX];
	static uint8_t marks[SEGMENTS_MAX];
	static fzn_retain_walk_t walk;
	char chain_path[PATH_MAX_], path[PATH_MAX_], tmp[PATH_MAX_];
	fzn_log_pack_err_t err = FZN_LOG_PACK_OK;
	struct flock lk;
	struct dirent *e;
	size_t n = 0, i;
	int fd, k, entries;
	DIR *d;

	if (!dir || !program || !program[0] || strchr(program, '/') || (!rules && n_rules) || !hash
	    || !hash->hash || !removed || !repacked)
		return FZN_LOG_PACK_ERR_MALFORMED;
	*removed = 0;
	*repacked = 0;
	k = snprintf(chain_path, sizeof(chain_path), "%s/%s.chain", dir, program);
	if (k <= 0 || (size_t)k >= sizeof(chain_path))
		return FZN_LOG_PACK_ERR_MALFORMED;
	fd = open(chain_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (fd < 0)
		return FZN_LOG_PACK_ERR_FILE;
	memset(&lk, 0, sizeof(lk));
	lk.l_type = F_WRLCK;
	lk.l_whence = SEEK_SET;
	if (fcntl(fd, F_SETLK, &lk) != 0) {
		(void)close(fd);
		return (errno == EACCES || errno == EAGAIN) ? FZN_LOG_PACK_OK : FZN_LOG_PACK_ERR_FILE;
	}
	d = opendir(dir);
	if (!d) {
		err = FZN_LOG_PACK_ERR_FILE;
		goto done;
	}
	while ((e = readdir(d)) != NULL && n < SEGMENTS_MAX) {
		struct held h;
		struct stat st;

		h.at = segment_at(e->d_name, program, &h.packed);
		if (h.at == 0u || strlen(e->d_name) >= sizeof(h.name)
		    || snprintf(path, sizeof(path), "%s/%s", dir, e->d_name) >= (int)sizeof(path)
		    || stat(path, &st) != 0)
			continue;
		strcpy(h.name, e->d_name);
		segs[n] = h;
		n++;
	}
	(void)closedir(d);
	qsort(segs, n, sizeof(segs[0]), newest_first);
	for (i = 0; i < n; i++) {
		struct stat st;

		(void)snprintf(path, sizeof(path), "%s/%s", dir, segs[i].name);
		sizes[i].closed_us = segs[i].at;
		sizes[i].bytes = stat(path, &st) == 0 && st.st_size > 0 ? (uint64_t)st.st_size : 0u;
	}
	if (fzn_retain_marks(program, sizes, n, rules, n_rules, now_us, marks) != FZN_RETAIN_OK
	    || fzn_retain_walk_init(&walk, program, rules, n_rules, now_us) != FZN_RETAIN_OK) {
		err = FZN_LOG_PACK_ERR_MALFORMED;
		goto done;
	}
	entries = fzn_retain_reads_entries(program, rules, n_rules);
	for (i = 0; i < n && err == FZN_LOG_PACK_OK; i++) {
		uint8_t *b = NULL, *drop = NULL;
		size_t *starts = NULL, len = 0, body, lines = 0, dropped = 0, j;
		trailer_t tr;
		int all, readable;

		if (snprintf(path, sizeof(path), "%s/%s", dir, segs[i].name) >= (int)sizeof(path)
		    || snprintf(tmp, sizeof(tmp), "%s/%s.new", dir, segs[i].name) >= (int)sizeof(tmp)) {
			err = FZN_LOG_PACK_ERR_MALFORMED;
			break;
		}
		/* NO ENTRY RULE: the whole-segment plan, unread. */
		readable = entries && read_all(path, segs[i].packed, &b, &len);
		body = len;
		/* A PACKED ONE IS READ ONLY WHOLE AND SOUND: its trailer the last
		 * line, the chain over the rest from its own prev. */
		if (readable && segs[i].packed) {
			uint8_t check[FZN_LOG_PACK_HASH_LEN];

			for (body = len ? len - 1u : 0u; body > 0u && b[body - 1u] != '\n'; body--)
				;
			readable = len >= 2u && len - body <= TRAILER_MAX
			           && parse_trailer(b + body, len - body, &tr)
			           && chain_over(hash, tr.prev, b, body, check)
			           && memcmp(check, tr.hash, FZN_LOG_PACK_HASH_LEN) == 0;
		}
		if (readable) {
			for (j = 0; j < body; j++)
				if (j == 0u || b[j - 1u] == '\n')
					lines++;
			starts = malloc((lines ? lines : 1u) * sizeof(*starts));
			drop = malloc(lines ? lines : 1u);
			readable = starts && drop;
		}
		if (!readable) {
			all = marks[i] == FZN_RETAIN_MARK_PRUNED;
		} else {
			for (j = 0, lines = 0; j < body; j++)
				if (j == 0u || b[j - 1u] == '\n')
					starts[lines++] = j;
			all = judge(&walk, marks[i], b, body, starts, lines, drop, &dropped);
		}
		if (all) {
			/* GONE ALREADY is another instance's pass, and fine. */
			if (remove(path) != 0 && errno != ENOENT)
				err = FZN_LOG_PACK_ERR_FILE;
			else
				(*removed)++;
		} else if (readable && dropped && segs[i].packed) {
			err = repack(path, tmp, b, len, body, starts, lines, drop, dropped, &tr, hash,
			             signer);
			if (err == FZN_LOG_PACK_OK)
				(*repacked)++;
		}
		free(b);
		free(starts);
		free(drop);
	}
done:
	lk.l_type = F_UNLCK;
	(void)fcntl(fd, F_SETLK, &lk);
	(void)close(fd);
	return err;
}

/* ---- the fossil class, sec 588 ------------------------------------------- */

/* `from` copied to `to` through `tmp`, synced and renamed into place. */
static int copy_whole(const char *from, const char *tmp, const char *to)
{
	static uint8_t buf[65536];
	ssize_t got;
	int in, out, ok = 1;

	in = open(from, O_RDONLY | O_CLOEXEC);
	if (in < 0)
		return 0;
	out = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (out < 0) {
		(void)close(in);
		return 0;
	}
	while (ok && (got = read(in, buf, sizeof(buf))) != 0) {
		if (got < 0)
			ok = errno == EINTR;
		else
			ok = write(out, buf, (size_t)got) == got;
	}
	ok = ok && fsync(out) == 0;
	ok = (close(out) == 0) && ok;
	(void)close(in);
	if (!ok || rename(tmp, to) != 0) {
		(void)remove(tmp);
		return 0;
	}
	return 1;
}

fzn_log_pack_err_t fzn_log_pack_archive(const char *dir, const char *program,
                                        const fzn_retain_rule_t *rules, size_t n_rules,
                                        const char *archive, uint64_t now_us,
                                        size_t *archived)
{
	static struct held segs[SEGMENTS_MAX];
	static fzn_retain_segment_t sizes[SEGMENTS_MAX];
	static uint8_t marks[SEGMENTS_MAX];
	char chain_path[PATH_MAX_], path[PATH_MAX_], dest[PATH_MAX_], tmp[PATH_MAX_];
	fzn_log_pack_err_t err = FZN_LOG_PACK_OK;
	struct flock lk;
	struct dirent *e;
	size_t n = 0, i;
	int fd, k;
	DIR *d;

	if (!dir || !program || !program[0] || strchr(program, '/') || (!rules && n_rules)
	    || !archive || !archive[0] || !archived)
		return FZN_LOG_PACK_ERR_MALFORMED;
	*archived = 0;
	k = snprintf(chain_path, sizeof(chain_path), "%s/%s.chain", dir, program);
	if (k <= 0 || (size_t)k >= sizeof(chain_path))
		return FZN_LOG_PACK_ERR_MALFORMED;
	fd = open(chain_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (fd < 0)
		return FZN_LOG_PACK_ERR_FILE;
	memset(&lk, 0, sizeof(lk));
	lk.l_type = F_WRLCK;
	lk.l_whence = SEEK_SET;
	if (fcntl(fd, F_SETLK, &lk) != 0) {
		(void)close(fd);
		return (errno == EACCES || errno == EAGAIN) ? FZN_LOG_PACK_OK : FZN_LOG_PACK_ERR_FILE;
	}
	d = opendir(dir);
	if (!d) {
		err = FZN_LOG_PACK_ERR_FILE;
		goto done;
	}
	while ((e = readdir(d)) != NULL && n < SEGMENTS_MAX) {
		struct held h;

		h.at = segment_at(e->d_name, program, &h.packed);
		if (h.at == 0u || strlen(e->d_name) >= sizeof(h.name))
			continue;
		strcpy(h.name, e->d_name);
		segs[n++] = h;
	}
	(void)closedir(d);
	qsort(segs, n, sizeof(segs[0]), newest_first);
	for (i = 0; i < n; i++) {
		struct stat st;

		(void)snprintf(path, sizeof(path), "%s/%s", dir, segs[i].name);
		sizes[i].closed_us = segs[i].at;
		sizes[i].bytes = stat(path, &st) == 0 && st.st_size > 0 ? (uint64_t)st.st_size : 0u;
	}
	if (fzn_retain_marks(program, sizes, n, rules, n_rules, now_us, marks) != FZN_RETAIN_OK) {
		err = FZN_LOG_PACK_ERR_MALFORMED;
		goto done;
	}
	for (i = 0; i < n && err == FZN_LOG_PACK_OK; i++) {
		if (!segs[i].packed || !(marks[i] & FZN_RETAIN_MARK_ARCHIVED)
		    || (marks[i] & FZN_RETAIN_MARK_KEPT))
			continue;
		if (snprintf(path, sizeof(path), "%s/%s", dir, segs[i].name) >= (int)sizeof(path)
		    || snprintf(dest, sizeof(dest), "%s/%s", archive, segs[i].name)
		               >= (int)sizeof(dest)
		    || snprintf(tmp, sizeof(tmp), "%s/%s.new", archive, segs[i].name)
		               >= (int)sizeof(tmp)) {
			err = FZN_LOG_PACK_ERR_MALFORMED;
			break;
		}
		if (mkdir(archive, 0700) != 0 && errno != EEXIST) {
			err = FZN_LOG_PACK_ERR_FILE;
			break;
		}
		if (rename(path, dest) == 0) {
			(*archived)++;
			continue;
		}
		/* GONE ALREADY is another instance's pass, and fine. */
		if (errno == ENOENT)
			continue;
		if (errno != EXDEV || !copy_whole(path, tmp, dest)
		    || (remove(path) != 0 && errno != ENOENT)) {
			err = FZN_LOG_PACK_ERR_FILE;
			break;
		}
		(*archived)++;
	}
done:
	lk.l_type = F_UNLCK;
	(void)fcntl(fd, F_SETLK, &lk);
	(void)close(fd);
	return err;
}

/* ---- checking a directory's chain, sec 482 ------------------------------ */

fzn_log_pack_err_t fzn_log_pack_check(const char *dir, const char *program,
                                      const fzn_hash_ops_t *hash, const fzn_sign_ops_t *sign,
                                      fzn_log_pack_report_t *report)
{
	static struct held segs[SEGMENTS_MAX];
	static trailer_t tr;
	char path[PATH_MAX_];
	uint8_t prev[FZN_LOG_PACK_HASH_LEN], next[FZN_LOG_PACK_HASH_LEN];
	struct dirent *e;
	size_t n = 0, i;
	DIR *d;

	if (!dir || !program || !program[0] || strchr(program, '/') || !hash || !hash->hash || !sign
	    || !report)
		return FZN_LOG_PACK_ERR_MALFORMED;
	memset(report, 0, sizeof(*report));
	d = opendir(dir);
	if (!d)
		return FZN_LOG_PACK_ERR_FILE;
	while ((e = readdir(d)) != NULL && n < SEGMENTS_MAX) {
		struct held h;

		h.at = segment_at(e->d_name, program, &h.packed);
		if (h.at == 0u || !h.packed || strlen(e->d_name) >= sizeof(h.name))
			continue;
		strcpy(h.name, e->d_name);
		segs[n++] = h;
	}
	(void)closedir(d);
	/* OLDEST FIRST: the order the chain runs. */
	qsort(segs, n, sizeof(segs[0]), newest_first);
	for (i = 0; i < n / 2u; i++) {
		struct held t = segs[i];

		segs[i] = segs[n - 1u - i];
		segs[n - 1u - i] = t;
	}
	for (i = 0; i < n; i++) {
		fzn_log_pack_err_t err;
		int is_signed = 0;
		uint8_t key[FZN_LOG_PACK_HASH_LEN];

		if (snprintf(path, sizeof(path), "%s/%s", dir, segs[i].name) >= (int)sizeof(path))
			return FZN_LOG_PACK_ERR_MALFORMED;
		/* THE OLDEST HELD starts from the prev its own trailer names:
		 * older segments may have been pruned, and the chain is
		 * verifiable from the oldest kept (sec 460). */
		if (i == 0u) {
			uint8_t *b = NULL;
			size_t len = 0, body;
			int ok;

			if (!read_all(path, 1, &b, &len)) {
				snprintf(report->broken, sizeof(report->broken), "%.255s", segs[i].name);
				return FZN_LOG_PACK_ERR_ZSTD;
			}
			for (body = len ? len - 1u : 0u; body > 0u && b[body - 1u] != '\n'; body--)
				;
			ok = len >= 2u && len - body <= TRAILER_MAX && parse_trailer(b + body, len - body, &tr);
			if (ok)
				memcpy(prev, tr.prev, sizeof(prev));
			free(b);
			if (!ok) {
				snprintf(report->broken, sizeof(report->broken), "%.255s", segs[i].name);
				return FZN_LOG_PACK_ERR_CHAIN;
			}
		}
		err = fzn_log_pack_verify_signed(path, prev, hash, sign, next, &is_signed, key);
		if (err != FZN_LOG_PACK_OK) {
			snprintf(report->broken, sizeof(report->broken), "%.255s", segs[i].name);
			return err;
		}
		report->segments++;
		if (is_signed) {
			/* WHO SIGNED: one key throughout is the ordinary case, and a
			 * second is said, since a host signs only its own. */
			if (report->signed_count && memcmp(key, report->signer, sizeof(key)) != 0)
				report->signers_differ = 1;
			if (!report->signed_count)
				memcpy(report->signer, key, sizeof(key));
			report->signed_count++;
		}
		memcpy(prev, next, sizeof(prev));
	}
	return FZN_LOG_PACK_OK;
}

fzn_log_pack_err_t fzn_log_pack_trailer_prev(const char *zst_path,
                                             uint8_t prev[FZN_LOG_PACK_HASH_LEN])
{
	static trailer_t tr;
	uint8_t *b = NULL;
	size_t len = 0, body;
	int ok;

	if (!zst_path || !prev)
		return FZN_LOG_PACK_ERR_MALFORMED;
	if (!read_all(zst_path, 1, &b, &len))
		return FZN_LOG_PACK_ERR_ZSTD;
	for (body = len ? len - 1u : 0u; body > 0u && b[body - 1u] != '\n'; body--)
		;
	ok = len >= 2u && len - body <= TRAILER_MAX && parse_trailer(b + body, len - body, &tr);
	free(b);
	if (!ok)
		return FZN_LOG_PACK_ERR_CHAIN;
	memcpy(prev, tr.prev, FZN_LOG_PACK_HASH_LEN);
	return FZN_LOG_PACK_OK;
}
