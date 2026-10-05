/* See copy.h. */

#define _POSIX_C_SOURCE 200809L

#include "copy.h"

#include "../wire/bytes.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PATH_MAX_ 512u
/* A part's head: version, type, done, total, offset, length. */
#define PART_HEAD (2u + 1u + 8u + 8u + 4u)
/* A listing's head: version, type, done, count. */
#define LIST_HEAD 4u
/* A query at its longest: version, type, a name, a key or an offset. */
#define QUERY_MAX (2u + 1u + 255u + 8u)

static const char HEX[] = "0123456789abcdef";

const char *fzn_log_copy_err_str(fzn_log_copy_err_t err)
{
	switch (err) {
	case FZN_LOG_COPY_OK:
		return "ok";
	case FZN_LOG_COPY_ERR_MALFORMED:
		return "malformed";
	case FZN_LOG_COPY_ERR_NO_ANSWER:
		return "the host did not answer";
	case FZN_LOG_COPY_ERR_REFUSED:
		return "the host answered with something else";
	case FZN_LOG_COPY_ERR_FILE:
		return "the copy directory would not write";
	case FZN_LOG_COPY_ERR_VERIFY:
		return "a segment did not chain, or was not signed by its host";
	}
	return "unknown";
}

static int program_ok(const char *p, size_t n)
{
	size_t i;

	if (n == 0u || n > FZN_ENTRY_WORD_MAX)
		return 0;
	for (i = 0; i < n; i++)
		if (p[i] == '/' || p[i] == '.' || (unsigned char)p[i] < 0x21u
		    || (unsigned char)p[i] > 0x7eu)
			return 0;
	return 1;
}

/* `PROGRAM.TIME.PID.log.zst`, `program` given or any: its closing time, or
 * 0. The only names this module reads, serves or writes. */
static uint64_t packed_key(const char *name, const char *program)
{
	const char *dot = strchr(name, '.'), *t, *end;
	size_t n = strlen(name), i;
	uint64_t v = 0;

	if (!dot || n < 9u || strcmp(name + n - 8u, ".log.zst") != 0 || strchr(name, '/'))
		return 0;
	if (!program_ok(name, (size_t)(dot - name))
	    || (program && (strlen(program) != (size_t)(dot - name)
	                    || memcmp(name, program, (size_t)(dot - name)) != 0)))
		return 0;
	t = dot + 1;
	end = strchr(t, '.');
	if (!end || end == t)
		return 0;
	for (; t < end; t++) {
		if (*t < '0' || *t > '9' || v > (UINT64_MAX - 9u) / 10u)
			return 0;
		v = (v * 10u) + (uint64_t)(*t - '0');
	}
	t = end + 1;
	end = strchr(t, '.');
	if (!end || end == t || end != name + n - 8u)
		return 0;
	for (i = 0; t + i < end; i++)
		if (t[i] < '0' || t[i] > '9')
			return 0;
	return v;
}

int fzn_log_copy_dir(const char *dir, const uint8_t host[FZN_LOG_PACK_HASH_LEN], char *out,
                     size_t cap)
{
	char hex[(FZN_LOG_PACK_HASH_LEN * 2u) + 1u];
	size_t i;
	int k;

	if (!dir || !host || !out)
		return 0;
	for (i = 0; i < FZN_LOG_PACK_HASH_LEN; i++) {
		hex[2u * i] = HEX[host[i] >> 4];
		hex[(2u * i) + 1u] = HEX[host[i] & 15u];
	}
	hex[sizeof(hex) - 1u] = '\0';
	k = snprintf(out, cap, "%s/copy/%s", dir, hex);
	return k > 0 && (size_t)k < cap;
}

/* ---- the host's answer --------------------------------------------------- */

struct listed {
	uint64_t key;
	char name[256];
};

static int by_key(const void *a, const void *b)
{
	const struct listed *x = a, *y = b;

	if (x->key != y->key)
		return x->key < y->key ? -1 : 1;
	return strcmp(x->name, y->name);
}

static size_t answer_segments(const char *dir, const uint8_t *q, size_t len, uint8_t *reply,
                              size_t cap)
{
	static struct listed all[1024];
	char program[FZN_ENTRY_WORD_MAX + 1u], path[PATH_MAX_];
	size_t n = 0, i, used = LIST_HEAD, pn;
	uint64_t after;
	unsigned count = 0;
	struct dirent *e;
	DIR *d;

	if (len < 3u || q[2] == 0u || len != 3u + q[2] + 8u || cap < LIST_HEAD)
		return 0;
	pn = q[2];
	if (!program_ok((const char *)q + 3, pn))
		return 0;
	memcpy(program, q + 3, pn);
	program[pn] = '\0';
	after = fzn_get_be64(q + 3 + pn);
	d = opendir(dir);
	if (!d)
		return 0;
	while ((e = readdir(d)) != NULL && n < sizeof(all) / sizeof(all[0])) {
		uint64_t k = packed_key(e->d_name, program);

		if (k == 0u || k <= after || strlen(e->d_name) >= sizeof(all[0].name))
			continue;
		all[n].key = k;
		strcpy(all[n].name, e->d_name);
		n++;
	}
	(void)closedir(d);
	qsort(all, n, sizeof(all[0]), by_key);
	for (i = 0; i < n && count < FZN_LOG_COPY_LIST_MAX; i++) {
		size_t nl = strlen(all[i].name);
		struct stat st;

		if (snprintf(path, sizeof(path), "%s/%s", dir, all[i].name) >= (int)sizeof(path)
		    || stat(path, &st) != 0 || st.st_size <= 0)
			continue;
		if (cap - used < 1u + nl + 8u)
			break;
		reply[used++] = (uint8_t)nl;
		memcpy(reply + used, all[i].name, nl);
		used += nl;
		fzn_put_be64(reply + used, (uint64_t)st.st_size);
		used += 8u;
		count++;
	}
	reply[0] = (uint8_t)FZN_GATHER_VERSION;
	reply[1] = (uint8_t)FZN_LOG_COPY_SEGMENTS;
	reply[2] = (uint8_t)(i == n);
	reply[3] = (uint8_t)count;
	return used;
}

static size_t answer_part(const char *dir, const uint8_t *q, size_t len, uint8_t *reply,
                          size_t cap)
{
	char name[256], path[PATH_MAX_];
	uint64_t offset, total;
	size_t nl, got = 0, room;
	struct stat st;
	FILE *f;

	if (len < 3u || q[2] == 0u || len != 3u + q[2] + 8u || cap <= PART_HEAD)
		return 0;
	nl = q[2];
	memcpy(name, q + 3, nl);
	name[nl] = '\0';
	/* ONLY A PACKED SEGMENT, by its own name: nothing else in the
	 * directory -- the current file, the chain's head -- is served. */
	if (memchr(name, '\0', nl) || packed_key(name, NULL) == 0u
	    || snprintf(path, sizeof(path), "%s/%s", dir, name) >= (int)sizeof(path))
		return 0;
	offset = fzn_get_be64(q + 3 + nl);
	f = fopen(path, "rb");
	if (!f)
		return 0;
	if (fstat(fileno(f), &st) != 0 || st.st_size < 0 || (uint64_t)st.st_size < offset
	    || fseek(f, (long)offset, SEEK_SET) != 0) {
		(void)fclose(f);
		return 0;
	}
	total = (uint64_t)st.st_size;
	room = cap - PART_HEAD;
	if (room > 0xffffffffu)
		room = 0xffffffffu;
	if (total - offset < room)
		room = (size_t)(total - offset);
	if (room)
		got = fread(reply + PART_HEAD, 1u, room, f);
	(void)fclose(f);
	if (got != room)
		return 0;
	reply[0] = (uint8_t)FZN_GATHER_VERSION;
	reply[1] = (uint8_t)FZN_LOG_COPY_PART;
	reply[2] = (uint8_t)(offset + got == total);
	fzn_put_be64(reply + 3, total);
	fzn_put_be64(reply + 11, offset);
	fzn_put_be32(reply + 19, (uint32_t)got);
	return PART_HEAD + got;
}

size_t fzn_log_copy_answer(const char *dir, const uint8_t *request, size_t request_len,
                           uint8_t *reply, size_t reply_cap)
{
	if (!dir || !request || !reply || request_len < 2u || request[0] != FZN_GATHER_VERSION)
		return 0;
	if (request[1] == FZN_LOG_COPY_SEGMENTS_QUERY)
		return answer_segments(dir, request, request_len, reply, reply_cap);
	if (request[1] == FZN_LOG_COPY_PART_QUERY)
		return answer_part(dir, request, request_len, reply, reply_cap);
	return 0;
}

/* ---- the puller ---------------------------------------------------------- */

static int make_dir(const char *path)
{
	char at[PATH_MAX_];
	size_t i, n = strlen(path);

	if (n == 0u || n >= sizeof(at))
		return 0;
	memcpy(at, path, n + 1u);
	/* EACH LEVEL, owner-only: a copy is somebody else's log. */
	for (i = 1; i <= n; i++)
		if (at[i] == '/' || at[i] == '\0') {
			char c = at[i];

			at[i] = '\0';
			if (mkdir(at, 0700) != 0 && errno != EEXIST)
				return 0;
			at[i] = c;
		}
	return 1;
}

/* The head of the copy's chain, `PROGRAM.chain`: 1 read, 0 none, -1 bad. */
static int read_head(const char *copy_dir, const char *program, uint8_t head[32])
{
	char path[PATH_MAX_], t[66];
	size_t i;
	FILE *f;

	if (snprintf(path, sizeof(path), "%s/%s.chain", copy_dir, program) >= (int)sizeof(path))
		return -1;
	f = fopen(path, "r");
	if (!f)
		return errno == ENOENT ? 0 : -1;
	i = fread(t, 1u, sizeof(t), f);
	(void)fclose(f);
	if (i != 65u || t[64] != '\n')
		return -1;
	for (i = 0; i < 64u; i++) {
		const char *h = strchr(HEX, t[i]);

		if (!h || !t[i])
			return -1;
		if (i % 2u == 0u)
			head[i / 2u] = (uint8_t)((h - HEX) << 4);
		else
			head[i / 2u] = (uint8_t)(head[i / 2u] | (uint8_t)(h - HEX));
	}
	return 1;
}

static int write_head(const char *copy_dir, const char *program, const uint8_t head[32])
{
	char path[PATH_MAX_], tmp[PATH_MAX_ + 8u], t[65];
	size_t i;
	FILE *f;

	for (i = 0; i < 32u; i++) {
		t[2u * i] = HEX[head[i] >> 4];
		t[(2u * i) + 1u] = HEX[head[i] & 15u];
	}
	t[64] = '\n';
	if (snprintf(path, sizeof(path), "%s/%s.chain", copy_dir, program) >= (int)sizeof(path)
	    || snprintf(tmp, sizeof(tmp), "%s.new", path) >= (int)sizeof(tmp))
		return 0;
	f = fopen(tmp, "w");
	if (!f)
		return 0;
	if (fwrite(t, 1u, 65u, f) != 65u || fflush(f) != 0 || fsync(fileno(f)) != 0) {
		(void)fclose(f);
		(void)remove(tmp);
		return 0;
	}
	if (fclose(f) != 0 || rename(tmp, path) != 0) {
		(void)remove(tmp);
		return 0;
	}
	return 1;
}

/* The newest copy held: its key, 0 for none. */
static uint64_t newest_held(const char *copy_dir, const char *program)
{
	uint64_t best = 0;
	struct dirent *e;
	DIR *d = opendir(copy_dir);

	if (!d)
		return 0;
	while ((e = readdir(d)) != NULL) {
		uint64_t k = packed_key(e->d_name, program);

		if (k > best)
			best = k;
	}
	(void)closedir(d);
	return best;
}

/* One segment, fetched whole into `buf`, `size` bytes as listed. */
static fzn_log_copy_err_t fetch(fzn_gather_ask_t ask, void *ask_ctx, const char *name,
                                uint8_t *buf, uint64_t size)
{
	static uint8_t reply[1u << 17];
	uint8_t q[QUERY_MAX];
	size_t nl = strlen(name);
	uint64_t at = 0;

	q[0] = (uint8_t)FZN_GATHER_VERSION;
	q[1] = (uint8_t)FZN_LOG_COPY_PART_QUERY;
	q[2] = (uint8_t)nl;
	memcpy(q + 3, name, nl);
	while (at < size) {
		size_t reply_len = 0;
		uint32_t got;

		fzn_put_be64(q + 3 + nl, at);
		if (!ask(ask_ctx, q, 3u + nl + 8u, reply, sizeof(reply), &reply_len))
			return FZN_LOG_COPY_ERR_NO_ANSWER;
		if (reply_len < PART_HEAD || reply[0] != FZN_GATHER_VERSION
		    || reply[1] != FZN_LOG_COPY_PART)
			return FZN_LOG_COPY_ERR_REFUSED;
		got = fzn_get_be32(reply + 19);
		/* THE BYTES ASKED FOR, of the size listed, and some: a host that
		 * answers another offset, a changed size or nothing is refused. */
		if (fzn_get_be64(reply + 3) != size || fzn_get_be64(reply + 11) != at
		    || reply_len != PART_HEAD + got || got == 0u || got > size - at)
			return FZN_LOG_COPY_ERR_REFUSED;
		memcpy(buf + at, reply + PART_HEAD, got);
		at += got;
	}
	return FZN_LOG_COPY_OK;
}

fzn_log_copy_err_t fzn_log_copy_pull(fzn_gather_ask_t ask, void *ask_ctx, const char *program,
                                     const uint8_t host[FZN_LOG_PACK_HASH_LEN],
                                     const char *copy_dir, const fzn_hash_ops_t *hash,
                                     const fzn_sign_ops_t *sign, fzn_log_copy_tally_t *tally)
{
	static uint8_t reply[1u << 17];
	static struct listed cur;
	uint8_t head[32];
	size_t pages = 0;
	int have_head;
	uint64_t after;

	if (!ask || !program || !program_ok(program, strlen(program)) || !host || !copy_dir || !hash
	    || !sign || !tally)
		return FZN_LOG_COPY_ERR_MALFORMED;
	memset(tally, 0, sizeof(*tally));
	if (!make_dir(copy_dir))
		return FZN_LOG_COPY_ERR_FILE;
	have_head = read_head(copy_dir, program, head);
	if (have_head < 0)
		return FZN_LOG_COPY_ERR_FILE;
	after = newest_held(copy_dir, program);
	/* BOUNDED BY PAGES, not by the host's word. */
	while (pages++ < 1024u) {
		uint8_t q[QUERY_MAX];
		size_t pn = strlen(program), reply_len = 0, at = LIST_HEAD, i;
		int done;

		q[0] = (uint8_t)FZN_GATHER_VERSION;
		q[1] = (uint8_t)FZN_LOG_COPY_SEGMENTS_QUERY;
		q[2] = (uint8_t)pn;
		memcpy(q + 3, program, pn);
		fzn_put_be64(q + 3 + pn, after);
		if (!ask(ask_ctx, q, 3u + pn + 8u, reply, sizeof(reply), &reply_len))
			return FZN_LOG_COPY_ERR_NO_ANSWER;
		if (reply_len < LIST_HEAD || reply[0] != FZN_GATHER_VERSION
		    || reply[1] != FZN_LOG_COPY_SEGMENTS || reply[2] > 1u
		    || reply[3] > FZN_LOG_COPY_LIST_MAX)
			return FZN_LOG_COPY_ERR_REFUSED;
		done = reply[2];
		for (i = 0; i < reply[3]; i++) {
			size_t nl;

			if (at >= reply_len || (nl = reply[at]) == 0u || reply_len - at < 1u + nl + 8u)
				return FZN_LOG_COPY_ERR_REFUSED;
			memcpy(cur.name, reply + at + 1, nl);
			cur.name[nl] = '\0';
			/* A NAME THAT IS NOT ONE OF THIS PROGRAM'S SEGMENTS, or one
			 * not after the last, is a host answering something else. */
			cur.key = packed_key(cur.name, program);
			if (cur.key <= after || memchr(cur.name, '\0', nl))
				return FZN_LOG_COPY_ERR_REFUSED;
			{
				uint64_t size = fzn_get_be64(reply + at + 1 + nl);
				char path[PATH_MAX_], tmp[PATH_MAX_ + 8u];
				uint8_t prev[32], next[32], key[32];
				uint8_t *buf;
				fzn_log_copy_err_t err;
				fzn_log_pack_err_t perr;
				int is_signed = 0;
				FILE *f;

				at += 1u + nl + 8u;
				if (size == 0u || size > FZN_LOG_COPY_SEGMENT_MAX) {
					snprintf(tally->refused, sizeof(tally->refused), "%.255s", cur.name);
					return FZN_LOG_COPY_ERR_VERIFY;
				}
				if (snprintf(path, sizeof(path), "%s/%s", copy_dir, cur.name)
				            >= (int)sizeof(path)
				    || snprintf(tmp, sizeof(tmp), "%s.new", path) >= (int)sizeof(tmp))
					return FZN_LOG_COPY_ERR_MALFORMED;
				buf = malloc((size_t)size);
				if (!buf)
					return FZN_LOG_COPY_ERR_FILE;
				err = fetch(ask, ask_ctx, cur.name, buf, size);
				if (err == FZN_LOG_COPY_OK) {
					f = fopen(tmp, "wb");
					if (!f || fwrite(buf, 1u, (size_t)size, f) != (size_t)size
					    || fflush(f) != 0 || fsync(fileno(f)) != 0)
						err = FZN_LOG_COPY_ERR_FILE;
					if (f && fclose(f) != 0)
						err = FZN_LOG_COPY_ERR_FILE;
				}
				free(buf);
				if (err != FZN_LOG_COPY_OK) {
					(void)remove(tmp);
					return err;
				}
				/* VERIFIED BEFORE KEPT: chained from the last copy, the
				 * first from its own prev, and signed by THIS host. */
				if (have_head)
					memcpy(prev, head, sizeof(prev));
				perr = have_head ? FZN_LOG_PACK_OK : fzn_log_pack_trailer_prev(tmp, prev);
				if (perr == FZN_LOG_PACK_OK)
					perr = fzn_log_pack_verify_signed(tmp, prev, hash, sign, next,
					                                  &is_signed, key);
				if (perr != FZN_LOG_PACK_OK || !is_signed
				    || memcmp(key, host, sizeof(key)) != 0) {
					(void)remove(tmp);
					snprintf(tally->refused, sizeof(tally->refused), "%.255s",
					         cur.name);
					return FZN_LOG_COPY_ERR_VERIFY;
				}
				if (rename(tmp, path) != 0 || !write_head(copy_dir, program, next)) {
					(void)remove(tmp);
					return FZN_LOG_COPY_ERR_FILE;
				}
				memcpy(head, next, sizeof(head));
				have_head = 1;
				after = cur.key;
				tally->copied++;
				tally->bytes += (size_t)size;
			}
		}
		if (done)
			return FZN_LOG_COPY_OK;
		if (reply[3] == 0u)
			return FZN_LOG_COPY_ERR_REFUSED;
	}
	return FZN_LOG_COPY_ERR_REFUSED;
}
