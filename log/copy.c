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
	case FZN_LOG_COPY_ERR_DECLINED:
		return "the member takes no copies of that program";
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

/* VERIFIED BEFORE KEPT, pulled or pushed: `tmp` chains from the last copy
 * of `program` held in `copy_dir` -- the first from the prev its own trailer
 * names -- and is signed by `host`. Only then is it renamed to `path` and the
 * chain's head written; otherwise it is removed. */
static fzn_log_copy_err_t keep(const char *copy_dir, const char *program, const char *tmp,
                               const char *path, const uint8_t host[32],
                               const fzn_hash_ops_t *hash, const fzn_sign_ops_t *sign)
{
	uint8_t prev[32], next[32], key[32];
	fzn_log_pack_err_t perr;
	int is_signed = 0, have_head = read_head(copy_dir, program, prev);

	/* NO SIGNER UNTIL ONE IS READ: an unsigned trailer writes none, and a
	 * key left from anything else must not pass for the host's. */
	memset(key, 0, sizeof(key));

	if (have_head < 0) {
		(void)remove(tmp);
		return FZN_LOG_COPY_ERR_FILE;
	}
	perr = have_head ? FZN_LOG_PACK_OK : fzn_log_pack_trailer_prev(tmp, prev);
	if (perr == FZN_LOG_PACK_OK)
		perr = fzn_log_pack_verify_signed(tmp, prev, hash, sign, next, &is_signed, key);
	if (perr != FZN_LOG_PACK_OK || !is_signed || memcmp(key, host, sizeof(key)) != 0) {
		(void)remove(tmp);
		return FZN_LOG_COPY_ERR_VERIFY;
	}
	if (rename(tmp, path) != 0 || !write_head(copy_dir, program, next)) {
		(void)remove(tmp);
		return FZN_LOG_COPY_ERR_FILE;
	}
	return FZN_LOG_COPY_OK;
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
	size_t pages = 0;
	uint64_t after;

	if (!ask || !program || !program_ok(program, strlen(program)) || !host || !copy_dir || !hash
	    || !sign || !tally)
		return FZN_LOG_COPY_ERR_MALFORMED;
	memset(tally, 0, sizeof(*tally));
	if (!make_dir(copy_dir))
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
				uint8_t *buf;
				fzn_log_copy_err_t err;
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
				err = keep(copy_dir, program, tmp, path, host, hash, sign);
				if (err == FZN_LOG_COPY_ERR_VERIFY)
					snprintf(tally->refused, sizeof(tally->refused), "%.255s",
					         cur.name);
				if (err != FZN_LOG_COPY_OK)
					return err;
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

/* ---- pushed, sec 488 ------------------------------------------------------ */

/* A push_took's length: version, type, status, held. */
#define TOOK_LEN (2u + 1u + 8u)
/* A push_part's head: version, type, the name's length; then the name,
 * total, offset and length. */
#define PUSH_HEAD(nl) (3u + (nl) + 8u + 8u + 4u)
/* Parts one segment's push may be answered out of place before the pusher
 * gives up on it, so two hosts that disagree cannot loop. */
#define RESYNC_MAX 4u

/* `program` among `programs`. */
static int takes(const char *const *programs, size_t n, const char *program, size_t len)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (programs[i] && strlen(programs[i]) == len && memcmp(programs[i], program, len) == 0)
			return 1;
	return 0;
}

static size_t took(uint8_t *reply, size_t cap, unsigned status, uint64_t held)
{
	if (cap < TOOK_LEN)
		return 0;
	reply[0] = (uint8_t)FZN_GATHER_VERSION;
	reply[1] = (uint8_t)FZN_LOG_COPY_PUSH_TOOK;
	reply[2] = (uint8_t)status;
	fzn_put_be64(reply + 3, held);
	return TOOK_LEN;
}

/* PARTIALS LEFT BEHIND, `PROGRAM.*.log.zst.new` for segments no newer than
 * `upto`: a push broken off for a segment since passed by. By name. */
static void drop_partials(const char *copy_dir, const char *program, uint64_t upto)
{
	char path[PATH_MAX_], name[256];
	struct dirent *e;
	DIR *d = opendir(copy_dir);
	size_t n;

	if (!d)
		return;
	while ((e = readdir(d)) != NULL) {
		n = strlen(e->d_name);
		if (n < 5u || n >= sizeof(name) || strcmp(e->d_name + n - 4u, ".new") != 0)
			continue;
		memcpy(name, e->d_name, n - 4u);
		name[n - 4u] = '\0';
		{
			uint64_t k = packed_key(name, program);

			if (k != 0u && k <= upto
			    && snprintf(path, sizeof(path), "%s/%s", copy_dir, e->d_name)
			               < (int)sizeof(path))
				(void)remove(path);
		}
	}
	(void)closedir(d);
}

static size_t take_part(const char *dir, const uint8_t sender[32], const char *const *programs,
                        size_t n_programs, const fzn_hash_ops_t *hash,
                        const fzn_sign_ops_t *sign, const uint8_t *q, size_t len,
                        uint8_t *reply, size_t cap, fzn_log_copy_took_note_t *note)
{
	char name[256], copy_dir[PATH_MAX_], path[PATH_MAX_], tmp[PATH_MAX_ + 8u];
	const char *dot;
	uint64_t key, total, offset, have = 0;
	uint32_t part;
	size_t nl;
	struct stat st;
	FILE *f;

	if (len < 3u || q[2] == 0u || len < PUSH_HEAD(q[2]))
		return 0;
	nl = q[2];
	memcpy(name, q + 3, nl);
	name[nl] = '\0';
	total = fzn_get_be64(q + 3 + nl);
	offset = fzn_get_be64(q + 3 + nl + 8u);
	part = fzn_get_be32(q + 3 + nl + 16u);
	if (len != PUSH_HEAD(nl) + part)
		return 0;
	/* A PACKED SEGMENT OF A PROGRAM THIS NODE TAKES, by its own name. */
	key = memchr(name, '\0', nl) ? 0u : packed_key(name, NULL);
	dot = strchr(name, '.');
	if (key == 0u || !takes(programs, n_programs, name, (size_t)(dot - name)) || total == 0u
	    || total > FZN_LOG_COPY_SEGMENT_MAX || part == 0u || offset > total
	    || part > total - offset)
		return took(reply, cap, FZN_LOG_COPY_TOOK_REFUSED, 0u);
	{
		char program[FZN_ENTRY_WORD_MAX + 1u];

		memcpy(program, name, (size_t)(dot - name));
		program[dot - name] = '\0';
		if (!fzn_log_copy_dir(dir, sender, copy_dir, sizeof(copy_dir)) || !make_dir(copy_dir)
		    || snprintf(path, sizeof(path), "%s/%s", copy_dir, name) >= (int)sizeof(path)
		    || snprintf(tmp, sizeof(tmp), "%s.new", path) >= (int)sizeof(tmp))
			return took(reply, cap, FZN_LOG_COPY_TOOK_REFUSED, 0u);
		/* HELD ALREADY, this one or a newer: nothing to place. */
		if (key <= newest_held(copy_dir, program))
			return took(reply, cap, FZN_LOG_COPY_TOOK_HELD, total);
		if (stat(tmp, &st) == 0 && st.st_size > 0)
			have = (uint64_t)st.st_size;
		/* NOT WHERE THIS NODE IS: said, so the pusher goes on from here. A
		 * partial longer than the segment is no part of it, and restarts. */
		if (have > total) {
			(void)remove(tmp);
			have = 0;
		}
		if (offset != have)
			return took(reply, cap, FZN_LOG_COPY_TOOK_MORE, have);
		f = fopen(tmp, offset ? "ab" : "wb");
		if (!f)
			return took(reply, cap, FZN_LOG_COPY_TOOK_REFUSED, have);
		if (fwrite(q + PUSH_HEAD(nl), 1u, part, f) != part || fflush(f) != 0
		    || (offset + part == total && fsync(fileno(f)) != 0)) {
			(void)fclose(f);
			(void)remove(tmp);
			return took(reply, cap, FZN_LOG_COPY_TOOK_REFUSED, 0u);
		}
		if (fclose(f) != 0) {
			(void)remove(tmp);
			return took(reply, cap, FZN_LOG_COPY_TOOK_REFUSED, 0u);
		}
		if (offset + part < total)
			return took(reply, cap, FZN_LOG_COPY_TOOK_MORE, offset + part);
		/* WHOLE: verified against the SENDER, or removed. */
		if (note)
			snprintf(note->name, sizeof(note->name), "%.255s", name);
		if (keep(copy_dir, program, tmp, path, sender, hash, sign) != FZN_LOG_COPY_OK) {
			if (note)
				note->refused = 1;
			return took(reply, cap, FZN_LOG_COPY_TOOK_REFUSED, 0u);
		}
		drop_partials(copy_dir, program, key);
		if (note)
			note->kept = 1;
		return took(reply, cap, FZN_LOG_COPY_TOOK_KEPT, total);
	}
}

size_t fzn_log_copy_take(const char *dir, const uint8_t sender[FZN_LOG_PACK_HASH_LEN],
                         const char *const *programs, size_t n_programs,
                         const fzn_hash_ops_t *hash, const fzn_sign_ops_t *sign,
                         const uint8_t *request, size_t request_len, uint8_t *reply,
                         size_t reply_cap, fzn_log_copy_took_note_t *note)
{
	if (note)
		memset(note, 0, sizeof(*note));
	if (!dir || !sender || !hash || !sign || !request || !reply || request_len < 2u
	    || request[0] != FZN_GATHER_VERSION)
		return 0;
	if (request[1] == FZN_LOG_COPY_PUSH_QUERY) {
		char copy_dir[PATH_MAX_], program[FZN_ENTRY_WORD_MAX + 1u];
		size_t pn = request_len > 2u ? request[2] : 0u;
		int taking;

		if (pn == 0u || request_len != 3u + pn || !program_ok((const char *)request + 3, pn)
		    || reply_cap < 11u || !fzn_log_copy_dir(dir, sender, copy_dir, sizeof(copy_dir)))
			return 0;
		memcpy(program, request + 3, pn);
		program[pn] = '\0';
		taking = takes(programs, n_programs, program, pn);
		reply[0] = (uint8_t)FZN_GATHER_VERSION;
		reply[1] = (uint8_t)FZN_LOG_COPY_PUSH_AT;
		reply[2] = (uint8_t)taking;
		fzn_put_be64(reply + 3, taking ? newest_held(copy_dir, program) : 0u);
		return 11u;
	}
	if (request[1] == FZN_LOG_COPY_PUSH_PART)
		return take_part(dir, sender, programs, n_programs, hash, sign, request, request_len,
		                 reply, reply_cap, note);
	return 0;
}

/* `program`'s packed segments in `dir` after `after`, oldest first. */
static size_t list_after(const char *dir, const char *program, uint64_t after,
                         struct listed *all, size_t max)
{
	struct dirent *e;
	size_t n = 0;
	DIR *d = opendir(dir);

	if (!d)
		return 0;
	while ((e = readdir(d)) != NULL && n < max) {
		uint64_t k = packed_key(e->d_name, program);

		if (k == 0u || k <= after || strlen(e->d_name) >= sizeof(all[0].name))
			continue;
		all[n].key = k;
		strcpy(all[n].name, e->d_name);
		n++;
	}
	(void)closedir(d);
	qsort(all, n, sizeof(all[0]), by_key);
	return n;
}

fzn_log_copy_err_t fzn_log_copy_push(fzn_gather_ask_t ask, void *ask_ctx, const char *dir,
                                     const char *program, size_t budget,
                                     fzn_log_copy_tally_t *tally)
{
	static struct listed all[1024];
	static uint8_t q[PUSH_HEAD(255u) + FZN_LOG_COPY_PUSH_PART_MAX];
	uint8_t reply[64];
	size_t pn, n, i, reply_len = 0, sent = 0;
	uint64_t after;

	if (!ask || !dir || !program || !program_ok(program, strlen(program)) || !tally)
		return FZN_LOG_COPY_ERR_MALFORMED;
	memset(tally, 0, sizeof(*tally));
	pn = strlen(program);
	q[0] = (uint8_t)FZN_GATHER_VERSION;
	q[1] = (uint8_t)FZN_LOG_COPY_PUSH_QUERY;
	q[2] = (uint8_t)pn;
	memcpy(q + 3, program, pn);
	if (!ask(ask_ctx, q, 3u + pn, reply, sizeof(reply), &reply_len))
		return FZN_LOG_COPY_ERR_NO_ANSWER;
	if (reply_len != 11u || reply[0] != FZN_GATHER_VERSION || reply[1] != FZN_LOG_COPY_PUSH_AT
	    || reply[2] > 1u)
		return FZN_LOG_COPY_ERR_REFUSED;
	if (!reply[2])
		return FZN_LOG_COPY_ERR_DECLINED;
	after = fzn_get_be64(reply + 3);
	n = list_after(dir, program, after, all, sizeof(all) / sizeof(all[0]));
	for (i = 0; i < n; i++) {
		char path[PATH_MAX_];
		size_t nl = strlen(all[i].name);
		unsigned resyncs = 0;
		uint64_t at = 0, size;
		struct stat st;
		FILE *f;

		if (snprintf(path, sizeof(path), "%s/%s", dir, all[i].name) >= (int)sizeof(path))
			return FZN_LOG_COPY_ERR_MALFORMED;
		f = fopen(path, "rb");
		/* GONE SINCE IT WAS LISTED -- pruned, or repacked under it -- is
		 * passed over; the next is its chain's to answer for. */
		if (!f)
			continue;
		if (fstat(fileno(f), &st) != 0 || st.st_size <= 0
		    || (uint64_t)st.st_size > FZN_LOG_COPY_SEGMENT_MAX) {
			(void)fclose(f);
			continue;
		}
		size = (uint64_t)st.st_size;
		while (at < size) {
			size_t chunk = size - at < FZN_LOG_COPY_PUSH_PART_MAX ? (size_t)(size - at)
			                                                      : FZN_LOG_COPY_PUSH_PART_MAX;
			uint64_t held;

			/* THE BUDGET, kept between parts: the rest is the next call's,
			 * from where the member will say it is. */
			if (sent && sent + chunk > budget) {
				(void)fclose(f);
				return FZN_LOG_COPY_OK;
			}
			if (fseek(f, (long)at, SEEK_SET) != 0
			    || fread(q + PUSH_HEAD(nl), 1u, chunk, f) != chunk) {
				(void)fclose(f);
				return FZN_LOG_COPY_ERR_FILE;
			}
			q[1] = (uint8_t)FZN_LOG_COPY_PUSH_PART;
			q[2] = (uint8_t)nl;
			memcpy(q + 3, all[i].name, nl);
			fzn_put_be64(q + 3 + nl, size);
			fzn_put_be64(q + 3 + nl + 8u, at);
			fzn_put_be32(q + 3 + nl + 16u, (uint32_t)chunk);
			if (!ask(ask_ctx, q, PUSH_HEAD(nl) + chunk, reply, sizeof(reply), &reply_len)) {
				(void)fclose(f);
				return FZN_LOG_COPY_ERR_NO_ANSWER;
			}
			if (reply_len != TOOK_LEN || reply[0] != FZN_GATHER_VERSION
			    || reply[1] != FZN_LOG_COPY_PUSH_TOOK || reply[2] > FZN_LOG_COPY_TOOK_HELD) {
				(void)fclose(f);
				return FZN_LOG_COPY_ERR_REFUSED;
			}
			held = fzn_get_be64(reply + 3);
			if (reply[2] == FZN_LOG_COPY_TOOK_REFUSED) {
				(void)fclose(f);
				snprintf(tally->refused, sizeof(tally->refused), "%.255s", all[i].name);
				return FZN_LOG_COPY_ERR_VERIFY;
			}
			if (reply[2] == FZN_LOG_COPY_TOOK_HELD)
				break;
			if (reply[2] == FZN_LOG_COPY_TOOK_KEPT) {
				sent += chunk;
				tally->copied++;
				tally->bytes += (size_t)size;
				break;
			}
			/* MORE: on from where the member is -- after this part when it
			 * took it, elsewhere when it did not, a bounded number of times. */
			if (held > size || (held != at + chunk && ++resyncs > RESYNC_MAX)) {
				(void)fclose(f);
				return FZN_LOG_COPY_ERR_REFUSED;
			}
			if (held == at + chunk)
				sent += chunk;
			at = held;
		}
		(void)fclose(f);
	}
	return FZN_LOG_COPY_OK;
}
