/* See gather.h. */

#define _POSIX_C_SOURCE 200809L

#include "gather.h"

#include "../wire/bytes.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef FZN_LOG_PACK_ON
#include <zstd.h>
#endif

/* Segments one answer lists; past it the newest are read and the oldest
 * wait for retention. */
#define SEGMENTS_MAX 1024u
#define PATH_MAX_ 600u

const char *fzn_gather_err_str(fzn_gather_err_t err)
{
	switch (err) {
	case FZN_GATHER_OK:
		return "ok";
	case FZN_GATHER_ERR_MALFORMED:
		return "malformed";
	case FZN_GATHER_ERR_NO_ANSWER:
		return "the host did not answer";
	case FZN_GATHER_ERR_REFUSED:
		return "the host answered with something else";
	case FZN_GATHER_ERR_FILE:
		return "the log directory would not read";
	}
	return "unknown";
}

static int word_ok(const char *w, size_t max)
{
	size_t i;

	if (!w || !w[0])
		return 0;
	for (i = 0; w[i]; i++) {
		char c = w[i];

		if (i >= max
		    || !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		         || c == '_' || c == '-' || c == '.' || c == '+' || c == '$'))
			return 0;
	}
	return 1;
}

/* ---- the query ----------------------------------------------------------- */

fzn_gather_err_t fzn_gather_query_encode(const fzn_gather_query_t *q, uint8_t *out, size_t cap,
                                         size_t *len)
{
	size_t p, m, at;

	if (!q || !out || !len || !word_ok(q->program, FZN_ENTRY_WORD_MAX)
	    || memchr(q->match, '\0', sizeof(q->match)) == NULL)
		return FZN_GATHER_ERR_MALFORMED;
	p = strlen(q->program);
	m = strlen(q->match);
	if (cap < 2u + 32u + 1u + p + 1u + m)
		return FZN_GATHER_ERR_MALFORMED;
	out[0] = FZN_GATHER_VERSION;
	out[1] = FZN_GATHER_QUERY;
	fzn_put_be64(out + 2, q->since_us);
	fzn_put_be64(out + 10, q->until_us);
	fzn_put_be64(out + 18, q->cursor_key);
	fzn_put_be64(out + 26, q->cursor_off);
	at = 34;
	out[at++] = (uint8_t)p;
	memcpy(out + at, q->program, p);
	at += p;
	out[at++] = (uint8_t)m;
	memcpy(out + at, q->match, m);
	*len = at + m;
	return FZN_GATHER_OK;
}

static int query_decode(const uint8_t *in, size_t len, fzn_gather_query_t *q)
{
	size_t p, m;

	memset(q, 0, sizeof(*q));
	if (len < 36u || in[0] != FZN_GATHER_VERSION || in[1] != FZN_GATHER_QUERY)
		return 0;
	q->since_us = fzn_get_be64(in + 2);
	q->until_us = fzn_get_be64(in + 10);
	q->cursor_key = fzn_get_be64(in + 18);
	q->cursor_off = fzn_get_be64(in + 26);
	p = in[34];
	if (p == 0u || p > FZN_ENTRY_WORD_MAX || len < 35u + p + 1u)
		return 0;
	memcpy(q->program, in + 35, p);
	m = in[35 + p];
	if (m > FZN_GATHER_MATCH_MAX || len != 36u + p + m)
		return 0;
	memcpy(q->match, in + 36 + p, m);
	/* NO NUL INSIDE: a match is compared as a string. */
	return word_ok(q->program, FZN_ENTRY_WORD_MAX) && strlen(q->match) == m;
}

/* ---- the segments -------------------------------------------------------- */

struct segment {
	uint64_t key;
	int packed;
	char name[256];
};

/* `PROGRAM.log` is the current file, the largest key; `PROGRAM.TIME.PID.log`
 * and its `.zst` are closed ones keyed by TIME. 0 for anything else. */
static uint64_t key_of(const char *name, const char *program, int *packed)
{
	size_t plen = strlen(program), i;
	const char *t, *dot;
	uint64_t v = 0;

	*packed = 0;
	if (strncmp(name, program, plen) != 0 || name[plen] != '.')
		return 0;
	t = name + plen + 1u;
	if (strcmp(t, "log") == 0)
		return UINT64_MAX;
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
	if (!dot || dot == t)
		return 0;
	if (strcmp(dot, ".log.zst") == 0)
		*packed = 1;
	else if (strcmp(dot, ".log") != 0)
		return 0;
	for (; t < dot; t++)
		if (*t < '0' || *t > '9')
			return 0;
	return v == UINT64_MAX ? 0 : v;
}

static int by_key(const void *a, const void *b)
{
	const struct segment *x = a, *y = b;

	if (x->key != y->key)
		return x->key < y->key ? -1 : 1;
	return x->packed - y->packed;
}

/* ---- reading a segment's lines ------------------------------------------- */

struct reader {
	FILE *f;
	int packed;
#ifdef FZN_LOG_PACK_ON
	ZSTD_DCtx *dc;
	uint8_t in[1u << 14];
	ZSTD_inBuffer src;
	int ended;
#endif
	uint8_t buf[1u << 15];
	size_t have, at;
};

static int reader_open(struct reader *r, const char *path, int packed)
{
	memset(r, 0, sizeof(*r));
	r->packed = packed;
#ifndef FZN_LOG_PACK_ON
	if (packed)
		return 0;
#endif
	r->f = fopen(path, "rb");
	if (!r->f)
		return 0;
#ifdef FZN_LOG_PACK_ON
	if (packed) {
		r->dc = ZSTD_createDCtx();
		if (!r->dc) {
			(void)fclose(r->f);
			return 0;
		}
		r->src.src = r->in;
	}
#endif
	return 1;
}

static void reader_close(struct reader *r)
{
#ifdef FZN_LOG_PACK_ON
	if (r->dc)
		ZSTD_freeDCtx(r->dc);
#endif
	if (r->f)
		(void)fclose(r->f);
}

/* More bytes into `buf`; 0 at the end or on an error. */
static int reader_fill(struct reader *r)
{
	if (r->at > 0u) {
		memmove(r->buf, r->buf + r->at, r->have - r->at);
		r->have -= r->at;
		r->at = 0;
	}
	if (r->have >= sizeof(r->buf))
		return 0;
	if (!r->packed) {
		size_t n = fread(r->buf + r->have, 1u, sizeof(r->buf) - r->have, r->f);

		r->have += n;
		return n > 0u;
	}
#ifdef FZN_LOG_PACK_ON
	for (;;) {
		ZSTD_outBuffer dst = { r->buf + r->have, sizeof(r->buf) - r->have, 0 };
		size_t rc;

		if (r->src.pos == r->src.size) {
			if (r->ended)
				return 0;
			r->src.size = fread(r->in, 1u, sizeof(r->in), r->f);
			r->src.pos = 0;
			if (r->src.size == 0u) {
				r->ended = 1;
				return 0;
			}
		}
		rc = ZSTD_decompressStream(r->dc, &dst, &r->src);
		if (ZSTD_isError(rc))
			return 0;
		r->have += dst.pos;
		if (dst.pos > 0u)
			return 1;
	}
#else
	return 0;
#endif
}

/* The next line, without its newline, NUL-terminated in place; its length
 * in `*len`, and 0 at the end. A line too long for the buffer is not one. */
static char *reader_line(struct reader *r, size_t *len)
{
	for (;;) {
		uint8_t *nl = memchr(r->buf + r->at, '\n', r->have - r->at);

		if (nl) {
			char *line = (char *)r->buf + r->at;

			*nl = '\0';
			*len = (size_t)(nl - (r->buf + r->at));
			r->at = (size_t)(nl - r->buf) + 1u;
			return line;
		}
		if (!reader_fill(r))
			return NULL;
	}
}

/* ---- the answer ---------------------------------------------------------- */

size_t fzn_gather_answer(const char *dir, const uint8_t *request, size_t request_len,
                         uint8_t *reply, size_t reply_cap)
{
	static struct segment segs[SEGMENTS_MAX];
	static struct reader r;
	char path[PATH_MAX_];
	fzn_gather_query_t q;
	struct dirent *e;
	size_t n = 0, i, used = FZN_GATHER_LINES_HEAD;
	uint64_t key = UINT64_MAX, off = 0;
	unsigned count = 0;
	int done = 1;
	DIR *d;

	if (!request || request_len < 2u || request[0] != FZN_GATHER_VERSION
	    || request[1] != FZN_GATHER_QUERY)
		return 0;
	if (!dir || !reply || reply_cap < FZN_GATHER_LINES_HEAD || !query_decode(request, request_len, &q))
		return 0;
	d = opendir(dir);
	if (!d)
		return 0;
	while ((e = readdir(d)) != NULL && n < SEGMENTS_MAX) {
		int packed = 0;
		uint64_t k = key_of(e->d_name, q.program, &packed);

		if (k == 0u || strlen(e->d_name) >= sizeof(segs[0].name))
			continue;
		segs[n].key = k;
		segs[n].packed = packed;
		strcpy(segs[n].name, e->d_name);
		n++;
	}
	(void)closedir(d);
	qsort(segs, n, sizeof(segs[0]), by_key);
	for (i = 0; i < n && done; i++) {
		char *line;
		size_t len;
		uint64_t at = 0, start;

		/* ONE COPY OF A SEGMENT: mid-pack it is both, and the plain one
		 * is whole. */
		if (i > 0u && segs[i].key == segs[i - 1u].key)
			continue;
		if (segs[i].key < q.cursor_key)
			continue;
		/* CLOSED BEFORE THE WINDOW: nothing in it can be in it. */
		if (segs[i].key != UINT64_MAX && segs[i].key < q.since_us)
			continue;
		start = segs[i].key == q.cursor_key ? q.cursor_off : 0u;
		(void)snprintf(path, sizeof(path), "%s/%.255s", dir, segs[i].name);
		if (!reader_open(&r, path, segs[i].packed))
			continue;
		while ((line = reader_line(&r, &len)) != NULL) {
			uint64_t here = at, t = 0;

			at += len + 1u;
			if (here < start || line[0] == '#')
				continue;
			if (fzn_entry_line_time(line, len, &t) != FZN_ENTRY_OK || t < q.since_us
			    || t > q.until_us || (q.match[0] && !strstr(line, q.match)))
				continue;
			/* ONE NO PAGE COULD CARRY is passed over: past a u16, or
			 * too long for an empty page. Any other that does not fit
			 * ends the page, to be read next. */
			if (len > 0xffffu || reply_cap - FZN_GATHER_LINES_HEAD < 2u + len)
				continue;
			if (reply_cap - used < 2u + len) {
				key = segs[i].key;
				off = here;
				done = 0;
				break;
			}
			fzn_put_be16(reply + used, (uint16_t)len);
			memcpy(reply + used + 2, line, len);
			used += 2u + len;
			count++;
			if (count == 0xffffu) {
				key = segs[i].key;
				off = at;
				done = 0;
				break;
			}
		}
		reader_close(&r);
	}
	reply[0] = FZN_GATHER_VERSION;
	reply[1] = FZN_GATHER_LINES;
	reply[2] = (uint8_t)done;
	fzn_put_be64(reply + 3, key);
	fzn_put_be64(reply + 11, off);
	fzn_put_be16(reply + 19, (uint16_t)count);
	return used;
}

/* ---- the troubleshooter -------------------------------------------------- */

fzn_gather_err_t fzn_gather_fetch(fzn_gather_ask_t ask, void *ask_ctx,
                                  const fzn_gather_query_t *q, size_t pages_max,
                                  fzn_gather_line_fn each, void *each_ctx, size_t *lines)
{
	static uint8_t reply[1u << 17];
	static char line[1u << 16];
	uint8_t request[FZN_GATHER_QUERY_MAX];
	fzn_gather_query_t at;
	size_t pages;

	if (!ask || !q || !each || !lines)
		return FZN_GATHER_ERR_MALFORMED;
	*lines = 0;
	at = *q;
	for (pages = 0; pages < pages_max; pages++) {
		size_t req_len = 0, reply_len = 0, k, pos;
		unsigned count;

		if (fzn_gather_query_encode(&at, request, sizeof(request), &req_len) != FZN_GATHER_OK)
			return FZN_GATHER_ERR_MALFORMED;
		if (!ask(ask_ctx, request, req_len, reply, sizeof(reply), &reply_len))
			return FZN_GATHER_ERR_NO_ANSWER;
		if (reply_len < FZN_GATHER_LINES_HEAD || reply[0] != FZN_GATHER_VERSION
		    || reply[1] != FZN_GATHER_LINES || reply[2] > 1u)
			return FZN_GATHER_ERR_REFUSED;
		count = fzn_get_be16(reply + 19);
		pos = FZN_GATHER_LINES_HEAD;
		for (k = 0; k < count; k++) {
			size_t len;

			if (reply_len - pos < 2u)
				return FZN_GATHER_ERR_REFUSED;
			len = fzn_get_be16(reply + pos);
			if (len == 0u || reply_len - pos - 2u < len || len >= sizeof(line))
				return FZN_GATHER_ERR_REFUSED;
			memcpy(line, reply + pos + 2, len);
			line[len] = '\0';
			each(each_ctx, line, len);
			(*lines)++;
			pos += 2u + len;
		}
		if (pos != reply_len)
			return FZN_GATHER_ERR_REFUSED;
		if (reply[2])
			return FZN_GATHER_OK;
		at.cursor_key = fzn_get_be64(reply + 3);
		at.cursor_off = fzn_get_be64(reply + 11);
	}
	return FZN_GATHER_OK;
}
