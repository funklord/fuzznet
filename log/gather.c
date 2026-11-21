/* See gather.h. */

#define _POSIX_C_SOURCE 200809L

#include "gather.h"
#include "../wire/generated/gather_wire.h"
#include "../wire/generated/gather_wire_build.h"

#include "../wire/bytes.h"
#include "../wire/status.h"

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
	case FZN_GATHER_ERR_DENIED:
		return "the host denied it: its log is not this node's to gather";
	}
	return "unknown";
}

/* A HOST'S REFUSAL, sec 735: a STATUS denied (sec 1078; a text line opening
 * `denied ` before), as a host whose log is host-private answers. Told apart
 * from a reply that is not a page, so the gatherer is not left guessing why.
 * Read from its three head bytes, its length agreeing, so a gatherer links no
 * codec for it. */
static int denied(const uint8_t *reply, size_t len)
{
	return len >= FZN_STATUS_HEAD_LEN && reply[0] == FZN_CMD_STATUS
	       && reply[1] == (uint8_t)FZN_STATUS_DENIED
	       && (size_t)FZN_STATUS_HEAD_LEN + reply[2] == len;
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
	size_t p, m;
	uint32_t wrote = 0;

	if (!q || !out || !len || !word_ok(q->program, FZN_ENTRY_WORD_MAX)
	    || memchr(q->match, '\0', sizeof(q->match)) == NULL)
		return FZN_GATHER_ERR_MALFORMED;
	p = strlen(q->program);
	m = strlen(q->match);
	/* BUILT BY THE CODE situ GENERATES from `log/gather_wire.situ`, sec
	 * 1372: a buffer too small, or a match past its bound, the builder's
	 * to refuse. */
	if (fzn_gather_wire_fzn_gather_query_build(
	            out, cap > UINT32_MAX ? UINT32_MAX : (uint32_t)cap, (uint8_t)FZN_CMD_GATHER,
	            FZN_GATHER_WIRE_FZN_GATHER_TYPE_QUERY, q->since_us, q->until_us, q->cursor_key,
	            q->cursor_off, (const uint8_t *)q->program, (uint32_t)p, (const uint8_t *)q->match,
	            (uint32_t)m, &wrote)
	    != SITU_OK)
		return FZN_GATHER_ERR_MALFORMED;
	*len = wrote;
	return FZN_GATHER_OK;
}

static int query_decode(const uint8_t *in, size_t len, fzn_gather_query_t *q)
{
	situ_msg_t msg;
	situ_view_t v;
	uint32_t need = 0;
	size_t p, m;

	memset(q, 0, sizeof(*q));
	/* READ AS THE SCHEMA SAYS, sec 1372: version, type, a program of 1 to
	 * 64 bytes, a match of at most 64 and every byte accounted for the
	 * generated code's. */
	if (len > UINT32_MAX
	    || fzn_gather_wire_fzn_gather_query_required(in, (uint32_t)len, &need) != SITU_OK
	    || need != len)
		return 0;
	situ_msg_init(&msg, (uint8_t *)(uintptr_t)in, (uint32_t)len);
	if (fzn_gather_wire_fzn_gather_query_view(&msg, 0u, (uint32_t)len, &v) != SITU_OK
	    || fzn_gather_wire_fzn_gather_query_validate(v) != SITU_OK)
		return 0;
	q->since_us = fzn_gather_wire_fzn_gather_query_since_us_get(v);
	q->until_us = fzn_gather_wire_fzn_gather_query_until_us_get(v);
	q->cursor_key = fzn_gather_wire_fzn_gather_query_cursor_key_get(v);
	q->cursor_off = fzn_gather_wire_fzn_gather_query_cursor_off_get(v);
	p = fzn_gather_wire_fzn_gather_query_program_len_get(v);
	m = fzn_gather_wire_fzn_gather_query_match_len_get(v);
	if (p > FZN_ENTRY_WORD_MAX || m > FZN_GATHER_MATCH_MAX)
		return 0;
	memcpy(q->program, fzn_gather_wire_fzn_gather_query_program_ptr(v), p);
	memcpy(q->match, fzn_gather_wire_fzn_gather_query_match_ptr(v), m);
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

	if (!request || request_len < 2u || request[0] != FZN_CMD_GATHER
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
	reply[0] = FZN_CMD_GATHER;
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
		size_t req_len = 0, reply_len = 0, k;
		situ_msg_t msg;
		situ_view_t v, one;
		uint32_t need = 0;
		unsigned count;

		if (fzn_gather_query_encode(&at, request, sizeof(request), &req_len) != FZN_GATHER_OK)
			return FZN_GATHER_ERR_MALFORMED;
		if (!ask(ask_ctx, request, req_len, reply, sizeof(reply), &reply_len))
			return FZN_GATHER_ERR_NO_ANSWER;
		if (denied(reply, reply_len))
			return FZN_GATHER_ERR_DENIED;
		/* THE PAGE READ WHOLE BEFORE ANY LINE IS HANDED ON, sec 1372: its
		 * version, type, done flag, every line of at least one byte and
		 * nothing after the last the generated code's -- so a malformed
		 * page gives its caller no line rather than the lines before the
		 * fault. */
		if (reply_len < FZN_GATHER_LINES_HEAD || reply_len > sizeof(reply)
		    || fzn_gather_wire_fzn_gather_lines_required(reply, (uint32_t)reply_len, &need) != SITU_OK
		    || need != reply_len)
			return FZN_GATHER_ERR_REFUSED;
		situ_msg_init(&msg, reply, (uint32_t)reply_len);
		if (fzn_gather_wire_fzn_gather_lines_view(&msg, 0u, (uint32_t)reply_len, &v) != SITU_OK
		    || fzn_gather_wire_fzn_gather_lines_validate(v) != SITU_OK)
			return FZN_GATHER_ERR_REFUSED;
		count = fzn_gather_wire_fzn_gather_lines_lines_count(v);
		for (k = 0; k < count; k++) {
			size_t len;

			if (fzn_gather_wire_fzn_gather_lines_lines_at(v, (uint32_t)k, &one) != SITU_OK)
				return FZN_GATHER_ERR_REFUSED;
			len = fzn_gather_wire_fzn_gather_line_len_get(one);
			if (len >= sizeof(line))
				return FZN_GATHER_ERR_REFUSED;
			memcpy(line, fzn_gather_wire_fzn_gather_line_line_ptr(one), len);
			line[len] = '\0';
			each(each_ctx, line, len);
			(*lines)++;
		}
		if (fzn_gather_wire_fzn_gather_lines_done_get(v))
			return FZN_GATHER_OK;
		at.cursor_key = fzn_gather_wire_fzn_gather_lines_cursor_key_get(v);
		at.cursor_off = fzn_gather_wire_fzn_gather_lines_cursor_off_get(v);
	}
	return FZN_GATHER_OK;
}

/* ---- the flight recorder on request, sec 464 ----------------------------- */

struct ring_page {
	int started;
	uint64_t after;
	uint8_t *reply;
	size_t cap, used;
	unsigned count;
	int full;
};

static void ring_take(void *ctx, const fzn_entry_t *e)
{
	struct ring_page *p = ctx;
	uint8_t rec[FZN_ENTRY_RECORD_MAX];
	size_t len = 0;

	if (p->full || (p->started && e->name.position <= p->after))
		return;
	if (fzn_entry_pack(e, rec, sizeof(rec), &len) != FZN_ENTRY_OK)
		return;
	/* WHOLE RECORDS ONLY: the first that does not fit ends the page, and
	 * the next page starts past the last one sent. */
	if (p->cap - p->used < 2u + len || p->count == 0xffffu) {
		p->full = 1;
		return;
	}
	fzn_put_be16(p->reply + p->used, (uint16_t)len);
	memcpy(p->reply + p->used + 2, rec, len);
	p->used += 2u + len;
	p->count++;
}

size_t fzn_gather_ring_answer(const fzn_ring_t *ring, const uint8_t *request,
                              size_t request_len, uint8_t *reply, size_t reply_cap)
{
	struct ring_page p;
	situ_msg_t msg;
	situ_view_t v;

	if (!request || request_len < 2u || request[0] != FZN_CMD_GATHER
	    || request[1] != FZN_GATHER_RING_QUERY)
		return 0;
	if (!ring || !reply || reply_cap < FZN_GATHER_RING_HEAD + 2u + FZN_ENTRY_RECORD_MAX
	    || request_len != FZN_GATHER_RING_QUERY_LEN)
		return 0;
	/* READ AS THE SCHEMA SAYS, sec 1372: version, type and a started flag
	 * of 0 or 1 the generated validate's. */
	situ_msg_init(&msg, (uint8_t *)(uintptr_t)request, (uint32_t)request_len);
	if (fzn_gather_wire_fzn_gather_ring_query_view(&msg, 0u, &v) != SITU_OK
	    || fzn_gather_wire_fzn_gather_ring_query_validate(v) != SITU_OK)
		return 0;
	memset(&p, 0, sizeof(p));
	p.started = fzn_gather_wire_fzn_gather_ring_query_started_get(v);
	p.after = fzn_gather_wire_fzn_gather_ring_query_after_get(v);
	p.reply = reply;
	p.cap = reply_cap;
	p.used = FZN_GATHER_RING_HEAD;
	(void)fzn_ring_walk(ring, ring_take, &p);
	reply[0] = FZN_CMD_GATHER;
	reply[1] = FZN_GATHER_RING;
	reply[2] = (uint8_t)!p.full;
	fzn_put_be16(reply + 3, (uint16_t)p.count);
	return p.used;
}

fzn_gather_err_t fzn_gather_ring_fetch(fzn_gather_ask_t ask, void *ask_ctx, size_t pages_max,
                                       fzn_gather_entry_fn each, void *each_ctx,
                                       size_t *entries)
{
	static uint8_t reply[1u << 17];
	uint8_t request[FZN_GATHER_RING_QUERY_LEN];
	uint64_t after = 0;
	int started = 0;
	size_t pages;

	if (!ask || !each || !entries)
		return FZN_GATHER_ERR_MALFORMED;
	*entries = 0;
	for (pages = 0; pages < pages_max; pages++) {
		size_t reply_len = 0, k;
		situ_msg_t msg;
		situ_view_t v, one;
		uint32_t need = 0, wrote = 0;
		unsigned count;

		if (fzn_gather_wire_fzn_gather_ring_query_build(request, (uint32_t)sizeof(request),
		                                               (uint8_t)FZN_CMD_GATHER,
		                                               FZN_GATHER_WIRE_FZN_GATHER_TYPE_RING_QUERY,
		                                               (uint8_t)started, after, &wrote)
		    != SITU_OK)
			return FZN_GATHER_ERR_MALFORMED;
		if (!ask(ask_ctx, request, sizeof(request), reply, sizeof(reply), &reply_len))
			return FZN_GATHER_ERR_NO_ANSWER;
		if (denied(reply, reply_len))
			return FZN_GATHER_ERR_DENIED;
		/* THE PAGE READ WHOLE FIRST, sec 1372: version, type, done flag,
		 * every record 55 to 4672 bytes and nothing after the last the
		 * generated code's. Each record is then unpacked as before, and
		 * one that will not unpack refuses the page there. */
		if (reply_len < FZN_GATHER_RING_HEAD || reply_len > sizeof(reply)
		    || fzn_gather_wire_fzn_gather_ring_required(reply, (uint32_t)reply_len, &need) != SITU_OK
		    || need != reply_len)
			return FZN_GATHER_ERR_REFUSED;
		situ_msg_init(&msg, reply, (uint32_t)reply_len);
		if (fzn_gather_wire_fzn_gather_ring_view(&msg, 0u, (uint32_t)reply_len, &v) != SITU_OK
		    || fzn_gather_wire_fzn_gather_ring_validate(v) != SITU_OK)
			return FZN_GATHER_ERR_REFUSED;
		count = fzn_gather_wire_fzn_gather_ring_records_count(v);
		for (k = 0; k < count; k++) {
			fzn_entry_t e;

			if (fzn_gather_wire_fzn_gather_ring_records_at(v, (uint32_t)k, &one) != SITU_OK
			    || fzn_entry_unpack(fzn_gather_wire_fzn_gather_record_record_ptr(one),
			                        fzn_gather_wire_fzn_gather_record_len_get(one), &e)
			               != FZN_ENTRY_OK)
				return FZN_GATHER_ERR_REFUSED;
			each(each_ctx, &e);
			(*entries)++;
			after = e.name.position;
			started = 1;
		}
		/* DONE, OR A PAGE THAT BROUGHT NOTHING: a host whose ring holds
		 * one record too large for its reply would be asked for ever. */
		if (fzn_gather_wire_fzn_gather_ring_done_get(v) || count == 0u)
			return FZN_GATHER_OK;
	}
	return FZN_GATHER_OK;
}
