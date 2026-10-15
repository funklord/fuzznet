/* App streams: project.md sec 632, and the header. */
#include "streams.h"

#include <string.h>

#include "../wire/bytes.h"

const char *fzn_streams_err_str(fzn_streams_err_t err)
{
	switch (err) {
	case FZN_STREAMS_OK:
		return "ok";
	case FZN_STREAMS_ERR_MALFORMED:
		return "malformed";
	case FZN_STREAMS_ERR_ABSENT:
		return "no such record";
	case FZN_STREAMS_ERR_DENIED:
		return "not granted";
	case FZN_STREAMS_ERR_FULL:
		return "too many grants";
	case FZN_STREAMS_ERR_BACKEND:
		return "the store refused";
	}
	return "unknown";
}

int fzn_stream_name_ok(const char *name, size_t len)
{
	size_t i;

	if (!name || len == 0u || len > FZN_STREAM_NAME_MAX)
		return 0;
	for (i = 0; i < len; i++)
		if (!((name[i] >= 'a' && name[i] <= 'z') || (name[i] >= '0' && name[i] <= '9')
		      || name[i] == '_'))
			return 0;
	return 1;
}

static int usable(const fzn_streams_t *s)
{
	return s && s->store && s->store->load && s->store->save && s->hash && s->hash->hash;
}

/* A ROW'S SUBJECT: the hash of a kind, the name, a key and a number. */
static int subject_of(const fzn_streams_t *s, char kind, const char *name, size_t name_len,
                      const uint8_t *key, uint64_t n, uint8_t out[32])
{
	uint8_t in[1u + 1u + FZN_STREAM_NAME_MAX + 32u + 8u];

	memset(in, 0, sizeof(in));
	in[0] = (uint8_t)kind;
	in[1] = (uint8_t)name_len;
	memcpy(in + 2, name, name_len);
	memcpy(in + 2 + FZN_STREAM_NAME_MAX, key, 32u);
	fzn_put_be64(in + 2 + FZN_STREAM_NAME_MAX + 32u, n);
	return s->hash->hash(s->hash->ctx, out, 32u, in, sizeof(in));
}

#define RECORD_VERSION 1u
#define RECORD_MAX                                                                         \
	(1u + 8u + 8u + 1u + FZN_STREAM_LEVELS_MAX * (1u + FZN_STREAM_RENDITION_MAX))

static size_t record_encode(const fzn_stream_record_t *r, uint8_t *out)
{
	size_t at = 0, k;

	out[at++] = RECORD_VERSION;
	fzn_put_be64(out + at, r->seq);
	at += 8u;
	fzn_put_be64(out + at, r->at);
	at += 8u;
	out[at++] = (uint8_t)r->levels;
	for (k = 0; k < r->levels; k++) {
		out[at++] = (uint8_t)r->rendition_len[k];
		memcpy(out + at, r->rendition[k], r->rendition_len[k]);
		at += r->rendition_len[k];
	}
	return at;
}

static int record_decode(const uint8_t *in, size_t len, fzn_stream_record_t *r)
{
	size_t at = 0, k;

	memset(r, 0, sizeof(*r));
	if (len < 1u + 8u + 8u + 1u || in[0] != RECORD_VERSION)
		return 0;
	at = 1u;
	r->seq = fzn_get_be64(in + at);
	at += 8u;
	r->at = fzn_get_be64(in + at);
	at += 8u;
	r->levels = in[at++];
	if (r->levels == 0u || r->levels > FZN_STREAM_LEVELS_MAX)
		return 0;
	for (k = 0; k < r->levels; k++) {
		if (at >= len || in[at] > FZN_STREAM_RENDITION_MAX || len - at - 1u < in[at])
			return 0;
		r->rendition_len[k] = in[at++];
		memcpy(r->rendition[k], in + at, r->rendition_len[k]);
		at += r->rendition_len[k];
	}
	return at == len;
}

/* A HEAD: the last seq, and the origin and name it is of, so the origins
 * of a stream can be listed. */
#define HEAD_MAX (8u + 32u + 1u + FZN_STREAM_NAME_MAX)

uint64_t fzn_streams_last(const fzn_streams_t *s, const char *name, size_t name_len,
                          const uint8_t origin[32])
{
	uint8_t subject[32], bytes[HEAD_MAX];
	size_t n = 0;

	if (!usable(s) || !fzn_stream_name_ok(name, name_len) || !origin
	    || !subject_of(s, 'h', name, name_len, origin, 0u, subject)
	    || !s->store->load(s->store->ctx, FZN_PERSIST_STREAM_HEAD, subject, bytes, sizeof(bytes),
	                       &n)
	    || n < 8u)
		return 0;
	return fzn_get_be64(bytes);
}

fzn_streams_err_t fzn_streams_origins(const fzn_streams_t *s, const char *name, size_t name_len,
                                      uint8_t (*out)[32], size_t cap, size_t *count)
{
	static uint8_t subjects[FZN_STREAM_HEADS_MAX][32];
	uint8_t bytes[HEAD_MAX];
	size_t n = 0, i, len = 0;

	if (!usable(s) || !fzn_stream_name_ok(name, name_len) || !out || !count)
		return FZN_STREAMS_ERR_MALFORMED;
	*count = 0;
	if (!s->store->list
	    || !s->store->list(s->store->ctx, FZN_PERSIST_STREAM_HEAD, (uint8_t *)subjects,
	                       FZN_STREAM_HEADS_MAX, &n))
		return FZN_STREAMS_ERR_BACKEND;
	for (i = 0; i < n && *count < cap; i++)
		if (s->store->load(s->store->ctx, FZN_PERSIST_STREAM_HEAD, subjects[i], bytes,
		                   sizeof(bytes), &len)
		    && len == 8u + 32u + 1u + name_len && bytes[40] == name_len
		    && memcmp(bytes + 41, name, name_len) == 0)
			memcpy(out[(*count)++], bytes + 8, 32u);
	return FZN_STREAMS_OK;
}

fzn_streams_err_t fzn_streams_keep(const fzn_streams_t *s, const char *name, size_t name_len,
                                   const uint8_t origin[32], const fzn_stream_record_t *r)
{
	uint8_t subject[32], bytes[RECORD_MAX], last[HEAD_MAX];
	uint64_t held;
	size_t n, k;

	if (!usable(s) || !fzn_stream_name_ok(name, name_len) || !origin || !r || r->seq == 0u
	    || r->levels == 0u || r->levels > FZN_STREAM_LEVELS_MAX)
		return FZN_STREAMS_ERR_MALFORMED;
	for (k = 0; k < r->levels; k++)
		if (r->rendition_len[k] > FZN_STREAM_RENDITION_MAX)
			return FZN_STREAMS_ERR_MALFORMED;
	held = fzn_streams_last(s, name, name_len, origin);
	/* NEWER THAN THE LAST HELD, a record held already being no error: a
	 * reader further behind than the owner's ring reaches skips what the
	 * ring lost, which no one holds any more. */
	if (r->seq <= held)
		return FZN_STREAMS_OK;
	n = record_encode(r, bytes);
	if (!subject_of(s, 'r', name, name_len, origin, r->seq % FZN_STREAM_KEEP, subject)
	    || !s->store->save(s->store->ctx, FZN_PERSIST_STREAM_RECORD, subject, bytes, n))
		return FZN_STREAMS_ERR_BACKEND;
	fzn_put_be64(last, r->seq);
	memcpy(last + 8, origin, 32u);
	last[40] = (uint8_t)name_len;
	memcpy(last + 41, name, name_len);
	if (!subject_of(s, 'h', name, name_len, origin, 0u, subject)
	    || !s->store->save(s->store->ctx, FZN_PERSIST_STREAM_HEAD, subject, last,
	                       8u + 32u + 1u + name_len))
		return FZN_STREAMS_ERR_BACKEND;
	return FZN_STREAMS_OK;
}

fzn_streams_err_t fzn_streams_get(const fzn_streams_t *s, const char *name, size_t name_len,
                                  const uint8_t origin[32], uint64_t seq,
                                  fzn_stream_record_t *out)
{
	uint8_t subject[32], bytes[RECORD_MAX];
	size_t n = 0;

	if (!usable(s) || !fzn_stream_name_ok(name, name_len) || !origin || !out || seq == 0u)
		return FZN_STREAMS_ERR_MALFORMED;
	if (!subject_of(s, 'r', name, name_len, origin, seq % FZN_STREAM_KEEP, subject)
	    || !s->store->load(s->store->ctx, FZN_PERSIST_STREAM_RECORD, subject, bytes,
	                       sizeof(bytes), &n)
	    || !record_decode(bytes, n, out) || out->seq != seq)
		return FZN_STREAMS_ERR_ABSENT;
	return FZN_STREAMS_OK;
}

fzn_streams_err_t fzn_streams_grant(const fzn_streams_t *s, const char *name, size_t name_len,
                                    const uint8_t grantee[32], int level)
{
	static uint8_t subjects[FZN_STREAM_GRANTS_MAX + 1u][32];
	uint8_t subject[32], bytes[1];
	unsigned held;
	size_t n = 0;

	if (!usable(s) || !fzn_stream_name_ok(name, name_len) || !grantee
	    || level >= (int)FZN_STREAM_LEVELS_MAX)
		return FZN_STREAMS_ERR_MALFORMED;
	if (!subject_of(s, 'g', name, name_len, grantee, 0u, subject))
		return FZN_STREAMS_ERR_BACKEND;
	if (level < 0) {
		if (fzn_streams_granted(s, name, name_len, grantee, &held) != FZN_STREAMS_OK)
			return FZN_STREAMS_ERR_ABSENT;
		return s->store->remove
		               && s->store->remove(s->store->ctx, FZN_PERSIST_STREAM_GRANT, subject)
		               ? FZN_STREAMS_OK
		               : FZN_STREAMS_ERR_BACKEND;
	}
	if (fzn_streams_granted(s, name, name_len, grantee, &held) != FZN_STREAMS_OK) {
		if (!s->store->list
		    || !s->store->list(s->store->ctx, FZN_PERSIST_STREAM_GRANT, (uint8_t *)subjects,
		                       FZN_STREAM_GRANTS_MAX + 1u, &n))
			return FZN_STREAMS_ERR_BACKEND;
		if (n >= FZN_STREAM_GRANTS_MAX)
			return FZN_STREAMS_ERR_FULL;
	}
	bytes[0] = (uint8_t)level;
	return s->store->save(s->store->ctx, FZN_PERSIST_STREAM_GRANT, subject, bytes, sizeof(bytes))
	               ? FZN_STREAMS_OK
	               : FZN_STREAMS_ERR_BACKEND;
}

fzn_streams_err_t fzn_streams_granted(const fzn_streams_t *s, const char *name, size_t name_len,
                                      const uint8_t grantee[32], unsigned *level)
{
	uint8_t subject[32], bytes[1];
	size_t n = 0;

	if (!usable(s) || !fzn_stream_name_ok(name, name_len) || !grantee || !level)
		return FZN_STREAMS_ERR_MALFORMED;
	if (!subject_of(s, 'g', name, name_len, grantee, 0u, subject)
	    || !s->store->load(s->store->ctx, FZN_PERSIST_STREAM_GRANT, subject, bytes, sizeof(bytes),
	                       &n)
	    || n != 1u || bytes[0] >= FZN_STREAM_LEVELS_MAX)
		return FZN_STREAMS_ERR_DENIED;
	*level = bytes[0];
	return FZN_STREAMS_OK;
}

void fzn_streams_render(const fzn_stream_record_t *r, unsigned level, fzn_stream_record_t *out)
{
	size_t k;

	if (!r || !out || r->levels == 0u)
		return;
	k = level < r->levels ? level : r->levels - 1u;
	memset(out, 0, sizeof(*out));
	out->seq = r->seq;
	out->at = r->at;
	out->levels = 1u;
	memcpy(out->rendition[0], r->rendition[k], r->rendition_len[k]);
	out->rendition_len[0] = r->rendition_len[k];
}
