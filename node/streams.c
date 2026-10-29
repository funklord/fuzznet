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
	case FZN_STREAMS_ERR_ROOM:
		return "more are held than the room given";
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

/* WHATEVER RECORD ring slot `slot` holds, whatever its seq. */
static int ring_at(const fzn_streams_t *s, const char *name, size_t name_len,
                   const uint8_t origin[32], uint64_t slot, fzn_stream_record_t *out)
{
	uint8_t subject[32], bytes[RECORD_MAX];
	size_t n = 0;

	return subject_of(s, 'r', name, name_len, origin, slot, subject)
	       && s->store->load(s->store->ctx, FZN_PERSIST_STREAM_RECORD, subject, bytes,
	                         sizeof(bytes), &n)
	       && record_decode(bytes, n, out);
}

uint64_t fzn_streams_next(const fzn_streams_t *s, const char *name, size_t name_len,
                          const uint8_t origin[32])
{
	fzn_stream_record_t r;
	uint64_t last = fzn_streams_last(s, name, name_len, origin), slot;

	if (last || !usable(s) || !fzn_stream_name_ok(name, name_len) || !origin)
		return last + 1u;
	/* THE RING READ, once: only a host with no head pays it. */
	for (slot = 0; slot < FZN_STREAM_KEEP; slot++)
		if (ring_at(s, name, name_len, origin, slot, &r) && r.seq > last)
			last = r.seq;
	return last + 1u;
}

/* EVERY HEAD, walked, sec 704: those of `name` kept, as many as fit, and
 * all counted. It listed 512 heads of every stream into a fixed table. */
struct origins_walk {
	const fzn_streams_t *s;
	const char *name;
	size_t name_len;
	uint8_t (*out)[32];
	size_t cap, n;
};

static int origin_walked(void *arg, const uint8_t subject[FZN_PUBKEY_LEN])
{
	struct origins_walk *w = arg;
	uint8_t bytes[HEAD_MAX];
	size_t len = 0;

	if (w->s->store->load(w->s->store->ctx, FZN_PERSIST_STREAM_HEAD, subject, bytes,
	                      sizeof(bytes), &len)
	    && len == 8u + 32u + 1u + w->name_len && bytes[40] == w->name_len
	    && memcmp(bytes + 41, w->name, w->name_len) == 0) {
		if (w->n < w->cap)
			memcpy(w->out[w->n], bytes + 8, 32u);
		w->n++;
	}
	return 1;
}

fzn_streams_err_t fzn_streams_origins(const fzn_streams_t *s, const char *name, size_t name_len,
                                      uint8_t (*out)[32], size_t cap, size_t *count)
{
	struct origins_walk w;

	if (!usable(s) || !fzn_stream_name_ok(name, name_len) || (!out && cap) || !count)
		return FZN_STREAMS_ERR_MALFORMED;
	*count = 0;
	w.s = s;
	w.name = name;
	w.name_len = name_len;
	w.out = out;
	w.cap = cap;
	w.n = 0;
	if (!fzn_persist_each(s->store, FZN_PERSIST_STREAM_HEAD, origin_walked, &w))
		return FZN_STREAMS_ERR_BACKEND;
	*count = w.n;
	return w.n > cap ? FZN_STREAMS_ERR_ROOM : FZN_STREAMS_OK;
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
	uint8_t subject[32], bytes[1];
	unsigned held;

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
	/* AS MANY GRANTS AS THE USER MAKES, sec 704: they were 256, across every
	 * stream. */
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

const char *fzn_streams_refuse_query(const fzn_streams_asker_t *asker, int *whole,
                                     unsigned *level)
{
	*whole = 0;
	*level = 0;
	if (!asker || (!asker->member && !asker->contact && !asker->group_host))
		return "streams to whom it grants";
	if (asker->member) {
		*whole = 1;
		return NULL;
	}
	if (asker->level < 0 || asker->level >= (int)FZN_STREAM_LEVELS_MAX)
		return "that stream is not granted";
	*level = (unsigned)asker->level;
	return NULL;
}

const char *fzn_streams_refuse_local(fzn_origin_t origin)
{
	return origin == FZN_ORIGIN_SAME_USER ? NULL : "streams are this node's own user's";
}

fzn_streams_err_t fzn_streams_take(const fzn_streams_t *s, const char *name, size_t name_len,
                                   const uint8_t origin[32], const uint8_t *records, size_t len,
                                   size_t count, size_t *taken, uint64_t *stopped_at)
{
	fzn_stream_record_t r;
	fzn_streams_err_t err;
	size_t at = 0, k, l;

	if (taken)
		*taken = 0;
	if (stopped_at)
		*stopped_at = 0;
	if (!records && len)
		return FZN_STREAMS_ERR_MALFORMED;
	for (k = 0; k < count; k++) {
		if (len - at < 17u)
			return FZN_STREAMS_ERR_MALFORMED;
		memset(&r, 0, sizeof(r));
		r.seq = fzn_get_be64(records + at);
		r.at = fzn_get_be64(records + at + 8u);
		r.levels = records[at + 16u];
		at += 17u;
		if (r.levels == 0u || r.levels > FZN_STREAM_LEVELS_MAX)
			return FZN_STREAMS_ERR_MALFORMED;
		for (l = 0; l < r.levels; l++) {
			if (at >= len || records[at] > FZN_STREAM_RENDITION_MAX
			    || len - at - 1u < records[at])
				return FZN_STREAMS_ERR_MALFORMED;
			r.rendition_len[l] = records[at++];
			memcpy(r.rendition[l], records + at, r.rendition_len[l]);
			at += r.rendition_len[l];
		}
		if ((err = fzn_streams_keep(s, name, name_len, origin, &r)) != FZN_STREAMS_OK) {
			if (stopped_at)
				*stopped_at = r.seq;
			return err;
		}
		if (taken)
			(*taken)++;
	}
	return FZN_STREAMS_OK;
}
