/*
 * Which recording a tune is: media/fingerprint.h, project.md sec 1459.
 */
#include "fingerprint.h"
#include "analysis.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- AcoustID's answer, read ------------------------------------------------
 *
 * A JSON reader of its own, as small as the one answer it reads needs: the
 * answer is a stranger's bytes, so it is bounded in depth and length and
 * reads nothing past `end`. Only `status`, `results[].id`, `.score` and
 * `.recordings[0].id` are taken; everything else is stepped over. */

#define JSON_DEPTH_MAX 32

struct json {
	const char *at, *end;
};

static void json_space(struct json *j)
{
	while (j->at < j->end && (*j->at == ' ' || *j->at == '\t' || *j->at == '\n' || *j->at == '\r'))
		j->at++;
}

/* A string, its raw bytes (escapes kept, which no id holds) into `out` of
 * `cap` where `out` is not NULL: 1, or 0 where it does not read. */
static int json_string(struct json *j, char *out, size_t cap)
{
	size_t n = 0;

	json_space(j);
	if (j->at >= j->end || *j->at != '"')
		return 0;
	j->at++;
	while (j->at < j->end && *j->at != '"') {
		if (*j->at == '\\') {
			if (++j->at >= j->end)
				return 0;
		}
		if (out && n + 1u < cap)
			out[n++] = *j->at;
		j->at++;
	}
	if (j->at >= j->end)
		return 0;
	j->at++;
	if (out && cap)
		out[n] = '\0';
	return 1;
}

static int json_skip(struct json *j, int depth);

static int json_number(struct json *j, double *out)
{
	char text[64];
	size_t n = 0;
	char *stop;

	json_space(j);
	while (j->at < j->end && n + 1u < sizeof(text) && strchr("+-0123456789.eE", *j->at))
		text[n++] = *j->at++;
	text[n] = '\0';
	if (!n)
		return 0;
	*out = strtod(text, &stop);
	return *stop == '\0';
}

/* Steps over one value of any kind. */
static int json_skip(struct json *j, int depth)
{
	json_space(j);
	if (j->at >= j->end || depth > JSON_DEPTH_MAX)
		return 0;
	if (*j->at == '"')
		return json_string(j, NULL, 0);
	if (*j->at == '{' || *j->at == '[') {
		const char close = *j->at == '{' ? '}' : ']';
		const int object = close == '}';

		j->at++;
		json_space(j);
		if (j->at < j->end && *j->at == close) {
			j->at++;
			return 1;
		}
		for (;;) {
			if (object) {
				if (!json_string(j, NULL, 0))
					return 0;
				json_space(j);
				if (j->at >= j->end || *j->at++ != ':')
					return 0;
			}
			if (!json_skip(j, depth + 1))
				return 0;
			json_space(j);
			if (j->at >= j->end)
				return 0;
			if (*j->at == close) {
				j->at++;
				return 1;
			}
			if (*j->at++ != ',')
				return 0;
		}
	}
	while (j->at < j->end && strchr("+-0123456789.eEtruefalsn", *j->at))
		j->at++;
	return 1;
}

/* Each member of an object: `each` handed its key, and the reader at its
 * value, which it reads or skips. */
static int json_object(struct json *j, int (*each)(struct json *j, const char *key, void *ctx), void *ctx)
{
	char key[32];

	json_space(j);
	if (j->at >= j->end || *j->at++ != '{')
		return 0;
	json_space(j);
	if (j->at < j->end && *j->at == '}') {
		j->at++;
		return 1;
	}
	for (;;) {
		if (!json_string(j, key, sizeof(key)))
			return 0;
		json_space(j);
		if (j->at >= j->end || *j->at++ != ':' || !each(j, key, ctx))
			return 0;
		json_space(j);
		if (j->at >= j->end)
			return 0;
		if (*j->at == '}') {
			j->at++;
			return 1;
		}
		if (*j->at++ != ',')
			return 0;
	}
}

/* Each element of an array of objects, handed to `each` as above. */
static int json_objects(struct json *j, int (*each)(struct json *j, const char *key, void *ctx),
                        int (*done)(void *ctx), void *ctx)
{
	json_space(j);
	if (j->at >= j->end || *j->at++ != '[')
		return 0;
	json_space(j);
	if (j->at < j->end && *j->at == ']') {
		j->at++;
		return 1;
	}
	for (;;) {
		if (!json_object(j, each, ctx) || !done(ctx))
			return 0;
		json_space(j);
		if (j->at >= j->end)
			return 0;
		if (*j->at == ']') {
			j->at++;
			return 1;
		}
		if (*j->at++ != ',')
			return 0;
	}
}

struct reading {
	char status[16];
	/* the result being read, and the best so far */
	char id[FZN_MEDIA_ID_MAX + 1u], recording[FZN_MEDIA_ID_MAX + 1u];
	double score;
	int recordings_seen;
	fzn_media_identity_t best;
	int found;
};

static int recording_member(struct json *j, const char *key, void *ctx)
{
	struct reading *r = ctx;

	if (!strcmp(key, "id") && !r->recordings_seen)
		return json_string(j, r->recording, sizeof(r->recording));
	return json_skip(j, 3);
}

static int recording_done(void *ctx)
{
	((struct reading *)ctx)->recordings_seen = 1;
	return 1;
}

static int result_member(struct json *j, const char *key, void *ctx)
{
	struct reading *r = ctx;

	if (!strcmp(key, "id"))
		return json_string(j, r->id, sizeof(r->id));
	if (!strcmp(key, "score"))
		return json_number(j, &r->score);
	if (!strcmp(key, "recordings"))
		return json_objects(j, recording_member, recording_done, r);
	return json_skip(j, 2);
}

/* A result read: the best so far kept, the next begun afresh. */
static int result_done(void *ctx)
{
	struct reading *r = ctx;

	if (r->id[0] && (!r->found || r->score > r->best.score)) {
		snprintf(r->best.acoustid, sizeof(r->best.acoustid), "%s", r->id);
		snprintf(r->best.recording, sizeof(r->best.recording), "%s", r->recording);
		r->best.score = r->score;
		r->found = 1;
	}
	r->id[0] = r->recording[0] = '\0';
	r->score = 0;
	r->recordings_seen = 0;
	return 1;
}

static int answer_member(struct json *j, const char *key, void *ctx)
{
	struct reading *r = ctx;

	if (!strcmp(key, "status"))
		return json_string(j, r->status, sizeof(r->status));
	if (!strcmp(key, "results"))
		return json_objects(j, result_member, result_done, r);
	return json_skip(j, 1);
}

/* An id is a UUID's letters: hex and dashes, nothing a catalogue would
 * show or a shell would read otherwise. */
static int id_ok(const char *id)
{
	size_t n = strlen(id);

	return n >= 8u && n <= FZN_MEDIA_ID_MAX && strspn(id, "0123456789abcdefABCDEF-") == n;
}

fzn_media_lookup_result_t fzn_media_acoustid_read(const char *json, size_t len, fzn_media_identity_t *out)
{
	struct json j = { json, json + len };
	struct reading r;

	memset(&r, 0, sizeof(r));
	if (out)
		memset(out, 0, sizeof(*out));
	if (!json || !out || !json_object(&j, answer_member, &r))
		return FZN_MEDIA_LOOKUP_NO_ANSWER;
	if (strcmp(r.status, "ok") != 0)
		return strcmp(r.status, "error") == 0 ? FZN_MEDIA_LOOKUP_REFUSED : FZN_MEDIA_LOOKUP_NO_ANSWER;
	if (!r.found || !id_ok(r.best.acoustid))
		return FZN_MEDIA_LOOKUP_UNKNOWN;
	if (r.best.recording[0] && !id_ok(r.best.recording))
		r.best.recording[0] = '\0';
	if (!(r.best.score >= 0.0 && r.best.score <= 1.0))
		r.best.score = 0.0;
	*out = r.best;
	return FZN_MEDIA_LOOKUP_FOUND;
}

/* snurra's measure, in C. */
double fzn_media_print_distance(const uint32_t *a, size_t a_n, const uint32_t *b, size_t b_n, int shift, int least)
{
	double best = 1.0;
	int offset;

	for (offset = -shift; offset <= shift; ++offset) {
		/* b moved by `offset` against a. */
		const long from = offset < 0 ? -offset : 0;
		const long to = (long)a_n < (long)b_n - offset ? (long)a_n : (long)b_n - offset;
		long i, bits = 0;

		if (to - from < least)
			continue;
		for (i = from; i < to; ++i)
			bits += __builtin_popcount(a[i] ^ b[i + offset]);
		if ((double)bits / (32.0 * (double)(to - from)) < best)
			best = (double)bits / (32.0 * (double)(to - from));
	}
	return best;
}

#ifdef FZN_MEDIA_DECODE_ON

#include <libavformat/avformat.h>
#include <libavutil/channel_layout.h>
#include <libavutil/dict.h>
#include <libavutil/log.h>
#include <libavutil/mem.h>

#define AVIO_BUFFER 4096
#define PRINT_FRAMES_MAX ((uint64_t)FZN_MEDIA_PRINT_SECONDS * FZN_MEDIA_ANALYSIS_RATE)

struct fzn_media_print {
	AVFormatContext *mux;
	uint8_t *out;
	size_t out_len, out_cap;
	uint64_t frames;
	int16_t pcm[2 * 4096];
	int open, overflow;
};

static int print_write(void *ctx, const uint8_t *data, int size)
{
	fzn_media_print_t *p = ctx;

	if (size < 0)
		return -1;
	if (p->out_len + (size_t)size > p->out_cap) {
		size_t cap = p->out_cap ? p->out_cap * 2u : 4096u;
		uint8_t *more;

		while (cap < p->out_len + (size_t)size)
			cap *= 2u;
		if (cap > (size_t)64u * 1024u * 1024u || !(more = realloc(p->out, cap))) {
			p->overflow = 1;
			return size;
		}
		p->out = more;
		p->out_cap = cap;
	}
	memcpy(p->out + p->out_len, data, (size_t)size);
	p->out_len += (size_t)size;
	return size;
}

fzn_media_print_t *fzn_media_print_open(int raw)
{
	fzn_media_print_t *p = calloc(1, sizeof(*p));
	AVDictionary *options = NULL;
	AVStream *stream;
	uint8_t *buffer;

	if (!p)
		return NULL;
	av_log_set_level(AV_LOG_QUIET);
	if (avformat_alloc_output_context2(&p->mux, NULL, "chromaprint", NULL) < 0 || !p->mux)
		goto fail;
	if (!(buffer = av_malloc(AVIO_BUFFER)))
		goto fail;
	if (!(p->mux->pb = avio_alloc_context(buffer, AVIO_BUFFER, 1, p, NULL, print_write, NULL))) {
		av_free(buffer);
		goto fail;
	}
	p->mux->flags |= AVFMT_FLAG_CUSTOM_IO;
	if (!(stream = avformat_new_stream(p->mux, NULL)))
		goto fail;
	stream->codecpar->codec_type = AVMEDIA_TYPE_AUDIO;
	stream->codecpar->codec_id = AV_CODEC_ID_PCM_S16LE;
	stream->codecpar->sample_rate = (int)FZN_MEDIA_ANALYSIS_RATE;
	av_channel_layout_default(&stream->codecpar->ch_layout, 2);
	stream->time_base = (AVRational){ 1, (int)FZN_MEDIA_ANALYSIS_RATE };
	(void)av_dict_set(&options, "fp_format", raw ? "raw" : "base64", 0);
	p->open = avformat_write_header(p->mux, &options) >= 0;
	av_dict_free(&options);
	if (!p->open)
		goto fail;
	return p;
fail:
	fzn_media_print_free(p);
	return NULL;
}

void fzn_media_print_free(fzn_media_print_t *p)
{
	if (!p)
		return;
	if (p->mux) {
		if (p->mux->pb) {
			av_freep(&p->mux->pb->buffer);
			avio_context_free(&p->mux->pb);
		}
		avformat_free_context(p->mux);
	}
	free(p->out);
	free(p);
}

int fzn_media_print_add(fzn_media_print_t *p, const float *stereo, size_t frames)
{
	while (p && p->open && frames && p->frames < PRINT_FRAMES_MAX) {
		size_t n = frames < 4096u ? frames : 4096u, i;
		AVPacket *packet;

		if (n > PRINT_FRAMES_MAX - p->frames)
			n = (size_t)(PRINT_FRAMES_MAX - p->frames);
		for (i = 0; i < 2u * n; i++) {
			const float v = stereo[i] < -1.0f ? -1.0f : stereo[i] > 1.0f ? 1.0f : stereo[i];
			p->pcm[i] = (int16_t)lrintf(v * 32767.0f);
		}
		if (!(packet = av_packet_alloc()) || av_new_packet(packet, (int)(n * 4u)) != 0) {
			av_packet_free(&packet);
			p->open = 0;
			return 0;
		}
		memcpy(packet->data, p->pcm, n * 4u);
		packet->pts = packet->dts = (int64_t)p->frames;
		packet->duration = (int64_t)n;
		packet->stream_index = 0;
		if (av_write_frame(p->mux, packet) < 0)
			p->open = 0;
		av_packet_free(&packet);
		p->frames += n;
		stereo += 2u * n;
		frames -= n;
	}
	return p && p->open;
}

size_t fzn_media_print_finish(fzn_media_print_t *p, uint8_t *out, size_t cap)
{
	size_t n = 0;

	if (!p)
		return 0;
	if (p->open && p->frames && av_write_trailer(p->mux) >= 0) {
		avio_flush(p->mux->pb);
		/* base64 ends in a newline; the text is the print. */
		while (p->out_len && (p->out[p->out_len - 1u] == '\n' || p->out[p->out_len - 1u] == '\r'))
			p->out_len--;
		if (!p->overflow && p->out_len && p->out_len <= cap && out) {
			memcpy(out, p->out, p->out_len);
			n = p->out_len;
		}
	}
	p->open = 0;
	fzn_media_print_free(p);
	return n;
}

/* `text` into `out` as a query's value: letters, digits and -._~ kept, the
 * rest %XX. 0 where it does not fit. */
static size_t url_escape(const char *text, char *out, size_t cap)
{
	static const char hex[] = "0123456789ABCDEF";
	size_t n = 0;

	for (; *text; text++) {
		const unsigned char c = (unsigned char)*text;

		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strchr("-._~", c)) {
			if (n + 2u > cap)
				return 0;
			out[n++] = (char)c;
		} else {
			if (n + 4u > cap)
				return 0;
			out[n++] = '%';
			out[n++] = hex[c >> 4];
			out[n++] = hex[c & 15u];
		}
	}
	out[n] = '\0';
	return n;
}

#define ANSWER_MAX (256u * 1024u)

fzn_media_lookup_result_t fzn_media_acoustid_lookup(const char *url, const char *key, const char *print,
                                                    unsigned seconds, fzn_media_identity_t *out)
{
	static const char hex[] = "0123456789abcdef";
	AVIOContext *io = NULL;
	AVDictionary *options = NULL;
	char *form = NULL, *form_hex = NULL, *answer = NULL, key_q[256], *print_q = NULL;
	size_t form_cap, got = 0, i;
	fzn_media_lookup_result_t result = FZN_MEDIA_LOOKUP_NO_ANSWER;
	int n;

	if (out)
		memset(out, 0, sizeof(*out));
	if (!url || !key || !*key || !print || !*print || !seconds || !out)
		return FZN_MEDIA_LOOKUP_NONE;
	if (!url_escape(key, key_q, sizeof(key_q)))
		return FZN_MEDIA_LOOKUP_NONE;
	av_log_set_level(AV_LOG_QUIET);
	/* A POST, as snurra asks it: the print is long for a query. */
	form_cap = sizeof(key_q) + 3u * strlen(print) + 128u;
	if (!(print_q = malloc(3u * strlen(print) + 1u)) || !(form = malloc(form_cap)) || !(answer = malloc(ANSWER_MAX + 1u))
	    || !url_escape(print, print_q, 3u * strlen(print) + 1u))
		goto done;
	n = snprintf(form, form_cap, "format=json&meta=recordingids&client=%s&duration=%u&fingerprint=%s", key_q, seconds,
	             print_q);
	if (n < 0 || (size_t)n >= form_cap || !(form_hex = malloc(2u * (size_t)n + 1u)))
		goto done;
	for (i = 0; i < (size_t)n; i++) {
		form_hex[2u * i] = hex[(unsigned char)form[i] >> 4];
		form_hex[2u * i + 1u] = hex[(unsigned char)form[i] & 15u];
	}
	form_hex[2u * (size_t)n] = '\0';
	/* THE CERTIFICATE CHECKED, which FFmpeg's TLS does not do unasked; ten
	 * seconds to answer. */
	(void)av_dict_set(&options, "method", "POST", 0);
	(void)av_dict_set(&options, "post_data", form_hex, 0);
	(void)av_dict_set(&options, "content_type", "application/x-www-form-urlencoded", 0);
	(void)av_dict_set(&options, "tls_verify", "1", 0);
	(void)av_dict_set(&options, "rw_timeout", "10000000", 0);
	(void)av_dict_set(&options, "timeout", "10000000", 0);
	if (avio_open2(&io, url, AVIO_FLAG_READ, NULL, &options) < 0)
		goto done;
	for (;;) {
		const int r = avio_read(io, (unsigned char *)answer + got, (int)(ANSWER_MAX - got));

		if (r <= 0)
			break;
		got += (size_t)r;
		if (got >= ANSWER_MAX)
			break;
	}
	result = fzn_media_acoustid_read(answer, got, out);
done:
	av_dict_free(&options);
	avio_closep(&io);
	free(print_q);
	free(form);
	free(form_hex);
	free(answer);
	return result;
}

#else

fzn_media_print_t *fzn_media_print_open(int raw)
{
	(void)raw;
	return NULL;
}

int fzn_media_print_add(fzn_media_print_t *p, const float *stereo, size_t frames)
{
	(void)p;
	(void)stereo;
	(void)frames;
	return 0;
}

size_t fzn_media_print_finish(fzn_media_print_t *p, uint8_t *out, size_t cap)
{
	(void)p;
	(void)out;
	(void)cap;
	return 0;
}

void fzn_media_print_free(fzn_media_print_t *p)
{
	(void)p;
}

fzn_media_lookup_result_t fzn_media_acoustid_lookup(const char *url, const char *key, const char *print,
                                                    unsigned seconds, fzn_media_identity_t *out)
{
	(void)url;
	(void)key;
	(void)print;
	(void)seconds;
	if (out)
		memset(out, 0, sizeof(*out));
	return FZN_MEDIA_LOOKUP_NONE;
}

#endif
