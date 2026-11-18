/* Opus for a call's sound, through FFmpeg: call_opus.h, fuzznet sec 1254. */
#include "call_opus.h"

#include <new>

#include <stdio.h>

#include <string.h>

#ifdef FZN_OPUS_ON
extern "C" {
#include <libavcodec/avcodec.h>
#include <libavutil/channel_layout.h>
#include <libavutil/opt.h>
}

/* PACKETS AN ENCODER GAVE AT ONCE beyond the one returned, kept for the next
 * frames: FFmpeg's own may hand two in one turn while it settles. */
#define QUEUED_MAX 4u

struct fzn_call_opus {
	AVCodecContext *enc = nullptr, *dec = nullptr;
	AVFrame *in = nullptr, *out = nullptr;
	AVPacket *packet = nullptr;
	fzn_call_codec_t codec;
	char encoder[32] = "";
	uint8_t queued[QUEUED_MAX][FZN_RPC_FRAME_MAX];
	size_t queued_len[QUEUED_MAX] = {};
	size_t queued_n = 0;
};

/* The first sample format a codec takes that this converts, s16 or float,
 * packed or planar (mono, so the two are one layout). */
static AVSampleFormat opus_format(const AVCodecContext *ctx, const AVCodec *codec)
{
	const void *list = nullptr;
	int n = 0;

	if (avcodec_get_supported_config(ctx, codec, AV_CODEC_CONFIG_SAMPLE_FORMAT, 0, &list, &n) < 0 || !list)
		return AV_SAMPLE_FMT_S16; /* any, by FFmpeg's word */
	const auto *f = static_cast<const AVSampleFormat *>(list);
	for (int i = 0; i < n; i++)
		if (f[i] == AV_SAMPLE_FMT_S16 || f[i] == AV_SAMPLE_FMT_FLT || f[i] == AV_SAMPLE_FMT_FLTP
		    || f[i] == AV_SAMPLE_FMT_S16P)
			return f[i];
	return AV_SAMPLE_FMT_NONE;
}

static bool is_float(int format) { return format == AV_SAMPLE_FMT_FLT || format == AV_SAMPLE_FMT_FLTP; }

/* ONE FRAME IN, a packet out: the first the encoder gives, the rest queued;
 * 0 where it holds the frame back, as it may at the start. */
static int encode(void *ctx, const int16_t *pcm, size_t n, uint8_t *packet, size_t cap)
{
	auto *o = static_cast<fzn_call_opus *>(ctx);

	if (n != FZN_CALL_OPUS_FRAME)
		return -1;
	av_frame_unref(o->in);
	o->in->nb_samples = (int)n;
	o->in->format = o->enc->sample_fmt;
	o->in->sample_rate = (int)FZN_CALL_OPUS_RATE;
	if (av_channel_layout_copy(&o->in->ch_layout, &o->enc->ch_layout) < 0 || av_frame_get_buffer(o->in, 0) < 0)
		return -1;
	for (size_t i = 0; i < n; i++) {
		if (is_float(o->enc->sample_fmt))
			reinterpret_cast<float *>(o->in->data[0])[i] = (float)pcm[i] / 32768.0f;
		else
			reinterpret_cast<int16_t *>(o->in->data[0])[i] = pcm[i];
	}
	if (avcodec_send_frame(o->enc, o->in) < 0)
		return -1;
	while (avcodec_receive_packet(o->enc, o->packet) == 0) {
		/* A PACKET PAST ONE `add frame`, or past the queue, is dropped:
		 * at 24 kbit/s neither happens. */
		if ((size_t)o->packet->size <= FZN_RPC_FRAME_MAX && o->queued_n < QUEUED_MAX) {
			memcpy(o->queued[o->queued_n], o->packet->data, (size_t)o->packet->size);
			o->queued_len[o->queued_n++] = (size_t)o->packet->size;
		}
		av_packet_unref(o->packet);
	}
	if (!o->queued_n)
		return 0;
	const size_t len = o->queued_len[0];
	if (len > cap)
		return -1;
	memcpy(packet, o->queued[0], len);
	memmove(o->queued[0], o->queued[1], (o->queued_n - 1u) * sizeof(o->queued[0]));
	memmove(&o->queued_len[0], &o->queued_len[1], (o->queued_n - 1u) * sizeof(o->queued_len[0]));
	o->queued_n--;
	return (int)len;
}

/* A PACKET IN, its samples out -- every one it holds, whatever the other
 * end's encoder chose, cut at `cap`. One that did not come is silence. */
static int decode(void *ctx, const uint8_t *packet, size_t len, int16_t *pcm, size_t cap)
{
	auto *o = static_cast<fzn_call_opus *>(ctx);
	size_t got = 0;

	if (!packet || !len)
		return 0;
	o->packet->data = const_cast<uint8_t *>(packet);
	o->packet->size = (int)len;
	const int sent = avcodec_send_packet(o->dec, o->packet);
	o->packet->data = nullptr;
	o->packet->size = 0;
	if (sent < 0)
		return -1;
	while (avcodec_receive_frame(o->dec, o->out) == 0) {
		for (int i = 0; i < o->out->nb_samples && got < cap; i++) {
			if (is_float(o->out->format)) {
				const float v = reinterpret_cast<const float *>(o->out->data[0])[i] * 32768.0f;
				pcm[got++] = (int16_t)(v > 32767.0f ? 32767 : v < -32768.0f ? -32768 : (int)v);
			} else {
				pcm[got++] = reinterpret_cast<const int16_t *>(o->out->data[0])[i];
			}
		}
		av_frame_unref(o->out);
	}
	return (int)got;
}

struct fzn_call_opus *fzn_call_opus_open(const char *encoder)
{
	/* libopus where the build has it; FFmpeg's own otherwise. */
	const AVCodec *enc = avcodec_find_encoder_by_name(encoder ? encoder : "libopus");
	if (!enc && !encoder)
		enc = avcodec_find_encoder(AV_CODEC_ID_OPUS);
	const AVCodec *dec = avcodec_find_decoder(AV_CODEC_ID_OPUS);
	if (!enc || !dec)
		return nullptr;
	auto *o = new (std::nothrow) fzn_call_opus;
	if (!o)
		return nullptr;
	o->enc = avcodec_alloc_context3(enc);
	o->dec = avcodec_alloc_context3(dec);
	o->in = av_frame_alloc();
	o->out = av_frame_alloc();
	o->packet = av_packet_alloc();
	if (!o->enc || !o->dec || !o->in || !o->out || !o->packet) {
		fzn_call_opus_close(o);
		return nullptr;
	}
	const AVChannelLayout mono = AV_CHANNEL_LAYOUT_MONO;
	o->enc->sample_rate = (int)FZN_CALL_OPUS_RATE;
	(void)av_channel_layout_copy(&o->enc->ch_layout, &mono);
	o->enc->bit_rate = 24000;
	o->enc->strict_std_compliance = FF_COMPLIANCE_EXPERIMENTAL;
	o->enc->sample_fmt = opus_format(o->enc, enc);
	/* A PACKET EACH 20 ms from either encoder, and FFmpeg's own held to one
	 * frame of delay; libopus has no such option and ignores it. */
	(void)av_opt_set(o->enc->priv_data, "frame_duration", "20", 0);
	(void)av_opt_set(o->enc->priv_data, "opus_delay", "20", 0);
	o->dec->sample_rate = (int)FZN_CALL_OPUS_RATE;
	(void)av_channel_layout_copy(&o->dec->ch_layout, &mono);
	if (o->enc->sample_fmt == AV_SAMPLE_FMT_NONE || avcodec_open2(o->enc, enc, nullptr) < 0
	    || avcodec_open2(o->dec, dec, nullptr) < 0
	    || (o->enc->frame_size > 0 && o->enc->frame_size != (int)FZN_CALL_OPUS_FRAME)) {
		fzn_call_opus_close(o);
		return nullptr;
	}
	snprintf(o->encoder, sizeof(o->encoder), "%s", enc->name);
	o->codec.ctx = o;
	o->codec.rate = FZN_CALL_OPUS_RATE;
	o->codec.frame = FZN_CALL_OPUS_FRAME;
	o->codec.encode = encode;
	o->codec.decode = decode;
	return o;
}

void fzn_call_opus_close(struct fzn_call_opus *o)
{
	if (!o)
		return;
	avcodec_free_context(&o->enc);
	avcodec_free_context(&o->dec);
	av_frame_free(&o->in);
	av_frame_free(&o->out);
	av_packet_free(&o->packet);
	delete o;
}

const fzn_call_codec_t *fzn_call_opus_codec(struct fzn_call_opus *o) { return o ? &o->codec : nullptr; }

const char *fzn_call_opus_encoder(const struct fzn_call_opus *o) { return o ? o->encoder : ""; }

#else /* no FFmpeg in this build: mu-law alone */

struct fzn_call_opus *fzn_call_opus_open(const char *encoder)
{
	(void)encoder;
	return nullptr;
}

void fzn_call_opus_close(struct fzn_call_opus *o) { (void)o; }

const fzn_call_codec_t *fzn_call_opus_codec(struct fzn_call_opus *o)
{
	(void)o;
	return nullptr;
}

const char *fzn_call_opus_encoder(const struct fzn_call_opus *o)
{
	(void)o;
	return "";
}

#endif
