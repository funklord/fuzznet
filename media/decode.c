/*
 * A file's sound through FFmpeg: media/decode.h, project.md sec 1457.
 */
#include "decode.h"
#include "analysis.h"

#ifdef FZN_MEDIA_DECODE_ON

#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/channel_layout.h>
#include <libavutil/log.h>
#include <libavutil/opt.h>
#include <libswresample/swresample.h>

#include <stdlib.h>

#define OUT_FRAMES 4096

int fzn_media_decode_available(void)
{
	return 1;
}

/* Converted frames handed on, as many as `left` still wants: 0 to stop. */
static int hand_on(SwrContext *swr, const uint8_t **in, int in_frames, float *out, uint64_t *left,
                   fzn_media_frames_t frames, void *ctx)
{
	for (;;) {
		uint8_t *planes[1] = { (uint8_t *)out };
		int n = swr_convert(swr, planes, OUT_FRAMES, in, in_frames);

		if (n < 0)
			return 0;
		if (n == 0)
			return 1;
		if ((uint64_t)n > *left)
			n = (int)*left;
		*left -= (uint64_t)n;
		if (!frames(ctx, out, (size_t)n) || !*left)
			return 0;
		in = NULL;
		in_frames = 0;
	}
}

fzn_media_decode_result_t fzn_media_decode(const char *path, double max_seconds, fzn_media_frames_t frames,
                                           void *ctx, const volatile int *stop)
{
	float *out = NULL;
	AVFormatContext *format = NULL;
	AVCodecContext *codec = NULL;
	const AVCodec *decoder = NULL;
	SwrContext *swr = NULL;
	AVPacket *packet = NULL;
	AVFrame *frame = NULL;
	AVChannelLayout stereo = AV_CHANNEL_LAYOUT_STEREO;
	fzn_media_decode_result_t result = FZN_MEDIA_DECODE_NO_SOUND;
	uint64_t left = max_seconds > 0 ? (uint64_t)(max_seconds * FZN_MEDIA_ANALYSIS_RATE) : UINT64_MAX;
	int stream, going = 1;

	if (!path || !frames)
		return FZN_MEDIA_DECODE_NO_SOUND;
	av_log_set_level(AV_LOG_QUIET);
	if (avformat_open_input(&format, path, NULL, NULL) < 0)
		return FZN_MEDIA_DECODE_NO_SOUND;
	if (avformat_find_stream_info(format, NULL) < 0
	    || (stream = av_find_best_stream(format, AVMEDIA_TYPE_AUDIO, -1, -1, &decoder, 0)) < 0 || !decoder
	    || !(codec = avcodec_alloc_context3(decoder))
	    || avcodec_parameters_to_context(codec, format->streams[stream]->codecpar) < 0
	    || avcodec_open2(codec, decoder, NULL) < 0 || !(packet = av_packet_alloc()) || !(frame = av_frame_alloc())
	    || !(out = malloc(2u * OUT_FRAMES * sizeof(*out))))
		goto done;
	if (codec->ch_layout.order == AV_CHANNEL_ORDER_UNSPEC)
		av_channel_layout_default(&codec->ch_layout, codec->ch_layout.nb_channels);
	if (swr_alloc_set_opts2(&swr, &stereo, AV_SAMPLE_FMT_FLT, (int)FZN_MEDIA_ANALYSIS_RATE, &codec->ch_layout,
	                        codec->sample_fmt, codec->sample_rate, 0, NULL)
	            < 0
	    || swr_init(swr) < 0)
		goto done;
	result = FZN_MEDIA_DECODE_OK;
	while (going && av_read_frame(format, packet) >= 0) {
		if (stop && *stop) {
			result = FZN_MEDIA_DECODE_STOPPED;
			going = 0;
		} else if (packet->stream_index == stream && avcodec_send_packet(codec, packet) >= 0) {
			while (going && avcodec_receive_frame(codec, frame) >= 0) {
				if (!hand_on(swr, (const uint8_t **)frame->extended_data, frame->nb_samples, out, &left, frames,
				             ctx)) {
					result = left ? FZN_MEDIA_DECODE_STOPPED : FZN_MEDIA_DECODE_OK;
					going = 0;
				}
				av_frame_unref(frame);
			}
		}
		av_packet_unref(packet);
	}
	/* WHAT THE DECODER AND THE RESAMPLER STILL HOLD, at the end. */
	if (going && avcodec_send_packet(codec, NULL) >= 0) {
		while (going && avcodec_receive_frame(codec, frame) >= 0) {
			if (!hand_on(swr, (const uint8_t **)frame->extended_data, frame->nb_samples, out, &left, frames, ctx)) {
				result = left ? FZN_MEDIA_DECODE_STOPPED : FZN_MEDIA_DECODE_OK;
				going = 0;
			}
			av_frame_unref(frame);
		}
	}
	if (going && !hand_on(swr, NULL, 0, out, &left, frames, ctx) && left)
		result = FZN_MEDIA_DECODE_STOPPED;
done:
	free(out);
	av_frame_free(&frame);
	av_packet_free(&packet);
	swr_free(&swr);
	avcodec_free_context(&codec);
	avformat_close_input(&format);
	return result;
}

#else

int fzn_media_decode_available(void)
{
	return 0;
}

fzn_media_decode_result_t fzn_media_decode(const char *path, double max_seconds, fzn_media_frames_t frames,
                                           void *ctx, const volatile int *stop)
{
	(void)path;
	(void)max_seconds;
	(void)frames;
	(void)ctx;
	(void)stop;
	return FZN_MEDIA_DECODE_NONE;
}

#endif
