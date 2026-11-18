/* A call's sound through the node: local/call_sound.h, fuzznet sec 1235. */
#include "call_sound.h"

#include <string.h>

int fzn_call_sound_start(fzn_call_sound_t *s, const char *id, uint64_t now_ms)
{
	size_t i;

	if (!s || !id || strlen(id) != FZN_RPC_ID_HEX)
		return -1;
	for (i = 0; i < FZN_RPC_ID_HEX; i++)
		if (!((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f')))
			return -1;
	memset(s, 0, sizeof(*s));
	memcpy(s->id, id, FZN_RPC_ID_HEX);
	s->started_ms = now_ms;
	s->trip_ms = -1;
	fzn_jitter_init(&s->jitter);
	fzn_jitter_init(&s->coded);
	return 0;
}

int fzn_call_sound_codec(fzn_call_sound_t *s, const fzn_call_codec_t *codec)
{
	if (!s || (codec
	           && (!codec->encode || !codec->decode || !codec->rate || codec->rate % 8000u
	               || codec->frame != codec->rate / 50u || codec->frame > FZN_CALL_SOUND_FRAME_MAX)))
		return -1;
	s->codec = codec;
	s->pending_n = 0;
	fzn_jitter_init(&s->coded);
	return 0;
}

unsigned fzn_call_sound_rate(const fzn_call_sound_t *s) { return s && s->codec ? s->codec->rate : 8000u; }

size_t fzn_call_sound_frame(const fzn_call_sound_t *s)
{
	return s && s->codec ? (size_t)s->codec->frame : (size_t)FZN_ULAW_FRAME_SAMPLES;
}

int fzn_call_sound_send(fzn_call_sound_t *s, fzn_rpc_t *c, const int16_t *pcm, size_t n,
                        uint64_t now_ms)
{
	uint8_t frame[FZN_JITTER_FRAME_MAX];
	const size_t want = fzn_call_sound_frame(s);
	size_t i, len;
	int sent = 0;

	if (!s || !c || (n && !pcm))
		return FZN_RPC_ERR_MALFORMED;
	for (i = 0; i < n; i++) {
		int taken = 0, rc;

		s->pending[s->pending_n++] = s->muted ? 0 : pcm[i];
		if (s->pending_n < want)
			continue;
		s->pending_n = 0;
		if (s->codec) {
			/* A PACKET, or none yet: a codec may hold a frame back. */
			/* AT MOST WHAT ONE `add frame` CARRIES: an Opus packet at
			 * 24 kbit/s is 60 to 90 bytes. */
			const int got = s->codec->encode(s->codec->ctx, s->pending, want, frame, FZN_RPC_FRAME_MAX);

			if (got < 0 || (size_t)got > FZN_RPC_FRAME_MAX)
				return FZN_RPC_ERR_MALFORMED;
			if (!got)
				continue;
			len = (size_t)got;
		} else {
			fzn_ulaw_encode_frame(s->pending, FZN_ULAW_FRAME_SAMPLES, frame);
			len = FZN_ULAW_FRAME_SAMPLES;
		}
		/* AT, this end's own clock from the call's start: what the other
		 * end's report gives back, for the round trip. */
		rc = fzn_rpc_frame_add(c, s->id, s->codec ? FZN_CALL_SOUND_CODED_STREAM : FZN_CALL_SOUND_ULAW_STREAM,
		                       s->seq, (uint32_t)(now_ms - s->started_ms), frame, len, &taken);
		if (rc != FZN_RPC_OK)
			return rc;
		/* NUMBERED WHETHER OR NOT IT WENT: a frame `ok lost` is a gap the
		 * other end counts, not one to fill by renumbering. */
		s->seq++;
		sent++;
	}
	return sent;
}

int fzn_call_sound_receive(fzn_call_sound_t *s, fzn_rpc_t *c)
{
	static fzn_rpc_frame_t got[8];
	int reads, taken = 0;

	if (!s || !c)
		return FZN_RPC_ERR_MALFORMED;
	/* A FEW READS AT MOST A TICK: a reply holds a few frames, and a tick
	 * that read until the node ran dry could be kept past its 20 ms. */
	for (reads = 0; reads < 4; reads++) {
		size_t n = 0, i;
		uint64_t next = s->from;
		const int rc = fzn_rpc_frames(c, s->id, s->from, got, sizeof(got) / sizeof(got[0]), &n, &next);

		if (rc != FZN_RPC_OK)
			return taken ? taken : rc;
		for (i = 0; i < n; i++)
			/* MU-LAW ON STREAM 0, THE CODEC'S ON 1 where this end has
			 * one, each whole: a frame of another stream or in pieces is
			 * another reader's. */
			if (got[i].pieces == 1u
			    && ((got[i].stream == FZN_CALL_SOUND_ULAW_STREAM
			         && fzn_jitter_take(&s->jitter, got[i].seq, got[i].media, got[i].len))
			        || (got[i].stream == FZN_CALL_SOUND_CODED_STREAM && s->codec
			            && fzn_jitter_take(&s->coded, got[i].seq, got[i].media, got[i].len))))
				taken++;
		if (next == s->from)
			break;
		s->from = next;
	}
	return taken;
}

int fzn_call_sound_play(fzn_call_sound_t *s, int16_t *out)
{
	uint8_t frame[FZN_JITTER_FRAME_MAX];
	int16_t low[FZN_ULAW_FRAME_SAMPLES];
	size_t len = 0, i, k, times;

	if (!s || !out)
		return 0;
	/* THE CODEC'S STREAM WHILE IT ARRIVES: once it is held or playing. A
	 * frame that did not come is the codec's to conceal. */
	if (s->codec && (s->coded.playing || fzn_jitter_held(&s->coded))) {
		int got;

		if (!fzn_jitter_pull(&s->coded, frame, sizeof(frame), &len))
			return 0;
		memset(out, 0, s->codec->frame * sizeof(out[0]));
		got = s->codec->decode(s->codec->ctx, len ? frame : NULL, len, out, s->codec->frame);
		if (got < 0)
			memset(out, 0, s->codec->frame * sizeof(out[0]));
		return 1;
	}
	if (!fzn_jitter_pull(&s->jitter, frame, sizeof(frame), &len))
		return 0;
	/* SILENCE where a frame did not come, or came short. */
	memset(low, 0, sizeof(low));
	fzn_ulaw_decode_frame(frame, len < FZN_ULAW_FRAME_SAMPLES ? len : FZN_ULAW_FRAME_SAMPLES, low);
	/* AT THE CODEC'S RATE, each sample repeated: what the devices run at. */
	times = fzn_call_sound_rate(s) / 8000u;
	for (i = 0; i < FZN_ULAW_FRAME_SAMPLES; i++)
		for (k = 0; k < times; k++)
			out[i * times + k] = low[i];
	return 1;
}

int fzn_call_sound_quality(fzn_call_sound_t *s, fzn_rpc_t *c, uint64_t now_ms)
{
	fzn_rpc_quality_t q;
	uint64_t heard, since;
	int rc;

	if (!s || !c)
		return FZN_RPC_ERR_MALFORMED;
	memset(&q, 0, sizeof(q));
	/* OF THE STREAM THIS END SENDS. */
	rc = fzn_rpc_quality(c, s->id, s->codec ? FZN_CALL_SOUND_CODED_STREAM : FZN_CALL_SOUND_ULAW_STREAM, &q);
	if (rc != FZN_RPC_OK)
		return rc;
	if (!q.have_sent)
		return 0;
	heard = q.sent_received + q.sent_lost;
	s->loss_pct = heard ? (unsigned)(100u * q.sent_lost / heard) : 0u;
	/* THE ROUND TRIP ON THIS END'S OWN CLOCK (sec 1026): now, less the AT
	 * of the newest frame the other end had, less how long it held it. */
	since = now_ms - s->started_ms;
	s->trip_ms = since >= q.last_at + q.held_ms ? (long)(since - q.last_at - q.held_ms) : -1;
	s->have_quality = 1;
	return 1;
}
