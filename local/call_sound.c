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
	return 0;
}

int fzn_call_sound_send(fzn_call_sound_t *s, fzn_rpc_t *c, const int16_t *pcm, size_t n,
                        uint64_t now_ms)
{
	uint8_t frame[FZN_ULAW_FRAME_SAMPLES];
	size_t i;
	int sent = 0;

	if (!s || !c || (n && !pcm))
		return FZN_RPC_ERR_MALFORMED;
	for (i = 0; i < n; i++) {
		int taken = 0, rc;

		s->pending[s->pending_n++] = s->muted ? 0 : pcm[i];
		if (s->pending_n < FZN_ULAW_FRAME_SAMPLES)
			continue;
		s->pending_n = 0;
		fzn_ulaw_encode_frame(s->pending, FZN_ULAW_FRAME_SAMPLES, frame);
		/* AT, this end's own clock from the call's start: what the other
		 * end's report gives back, for the round trip. */
		rc = fzn_rpc_frame_add(c, s->id, 0, s->seq, (uint32_t)(now_ms - s->started_ms), frame, sizeof(frame),
		                       &taken);
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
			/* MU-LAW, WHOLE: stream 0, one piece -- a frame of another
			 * stream or in pieces is another reader's. */
			if (got[i].stream == 0u && got[i].pieces == 1u
			    && fzn_jitter_take(&s->jitter, got[i].seq, got[i].media, got[i].len))
				taken++;
		if (next == s->from)
			break;
		s->from = next;
	}
	return taken;
}

int fzn_call_sound_play(fzn_call_sound_t *s, int16_t out[FZN_ULAW_FRAME_SAMPLES])
{
	uint8_t frame[FZN_JITTER_FRAME_MAX];
	size_t len = 0;

	if (!s || !out || !fzn_jitter_pull(&s->jitter, frame, sizeof(frame), &len))
		return 0;
	/* SILENCE where a frame did not come, or came short. */
	memset(out, 0, FZN_ULAW_FRAME_SAMPLES * sizeof(out[0]));
	fzn_ulaw_decode_frame(frame, len < FZN_ULAW_FRAME_SAMPLES ? len : FZN_ULAW_FRAME_SAMPLES, out);
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
	rc = fzn_rpc_quality(c, s->id, 0, &q);
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
