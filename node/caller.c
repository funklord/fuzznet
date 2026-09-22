/* See caller.h. */

#include "caller.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>

const char *fzn_caller_err_str(fzn_caller_err_t err)
{
	switch (err) {
	case FZN_CALLER_OK:
		return "ok";
	case FZN_CALLER_ERR_MALFORMED:
		return "malformed";
	case FZN_CALLER_ERR_REQUEST_TOO_LONG:
		return "request too long";
	case FZN_CALLER_ERR_SEAL:
		return "seal";
	case FZN_CALLER_ERR_SEND:
		return "send";
	case FZN_CALLER_ERR_TIMEOUT:
		return "timeout";
	case FZN_CALLER_ERR_REASSEMBLY:
		return "reassembly";
	case FZN_CALLER_ERR_REPLY_TOO_LONG:
		return "reply too long";
	}
	/* Never NULL, including for a value outside the enum, so a caller may
	 * hand this straight to a printf. */
	return "unknown";
}

fzn_caller_err_t fzn_caller_send(fzn_caller_t *caller, const uint8_t *payload,
                                 size_t payload_len, uint64_t expires_at,
                                 uint32_t *msg)
{
	uint8_t frame[FZN_UDP_DATAGRAM_MAX];
	size_t frame_len = 0;
	fzn_send_t what;

	if (!caller || caller->fd < 0 || !caller->hash || !caller->aead ||
	    !caller->rng || !msg)
		return FZN_CALLER_ERR_MALFORMED;
	if (!payload && payload_len)
		return FZN_CALLER_ERR_MALFORMED;
	/* REFUSED HERE RATHER THAN SENT. The node opens one frame per datagram
	 * on this path and reassembles nothing, so an over-large request is
	 * dropped at the far end and arrives back as a TIMEOUT -- an error
	 * about the network for a fault in the request. caller.h names the
	 * mirror piece the node would need first. */
	if (payload_len > (size_t)FZN_SPLIT_MAX_PAYLOAD)
		return FZN_CALLER_ERR_REQUEST_TOO_LONG;

	*msg = caller->next_msg++;

	memset(&what, 0, sizeof(what));
	what.sender = caller->sender;
	what.capability = caller->capability.b;
	what.payload = payload;
	what.payload_len = payload_len;
	what.expires_at = expires_at;
	what.msg = *msg;
	what.index = 0u;
	what.chunks = 1u;
	what.kind = FZN_KIND_UNIT;
	what.hops = caller->hops;
	if (fzn_seal_build(frame, sizeof(frame), &frame_len, &what,
	                   caller->send_key, caller->send_ckey, caller->hash,
	                   caller->rng, caller->aead) != FZN_SEAL_OK)
		return FZN_CALLER_ERR_SEAL;
	if (fzn_udp_send(caller->fd, &caller->node, frame, frame_len) != FZN_UDP_OK)
		return FZN_CALLER_ERR_SEND;
	return FZN_CALLER_OK;
}

fzn_caller_err_t fzn_caller_recv(fzn_caller_t *caller, uint32_t msg,
                                 uint8_t *reply, size_t reply_cap,
                                 size_t *reply_len, unsigned timeout_ms)
{
	struct timeval tv;

	if (!caller || caller->fd < 0 || !caller->hash || !caller->aead ||
	    !caller->reasm || !reply || reply_cap == 0 || !reply_len)
		return FZN_CALLER_ERR_MALFORMED;
	if (timeout_ms) {
		tv.tv_sec = (time_t)(timeout_ms / 1000u);
		tv.tv_usec = (suseconds_t)((timeout_ms % 1000u) * 1000u);
		(void)setsockopt(caller->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}

	for (;;) {
		uint8_t in[FZN_UDP_DATAGRAM_MAX];
		size_t in_len = 0;
		fzn_opened_t opened;
		fzn_partial_t *done = NULL;

		if (fzn_udp_recv(caller->fd, in, sizeof(in), &in_len, NULL) !=
		    FZN_UDP_OK)
			return FZN_CALLER_ERR_TIMEOUT;
		/* SKIPPED, NOT FATAL. This socket can receive a late reply to an
		 * earlier question, a retransmission, or a stranger's datagram.
		 * Failing on the first would let anyone able to send a packet to
		 * this port turn every request into an error; the timeout is
		 * what bounds the wait instead. */
		if (fzn_seal_open(in, in_len, caller->send_key, caller->send_ckey,
		                  caller->hash, caller->aead, &opened) != FZN_SEAL_OK)
			continue;
		if (opened.msg != msg)
			continue;

		/* ONE PIECE STILL GOES THROUGH REASSEMBLY. A reply of one frame
		 * could be copied straight out, and that second path is where a
		 * single-frame answer and a first chunk would come to be handled
		 * differently -- the same argument `node/serve.c` makes for
		 * planning every reply, including the ones that fit. */
		if (fzn_reasm_accept(caller->reasm, opened.sender, opened.msg,
		                     opened.index, opened.chunks, opened.payload,
		                     opened.payload_len, opened.expires_at, 0u,
		                     &done) != FZN_REASM_OK)
			return FZN_CALLER_ERR_REASSEMBLY;
		if (!done)
			continue;

		if (done->bytes > reply_cap) {
			/* A prefix of a reply is a different reply. The slot is
			 * released either way, or a refused answer would hold it
			 * until the table expired it. */
			fzn_reasm_release(done);
			return FZN_CALLER_ERR_REPLY_TOO_LONG;
		}
		memcpy(reply, done->buf, done->bytes);
		*reply_len = done->bytes;
		fzn_reasm_release(done);
		return FZN_CALLER_OK;
	}
}

fzn_caller_err_t fzn_caller_ask(fzn_caller_t *caller, const uint8_t *payload,
                                size_t payload_len, uint64_t expires_at,
                                uint8_t *reply, size_t reply_cap,
                                size_t *reply_len, unsigned timeout_ms)
{
	uint32_t msg = 0;
	fzn_caller_err_t err;

	/* A CALL RATHER THAN A COPY, so the two cannot come to disagree about
	 * what a request looks like or which replies belong to it. */
	err = fzn_caller_send(caller, payload, payload_len, expires_at, &msg);
	if (err != FZN_CALLER_OK)
		return err;
	return fzn_caller_recv(caller, msg, reply, reply_cap, reply_len,
	                       timeout_ms);
}
