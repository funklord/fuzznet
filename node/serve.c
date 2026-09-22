/* See serve.h. */

#include "serve.h"

#include <poll.h>
#include <string.h>
#include <unistd.h>

#include "local.h"
#include "../local/socket.h"
#include "../net/udp.h"
#include "../wire/seal.h"

const fzn_node_peer_t *fzn_node_find_peer(const fzn_node_peer_t *peers,
                                          size_t count,
                                          const uint8_t sender[FZN_PUBKEY_LEN])
{
	size_t i;

	if (!peers || !sender)
		return NULL;
	for (i = 0; i < count; i++)
		if (memcmp(peers[i].sender, sender, FZN_PUBKEY_LEN) == 0)
			return &peers[i];
	return NULL;
}

static void serve_ready_local(fzn_node_state_t *state)
{
	int cfd;
	fzn_peer_t peer;

	if (fzn_socket_accept(state->listen_fd, &cfd, &peer) != FZN_SOCKET_OK)
		return;
	(void)fzn_node_serve_local(&state->config, cfd, &peer, state->on_local,
	                           state->on_local_ctx);
	(void)close(cfd);
}

static void serve_ready_datagram(fzn_node_state_t *state)
{
	uint8_t frame[FZN_UDP_DATAGRAM_MAX];
	size_t flen;
	fzn_udp_addr_t from;
	const uint8_t *sender;
	const fzn_node_peer_t *peer;
	fzn_opened_t opened;
	fzn_node_remote_result_t result;
	uint64_t now;

	if (fzn_udp_recv(state->udp_fd, frame, sizeof(frame), &flen, &from)
	    != FZN_UDP_OK)
		return;
	if (fzn_seal_peek_sender(frame, flen, &sender) != FZN_SEAL_OK)
		return;
	/* An unprovisioned sender is dropped: no session, nothing to open
	 * the frame with. */
	peer = fzn_node_find_peer(state->peers, state->peer_count, sender);
	if (!peer)
		return;
	now = state->clock ? state->clock() : 0u;
	result = fzn_node_serve_datagram(&state->config, peer, state->hash,
	                                 state->aead, state->sign, state->replay,
	                                 now, frame, flen, &opened);
	/* A dropped frame never authenticated -- nothing to hand a handler. */
	if (result != FZN_NODE_REMOTE_DROPPED && state->on_remote) {
		uint8_t own[FZN_NODE_REPLY_MAX];
		/* The consumer's buffer where it supplied one, the node's own
		 * otherwise. A consumer answering more than 512 bytes sets
		 * `reply`/`reply_cap`; serve.h says why the default stays small. */
		uint8_t *reply = state->reply ? state->reply : own;
		size_t reply_cap = state->reply ? state->reply_cap : sizeof(own);
		size_t reply_len;

		if (!reply || reply_cap == 0)
			return;
		reply_len = state->on_remote(state->on_remote_ctx, result, &opened,
		                             reply, reply_cap);
		/* A handler claiming more than it was given wrote nothing this
		 * loop may send -- the same refusal the local seam makes, and for
		 * the same reason: sending `reply_cap` of it would be a different
		 * reply rather than a shorter one. */
		if (reply_len > reply_cap)
			reply_len = 0;
		/* Seal the handler's reply under the peer session and send it back
		 * to where the datagram came from. */
		if (reply_len > 0 && state->rng) {
			uint8_t reply_frame[FZN_UDP_DATAGRAM_MAX];
			size_t reply_frame_len;
			fzn_split_t plan;
			uint16_t i;

			/* ONE PLAN FOR BOTH CASES. A reply that fits in a frame
			 * plans as one piece, so there is no short path here to
			 * disagree with the long one -- which is where a
			 * single-frame reply and a first chunk would come to be
			 * sealed differently. `fzn_split_plan` refuses a reply
			 * larger than a receiver will reassemble, so a plan that
			 * plans is a reply that can arrive. */
			if (fzn_split_plan(reply_len, FZN_SPLIT_MAX_PAYLOAD, &plan)
			    != FZN_SPLIT_OK)
				return;
			for (i = 0; i < plan.chunks; i++) {
				size_t off = 0, len = 0;

				if (fzn_split_at(&plan, i, &off, &len) != FZN_SPLIT_OK)
					return;
				if (fzn_node_seal_reply_chunk(peer, state->node_pubkey,
				                              reply + off, len,
				                              opened.msg, i, plan.chunks,
				                              0u, state->hash, state->rng,
				                              state->aead, reply_frame,
				                              sizeof(reply_frame),
				                              &reply_frame_len) != 0)
					return;
				/* Best effort per piece, as the single frame was:
				 * this is a datagram protocol and a lost piece is
				 * the retransmission layer's problem, not a reason
				 * to abandon the pieces that would have arrived. */
				(void)fzn_udp_send(state->udp_fd, &from,
				                   reply_frame, reply_frame_len);
			}
		}
	}
}

int fzn_node_run_once(fzn_node_state_t *state, int timeout_ms)
{
	struct pollfd fds[2];
	nfds_t nfds = 0;
	int li = -1, ui = -1, handled = 0, r;

	if (!state)
		return 0;
	if (state->listen_fd >= 0) {
		fds[nfds].fd = state->listen_fd;
		fds[nfds].events = POLLIN;
		fds[nfds].revents = 0;
		li = (int)nfds;
		nfds++;
	}
	if (state->udp_fd >= 0) {
		fds[nfds].fd = state->udp_fd;
		fds[nfds].events = POLLIN;
		fds[nfds].revents = 0;
		ui = (int)nfds;
		nfds++;
	}
	if (nfds == 0)
		return 0;

	r = poll(fds, nfds, timeout_ms);
	if (r <= 0)
		return 0;	/* a timeout or an interrupted poll; the caller loops */

	if (li >= 0 && (fds[li].revents & POLLIN)) {
		serve_ready_local(state);
		handled++;
	}
	if (ui >= 0 && (fds[ui].revents & POLLIN)) {
		serve_ready_datagram(state);
		handled++;
	}
	return handled;
}

void fzn_node_run(fzn_node_state_t *state)
{
	for (;;)
		(void)fzn_node_run_once(state, -1);
}
