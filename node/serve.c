/* See serve.h. */

#include "serve.h"

#include <poll.h>
#include <string.h>
#include <unistd.h>

#include "local.h"
#include "../local/socket.h"
#include "../net/udp.h"
#include "../wire/seal.h"
#include "../session/box.h" /* FZN_BOX_MARK, and nothing to link */

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
	int cfd, subscribed = 0;
	fzn_peer_t peer;

	if (fzn_socket_accept(state->listen_fd, &cfd, &peer) != FZN_SOCKET_OK)
		return;
	/* A SUBSCRIPTION TAKEN ONLY WHILE THERE IS ROOM for it, sec 609: past
	 * that, `get events` reaches the handler as any request does. */
	(void)fzn_node_serve_local_kept(&state->config, cfd, &peer, state->on_local,
	                                state->on_local_ctx,
	                                fzn_node_events_room(state->events) ? &subscribed : NULL);
	if (subscribed && fzn_node_events_add(state->events, cfd))
		return;
	(void)close(cfd);
}

/* Call the consumer's handler and send whatever it answers.
 *
 * ONE REPLY SITE, and it became a function when step 8 gave the datagram
 * path a second way to reach it. A chunked request and a single-frame one
 * must be answered identically; two copies of this would be two places for
 * the reply's bound, its sealing and its chunking to drift apart -- which is
 * the argument sec 362 already makes one layer down about sealing a
 * one-piece reply through the same plan as a twenty-piece one. */
static void serve_reply(fzn_node_state_t *state, const fzn_node_peer_t *peer,
                        const fzn_udp_addr_t *from,
                        fzn_node_remote_result_t result,
                        const fzn_opened_t *opened)
{
	uint8_t own[FZN_NODE_REPLY_MAX];
	/* The consumer's buffer where it supplied one, the node's own
	 * otherwise. A consumer answering more than 512 bytes sets
	 * `reply`/`reply_cap`; serve.h says why the default stays small. */
	uint8_t *reply = state->reply ? state->reply : own;
	size_t reply_cap = state->reply ? state->reply_cap : sizeof(own);
	size_t reply_len;

	if (!state->on_remote || !reply || reply_cap == 0)
		return;
	state->asking_from = from;
	reply_len = state->on_remote(state->on_remote_ctx, result, opened,
	                             reply, reply_cap);
	state->asking_from = NULL;
	state->asking_hops = 0;
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
			                              opened->msg, i, plan.chunks,
			                              0u, state->hash, state->rng,
			                              state->aead, reply_frame,
			                              sizeof(reply_frame),
			                              &reply_frame_len) != 0)
				return;
			/* Best effort per piece, as the single frame was:
			 * this is a datagram protocol and a lost piece is
			 * the retransmission layer's problem, not a reason
			 * to abandon the pieces that would have arrived. */
			(void)fzn_udp_send(state->udp_fd, from,
			                   reply_frame, reply_frame_len);
		}
	}
}

static void serve_ready_datagram(fzn_node_state_t *state)
{
	uint8_t frame[FZN_UDP_DATAGRAM_MAX];
	size_t flen;
	fzn_udp_addr_t from;
	const uint8_t *sender;
	const fzn_node_peer_t *peer;
	fzn_node_peer_t held;
	fzn_opened_t opened;
	fzn_node_remote_result_t result;
	uint64_t now;

	if (fzn_udp_recv(state->udp_fd, frame, sizeof(frame), &flen, &from)
	    != FZN_UDP_OK)
		return;
	/* A BOX IS NO FRAME: its first byte is one no frame's version is, so
	 * it goes to its own handler before any frame check reads it. */
	if (flen && frame[0] == FZN_BOX_MARK) {
		if (state->on_box)
			state->on_box(state->on_box_ctx, frame, flen);
		return;
	}
	now = state->clock ? state->clock() : 0u;
	/* AN ANSWER TO A FRAME THIS NODE RELAYED, sec 622: sent back, unread,
	 * to whoever asked for the relay. Asked before any key is chosen: it
	 * is sealed for somebody else, and opening it here would only drop it. */
	if (state->relay) {
		fzn_peek_t head;
		fzn_udp_addr_t back;

		if (fzn_seal_peek(frame, flen, &head) == FZN_SEAL_OK
		    && fzn_node_relay_back(state->relay, head.sender, head.msg, now, &back)) {
			(void)fzn_udp_send(state->udp_fd, &back, frame, flen);
			return;
		}
	}
	if (fzn_seal_peek_sender(frame, flen, &sender) != FZN_SEAL_OK)
		return;
	/* An unprovisioned sender is dropped: no session, nothing to open
	 * the frame with. */
	peer = fzn_node_find_peer(state->peers, state->peer_count, sender);
	if (!peer)
		return;
	/* THE PEER BY VALUE, for the whole request, its reply included: a
	 * handler that pairs or unpairs reloads the running set in place, and
	 * a pointer into it then names whichever peer the reload left at that
	 * slot -- measured in sec 614, a contact's offer answered under the
	 * session of the device it offered, which the asker could not open. A
	 * peer copied by value is self-contained (`remote.h`). */
	held = *peer;
	peer = &held;
	result = fzn_node_serve_datagram(&state->config, peer, state->hash,
	                                 state->aead, state->sign, state->replay,
	                                 now, frame, flen, &opened);
	/* THE HOP BYTE, outside the seal and so still as it came, for the
	 * handler (sec 622). */
	state->asking_hops = flen > 1u ? frame[1] : 0u;
	/* A HELLO, sec 622: a NOP that opened says where its sender is, from
	 * the socket it serves on -- a host behind a NAT keeping that socket's
	 * mapping open to the node that relays for it. Noted, and never
	 * answered: a NOP asks nothing. Only a hello is noted, since a host's
	 * other frames come from sockets nothing serves. */
	if (result != FZN_NODE_REMOTE_DROPPED && opened.kind == FZN_KIND_NOP) {
		if (state->relay)
			fzn_node_relay_saw(state->relay, peer->sender, &from, now);
		state->asking_hops = 0;
		return;
	}
	/* STEP 8. Every piece has passed steps 1 to 7 by now, which is what
	 * makes it safe to let one occupy a slot.
	 *
	 * A REQUEST OF ONE FRAME SKIPS THE TABLE ENTIRELY rather than being
	 * planned through it. That is the opposite of the reply side, where
	 * sec 362 deliberately sends a one-frame answer through the same plan
	 * as a twenty-frame one -- and the asymmetry is not an oversight. The
	 * reply side had two SEALING sites to keep in step; here there is one
	 * receive path either way, and routing every single-frame request
	 * through a table would make a node that takes no chunked requests
	 * need a table anyway. `chunks == 1` is the whole request already.
	 *
	 * A CHUNKED REQUEST WITH NO TABLE IS DROPPED, not handed up. A
	 * fragment is not the request anybody sent, and passing one to a
	 * handler that cannot tell it from a whole message is how a partial
	 * command gets executed. */
	if (result != FZN_NODE_REMOTE_DROPPED && opened.chunks > 1u) {
		fzn_partial_t *done = NULL;

		if (!state->reassembly)
			return;
		/* DENIED CHUNKS ARE NOT REASSEMBLED. A caller the node has
		 * refused must not be able to occupy slots by sending pieces,
		 * and the handler is told once -- on the first piece -- so it
		 * can answer a denial rather than one per chunk. */
		if (result == FZN_NODE_REMOTE_DENIED) {
			if (opened.index != 0u)
				return;
		} else {
			if (fzn_reasm_accept(state->reassembly, opened.sender,
			                     opened.msg, opened.index, opened.chunks,
			                     opened.payload, opened.payload_len,
			                     opened.expires_at, now, &done)
			    != FZN_REASM_OK)
				return;
			if (!done)
				return;	/* accepted, not yet whole */
			/* The handler sees the WHOLE message: the same head the
			 * last piece carried, with the payload pointing at the
			 * reassembled bytes. They live in the slot, so it is
			 * released after the handler returns and not before. */
			opened.payload = done->buf;
			opened.payload_len = done->bytes;
		}
		serve_reply(state, peer, &from, result, &opened);
		if (done)
			fzn_reasm_release(done);
		return;
	}

	/* A DROPPED FRAME NEVER AUTHENTICATED -- nothing to hand a handler.
	 * This guard was lost for one build when `serve_reply` was extracted:
	 * the call replaced an `if (result != DROPPED && state->on_remote)`
	 * block and kept only the second half of the condition. The replay
	 * case caught it, which is what a test asserting that a handler did
	 * NOT run is for -- nothing else in the suite would have noticed a
	 * handler being called too often. */
	if (result != FZN_NODE_REMOTE_DROPPED)
		serve_reply(state, peer, &from, result, &opened);
}

int fzn_node_run_once(fzn_node_state_t *state, int timeout_ms)
{
	struct pollfd fds[2u + FZN_NODE_EVENTS_MAX];
	int subscribers[FZN_NODE_EVENTS_MAX];
	nfds_t nfds = 0, first_sub;
	size_t n_sub = 0, s;
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
	/* EACH SUBSCRIBER, for hanging up or speaking out of turn. Copied, for
	 * dropping one while walking the poll's answers moves the rest. */
	first_sub = nfds;
	if (state->events)
		for (s = 0; s < state->events->n; s++) {
			subscribers[n_sub++] = state->events->fds[s];
			fds[nfds].fd = state->events->fds[s];
			fds[nfds].events = POLLIN;
			fds[nfds].revents = 0;
			nfds++;
		}
	if (nfds == 0)
		return 0;

	r = poll(fds, nfds, timeout_ms);
	if (r <= 0)
		return 0;	/* a timeout or an interrupted poll; the caller loops */

	/* SUBSCRIBERS FIRST: one dropped here frees its descriptor, and a
	 * connection accepted after could be given the same number -- taken
	 * for the one that hung up, were the order the other way. */
	for (s = 0; s < n_sub; s++)
		if (fds[first_sub + s].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) {
			(void)fzn_node_events_ready(state->events, subscribers[s]);
			handled++;
		}
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
