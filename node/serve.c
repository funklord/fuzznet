/* See serve.h. */

#define _POSIX_C_SOURCE 200809L /* clock_gettime */

#include "serve.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "local.h"
#include "sessions.h"
#include "types.h"
#include "../local/socket.h"
#include "../net/udp.h"
#include "../wire/bytes.h"
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


/* WHETHER `frame` IS SEALED FOR THIS NODE by `sender`, one of its peers:
 * opened on a copy, so the frame goes on whole if it is not. sec 871. */
static int opens_here(const fzn_node_state_t *state, const uint8_t *frame, size_t flen,
                      const uint8_t *sender)
{
	static uint8_t trial[FZN_UDP_DATAGRAM_MAX];
	const fzn_node_peer_t *peer;
	fzn_opened_t opened;

	if (!state->hash || !state->aead || flen > sizeof(trial)
	    || !(peer = fzn_node_find_peer(state->peers, state->peer_count, sender)))
		return 0;
	memcpy(trial, frame, flen);
	return fzn_seal_open(trial, flen, peer->recv_key, peer->recv_ckey, state->hash, state->aead,
	                     &opened)
	       == FZN_SEAL_OK;
}

/* A LOCAL CONNECTION WAITING FOR ITS REQUEST, sec 903. Reading it at once, as
 * this did, let a client that opened and said nothing hold the node for 5 s,
 * and everyone behind it: a hundred such were eight minutes of a daemon not
 * answering. So it waits here, polled with the rest, and is served when its
 * line has come whole. */
#define WAITING_MS 5000u

struct fzn_node_waiting {
	int fd;
	fzn_peer_t peer;
	uint64_t since_ms;
};

static uint64_t monotonic_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void waiting_drop(fzn_node_state_t *state, size_t i)
{
	state->waiting[i] = state->waiting[--state->n_waiting];
}

static void serve_connection(fzn_node_state_t *state, int cfd, const fzn_peer_t *peer)
{
	int subscribed = 0, held = 0;

	(void)fzn_node_serve_local_held(&state->config, cfd, peer, state->on_local,
	                                state->on_local_ctx, state->events ? &subscribed : NULL,
	                                state->on_local_denied, state->on_local_denied_ctx,
	                                state->hears, state->hears_ctx, &held);
	if (subscribed
	    && (held ? fzn_node_events_add_held(state->events, cfd)
	             : fzn_node_events_add(state->events, cfd)))
		return;
	(void)close(cfd);
}

/* WAITING CONNECTION `i`: served once its line is whole, or a line's room is
 * full, which the request's reader refuses; closed when it hung up. */
static void waiting_step(fzn_node_state_t *state, size_t i)
{
	uint8_t peek[FZN_REQUEST_MAX + 1u];
	struct fzn_node_waiting w = state->waiting[i];
	ssize_t n = recv(w.fd, peek, sizeof(peek), MSG_PEEK | MSG_DONTWAIT);

	if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
		return;
	waiting_drop(state, i);
	if (n <= 0) {
		(void)close(w.fd);
		return;
	}
	if (!memchr(peek, '\n', (size_t)n) && (size_t)n < sizeof(peek)) {
		state->waiting[state->n_waiting++] = w;
		return;
	}
	{
		uint64_t began = monotonic_ms(), took;

		serve_connection(state, w.fd, &w.peer);
		took = monotonic_ms() - began;
		if (took >= state->held_what_ms) {
			size_t at = 0, words = 0;

			/* THE VERB AND ITS SUBJECT, printable, two words at most. */
			while (at < (size_t)n && at + 1u < sizeof(state->held_what)) {
				uint8_t c = peek[at];

				if (c == ' ' && ++words == 2u)
					break;
				if (c < 0x20u || c >= 0x7fu)
					break;
				state->held_what[at++] = (char)c;
			}
			state->held_what[at] = '\0';
			state->held_what_ms = took;
		}
	}
}

/* EVERY CONNECTION THE LISTENER HOLDS, not one a pass: a pass polls everything
 * open, so one at a time is that cost for each of thousands. */
static void serve_ready_local(fzn_node_state_t *state)
{
	int cfd, flags = fcntl(state->listen_fd, F_GETFL);
	fzn_peer_t peer;

	if (flags >= 0 && !(flags & O_NONBLOCK))
		(void)fcntl(state->listen_fd, F_SETFL, flags | O_NONBLOCK);
	while (fzn_socket_accept(state->listen_fd, &cfd, &peer) == FZN_SOCKET_OK) {
		if (state->n_waiting == state->waiting_cap) {
			size_t cap = state->waiting_cap ? state->waiting_cap * 2u : 16u;
			struct fzn_node_waiting *more = realloc(state->waiting, cap * sizeof(*more));

			if (!more) {
				(void)close(cfd);
				return;
			}
			state->waiting = more;
			state->waiting_cap = cap;
		}
		state->waiting[state->n_waiting].fd = cfd;
		state->waiting[state->n_waiting].peer = peer;
		state->waiting[state->n_waiting].since_ms = monotonic_ms();
		state->n_waiting++;
		waiting_step(state, state->n_waiting - 1u);
	}
}

/* Call the consumer's handler and send whatever it answers.
 *
 * ONE REPLY SITE, and it became a function when step 8 gave the datagram
 * path a second way to reach it. A chunked request and a single-frame one
 * must be answered identically; two copies of this would be two places for
 * the reply's bound, its sealing and its chunking to drift apart -- which is
 * the argument sec 362 already makes one layer down about sealing a
 * one-piece reply through the same plan as a twenty-piece one. */
/* SEAL AND SEND `reply` back to where the datagram came from, under the
 * peer's session, in as many pieces as it takes; `on_replied` told how
 * many went. */
static void send_reply(fzn_node_state_t *state, const fzn_node_peer_t *peer,
                       const fzn_udp_addr_t *from, const fzn_opened_t *opened,
                       const uint8_t *reply, size_t reply_len, int kept)
{
	uint8_t reply_frame[FZN_UDP_DATAGRAM_MAX];
	size_t reply_frame_len;
	fzn_split_t plan;
	uint16_t i;
	unsigned sent = 0;

	if (reply_len == 0u || !state->rng)
		return;
	/* IN THE SESSION IT CAME IN, where it fits; in pieces otherwise, as a
	 * session frame is one unit and a peer holding a session still opens full
	 * frames. */
	if (state->answering && reply_len <= FZN_SESSION_FRAME_PAYLOAD_MAX) {
		fzn_node_session_t *s = &state->sessions->table[state->answering - 1u];

		if (fzn_session_frame_seal(&s->end, opened->msg, 0u, reply, reply_len, reply_frame,
		                           sizeof(reply_frame), &reply_frame_len, state->aead)
		    == FZN_SESSION_FRAME_OK) {
			if (fzn_udp_send(state->udp_fd, from, reply_frame, reply_frame_len) == FZN_UDP_OK)
				sent = 1u;
			if (state->on_replied)
				state->on_replied(state->on_replied_ctx, opened, reply_len, sent, 1u, kept,
				                  from);
			return;
		}
	}
	/* ONE PLAN FOR BOTH CASES. A reply that fits in a frame
	 * plans as one piece, so there is no short path here to
	 * disagree with the long one -- which is where a
	 * single-frame reply and a first chunk would come to be
	 * sealed differently. `fzn_split_plan` refuses a reply
	 * larger than a receiver will reassemble, so a plan that
	 * plans is a reply that can arrive. */
	if (fzn_split_plan(reply_len, FZN_SPLIT_MAX_PAYLOAD, &plan) != FZN_SPLIT_OK)
		return;
	for (i = 0; i < plan.chunks; i++) {
		size_t off = 0, len = 0;

		if (fzn_split_at(&plan, i, &off, &len) != FZN_SPLIT_OK)
			break;
		if (fzn_node_seal_reply_chunk(peer, state->node_pubkey, reply + off, len,
		                              opened->msg, i, plan.chunks, 0u, state->hash,
		                              state->rng, state->aead, reply_frame,
		                              sizeof(reply_frame), &reply_frame_len)
		    != 0)
			break;
		/* Best effort per piece, as the single frame was:
		 * this is a datagram protocol and a lost piece is
		 * the retransmission layer's problem, not a reason
		 * to abandon the pieces that would have arrived. */
		if (fzn_udp_send(state->udp_fd, from, reply_frame, reply_frame_len) == FZN_UDP_OK)
			sent++;
	}
	if (state->on_replied)
		state->on_replied(state->on_replied_ctx, opened, reply_len, sent, plan.chunks, kept,
		                  from);
}

static void serve_reply(fzn_node_state_t *state, const fzn_node_peer_t *peer,
                        const fzn_udp_addr_t *from,
                        fzn_node_remote_result_t result,
                        const fzn_opened_t *opened, uint64_t now)
{
	uint8_t own[FZN_NODE_REPLY_MAX];
	/* The consumer's buffer where it supplied one, the node's own
	 * otherwise. A consumer answering more than 512 bytes sets
	 * `reply`/`reply_cap`; serve.h says why the default stays small. */
	uint8_t *reply = state->reply ? state->reply : own;
	size_t reply_cap = state->reply ? state->reply_cap : sizeof(own);
	size_t reply_len;
	const uint8_t *kept;

	if (!state->on_remote || !reply || reply_cap == 0)
		return;
	/* A REQUEST RESENT, sec 737: answered as it was the first time, its
	 * handler not run again. */
	if (state->replies
	    && (kept = fzn_node_replies_find(state->replies, opened->sender, opened->msg,
	                                     opened->payload, opened->payload_len, now,
	                                     &reply_len))
	               != NULL) {
		if (fzn_node_replies_answers(state->replies, kept, from->storage, from->len))
			send_reply(state, peer, from, opened, kept, reply_len, 1);
		return;
	}
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
	if (reply_len > 0 && state->replies) {
		fzn_node_replies_keep(state->replies, opened->sender, opened->msg, opened->expires_at,
		                      opened->payload, opened->payload_len, now, reply, reply_len);
		fzn_node_replies_where(state->replies, opened->sender, opened->msg, from->storage,
		                       from->len);
	}
	send_reply(state, peer, from, opened, reply, reply_len, 0);
}

/* A PEER ASKS FOR A SESSION, its full frame having opened and passed: granted, in
 * a full frame, or not answered at all, when it stays on full frames. */
static void serve_session_ask(fzn_node_state_t *state, const fzn_node_peer_t *peer,
                              const fzn_udp_addr_t *from, const fzn_opened_t *opened, uint64_t now)
{
	uint8_t grant[2u + FZN_SESSION_GRANT_LEN];
	uint64_t now_ms = state->clock_ms ? state->clock_ms() : now * 1000u;
	const uint8_t *ask = fzn_node_session_ask_body(opened->payload, opened->payload_len);

	grant[0] = FZN_TYPES_VERSION_SHARED;
	grant[1] = FZN_TYPE_SESSION_GRANT;
	if (ask
	    && fzn_node_sessions_grant(state->sessions, peer->sender, opened->capability,
	                               peer->recv_key, ask, now_ms, state->hash, state->rng,
	                               grant + 2u))
		send_reply(state, peer, from, opened, grant, sizeof(grant), 0);
}

/* A SESSION FRAME, sec 932. What its handle finds says who it is from; the
 * rest is a full frame's way, with the peer as it stands now: gone, or paired
 * afresh, and the session is too, and a capability is judged here, each frame.
 * Nothing is said to what does not open: nobody can be named to say it to. */
static void serve_session_frame(fzn_node_state_t *state, uint8_t *frame, size_t flen,
                                const fzn_udp_addr_t *from)
{
	fzn_node_sessions_t *sessions = state->sessions;
	fzn_session_opened_t got;
	fzn_node_session_t *s;
	const fzn_node_peer_t *found;
	fzn_node_peer_t held;
	fzn_opened_t opened;
	fzn_node_remote_result_t result;
	uint8_t nonce[FZN_AEAD_NONCE_LEN];
	uint8_t sender[FZN_PUBKEY_LEN], capability[FZN_CAP_ID_LEN];
	uint32_t handle;
	uint64_t now;

	if (!sessions || !state->aead || !fzn_session_frame_handle(frame, flen, &handle))
		return;
	if (!(s = fzn_node_sessions_find(sessions, handle))) {
		/* A SESSION RELAYED, sec 1045: no session of this host's own holds the
		 * handle, and a way stands for it from where the frame came -- sent on,
		 * unread. A frame of this host's own is never forwarded: its handle
		 * finds its session first. */
		fzn_udp_addr_t to;

		if (state->relay && state->udp_fd >= 0
		    && fzn_node_relay_session_to(state->relay, from, handle,
		                                 state->clock ? state->clock() : 0u, &to))
			(void)fzn_udp_send(state->udp_fd, &to, frame, flen);
		return;
	}
	found = fzn_node_find_peer(state->peers, state->peer_count, s->sender);
	/* A SESSION THIS HOST ASKED, sec 1018, is rooted in the key it sends under,
	 * which between two hosts of an estate is the key its peer row holds:
	 * measured, so the same check stands for both ends. */
	if (!found || memcmp(found->recv_key, s->root, FZN_AEAD_KEY_LEN) != 0) {
		fzn_node_sessions_drop(s);
		return;
	}
	held = *found;
	if (fzn_session_frame_open(&s->end, frame, flen, state->aead, &got) != FZN_SESSION_FRAME_OK)
		return;
	fzn_node_sessions_confirm(sessions, s);
	if (from->len <= sizeof(s->from)) {
		memcpy(s->from, from->storage, from->len);
		s->from_len = from->len;
	}
	now = state->clock ? state->clock() : 0u;
	/* THE FULL FRAME'S EXPIRY, read after the seal as it was sealed: a frame
	 * held back and let go later is refused as one would be. The counter
	 * has done the replay's work. */
	if (!state->replay || got.expires_at <= now || got.expires_at > now + state->replay->max_ahead) {
		if (state->on_stale && state->replay)
			state->on_stale(state->on_stale_ctx, held.sender, got.expires_at, now,
			                state->replay->max_ahead);
		return;
	}
	/* HELD BY VALUE, as a handler may grow nothing here but may reload peers,
	 * and the table is read again by slot when the answer goes. */
	memcpy(sender, s->sender, sizeof(sender));
	memcpy(capability, s->capability, sizeof(capability));
	memset(nonce, 0, sizeof(nonce));
	fzn_put_be32(nonce + sizeof(nonce) - 4u, got.counter);
	memset(&opened, 0, sizeof(opened));
	opened.sender = sender;
	opened.capability = capability;
	opened.nonce = nonce;
	opened.payload = got.payload;
	opened.payload_len = got.payload_len;
	opened.expires_at = got.expires_at;
	opened.msg = got.msg;
	opened.chunks = 1u;
	opened.kind = FZN_KIND_UNIT;
	result = fzn_node_serve_authorise(&state->config, &held, state->sign, now, &opened);
	state->asking_hops = 0;
	/* SAID, sec 935: nothing to answer, and nothing kept. */
	if (got.msg == 0u) {
		if (result == FZN_NODE_REMOTE_GRANTED && state->on_said)
			state->on_said(state->on_said_ctx, &opened);
		return;
	}
	state->answering = (size_t)(s - sessions->table) + 1u;
	serve_reply(state, &held, from, result, &opened, now);
	state->answering = 0;
}

int fzn_node_serve_say(fzn_node_state_t *state, const uint8_t sender[FZN_PUBKEY_LEN],
                       const uint8_t *payload, size_t len)
{
	uint8_t frame[FZN_SESSION_FRAME_MAX];
	fzn_node_session_t *s;
	fzn_udp_addr_t to;
	size_t frame_len = 0;
	uint64_t now = state && state->clock ? state->clock() : 0u, ahead = 30u;

	/* AN EXPIRY A HOST TAKES, sec 1018: 0 was taken by a device, which reads
	 * none, and refused by a host as expired. */
	if (state && state->replay && state->replay->max_ahead < ahead)
		ahead = state->replay->max_ahead;
	if (!state || !state->aead || !(s = fzn_node_sessions_of(state->sessions, sender))
	    || !s->from_len
	    || fzn_session_frame_seal(&s->end, 0u, (uint32_t)(now + ahead), payload, len, frame,
	                              sizeof(frame), &frame_len, state->aead)
	               != FZN_SESSION_FRAME_OK)
		return 0;
	memcpy(to.storage, s->from, s->from_len);
	to.len = s->from_len;
	return fzn_udp_send(state->udp_fd, &to, frame, frame_len) == FZN_UDP_OK;
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
			state->on_box(state->on_box_ctx, frame, flen, &from);
		return;
	}
	/* A SESSION FRAME, the same way. */
	if (flen && frame[0] == FZN_SESSION_FRAME_MARK) {
		serve_session_frame(state, frame, flen, &from);
		return;
	}
	/* A LAN PROBE, sec 624, the same way. */
	if (flen && frame[0] == FZN_NODE_PROBE_MARK) {
		if (state->on_probe)
			state->on_probe(state->on_probe_ctx, frame, flen, &from);
		return;
	}
	now = state->clock ? state->clock() : 0u;
	/* AN ANSWER TO A FRAME THIS NODE RELAYED, sec 622: sent back, unread,
	 * to whoever asked for the relay -- unless the frame is this node's
	 * own, sec 871. A route keys on the sender and the message id, and a
	 * peer's frame to THIS node under the same id within the route's life
	 * was sent to the asker, who could not open it, and lost here. The
	 * head names no recipient, so the frame says whose it is by opening:
	 * tried on a copy under the sender's session with this node, which an
	 * answer sealed for the asker does not open (a wrong key fails at the
	 * commitment, before any AEAD). */
	if (state->relay) {
		fzn_peek_t head;
		fzn_udp_addr_t back;

		if (fzn_seal_peek(frame, flen, &head) == FZN_SEAL_OK
		    && fzn_node_relay_back(state->relay, head.sender, head.msg, now, &back)
		    /* THIS HOST'S OWN ROUTE, sec 1031: an answer to its own ask, which
		     * opens here and is still for the socket awaiting it. */
		    && (fzn_node_relay_owns(state->relay, head.sender, head.msg, now)
		        || !opens_here(state, frame, flen, head.sender))) {
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
	memset(&opened, 0, sizeof(opened));
	result = fzn_node_serve_datagram(&state->config, peer, state->hash,
	                                 state->aead, state->sign, state->replay,
	                                 now, frame, flen, &opened);
	/* DROPPED WITH AN EXPIRY OPENED: the seal opened, so it is the peer's
	 * own frame, and freshness refused it. Its clock, if the expiry is
	 * outside the window either way; a replay inside it says nothing. */
	if (result == FZN_NODE_REMOTE_DROPPED && opened.expires_at && state->on_stale && state->replay
	    && (opened.expires_at <= now || opened.expires_at > now + state->replay->max_ahead))
		state->on_stale(state->on_stale_ctx, peer->sender, opened.expires_at, now,
		                state->replay->max_ahead);
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
	/* A SESSION ASKED FOR, sec 932: by a caller that stands, and answered by
	 * nothing else. A denied one is told nothing. */
	if (result != FZN_NODE_REMOTE_DROPPED
	    && fzn_node_session_ask_body(opened.payload, opened.payload_len)) {
		if (result == FZN_NODE_REMOTE_GRANTED && state->sessions)
			serve_session_ask(state, peer, &from, &opened, now);
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
			const uint8_t *kept;
			size_t kept_len;
			fzn_reasm_err_t rerr;

			/* A PIECE OF A REQUEST ANSWERED ALREADY, sec 741: a resend's,
			 * or one late from the first sending. Reassembled, a late one
			 * opened a partial nothing finished, and its sender's one
			 * slot was held for the whole hold: every chunked request it
			 * sent next was refused. The first piece is answered with
			 * the kept reply, once per sending rather than once a piece;
			 * the others are dropped. */
			if (state->replies
			    && (kept = fzn_node_replies_find_piece(state->replies, opened.sender,
			                                           opened.msg, opened.expires_at,
			                                           now, &kept_len))
			               != NULL) {
				if (opened.index == 0u
				    && fzn_node_replies_answers(state->replies, kept, from.storage, from.len))
					send_reply(state, peer, &from, &opened, kept, kept_len, 1);
				return;
			}
			rerr = fzn_reasm_accept(state->reassembly, opened.sender, opened.msg,
			                        opened.index, opened.chunks, opened.payload,
			                        opened.payload_len, opened.expires_at, now, &done);
			if (rerr != FZN_REASM_OK) {
				/* SAID, sec 741: a refused piece was silence at both
				 * ends, and a sender over its quota looked like a node
				 * that had stopped answering. */
				if (state->on_refused)
					state->on_refused(state->on_refused_ctx, &opened, rerr, &from);
				return;
			}
			if (!done)
				return;	/* accepted, not yet whole */
			/* The handler sees the WHOLE message: the same head the
			 * last piece carried, with the payload pointing at the
			 * reassembled bytes. They live in the slot, so it is
			 * released after the handler returns and not before. */
			opened.payload = done->buf;
			opened.payload_len = done->bytes;
		}
		serve_reply(state, peer, &from, result, &opened, now);
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
		serve_reply(state, peer, &from, result, &opened, now);
}

void fzn_node_serve_release(fzn_node_state_t *state)
{
	size_t i;

	if (!state)
		return;
	for (i = 0; i < state->n_waiting; i++)
		(void)close(state->waiting[i].fd);
	free(state->waiting);
	free(state->polled);
	free(state->wait_polled);
	free(state->polled_subscribers);
	state->waiting = NULL;
	state->polled = NULL;
	state->wait_polled = NULL;
	state->polled_subscribers = NULL;
	state->n_waiting = state->waiting_cap = state->polled_cap = state->wait_polled_cap = 0;
}

int fzn_node_run_once(fzn_node_state_t *state, int timeout_ms)
{
	struct pollfd *fds;
	int *subscribers, awaited[FZN_NODE_ASKS_MAX], own[FZN_NODE_OWN_FDS_MAX];
	nfds_t nfds = 0, first_sub, first_ask, first_own, first_wait;
	size_t n_sub = 0, n_ask = 0, n_own = 0, n_wait, s, want;
	int li = -1, ui = -1, handled = 0, r;
	uint64_t now_ms;

	if (!state)
		return 0;
	/* ROOM FOR EVERY DESCRIPTOR, however many are open, sec 903. */
	want = 2u + (state->events ? state->events->n : 0u) + state->n_waiting + FZN_NODE_ASKS_MAX
	       + FZN_NODE_OWN_FDS_MAX;
	if (want > state->polled_cap) {
		size_t cap = want * 2u;
		struct pollfd *more = realloc(state->polled, cap * sizeof(*more));
		int *subs;

		if (!more)
			return 0;
		state->polled = more;
		subs = realloc(state->polled_subscribers, cap * sizeof(*subs));
		if (!subs)
			return 0;
		state->polled_subscribers = subs;
		state->polled_cap = cap;
	}
	fds = state->polled;
	subscribers = state->polled_subscribers;
	/* A CONNECTION THAT SAID NOTHING IN TIME goes, as it went by its read's
	 * timeout. Backward, as dropping one moves the last into its place. */
	now_ms = monotonic_ms();
	for (s = state->n_waiting; s > 0u; s--)
		if (now_ms - state->waiting[s - 1u].since_ms >= WAITING_MS) {
			(void)close(state->waiting[s - 1u].fd);
			waiting_drop(state, s - 1u);
		}
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
	/* EACH LOCAL CONNECTION STILL SAYING ITS REQUEST, sec 903. */
	first_wait = nfds;
	n_wait = state->n_waiting;
	for (s = 0; s < n_wait; s++) {
		fds[nfds].fd = state->waiting[s].fd;
		fds[nfds].events = POLLIN;
		fds[nfds].revents = 0;
		nfds++;
	}
	/* EACH SOCKET A REQUEST AWAITS ITS ANSWER ON, sec 636. */
	first_ask = nfds;
	if (state->asks) {
		n_ask = fzn_node_asks_fds(state->asks, awaited, FZN_NODE_ASKS_MAX);
		for (s = 0; s < n_ask; s++) {
			fds[nfds].fd = awaited[s];
			fds[nfds].events = POLLIN;
			fds[nfds].revents = 0;
			nfds++;
		}
	}
	/* A DAEMON'S OWN, sec 831, asked again each pass so they may change. */
	first_own = nfds;
	if (state->own_fds && state->own_ready) {
		n_own = state->own_fds(state->own_ctx, own, FZN_NODE_OWN_FDS_MAX);
		if (n_own > FZN_NODE_OWN_FDS_MAX)
			n_own = FZN_NODE_OWN_FDS_MAX;
		for (s = 0; s < n_own; s++) {
			fds[nfds].fd = own[s];
			fds[nfds].events = POLLIN;
			fds[nfds].revents = 0;
			nfds++;
		}
	}
	if (nfds == 0)
		return 0;

	r = poll(fds, nfds, timeout_ms);
	now_ms = monotonic_ms();
	state->held_ms = 0;
	state->held_what[0] = '\0';
	state->held_what_ms = 0;
	/* PAST ITS DEADLINE, whatever the poll said. */
	if (state->asks)
		handled += (int)fzn_node_asks_expire(state->asks);
	if (r <= 0)
		return handled;	/* a timeout or an interrupted poll; the caller loops */
	for (s = 0; s < n_ask; s++)
		if (fds[first_ask + s].revents & POLLIN)
			handled += (int)fzn_node_asks_ready(state->asks, awaited[s]);
	for (s = 0; s < n_own; s++)
		if (fds[first_own + s].revents & (POLLIN | POLLHUP | POLLERR)) {
			state->own_ready(state->own_ctx, own[s]);
			handled++;
		}

	/* SUBSCRIBERS FIRST: one dropped here frees its descriptor, and a
	 * connection accepted after could be given the same number -- taken
	 * for the one that hung up, were the order the other way. */
	for (s = 0; s < n_sub; s++)
		if (fds[first_sub + s].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) {
			(void)fzn_node_events_ready(state->events, subscribers[s]);
			handled++;
		}
	/* BACKWARD, so a connection dropped moves only one already looked at. */
	for (s = n_wait; s > 0u; s--)
		if (fds[first_wait + s - 1u].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) {
			waiting_step(state, s - 1u);
			handled++;
		}
	if (li >= 0 && (fds[li].revents & POLLIN)) {
		serve_ready_local(state);
		handled++;
	}
	if (ui >= 0 && (fds[ui].revents & POLLIN)) {
		uint64_t began = monotonic_ms(), took;

		serve_ready_datagram(state);
		took = monotonic_ms() - began;
		if (took >= state->held_what_ms) {
			memcpy(state->held_what, "a datagram", sizeof("a datagram"));
			state->held_what_ms = took;
		}
		handled++;
	}
	state->held_ms = monotonic_ms() - now_ms;
	return handled;
}

static uint64_t since_boot_ms(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

int fzn_node_wait_answering(fzn_node_state_t *state, int fd, unsigned timeout_ms, int local)
{
	uint64_t until = since_boot_ms() + timeout_ms;

	if (fd < 0)
		return 0;
	for (;;) {
		struct pollfd base[3u + FZN_NODE_OWN_FDS_MAX], *fds = base;
		int own[FZN_NODE_OWN_FDS_MAX], own_said[FZN_NODE_OWN_FDS_MAX];
		nfds_t nfds = 1, first_own, first_wait, at;
		size_t n_own = 0, n_wait = local && state ? state->n_waiting : 0u, s;
		int ui = -1, li = -1, r, udp_said, local_said, parked_said = 0;
		uint64_t now = since_boot_ms();

		if (now >= until)
			return 0;
		if (n_wait) {
			size_t want = 3u + FZN_NODE_OWN_FDS_MAX + n_wait;

			if (want > state->wait_polled_cap) {
				struct pollfd *more = realloc(state->wait_polled, want * 2u * sizeof(*more));

				if (more) {
					state->wait_polled = more;
					state->wait_polled_cap = want * 2u;
				}
			}
			/* NO ROOM: the parked wait for a pass, as they did. */
			if (want <= state->wait_polled_cap)
				fds = state->wait_polled;
			else
				n_wait = 0;
		}
		fds[0].fd = fd;
		fds[0].events = POLLIN;
		fds[0].revents = 0;
		if (state && state->udp_fd >= 0) {
			fds[nfds].fd = state->udp_fd;
			fds[nfds].events = POLLIN;
			fds[nfds].revents = 0;
			ui = (int)nfds++;
		}
		if (local && state && state->listen_fd >= 0) {
			fds[nfds].fd = state->listen_fd;
			fds[nfds].events = POLLIN;
			fds[nfds].revents = 0;
			li = (int)nfds++;
		}
		/* A DAEMON'S OWN, sec 835, as a pass polls them: a wait of 3 s is
		 * not a reason for its descriptors to wait. */
		first_own = nfds;
		if (state && state->own_fds && state->own_ready) {
			n_own = state->own_fds(state->own_ctx, own, FZN_NODE_OWN_FDS_MAX);
			if (n_own > FZN_NODE_OWN_FDS_MAX)
				n_own = FZN_NODE_OWN_FDS_MAX;
			for (s = 0; s < n_own; s++) {
				fds[nfds].fd = own[s];
				fds[nfds].events = POLLIN;
				fds[nfds].revents = 0;
				nfds++;
			}
		}
		/* EACH LOCAL CONNECTION STILL SAYING ITS REQUEST, as a pass polls them:
		 * connect and write are two calls, so one accepted in a wait is often
		 * parked, and a round's waits for silent peers run one after another,
		 * past what a client waits. Sec 949. */
		first_wait = nfds;
		for (s = 0; s < n_wait; s++) {
			fds[nfds].fd = state->waiting[s].fd;
			fds[nfds].events = POLLIN;
			fds[nfds].revents = 0;
			nfds++;
		}
		r = poll(fds, nfds, (int)(until - now));
		if (r < 0)
			continue; /* interrupted: the deadline still bounds it */
		if (r == 0)
			return 0;
		if (fds[0].revents & (POLLIN | POLLERR | POLLHUP))
			return 1;
		/* ALL OF IT READ BEFORE ANYTHING IS SERVED: a handler may ask a peer, and
		 * that wait fills `wait_polled` again. */
		for (s = 0; s < n_own; s++)
			own_said[s] = (fds[first_own + s].revents & (POLLIN | POLLHUP | POLLERR)) != 0;
		udp_said = ui >= 0 && (fds[ui].revents & POLLIN);
		local_said = li >= 0 && (fds[li].revents & POLLIN);
		for (at = first_wait; at < first_wait + n_wait; at++)
			parked_said |= (fds[at].revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0;
		for (s = 0; s < n_own; s++)
			if (own_said[s])
				state->own_ready(state->own_ctx, own[s]);
		/* EACH PARKED CONNECTION LOOKED AT, one with nothing to say left as it is.
		 * BACKWARD, so one dropped moves only one already looked at, and against
		 * the count as it now stands, as what is served may serve others. */
		if (parked_said)
			for (s = state->n_waiting; s > 0u; s--)
				if (s <= state->n_waiting)
					waiting_step(state, s - 1u);
		if (udp_said)
			serve_ready_datagram(state);
		if (local_said)
			serve_ready_local(state);
	}
}

void fzn_node_run(fzn_node_state_t *state)
{
	for (;;)
		(void)fzn_node_run_once(state, -1);
}
