/* The node runtime: fzn_node_find_peer directly, and fzn_node_run_once driven
 * over a real AF_UNIX listener without a fork. A client connects and sends a
 * request, one poll-and-dispatch iteration accepts and serves it, and the
 * client reads the status back -- the whole local path through the daemon
 * loop, bounded by the poll timeout so it cannot hang. */

#define _DEFAULT_SOURCE /* mkdtemp under -std=c11 */

#include "serve.h"
#include "sessions.h"
#include "relay.h"
#include "../local/socket.h"
#include "../session/aead_monocypher.h"
#include "../session/hash_monocypher.h"
#include "../session/random_system.h"
#include "../session/box.h" /* FZN_BOX_MARK */

#include <arpa/inet.h>
#include <netinet/in.h>

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int checks;
static int failures;

static void ok(int cond, const char *what)
{
	checks++;
	if (!cond) {
		failures++;
		printf("  FAIL serve_test.c: %s\n", what);
	}
}

/* Connect a client to an AF_UNIX path. Returns the fd, or -1. */
static int connect_to(const char *path)
{
	struct sockaddr_un addr;
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);

	if (fd < 0)
		return -1;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
	if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static int bound(int *fd, fzn_udp_addr_t *to);

static void test_find_peer(void)
{
	fzn_node_peer_t peers[2];
	uint8_t want[FZN_PUBKEY_LEN], absent[FZN_PUBKEY_LEN];

	memset(peers, 0, sizeof(peers));
	memset(peers[0].sender, 0x11, FZN_PUBKEY_LEN);
	memset(peers[1].sender, 0x22, FZN_PUBKEY_LEN);
	memset(want, 0x22, sizeof(want));
	memset(absent, 0x33, sizeof(absent));
	ok(fzn_node_find_peer(peers, 2, want) == &peers[1],
	   "a provisioned sender is found");
	ok(fzn_node_find_peer(peers, 2, absent) == NULL,
	   "an unprovisioned sender is not found");
	ok(fzn_node_find_peer(peers, 0, want) == NULL,
	   "an empty peer table finds nobody");
	ok(fzn_node_find_peer(NULL, 0, want) == NULL, "a null table is safe");
}

static void test_run_once_local(void)
{
	char dir[] = "/tmp/fzn_serve_test_XXXXXX";
	char path[128];
	fzn_node_state_t state;
	int lfd = -1, cfd;
	char resp[128];
	ssize_t n;

	if (!mkdtemp(dir)) {
		ok(0, "a temporary directory could not be made");
		return;
	}
	snprintf(path, sizeof(path), "%s/sock", dir);

	if (fzn_socket_listen(path, 0700u, 8, &lfd) != FZN_SOCKET_OK) {
		ok(0, "the listener would not bind");
		(void)rmdir(dir);
		return;
	}

	memset(&state, 0, sizeof(state));
	state.config.uid = (uint32_t)getuid();
	state.config.local_origins = FZN_ORIGIN_BIT(FZN_ORIGIN_SAME_USER) |
	                             FZN_ORIGIN_BIT(FZN_ORIGIN_LOCAL);
	state.listen_fd = lfd;
	state.udp_fd = -1;

	cfd = connect_to(path);
	ok(cfd >= 0, "a client connects to the node");
	if (cfd >= 0) {
		(void)write(cfd, "hello\n", 6);
		/* One iteration accepts the pending connection and serves it. */
		ok(fzn_node_run_once(&state, 1000) == 1,
		   "run_once accepts and serves one connection");
		n = read(cfd, resp, sizeof(resp) - 1);
		resp[n > 0 ? (size_t)n : 0] = '\0';
		ok(n > 0 && strstr(resp, "served") && strstr(resp, "origin 1"),
		   "the node's own user is served through the loop");
		(void)close(cfd);
	}

	/* AND DURING A WAIT, sec 727: a local client is served while a request
	 * asked in turn waits, when the wait says `local`, and not otherwise. */
	{
		int wfd = -1;
		fzn_udp_addr_t to_asker;

		if (bound(&wfd, &to_asker)) {
			cfd = connect_to(path);
			if (cfd >= 0) {
				(void)write(cfd, "hello\n", 6);
				ok(fzn_node_wait_answering(&state, wfd, 200u, 0) == 0,
				   "a wait with nothing came was not 0");
				ok(recv(cfd, resp, sizeof(resp) - 1, MSG_DONTWAIT) < 0,
				   "a wait not saying local served a local client");
				ok(fzn_node_wait_answering(&state, wfd, 300u, 1) == 0,
				   "a local wait with nothing came was not 0");
				/* BOUNDED: a wait that served nobody leaves nothing to read,
				 * and a plain read would hang the suite rather than fail. */
				{
					struct pollfd pfd = { cfd, POLLIN, 0 };

					n = poll(&pfd, 1, 1000) == 1 ? read(cfd, resp, sizeof(resp) - 1) : -1;
				}
				resp[n > 0 ? (size_t)n : 0] = '\0';
				ok(n > 0 && strstr(resp, "served"),
				   "a local client waited out a wait saying local");
				(void)close(cfd);
			} else {
				ok(0, "a client did not connect for the wait");
			}
			/* A CLIENT WHOSE LINE COMES AFTER ITS CONNECTION, sec 949: accepted
			 * in one wait and parked, as connect and write are two calls, and
			 * served by the next wait, not by the end of a round's waits. */
			cfd = connect_to(path);
			if (cfd >= 0) {
				struct pollfd pfd = { cfd, POLLIN, 0 };

				ok(fzn_node_wait_answering(&state, wfd, 100u, 1) == 0
				           && state.n_waiting == 1u,
				   "a connection with nothing said yet was not parked");
				(void)write(cfd, "hello\n", 6);
				ok(fzn_node_wait_answering(&state, wfd, 300u, 1) == 0,
				   "a wait over a parked client was not 0");
				n = poll(&pfd, 1, 200) == 1 ? read(cfd, resp, sizeof(resp) - 1) : -1;
				resp[n > 0 ? (size_t)n : 0] = '\0';
				ok(n > 0 && strstr(resp, "served") && state.n_waiting == 0u,
				   "a parked client's line went unread through a wait saying local");
				cfd = (close(cfd), -1);
				/* AND NOT THROUGH ONE NOT SAYING IT, as it would run a handler
				 * inside a handler. */
				cfd = connect_to(path);
				if (cfd >= 0) {
					(void)fzn_node_wait_answering(&state, wfd, 100u, 1);
					(void)write(cfd, "hello\n", 6);
					(void)fzn_node_wait_answering(&state, wfd, 150u, 0);
					ok(recv(cfd, resp, sizeof(resp) - 1, MSG_DONTWAIT) < 0
					           && state.n_waiting == 1u,
					   "a wait not saying local served a parked client");
					(void)close(cfd);
					(void)fzn_node_run_once(&state, 200);
				}
			}
			fzn_udp_close(wfd);
		} else {
			ok(0, "the waiting socket would not bind");
		}
	}

	/* An idle iteration returns 0 rather than blocking. */
	ok(fzn_node_run_once(&state, 50) == 0,
	   "an idle poll returns without blocking");

	fzn_socket_close(lfd, path);
	(void)rmdir(dir);
	fzn_node_serve_release(&state);
}

/* A LAN PROBE, sec 624: a datagram opening 0xFC goes to on_probe whole,
 * with where it came from -- the one thing a probe is answered by -- and a
 * box or a frame does not. */
static struct {
	int calls;
	size_t len;
	char host[FZN_UDP_HOST_MAX];
	uint16_t port;
} probed;

static void probe_heard(void *ctx, const uint8_t *probe, size_t len, const fzn_udp_addr_t *from)
{
	(void)ctx;
	(void)probe;
	probed.calls++;
	probed.len = len;
	if (fzn_udp_addr_text(from, probed.host, &probed.port) != FZN_UDP_OK)
		probed.host[0] = '\0';
}

static void test_run_once_probe(void)
{
	fzn_node_state_t state;
	uint8_t datagram[FZN_NODE_PROBE_LEN];
	struct sockaddr_in at;
	socklen_t at_len = sizeof(at);
	fzn_udp_addr_t to;
	uint16_t port, sender_port;
	int ufd = -1, sfd = -1;

	if (fzn_udp_bind(AF_INET, "127.0.0.1", 0, &ufd) != FZN_UDP_OK
	    || fzn_udp_bind(AF_INET, "127.0.0.1", 0, &sfd) != FZN_UDP_OK) {
		ok(0, "the datagram sockets would not bind");
		goto out;
	}
	if (getsockname(ufd, (struct sockaddr *)&at, &at_len) != 0) {
		ok(0, "the serving socket has no name");
		goto out;
	}
	port = ntohs(at.sin_port);
	at_len = sizeof(at);
	if (getsockname(sfd, (struct sockaddr *)&at, &at_len) != 0) {
		ok(0, "the sending socket has no name");
		goto out;
	}
	sender_port = ntohs(at.sin_port);
	(void)fzn_udp_resolve(AF_INET, "127.0.0.1", port, &to);
	memset(&state, 0, sizeof(state));
	state.listen_fd = -1;
	state.udp_fd = ufd;
	state.on_probe = probe_heard;
	memset(&probed, 0, sizeof(probed));
	memset(datagram, 0, sizeof(datagram));
	datagram[0] = FZN_NODE_PROBE_MARK;
	datagram[1] = 1u;
	(void)fzn_udp_send(sfd, &to, datagram, sizeof(datagram));
	ok(fzn_node_run_once(&state, 1000) == 1, "run_once reads a probe");
	ok(probed.calls == 1 && probed.len == FZN_NODE_PROBE_LEN,
	   "a probe reached on_probe whole");
	ok(strcmp(probed.host, "127.0.0.1") == 0 && probed.port == sender_port,
	   "a probe came with the address it was sent from");
	datagram[0] = FZN_BOX_MARK;
	(void)fzn_udp_send(sfd, &to, datagram, sizeof(datagram));
	(void)fzn_node_run_once(&state, 1000);
	ok(probed.calls == 1, "a box reached on_probe");
	datagram[0] = FZN_NODE_PROBE_MARK;
	state.on_probe = NULL;
	(void)fzn_udp_send(sfd, &to, datagram, sizeof(datagram));
	(void)fzn_node_run_once(&state, 1000);
	ok(probed.calls == 1, "a probe with no handler went somewhere");
out:
	if (ufd >= 0)
		fzn_udp_close(ufd);
	if (sfd >= 0)
		fzn_udp_close(sfd);
	fzn_node_serve_release(&state);
}

/* A port bound on loopback, its fd and the address to send to it. */
static int bound(int *fd, fzn_udp_addr_t *to)
{
	struct sockaddr_in at;
	socklen_t at_len = sizeof(at);

	if (fzn_udp_bind(AF_INET, "127.0.0.1", 0, fd) != FZN_UDP_OK)
		return 0;
	if (getsockname(*fd, (struct sockaddr *)&at, &at_len) != 0)
		return 0;
	return fzn_udp_resolve(AF_INET, "127.0.0.1", ntohs(at.sin_port), to) == FZN_UDP_OK;
}

/* A SESSION FRAME THROUGH THE LOOP, sec 932. The peer here holds no chain, so it
 * stands for a host revoked since its session began: the frame opens, and the
 * capability is what must say no, on every frame. */
static struct {
	int calls, granted, denied;
	uint32_t msg;
	size_t cap_ok;
} remoted;
static int said_calls;
static uint8_t session_capability[FZN_CAP_ID_LEN];

static size_t session_remote(void *ctx, fzn_node_remote_result_t result, const fzn_opened_t *req,
                             uint8_t *reply, size_t reply_cap)
{
	(void)ctx;
	remoted.calls++;
	remoted.granted += result == FZN_NODE_REMOTE_GRANTED;
	remoted.denied += result == FZN_NODE_REMOTE_DENIED;
	remoted.msg = req->msg;
	remoted.cap_ok = memcmp(req->capability, session_capability, FZN_CAP_ID_LEN) == 0;
	if (reply_cap < 2u)
		return 0;
	memcpy(reply, "no", 2u);
	return 2u;
}

static void session_said(void *ctx, const fzn_opened_t *said)
{
	(void)ctx;
	(void)said;
	said_calls++;
}

static uint64_t session_now(void)
{
	return 1000u;
}

static void session_send(int fd, const fzn_udp_addr_t *to, fzn_session_end_t *end, uint32_t msg,
                         uint32_t expires, const fzn_aead_ops_t *aead, uint8_t *kept, size_t *n)
{
	ok(fzn_session_frame_seal(end, msg, expires, (const uint8_t *)"hi", 2u, kept,
	                          FZN_SESSION_FRAME_MAX, n, aead)
	           == FZN_SESSION_FRAME_OK,
	   "a session frame did not seal");
	(void)fzn_udp_send(fd, to, kept, *n);
}

static void test_run_once_session(void)
{
	static fzn_node_peer_t peer;
	static fzn_replay_entry_t entries[8];
	static fzn_replay_window_t replay;
	fzn_node_sessions_t sessions;
	fzn_node_state_t state;
	fzn_hash_ops_t hash;
	fzn_aead_ops_t aead;
	fzn_random_ops_t rng;
	fzn_session_end_t asker;
	fzn_session_opened_t got;
	fzn_udp_addr_t to, to_asker, from;
	uint8_t ask[FZN_SESSION_ASK_LEN], grant[FZN_SESSION_GRANT_LEN];
	uint8_t frame[FZN_SESSION_FRAME_MAX], back[FZN_SESSION_FRAME_MAX];
	size_t n = 0, back_len = 0;
	int ufd = -1, sfd = -1;

	fzn_hash_monocypher_init(&hash);
	fzn_aead_monocypher_init(&aead);
	fzn_random_system_init(&rng);
	memset(&sessions, 0, sizeof(sessions));
	memset(&peer, 0, sizeof(peer));
	memset(peer.sender, 0x51, sizeof(peer.sender));
	memset(peer.recv_key, 0x52, sizeof(peer.recv_key));
	memset(session_capability, 0x53, sizeof(session_capability));
	memset(ask, 0x54, sizeof(ask));
	memset(&remoted, 0, sizeof(remoted));
	said_calls = 0;
	if (!bound(&ufd, &to) || !bound(&sfd, &to_asker)) {
		ok(0, "the datagram sockets would not bind");
		goto out;
	}
	ok(fzn_replay_init(&replay, entries, 8u, 60u) == FZN_FRESH_OK, "fixture: the window");
	ok(fzn_node_sessions_grant(&sessions, peer.sender, session_capability, peer.recv_key, ask,
	                           5000u, &hash, &rng, grant),
	   "an ask was not granted");
	ok(fzn_session_end_derive(&asker, &hash, peer.recv_key, ask, grant, 1), "the asker");
	memset(&state, 0, sizeof(state));
	state.listen_fd = -1;
	state.udp_fd = ufd;
	state.hash = &hash;
	state.aead = &aead;
	state.rng = &rng;
	state.replay = &replay;
	state.clock = session_now;
	state.peers = &peer;
	state.peer_count = 1u;
	state.sessions = &sessions;
	state.on_remote = session_remote;
	state.on_said = session_said;

	/* OPENS, AND THE CAPABILITY SAYS NO. */
	session_send(sfd, &to, &asker, 9u, 1030u, &aead, frame, &n);
	(void)fzn_node_run_once(&state, 1000);
	ok(remoted.calls == 1 && remoted.denied == 1 && remoted.granted == 0,
	   "a session frame went past the capability its peer no longer holds");
	ok(remoted.msg == 9u && remoted.cap_ok, "a session frame lost its message or its capability");

	/* ITS ANSWER IN THE SESSION. */
	{
		struct pollfd p = { sfd, POLLIN, 0 };

		ok(poll(&p, 1, 1000) == 1
		           && fzn_udp_recv(sfd, back, sizeof(back), &back_len, &from) == FZN_UDP_OK,
		   "no answer came");
		ok(back_len == FZN_SESSION_FRAME_OVERHEAD + 2u
		           && fzn_session_frame_open(&asker, back, back_len, &aead, &got)
		                      == FZN_SESSION_FRAME_OK
		           && got.msg == 9u,
		   "the answer was not a session frame of that message");
	}

	/* ONCE. */
	session_send(sfd, &to, &asker, 10u, 1030u, &aead, frame, &n);
	(void)fzn_node_run_once(&state, 1000);
	ok(remoted.calls == 2, "a frame was not served");
	(void)fzn_udp_send(sfd, &to, frame, n);
	(void)fzn_node_run_once(&state, 200);
	ok(remoted.calls == 2, "a frame played back was served");

	/* EXPIRED, AND PAST THE HORIZON. */
	session_send(sfd, &to, &asker, 11u, 1000u, &aead, frame, &n);
	(void)fzn_node_run_once(&state, 1000);
	session_send(sfd, &to, &asker, 12u, 1061u, &aead, frame, &n);
	(void)fzn_node_run_once(&state, 1000);
	ok(remoted.calls == 2, "an expiry past its window was served");

	/* WORDS, FROM ONE WHOSE CAPABILITY FAILS, are told to nobody. */
	session_send(sfd, &to, &asker, 0u, 1030u, &aead, frame, &n);
	(void)fzn_node_run_once(&state, 1000);
	ok(said_calls == 0 && remoted.calls == 2, "a word passed a capability that failed");

	/* SAID FROM THIS END, to where the last frame came from. */
	ok(fzn_node_serve_say(&state, peer.sender, (const uint8_t *)"ring", 4u) == 1,
	   "a word to a session in use did not go");
	{
		struct pollfd p = { sfd, POLLIN, 0 };

		while (poll(&p, 1, 300) == 1
		       && fzn_udp_recv(sfd, back, sizeof(back), &back_len, &from) == FZN_UDP_OK) {
			if (fzn_session_frame_open(&asker, back, back_len, &aead, &got)
			            == FZN_SESSION_FRAME_OK
			    && got.msg == 0u)
				break;
			got.msg = 1u;
		}
		ok(got.msg == 0u && got.payload_len == 4u && memcmp(got.payload, "ring", 4u) == 0,
		   "a word did not reach the peer");
	}

	/* THE PEER GONE: the session with it. */
	state.peer_count = 0u;
	session_send(sfd, &to, &asker, 13u, 1030u, &aead, frame, &n);
	(void)fzn_node_run_once(&state, 1000);
	ok(remoted.calls == 2 && !fzn_node_sessions_find(&sessions, asker.speaks_to),
	   "a session outlived its peer");
	ok(fzn_node_serve_say(&state, peer.sender, (const uint8_t *)"x", 1u) == 0,
	   "a word went to a session gone");
out:
	fzn_node_sessions_release(&sessions);
	if (ufd >= 0)
		fzn_udp_close(ufd);
	if (sfd >= 0)
		fzn_udp_close(sfd);
	fzn_node_serve_release(&state);
}

/* A WAIT THAT ANSWERS PEERS, sec 720: while a request asked in turn waits on
 * its own socket, what the node's socket receives is served -- two hosts
 * asking each other at once each waited out the other's timeout before --
 * and the wait ends when its own socket has something. */
static void test_wait_answering(void)
{
	fzn_node_state_t state;
	uint8_t datagram[FZN_NODE_PROBE_LEN], got[64];
	fzn_udp_addr_t to_node, to_asker, to_sender;
	size_t got_len = 0;
	int ufd = -1, wfd = -1, sfd = -1;

	if (!bound(&ufd, &to_node) || !bound(&wfd, &to_asker) || !bound(&sfd, &to_sender)) {
		ok(0, "the datagram sockets would not bind");
		goto out;
	}
	memset(&state, 0, sizeof(state));
	state.listen_fd = -1;
	state.udp_fd = ufd;
	state.on_probe = probe_heard;
	memset(&probed, 0, sizeof(probed));
	memset(datagram, 0, sizeof(datagram));
	datagram[0] = FZN_NODE_PROBE_MARK;
	datagram[1] = 1u;
	ok(fzn_node_wait_answering(&state, wfd, 50u, 0) == 0, "a wait with nothing came was not 0");
	(void)fzn_udp_send(sfd, &to_node, datagram, sizeof(datagram));
	(void)fzn_udp_send(sfd, &to_node, datagram, sizeof(datagram));
	ok(fzn_node_wait_answering(&state, wfd, 300u, 0) == 0 && probed.calls == 2,
	   "what the node's socket received while a request waited was not served");
	(void)fzn_udp_send(sfd, &to_asker, (const uint8_t *)"answer", 6u);
	ok(fzn_node_wait_answering(&state, wfd, 3000u, 0) == 1,
	   "the wait did not end when its own socket had something");
	ok(fzn_udp_recv(wfd, got, sizeof(got), &got_len, NULL) == FZN_UDP_OK && got_len == 6u
	           && memcmp(got, "answer", 6u) == 0,
	   "the wait took what came to its own socket");
	ok(fzn_node_wait_answering(&state, -1, 10u, 0) == 0, "a wait on no socket was not 0");
out:
	if (ufd >= 0)
		fzn_udp_close(ufd);
	if (wfd >= 0)
		fzn_udp_close(wfd);
	if (sfd >= 0)
		fzn_udp_close(sfd);
	fzn_node_serve_release(&state);
}

/* A DAEMON'S OWN DESCRIPTORS, sec 831: the node's pass polls what
 * `own_fds` names, and tells `own_ready` of each readable one -- with no
 * socket of the node's own at all. */
static int own_pipe[2] = { -1, -1 }, own_told = -1, own_asked;

static size_t own_fds(void *ctx, int *fds, size_t cap)
{
	(void)ctx;
	own_asked++;
	if (cap < 1u || own_pipe[0] < 0)
		return 0;
	fds[0] = own_pipe[0];
	return 1;
}

static void own_ready(void *ctx, int fd)
{
	char c;

	(void)ctx;
	own_told = fd;
	(void)read(fd, &c, 1);
}

static void test_run_once_own_fds(void)
{
	fzn_node_state_t state;

	memset(&state, 0, sizeof(state));
	state.listen_fd = -1;
	state.udp_fd = -1;
	ok(fzn_node_run_once(&state, 50) == 0, "a node with nothing to poll was told something");
	ok(pipe(own_pipe) == 0, "fixture: a pipe");
	state.own_fds = own_fds;
	state.own_ready = own_ready;
	ok(fzn_node_run_once(&state, 50) == 0 && own_asked == 1 && own_told == -1,
	   "a quiet descriptor of the daemon's own was told it was ready, or never asked for");
	ok(write(own_pipe[1], "x", 1) == 1, "fixture: a byte written");
	ok(fzn_node_run_once(&state, 1000) == 1 && own_told == own_pipe[0],
	   "a readable descriptor of the daemon's own was not told");
	close(own_pipe[0]);
	close(own_pipe[1]);
	own_pipe[0] = own_pipe[1] = -1;
	fzn_node_serve_release(&state);
}

/* AND IN A WAIT IN TURN, sec 835: a request waiting up to 3 s on its own
 * socket tells the daemon of its own readable descriptor as a pass would,
 * and goes on waiting -- netcfgd's confirm window must not wait out a
 * round. */
static void test_wait_answering_own_fds(void)
{
	fzn_node_state_t state;
	fzn_udp_addr_t to_asker;
	int wfd = -1;

	if (!bound(&wfd, &to_asker)) {
		ok(0, "the datagram socket would not bind");
		return;
	}
	memset(&state, 0, sizeof(state));
	state.listen_fd = -1;
	state.udp_fd = -1;
	own_told = -1;
	own_asked = 0;
	ok(pipe(own_pipe) == 0, "fixture: a pipe");
	state.own_fds = own_fds;
	state.own_ready = own_ready;
	ok(write(own_pipe[1], "x", 1) == 1, "fixture: a byte written");
	ok(fzn_node_wait_answering(&state, wfd, 300u, 0) == 0,
	   "a wait ended on the daemon's own descriptor rather than its own socket");
	ok(own_told == own_pipe[0] && own_asked >= 1,
	   "a readable descriptor of the daemon's own was not told during a wait in turn");
	close(own_pipe[0]);
	close(own_pipe[1]);
	own_pipe[0] = own_pipe[1] = -1;
	fzn_udp_close(wfd);
	fzn_node_serve_release(&state);
}

static int same_addr(const fzn_udp_addr_t *a, const fzn_udp_addr_t *b)
{
	return a->len == b->len && memcmp(a->storage, b->storage, a->len) == 0;
}

/* A SESSION RELAYED THROUGH THE LOOP, sec 1045: a session frame whose handle no
 * session here holds goes on, byte for byte, where a way stands for it from where
 * it came; from anywhere else, nowhere. */
static void test_run_once_relays_a_session(void)
{
	static fzn_node_relay_t relay;
	fzn_node_sessions_t mine, theirs;
	fzn_node_state_t state;
	fzn_hash_ops_t hash;
	fzn_aead_ops_t aead;
	fzn_random_ops_t rng;
	fzn_session_end_t end;
	fzn_udp_addr_t at_relay, at_a, at_b, at_c, from;
	uint8_t key[FZN_AEAD_KEY_LEN], sender[FZN_PUBKEY_LEN], cap[FZN_CAP_ID_LEN];
	uint8_t ask[FZN_SESSION_ASK_LEN], grant[FZN_SESSION_GRANT_LEN];
	uint8_t frame[FZN_SESSION_FRAME_MAX], got[FZN_SESSION_FRAME_MAX];
	size_t n = 0, got_len = 0;
	int rfd = -1, afd = -1, bfd = -1, cfd = -1;
	struct pollfd p;

	fzn_hash_monocypher_init(&hash);
	fzn_aead_monocypher_init(&aead);
	fzn_random_system_init(&rng);
	memset(&mine, 0, sizeof(mine));
	memset(&theirs, 0, sizeof(theirs));
	memset(key, 0x61, sizeof(key));
	memset(sender, 0x62, sizeof(sender));
	memset(cap, 0x63, sizeof(cap));
	memset(ask, 0x64, sizeof(ask));
	if (!bound(&rfd, &at_relay) || !bound(&afd, &at_a) || !bound(&bfd, &at_b)
	    || !bound(&cfd, &at_c)) {
		ok(0, "the datagram sockets would not bind");
		goto out;
	}
	/* B's session, granted at B: A's frames to B carry B's handle. The relay
	 * holds no session of its own with either. */
	ok(fzn_node_sessions_grant(&theirs, sender, cap, key, ask, 5000u, &hash, &rng, grant)
	           && fzn_session_end_derive(&end, &hash, key, ask, grant, 1),
	   "fixture: a session between A and B");
	fzn_node_relay_init(&relay);
	ok(fzn_node_relay_session(&relay, &at_a, 0x0a0a0a0au, &at_b, end.speaks_to, 1000u),
	   "the session was not relayed");
	memset(&state, 0, sizeof(state));
	state.listen_fd = -1;
	state.udp_fd = rfd;
	state.hash = &hash;
	state.aead = &aead;
	state.rng = &rng;
	state.clock = session_now;
	state.sessions = &mine;
	state.relay = &relay;

	ok(fzn_session_frame_seal(&end, 7u, 1030u, (const uint8_t *)"hi", 2u, frame, sizeof(frame),
	                          &n, &aead)
	           == FZN_SESSION_FRAME_OK,
	   "fixture: a session frame");
	(void)fzn_udp_send(afd, &at_relay, frame, n);
	(void)fzn_node_run_once(&state, 1000);
	p.fd = bfd;
	p.events = POLLIN;
	p.revents = 0;
	ok(poll(&p, 1, 1000) == 1 && fzn_udp_recv(bfd, got, sizeof(got), &got_len, &from) == FZN_UDP_OK
	           && got_len == n && memcmp(got, frame, n) == 0 && same_addr(&from, &at_relay),
	   "A's session frame did not reach B from the relay, byte for byte");

	/* FROM A THIRD HOST, the same frame: no way stands from there. */
	(void)fzn_udp_send(cfd, &at_relay, frame, n);
	(void)fzn_node_run_once(&state, 300);
	p.revents = 0;
	ok(poll(&p, 1, 300) == 0, "a session frame from a host no way names was forwarded");
out:
	fzn_node_sessions_release(&mine);
	fzn_node_sessions_release(&theirs);
	if (rfd >= 0)
		fzn_udp_close(rfd);
	if (afd >= 0)
		fzn_udp_close(afd);
	if (bfd >= 0)
		fzn_udp_close(bfd);
	if (cfd >= 0)
		fzn_udp_close(cfd);
}

int main(void)
{
	test_find_peer();
	test_run_once_local();
	test_run_once_probe();
	test_run_once_session();
	test_run_once_relays_a_session();
	test_wait_answering();
	test_run_once_own_fds();
	test_wait_answering_own_fds();
	printf("serve_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
