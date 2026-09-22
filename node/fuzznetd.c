/* fuzznetd: the shared node of sec 298 and sec 300 -- a daemon a consumer who
 * does not want to write its own can run. It opens the local access socket
 * (always) and the remote UDP socket (when a port is given), then runs the
 * access loop: every caller is authenticated by the hop it arrived on and
 * authorised by the node core. This main is glue; the loop and the three
 * access methods are node/serve.h and what it composes.
 *
 * The remote hop binds but serves nobody until peers are provisioned -- a
 * frame from an unknown sender has no session to open it and is dropped.
 *
 * IT STILL DOES NOT MINT A PEER, and that half is unchanged: deciding what a
 * peer is granted, which prekeys are pinned and where a root signing key
 * lives is the copyright holder's, and nothing here does any of it. What it
 * does now is LOAD a set a consumer has already provisioned, from a store
 * named on the command line. Reading what somebody else decided is not
 * deciding it, and without this the daemon could bind the remote hop and
 * serve nobody for ever -- raidcfgd reported exactly that on 2026-09-22.
 *
 * `--store DIR` is opt-in. Without it the daemon behaves as before and a
 * consumer that fills the state itself and calls `fzn_node_run` is
 * unaffected. With it, a store that cannot be read is FATAL rather than
 * empty: a daemon that starts having silently served nobody is the failure
 * this exists to end, and `sec 366` records the same argument one layer
 * down.
 */

#include "serve.h"
#include "peer_persist.h"
#include "../local/socket.h"
#include "../net/udp.h"
#include "../persist/persist_file.h"
#include "../chain/sign_monocypher.h"
#include "../session/aead_monocypher.h"
#include "../session/hash_monocypher.h"
#include "../session/random_system.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* Hex to bytes, for an identity or a root on the command line.
 *
 * LOCAL ON PURPOSE. This is the fourth hand-rolled hex table in the tree --
 * `cli/peer_print.c` writes one, `persist/persist_file.c` writes one for
 * filenames, and a test writes a third -- so a shared helper is clearly
 * wanted. It is not extracted here: `harmonization.md` says an extraction
 * spanning modules is its own deliberate piece of work with the whole picture
 * in view, and `cli/` is the natural home but is build-time optional
 * (FZN_CLI=0), which a daemon must not depend on. Recorded as a signal
 * instead. sec 368. */
static int hex_pubkey(const char *text, uint8_t out[FZN_PUBKEY_LEN])
{
	unsigned i;

	if (!text || strlen(text) != (size_t)FZN_PUBKEY_LEN * 2u)
		return 0;
	for (i = 0; i < (unsigned)FZN_PUBKEY_LEN; i++) {
		unsigned j;
		unsigned byte = 0;

		for (j = 0; j < 2u; j++) {
			char c = text[(i * 2u) + j];
			unsigned v;

			if (c >= '0' && c <= '9')
				v = (unsigned)(c - '0');
			else if (c >= 'a' && c <= 'f')
				v = 10u + (unsigned)(c - 'a');
			else if (c >= 'A' && c <= 'F')
				v = 10u + (unsigned)(c - 'A');
			else
				return 0;
			byte = (byte << 4) | v;
		}
		out[i] = (uint8_t)byte;
	}
	return 1;
}

/* THE CLOCK, AND THE UNIT NOTHING IN THIS LIBRARY STATES.
 *
 * `frame/freshness.h` compares `now` against an `expires_at` that arrived
 * from a peer, and neither it nor `wire/frame.situ` nor sec 4.3 says what
 * either counts in. The library never sources a clock -- `now` is always the
 * caller's -- so the unit is settled per deployment by everyone agreeing,
 * which is a thing that works right up until two consumers do not.
 *
 * This daemon uses SECONDS SINCE THE UNIX EPOCH, which is what `time()`
 * gives and what a peer stamping an expiry will reach for. Stated here
 * because a daemon has to choose; whether fuzznet should MANDATE it rather
 * than leave it to agreement is the holder's, and sec 368 records it. */
static uint64_t wall_clock(void)
{
	time_t t = time(NULL);

	return (t < 0) ? 0u : (uint64_t)t;
}

/* A LIFETIME PLUS A SKEW, which is what freshness.h asks for and the term it
 * says a consumer gets wrong in the direction that looks safe. Ten minutes:
 * a command lifetime of five and five minutes of tolerated clock skew. A
 * deployment wanting different values sets them by writing its own node
 * rather than by this daemon growing two more flags for numbers almost
 * nobody changes. */
#define FZND_MAX_AHEAD 600u
#define FZND_REPLAY_ENTRIES 256u

static void usage(const char *prog)
{
	fprintf(stderr,
	        "usage: %s --socket PATH [--group GID] [--udp-port PORT]"
	        " [--udp6] [--store DIR] [--identity HEX] [--root HEX]\n", prog);
}

int main(int argc, char **argv)
{
	const char *sock_path = NULL;
	fzn_hash_ops_t hash_ops;
	fzn_aead_ops_t aead_ops;
	fzn_random_ops_t rng_ops;
	fzn_sign_ops_t sign_ops;
	fzn_sign_monocypher_t signer;
	fzn_replay_window_t replay;
	static fzn_replay_entry_t replay_entries[FZND_REPLAY_ENTRIES];
	const char *store_dir = NULL;
	const char *identity_hex = NULL;
	const char *root_hex = NULL;
	long group = -1;
	long udp_port = -1;
	int family = AF_INET;
	fzn_node_state_t state;
	int lfd = -1, ufd = -1, i;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--socket") && i + 1 < argc) {
			sock_path = argv[++i];
		} else if (!strcmp(argv[i], "--group") && i + 1 < argc) {
			group = strtol(argv[++i], NULL, 10);
		} else if (!strcmp(argv[i], "--udp-port") && i + 1 < argc) {
			udp_port = strtol(argv[++i], NULL, 10);
		} else if (!strcmp(argv[i], "--store") && i + 1 < argc) {
			store_dir = argv[++i];
		} else if (!strcmp(argv[i], "--identity") && i + 1 < argc) {
			identity_hex = argv[++i];
		} else if (!strcmp(argv[i], "--root") && i + 1 < argc) {
			root_hex = argv[++i];
		} else if (!strcmp(argv[i], "--udp6")) {
			family = AF_INET6;
		} else {
			usage(argv[0]);
			return 2;
		}
	}
	if (!sock_path) {
		usage(argv[0]);
		return 2;
	}

	memset(&state, 0, sizeof(state));
	state.config.uid = (uint32_t)getuid();
	state.config.local_origins = FZN_ORIGIN_BIT(FZN_ORIGIN_SAME_USER);
	if (group >= 0) {
		state.config.has_service_gid = 1;
		state.config.service_gid = (uint32_t)group;
		state.config.local_origins |= FZN_ORIGIN_BIT(FZN_ORIGIN_LOCAL);
	}
	state.udp_fd = -1;

	/* THE REMOTE HOP COULD NOT SERVE A SINGLE FRAME BEFORE THIS.
	 *
	 * `serve_ready_datagram` hands `state->hash`, `aead`, `sign` and
	 * `replay` to `fzn_node_serve_datagram`, and this main zeroed the
	 * state and filled none of them -- so a daemon started with
	 * `--udp-port` bound a socket, loaded peers once sec 367 let it, and
	 * dropped everything that arrived. Looking configured while serving
	 * nobody is the symptom these last sections exist to end, so the ops
	 * are wired here and the identity is required rather than defaulted.
	 *
	 * NO SECRET IS NEEDED TO SERVE. Verifying a peer's chain needs the
	 * root's PUBLIC key, opening its frames needs the session key that
	 * came with the peer record, and sealing a reply needs the same
	 * session key -- `fzn_node_seal_reply` carries no capability and signs
	 * nothing. So this daemon holds no private key at all, which is why it
	 * can read its identity from a command line. Minting is what needs a
	 * secret, and this daemon still does not mint. */
	fzn_hash_monocypher_init(&hash_ops);
	fzn_aead_monocypher_init(&aead_ops);
	fzn_random_system_init(&rng_ops);
	fzn_sign_monocypher_init(&sign_ops, &signer);
	if (fzn_replay_init(&replay, replay_entries, FZND_REPLAY_ENTRIES,
	                    FZND_MAX_AHEAD) != FZN_FRESH_OK) {
		fprintf(stderr, "fuzznetd: the replay window would not initialise\n");
		return 1;
	}
	state.hash = &hash_ops;
	state.aead = &aead_ops;
	state.sign = &sign_ops;
	state.rng = &rng_ops;
	state.replay = &replay;
	state.clock = wall_clock;

	/* The node's own public identity, and the root its peers' chains must
	 * reach. They are the same key for a node that provisioned its own
	 * peers -- `node/provision.h` says the identity IS the root when a
	 * node mints -- so `--root` is an override for the case where somebody
	 * else is root, not a second thing to remember. */
	if (identity_hex && !hex_pubkey(identity_hex, state.node_pubkey)) {
		fprintf(stderr, "fuzznetd: --identity is not 64 hex characters\n");
		return 2;
	}
	if (identity_hex)
		memcpy(state.config.root, state.node_pubkey, FZN_PUBKEY_LEN);
	if (root_hex && !hex_pubkey(root_hex, state.config.root)) {
		fprintf(stderr, "fuzznetd: --root is not 64 hex characters\n");
		return 2;
	}
	/* REFUSED RATHER THAN BOUND. A remote hop with no identity seals its
	 * replies as from the zero key and verifies chains against a zero
	 * root, which no real peer can satisfy -- so it would bind, look
	 * healthy, and drop every frame. That is the exact failure this wiring
	 * closes, and starting anyway would reintroduce it with more moving
	 * parts. */
	if (udp_port >= 0 && !identity_hex) {
		fprintf(stderr, "fuzznetd: --udp-port needs --identity\n");
		return 2;
	}

	/* The socket mode lets a client connect; the authoritative gate is the
	 * in-process peer-credential check, which the kernel fills and no
	 * client can forge. A deployment may tighten ownership and mode on
	 * top of that. */
	if (fzn_socket_listen(sock_path, 0777u, 16, &lfd) != FZN_SOCKET_OK) {
		fprintf(stderr, "fuzznetd: could not listen on %s\n", sock_path);
		return 1;
	}
	state.listen_fd = lfd;

	if (udp_port >= 0) {
		if (fzn_udp_bind(family, NULL, (uint16_t)udp_port, &ufd) !=
		    FZN_UDP_OK) {
			fprintf(stderr, "fuzznetd: could not bind udp port %ld\n",
			        udp_port);
			fzn_socket_close(lfd, sock_path);
			return 1;
		}
		state.udp_fd = ufd;
		state.config.serves_remote = 1;
	}

	/* THE PEERS A CONSUMER ALREADY PROVISIONED, if a store was named.
	 *
	 * Static rather than automatic because the set is about 96 KiB at
	 * FZN_NODE_PEERS_MAX and a daemon's main frame is not where that
	 * belongs; `state.peers` borrows it for the life of the process, which
	 * is what `fzn_node_state_t` asks of it.
	 *
	 * A STORE THAT CANNOT BE READ IS FATAL. Serving nobody is what this
	 * exists to end, so starting anyway -- with the sockets bound and an
	 * empty peer set -- would reproduce the symptom while looking healthy.
	 * The one honest exception is a store that is simply EMPTY: that is a
	 * deployment which has provisioned nothing yet, and it is reported
	 * rather than refused. */
	if (store_dir) {
		static fzn_node_peer_t peers[FZN_NODE_PEERS_MAX];
		static fzn_persist_file_t store;
		const fzn_persist_ops_t *ops = fzn_persist_file_init(&store, store_dir);
		size_t loaded = 0;
		fzn_persist_err_t err;

		if (!ops) {
			fprintf(stderr, "fuzznetd: could not open store %s\n", store_dir);
			fzn_socket_close(lfd, sock_path);
			if (ufd >= 0)
				fzn_udp_close(ufd);
			return 1;
		}
		err = fzn_node_peers_load(ops, peers, FZN_NODE_PEERS_MAX, &loaded);
		if (err != FZN_PERSIST_OK) {
			fprintf(stderr, "fuzznetd: could not load peers from %s (%d)\n",
			        store_dir, (int)err);
			fzn_socket_close(lfd, sock_path);
			if (ufd >= 0)
				fzn_udp_close(ufd);
			return 1;
		}
		state.peers = peers;
		state.peer_count = loaded;
		fprintf(stderr, "fuzznetd: %zu peer(s) from %s\n", loaded, store_dir);
	}

	fprintf(stderr, "fuzznetd: serving on %s%s\n", sock_path,
	        (udp_port >= 0) ? " and udp" : "");
	fzn_node_run(&state);	/* until the process is signalled */

	/* Unreached in normal operation; named so the sockets read as closed
	 * rather than leaked. */
	fzn_socket_close(lfd, sock_path);
	if (ufd >= 0)
		fzn_udp_close(ufd);
	return 0;
}
