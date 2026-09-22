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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void usage(const char *prog)
{
	fprintf(stderr,
	        "usage: %s --socket PATH [--group GID] [--udp-port PORT]"
	        " [--udp6] [--store DIR]\n", prog);
}

int main(int argc, char **argv)
{
	const char *sock_path = NULL;
	const char *store_dir = NULL;
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
