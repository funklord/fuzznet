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
 * IT STILL DOES NOT MINT A PEER: deciding what a peer is granted and which
 * prekeys are pinned is not something a daemon should do on its own say-so.
 * WHERE ITS OWN KEY LIVES is settled, by sec 136's "generate it when absent":
 * with `--store` and no `--identity` the daemon loads its identity from the
 * store, or creates a self-rooted one when the store holds none, through
 * `node/identity.h`. sec 375. What it also does is LOAD a set a consumer has
 * already provisioned, from the same store. Reading what somebody else decided is not
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
#include "identity.h"
#include "pair.h"
#include "peer_persist.h"
#include "../local/socket.h"
#include "../net/udp.h"
#include "../persist/persist_file.h"
#include "../chain/service.h"
#include "../constant_time/constant_time.h"
#include "../chain/sign_monocypher.h"
#include "../cli/cli.h"
#include "../provision/provision.h"
#include "../session/aead_monocypher.h"
#include "../session/agree_monocypher.h"
#include "../session/hash_monocypher.h"
#include "../session/random_system.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* Hex to bytes, for an identity, a root or a device's prekey record on the
 * command line.
 *
 * LOCAL ON PURPOSE. This is the fourth hand-rolled hex table in the tree --
 * `cli/peer_print.c` writes one, `persist/persist_file.c` writes one for
 * filenames, and a test writes a third -- so a shared helper is clearly
 * wanted. It is not extracted here: `harmonization.md` says an extraction
 * spanning modules is its own deliberate piece of work with the whole picture
 * in view, and `cli/` is the natural home but is build-time optional
 * (FZN_CLI=0), which a daemon must not depend on. Recorded as a signal
 * instead. sec 368. */
static int hex_bytes(const char *text, uint8_t *out, size_t len)
{
	size_t i;

	if (!text || strlen(text) != len * 2u)
		return 0;
	for (i = 0; i < len; i++) {
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

static int hex_pubkey(const char *text, uint8_t out[FZN_PUBKEY_LEN])
{
	return hex_bytes(text, out, FZN_PUBKEY_LEN);
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
static void print_hex(FILE *f, const uint8_t *bytes, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		fprintf(f, "%02x", bytes[i]);
}

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

/* HOW LONG A PAIRING CARD MAY WAIT TO BE ACCEPTED. The card carries no
 * secret -- the node's root, the node's prekey, and a grant only the device's
 * key can use -- so this bounds how long a card photographed off a screen
 * stays worth accepting, not what it can reveal. A day: long enough to carry
 * a card to a device, short enough that a stale one is not a standing
 * invitation. The GRANT inside it does not expire; a lost device is revoked,
 * which is the capability model's answer (sec 1). */
#define FZND_CARD_LIFETIME 86400u

static void usage(const char *prog)
{
	fprintf(stderr,
	        "usage: %s --socket PATH [--group GID] [--udp-port PORT]"
	        " [--udp6] [--store DIR] [--identity HEX] [--root HEX]"
	        " [fuzznet options]\n"
	        "       %s --store DIR --pair PREKEY_HEX [fuzznet options]\n"
	        "       %s --store DIR --prekey\n"
	        "       %s --store DIR --accept CARD\n"
	        "fuzznet options:\n%s",
	        prog, prog, prog, prog, fzn_cli_usage());
}

/* PAIR ONE DEVICE AND EXIT.
 *
 * The device's prekey record arrives out of band -- it is what the device
 * publishes, self-signed -- and the node answers with a card: its root, its
 * prekey, and the device's grant. The peer is saved to the store before the
 * card is printed, so a card never exists for a pairing the node forgot. A
 * running daemon loads its peers at start, so it serves the device from its
 * next start; pairing into a live daemon needs a local verb, which is the
 * vocabulary's to add and not this main's.
 *
 * WHAT THE DEVICE IS GRANTED IS THE ONE CAPABILITY THE REMOTE HOP CHECKS,
 * `config.remote_capability`, derived from `--fuzznet-service` and
 * `--fuzznet-product`. The composition, and the refusal of a node that is
 * not its own root, are `node/pair.h`'s, where a suite reaches them. */
static int pair_device(const fzn_node_identity_t *id, const fzn_node_config_t *config,
                       const fzn_persist_ops_t *store, const char *prekey_hex, uint64_t now)
{
	uint8_t record_bytes[FZN_PREKEY_LEN_TOTAL];
	uint8_t card[FZN_PROVISION_LEN_TOTAL];
	char text[FZN_PROVISION_TEXT_LEN];
	fzn_prekey_record_t record;
	fzn_node_pair_err_t perr;
	size_t card_len = 0;

	if (!hex_bytes(prekey_hex, record_bytes, sizeof(record_bytes))
	    || fzn_prekey_open(record_bytes, sizeof(record_bytes), &record) != FZN_PREKEY_OK) {
		fprintf(stderr, "fuzznetd: --pair is not a prekey record (%u hex characters)\n",
		        (unsigned)(FZN_PREKEY_LEN_TOTAL * 2u));
		return 2;
	}
	perr = fzn_node_pair(id, config->root, &config->remote_capability, store, record, now,
	                     now + FZND_CARD_LIFETIME, card, sizeof(card), &card_len);
	if (perr != FZN_NODE_PAIR_OK) {
		fprintf(stderr, "fuzznetd: not paired: %s\n", fzn_node_pair_err_str(perr));
		return 1;
	}
	if (fzn_provision_text(card, card_len, text, sizeof(text)) != FZN_PROVISION_OK) {
		fprintf(stderr, "fuzznetd: the device is saved but its card would not encode; "
		                "pair it again\n");
		return 1;
	}
	fprintf(stderr, "fuzznetd: paired ");
	print_hex(stderr, record.host, FZN_PUBKEY_LEN);
	fprintf(stderr, "\n");
	printf("%s\n", text);
	return 0;
}

int main(int argc, char **argv)
{
	const char *sock_path = NULL;
	fzn_hash_ops_t hash_ops;
	fzn_aead_ops_t aead_ops;
	fzn_random_ops_t rng_ops;
	fzn_sign_ops_t sign_ops;
	fzn_sign_seat_t seat;
	fzn_agree_ops_t agree_ops;
	fzn_sign_monocypher_t signer;
	static fzn_persist_file_t store;
	const fzn_persist_ops_t *store_ops = NULL;
	static fzn_agree_secret_t agree_secret;
	static fzn_trust_t trust;
	static fzn_node_identity_t identity;
	int booted = 0;
	fzn_replay_window_t replay;
	static fzn_replay_entry_t replay_entries[FZND_REPLAY_ENTRIES];
	const char *store_dir = NULL;
	const char *identity_hex = NULL;
	const char *root_hex = NULL;
	long group = -1;
	long udp_port = -1;
	int family = AF_INET;
	fzn_node_state_t state;
	fzn_cli_t cli;
	const char *pair_hex = NULL;
	int show_prekey = 0;
	const char *accept_text = NULL;
	int has_capability = 0;
	int lfd = -1, ufd = -1, i;

	fzn_cli_init(&cli);

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
		} else if (!strcmp(argv[i], "--pair") && i + 1 < argc) {
			pair_hex = argv[++i];
		} else if (!strcmp(argv[i], "--prekey")) {
			show_prekey = 1;
		} else if (!strcmp(argv[i], "--accept") && i + 1 < argc) {
			accept_text = argv[++i];
		} else {
			/* FUZZNET'S OWN OPTIONS ARE FUZZNET'S PARSER'S, so this
			 * daemon, the config dialog and every consumer refuse the
			 * same values in the same words (sec 140). */
			int claimed = 0;
			fzn_cli_err_t cerr = fzn_cli_arg(&cli, argv[i], &claimed);

			if (claimed && cerr != FZN_CLI_OK) {
				fprintf(stderr, "fuzznetd: %s: %s\n", argv[i],
				        fzn_cli_err_str(cerr));
				return 2;
			}
			if (!claimed) {
				usage(argv[0]);
				return 2;
			}
		}
	}
	if (!sock_path && !pair_hex && !show_prekey && !accept_text) {
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
	memset(&signer, 0, sizeof(signer));
	fzn_sign_monocypher_init(&sign_ops, &signer);
	fzn_sign_monocypher_seat_init(&seat, &signer);
	fzn_agree_monocypher_init(&agree_ops);
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

	/* THE CAPABILITY THE REMOTE HOP REQUIRES, which this main never set.
	 * `state` is zeroed, so the hop required the all-zero capability id --
	 * one `fzn_service_capability` refuses to make, because a capability
	 * naming no service must not exist. No correctly provisioned peer could
	 * present it: the daemon bound, loaded its peers, and denied every one.
	 * It is derived from fuzznet's own options, and a remote hop without
	 * them is refused here rather than bound -- before the store is
	 * opened, so a refused command line creates nothing. sec 376. */
	if (cli.service != FZN_SERVICE_NONE || cli.product != FZN_PRODUCT_NONE) {
		if (fzn_service_capability(cli.service, cli.product, NULL, 0, &hash_ops,
		                           &state.config.remote_capability) != FZN_CHAIN_OK) {
			fprintf(stderr, "fuzznetd: the remote capability needs both "
			                "--fuzznet-service and --fuzznet-product\n");
			return 2;
		}
		has_capability = 1;
	}
	if ((udp_port >= 0 || pair_hex) && !has_capability) {
		fprintf(stderr, "fuzznetd: %s needs --fuzznet-service and --fuzznet-product: "
		                "the remote hop checks one capability, and with none "
		                "configured it would require one nobody can hold\n",
		        pair_hex ? "--pair" : "--udp-port");
		return 2;
	}

	/* THE STORE, OPENED BEFORE THE IDENTITY because the identity may live
	 * in it. A store that cannot be opened is fatal, for the reason the
	 * peer load below gives. */
	if (store_dir) {
		store_ops = fzn_persist_file_init(&store, store_dir);
		if (!store_ops) {
			fprintf(stderr, "fuzznetd: could not open store %s\n", store_dir);
			return 1;
		}
	}

	/* THIS NODE'S OWN IDENTITY, from the store, when none was named.
	 *
	 * `--identity` keeps its meaning: a daemon that serves with a public
	 * key alone and holds no secret, which sec 368 built and which a
	 * deployment keeping its root key elsewhere still wants. Without it and
	 * with a store, the daemon becomes a node that owns its key -- and the
	 * store is asked, per part, whether it holds it, because generating
	 * over a store that was merely unreadable would replace this node with
	 * a stranger. A partial store is refused by name; which part is gone
	 * and what to do about it is the operator's. */
	if (!identity_hex && store_ops) {
		fzn_node_identity_env_t env;
		fzn_node_identity_found_t found;
		fzn_node_identity_err_t ierr;
		int created = 0;

		env.store = store_ops;
		env.rng = &rng_ops;
		env.seat = &seat;
		env.sign = &sign_ops;
		env.hash = &hash_ops;
		env.agree = &agree_ops;
		env.log = NULL; /* this main reports on stderr below */
		found.seed = fzn_persist_file_holds(&store, FZN_PERSIST_OWN_IDENTITY, NULL);
		found.prekey = fzn_persist_file_holds(&store, FZN_PERSIST_OWN_PREKEY, NULL);
		found.trust = fzn_persist_file_holds(&store, FZN_PERSIST_TRUST, NULL);
		ierr = fzn_node_identity_boot(&env, &found, wall_clock(), &agree_secret, &trust,
		                              &identity, &created);
		if (ierr != FZN_NODE_IDENTITY_OK) {
			fprintf(stderr, "fuzznetd: no identity from %s: %s\n", store_dir,
			        fzn_node_identity_err_str(ierr));
			if (ierr == FZN_NODE_IDENTITY_PARTIAL)
				fprintf(stderr, "fuzznetd: identity %s, prekey %s, anchor %s\n",
				        found.seed == FZN_PERSIST_OK ? "present" : "absent",
				        found.prekey == FZN_PERSIST_OK ? "present" : "absent",
				        found.trust == FZN_PERSIST_OK ? "present" : "absent");
			return 1;
		}
		memcpy(state.node_pubkey, identity.pubkey, FZN_PUBKEY_LEN);
		memcpy(state.config.root, fzn_trust_root(&trust), FZN_PUBKEY_LEN);
		booted = 1;
		fprintf(stderr, "fuzznetd: identity ");
		print_hex(stderr, identity.pubkey, FZN_PUBKEY_LEN);
		fprintf(stderr, " %s %s\n", created ? "created in" : "loaded from", store_dir);
	}

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

	/* THIS NODE'S PREKEY RECORD, which is what another node pairs it by:
	 * the other half of `--pair`, for the node that is the device. Self-
	 * signed, so it proves authorship and not identity -- the operator
	 * carrying it to the pairing node is what vouches for it. */
	if (show_prekey) {
		if (!booted) {
			fprintf(stderr, "fuzznetd: --prekey needs --store, and no --identity\n");
			return 2;
		}
		print_hex(stdout, identity.prekey_record, FZN_PREKEY_LEN_TOTAL);
		printf("\n");
		return 0;
	}

	/* THE DEVICE'S HALF OF `--pair`: accept a node's card and keep the
	 * pairing. It prints the node's root, which is the name the pairing is
	 * filed under and what the device asks the node by. sec 377. */
	if (accept_text) {
		uint8_t card[FZN_PROVISION_LEN_TOTAL];
		size_t card_len = 0;
		fzn_node_pairing_t paired;
		fzn_node_pair_err_t perr;

		if (!booted) {
			fprintf(stderr, "fuzznetd: --accept needs --store, and no --identity\n");
			return 2;
		}
		if (fzn_provision_from_text(accept_text, card, sizeof(card), &card_len)
		    != FZN_PROVISION_OK) {
			fprintf(stderr, "fuzznetd: --accept is not a card\n");
			return 2;
		}
		perr = fzn_node_pairing_accept(&identity, card, card_len, wall_clock(), store_ops,
		                               &paired);
		if (perr != FZN_NODE_PAIR_OK) {
			fprintf(stderr, "fuzznetd: not accepted: %s\n", fzn_node_pair_err_str(perr));
			return 1;
		}
		fprintf(stderr, "fuzznetd: paired to ");
		print_hex(stderr, paired.root, FZN_PUBKEY_LEN);
		fprintf(stderr, "\n");
		print_hex(stdout, paired.root, FZN_PUBKEY_LEN);
		printf("\n");
		fzn_wipe(&paired, sizeof(paired));
		return 0;
	}

	if (pair_hex) {
		if (!booted) {
			fprintf(stderr, "fuzznetd: --pair needs --store, and no --identity: "
			                "pairing mints, so the node must hold its key\n");
			return 2;
		}
		return pair_device(&identity, &state.config, store_ops, pair_hex,
		                   wall_clock());
	}
	/* REFUSED RATHER THAN BOUND. A remote hop with no identity seals its
	 * replies as from the zero key and verifies chains against a zero
	 * root, which no real peer can satisfy -- so it would bind, look
	 * healthy, and drop every frame. That is the exact failure this wiring
	 * closes, and starting anyway would reintroduce it with more moving
	 * parts. */
	if (udp_port >= 0 && !identity_hex && !booted) {
		fprintf(stderr, "fuzznetd: --udp-port needs --identity or --store\n");
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
	if (store_ops) {
		static fzn_node_peer_t peers[FZN_NODE_PEERS_MAX];
		size_t loaded = 0;
		fzn_persist_err_t err;

		err = fzn_node_peers_load(store_ops, peers, FZN_NODE_PEERS_MAX, &loaded);
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
