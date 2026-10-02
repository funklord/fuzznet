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
 * with `--fuzznet-dir` and no `--identity` the daemon loads its identity from
 * there, or creates a self-rooted one when it holds none, through
 * `node/identity.h`. sec 375. What it also does is LOAD a set a consumer has
 * already provisioned, from the same store. Reading what somebody else decided is not
 * deciding it, and without this the daemon could bind the remote hop and
 * serve nobody for ever -- raidcfgd reported exactly that on 2026-09-22.
 *
 * TWO DIRECTORIES SINCE sec 392, by the holder's rule that anything needed to
 * keep an attacker out lives in the core one whatever its size: identity,
 * anchor, pinned prekeys, ratchet positions and revocations under
 * `--fuzznet-dir`; the peers a node serves and the pairings a device holds
 * under `--fuzznet-store`, which defaults to the core directory when omitted
 * (`fzn_persist_slot_is_core`). They replace the one `--store DIR`.
 *
 * `--fuzznet-dir` is opt-in. Without it the daemon behaves as before and a
 * consumer that fills the state itself and calls `fzn_node_run` is
 * unaffected. With it, a store that cannot be read is FATAL rather than
 * empty: a daemon that starts having silently served nobody is the failure
 * this exists to end, and `sec 366` records the same argument one layer
 * down.
 */

#include "serve.h"
#include "admin.h"
#include "caller.h"
#include "identity.h"
#include "pair.h"
#include "revoke.h"
#include "roots.h"
#include "peer_persist.h"
#include "notes.h"
#include "../notes/received.h"
#include "../notes/share.h"
#include "members.h"
#include "received.h"
#ifdef FZN_SPOOL_FILE_ON
#include "shelf.h"
#endif
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

/* The wall clock in milliseconds, which a note's times are in. */
static uint64_t wall_ms(void)
{
	struct timespec ts;

	/* C11's, so nothing here needs a POSIX feature macro for it. */
	if (timespec_get(&ts, TIME_UTC) != TIME_UTC || ts.tv_sec < 0)
		return 0u;
	return ((uint64_t)ts.tv_sec * 1000u) + ((uint64_t)ts.tv_nsec / 1000000u);
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

/* HOW OFTEN A MEMBER ASKS ITS ROOT WHAT IT HAS REVOKED. fuzzypickles sweeps
 * its siblings on the same period, and it bounds the same thing: how long a
 * device the root cut off goes on being served here. A pull blocks the loop
 * for as long as the root takes to answer, at most 3 s a page, which is the
 * price of asking from the loop's own thread. sec 384. */
#define FZND_PULL_EVERY 60u

/* THE PEERS A NODE PULLS VOTES FROM: `--root-at` for the pairing it joined
 * with, and `--pull-from` for any other node it holds a pairing to. Each has
 * its own socket and reassembly table, so a late answer from one is never
 * read as another's. Eight, because an estate's nodes are a household's and
 * every one costs a pull a minute. sec 401. */
#define FZND_PULL_TARGETS_MAX 8u

#ifdef FZN_SPOOL_FILE_ON
/* LONG NOTES' TEXTS, on the shelf under the store directory, served to any
 * peer the remote hop admits and fetched from the pull peers each round. The
 * node's reply buffer and a pull's reassembly are both sized to the shelf's
 * largest DATA, since the default reply is 512 bytes and one leaf is more.
 * sec 424. */
static fzn_node_shelf_t shelf;
static int shelf_on;

/* The node's notes seal a long text onto the shelf and open it back. */
static int shelf_seal(void *ctx, const uint8_t *text, size_t len, fzn_note_blob_ref_t *ref)
{
	return fzn_node_shelf_put((fzn_node_shelf_t *)ctx, text, len, ref) == FZN_NODE_SHELF_OK;
}

static int shelf_open(void *ctx, const fzn_note_blob_ref_t *ref, uint8_t *out, size_t cap,
                      size_t *out_len)
{
	fzn_note_err_t text_err = FZN_NOTE_OK;

	return fzn_node_shelf_open((fzn_node_shelf_t *)ctx, ref, out, cap, out_len, &text_err)
	       == FZN_NODE_SHELF_OK;
}

#define FZND_REPLY_MAX                                                                        \
	(FZN_NODE_SHELF_REPLY_MAX > FZN_NOTES_SYNC_REPLY_MAX ? FZN_NODE_SHELF_REPLY_MAX          \
	                                                     : FZN_NOTES_SYNC_REPLY_MAX)
#else
#define FZND_REPLY_MAX FZN_NOTES_SYNC_REPLY_MAX
#endif

/* THE NODE'S REPLY BUFFER, and each pull's reassembly, sized to the largest
 * answer a peer sends -- a shelf's DATA, a notes sync's RECORDS -- since the
 * default reply is 512 bytes. secs 424 and 432. */
static uint8_t node_reply[FZND_REPLY_MAX];
#define FZND_PULL_REPLY_MAX FZND_REPLY_MAX

/* THE REQUESTS THIS NODE REASSEMBLES, sec 447: a request past one frame
 * arrives in pieces, and sec 370 gave the node a table to put them back
 * together -- which this daemon never handed it, so every such request was
 * dropped and its caller timed out. Four at once, each up to 32 KiB, one a
 * sender, held a minute. A request past 32 KiB is still refused, by the
 * table, which is a bound rather than a silence the caller cannot tell from
 * the network. */
#define FZND_REQUEST_SLOTS 4u
#define FZND_REQUEST_MAX (32u * 1024u)

/* The node's notes, when it keeps them: answered on the socket, served to
 * peers and pulled from them each round. sec 431, 432. */
static fzn_node_notes_t node_notes;
static int notes_on;

/* What the shelf and the notes ask a pull peer through: its caller, as a
 * votes pull does. */
struct peer_asking {
	fzn_caller_t *caller;
	uint64_t now;
};

static int peer_ask(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
                    size_t reply_cap, size_t *reply_len)
{
	struct peer_asking *asking = (struct peer_asking *)ctx;
	uint32_t msg = 0;

	return fzn_caller_send(asking->caller, request, request_len, asking->now + 300u, &msg)
	               == FZN_CALLER_OK
	       && fzn_caller_recv(asking->caller, msg, reply, reply_cap, reply_len, 3000u)
	                  == FZN_CALLER_OK;
}

struct pull_target {
	const char *host;
	long port;
	int is_root_at;
	uint8_t node[FZN_PUBKEY_LEN];
	fzn_node_pairing_t pairing;
	fzn_caller_t caller;
	fzn_reasm_t table;
	fzn_partial_t slot;
	uint8_t slot_buf[FZND_PULL_REPLY_MAX];
	int fd;
};

/* The members the last round's pulls proved, sec 445, kept so the writer set
 * can be rebuilt between rounds. */
static uint8_t pulled_members[FZN_NODE_NOTES_WRITERS][FZN_PUBKEY_LEN];
static size_t n_pulled_members;

/* THE WRITERS BEYOND THIS NODE AND ITS PULL PEERS, rebuilt from what is live
 * now, sec 451: the estate's standing roots (sec 450), the peers paired to
 * this node that are no contact (sec 436), and the members the last round
 * proved. Asked every pass of the loop, so a device paired or un-paired on
 * the socket is a writer, or not, at once rather than after a restart. */
static void admit_writers(const fzn_node_state_t *state, const fzn_node_roots_t *roots)
{
	static uint8_t keys[FZN_NODE_NOTES_WRITERS][FZN_PUBKEY_LEN];
	size_t n, i;

	if (!notes_on)
		return;
	n = fzn_node_roots_standing(roots, keys, FZN_NODE_NOTES_WRITERS);
	for (i = 0; i < state->peer_count && n < FZN_NODE_NOTES_WRITERS; i++)
		if (!fzn_node_peer_contact(&state->config, &state->peers[i]))
			memcpy(keys[n++], state->peers[i].sender, FZN_PUBKEY_LEN);
	for (i = 0; i < n_pulled_members && n < FZN_NODE_NOTES_WRITERS; i++)
		memcpy(keys[n++], pulled_members[i], FZN_PUBKEY_LEN);
	(void)fzn_node_notes_admit_members(&node_notes, (const uint8_t (*)[FZN_PUBKEY_LEN])keys, n);
}

/* Every note each pull peer holds that this node lacks or holds older,
 * admitted as any record is. sec 432. */
static void pull_notes(struct pull_target *pulls, size_t npulls, uint64_t now,
                       const fzn_node_state_t *state,
                       const fzn_revocation_store_t *revocations,
                       const fzn_node_roots_t *roots)
{
	const fzn_node_config_t *config = &state->config;
	uint8_t (*members)[FZN_PUBKEY_LEN] = pulled_members;
	size_t t, n_members = 0;

	if (!notes_on)
		return;
	/* THE ESTATE'S MEMBERS FIRST, sec 445: each pull peer's, admitted on
	 * the proof of their chains against this node's own root, so a note a
	 * member wrote and a peer relays is taken. Rebuilt every round, so a
	 * member revoked since drops out. */
	for (t = 0; t < npulls; t++) {
		struct peer_asking asking = { &pulls[t].caller, now };
		size_t got = 0, refused = 0;
		fzn_node_members_err_t merr = fzn_node_members_pull(
		        peer_ask, &asking, config->root, &config->remote_capability, now,
		        node_notes.author.sign, revocations, members + n_members,
		        FZN_NODE_NOTES_WRITERS - n_members, &got, &refused);

		if (merr != FZN_NODE_MEMBERS_OK)
			fprintf(stderr, "fuzznetd: members from %s: %s\n", pulls[t].host,
			        fzn_node_members_err_str(merr));
		else if (refused)
			fprintf(stderr, "fuzznetd: %zu member(s) from %s did not prove\n", refused,
			        pulls[t].host);
		n_members += got;
	}
	n_pulled_members = n_members;
	admit_writers(state, roots);
	for (t = 0; t < npulls; t++) {
		struct peer_asking asking = { &pulls[t].caller, now };
		fzn_notes_sync_tally_t tally;
		fzn_notes_sync_err_t err = fzn_notes_sync_pull(&node_notes.store,
		                                               node_notes.author.policy,
		                                               node_notes.author.sign, peer_ask,
		                                               &asking, &tally);

		if (err != FZN_NOTES_SYNC_OK)
			fprintf(stderr, "fuzznetd: notes from %s: %s\n", pulls[t].host,
			        fzn_notes_sync_err_str(err));
		else if (tally.learned || tally.refused)
			fprintf(stderr, "fuzznetd: %zu note record(s) from %s, %zu refused\n",
			        tally.learned, pulls[t].host, tally.refused);
		/* AND PUSHED BACK, sec 446: what this node holds that the peer
		 * lacks, so a note written here reaches a node that does not pull
		 * from this one. */
		{
			fzn_notes_push_tally_t pt;
			fzn_notes_sync_err_t perr =
			        fzn_notes_sync_push(&node_notes.store, peer_ask, &asking, &pt);

			if (perr != FZN_NOTES_SYNC_OK)
				fprintf(stderr, "fuzznetd: notes to %s: %s\n", pulls[t].host,
				        fzn_notes_sync_err_str(perr));
			else if (pt.taken || pt.refused)
				fprintf(stderr, "fuzznetd: %zu note record(s) to %s, %zu refused\n",
				        pt.taken, pulls[t].host, pt.refused);
		}
		/* AND THEIR TEXTS, sec 448: a pushed note whose text stayed here
		 * would be a note nobody there could read. */
		{
			fzn_node_notes_text_tally_t tt;

			if (!fzn_node_notes_push_texts(&node_notes, peer_ask, &asking, &tt))
				fprintf(stderr, "fuzznetd: texts to %s: no answer\n", pulls[t].host);
			else if (tt.pushed || tt.refused)
				fprintf(stderr, "fuzznetd: %zu text(s) to %s in %zu span(s), %zu refused\n",
				        tt.pushed, pulls[t].host, tt.spans, tt.refused);
		}
		/* THE PURGE CONVERSATION, driven from this side. sec 433. */
		{
			fzn_notes_purge_tally_t pt;

			err = fzn_notes_sync_purges(&node_notes.store, node_notes.author.policy,
			                            node_notes.pulls[t].key, peer_ask, &asking, &pt);
			if (err != FZN_NOTES_SYNC_OK)
				fprintf(stderr, "fuzznetd: purges with %s: %s\n", pulls[t].host,
				        fzn_notes_sync_err_str(err));
			else if (pt.erased || pt.finished || pt.taken || pt.refused || pt.declined)
				fprintf(stderr,
				        "fuzznetd: purges with %s: %zu erased there, %zu finished, "
				        "%zu taken, %zu refused, %zu declined\n",
				        pulls[t].host, pt.erased, pt.finished, pt.taken, pt.refused,
				        pt.declined);
		}
	}
#ifdef FZN_SPOOL_FILE_ON
	/* A NOTE WHOSE TEXT IS A BLOB NAMES WHAT TO FETCH: every one held is
	 * wanted on the shelf, which answers at once for a text already here,
	 * so the texts follow their notes in the same round. sec 432. */
	if (shelf_on
	    && fzn_notes_view_load(&node_notes.store, node_notes.author.view) == FZN_NOTES_OK) {
		const fzn_notes_view_t *v = node_notes.author.view;
		size_t i;

		for (i = 0; i < v->count; i++) {
			fzn_note_t note;
			fzn_note_blob_ref_t ref;

			if (fzn_note_open(v->nodes[i].content_type, v->nodes[i].content,
			                  v->nodes[i].content_len, &note)
			            == FZN_NOTE_OK
			    && fzn_note_blob_ref(&note, &ref) == FZN_NOTE_OK)
				(void)fzn_node_shelf_want(&shelf, ref.root, ref.length);
		}
	}
#endif
}

/* SHARES THIS NODE ACCEPTED, as pull targets, sec 437: each sharer's node at
 * the address `add received` recorded, asked under the pairing its card
 * made. Reloaded when the verbs change the table. */
struct share_target {
	struct pull_target pt;
	char host[FZN_NODE_RECEIVED_HOST_MAX + 1u];
	uint8_t sharer[FZN_PUBKEY_LEN];
};

static struct share_target shares_in[FZN_NODE_RECEIVED_MAX];
static size_t nshares_in;
/* The running admin, whose `received_fresh` the loop reads. */
static fzn_node_admin_t *running_admin;

static void load_received(int family, const uint8_t self[FZN_PUBKEY_LEN],
                          const fzn_hash_ops_t *hash, const fzn_aead_ops_t *aead,
                          const fzn_random_ops_t *rng)
{
	static fzn_node_received_t rows[FZN_NODE_RECEIVED_MAX];
	size_t count = 0, i;

	for (i = 0; i < nshares_in; i++) {
		if (shares_in[i].pt.fd >= 0)
			fzn_udp_close(shares_in[i].pt.fd);
		fzn_wipe(&shares_in[i].pt.pairing, sizeof(shares_in[i].pt.pairing));
	}
	nshares_in = 0;
	if (!notes_on
	    || fzn_node_received_list(node_notes.store.ops, rows, FZN_NODE_RECEIVED_MAX, &count)
	               != FZN_NODE_RECEIVED_OK)
		return;
	for (i = 0; i < count; i++) {
		struct share_target *sh = &shares_in[nshares_in];
		struct pull_target *pt = &sh->pt;
		int fd = -1;

		memset(sh, 0, sizeof(*sh));
		pt->fd = -1;
		memcpy(sh->host, rows[i].host, rows[i].host_len);
		sh->host[rows[i].host_len] = '\0';
		memcpy(sh->sharer, rows[i].sharer, FZN_PUBKEY_LEN);
		pt->host = sh->host;
		pt->port = rows[i].port;
		/* A ROW WITH NO PAIRING is reported and skipped: the others are
		 * still pulled. */
		if (fzn_node_pairing_load(node_notes.store.ops, rows[i].sharer, &pt->pairing)
		    != FZN_PERSIST_OK) {
			fprintf(stderr, "fuzznetd: a share from %s holds no pairing\n", sh->host);
			continue;
		}
		if (fzn_udp_bind(family, NULL, 0, &fd) != FZN_UDP_OK
		    || fzn_udp_resolve(family, sh->host, rows[i].port, &pt->caller.node)
		               != FZN_UDP_OK
		    || fzn_reasm_slot_init(&pt->slot, pt->slot_buf, sizeof(pt->slot_buf))
		               != FZN_REASM_OK
		    || fzn_reasm_init(&pt->table, &pt->slot, 1, 1u, 60u) != FZN_REASM_OK) {
			fprintf(stderr, "fuzznetd: could not reach for a share at %s\n", sh->host);
			if (fd >= 0)
				fzn_udp_close(fd);
			fzn_wipe(&pt->pairing, sizeof(pt->pairing));
			continue;
		}
		pt->fd = fd;
		fzn_node_pairing_caller(&pt->pairing, self, &pt->caller);
		pt->caller.fd = fd;
		pt->caller.hash = hash;
		pt->caller.aead = aead;
		pt->caller.rng = rng;
		pt->caller.reasm = &pt->table;
		pt->caller.hops = 1u;
		nshares_in++;
	}
}

/* Each accepted share into its sharer's tree. sec 437. */
static void pull_received(uint64_t now)
{
	size_t i;

	if (!notes_on)
		return;
	for (i = 0; i < nshares_in; i++) {
		static fzn_notes_received_t seam;
		static fzn_persist_ops_t ops;
		fzn_notes_store_t tree;
		struct peer_asking asking = { &shares_in[i].pt.caller, now };
		fzn_notes_sync_tally_t tally;
		fzn_notes_sync_err_t err;

		if (fzn_notes_received_ops(&seam, node_notes.store.ops, node_notes.store.hash,
		                           shares_in[i].sharer, &ops)
		            != FZN_NOTES_OK
		    || fzn_notes_store_init(&tree, &ops, node_notes.store.hash) != FZN_NOTES_OK)
			continue;
		err = fzn_notes_sync_pull_shared(&tree, node_notes.author.sign, peer_ask, &asking,
		                                 &tally);
		if (err != FZN_NOTES_SYNC_OK)
			fprintf(stderr, "fuzznetd: shared notes from %s: %s\n", shares_in[i].host,
			        fzn_notes_sync_err_str(err));
		else if (tally.learned || tally.refused)
			fprintf(stderr, "fuzznetd: %zu shared note record(s) from %s, %zu refused\n",
			        tally.learned, shares_in[i].host, tally.refused);
#ifdef FZN_SPOOL_FILE_ON
		/* THE SHARED NOTES' TEXTS, sec 438: each blob one of them names is
		 * wanted on the shelf and asked of the sharer, which serves a
		 * contact the texts of what it shares and nothing else. */
		if (shelf_on && fzn_notes_view_load(&tree, node_notes.author.view) == FZN_NOTES_OK) {
			const fzn_notes_view_t *v = node_notes.author.view;
			size_t k, got;

			for (k = 0; k < v->count; k++) {
				fzn_note_t note;
				fzn_note_blob_ref_t ref;

				if (fzn_note_open(v->nodes[k].content_type, v->nodes[k].content,
				                  v->nodes[k].content_len, &note)
				            == FZN_NOTE_OK
				    && fzn_note_blob_ref(&note, &ref) == FZN_NOTE_OK)
					(void)fzn_node_shelf_want(&shelf, ref.root, ref.length);
			}
			got = fzn_node_shelf_fetch_wants(&shelf, peer_ask, &asking);
			if (got)
				fprintf(stderr, "fuzznetd: %zu shared text(s) from %s\n", got,
				        shares_in[i].host);
		}
#endif
	}
}

#ifdef FZN_SPOOL_FILE_ON
/* COLLECTING THE SHELF, sec 443: a text no note names, this node's or a
 * sharer's, goes. Run after each round's fetches, so a text just wanted is
 * kept by its want. */
static int keep_blob(void *ctx, const uint8_t root[FZN_BLOB_HASH_LEN])
{
	return fzn_node_notes_names_blob((fzn_node_notes_t *)ctx, root);
}

static int shelf_collect(void *ctx, int (*keep)(void *keep_ctx, const uint8_t *root),
                         void *keep_ctx, size_t *kept, size_t *removed)
{
	return fzn_node_shelf_collect((fzn_node_shelf_t *)ctx, keep, keep_ctx, kept, removed)
	       == FZN_NODE_SHELF_OK;
}

/* PUSHED TEXTS, sec 448, over the shelf. */
static int shelf_place(void *ctx, const uint8_t *root, uint64_t length, const uint8_t *data,
                       size_t data_len, int *complete)
{
	fzn_node_shelf_t *sh = (fzn_node_shelf_t *)ctx;
	uint64_t have = 0;

	if (!data) {
		*complete = fzn_node_shelf_held(sh, root, &have) == FZN_NODE_SHELF_OK
		            && have == length;
		return 1;
	}
	return fzn_node_shelf_place(sh, root, length, data, data_len, complete)
	       == FZN_NODE_SHELF_OK;
}

static int shelf_span(void *ctx, const uint8_t *root, uint64_t first, uint8_t *out, size_t cap,
                      size_t *out_len, uint64_t *count)
{
	return fzn_node_shelf_data_at((fzn_node_shelf_t *)ctx, root, first, out, cap, out_len,
	                              count)
	       == FZN_NODE_SHELF_OK;
}

static void collect_texts(void)
{
	size_t kept = 0, removed = 0;

	if (!shelf_on || !notes_on)
		return;
	if (fzn_node_shelf_collect(&shelf, keep_blob, &node_notes, &kept, &removed)
	    != FZN_NODE_SHELF_OK)
		fprintf(stderr, "fuzznetd: the shelf would not all be collected\n");
	else if (removed)
		fprintf(stderr, "fuzznetd: %zu text(s) no note names removed, %zu kept\n", removed,
		        kept);
}

/* THE SHELF RE-VERIFIED AT REST, sec 452: a few texts every half minute,
 * in turn, so a bad sector or a file edited underneath is found by the node
 * rather than by the next reader. A text that fails stops being held and is
 * fetched again by the round, which wants every text a note names. */
#define FZND_SCRUB_EVERY 30u
#define FZND_SCRUB_STEPS 4u

static void scrub_shelf(uint64_t now)
{
	static uint64_t next_scrub;
	uint8_t began[FZN_BLOB_HASH_LEN];
	size_t i;

	if (!shelf_on || now < next_scrub)
		return;
	next_scrub = now + FZND_SCRUB_EVERY;
	for (i = 0; i < FZND_SCRUB_STEPS; i++) {
		int checked = 0, dropped = 0;
		fzn_node_shelf_err_t err = fzn_node_shelf_scrub_step(&shelf, &checked, &dropped);

		if (err != FZN_NODE_SHELF_OK) {
			fprintf(stderr, "fuzznetd: the shelf's check at rest: %s\n",
			        fzn_node_shelf_err_str(err));
			return;
		}
		if (dropped) {
			char hex[(FZN_BLOB_HASH_LEN * 2u) + 1u];
			size_t k;

			for (k = 0; k < FZN_BLOB_HASH_LEN; k++)
				(void)snprintf(hex + (k * 2u), 3u, "%02x", shelf.scrub_after[k]);
			fprintf(stderr, "fuzznetd: text %s failed its check at rest; it is fetched "
			                "again\n",
			        hex);
		}
		/* A SHELF SMALLER THAN A BATCH: the batch stops once the walk is
		 * back at the text it began with, not round and round. */
		if (!checked || (i > 0u && memcmp(shelf.scrub_after, began, sizeof(began)) == 0))
			return;
		if (i == 0u)
			memcpy(began, shelf.scrub_after, sizeof(began));
	}
}

/* A contact may fetch the texts of the notes shared with it, sec 438: the
 * shelf answers a root the notes say a note in that contact's share has. */
static int shared_text_permit(void *ctx, const uint8_t root[FZN_BLOB_HASH_LEN])
{
	return fzn_node_notes_shares_blob(&node_notes, (const uint8_t *)ctx, root);
}

static size_t shared_text(void *ctx, const uint8_t *sender, const uint8_t *request,
                          size_t request_len, uint8_t *reply, size_t reply_cap)
{
	return fzn_node_shelf_answer_permitted((const fzn_node_shelf_t *)ctx, shared_text_permit,
	                                       (void *)(uintptr_t)sender, request, request_len,
	                                       reply, reply_cap);
}
#endif

#ifdef FZN_SPOOL_FILE_ON
/* Every remembered text, from each pull peer in turn until it is here. */
static void fetch_texts(struct pull_target *pulls, size_t npulls, uint64_t now)
{
	size_t t;

	if (!shelf_on)
		return;
	shelf.fresh = 0;
	for (t = 0; t < npulls; t++) {
		struct peer_asking asking = { &pulls[t].caller, now };
		size_t got = fzn_node_shelf_fetch_wants(&shelf, peer_ask, &asking);

		if (got)
			fprintf(stderr, "fuzznetd: %zu text(s) from %s\n", got, pulls[t].host);
	}
}
#endif

static void usage(const char *prog)
{
	fprintf(stderr,
	        "usage: %s --socket=PATH [--group GID] [--udp-port=PORT]"
	        " [--udp6] [--identity HEX] [--root HEX]"
	        " [fuzznet options]\n"
	        "       %s --fuzznet-dir=DIR --pair=PREKEY_HEX [--delegable] [fuzznet options]\n"
	        "       %s --fuzznet-dir=DIR --prekey\n"
	        "       %s --fuzznet-dir=DIR --new-root\n"
	        "       %s --fuzznet-dir=DIR --set-admin CHAIN [fuzznet options]\n"
	        "       %s --fuzznet-dir=DIR --accept=CARD [--join]\n"
	        "       %s --fuzznet-dir=DIR --ask LINE --node=ROOT_HEX --to HOST PORT [--udp6]\n"
	        "a member of an estate may add --root-at HOST PORT when serving, and any\n"
	        "node --pull-from NODE_HEX HOST PORT (up to 8) for a node it holds a\n"
	        "pairing to: it pulls their revocation votes at start and every %u seconds\n"
	        "--quorum K: a revocation needs K distinct entitled issuers, a root alone\n"
	        "counting as K (default 2), until a root sets the estate's k (set quorum K)\n"
	        "%s",
	        prog, prog, prog, prog, prog, prog, prog, FZND_PULL_EVERY, fzn_cli_usage());
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
                       const fzn_node_authority_t *authority, int delegable,
                       const fzn_persist_ops_t *store, const char *prekey_hex, uint64_t now)
{
	uint8_t record_bytes[FZN_PREKEY_LEN_TOTAL];
	uint8_t card[FZN_PROVISION_MAX_LEN];
	char text[FZN_PROVISION_TEXT_MAX_LEN];
	fzn_prekey_record_t record;
	fzn_node_pair_err_t perr;
	size_t card_len = 0;

	if (!hex_bytes(prekey_hex, record_bytes, sizeof(record_bytes))
	    || fzn_prekey_open(record_bytes, sizeof(record_bytes), &record) != FZN_PREKEY_OK) {
		fprintf(stderr, "fuzznetd: --pair is not a prekey record (%u hex characters)\n",
		        (unsigned)(FZN_PREKEY_LEN_TOTAL * 2u));
		return 2;
	}
	perr = fzn_node_pair(id, config->root, &config->remote_capability, authority, delegable,
	                     store, record, now, now + FZND_CARD_LIFETIME, card, sizeof(card),
	                     &card_len);
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
	/* A SECOND SIGNER for the root key this node may hold beside its
	 * identity, sec 409: two keys, two seats, never one signer re-armed. */
	static fzn_sign_monocypher_t root_signer;
	fzn_sign_ops_t root_sign_ops;
	fzn_sign_seat_t root_seat;
	int new_root = 0;
	fzn_agree_ops_t agree_ops;
	fzn_sign_monocypher_t signer;
	static fzn_persist_file_t core_file, bulk_file;
	static fzn_persist_route_t route;
	static fzn_persist_ops_t routed;
	const fzn_persist_ops_t *store_ops = NULL;
	static fzn_agree_secret_t agree_secret;
	static fzn_trust_t trust;
	static fzn_node_identity_t identity;
	int booted = 0;
	fzn_replay_window_t replay;
	static fzn_replay_entry_t replay_entries[FZND_REPLAY_ENTRIES];
	const char *store_dir = NULL;	/* the core directory, for messages */
	const char *bulk_dir = NULL;
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
	const char *set_admin = NULL;
	static fzn_node_admin_chain_t own_admin;
	int delegable = 0, join = 0;
	static fzn_node_pairing_t estate;
	static fzn_node_authority_t authority;
	const fzn_node_authority_t *my_authority = NULL;
	const char *ask_line = NULL;
	const char *to_host = NULL;
	long to_port = -1;
	static struct pull_target pulls[FZND_PULL_TARGETS_MAX];
	size_t npulls = 0;
	fzn_revocation_store_t *running = NULL;
	fzn_node_roots_t *running_roots = NULL;
	long quorum = 2;
	int has_capability = 0;
	int lfd = -1, ufd = -1, i;

	fzn_cli_init(&cli);

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--group") && i + 1 < argc) {
			group = strtol(argv[++i], NULL, 10);
		} else if (!strcmp(argv[i], "--identity") && i + 1 < argc) {
			identity_hex = argv[++i];
		} else if (!strcmp(argv[i], "--root") && i + 1 < argc) {
			root_hex = argv[++i];
		} else if (!strcmp(argv[i], "--new-root")) {
			new_root = 1;
		} else if (!strcmp(argv[i], "--set-admin") && i + 1 < argc) {
			set_admin = argv[++i];
		} else if (!strcmp(argv[i], "--delegable")) {
			delegable = 1;
		} else if (!strcmp(argv[i], "--join")) {
			join = 1;
		} else if (!strcmp(argv[i], "--ask") && i + 1 < argc) {
			ask_line = argv[++i];
		} else if (!strcmp(argv[i], "--quorum") && i + 1 < argc) {
			char *end = NULL;

			quorum = strtol(argv[++i], &end, 10);
			if (!end || *end || quorum < 1 || quorum > 64) {
				fprintf(stderr, "fuzznetd: --quorum: a count from 1 to 64\n");
				return 2;
			}
		} else if (!strcmp(argv[i], "--root-at") && i + 2 < argc) {
			if (npulls >= FZND_PULL_TARGETS_MAX) {
				fprintf(stderr, "fuzznetd: at most %u peers to pull from\n",
				        FZND_PULL_TARGETS_MAX);
				return 2;
			}
			pulls[npulls].host = argv[++i];
			pulls[npulls].port = strtol(argv[++i], NULL, 10);
			pulls[npulls].is_root_at = 1;
			npulls++;
		} else if (!strcmp(argv[i], "--pull-from") && i + 3 < argc) {
			if (npulls >= FZND_PULL_TARGETS_MAX) {
				fprintf(stderr, "fuzznetd: at most %u peers to pull from\n",
				        FZND_PULL_TARGETS_MAX);
				return 2;
			}
			if (!hex_pubkey(argv[++i], pulls[npulls].node)) {
				fprintf(stderr, "fuzznetd: --pull-from: a node key is 64 hex digits\n");
				return 2;
			}
			pulls[npulls].host = argv[++i];
			pulls[npulls].port = strtol(argv[++i], NULL, 10);
			pulls[npulls].is_root_at = 0;
			npulls++;
		} else if (!strcmp(argv[i], "--to") && i + 2 < argc) {
			to_host = argv[++i];
			to_port = strtol(argv[++i], NULL, 10);
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
	/* THE NODE'S OPTIONS ARE FUZZNET'S PARSER'S since sec 421, read back
	 * here into the names this main has always used. */
	sock_path = cli.socket;
	udp_port = cli.has_udp_port ? (long)cli.udp_port : -1;
	if (cli.udp6)
		family = AF_INET6;
	pair_hex = cli.pair;
	show_prekey = cli.prekey;
	accept_text = cli.accept;
	/* A NODE THAT SERVES ONLY THE REMOTE HOP needs no local socket, and the
	 * loop has always taken a listen fd of -1 (sec 381). */
	if (!sock_path && !pair_hex && !show_prekey && !new_root && !accept_text && !ask_line
	    && !set_admin && udp_port < 0) {
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
	fzn_sign_monocypher_init(&root_sign_ops, &root_signer);
	fzn_sign_monocypher_seat_init(&root_seat, &root_signer);
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
		                           &state.config.remote_capability) != FZN_CHAIN_OK
		    || fzn_service_capability(cli.service, cli.product,
		                              (const uint8_t *)FZN_NODE_ADMIN_NAME,
		                              sizeof(FZN_NODE_ADMIN_NAME) - 1u, &hash_ops,
		                              &state.config.admin_capability) != FZN_CHAIN_OK) {
			fprintf(stderr, "fuzznetd: the remote capability needs both "
			                "--fuzznet-service and --fuzznet-product\n");
			return 2;
		}
		has_capability = 1;
		state.config.has_admin = 1;
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
	store_dir = cli.dir;
	bulk_dir = cli.store ? cli.store : cli.dir;
	if (store_dir) {
		route.core = fzn_persist_file_init(&core_file, store_dir);
		route.store = (bulk_dir == store_dir) ? route.core
		                                      : fzn_persist_file_init(&bulk_file, bulk_dir);
		if (!route.core || !route.store) {
			fprintf(stderr, "fuzznetd: could not open %s\n",
			        route.core ? bulk_dir : store_dir);
			return 1;
		}
		fzn_persist_route_ops(&route, &routed);
		store_ops = &routed;
	} else if (cli.store) {
		fprintf(stderr, "fuzznetd: --fuzznet-store needs --fuzznet-dir: the identity "
		                "and what keeps attackers out live in the core directory\n");
		return 2;
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
		found.seed = fzn_persist_file_holds(&core_file, FZN_PERSIST_OWN_IDENTITY, NULL);
		found.prekey = fzn_persist_file_holds(&core_file, FZN_PERSIST_OWN_PREKEY, NULL);
		found.trust = fzn_persist_file_holds(&core_file, FZN_PERSIST_TRUST, NULL);
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

		/* A NODE THAT HAS JOINED AN ESTATE grants through the hop its root
		 * gave it, which it holds as its pairing to that root (sec 383). A
		 * joined node without one still serves; it cannot pair, and
		 * `fzn_node_pair` says so when asked. */
		if (memcmp(state.config.root, identity.pubkey, FZN_PUBKEY_LEN) != 0) {
			fprintf(stderr, "fuzznetd: member of the estate rooted at ");
			print_hex(stderr, state.config.root, FZN_PUBKEY_LEN);
			fprintf(stderr, "\n");
			/* Found by shape: joined through a member, the pairing
			 * is filed under that member, not the root. sec 391. */
			if (fzn_node_pairing_estate(store_ops, state.config.root, identity.pubkey,
			                            &estate) == FZN_PERSIST_OK) {
				authority.hops = (const uint8_t (*)[FZN_HOP_LEN])estate.chain;
				authority.hop_count = estate.hop_count;
				my_authority = &authority;
			}
		}
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
			fprintf(stderr, "fuzznetd: --prekey needs --fuzznet-dir, and no --identity\n");
			return 2;
		}
		print_hex(stdout, identity.prekey_record, FZN_PREKEY_LEN_TOTAL);
		printf("\n");
		return 0;
	}

	/* THIS NODE'S ADMIN CHAIN, sec 416: the `h` items `grant admin` answered,
	 * verified from a root of the estate -- the set this node holds -- for
	 * the admin capability, naming this node, and kept in the core
	 * directory. Offline, as `--pair` is; the daemon votes on it from its
	 * next start. */
	if (set_admin) {
		static fzn_node_roots_t held;
		static fzn_revocation_t none[1];
		static uint8_t hops[FZN_CHAIN_MAX_HOPS][FZN_HOP_LEN];
		fzn_revocation_store_t judged;
		fzn_node_revoke_err_t rerr;
		const char *at = set_admin;
		size_t n = 0, nroots = 0;

		if (!booted || !store_ops || !has_capability) {
			fprintf(stderr, "fuzznetd: --set-admin needs --fuzznet-dir and the service "
			                "options its capability is derived from\n");
			return 2;
		}
		while (*at) {
			char item[(FZN_HOP_LEN * 2u) + 1u];

			while (*at == ' ')
				at++;
			if (!*at)
				break;
			if (*at == 'h')
				at++;
			if (n >= FZN_CHAIN_MAX_HOPS - 1u || strlen(at) < FZN_HOP_LEN * 2u) {
				fprintf(stderr, "fuzznetd: --set-admin is not a chain of hops\n");
				return 2;
			}
			memcpy(item, at, FZN_HOP_LEN * 2u);
			item[FZN_HOP_LEN * 2u] = '\0';
			if (!hex_bytes(item, hops[n], FZN_HOP_LEN)) {
				fprintf(stderr, "fuzznetd: --set-admin is not a chain of hops\n");
				return 2;
			}
			n++;
			at += FZN_HOP_LEN * 2u;
		}
		if (fzn_revocation_store_init(&judged, none, 1u) != FZN_CHAIN_OK
		    || fzn_node_roots_init(&held, state.config.root, &sign_ops, &hash_ops)
		               != FZN_NODE_ROOTS_OK
		    || fzn_node_roots_load(&held, store_ops, &nroots) != FZN_NODE_ROOTS_OK
		    || fzn_node_roots_attach(&held, &judged) != FZN_NODE_ROOTS_OK) {
			fprintf(stderr, "fuzznetd: --set-admin could not restore the roots\n");
			return 1;
		}
		rerr = fzn_node_admin_chain_set(store_ops, &judged, &identity, state.config.root,
		                                &state.config.admin_capability,
		                                (const uint8_t (*)[FZN_HOP_LEN])hops, n, wall_clock(),
		                                &own_admin);
		if (rerr != FZN_NODE_REVOKE_OK) {
			fprintf(stderr, "fuzznetd: --set-admin: %s\n", fzn_node_revoke_err_str(rerr));
			return 1;
		}
		fprintf(stderr, "fuzznetd: admin chain of %zu hop(s) kept\n", n);
		return 0;
	}

	/* A ROOT KEY OF THIS NODE'S OWN, sec 409: generated, saved in the core
	 * directory, and its public key printed. It is a root only once a
	 * standing root adds it -- `add root KEY` on that root's node. */
	if (new_root) {
		static fzn_node_roots_t mine;

		if (!booted || !store_ops) {
			fprintf(stderr, "fuzznetd: --new-root needs --fuzznet-dir\n");
			return 2;
		}
		if (fzn_node_roots_init(&mine, identity.pubkey, &sign_ops, &hash_ops)
		            != FZN_NODE_ROOTS_OK) {
			fprintf(stderr, "fuzznetd: --new-root could not start\n");
			return 1;
		}
		{
			fzn_node_roots_err_t rerr = fzn_node_roots_key_create(&mine, store_ops, &rng_ops,
			                                                      &root_seat,
			                                                      &root_sign_ops);

			if (rerr != FZN_NODE_ROOTS_OK) {
				fprintf(stderr, "fuzznetd: --new-root: %s\n",
				        fzn_node_roots_err_str(rerr));
				return 1;
			}
		}
		print_hex(stdout, mine.key, FZN_PUBKEY_LEN);
		printf("\n");
		return 0;
	}

	/* THE DEVICE'S HALF OF `--pair`: accept a node's card and keep the
	 * pairing. It prints the node's root, which is the name the pairing is
	 * filed under and what the device asks the node by. sec 377. */
	if (accept_text) {
		uint8_t card[FZN_PROVISION_MAX_LEN];
		size_t card_len = 0;
		fzn_node_pairing_t paired;
		fzn_node_pair_err_t perr;

		if (!booted) {
			fprintf(stderr, "fuzznetd: --accept needs --fuzznet-dir, and no --identity\n");
			return 2;
		}
		if (fzn_provision_from_text(accept_text, card, sizeof(card), &card_len)
		    != FZN_PROVISION_OK) {
			fprintf(stderr, "fuzznetd: --accept is not a card\n");
			return 2;
		}
		perr = join ? fzn_node_join(&identity, card, card_len, wall_clock(), store_ops,
		                            &trust, &paired)
		            : fzn_node_pairing_accept(&identity, card, card_len, wall_clock(),
		                                      store_ops, &paired);
		if (perr != FZN_NODE_PAIR_OK) {
			fprintf(stderr, "fuzznetd: not accepted: %s\n", fzn_node_pair_err_str(perr));
			return 1;
		}
		if (join) {
			fprintf(stderr, "fuzznetd: joined the estate rooted at ");
			print_hex(stderr, fzn_trust_root(&trust), FZN_PUBKEY_LEN);
			fprintf(stderr, " through ");
		} else {
			fprintf(stderr, "fuzznetd: paired to ");
		}
		print_hex(stderr, paired.node, FZN_PUBKEY_LEN);
		fprintf(stderr, "\n");
		print_hex(stdout, paired.node, FZN_PUBKEY_LEN);
		printf("\n");
		fzn_wipe(&paired, sizeof(paired));
		return 0;
	}

	/* THE DEVICE ASKING THE NODE IT IS PAIRED TO, which is the other half of
	 * the remote hop and what a device could not do from a command line.
	 * The line is fuzznet's grammar (sec 381); the credentials are the
	 * stored pairing, looked up by the node's root; the address is given,
	 * since a pairing carries none. Prints the reply line and exits 0 when
	 * it is `ok`. */
	if (ask_line) {
		static fzn_partial_t slots[1];
		static uint8_t slot_buf[1][FZN_NODE_REPLY_MAX * 4u];
		static uint8_t answer[FZN_NODE_REPLY_MAX * 4u];
		uint8_t node_root[FZN_PUBKEY_LEN];
		fzn_node_pairing_t pairing;
		fzn_reasm_t table;
		fzn_caller_t caller;
		fzn_caller_err_t cerr;
		size_t answer_len = 0;
		uint32_t msg = 0;
		int fd = -1, rc;

		if (!booted || !cli.has_node || !to_host || to_port < 0 || to_port > 65535) {
			fprintf(stderr, "fuzznetd: --ask needs --fuzznet-dir, --node and --to\n");
			return 2;
		}
		memcpy(node_root, cli.node, FZN_PUBKEY_LEN);
		if (fzn_node_pairing_load(store_ops, node_root, &pairing) != FZN_PERSIST_OK) {
			fprintf(stderr, "fuzznetd: not paired to that node\n");
			return 1;
		}
		memset(&caller, 0, sizeof(caller));
		if (fzn_udp_bind(family, NULL, 0, &fd) != FZN_UDP_OK
		    || fzn_udp_resolve(family, to_host, (uint16_t)to_port, &caller.node)
		               != FZN_UDP_OK
		    || fzn_reasm_slot_init(&slots[0], slot_buf[0], sizeof(slot_buf[0]))
		               != FZN_REASM_OK
		    || fzn_reasm_init(&table, slots, 1, 1u, 60u) != FZN_REASM_OK) {
			fprintf(stderr, "fuzznetd: could not set up the request\n");
			fzn_wipe(&pairing, sizeof(pairing));
			if (fd >= 0)
				fzn_udp_close(fd);
			return 1;
		}
		fzn_node_pairing_caller(&pairing, identity.pubkey, &caller);
		fzn_wipe(&pairing, sizeof(pairing));
		caller.fd = fd;
		caller.hash = &hash_ops;
		caller.aead = &aead_ops;
		caller.rng = &rng_ops;
		caller.reasm = &table;
		caller.hops = 1u;
		/* The expiry sits inside the node's horizon: FZND_MAX_AHEAD is the
		 * lifetime plus the skew this daemon tolerates, and a request
		 * expiring later than that is refused as from the future. */
		cerr = fzn_caller_send(&caller, (const uint8_t *)ask_line, strlen(ask_line),
		                       wall_clock() + (FZND_MAX_AHEAD / 2u), &msg);
		if (cerr == FZN_CALLER_OK)
			cerr = fzn_caller_recv(&caller, msg, answer, sizeof(answer), &answer_len,
			                       3000u);
		fzn_wipe(&caller, sizeof(caller));
		fzn_udp_close(fd);
		if (cerr != FZN_CALLER_OK) {
			fprintf(stderr, "fuzznetd: no answer: %s\n", fzn_caller_err_str(cerr));
			return 1;
		}
		rc = fzn_reply_ok(fzn_reply_of(answer, answer_len, NULL, NULL)) ? 0 : 1;
		if (answer_len && answer[answer_len - 1u] == '\n')
			answer_len--;
		printf("%.*s\n", (int)answer_len, (const char *)answer);
		return rc;
	}

	if (pair_hex) {
		if (!booted) {
			fprintf(stderr, "fuzznetd: --pair needs --fuzznet-dir, and no --identity: "
			                "pairing mints, so the node must hold its key\n");
			return 2;
		}
		/* THROUGH THIS NODE'S ROOT KEY, sec 411, when it holds one that
		 * stands and is not its estate's root by identity: the key's grant
		 * to the identity, and the adds that make the key a root, travel on
		 * the card. Otherwise the chain it joined with, as before. */
		if (memcmp(state.config.root, identity.pubkey, FZN_PUBKEY_LEN) != 0) {
			static fzn_node_roots_t pair_roots;
			static uint8_t grant[FZN_HOP_LEN];
			static uint8_t proof[FZN_PROVISION_PROOF_MAX][FZN_PROVISION_PROOF_ITEM_LEN];
			static fzn_node_authority_t through_key;
			size_t nroots = 0;
			fzn_node_roots_err_t rerr;

			if (fzn_node_roots_init(&pair_roots, state.config.root, &sign_ops, &hash_ops)
			            != FZN_NODE_ROOTS_OK
			    || fzn_node_roots_load(&pair_roots, store_ops, &nroots) != FZN_NODE_ROOTS_OK
			    || fzn_node_roots_key_load(&pair_roots, store_ops, &root_seat,
			                               &root_sign_ops) != FZN_NODE_ROOTS_OK) {
				fprintf(stderr, "fuzznetd: --pair could not restore the roots in %s\n",
				        store_dir);
				return 1;
			}
			/* AS A ROOT BY IDENTITY FIRST, sec 419: one hop and the proof,
			 * a shorter card than a root key's two hops. */
			rerr = fzn_node_roots_identity_root(&pair_roots, store_ops, identity.pubkey,
			                                    proof, &through_key);
			if (rerr == FZN_NODE_ROOTS_NOT_ROOT)
				rerr = fzn_node_roots_self_grant(&pair_roots, store_ops, identity.pubkey,
				                                 &state.config.remote_capability, grant,
				                                 proof, &through_key);
			if (rerr == FZN_NODE_ROOTS_OK) {
				my_authority = &through_key;
			} else if (rerr != FZN_NODE_ROOTS_NOT_ROOT) {
				fprintf(stderr, "fuzznetd: not paired through the root key: %s\n",
				        fzn_node_roots_err_str(rerr));
				return 1;
			}
		}
		return pair_device(&identity, &state.config, my_authority, delegable, store_ops,
		                   pair_hex, wall_clock());
	}
	/* REFUSED RATHER THAN BOUND. A remote hop with no identity seals its
	 * replies as from the zero key and verifies chains against a zero
	 * root, which no real peer can satisfy -- so it would bind, look
	 * healthy, and drop every frame. That is the exact failure this wiring
	 * closes, and starting anyway would reintroduce it with more moving
	 * parts. */
	if (udp_port >= 0 && !identity_hex && !booted) {
		fprintf(stderr, "fuzznetd: --udp-port needs --identity or --fuzznet-dir\n");
		return 2;
	}

	/* The socket mode lets a client connect; the authoritative gate is the
	 * in-process peer-credential check, which the kernel fills and no
	 * client can forge. A deployment may tighten ownership and mode on
	 * top of that. */
	if (sock_path && fzn_socket_listen(sock_path, 0777u, 16, &lfd) != FZN_SOCKET_OK) {
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
		static fzn_node_admin_t admin;
		static fzn_revocation_t revoked_entries[FZN_NODE_REVOCATIONS_MAX];
		static fzn_revocation_store_t revoked;
		static fzn_node_roots_t estate_roots;
		/* ADMINS AND THEIR CONFIRMATIONS, sec 415: the admin table at the
		 * store's ceiling, and a confirmation table set before anything
		 * is loaded, since an admin admitted before it could never be
		 * confirmed. */
		static fzn_revocation_admin_t admins[32];
		static fzn_revocation_confirm_t confirms[FZN_NODE_REVOCATIONS_MAX];
		size_t loaded = 0, nrevoked = 0, nroots = 0;

		/* THE REVOCATIONS THIS NODE ISSUED, admitted again before any
		 * peer is served -- a node that served first and remembered
		 * second would answer a revoked device in the gap. A record that
		 * will not admit is fatal for the same reason. sec 380. */
		/* THE ESTATE'S ROOTS FIRST, sec 407: the set grown from the pinned
		 * root, attached before any revocation is re-admitted, so one by
		 * a member root admits and a removed root's after its cut does
		 * not count. With nothing stored, the pinned root alone. */
		if (fzn_revocation_store_init(&revoked, revoked_entries,
		                              FZN_NODE_REVOCATIONS_MAX) != FZN_CHAIN_OK
		    || fzn_revocation_store_set_quorum(&revoked, (size_t)quorum,
		                                       state.config.has_admin
		                                               ? &state.config.admin_capability
		                                               : NULL,
		                                       state.config.has_admin ? admins : NULL,
		                                       state.config.has_admin ? 32u : 0u)
		               != FZN_CHAIN_OK
		    || (state.config.has_admin
		        && fzn_revocation_store_set_confirmations(&revoked, confirms,
		                                                  FZN_NODE_REVOCATIONS_MAX, &hash_ops)
		                   != FZN_CHAIN_OK)
		    || fzn_node_roots_init(&estate_roots, state.config.root, &sign_ops, &hash_ops)
		               != FZN_NODE_ROOTS_OK
		    || fzn_node_roots_load(&estate_roots, store_ops, &nroots) != FZN_NODE_ROOTS_OK
		    || fzn_node_roots_key_load(&estate_roots, store_ops, &root_seat, &root_sign_ops)
		               != FZN_NODE_ROOTS_OK
		    || fzn_node_roots_attach(&estate_roots, &revoked) != FZN_NODE_ROOTS_OK
		    || fzn_node_admin_chain_load(store_ops, &own_admin) < 0
		    || fzn_node_revocations_load(store_ops, &revoked, state.config.root,
		                                 my_authority, fzn_node_admin_chain_view(&own_admin),
		                                 &sign_ops, &hash_ops, &nrevoked)
		               != FZN_PERSIST_OK) {
			fprintf(stderr, "fuzznetd: could not restore the revocations in %s\n",
			        store_dir);
			fzn_socket_close(lfd, sock_path);
			if (ufd >= 0)
				fzn_udp_close(ufd);
			return 1;
		}
		/* THE ESTATE'S k, when a root has set one; `--quorum` until then.
		 * sec 418. */
		(void)fzn_revocation_store_set_k(&revoked,
		                                 fzn_node_roots_quorum(&estate_roots, (uint8_t)quorum));
		if (revoked.quorum != (size_t)quorum)
			fprintf(stderr, "fuzznetd: the estate's k is %zu, set by a root\n",
			        revoked.quorum);
		state.config.revocations = &revoked;
		running = &revoked;
		running_roots = &estate_roots;
		if (nrevoked)
			fprintf(stderr, "fuzznetd: %zu revocation(s) from %s\n", nrevoked,
			        store_dir);
		if (nroots)
			fprintf(stderr, "fuzznetd: %zu root record(s) from %s\n", nroots,
			        store_dir);
		fzn_persist_err_t err;

		err = fzn_node_peers_load(store_ops, peers, FZN_NODE_PEERS_MAX, &loaded);
		if (err != FZN_PERSIST_OK) {
			fprintf(stderr, "fuzznetd: could not load peers from %s (%d)\n",
			        bulk_dir, (int)err);
			fzn_socket_close(lfd, sock_path);
			if (ufd >= 0)
				fzn_udp_close(ufd);
			return 1;
		}
		state.peers = peers;
		state.peer_count = loaded;
		fprintf(stderr, "fuzznetd: %zu peer(s) from %s\n", loaded, bulk_dir);

		/* FUZZNET'S OWN VERBS, answered by the node about itself, when it
		 * holds what they need: its key, a store, and the capability it
		 * grants. `add peer` then pairs a device into the RUNNING node,
		 * which `--pair` could only do for its next start. sec 378. */
		if (booted && has_capability) {
			admin.state = &state;
			admin.peers = peers;
			admin.peers_cap = FZN_NODE_PEERS_MAX;
			admin.id = &identity;
			admin.store = store_ops;
			admin.card_lifetime = FZND_CARD_LIFETIME;
			running_admin = &admin;
			admin.revocations = &revoked;
			admin.authority = my_authority;
			admin.roots = &estate_roots;
			admin.admin_chain = &own_admin;
			state.on_local = fzn_node_admin_handle;
			state.on_local_ctx = &admin;
			state.on_remote = fzn_node_admin_remote;
			state.on_remote_ctx = &admin;
#ifdef FZN_SPOOL_FILE_ON
			{
				char shelf_dir[FZN_NODE_SHELF_DIR_MAX];
				int n = snprintf(shelf_dir, sizeof(shelf_dir), "%s/text", bulk_dir);

				if (n > 0 && (size_t)n < sizeof(shelf_dir)
				    && fzn_node_shelf_init(&shelf, shelf_dir, &hash_ops, &aead_ops,
				                           &rng_ops)
				               == FZN_NODE_SHELF_OK) {
					shelf_on = 1;
					admin.text_local = fzn_node_shelf_local;
					admin.text_remote = fzn_node_shelf_remote;
					admin.text_ctx = &shelf;
				} else {
					fprintf(stderr, "fuzznetd: no shelf for texts under %s\n",
					        bulk_dir);
				}
			}
#endif
			/* NOTES, sec 431: admitted from this node and the nodes it
			 * pulls from, which are the nodes they will sync with. */
			state.reply = node_reply;
			state.reply_cap = sizeof(node_reply);
			{
				/* ADMITTED: the nodes it pulls from, as the base; the
				 * nodes paired to it join from the live table, sec 451.
				 * sec 433. */
				static uint8_t writers[FZND_PULL_TARGETS_MAX + FZN_NODE_PEERS_MAX]
				                      [FZN_PUBKEY_LEN];
				uint8_t pull_keys[FZND_PULL_TARGETS_MAX][FZN_PUBKEY_LEN];
				size_t w, nw = 0;

				for (w = 0; w < npulls; w++) {
					memcpy(pull_keys[w],
					       pulls[w].is_root_at ? state.config.root : pulls[w].node,
					       FZN_PUBKEY_LEN);
					memcpy(writers[nw++], pull_keys[w], FZN_PUBKEY_LEN);
				}
				/* THE PAIRED PEERS ARE NOT IN THE BASE, sec 451:
				 * `admit_writers` adds them from the live table, so
				 * one un-paired on the socket stops being a writer. */
				if (fzn_node_notes_init(&node_notes, store_ops, &hash_ops, &sign_ops,
				                        &rng_ops, identity.pubkey,
				                        (const uint8_t (*)[FZN_PUBKEY_LEN])writers, nw,
				                        (const uint8_t (*)[FZN_PUBKEY_LEN])pull_keys, npulls,
				                        wall_ms)
				    == FZN_NOTES_OK) {
					admit_writers(&state, running_roots);
#ifdef FZN_SPOOL_FILE_ON
					if (shelf_on) {
						node_notes.seal = shelf_seal;
						node_notes.open = shelf_open;
						node_notes.text_ctx = &shelf;
						node_notes.collect = shelf_collect;
						node_notes.place = shelf_place;
						node_notes.span = shelf_span;
						admin.text_shared = shared_text;
						admin.text_shared_ctx = &shelf;
					}
#endif
					admin.notes_local = fzn_node_notes_local;
					admin.notes_remote = fzn_node_notes_remote;
					admin.notes_ctx = &node_notes;
					notes_on = 1;
					/* SHARING, sec 436: a contact's chain for the share
					 * capability verifies against this node's own key. */
					if (has_capability
					    && fzn_notes_share_capability(cli.service, cli.product, &hash_ops,
					                                  &state.config.share_capability)
					               == FZN_NOTES_OK) {
						memcpy(state.config.share_root, identity.pubkey, FZN_PUBKEY_LEN);
						state.config.has_share = 1;
					}
				} else {
					fprintf(stderr, "fuzznetd: no notes: the store cannot list\n");
				}
			}
		}
	}

	/* A MEMBER PULLS WHAT ITS ROOT REVOKED. The pairing it joined with is
	 * what makes it the root's caller, and the address is given because a
	 * pairing carries none (sec 377). The first pull runs before the first
	 * frame is served; a root that does not answer is reported and not
	 * fatal, since what was pulled before is already loaded from slot 10
	 * and refusing to serve would cut off every device the root did not
	 * revoke. sec 384. */
	{
		static fzn_partial_t request_slots[FZND_REQUEST_SLOTS];
		static uint8_t request_bufs[FZND_REQUEST_SLOTS][FZND_REQUEST_MAX];
		static fzn_reasm_t requests;
		size_t r;
		int ok = 1;

		for (r = 0; r < FZND_REQUEST_SLOTS; r++)
			ok = ok
			     && fzn_reasm_slot_init(&request_slots[r], request_bufs[r],
			                            sizeof(request_bufs[r]))
			                == FZN_REASM_OK;
		if (ok
		    && fzn_reasm_init(&requests, request_slots, FZND_REQUEST_SLOTS, 1u, 60u)
		               == FZN_REASM_OK)
			state.reassembly = &requests;
		else
			fprintf(stderr, "fuzznetd: no request reassembly; requests past one frame "
			                "are dropped\n");
	}

	/* A NODE KEEPING NOTES LOOPS TOO, with no estate peer to pull: a
	 * share it accepts is pulled on the same round. sec 437. And so does
	 * one reassembling requests, since the loop is what expires a request
	 * whose sender stopped part way. sec 447. */
	if (npulls || notes_on || state.reassembly) {
		uint64_t next_pull = 0, last_fresh_round = 0;
		size_t t;

		/* A PULL NEEDS A STORE TO KEEP WHAT IT LEARNS, and `--root-at`
		 * needs a node that joined through the root: a node that joined
		 * through a member holds its pairing to that member, and names
		 * it with `--pull-from` instead. */
		if (npulls && (!running || !store_ops)) {
			fprintf(stderr, "fuzznetd: pulling votes needs --fuzznet-dir\n");
			fzn_socket_close(lfd, sock_path);
			if (ufd >= 0)
				fzn_udp_close(ufd);
			return 2;
		}
		for (t = 0; t < npulls; t++) {
			struct pull_target *pt = &pulls[t];
			int fd = -1;

			pt->fd = -1;
			if (pt->is_root_at) {
				if (!my_authority
				    || memcmp(estate.node, state.config.root, FZN_PUBKEY_LEN) != 0) {
					fprintf(stderr, "fuzznetd: --root-at needs a node that joined an "
					                "estate through its root; name a member with "
					                "--pull-from\n");
					fzn_socket_close(lfd, sock_path);
					if (ufd >= 0)
						fzn_udp_close(ufd);
					return 2;
				}
				pt->pairing = estate;
			} else if (fzn_node_pairing_load(store_ops, pt->node, &pt->pairing)
			           != FZN_PERSIST_OK) {
				fprintf(stderr, "fuzznetd: --pull-from %s: this node holds no pairing to "
				                "that node\n", pt->host);
				fzn_socket_close(lfd, sock_path);
				if (ufd >= 0)
					fzn_udp_close(ufd);
				return 2;
			}
			if (pt->port < 0 || pt->port > 65535
			    || fzn_udp_bind(family, NULL, 0, &fd) != FZN_UDP_OK
			    || fzn_udp_resolve(family, pt->host, (uint16_t)pt->port, &pt->caller.node)
			               != FZN_UDP_OK
			    || fzn_reasm_slot_init(&pt->slot, pt->slot_buf, sizeof(pt->slot_buf))
			               != FZN_REASM_OK
			    || fzn_reasm_init(&pt->table, &pt->slot, 1, 1u, 60u) != FZN_REASM_OK) {
				fprintf(stderr, "fuzznetd: could not reach for the peer at %s\n",
				        pt->host);
				fzn_socket_close(lfd, sock_path);
				if (fd >= 0)
					fzn_udp_close(fd);
				if (ufd >= 0)
					fzn_udp_close(ufd);
				return 1;
			}
			pt->fd = fd;
			fzn_node_pairing_caller(&pt->pairing, identity.pubkey, &pt->caller);
			pt->caller.fd = fd;
			pt->caller.hash = &hash_ops;
			pt->caller.aead = &aead_ops;
			pt->caller.rng = &rng_ops;
			pt->caller.reasm = &pt->table;
			pt->caller.hops = 1u;
		}

		load_received(family, identity.pubkey, &hash_ops, &aead_ops, &rng_ops);
		fprintf(stderr, "fuzznetd: serving%s%s%s, pulling from %zu peer(s) every %us\n",
		        sock_path ? " on " : "", sock_path ? sock_path : "",
		        (udp_port >= 0) ? " udp" : "", npulls, FZND_PULL_EVERY);
		for (;;) {
			uint64_t now = wall_clock();

			admit_writers(&state, running_roots);
#ifdef FZN_SPOOL_FILE_ON
			scrub_shelf(now);
#endif

			/* EVERY PEER EACH ROUND, one after another. A peer that does
			 * not answer is reported and the next is asked: what one
			 * peer cannot say another may, which is the point of asking
			 * more than one. sec 401. */
			if (now >= next_pull) {
				for (t = 0; t < npulls; t++) {
					size_t learned = 0, refused = 0;
					fzn_node_pull_err_t perr;

					/* ROOTS BEFORE VOTES, sec 408: a vote cast by a root
					 * this node has not yet heard of admits only once it
					 * has. */
					perr = fzn_node_roots_pull(running_roots, store_ops,
					                           &pulls[t].caller, now, &learned,
					                           &refused);
					if (perr != FZN_NODE_PULL_OK)
						fprintf(stderr, "fuzznetd: roots from %s: %s\n",
						        pulls[t].host, fzn_node_pull_err_str(perr));
					else if (learned || refused)
						fprintf(stderr,
						        "fuzznetd: %zu root record(s) from %s, %zu refused\n",
						        learned, pulls[t].host, refused);
					/* THE ESTATE'S k MAY HAVE ARRIVED WITH THEM. sec 418. */
					if (running)
						(void)fzn_revocation_store_set_k(
						        running,
						        fzn_node_roots_quorum(running_roots, (uint8_t)quorum));
					learned = 0;
					refused = 0;
					perr = fzn_node_votes_pull(&pulls[t].caller, state.config.root,
					                           &sign_ops, &hash_ops, now, running,
					                           store_ops, &learned, &refused);
					if (perr != FZN_NODE_PULL_OK)
						fprintf(stderr, "fuzznetd: votes from %s: %s\n",
						        pulls[t].host, fzn_node_pull_err_str(perr));
					else if (learned || refused)
						fprintf(stderr,
						        "fuzznetd: %zu vote(s) from %s, %zu refused\n",
						        learned, pulls[t].host, refused);
				}
				/* NOTES, then TEXTS, secs 432 and 424: a note's text is
				 * fetched once the note naming it has arrived. */
				pull_notes(pulls, npulls, now, &state, running, running_roots);
				pull_received(now);
#ifdef FZN_SPOOL_FILE_ON
				fetch_texts(pulls, npulls, now);
				collect_texts();
#endif
				next_pull = wall_clock() + FZND_PULL_EVERY;
			}
#ifdef FZN_SPOOL_FILE_ON
			/* A TEXT JUST ASKED FOR is fetched now, not at the next
			 * round. sec 424. */
			if (shelf.fresh)
				fetch_texts(pulls, npulls, now);
#endif
			/* A TRASH JUST EMPTIED is carried to the pull peers now, not
			 * at the next round. sec 433. */
			/* A SHARE JUST ACCEPTED is pulled now. sec 437. */
			if (running_admin && running_admin->received_fresh) {
				running_admin->received_fresh = 0;
				load_received(family, identity.pubkey, &hash_ops, &aead_ops, &rng_ops);
				pull_received(now);
			}
			/* A WRITE HERE GOES OUT NOW, sec 449, a round at most every
			 * two seconds, so a burst of edits is one round rather than
			 * one each. */
			if (notes_on && node_notes.fresh && now >= last_fresh_round + 2u) {
				node_notes.fresh = 0;
				last_fresh_round = now;
				pull_notes(pulls, npulls, now, &state, running, running_roots);
			}
			/* A REQUEST NEVER FINISHED gives its slot back. */
			if (state.reassembly)
				(void)fzn_reasm_expire(state.reassembly, wall_clock());
			(void)fzn_node_run_once(&state, 1000);
		}
	}

	fprintf(stderr, "fuzznetd: serving%s%s%s\n", sock_path ? " on " : "",
	        sock_path ? sock_path : "", (udp_port >= 0) ? " udp" : "");
	fzn_node_run(&state);	/* until the process is signalled */

	/* Unreached in normal operation; named so the sockets read as closed
	 * rather than leaked. */
	fzn_socket_close(lfd, sock_path);
	if (ufd >= 0)
		fzn_udp_close(ufd);
	return 0;
}
