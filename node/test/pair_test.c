/* node/pair.h under real Monocypher: a node pairs a device, and the pairing
 * holds on BOTH sides. sec 376.
 *
 * WHAT IS ASSERTED IS THE RELATIONSHIP, not the pieces. `provision_test`
 * already shows each step works; what this adds is that the steps as composed
 * leave a device holding keys that ARE the node's receive keys for it, a card
 * whose root IS the node, and a grant the NODE'S OWN authorisation check
 * accepts for the capability its remote hop requires -- and refuses for
 * another, which is the control that makes the acceptance mean something.
 * `fuzznetd` required an all-zero capability for weeks with every piece
 * passing its own test; this is the test that would have seen it.
 *
 * Two nodes, each with an identity from `node/identity.h` over an in-memory
 * store, so the fixture is built the way a real node builds itself.
 */

#include "../pair.h"
#include "../../provision/provision.h"
#include "../identity.h"
#include "../node.h"
#include "../peer_persist.h"
#include "../../chain/service.h"
#include "../../chain/sign_monocypher.h"
#include "../../session/agree_monocypher.h"
#include "../../session/hash_monocypher.h"
#include "../../session/random_system.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL pair_test.c:%d: %s\n", line, what);
	}
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

/* ---- an in-memory store that can list, since loading peers needs it -- */

#define SLOTS 8
#define ENTRIES 4

struct mem_entry {
	int used;
	fzn_persist_slot_t slot;
	int has_subject;
	uint8_t subject[FZN_PUBKEY_LEN];
	uint8_t bytes[FZN_NODE_PEER_BLOB_MAX];
	size_t len;
};

struct mem_store {
	struct mem_entry e[SLOTS * ENTRIES];
	unsigned saves;
	int refuse_saves;
};

static struct mem_entry *find(struct mem_store *m, fzn_persist_slot_t slot,
                              const uint8_t *subject, int make)
{
	size_t i;
	struct mem_entry *free_one = NULL;

	for (i = 0; i < sizeof(m->e) / sizeof(m->e[0]); i++) {
		struct mem_entry *x = &m->e[i];

		if (!x->used) {
			if (!free_one)
				free_one = x;
			continue;
		}
		if (x->slot == slot && x->has_subject == (subject != NULL)
		    && (!subject || memcmp(x->subject, subject, FZN_PUBKEY_LEN) == 0))
			return x;
	}
	if (!make || !free_one)
		return NULL;
	memset(free_one, 0, sizeof(*free_one));
	free_one->used = 1;
	free_one->slot = slot;
	free_one->has_subject = subject != NULL;
	if (subject)
		memcpy(free_one->subject, subject, FZN_PUBKEY_LEN);
	return free_one;
}

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	struct mem_entry *x = find((struct mem_store *)ctx, slot, subject, 0);

	if (!x || x->len > cap)
		return 0;
	memcpy(out, x->bytes, x->len);
	*len = x->len;
	return 1;
}

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	struct mem_store *m = (struct mem_store *)ctx;
	struct mem_entry *x;

	if (m->refuse_saves || len > sizeof(x->bytes))
		return 0;
	x = find(m, slot, subject, 1);
	if (!x)
		return 0;
	memcpy(x->bytes, bytes, len);
	x->len = len;
	m->saves++;
	return 1;
}

static int mem_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max,
                    size_t *count)
{
	struct mem_store *m = (struct mem_store *)ctx;
	size_t i, n = 0;

	for (i = 0; i < sizeof(m->e) / sizeof(m->e[0]); i++) {
		if (!m->e[i].used || m->e[i].slot != slot || !m->e[i].has_subject)
			continue;
		if (n >= max)
			return 0;
		memcpy(out + (n * FZN_PUBKEY_LEN), m->e[i].subject, FZN_PUBKEY_LEN);
		n++;
	}
	*count = n;
	return 1;
}

static unsigned peers_held(struct mem_store *m)
{
	size_t i;
	unsigned n = 0;

	for (i = 0; i < sizeof(m->e) / sizeof(m->e[0]); i++)
		if (m->e[i].used && m->e[i].slot == FZN_PERSIST_NODE_PEER)
			n++;
	return n;
}

/* ---- one node: its store, its signer, its identity -------------------- */

struct node {
	struct mem_store store;
	fzn_persist_ops_t ops;
	fzn_sign_monocypher_t signer;
	fzn_sign_ops_t sign;
	fzn_sign_seat_t seat;
	fzn_agree_secret_t agree_secret;
	fzn_trust_t trust;
	fzn_node_identity_t id;
};

static fzn_hash_ops_t hash_ops;
static fzn_agree_ops_t agree_ops;
static fzn_random_ops_t rng_ops;

static int node_up(struct node *n)
{
	fzn_node_identity_env_t env;

	memset(n, 0, sizeof(*n));
	n->ops.load = mem_load;
	n->ops.save = mem_save;
	n->ops.list = mem_list;
	n->ops.ctx = &n->store;
	fzn_sign_monocypher_init(&n->sign, &n->signer);
	fzn_sign_monocypher_seat_init(&n->seat, &n->signer);
	fzn_trust_init(&n->trust);
	env.store = &n->ops;
	env.rng = &rng_ops;
	env.seat = &n->seat;
	env.sign = &n->sign;
	env.hash = &hash_ops;
	env.agree = &agree_ops;
	env.log = NULL;
	return fzn_node_identity_create(&env, 1000u, &n->agree_secret, &n->trust, &n->id)
	       == FZN_NODE_IDENTITY_OK;
}

static fzn_authz_verdict_t node_decides(const struct node *n, const fzn_cap_id_t *required,
                                        const fzn_node_peer_t *peer, uint64_t now)
{
	fzn_node_config_t config;
	fzn_chain_hop_t hops[FZN_CHAIN_MAX_HOPS];
	size_t i;

	memset(&config, 0, sizeof(config));
	config.serves_remote = 1;
	config.remote_capability = *required;
	memcpy(config.root, n->id.pubkey, FZN_PUBKEY_LEN);
	for (i = 0; i < peer->hop_count; i++)
		if (fzn_hop_open(peer->hop_bytes[i], FZN_HOP_LEN, &hops[i]) != FZN_CHAIN_OK)
			return FZN_AUTHZ_DENIED;
	return fzn_node_decide(&config, FZN_ORIGIN_REMOTE, hops, peer->hop_count, now, &n->sign,
	                       NULL, NULL);
}

int main(void)
{
	static struct node node, device, stranger;
	fzn_prekey_record_t device_record;
	fzn_cap_id_t cap, other;
	uint8_t card[FZN_PROVISION_LEN_TOTAL];
	size_t card_len = 0;
	uint8_t send_key[FZN_AEAD_KEY_LEN], send_ckey[FZN_COMMITMENT_KEY_LEN];
	uint8_t root[FZN_PUBKEY_LEN];
	fzn_chain_hop_t device_hop;
	static fzn_node_peer_t peers[2];
	size_t loaded = 0;

	fzn_hash_monocypher_init(&hash_ops);
	fzn_agree_monocypher_init(&agree_ops);
	fzn_random_system_init(&rng_ops);

	CHECK(node_up(&node) && node_up(&device) && node_up(&stranger),
	      "fixture: three nodes would not come up");
	CHECK(fzn_prekey_open(device.id.prekey_record, FZN_PREKEY_LEN_TOTAL, &device_record)
	              == FZN_PREKEY_OK,
	      "fixture: the device's prekey record does not open");
	CHECK(fzn_service_capability(7u, 3u, NULL, 0, &hash_ops, &cap) == FZN_CHAIN_OK
	              && fzn_service_capability(7u, 4u, NULL, 0, &hash_ops, &other) == FZN_CHAIN_OK,
	      "fixture: capabilities would not derive");

	/* ---- THE PAIRING. */
	node.store.saves = 0;
	CHECK(fzn_node_pair(&node.id, node.id.pubkey, &cap, &node.ops, device_record, 2000u,
	                    2000u + 86400u, card, sizeof(card), &card_len) == FZN_NODE_PAIR_OK,
	      "a node would not pair a device");
	CHECK(card_len == FZN_PROVISION_LEN_TOTAL, "the card is not a whole card");

	/* ---- THE DEVICE'S SIDE: it accepts, and the root it learns is the node. */
	CHECK(fzn_node_accept_card(&device.id, card, card_len, 2100u, send_key, send_ckey, root,
	                           &device_hop) == FZN_NODE_PROVISION_OK,
	      "the device refused the node's card");
	CHECK(memcmp(root, node.id.pubkey, FZN_PUBKEY_LEN) == 0,
	      "the card names a root that is not the node");

	/* ---- THE NODE'S SIDE, read back through the loader the daemon uses. */
	CHECK(fzn_node_peers_load(&node.ops, peers, 2, &loaded) == FZN_PERSIST_OK && loaded == 1u,
	      "the node does not hold exactly one peer after pairing one device");
	CHECK(memcmp(peers[0].sender, device.id.pubkey, FZN_PUBKEY_LEN) == 0,
	      "the saved peer is not the device");
	CHECK(memcmp(peers[0].recv_key, send_key, FZN_AEAD_KEY_LEN) == 0
	              && memcmp(peers[0].recv_ckey, send_ckey, FZN_COMMITMENT_KEY_LEN) == 0,
	      "the device's send keys are not the node's receive keys for it, so nothing "
	      "the device seals will open");

	/* ---- AND THE NODE'S OWN CHECK GRANTS IT, for this capability only. */
	CHECK(node_decides(&node, &cap, &peers[0], 3000u) == FZN_AUTHZ_GRANTED_BY_CHAIN,
	      "the node's own authorisation check refuses the device it just paired");
	CHECK(node_decides(&node, &other, &peers[0], 3000u) == FZN_AUTHZ_DENIED,
	      "the control: the paired device was granted a capability it was not given");

	/* ---- A NODE THAT IS NOT ITS OWN ROOT PAIRS NOTHING, and writes nothing. */
	stranger.store.saves = 0;
	CHECK(fzn_node_pair(&stranger.id, node.id.pubkey, &cap, &stranger.ops, device_record,
	                    2000u, 0u, card, sizeof(card), &card_len) == FZN_NODE_PAIR_NOT_ROOT,
	      "a node whose root is another key paired a device");
	CHECK(stranger.store.saves == 0u && peers_held(&stranger.store) == 0u && card_len == 0u,
	      "a refused pairing saved a peer or left a card");

	/* ---- A PREKEY THAT DOES NOT VERIFY PAIRS NOTHING. */
	{
		uint8_t forged[FZN_PREKEY_LEN_TOTAL];
		fzn_prekey_record_t forged_record;

		memcpy(forged, device.id.prekey_record, sizeof(forged));
		forged[FZN_PREKEY_LEN_TOTAL - 1u] ^= 0x01u;
		CHECK(fzn_prekey_open(forged, sizeof(forged), &forged_record) == FZN_PREKEY_OK,
		      "fixture: the forged record no longer opens, so the case is about shape");
		stranger.store.saves = 0;
		CHECK(fzn_node_pair(&stranger.id, stranger.id.pubkey, &cap, &stranger.ops,
		                    forged_record, 2000u, 0u, card, sizeof(card), &card_len)
		              == FZN_NODE_PAIR_DEVICE,
		      "a device whose prekey signature is broken was paired");
		CHECK(stranger.store.saves == 0u && card_len == 0u,
		      "a refused device was saved or given a card");
	}

	/* ---- A STORE THAT REFUSES GETS NO CARD: no card for a device the node
	 * does not hold. */
	stranger.store.refuse_saves = 1;
	CHECK(fzn_node_pair(&stranger.id, stranger.id.pubkey, &cap, &stranger.ops, device_record,
	                    2000u, 0u, card, sizeof(card), &card_len) == FZN_NODE_PAIR_STORE,
	      "a pairing the store refused was reported as anything but the store's");
	CHECK(card_len == 0u, "a card was made for a device the node could not save");

	CHECK(fzn_node_pair(NULL, node.id.pubkey, &cap, &node.ops, device_record, 1u, 0u, card,
	                    sizeof(card), &card_len) == FZN_NODE_PAIR_MALFORMED,
	      "a null identity was accepted");
	CHECK(strcmp(fzn_node_pair_err_str(FZN_NODE_PAIR_STORE),
	             fzn_node_pair_err_str(FZN_NODE_PAIR_CARD)) != 0,
	      "two refusals share a sentence");

	fzn_sign_monocypher_wipe(&node.signer);
	fzn_sign_monocypher_wipe(&device.signer);
	fzn_sign_monocypher_wipe(&stranger.signer);
	printf("pair_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
