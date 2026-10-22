/*
 * A fuzz harness for the estate's members, `node/members.h`: sec 689's
 * estate journey. A node learns who else is in its estate by asking a
 * member for its members, each with the capability chain it holds.
 *
 * WHY THIS ONE. The MEMBERS page is the asked member's to write, every
 * byte, and what it admits are keys the estate then takes notes and
 * settings from. The claim is that only a key whose chain verifies against
 * this node's own root, for the remote capability, is admitted -- so a
 * member that lies can name only keys the root really granted.
 *
 * THE PEER LIES BY MUTATION. The answering member is honest; each page it
 * gives is bent with even odds -- bits flipped, cut short, grown, a count or
 * a length at its extremes, a slice repeated or two bytes swapped.
 *
 * THE PROPERTIES:
 *   1. ONLY MEMBERS. Every key admitted is one the root granted the remote
 *      capability: never the contact (share capability), never the peer
 *      whose chain starts at another root, never a key nobody granted.
 *   2. WITHIN THE CAP. No more keys than `cap`.
 *   3. THE ANSWER IS BOUNDED AND A FUNCTION. A bent request at a random cap
 *      is answered in at most the cap, the same bytes twice.
 *
 * FLOORS: a run that never admitted through a bent page, never refused an
 * entry, or never answered a bent request has not tested what it claims.
 */

#include "../members.h"
#include "../../chain/chain.h"
#include "../../chain/revocation.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FUZZ_DEFAULT_CASES 4000u
#define FUZZ_MIN_CASES 1000u

/* ---- the signer: keyed by the key's first byte, as exchange_fuzz's ------- */

static void mac(uint8_t out[FZN_SIG_LEN], uint8_t key, const uint8_t *msg, size_t len)
{
	uint64_t h = 0xcbf29ce484222325ull ^ key;
	size_t i;

	for (i = 0; i < len; i++)
		h = (h ^ msg[i]) * 0x100000001b3ull;
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h = (h ^ (uint64_t)i) * 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 56);
	}
}

static uint8_t signing_as;

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t len)
{
	(void)ctx;
	mac(sig, signing_as, msg, len);
	return 1;
}

static int stub_verify(void *ctx, const uint8_t pk[FZN_PUBKEY_LEN], const uint8_t *msg, size_t len,
                       const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	mac(want, pk[0], msg, len);
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static const fzn_sign_ops_t SIGN = { stub_verify, stub_sign, NULL };

/* ---- the generator ------------------------------------------------------ */

static uint32_t rng;

static uint32_t next(void)
{
	rng ^= rng << 13;
	rng ^= rng >> 17;
	rng ^= rng << 5;
	return rng;
}

static uint32_t below(uint32_t n)
{
	return n ? next() % n : 0u;
}

static size_t bend(uint8_t *buf, size_t len, size_t cap)
{
	size_t i, at, n, b;

	switch (below(6u)) {
	case 0:
		for (i = 1u + below(4u); i > 0 && len; i--)
			buf[below((uint32_t)len)] ^= (uint8_t)(1u << below(8u));
		return len;
	case 1:
		return len ? below((uint32_t)len) : 0u;
	case 2:
		n = below(64u);
		for (i = 0; i < n && len < cap; i++)
			buf[len++] = (uint8_t)next();
		return len;
	case 3:
		if (len >= 2u) {
			at = below((uint32_t)(len - 1u));
			b = below(2u) ? 0xffu : 0x00u;
			buf[at] = (uint8_t)b;
			buf[at + 1u] = (uint8_t)b;
		}
		return len;
	case 4:
		if (len >= 2u) {
			at = below((uint32_t)len);
			n = 1u + below((uint32_t)(len - at));
			if (len + n <= cap) {
				memmove(buf + at + n, buf + at, len - at);
				len += n;
			}
		}
		return len;
	default:
		if (len >= 2u) {
			uint8_t t;

			at = below((uint32_t)len);
			b = below((uint32_t)len);
			t = buf[at];
			buf[at] = buf[b];
			buf[b] = t;
		}
		return len;
	}
}

/* ---- the estate --------------------------------------------------------- */

#define ROOT 0x10u
#define OTHER_ROOT 0x70u
#define MEMBERS 3
static const uint8_t MEMBER[MEMBERS] = { 0x21u, 0x22u, 0x23u };
#define CONTACT 0x31u
#define STRANGER 0x41u

static fzn_node_config_t config;
static fzn_node_peer_t peers[MEMBERS + 2];
static size_t peer_count;
static fzn_revocation_t rev_entries[4];
static fzn_revocation_store_t revocations;
static uint8_t root_key[FZN_PUBKEY_LEN];

static void key(uint8_t out[FZN_PUBKEY_LEN], uint8_t seed)
{
	size_t i;

	for (i = 0; i < FZN_PUBKEY_LEN; i++)
		out[i] = (uint8_t)(seed + i * 5u);
	out[0] = seed;
}

static int peer_of(fzn_node_peer_t *p, uint8_t grantor, uint8_t grantee, const fzn_cap_id_t *cap)
{
	uint8_t from[FZN_PUBKEY_LEN];

	memset(p, 0, sizeof(*p));
	key(from, grantor);
	key(p->sender, grantee);
	signing_as = grantor;
	if (fzn_chain_mint(from, p->sender, cap, 100u, FZN_NO_EXPIRY, 0, &SIGN, p->hop_bytes[0])
	    != FZN_CHAIN_OK)
		return 0;
	p->hop_count = 1u;
	return 1;
}

static int estate(void)
{
	size_t i;

	memset(&config, 0, sizeof(config));
	memset(config.remote_capability.b, 0x61, FZN_CAP_ID_LEN);
	memset(config.share_capability.b, 0x62, FZN_CAP_ID_LEN);
	config.has_share = 1;
	key(root_key, ROOT);
	if (fzn_revocation_store_init(&revocations, rev_entries, 4) != FZN_CHAIN_OK)
		return 0;
	peer_count = 0;
	for (i = 0; i < MEMBERS; i++)
		if (!peer_of(&peers[peer_count++], ROOT, MEMBER[i], &config.remote_capability))
			return 0;
	/* A CONTACT, on the share capability: never listed. */
	if (!peer_of(&peers[peer_count++], ROOT, CONTACT, &config.share_capability))
		return 0;
	/* A PEER OF ANOTHER ROOT: listed, and never admitted. */
	return peer_of(&peers[peer_count++], OTHER_ROOT, STRANGER, &config.remote_capability);
}

static int is_member(const uint8_t k[FZN_PUBKEY_LEN])
{
	uint8_t want[FZN_PUBKEY_LEN];
	size_t i;

	for (i = 0; i < MEMBERS; i++) {
		key(want, MEMBER[i]);
		if (memcmp(want, k, FZN_PUBKEY_LEN) == 0)
			return 1;
	}
	return 0;
}

struct coverage {
	unsigned long bent, admitted_bent, refused, answered_bent;
};
static struct coverage cov;
static int bent_this;
static size_t answer_cap;

static int lying_ask(void *ctx, const uint8_t *request, size_t request_len, uint8_t *reply,
                     size_t reply_cap, size_t *reply_len)
{
	size_t cap = answer_cap < reply_cap ? answer_cap : reply_cap;

	(void)ctx;
	*reply_len = fzn_node_members_answer(&config, peers, peer_count, request, request_len, reply,
	                                     cap);
	if (*reply_len && below(2u)) {
		*reply_len = bend(reply, *reply_len, reply_cap);
		cov.bent++;
		bent_this = 1;
	}
	return *reply_len != 0u;
}

static int fuzz_one(unsigned long c)
{
	uint8_t got[8][FZN_PUBKEY_LEN];
	size_t n = 0, refused = 0, cap, i;

	rng = (uint32_t)(c * 2654435761u) ^ 0x1b873593u;
	if (!rng)
		rng = 1u;
	bent_this = 0;
	if (below(3u) == 0u) {
		/* 3: a bent request, at a random cap. */
		static uint8_t first[16384], second[16384];
		uint8_t req[64];
		size_t len, l1, l2;

		req[0] = 2u;
		req[1] = FZN_NODE_MEMBERS_QUERY;
		req[2] = 0u;
		req[3] = (uint8_t)below(4u);
		len = bend(req, FZN_NODE_MEMBERS_QUERY_LEN, sizeof(req));
		cap = 1u + below(sizeof(first) - 1u);
		l1 = fzn_node_members_answer(&config, peers, peer_count, req, len, first, cap);
		l2 = fzn_node_members_answer(&config, peers, peer_count, req, len, second, cap);
		if (l1 > cap || l1 != l2 || memcmp(first, second, l1) != 0) {
			printf("members_fuzz: case %lu: an answer of %zu at a cap of %zu, or not the "
			       "same twice (%zu)\n", c, l1, cap, l2);
			return 0;
		}
		if (l1)
			cov.answered_bent++;
		return 1;
	}
	/* A PAGE SMALL ENOUGH, sometimes, that the list takes several. */
	answer_cap = below(2u) ? 16384u : FZN_NODE_MEMBERS_HEAD_LEN + 2u * (FZN_PUBKEY_LEN + 1u
	                                                                     + FZN_HOP_LEN);
	cap = 1u + below(8u);
	(void)fzn_node_members_pull(lying_ask, NULL, root_key, &config.remote_capability, 1000u,
	                            &SIGN, &revocations, got, cap, &n, &refused);
	if (n > cap) {
		printf("members_fuzz: case %lu: %zu admitted at a cap of %zu\n", c, n, cap);
		return 0;
	}
	for (i = 0; i < n; i++)
		if (!is_member(got[i])) {
			printf("members_fuzz: case %lu: admitted %02x, which the root never made a "
			       "member\n", c, got[i][0]);
			return 0;
		}
	if (bent_this && n)
		cov.admitted_bent++;
	if (refused)
		cov.refused++;
	return 1;
}

static unsigned long floor_of(unsigned long cases, unsigned long per)
{
	unsigned long f = cases / per;

	return f ? f : 1u;
}

int main(int argc, char **argv)
{
	unsigned long cases = FUZZ_DEFAULT_CASES, c;

	if (argc > 1) {
		cases = strtoul(argv[1], NULL, 10);
		if (cases == 0)
			cases = FUZZ_DEFAULT_CASES;
	}
	if (cases < FUZZ_MIN_CASES) {
		printf("members_fuzz: %lu cases is below FUZZ_MIN_CASES (%u), so this run will not "
		       "report success. Re-run with %u or more.\n", cases, (unsigned)FUZZ_MIN_CASES,
		       (unsigned)FUZZ_MIN_CASES);
		return 1;
	}
	if (!estate()) {
		printf("members_fuzz: the estate would not mint\n");
		return 1;
	}
	for (c = 0; c < cases; c++)
		if (!fuzz_one(c + 1u)) {
			printf("members_fuzz: FAILED on case %lu\n", c + 1u);
			return 1;
		}
	if (cov.admitted_bent < floor_of(cases, 40u) || cov.refused < floor_of(cases, 40u)
	    || cov.answered_bent < floor_of(cases, 40u)) {
		printf("members_fuzz: REACHED TOO LITTLE -- %lu bent, %lu admitted through a bent "
		       "page, %lu refused, %lu bent requests answered, in %lu cases\n", cov.bent,
		       cov.admitted_bent, cov.refused, cov.answered_bent, cases);
		return 1;
	}
	printf("members_fuzz: %lu cases, %lu bent pages, %lu admitted through one, %lu refused, "
	       "%lu bent requests answered; every key admitted a member\n", cases, cov.bent,
	       cov.admitted_bent, cov.refused, cov.answered_bent);
	return 0;
}
