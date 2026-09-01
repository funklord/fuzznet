/* THE ON-DISK BLOBS, RECOMPUTED FROM THE FORMAT persist.c DOCUMENTS.
 *
 * WHY THIS FILE EXISTS, MEASURED FIRST. The peer blob was permuted -- its
 * `prekey` and `created_at` exchanged, in the packer and the opener together,
 * so the total length, the version byte and the slot byte were all unchanged
 * -- and the whole suite stayed green. Pack and open are the only two readers
 * of these bytes, so a layout change moves both halves at once and nothing
 * downstream can tell.
 *
 * THAT IS THE SAME BLINDNESS project.md sec 45 records for the domain labels
 * and the wire layouts, at the one boundary where the bytes are OURS ON BOTH
 * SIDES -- which is exactly why it survived longest. There is no peer to
 * disagree with us here. The disagreeing party is THIS HOST LATER, reading a
 * file it wrote before an upgrade.
 *
 * WHICH MAKES IT THE SHATTERED-ESTATE CASE, sec 46. A device that goes away
 * for a long time and returns reads its own persisted trust anchor, its own
 * prekey and its own ratchet chains. `head_check` is careful and catches most
 * of what can go wrong: it requires an EXACT length, the right version byte
 * and the right slot byte. What it cannot catch is a layout permuted WITHOUT
 * a version bump -- same length, same version, same slot, different meaning.
 * A peer blob permuted as above restores eight bytes of a timestamp into the
 * first eight bytes of a prekey, and the device agrees with nobody, including
 * its former self.
 *
 * SO WHAT THIS PINS IS THE DISCIPLINE, not just the bytes: changing the
 * layout now fails here, and the failure arrives at the moment somebody must
 * decide whether FZN_PERSIST_VERSION should have moved. That decision had
 * nothing prompting it before.
 *
 * The offsets and the composition are written out as literals rather than
 * through OFF_BODY and the *_BODY macros -- those are static to persist.c in
 * any case, and a constant shared between the code and its own test cannot
 * detect a change to itself.
 *
 * NOT GATED ON MONOCYPHER: packing these blobs is byte assembly with no
 * primitive in it, so this runs in every build.
 */

#include "../persist.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check(int ok, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		fprintf(stderr, "  FAIL: %s\n", what);
	}
}

/* From persist.c: "Every blob is `version | slot | payload`". */
#define V 1u /* FZN_PERSIST_VERSION */
#define T_TRUST 1u
#define T_SECRET 2u
#define T_PEER 3u
#define T_CHAIN 4u

static void put_be64(uint8_t *p, uint64_t v)
{
	unsigned i;
	for (i = 0u; i < 8u; i++)
		p[i] = (uint8_t)(v >> (8u * (7u - i)));
}

static const uint8_t ROOT[FZN_PUBKEY_LEN] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
};

static const uint8_t PREKEY[FZN_PREKEY_LEN] = {
	0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
	0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
	0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
	0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0,
};

static const uint8_t CHAINKEY[FZN_CHAIN_KEY_LEN] = {
	0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
	0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0,
	0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8,
	0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0,
};

/* Chosen so every byte of each timestamp differs from every byte of the
 * other, and neither is a round number -- the permutation that survived
 * exchanged a timestamp with a key, and two tidy values would have let a
 * partial overlap through. */
#define ADOPTED_AT 0x1122334455667788u
#define CREATED_AT 0x99aabbccddeeff01u
#define CHAIN_SEQ  0x0f1e2d3c4b5a6978u

int main(void)
{
	uint8_t got[FZN_PERSIST_MAX];
	uint8_t want[FZN_PERSIST_MAX];
	size_t len;

	/* ---- trust: root | source | adopted_at ---------------------------- */
	{
		fzn_trust_t trust;
		fzn_trust_t back;

		memset(&trust, 0, sizeof(trust));
		memcpy(trust.root, ROOT, sizeof(ROOT));
		trust.adopted_at = ADOPTED_AT;
		trust.source = FZN_TRUST_ADOPTED;

		want[0] = V;
		want[1] = T_TRUST;
		memcpy(want + 2, ROOT, 32);
		want[34] = 2u; /* FZN_TRUST_ADOPTED */
		put_be64(want + 35, ADOPTED_AT);

		len = 0;
		check(fzn_persist_trust_pack(&trust, got, sizeof(got), &len) == FZN_PERSIST_OK,
		      "trust packs");
		check(len == 43u, "a trust blob is 43 bytes: 2 header, 32 root, 1 source, 8 time");
		check(memcmp(got, want, 43u) == 0,
		      "the trust blob is the bytes persist.c's format specifies");

		/* Opening the LITERAL bytes, not what the packer just produced --
		 * so the reader is held to the format rather than to the writer. */
		memset(&back, 0xee, sizeof(back));
		check(fzn_persist_trust_open(want, 43u, &back) == FZN_PERSIST_OK,
		      "the literal trust blob opens");
		check(memcmp(back.root, ROOT, sizeof(ROOT)) == 0
		              && back.adopted_at == ADOPTED_AT
		              && back.source == FZN_TRUST_ADOPTED,
		      "the literal trust blob restores the values it encodes");
	}

	/* ---- peer: trust | prekey | created_at ---------------------------- */
	{
		fzn_prekey_peer_t peer;
		fzn_prekey_peer_t back;

		memset(&peer, 0, sizeof(peer));
		memcpy(peer.trust.root, ROOT, sizeof(ROOT));
		peer.trust.adopted_at = ADOPTED_AT;
		peer.trust.source = FZN_TRUST_PINNED;
		memcpy(peer.prekey, PREKEY, sizeof(PREKEY));
		peer.created_at = CREATED_AT;

		want[0] = V;
		want[1] = T_PEER;
		memcpy(want + 2, ROOT, 32);
		want[34] = 1u; /* FZN_TRUST_PINNED */
		put_be64(want + 35, ADOPTED_AT);
		memcpy(want + 43, PREKEY, 32);
		put_be64(want + 75, CREATED_AT);

		len = 0;
		check(fzn_persist_peer_pack(&peer, got, sizeof(got), &len) == FZN_PERSIST_OK,
		      "peer packs");
		check(len == 83u, "a peer blob is 83 bytes");
		check(memcmp(got, want, 83u) == 0,
		      "the peer blob is the bytes persist.c's format specifies");

		/* THE PERMUTATION THAT SURVIVED. `prekey` begins at 43 and
		 * `created_at` at 75; exchanging them preserves the length, the
		 * version and the slot, and this is the check that sees it. */
		memset(&back, 0xee, sizeof(back));
		check(fzn_persist_peer_open(want, 83u, &back) == FZN_PERSIST_OK,
		      "the literal peer blob opens");
		check(memcmp(back.prekey, PREKEY, sizeof(PREKEY)) == 0
		              && back.created_at == CREATED_AT,
		      "the literal peer blob restores its prekey and its timestamp, "
		      "each from its own offset");
	}

	/* ---- chain: key | seq --------------------------------------------- */
	{
		fzn_ratchet_chain_t chain;
		fzn_ratchet_chain_t back;

		memset(&chain, 0, sizeof(chain));
		memcpy(chain.key, CHAINKEY, sizeof(CHAINKEY));
		chain.seq = CHAIN_SEQ;

		want[0] = V;
		want[1] = T_CHAIN;
		memcpy(want + 2, CHAINKEY, 32);
		put_be64(want + 34, CHAIN_SEQ);

		len = 0;
		check(fzn_persist_chain_pack(&chain, got, sizeof(got), &len) == FZN_PERSIST_OK,
		      "chain packs");
		check(len == 42u, "a chain blob is 42 bytes");
		check(memcmp(got, want, 42u) == 0,
		      "the chain blob is the bytes persist.c's format specifies");

		memset(&back, 0xee, sizeof(back));
		check(fzn_persist_chain_open(want, 42u, &back) == FZN_PERSIST_OK,
		      "the literal chain blob opens");
		check(memcmp(back.key, CHAINKEY, sizeof(CHAINKEY)) == 0 && back.seq == CHAIN_SEQ,
		      "the literal chain blob restores the values it encodes");
	}

	/* ---- the slot byte is load-bearing, and cheap to prove ------------- */
	{
		fzn_ratchet_chain_t back;

		want[0] = V;
		want[1] = T_CHAIN;
		memcpy(want + 2, CHAINKEY, 32);
		put_be64(want + 34, CHAIN_SEQ);
		want[1] = T_TRUST; /* the right shape, filed as the wrong thing */

		check(fzn_persist_chain_open(want, 42u, &back) != FZN_PERSIST_OK,
		      "a blob carrying another slot's tag is refused, not reinterpreted");

		want[1] = T_CHAIN;
		want[0] = V + 1u;
		check(fzn_persist_chain_open(want, 42u, &back) != FZN_PERSIST_OK,
		      "a blob from a future version is refused");
	}

	/* The bound persist.h advertises, checked against the largest blob this
	 * file actually built rather than against the macro that defines it. */
	check(FZN_PERSIST_MAX >= 83u, "FZN_PERSIST_MAX must hold the peer blob");

	if (failures == 0)
		printf("persist_kat_test: %d checks OK\n", checks);
	else
		fprintf(stderr, "persist_kat_test: %d of %d FAILED\n", failures, checks);
	return failures ? 1 : 0;
}
