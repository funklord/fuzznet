/* Packing a node peer and opening it again.
 *
 * THE PROPERTY IS THE ROUND TRIP, and the cases are chosen for the hop count
 * because that is the only variable thing in the record: zero hops (a
 * root-issued peer, which `fzn_revocation_offer_root` makes the ordinary
 * case), one, and the maximum. A record whose length must agree with a count
 * carried inside it fails at the ends.
 */

#define _DEFAULT_SOURCE /* mkdtemp under -std=c11 */

#include "peer_persist.h"

#include "../persist/persist_file.h"

#include <stdlib.h>
#include <unistd.h>

#include <stdio.h>
#include <string.h>

static int checks;
static int failures;

static void ok_at(int cond, int line, const char *what)
{
	checks++;
	if (!cond) {
		failures++;
		printf("  FAIL peer_persist_test.c:%d: %s\n", line, what);
	}
}

#define ok(c, what) ok_at((c) ? 1 : 0, __LINE__, (what))

static void fill(fzn_node_peer_t *p, size_t hops)
{
	size_t i, k;

	memset(p, 0, sizeof(*p));
	for (i = 0; i < FZN_PUBKEY_LEN; i++)
		p->sender[i] = (uint8_t)(i + 1u);
	for (i = 0; i < FZN_AEAD_KEY_LEN; i++)
		p->recv_key[i] = (uint8_t)(i * 3u + 7u);
	for (i = 0; i < FZN_COMMITMENT_KEY_LEN; i++)
		p->recv_ckey[i] = (uint8_t)(i * 5u + 11u);
	p->hop_count = hops;
	for (i = 0; i < hops; i++)
		for (k = 0; k < FZN_HOP_LEN; k++)
			p->hop_bytes[i][k] = (uint8_t)((i + 1u) * 31u + k);
}

static int same(const fzn_node_peer_t *a, const fzn_node_peer_t *b)
{
	size_t i;

	if (memcmp(a->sender, b->sender, FZN_PUBKEY_LEN) != 0)
		return 0;
	if (memcmp(a->recv_key, b->recv_key, FZN_AEAD_KEY_LEN) != 0)
		return 0;
	if (memcmp(a->recv_ckey, b->recv_ckey, FZN_COMMITMENT_KEY_LEN) != 0)
		return 0;
	if (a->hop_count != b->hop_count)
		return 0;
	for (i = 0; i < a->hop_count; i++)
		if (memcmp(a->hop_bytes[i], b->hop_bytes[i], FZN_HOP_LEN) != 0)
			return 0;
	return 1;
}

static int round_trips(size_t hops)
{
	fzn_node_peer_t in, out;
	uint8_t blob[FZN_NODE_PEER_BLOB_MAX];
	size_t len = 0;

	fill(&in, hops);
	if (fzn_node_peer_pack(&in, blob, sizeof(blob), &len) != FZN_PERSIST_OK)
		return 0;
	if (fzn_node_peer_open(blob, len, &out) != FZN_PERSIST_OK)
		return 0;
	return same(&in, &out);
}

int main(void)
{
	fzn_node_peer_t p, out;
	uint8_t blob[FZN_NODE_PEER_BLOB_MAX];
	size_t len = 0;

	ok(round_trips(0), "a peer with no hops did not round-trip");
	ok(round_trips(1), "a peer with one hop did not round-trip");
	ok(round_trips((size_t)FZN_CHAIN_MAX_HOPS),
	   "a peer with the maximum hops did not round-trip");

	/* The length tracks the count rather than being fixed, which is what
	 * makes the exactness check below worth anything. */
	{
		size_t a = 0, b = 0;

		fill(&p, 0);
		ok(fzn_node_peer_pack(&p, blob, sizeof(blob), &a) == FZN_PERSIST_OK,
		   "a hopless peer would not pack");
		fill(&p, 2);
		ok(fzn_node_peer_pack(&p, blob, sizeof(blob), &b) == FZN_PERSIST_OK,
		   "a two-hop peer would not pack");
		ok(b == a + (2u * (size_t)FZN_HOP_LEN),
		   "two hops did not cost two hops of blob, so the length and the "
		   "count have come apart");
		ok(b <= FZN_NODE_PEER_BLOB_MAX, "a blob exceeded its own maximum");
	}

	/* A hop count past what `fzn_chain_verify` accepts is refused at PACK.
	 *
	 * THE BUFFER IS DELIBERATELY OVERSIZED. With one of exactly
	 * FZN_NODE_PEER_BLOB_MAX the head writer refuses an over-large body on
	 * CAPACITY first, so removing the hop guard changed nothing a test
	 * could see -- the sabotage run reported it MISSED. What the guard
	 * actually prevents is reading `peer->hop_bytes[FZN_CHAIN_MAX_HOPS]`,
	 * one past an array of exactly that many, and only a buffer big enough
	 * to let the pack proceed reaches it. */
	{
		static uint8_t roomy[FZN_NODE_PEER_BLOB_MAX + (2u * FZN_HOP_LEN)];

		fill(&p, 0);
		p.hop_count = (size_t)FZN_CHAIN_MAX_HOPS + 1u;
		ok(fzn_node_peer_pack(&p, roomy, sizeof(roomy), &len)
		       == FZN_PERSIST_ERR_MALFORMED,
		   "a peer with more hops than the chain verifier accepts was "
		   "packed, reading a hop past the end of its own array");
	}

	/* And at OPEN, where the count arrives from a file rather than from a
	 * caller -- the case that matters, since a file is somebody else's. */
	fill(&p, 2);
	ok(fzn_node_peer_pack(&p, blob, sizeof(blob), &len) == FZN_PERSIST_OK,
	   "the control would not pack");
	{
		uint8_t bad[FZN_NODE_PEER_BLOB_MAX];

		memcpy(bad, blob, len);
		bad[FZN_PERSIST_HEAD_LEN + FZN_PUBKEY_LEN + FZN_AEAD_KEY_LEN +
		    FZN_COMMITMENT_KEY_LEN] = (uint8_t)FZN_CHAIN_MAX_HOPS + 1u;
		ok(fzn_node_peer_open(bad, len, &out) == FZN_PERSIST_ERR_SHAPE,
		   "a blob declaring more hops than the maximum opened");

		/* AND THE SAME COUNT WITH A LENGTH THAT AGREES WITH IT, which is
		 * the case that reaches the guard. The case above is refused by
		 * the exactness check -- the forged count disagreed with the
		 * blob's length -- so removing the hop bound changed nothing it
		 * could see. A file crafted to be self-consistent is refused by
		 * the bound and by nothing else, and without it `out->hop_bytes`
		 * is written one past its end. */
		{
			static uint8_t consistent[FZN_NODE_PEER_BLOB_MAX +
			                          (2u * FZN_HOP_LEN)];
			size_t over = (size_t)FZN_CHAIN_MAX_HOPS + 1u;
			size_t olen = FZN_PERSIST_HEAD_LEN +
			              FZN_NODE_PEER_BODY_FIXED +
			              (over * (size_t)FZN_HOP_LEN);

			memset(consistent, 0, sizeof(consistent));
			memcpy(consistent, blob, FZN_PERSIST_HEAD_LEN +
			       FZN_NODE_PEER_BODY_FIXED);
			consistent[FZN_PERSIST_HEAD_LEN + FZN_PUBKEY_LEN +
			           FZN_AEAD_KEY_LEN + FZN_COMMITMENT_KEY_LEN] =
			    (uint8_t)over;
			ok(olen <= sizeof(consistent), "the fixture does not fit");
			ok(fzn_node_peer_open(consistent, olen, &out)
			       == FZN_PERSIST_ERR_SHAPE,
			   "a self-consistent blob declaring nine hops opened, so a "
			   "crafted file writes past the end of hop_bytes");
		}

		/* THE COUNT AND THE LENGTH MUST AGREE. A blob claiming eight hops
		 * while carrying two is the case an `at least` check opens with
		 * six hops of whatever followed it in the file. */
		memcpy(bad, blob, len);
		bad[FZN_PERSIST_HEAD_LEN + FZN_PUBKEY_LEN + FZN_AEAD_KEY_LEN +
		    FZN_COMMITMENT_KEY_LEN] = 8u;
		ok(fzn_node_peer_open(bad, len, &out) == FZN_PERSIST_ERR_SHAPE,
		   "a blob whose declared hop count disagrees with its length "
		   "opened -- so hops are read from past the record");

		/* A trailing byte is a second encoding of one blob. */
		memcpy(bad, blob, len);
		bad[len] = 0x7fu;
		ok(fzn_node_peer_open(bad, len + 1u, &out) == FZN_PERSIST_ERR_SHAPE,
		   "a blob with a trailing byte opened");

		/* A wrong version and a wrong tag, which is what a blob from
		 * another slot looks like. */
		memcpy(bad, blob, len);
		bad[0] = (uint8_t)(FZN_PERSIST_VERSION + 1u);
		ok(fzn_node_peer_open(bad, len, &out) == FZN_PERSIST_ERR_SHAPE,
		   "a blob of another version opened");
		memcpy(bad, blob, len);
		bad[1] = (uint8_t)(FZN_PERSIST_BLOB_NODE_PEER + 1u);
		ok(fzn_node_peer_open(bad, len, &out) == FZN_PERSIST_ERR_SHAPE,
		   "a blob of another type opened, so the tag is not read and any "
		   "slot's bytes are a peer");

		/* Too short to hold even the count, in a buffer that is ACTUALLY
		 * that short. Passing a long buffer with a short length leaves
		 * the over-read inside allocated memory, where nothing sees it;
		 * the sabotage run reported this MISSED for exactly that reason.
		 * With a real short buffer the mutant reads past the end and the
		 * sanitized build is what says so -- the return value cannot,
		 * since a wrong count fails the exactness check either way. */
		{
			static uint8_t stub[FZN_PERSIST_HEAD_LEN + 4u];

			memcpy(stub, blob, sizeof(stub));
			ok(fzn_node_peer_open(stub, sizeof(stub), &out)
			       == FZN_PERSIST_ERR_SHAPE,
			   "a blob too short to carry a hop count opened, which would "
			   "read the count from past its end");
		}
	}

	/* A buffer that cannot hold the blob is refused rather than filled. */
	fill(&p, (size_t)FZN_CHAIN_MAX_HOPS);
	ok(fzn_node_peer_pack(&p, blob, 8u, &len) == FZN_PERSIST_ERR_MALFORMED,
	   "a peer was packed into a buffer too small for it");

	ok(fzn_node_peer_pack(NULL, blob, sizeof(blob), &len)
	       == FZN_PERSIST_ERR_MALFORMED, "a NULL peer packed");
	ok(fzn_node_peer_open(NULL, 32u, &out) == FZN_PERSIST_ERR_MALFORMED,
	   "NULL bytes opened");

	/* THROUGH A REAL BACKEND, which is the half sec 366 left: a node
	 * starting up does not know which peers it was told about, so `load`
	 * alone could never answer. */
	{
		char dir[] = "/tmp/fzn_peer_persist_XXXXXX";
		fzn_persist_file_t store;
		const fzn_persist_ops_t *ops;

		if (!mkdtemp(dir)) {
			ok(0, "a temporary directory could not be made");
		} else {
			fzn_node_peer_t a, b, got[4];
			size_t n = 0;

			ops = fzn_persist_file_init(&store, dir);
			ok(ops != NULL, "the file backend would not initialise");
			ok(ops && ops->list != NULL,
			   "the file backend cannot enumerate, so a node could not "
			   "find the peers it holds");

			fill(&a, 2);
			fill(&b, 0);
			b.sender[0] = 0xAAu;	/* a different identity, same shape */
			ok(fzn_node_peer_save(ops, &a) == FZN_PERSIST_OK,
			   "a peer would not save");
			ok(fzn_node_peer_save(ops, &b) == FZN_PERSIST_OK,
			   "a second peer would not save");

			ok(fzn_node_peers_load(ops, got, 4u, &n) == FZN_PERSIST_OK,
			   "the peers would not load");
			ok(n == 2u, "two peers were saved and a different number loaded");
			/* The order a directory hands back is its own, so match on
			 * identity rather than on position -- a test that assumed an
			 * order would pass here and fail on another filesystem. */
			{
				int seen_a = 0, seen_b = 0;
				size_t k;

				for (k = 0; k < n; k++) {
					if (same(&got[k], &a))
						seen_a = 1;
					if (same(&got[k], &b))
						seen_b = 1;
				}
				ok(seen_a && seen_b,
				   "a saved peer did not come back byte-for-byte");
			}

			/* A CAP SMALLER THAN THE STORE FAILS rather than returning
			 * the first few: a node serving some of its peers with
			 * nothing saying which are missing is worse than one that
			 * refuses. */
			ok(fzn_node_peers_load(ops, got, 1u, &n)
			       == FZN_PERSIST_ERR_BACKEND && n == 0u,
			   "a store holding more peers than the caller's array "
			   "returned a truncated set");

			/* A STRANGER IN THE DIRECTORY IS SKIPPED. The directory is
			 * the caller's; one unrelated file must not stop a node
			 * serving every peer it has. */
			{
				char junk[320];
				FILE *f;

				snprintf(junk, sizeof(junk), "%s/notours.txt", dir);
				f = fopen(junk, "w");
				if (f) {
					(void)fputs("hello", f);
					(void)fclose(f);
				}
				ok(fzn_node_peers_load(ops, got, 4u, &n) == FZN_PERSIST_OK &&
				   n == 2u,
				   "an unrelated file in the store changed what loaded");
				(void)unlink(junk);
			}

			/* A HALF-WRITTEN SAVE, which is the stranger that matters.
			 *
			 * `file_save` writes `<name>.tmp` and renames, so an
			 * interrupted save leaves exactly `<slot>-<64 hex>.tmp` --
			 * a name carrying the right prefix and a valid subject with
			 * four bytes glued on. The unrelated file above does not
			 * reach the length check at all: it fails on the prefix, so
			 * removing the length check changed nothing a test could
			 * see and the sabotage reported it MISSED. This is the name
			 * that gets past the prefix, and without the length check
			 * it lists as a peer -- a duplicate of one already there. */
			{
				static const char HEX[] = "0123456789abcdef";
				char tmp[400];
				char hexname[65];
				unsigned h;
				FILE *f;

				for (h = 0; h < 32u; h++) {
					hexname[h * 2u] = HEX[(a.sender[h] >> 4) & 0x0fu];
					hexname[(h * 2u) + 1u] = HEX[a.sender[h] & 0x0fu];
				}
				hexname[64] = '\0';
				snprintf(tmp, sizeof(tmp), "%s/%u-%s.tmp", dir,
				         (unsigned)FZN_PERSIST_NODE_PEER, hexname);
				f = fopen(tmp, "w");
				if (f) {
					(void)fputs("half", f);
					(void)fclose(f);
				}
				ok(fzn_node_peers_load(ops, got, 4u, &n) == FZN_PERSIST_OK &&
				   n == 2u,
				   "an interrupted save's .tmp listed as a peer, so a "
				   "crash during save leaves a duplicate in the set");
				(void)unlink(tmp);
			}

			/* A RECORD STORED UNDER ONE IDENTITY AND CARRYING ANOTHER.
			 * Either a corrupted store or a file somebody placed, and
			 * serving it means the node answers to a key the store does
			 * not index -- findable by nothing, removable by nothing. */
			{
				uint8_t misfiled[FZN_NODE_PEER_BLOB_MAX];
				uint8_t wrong[FZN_PUBKEY_LEN];
				size_t blen = 0;

				memset(wrong, 0x5Au, sizeof(wrong));
				ok(fzn_node_peer_pack(&a, misfiled, sizeof(misfiled), &blen)
				       == FZN_PERSIST_OK, "the misfiling fixture would not pack");
				ok(ops->save(ops->ctx, FZN_PERSIST_NODE_PEER, wrong, misfiled,
				             blen) == 1,
				   "the misfiled record would not store");
				ok(fzn_node_peers_load(ops, got, 4u, &n)
				       == FZN_PERSIST_ERR_SHAPE,
				   "a record filed under an identity it does not carry "
				   "loaded, so the node would answer to a key its store "
				   "cannot find");
			}

			/* A backend that cannot enumerate says so rather than
			 * reading as an empty set. */
			{
				fzn_persist_ops_t blind = *ops;

				blind.list = NULL;
				ok(fzn_node_peers_load(&blind, got, 4u, &n)
				       == FZN_PERSIST_ERR_BACKEND,
				   "a backend with no list read as a store holding nobody");
			}
		}
	}

	printf("peer_persist_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
