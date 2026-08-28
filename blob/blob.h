#ifndef FZN_BLOB_H
#define FZN_BLOB_H

/*
 * Content-addressed blobs: a file named by the root of a Merkle tree over
 * its SEALED leaves. project.md sec 16 carries the design; this header
 * carries the parts a caller has to get right.
 *
 * THE TREE IS OVER CIPHERTEXT, AND THAT ORDERING IS THE WHOLE DESIGN. Two
 * verifiers, answering different questions:
 *
 *   - `fzn_blob_proof_verify` checks a leaf against the root WITH NO KEY AT
 *     ALL, so a relay or a cache serves bytes it cannot read. A host that
 *     has never held the content key can still refuse a stranger's garbage.
 *   - `fzn_blob_leaf_open` additionally checks the AEAD, which is what
 *     authenticates the plaintext.
 *
 * A relay needs the first and must never need the second. Hashing the
 * plaintext instead would collapse the two into one and hand every cache
 * the key.
 *
 * ADOPTED FROM fuzzypickles' `core/src/blob_internal.h` at 2073cbe rather
 * than derived here, including the leaf size and its arithmetic. The commit
 * is part of the citation: a name alone does not say which of two true
 * readings was taken, and a vendored pin and the owner's tip are two facts
 * wearing one name. That tree has 1893 lines
 * of this in production behind stickers, file transfer and group assets;
 * this library is taking the contract, not reinventing it. What differs is
 * recorded in sec 16 and amounts to two things: nothing here allocates, and
 * the pieces are called LEAVES because `chunk/` in this tree already means a
 * datagram fragment with a different lifecycle.
 */

#include <stddef.h>
#include <stdint.h>

#include "../session/aead.h"
#include "../session/commitment.h"

/*
 * The canonical leaf size. IDENTITY-AFFECTING, therefore permanent: the blob
 * id is the root over leaves of this size and sealing is derived per leaf
 * index, so a different size is a different id for the same file and a
 * disjoint swarm.
 *
 * 1024, from fuzzypickles' FZP_BLOB_LEAF_SIZE and its arithmetic -- a sealed
 * leaf plus framing inside IPv6's guaranteed 1280-byte MTU, without relying
 * on path MTU discovery.
 *
 * THE PROPERTY THAT MATTERS IS NOT THE PACKING. A receiver cannot verify a
 * leaf until it holds all of it, so THE LEAF SIZE IS EXACTLY HOW MUCH
 * UNVERIFIED DATA AN ATTACKER CAN MAKE A HOST BUFFER. At datagram size every
 * arriving datagram is independently verifiable on arrival and garbage is
 * discarded immediately, so the usual peer-to-peer exhaustion vector closes
 * by construction rather than by a heuristic -- which matters here because
 * the bytes come from strangers by design.
 *
 * It costs FZN_BLOB_LEAF_OVERHEAD on every leaf, about 3%, forever.
 * Bisection -- naming a subtree by one index and one depth rather than
 * enumerating leaves -- is what keeps that affordable, and is why the cost
 * is a deliberate purchase rather than something to shave later.
 */
#define FZN_BLOB_LEAF_SIZE 1024u

/* A node in the tree, and a blob's id. */
#define FZN_BLOB_HASH_LEN 32u

/* The content key. Per blob, and NEVER reused across different content:
 * sealing is deterministic, so a second blob under the same key repeats
 * (key, index) pairs and the nonce reuse is catastrophic in the ordinary
 * way. See fzn_blob_leaf_seal, which cannot check this and says so. */
#define FZN_BLOB_KEY_LEN 32u

/* What one sealed leaf costs beyond its plaintext: the key commitment and
 * the AEAD tag. Spelled from the library's own constants rather than as 32,
 * so that a change to either is a change here and not a silent disagreement
 * between this header and session/. */
#define FZN_BLOB_LEAF_OVERHEAD (FZN_COMMITMENT_LEN + FZN_AEAD_TAG_LEN)
#define FZN_BLOB_SEALED_MAX (FZN_BLOB_LEAF_SIZE + FZN_BLOB_LEAF_OVERHEAD)

/*
 * The tallest tree this library will build or verify, which bounds both the
 * working set and any loop a stranger's bytes can drive.
 *
 * 2^40 leaves of 1 KiB is a terabyte, far past anything these projects move,
 * and the bound is what stops a crafted proof making a verifier iterate
 * without end. fuzzypickles bounds its own proofs at the same 40 for the
 * same reason.
 */
#define FZN_BLOB_MAX_DEPTH 40u

/* The most leaves a tree of that depth holds. Written as a shift rather than
 * a literal so the two cannot drift. */
#define FZN_BLOB_MAX_LEAVES (((uint64_t)1) << FZN_BLOB_MAX_DEPTH)

typedef enum fzn_blob_err {
	FZN_BLOB_OK = 0,
	/* The caller's bug: a null, a buffer too small, an index past the
	 * end. Never a peer's bytes. */
	FZN_BLOB_ERR_MALFORMED,
	/* A hash or AEAD vtable refused, or was absent. */
	FZN_BLOB_ERR_HASH,
	/* A peer's bytes are not this shape: a sealed leaf of impossible
	 * length, a proof deeper than FZN_BLOB_MAX_DEPTH. */
	FZN_BLOB_ERR_SHAPE,
	/* The key commitment did not match, which is refused BEFORE the AEAD
	 * -- see fzn_blob_leaf_open. */
	FZN_BLOB_ERR_COMMITMENT,
	/* The AEAD refused. */
	FZN_BLOB_ERR_AUTH,
	/* The proof does not reach the root. */
	FZN_BLOB_ERR_PROOF,
	/* The streaming tree is full, which needs FZN_BLOB_MAX_LEAVES leaves
	 * and therefore cannot happen to a caller who is not trying. */
	FZN_BLOB_ERR_FULL,
} fzn_blob_err_t;

const char *fzn_blob_err_str(fzn_blob_err_t err);

/*
 * ---- keys ---------------------------------------------------------------
 *
 * Derives one leaf's AEAD key and its key commitment from the blob's content
 * key and the leaf's index.
 *
 * THE INDEX IS BOUND INSIDE THE DERIVATION, not only into the nonce. A leaf
 * lifted from position 3 and replayed at position 7 therefore fails to
 * derive the same key at all, rather than relying on the Merkle root alone
 * to notice the reordering -- and the root is exactly what a peer serving
 * from a partial cache may not yet have checked.
 *
 * ONE hash producing both outputs, which is `session/commitment.h`'s
 * construction with a different label rather than a second implementation of
 * it. That shared input is what makes a second key matching a given
 * commitment a second-preimage problem instead of a free choice.
 */
fzn_blob_err_t fzn_blob_derive_leaf(const fzn_hash_ops_t *hash,
                                     const uint8_t content_key[FZN_BLOB_KEY_LEN],
                                     uint64_t index, uint8_t aead_key_out[FZN_AEAD_KEY_LEN],
                                     uint8_t commitment_out[FZN_COMMITMENT_LEN]);

/*
 * ---- leaves -------------------------------------------------------------
 *
 * Seals one leaf. `plain_len` must be FZN_BLOB_LEAF_SIZE except for the last
 * leaf of a blob, which may be shorter but never empty -- an empty final
 * leaf would give one file two encodings and two ids.
 *
 * The sealed form is `commitment | ciphertext | tag`, so `*out_len` is
 * `plain_len + FZN_BLOB_LEAF_OVERHEAD`.
 *
 * SEALING IS DETERMINISTIC. The nonce comes from the index, not from
 * entropy, so every holder of the same content and key produces
 * byte-identical bytes and therefore the same id. Without that, two people
 * sharing one file would seed two swarms, which is most of the point gone.
 *
 * THAT SAFETY RESTS ENTIRELY ON THE CALLER, and this function cannot check
 * it: a content key must be used for exactly one blob. Reuse repeats (key,
 * index) pairs across different plaintexts and breaks the AEAD in the
 * ordinary catastrophic way. The argument is named `content_key` rather than
 * `key` for that reason.
 */
fzn_blob_err_t fzn_blob_leaf_seal(const fzn_hash_ops_t *hash, const fzn_aead_ops_t *aead,
                                   const uint8_t content_key[FZN_BLOB_KEY_LEN], uint64_t index,
                                   const uint8_t *plain, size_t plain_len, uint8_t *out,
                                   size_t out_cap, size_t *out_len);

/*
 * Opens one sealed leaf in place of the caller's buffer.
 *
 * THE COMMITMENT IS CHECKED BEFORE THE AEAD, and the order is the point
 * rather than an optimisation: a plain AEAD is non-committing, so a
 * ciphertext can be crafted to open validly under two different keys, and a
 * blob whose leaves can mean two things is not content-addressed. The check
 * is constant-time.
 */
fzn_blob_err_t fzn_blob_leaf_open(const fzn_hash_ops_t *hash, const fzn_aead_ops_t *aead,
                                   const uint8_t content_key[FZN_BLOB_KEY_LEN], uint64_t index,
                                   const uint8_t *sealed, size_t sealed_len, uint8_t *out,
                                   size_t out_cap, size_t *out_len);

/*
 * ---- the tree -----------------------------------------------------------
 *
 * Hashes a sealed leaf, and an interior node from its two children.
 *
 * THE TWO ARE DOMAIN-SEPARATED BY A PREFIX BYTE, and it is not decoration.
 * Without it a Merkle tree carries the textbook second-preimage weakness: an
 * interior node hashes 64 bytes, which is a perfectly good leaf, so a
 * shallower tree can be presented as a deeper one's leaf and the root still
 * matches. THE KEYLESS VERIFIER IS THE ONE THAT WOULD ACCEPT IT, and the
 * keyless verifier is what strangers use. blob/test/blob_test.c builds that
 * forgery and checks it is refused; delete either prefix and it is not.
 */
fzn_blob_err_t fzn_blob_leaf_hash(const fzn_hash_ops_t *hash, const uint8_t *sealed,
                                   size_t sealed_len, uint8_t out[FZN_BLOB_HASH_LEN]);
fzn_blob_err_t fzn_blob_node_hash(const fzn_hash_ops_t *hash,
                                   const uint8_t left[FZN_BLOB_HASH_LEN],
                                   const uint8_t right[FZN_BLOB_HASH_LEN],
                                   uint8_t out[FZN_BLOB_HASH_LEN]);

/*
 * The streaming root.
 *
 * NOTHING HERE ALLOCATES, which is what shapes this type. A tree over a
 * gigabyte has a million leaf hashes and they will not be held; instead the
 * stack carries at most one hash per level, folded as leaves arrive, so the
 * working set is FZN_BLOB_MAX_DEPTH hashes whatever the blob's size.
 *
 * That is not a compromise made for the allocation rule. A receiver verifies
 * in arrival order anyway, so a construction that consumes leaves in order
 * is what it wanted.
 *
 * `level[i]` is the height of `stack[i]`, and the stack is strictly
 * decreasing in height from the bottom -- which is the invariant that makes
 * `push` fold in amortised constant time and `root` a single downward pass.
 */
typedef struct fzn_blob_tree {
	uint8_t stack[FZN_BLOB_MAX_DEPTH][FZN_BLOB_HASH_LEN];
	uint8_t level[FZN_BLOB_MAX_DEPTH];
	unsigned depth;
	uint64_t leaves;
} fzn_blob_tree_t;

void fzn_blob_tree_init(fzn_blob_tree_t *tree);
fzn_blob_err_t fzn_blob_tree_push(const fzn_hash_ops_t *hash, fzn_blob_tree_t *tree,
                                   const uint8_t leaf_hash[FZN_BLOB_HASH_LEN]);

/*
 * The root of what has been pushed so far. Does not consume the tree, so a
 * caller may ask for a running root and keep pushing.
 *
 * A tree with NO leaves has no root and is refused with
 * FZN_BLOB_ERR_MALFORMED. An empty blob is not addressable here, deliberately
 * -- giving it the hash of nothing would make every empty file share an id
 * with a tree nobody built, and there is no content to serve.
 */
fzn_blob_err_t fzn_blob_tree_root(const fzn_hash_ops_t *hash, const fzn_blob_tree_t *tree,
                                   uint8_t root_out[FZN_BLOB_HASH_LEN]);

/*
 * ---- proofs -------------------------------------------------------------
 *
 * An inclusion proof: the sibling hashes from a leaf up to the root, bottom
 * first.
 *
 * `fzn_blob_proof_build` needs every leaf hash and is therefore the SEEDER's
 * function -- 32 bytes per KiB of blob, held by whoever is serving. A
 * receiver never calls it. `fzn_blob_proof_verify` needs the one leaf, the
 * siblings, and the root, which is what arrives on the wire.
 *
 * `leaf_count` decides the SHAPE of the climb and is therefore part of what
 * is verified -- but only where the shape depends on it, and the difference
 * is a caller's problem rather than a footnote.
 *
 * THE ROOT DOES NOT COMMIT TO THE LEAF COUNT. That is RFC 6962's property
 * and this tree inherits it: a leaf inside a complete subtree has the same
 * path, the same siblings and the same root in a tree of 11 leaves and one
 * of 12, so a proof valid under one is valid under the other and this
 * function accepts both. Only a leaf whose depth actually differs is
 * refused.
 *
 * SO WHATEVER CARRIES A BLOB ID MUST CARRY ITS LENGTH BESIDE IT, inside the
 * same signature. A root alone names a set of trees rather than one blob,
 * and a receiver told "n leaves" by an attacker can be walked to a
 * truncation of the file it asked for. This library cannot fix that here --
 * the fix belongs to whatever record references a blob -- and it is stated
 * here because this is the function whose caller needs to know.
 *
 * Found by the test asserting the flat version of this and failing, which is
 * the honest order: the first draft claimed a proof never verifies against a
 * tree of another size, and it does.
 */
fzn_blob_err_t fzn_blob_proof_build(const fzn_hash_ops_t *hash, const uint8_t *leaf_hashes,
                                     uint64_t leaf_count, uint64_t index, uint8_t *out,
                                     size_t out_cap, unsigned *out_count);
fzn_blob_err_t fzn_blob_proof_verify(const fzn_hash_ops_t *hash,
                                      const uint8_t leaf_hash[FZN_BLOB_HASH_LEN], uint64_t index,
                                      uint64_t leaf_count, const uint8_t *siblings,
                                      unsigned sibling_count,
                                      const uint8_t root[FZN_BLOB_HASH_LEN]);

#endif /* FZN_BLOB_H */
