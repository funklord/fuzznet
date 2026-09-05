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

/*
 * WHERE A BYTE LIVES -- pure arithmetic, and deliberately not a reader.
 *
 * project.md sec 104 refused a read-at-offset source and sink, for two
 * reasons that both hold: netcfgd's constraint is that message boundaries are
 * preserved END TO END, and an API handing back a byte range has lost the
 * boundary whatever carries it underneath; and it would give up the property
 * the leaf size was chosen for -- "a receiver cannot verify a leaf until it
 * holds all of it, so THE LEAF SIZE IS EXACTLY HOW MUCH UNVERIFIED DATA AN
 * ATTACKER CAN MAKE A HOST BUFFER". **The verifiable unit and the interface
 * unit have to be the same thing, or the bound stops being a bound.**
 *
 * These two return LEAF INDICES, never bytes, so that stays true: a caller
 * still reads whole leaves through `fzn_spool_read`, verifies them, opens
 * them, and does its own copying. What is removed is only the arithmetic.
 *
 * Sec 104 called that arithmetic "the consumer's, and four lines", which was
 * right about the common case and wrong about the edges -- **the last leaf is
 * short and the store does not know how short**, which is the same fact sec
 * 109 met from the other side when a scrub could not recompute a leaf hash.
 * So the length is a parameter here, exactly as `fzn_split_plan` takes
 * `total`, and an exact multiple of the leaf size is the off-by-one every
 * hand-written version gets to make once.
 *
 * `chunk/split.h` is the same object one layer down and says it best: "PURE
 * ARITHMETIC. Nothing here holds a buffer, copies a payload, or knows what a
 * datagram looks like."
 */

/* The blob's shape, from the length of its content. `out_last_len` is the
 * PLAINTEXT length of the final leaf, which is what `fzn_blob_leaf_open`
 * needs and what nothing else in this library can tell a caller. */
fzn_blob_err_t fzn_blob_geometry(uint64_t content_len, uint64_t *out_leaves,
                                 size_t *out_last_len);

/* Which leaves cover a range of content, and where inside the first one it
 * starts. */
typedef struct fzn_blob_extent {
	uint64_t first;
	uint64_t count;
	/* Plaintext bytes to discard from the front of leaf `first`. Exposed
	 * because it is the number a caller would otherwise get wrong, which
	 * is why `fzn_split_t` exposes `buffer_needed` for the same reason. */
	size_t skip;
} fzn_blob_extent_t;

/*
 * A range naming nothing is refused rather than answered with an empty
 * extent, and a range past the end is refused rather than CLAMPED. Clamping
 * would turn a caller's arithmetic bug into a short read it never hears
 * about -- sec 25's rule met as its quieter cousin: the wrong request must
 * not silently become a right one.
 */
fzn_blob_err_t fzn_blob_extent_of(uint64_t content_len, uint64_t offset, uint64_t len,
                                  fzn_blob_extent_t *out);

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
 * `leaf_count` is part of what is verified, twice over. It decides the shape
 * of the climb, AND IT IS BOUND INTO THE ROOT -- so a verifier handed an
 * attacker's count recomputes a different root and refuses.
 *
 * THAT BINDING IS WHY THERE IS NO RULE HERE FOR CALLERS TO REMEMBER, and the
 * history is worth one paragraph because the first version of this header
 * carried the rule instead.
 *
 * Without the binding, a leaf inside a complete subtree has the same path,
 * the same siblings and the same apex in a tree of 11 leaves and one of 12 --
 * RFC 6962's shape does not commit to its size -- so a proof valid under one
 * verifies under the other, and a receiver told "n leaves" by an attacker can
 * be walked to a truncation of the file it asked for. This header said so,
 * and told callers to carry a blob's length inside whatever signature carries
 * its id. That was correct and CONDITIONAL: it holds until somebody writes a
 * caller that does not, it fails silently when they do, and this module
 * cannot detect it.
 *
 * fuzzypickles answered with their finaliser and it is adopted here: the root
 * is `H(label | u64be(leaf_count) | apex)`, at every place a root is produced
 * or checked. Same guarantee, one hash, and no caller can get it wrong
 * because no caller is involved.
 */
fzn_blob_err_t fzn_blob_proof_build(const fzn_hash_ops_t *hash, const uint8_t *leaf_hashes,
                                     uint64_t leaf_count, uint64_t index, uint8_t *out,
                                     size_t out_cap, unsigned *out_count);
/*
 * ---- spans: a proof that covers a whole request ------------------------
 *
 * A SPAN IS A CANONICAL SUBTREE, named the way the header above already
 * argues for: "naming a subtree by one index and one depth rather than
 * enumerating leaves -- is what keeps that affordable". These are the two
 * calls that make it affordable in fact rather than in principle.
 *
 * WHY, IN ONE NUMBER. A per-leaf proof is `log2(n)` siblings. Verifying a
 * 64-leaf request as 64 separate leaves against verifying it as one span, at
 * a blob of 2^20 leaves: 40960 bytes of proof against 448, which is 62%
 * overhead against 0.68%. project.md sec 103 has the table. A propagation
 * layer whose request and whose proof are not the same shape pays that
 * every batch, for ever.
 *
 * CANONICAL MEANS REACHABLE BY THE BISECTION, not "any aligned range". The
 * tree over `n` leaves splits at `split_at(n)` -- the largest power of two
 * strictly below `n`, RFC 6962's rule -- so for a non-power-of-two blob the
 * right-hand subtrees are not power-of-two sized and an "aligned" range is
 * the wrong test. A span is canonical exactly when the descent from the root
 * reaches it, and `fzn_blob_span_is_canonical` is the only thing entitled to
 * say so.
 *
 * A SINGLE LEAF IS THE SPAN OF COUNT 1, so these generalise the pair above
 * rather than replacing it. The per-leaf calls stay: they are what a
 * consumer verifying one arriving datagram wants, and that is the common
 * case on a lossy transport.
 */

/* Whether `[first, first + count)` is a node of the bisection over
 * `leaf_count` leaves. Non-zero when it is.
 *
 * A SERVER MUST CHECK THIS BEFORE ANSWERING, because a request naming a
 * non-canonical range has no single proof and a server that tried would
 * either send several or send one that proves something else. */
int fzn_blob_span_is_canonical(uint64_t leaf_count, uint64_t first, uint64_t count);

/* The root of a span, computed from the leaf hashes it covers.
 *
 * THE BARE APEX, with no root label and no leaf-count binding: a span is an
 * interior node of somebody's tree, not a blob of its own. Those two belong
 * to `fzn_blob_tree_root`, and confusing the two is how a span proof ends up
 * comparing an apex against a finalised root -- which is exactly the bug the
 * first version of `fzn_blob_span_proof_verify` had.
 *
 * A RECEIVER COMPUTES THIS FROM LEAVES IT HOLDS, which is the property the
 * leaf size was bought for kept at span granularity: nothing lets a caller
 * verify bytes it does not have. */
fzn_blob_err_t fzn_blob_span_root(const fzn_hash_ops_t *hash, const uint8_t *leaf_hashes,
                                   uint64_t count, uint8_t out[FZN_BLOB_HASH_LEN]);

/* The largest canonical span starting at `first` and no longer than
 * `max_count`, or 0 if there is none.
 *
 * The canonical spans that START at a given leaf form a chain -- they are the
 * nodes on the path from the root down to that leaf whose left edge is that
 * leaf -- so "largest that fits" is a walk rather than a search, and a
 * planner covering a run of missing leaves can take them greedily.
 *
 * This is what turns a run into requests: a propagation layer holds a bitmap
 * of what it lacks, and a bitmap's runs are arbitrary while a provable
 * request is not. */
uint64_t fzn_blob_span_largest_at(uint64_t leaf_count, uint64_t first, uint64_t max_count);

/* The siblings from the span's own root up to the blob's root.
 *
 * `out` receives `*out_count` hashes of FZN_BLOB_HASH_LEN. A span equal to
 * the whole blob has a proof of zero siblings, which is correct and is not
 * an error: its root IS the blob's root.
 *
 * Refuses a non-canonical span with FZN_BLOB_ERR_SHAPE rather than building
 * something, because the caller asked for a thing that does not exist in
 * this tree. */
fzn_blob_err_t fzn_blob_span_proof_build(const fzn_hash_ops_t *hash, const uint8_t *leaf_hashes,
                                          uint64_t leaf_count, uint64_t first, uint64_t count,
                                          uint8_t *out, size_t out_cap, unsigned *out_count);

/* Verify a span against the blob's root.
 *
 * `span_root` is the root OF THE SPAN, which a receiver computes from the
 * leaves it just received -- so the leaves are what is being verified and
 * the caller has already had to hold them. That is the property the leaf
 * size was bought for, kept at span granularity: nothing here lets a caller
 * verify bytes it does not have.
 *
 * THE DESCENT IS COMPUTED FROM `leaf_count`, `first` AND `count`, never read
 * from the proof, for the reason `fzn_blob_proof_verify` gives: the shape of
 * a tree over n leaves depends on n, so a verifier taking the path from the
 * prover's framing would accept a span from a differently-shaped tree
 * carrying the same siblings. */
fzn_blob_err_t fzn_blob_span_proof_verify(const fzn_hash_ops_t *hash,
                                           const uint8_t span_root[FZN_BLOB_HASH_LEN],
                                           uint64_t first, uint64_t count, uint64_t leaf_count,
                                           const uint8_t *siblings, unsigned sibling_count,
                                           const uint8_t root[FZN_BLOB_HASH_LEN]);

fzn_blob_err_t fzn_blob_proof_verify(const fzn_hash_ops_t *hash,
                                      const uint8_t leaf_hash[FZN_BLOB_HASH_LEN], uint64_t index,
                                      uint64_t leaf_count, const uint8_t *siblings,
                                      unsigned sibling_count,
                                      const uint8_t root[FZN_BLOB_HASH_LEN]);

#endif /* FZN_BLOB_H */
