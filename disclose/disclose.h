/*
 * SELECTIVE DISCLOSURE: one signature over many fields, and a recipient
 * shown only some of them.
 *
 * WHY THIS EXISTS. project.md sec 5j asked how the same statement reaches
 * different recipients at different fidelities -- exact location to one peer,
 * city-level to another -- listed three shapes and struck two off. Sec 72
 * found that one of them had been eliminated on a misreading, built it in a
 * test out of calls this library already had, and found that **one generic
 * piece was genuinely missing**. This is that piece.
 *
 * The construction needs nothing new: a field per leaf, `blob/`'s tree over
 * the leaf hashes, the root in a record body signed once, and
 * `fzn_blob_proof_verify` to check a disclosed field against it. What was
 * missing is the SALT, and its absence is not a weakness in the margin --
 * it is the whole property failing silently.
 *
 * THE FAILURE, MEASURED RATHER THAN WARNED ABOUT. A leaf is a hash of a
 * field. Hash a one-byte field on its own and anybody holding the root
 * recovers it in 256 tries -- and the search is one a real recipient can run,
 * because they hold the root and their own proof, so they hold the sibling
 * standing where the withheld field is. `sim/test/disclosure_test.c`
 * demonstrates exactly that, then demonstrates the same search failing once
 * the leaf carries sixteen bytes of salt, then demonstrates it SUCCEEDING
 * again when the salt is known -- so the refusal is attributable to not
 * knowing the salt rather than to a broken search.
 *
 * So a construction without a salt REVEALS WHAT IT WITHHOLDS, and looks
 * identical to one that works. That is why the convention is here rather than
 * left to four consumers: each would have to get it right separately, with a
 * wrong answer that verifies, round-trips and passes every test they would
 * think to write.
 *
 * WHAT A COMMITTED FIELD IS:
 *
 *     salt(16) || field
 *
 * Fixed-width salt first, so the split is unambiguous whatever the field's
 * length -- `wire/bytes.h`'s rule about fixed fields before variable ones,
 * for its reason: two implementations that agree on this cannot produce
 * different bytes for the same field.
 *
 * THE SALT IS FRESH PER FIELD AND TRAVELS WITH IT. It is drawn from the
 * entropy seam at commit time and is part of the leaf's preimage, so a
 * recipient shown the field is shown its salt -- they cannot recompute the
 * leaf hash otherwise. A salt DERIVED from a per-record secret would spare
 * the sender nothing: the recipient would still need the bytes, and handing
 * them the secret would hand them every other field's salt with it.
 *
 * WHAT IT DOES NOT HIDE, stated because a reader will otherwise assume it
 * does. `leaf_count` is bound into the root -- `blob.h` explains why, and it
 * is what stops a sender pretending a statement has fewer fields than it has
 * -- so **every recipient learns HOW MANY fields exist.** They learn nothing
 * about the contents of the ones withheld, and nothing about their lengths.
 * A sender who needs the count hidden needs a different construction.
 *
 * AND IT IS NOT ENCRYPTION. Disclosure here is by WITHHOLDING: the bytes are
 * not sent, so there is nothing to open. It protects against a recipient who
 * never sees them, not against one who obtains them later by other means.
 * `blob/`'s sealing cannot be borrowed for this -- `fzn_blob_leaf_seal`
 * requires FZN_BLOB_LEAF_SIZE for every leaf but the last, so it cannot carry
 * small fields at all, which sec 72 measured.
 */

#ifndef FZN_DISCLOSE_H
#define FZN_DISCLOSE_H

#include <stddef.h>
#include <stdint.h>

#include "../blob/blob.h"
#include "../session/random.h"

/* Sixteen bytes, which is 128 bits of the thing an attacker must guess.
 *
 * The number is not tuned to a field's entropy and deliberately so: a salt
 * sized against "how guessable is this field" would need every caller to
 * judge that, and the caller who judges wrong is the one with the field worth
 * hiding. Fixed and generous is the arrangement nobody can get wrong. */
#define FZN_DISCLOSE_SALT_LEN 16u

/* A field is a VALUE rather than a document -- a coordinate, a level, a name,
 * a flag. Bounded because nothing here allocates, and at this size a caller
 * can size a buffer statically and a committed field still fits inside a
 * record body with room for the rest. */
#define FZN_DISCLOSE_MAX_FIELD 256u

/* What a committed field occupies at most. */
#define FZN_DISCLOSE_MAX_LEN (FZN_DISCLOSE_SALT_LEN + FZN_DISCLOSE_MAX_FIELD)

typedef enum fzn_disclose_err {
	FZN_DISCLOSE_OK = 0,
	/* The caller's bug: a null, a buffer too small, a field too long. */
	FZN_DISCLOSE_ERR_MALFORMED = 1,
	/* These bytes are not a committed field: shorter than a salt, or
	 * longer than one plus the maximum. Separate from MALFORMED because
	 * this is somebody else's input rather than this caller's mistake. */
	FZN_DISCLOSE_ERR_SHAPE = 2,
	/* The entropy seam refused, or was absent. A committed field with a
	 * predictable salt is one whose field can be searched for, so this is
	 * a refusal rather than something to carry on from. */
	FZN_DISCLOSE_ERR_NO_SALT = 3,
	/* The hash seam refused, or was absent. */
	FZN_DISCLOSE_ERR_HASH = 4,
	/* The proof does not put this field in that root. */
	FZN_DISCLOSE_ERR_PROOF = 5
} fzn_disclose_err_t;

/* Commit one field: draw a fresh salt and lay `salt || field` into `out`.
 *
 * This is the whole of the convention, and it is a function rather than a
 * note in a header so that a consumer cannot half-follow it. */
fzn_disclose_err_t fzn_disclose_commit(const fzn_random_ops_t *rng, const uint8_t *field,
                                       size_t field_len, uint8_t *out, size_t out_cap,
                                       size_t *out_len);

/* The leaf hash of a committed field, to push into `fzn_blob_tree_push` and
 * to keep for `fzn_blob_proof_build`.
 *
 * A THIN WRAPPER OVER `fzn_blob_leaf_hash`, AND DELIBERATELY NOT A SECOND
 * IMPLEMENTATION. `code-style.md` warns that a parallel copy of a function in
 * two places needs a distinct name and becomes a landmine when something
 * links both; the safer arrangement is one implementation with a name saying
 * what this caller is doing.
 *
 * WHICH LEAVES A QUESTION WORTH ANSWERING RATHER THAN LEAVING: a disclosure
 * leaf and a blob leaf therefore hash identically, with the same prefix. That
 * is safe because a proof is only ever checked against a ROOT, and a root
 * belongs to one tree that one party built -- so presenting a blob leaf as a
 * disclosed field requires the committer to have built a tree mixing both,
 * which is the committer attacking themselves. Separating the domains would
 * mean copying blob's leaf hash to change one byte, and the copy is the worse
 * hazard. */
fzn_disclose_err_t fzn_disclose_leaf(const fzn_hash_ops_t *hash, const uint8_t *committed,
                                     size_t committed_len,
                                     uint8_t out[FZN_BLOB_HASH_LEN]);

/* The field inside a committed one, as a view over the caller's bytes.
 *
 * A VIEW RATHER THAN A COPY, on `chain.h`'s reasoning and with its warning:
 * the buffer must outlive the pointer. project.md sec 86 is what happens when
 * it does not, and it happened in this tree. */
fzn_disclose_err_t fzn_disclose_field(const uint8_t *committed, size_t committed_len,
                                      const uint8_t **field_out, size_t *field_len_out);

/* Check a disclosed field against the root its issuer signed, and hand back
 * the field.
 *
 * `field_count` is the number of fields the whole statement has, not the
 * number disclosed -- it is bound into the root, so a recipient told a
 * smaller one recomputes a different root and this refuses. */
fzn_disclose_err_t fzn_disclose_verify(const fzn_hash_ops_t *hash, const uint8_t *committed,
                                       size_t committed_len, uint64_t index,
                                       uint64_t field_count, const uint8_t *siblings,
                                       unsigned sibling_count,
                                       const uint8_t root[FZN_BLOB_HASH_LEN],
                                       const uint8_t **field_out, size_t *field_len_out);

/* A short name for `fzn_disclose_err_t`. Never NULL. */
const char *fzn_disclose_err_str(fzn_disclose_err_t err);

#endif /* FZN_DISCLOSE_H */
