/* A long note's text, held as a blob. sec 423, phase 2 of the notes move.
 *
 * `notes/note.h` gives a long note a 72-byte reference -- root, content key,
 * length -- in place of its text. This is the other end of that reference:
 * sealing a text into a `spool/` under a fresh key, opening it back, and
 * saying what state a note's text is in on this host. How the leaves travel
 * between hosts is the next half of phase 2 and not here.
 *
 * A FRESH KEY PER TEXT, from the caller's random source, because `blob/`
 * seals deterministically from the key and the leaf index: one key over two
 * different texts repeats (key, index) pairs and breaks the AEAD. So an edit
 * is a new blob under a new key, never an in-place rewrite.
 *
 * THE STATE A NOTE'S TEXT IS IN is the thing fuzzypickles' requirement made
 * visible: a note may exist, be verified, be correctly placed in the tree,
 * and still have no readable text yet. `fzn_note_text_state` names it, so a
 * UI shows "not here yet" rather than an empty note -- and a broken reference
 * is its own answer, not a pending one that never arrives.
 *
 * A POLICY BOUND, FZN_NOTE_TEXT_MAX. Sealing builds every leaf's inclusion
 * proof, which needs every leaf hash at once, and this library allocates
 * nothing; 256 KiB is 256 leaves and 8 KiB of hashes on the stack. That is
 * about forty thousand words -- far past a note, and a deliberate change to
 * raise.
 */

#ifndef FZN_NOTE_TEXT_H
#define FZN_NOTE_TEXT_H

#include <stddef.h>
#include <stdint.h>

#include "note.h"
#include "../session/aead.h"
#include "../session/random.h"
#include "../spool/spool.h"

#define FZN_NOTE_TEXT_MAX (256u * 1024u)
#define FZN_NOTE_TEXT_LEAVES_MAX (FZN_NOTE_TEXT_MAX / FZN_BLOB_LEAF_SIZE)
/* The completion bitmap a text's spool needs, one bit per leaf. */
#define FZN_NOTE_TEXT_PRESENT_LEN ((FZN_NOTE_TEXT_LEAVES_MAX + 7u) / 8u)

/* Seal `text` into `spool`, opened here over `ops` and `present` (at least
 * FZN_NOTE_TEXT_PRESENT_LEN bytes), under a content key drawn from `rng`,
 * and fill `ref` with what a note names it by. Every leaf is placed through
 * `fzn_spool_place`, so it is verified against the root before it is written,
 * as a stranger's would be. LEN for an empty text or one past
 * FZN_NOTE_TEXT_MAX: an empty text is inline. */
fzn_note_err_t fzn_note_text_seal(const fzn_hash_ops_t *hash, const fzn_aead_ops_t *aead,
                                  const fzn_random_ops_t *rng, const uint8_t *text, size_t len,
                                  const fzn_spool_ops_t *ops, uint8_t *present,
                                  size_t present_len, fzn_spool_t *spool,
                                  fzn_note_blob_ref_t *ref);

/* Open the text `ref` names from `spool` into `out`. MISMATCH when the spool
 * holds another blob or another leaf count; ABSENT when it is not complete;
 * CAPACITY when `out` is too small; CRYPTO when a leaf will not open under
 * the reference's key -- which is also how a length the blob does not have
 * is refused, when it implies the same leaf count: the root binds the count,
 * and the last leaf opens only at the length it was sealed at. `*out_len` is
 * ref->length on success. */
fzn_note_err_t fzn_note_text_open(const fzn_hash_ops_t *hash, const fzn_aead_ops_t *aead,
                                  const fzn_spool_t *spool, const fzn_note_blob_ref_t *ref,
                                  uint8_t *out, size_t out_cap, size_t *out_len);

typedef enum fzn_note_text_state {
	/* The text is in the note itself. */
	FZN_NOTE_TEXT_INLINE = 0,
	/* A blob, and all of it is here. */
	FZN_NOTE_TEXT_HERE = 1,
	/* A blob that is not all here yet: verified and placed, unreadable. */
	FZN_NOTE_TEXT_PENDING = 2,
	/* A reference that names nothing, which no fetch will ever complete. */
	FZN_NOTE_TEXT_BROKEN = 3
} fzn_note_text_state_t;

/* What state `note`'s text is in, given the spool this host holds for its
 * blob -- NULL when it holds none. A spool for another blob is not this
 * note's text, so it answers PENDING, not HERE. */
fzn_note_text_state_t fzn_note_text_state(const fzn_note_t *note, const fzn_spool_t *spool);

#endif /* FZN_NOTE_TEXT_H */
