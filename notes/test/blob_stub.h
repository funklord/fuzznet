/* A NOTE'S CONTENT, AS A TEST SEALS IT: what `fzn_notes_seal_fn` and
 * `fzn_notes_open_fn` ask, with no shelf behind them. project.md sec 514.
 *
 * Since sec 514 every note's content is a sealed blob, so every suite that
 * writes a note needs somewhere to seal it. The node's shelf is the real
 * one; this keeps each payload in a static arena under a root that is only
 * its slot number, with no cipher. It draws each blob a key and refuses to
 * open under any other, as the shelf's AEAD does: a stand-in that ignored the
 * key could not tell a wrapped one from an unwrapped one (sec 520), and once
 * did not. What is under test is the
 * notes model handing content over and taking it back, not the blob layer,
 * which `notes/test/text_test.c` covers.
 *
 * ONE ARENA FOR EVERY HOST in a suite, so a record synced from one store to
 * another finds its content on arrival; `blob_stub_drop` drops one blob,
 * which is how a suite makes a note's content not here yet.
 *
 * Header-only and static inline, so each suite that includes it has its own
 * copy, takes only what it calls, and none of it reaches the library.
 */

#ifndef FZN_NOTES_TEST_BLOB_STUB_H
#define FZN_NOTES_TEST_BLOB_STUB_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../author.h"

#define BLOB_STUB_SLOTS 4096u
#define BLOB_STUB_ARENA (8u * 1024u * 1024u)

static struct {
	uint8_t arena[BLOB_STUB_ARENA];
	size_t used;
	size_t at[BLOB_STUB_SLOTS];
	size_t len[BLOB_STUB_SLOTS];
	uint8_t key[BLOB_STUB_SLOTS][FZN_BLOB_KEY_LEN];
	size_t count;
	/* Seals refused while set, as a full shelf would refuse them. */
	int refuse;
} blob_stub;

static inline int blob_stub_seal(void *ctx, const uint8_t *payload, size_t len,
                                 fzn_note_blob_ref_t *ref)
{
	size_t slot = blob_stub.count;

	(void)ctx;
	if (blob_stub.refuse || !payload || !ref || len == 0u || slot >= BLOB_STUB_SLOTS
	    || len > BLOB_STUB_ARENA - blob_stub.used)
		return 0;
	memcpy(blob_stub.arena + blob_stub.used, payload, len);
	blob_stub.at[slot] = blob_stub.used;
	blob_stub.len[slot] = len;
	blob_stub.used += len;
	blob_stub.count++;
	memset(ref, 0, sizeof(*ref));
	/* THE SLOT IS THE ROOT, and one past it, so no root is all-zero. */
	ref->root[0] = (uint8_t)((slot + 1u) >> 8);
	ref->root[1] = (uint8_t)(slot + 1u);
	ref->length = len;
	/* A KEY OF ITS OWN, from the slot, as a fresh key per blob. */
	memset(ref->key, 0xb0 ^ (int)(slot & 0xffu), sizeof(ref->key));
	ref->key[1] = (uint8_t)(slot >> 8);
	memcpy(blob_stub.key[slot], ref->key, sizeof(ref->key));
	return 1;
}

static inline int blob_stub_open(void *ctx, const fzn_note_blob_ref_t *ref, uint8_t *out,
                                 size_t cap, size_t *out_len)
{
	size_t slot;

	(void)ctx;
	if (!ref || !out || !out_len)
		return 0;
	slot = (((size_t)ref->root[0] << 8) | ref->root[1]);
	if (slot == 0u || slot > blob_stub.count || blob_stub.len[slot - 1u] != ref->length
	    || ref->length > cap
	    || memcmp(blob_stub.key[slot - 1u], ref->key, sizeof(ref->key)) != 0)
		return 0;
	memcpy(out, blob_stub.arena + blob_stub.at[slot - 1u], (size_t)ref->length);
	*out_len = (size_t)ref->length;
	return 1;
}

/* Drop the one blob `ref` names, as a host that never fetched it. */
static inline void blob_stub_drop(const fzn_note_blob_ref_t *ref)
{
	size_t slot = (((size_t)ref->root[0] << 8) | ref->root[1]);

	if (slot != 0u && slot <= blob_stub.count)
		blob_stub.len[slot - 1u] = (size_t)-1;
}

/* The root of the blob sealed last. */
static inline void blob_stub_last_root(uint8_t root[FZN_BLOB_HASH_LEN])
{
	memset(root, 0, FZN_BLOB_HASH_LEN);
	root[0] = (uint8_t)(blob_stub.count >> 8);
	root[1] = (uint8_t)blob_stub.count;
}

/* An author's hooks onto this stub. */
static inline void blob_stub_attach(fzn_notes_author_t *a)
{
	a->seal = blob_stub_seal;
	a->open = blob_stub_open;
	a->text_ctx = NULL;
}

/* `node`'s title through this stub, or NULL with `*len` 0 when it will not
 * read. The bytes are a static copy, good until the next call. */
static inline const uint8_t *blob_stub_title(const fzn_notes_store_t *store,
                                             const fzn_tree_node_t *node, size_t *len)
{
	static uint8_t buf[FZN_NOTE_PAYLOAD_MAX];
	fzn_note_meta_t meta;
	fzn_note_t note;

	*len = 0;
	if (fzn_notes_read(store, blob_stub_open, NULL, node, &meta, buf, sizeof(buf), &note)
	    != FZN_NOTES_OK)
		return NULL;
	*len = note.title_len;
	return note.title;
}

#endif /* FZN_NOTES_TEST_BLOB_STUB_H */
