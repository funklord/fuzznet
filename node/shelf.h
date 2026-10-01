/* The node's shelf of long notes' texts, and how they travel. sec 424, the
 * second half of phase 2 of the notes move.
 *
 * `notes/text.h` seals a text into a spool and opens it back; this is where
 * those spools live on a running node and how a host holding a note but not
 * its text gets the leaves from a host that has them. The conversation is
 * `spool/message.h`'s four messages, carried as the payload of the remote hop
 * the node already serves -- no new transport, no new frame kind.
 *
 * ON DISK, under one directory, one blob per root:
 *
 *     <root hex>        the sealed leaves      (`spool/spool_file.h`)
 *     <root hex>.bits   which are present      (its sidecar)
 *     <root hex>.len    the text's length, be64
 *
 * THE LENGTH FILE IS WHAT A SERVER CANNOT DO WITHOUT. A spool reads a leaf
 * back as a whole slot, zero-filled past a short last leaf, and leaves the
 * true length to its caller (`spool/spool.h`). A server answering a WANT has
 * to hash every leaf to build the span's proof, and hashing the padded slot
 * gives another hash -- so it needs the last leaf's true length, which only
 * the text's length gives. The note carries it; a peer asking by root does
 * not, and a peer's word for it would be a length a stranger chose. So the
 * host records it when the text arrives here -- sealed here, or fetched
 * against a note that named it -- and a server trusts it only where the
 * length's leaf count agrees with the sidecar's.
 *
 * ONLY A COMPLETE BLOB IS SERVED. A proof is sibling hashes, and the hashes
 * of leaves a host does not hold are hashes it cannot compute. A host part
 * way through a fetch answers as if it held nothing.
 *
 * WHO MAY ASK. Any peer the remote hop admits, for any root: the hop has
 * already authenticated it under its session, which is also why the HAVE's
 * cookie carries nothing -- a spoofer cannot ask, so the anti-reflection the
 * cookie exists for is the session's here. And what is served is ciphertext:
 * the content key is in the note, never on the shelf (`notes/note.h`), so a
 * peer naming a root it learned without the note learns a length.
 *
 * NOTHING IS CREATED FOR A ROOT A PEER NAMES. A server looks for the sidecar
 * before opening anything (`fzn_spool_file_leaves`), because opening creates.
 */

#ifndef FZN_NODE_SHELF_H
#define FZN_NODE_SHELF_H

#include <stddef.h>
#include <stdint.h>

#include "../local/vocabulary.h"
#include "../chain/authz.h"
#include "../notes/text.h"
#include "../spool/message.h"
#include "../spool/spool_file.h"

/* The directory's length, leaving room for "/<64 hex>.bits" inside the
 * spool's own path bound. */
#define FZN_NODE_SHELF_DIR_MAX (FZN_SPOOL_FILE_PATH_MAX - 72u)

/* Leaves one DATA carries. A span is proved as a whole, so this is also the
 * retry unit (`spool/transfer.h`); sixteen is about 18 KB a reply. */
#define FZN_NODE_SHELF_SPAN 16u

/* The largest DATA a span of FZN_NODE_SHELF_SPAN makes, and so the reply
 * buffer both ends size: the node's, and the fetcher's reassembly. */
#define FZN_NODE_SHELF_REPLY_MAX                                                               \
	((size_t)FZN_MSG_DATA_OFF_PROOF + ((size_t)FZN_MSG_MAX_PROOF * FZN_BLOB_HASH_LEN)      \
	 + ((size_t)FZN_NODE_SHELF_SPAN * (4u + FZN_BLOB_SEALED_MAX)))

/* Texts waiting for their leaves. */
#define FZN_NODE_SHELF_WANTS 16u

typedef enum fzn_node_shelf_err {
	FZN_NODE_SHELF_OK = 0,
	FZN_NODE_SHELF_ERR_MALFORMED = -1,
	/* Not held here, or not all of it; or the peer holds none of it. */
	FZN_NODE_SHELF_ERR_ABSENT = -2,
	/* The disk refused. */
	FZN_NODE_SHELF_ERR_STORE = -3,
	/* The peer did not answer. */
	FZN_NODE_SHELF_ERR_NO_ANSWER = -4,
	/* The peer answered with something that is not the answer. */
	FZN_NODE_SHELF_ERR_SHAPE = -5,
	/* The peer's leaves did not prove against the root. Nothing written. */
	FZN_NODE_SHELF_ERR_UNVERIFIED = -6,
	/* Sealing or opening refused: `notes/text.h`'s error is the detail. */
	FZN_NODE_SHELF_ERR_TEXT = -7,
	/* Every want slot is taken. */
	FZN_NODE_SHELF_ERR_FULL = -8
} fzn_node_shelf_err_t;

const char *fzn_node_shelf_err_str(fzn_node_shelf_err_t err);

typedef struct fzn_node_shelf_want {
	uint8_t root[FZN_BLOB_HASH_LEN];
	uint64_t length;
	int live;
} fzn_node_shelf_want_t;

typedef struct fzn_node_shelf {
	char dir[FZN_NODE_SHELF_DIR_MAX];
	const fzn_hash_ops_t *hash;
	const fzn_aead_ops_t *aead;
	const fzn_random_ops_t *rng;
	fzn_node_shelf_want_t wants[FZN_NODE_SHELF_WANTS];
	/* Set when a want is added, for a caller that fetches on a timer to
	 * fetch now instead; the caller clears it. A text somebody just asked
	 * for should not wait out a pull period. */
	int fresh;
} fzn_node_shelf_t;

/* Over `dir`, which is created mode 0700 if it is not there. */
fzn_node_shelf_err_t fzn_node_shelf_init(fzn_node_shelf_t *shelf, const char *dir,
                                         const fzn_hash_ops_t *hash, const fzn_aead_ops_t *aead,
                                         const fzn_random_ops_t *rng);

/* Seal `text` onto the shelf under a fresh key, and say what a note names it
 * by. The root is not known until every leaf is sealed, so it is sealed under
 * a working name and renamed: a crash leaves the working name, which the next
 * put replaces, and never a blob under a root it is not. */
fzn_node_shelf_err_t fzn_node_shelf_put(fzn_node_shelf_t *shelf, const uint8_t *text, size_t len,
                                        fzn_note_blob_ref_t *ref);

/* Whether the whole of the blob `root` is here, and the text's length. */
fzn_node_shelf_err_t fzn_node_shelf_held(const fzn_node_shelf_t *shelf,
                                         const uint8_t root[FZN_BLOB_HASH_LEN],
                                         uint64_t *length);

/* Open the text `ref` names into `out`. ABSENT when it is not all here; TEXT
 * with `*text_err` set when `notes/text.h` refuses it. */
fzn_node_shelf_err_t fzn_node_shelf_open(const fzn_node_shelf_t *shelf,
                                         const fzn_note_blob_ref_t *ref, uint8_t *out,
                                         size_t out_cap, size_t *out_len,
                                         fzn_note_err_t *text_err);

/* THE SERVER: answer one `spool/message.h` request. A HAVE_QUERY gets a HAVE,
 * a WANT a DATA of the largest canonical span that fits `reply_cap`; a blob
 * not all here gets "absent". 0 when `request` is not one of the four, so a
 * caller dispatching on the first byte can fall through to its verbs. */
size_t fzn_node_shelf_answer(const fzn_node_shelf_t *shelf, const uint8_t *request,
                             size_t request_len, uint8_t *reply, size_t reply_cap);

/* How a fetch asks a peer: send `request`, fill `reply`. Nonzero on an
 * answer. The node's is the remote hop's caller; a test's is another shelf's
 * `fzn_node_shelf_answer`, which is what keeps the conversation testable
 * without a socket. */
typedef int (*fzn_node_shelf_ask_t)(void *ctx, const uint8_t *request, size_t request_len,
                                    uint8_t *reply, size_t reply_cap, size_t *reply_len);

/* THE FETCHER: get the text of `length` bytes named `root` from the peer
 * `ask` reaches, resuming what is already here. Every span is verified against
 * the root before a byte is written (`spool/spool.h`), so a peer can cost a
 * fetch bandwidth and never a wrong leaf. The length is written down first,
 * so this host can serve the text on once it is whole. */
fzn_node_shelf_err_t fzn_node_shelf_fetch(fzn_node_shelf_t *shelf,
                                          const uint8_t root[FZN_BLOB_HASH_LEN], uint64_t length,
                                          fzn_node_shelf_ask_t ask, void *ask_ctx);

/* Remember to fetch a text; OK at once when it is already here. */
fzn_node_shelf_err_t fzn_node_shelf_want(fzn_node_shelf_t *shelf,
                                         const uint8_t root[FZN_BLOB_HASH_LEN], uint64_t length);

/* Try every remembered text against one peer; those completed are forgotten.
 * Returns how many completed. */
size_t fzn_node_shelf_fetch_wants(fzn_node_shelf_t *shelf, fzn_node_shelf_ask_t ask,
                                  void *ask_ctx);

/* THE NODE'S VERBS, for `node/admin.h`'s hook. 0 when `request` is not one:
 *
 *     put text PATH     seal the file at PATH; answers the reference, hex
 *     fetch text REF    remember to fetch it from the pull peers
 *     get text REF      "here N" when it opens, "pending" when it does not
 *
 * REF is the 72-byte reference `notes/note.h` lays out, in hex. All three
 * need this node's own user: a put reads a file as the node, and a fetch
 * spends its disk. */
size_t fzn_node_shelf_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                            char *reply, size_t reply_cap);

/* The remote hop's hook: `fzn_node_shelf_answer` with `ctx` as the shelf. */
size_t fzn_node_shelf_remote(void *ctx, const uint8_t *request, size_t request_len,
                             uint8_t *reply, size_t reply_cap);

#endif /* FZN_NODE_SHELF_H */
