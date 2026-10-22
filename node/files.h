/* The node's files: blobs of any size, kept sealed in spool files. sec 490.
 *
 * WHAT IT IS FOR. The holder decided 2026-10-06 that fuzzypickles' file
 * storage moves onto fuzznet's `spool/` and `blob/`, reversing the decline
 * of 2026-09-01, and that a file referenced by an old-shape root is
 * invalidated rather than translated. This module is that store's first
 * half: putting a file, exporting it, listing what is held and deleting it.
 * Carrying files between hosts, tiers and the scrub follow (sec 490).
 *
 * IT IS THE SHELF'S SHAPE MADE TO SCALE. `node/shelf.h` keeps note texts of
 * at most 256 KiB, whose every leaf hash fits in memory. A file goes to
 * FZN_SPOOL_MAX_LEAVES leaves, 4 GiB, so its tree is kept on disk beside it
 * (`blob/levels.h`) and a file is sealed by streaming it twice: once to the
 * root, once to place every leaf through the spool's own verification.
 *
 * ON DISK, under one directory, one blob per root:
 *
 *     <root hex>        the sealed leaves       (`spool/spool_file.h`)
 *     <root hex>.bits   which are present       (its sidecar)
 *     <root hex>.len    the file's length, be64
 *     <root hex>.tree   its perfect subtrees    (`blob/levels.h`)
 *
 * A BLOB IS HELD WHEN ITS SIDECAR SAYS IT IS WHOLE. The sidecar is written
 * last when a file is put, and removed first when one is deleted, so a blob
 * is never held without its leaves, length and tree.
 *
 * THE CONTENT KEY IS NOT HERE. A put answers a reference -- root, key and
 * length, the 72 bytes `notes/note.h` lays out for a text -- and whoever
 * keeps the reference can open the file. The store holds ciphertext.
 *
 * DELETION, the holder's sixth requirement, as fuzzypickles stated it: one
 * device at a time, every file of the blob gone, never while a transfer of
 * it is running, and nothing done to whatever references it elsewhere. A
 * transfer marks its root busy for as long as it runs.
 */

#ifndef FZN_NODE_FILES_H
#define FZN_NODE_FILES_H

#include <stddef.h>
#include <stdint.h>

#include "../local/vocabulary.h"
#include "../persist/persist.h"
#include "../chain/authz.h"
#include "../blob/blob.h"
#include "../session/aead.h"
#include "../session/random.h"
#include "../spool/message.h"
#include "../spool/spool_file.h"
#include "../spool/transfer.h"

/* The directory's length, leaving room for "/<64 hex>.bits" and more. */
#define FZN_NODE_FILES_DIR_MAX (FZN_SPOOL_FILE_PATH_MAX - 80u)
/* A file's reference: root, content key, length. */
#define FZN_NODE_FILE_REF_LEN (FZN_BLOB_HASH_LEN + FZN_BLOB_KEY_LEN + 8u)
/* The largest file: as many leaves as a spool holds. */
#define FZN_NODE_FILE_MAX ((uint64_t)FZN_SPOOL_MAX_LEAVES * FZN_BLOB_LEAF_SIZE)
/* Roots a transfer may hold busy at once. */
#define FZN_NODE_FILES_BUSY_MAX 16u
/* Leaves one DATA carries: the most `spool/message.h` allows, about 68 KB a
 * reply in 67 datagrams. FEWER REQUESTS FOR THE SAME BYTES is the point, sec
 * 494: every request a node admits holds a slot of its replay window for the
 * request's 300 s lifetime, and at 16 leaves a request a sustained fetch
 * asked about 240 times a second -- a 32768-slot window full in about 2.3
 * minutes, the serving node then refusing everybody. At 64 the same bytes
 * are a quarter of the requests. */
#define FZN_NODE_FILES_SPAN 64u
#define FZN_NODE_FILES_REPLY_MAX                                                               \
	((size_t)FZN_MSG_DATA_OFF_PROOF + ((size_t)FZN_MSG_MAX_PROOF * FZN_BLOB_HASH_LEN)      \
	 + ((size_t)FZN_NODE_FILES_SPAN * (4u + FZN_BLOB_SEALED_MAX)))
/* Files a node fetches at once. */
#define FZN_NODE_FILES_WANTS_MAX 64u

typedef enum fzn_node_files_err {
	FZN_NODE_FILES_OK = 0,
	FZN_NODE_FILES_ERR_MALFORMED = -1,
	/* Not held here, or not all of it. */
	FZN_NODE_FILES_ERR_ABSENT = -2,
	/* The disk refused. */
	FZN_NODE_FILES_ERR_STORE = -3,
	/* Empty, or past FZN_NODE_FILE_MAX. */
	FZN_NODE_FILES_ERR_SIZE = -4,
	/* Sealing or opening refused: the key is not this file's, or a leaf
	 * on disk is not what was sealed. */
	FZN_NODE_FILES_ERR_CRYPTO = -5,
	/* A transfer of the blob is running. */
	FZN_NODE_FILES_ERR_BUSY = -6,
	/* An export's destination exists already. */
	FZN_NODE_FILES_ERR_EXISTS = -7,
	/* The peer did not answer. */
	FZN_NODE_FILES_ERR_NO_ANSWER = -8,
	/* The peer answered with something that is not the answer. */
	FZN_NODE_FILES_ERR_SHAPE = -9,
	/* The peer's leaves did not prove against the root. Nothing written. */
	FZN_NODE_FILES_ERR_UNVERIFIED = -10,
	/* The peer holds none of it, or not all. */
	FZN_NODE_FILES_ERR_NOT_THERE = -11
} fzn_node_files_err_t;

const char *fzn_node_files_err_str(fzn_node_files_err_t err);

typedef struct fzn_node_file_ref {
	uint8_t root[FZN_BLOB_HASH_LEN];
	uint8_t key[FZN_BLOB_KEY_LEN];
	uint64_t length;
} fzn_node_file_ref_t;

/* The 72 bytes, root then key then length big-endian, and back. */
void fzn_node_file_ref_write(const fzn_node_file_ref_t *ref, uint8_t out[FZN_NODE_FILE_REF_LEN]);
int fzn_node_file_ref_read(const uint8_t in[FZN_NODE_FILE_REF_LEN], fzn_node_file_ref_t *ref);

typedef struct fzn_node_files {
	char dir[FZN_NODE_FILES_DIR_MAX];
	const fzn_hash_ops_t *hash;
	const fzn_aead_ops_t *aead;
	const fzn_random_ops_t *rng;
	uint8_t busy[FZN_NODE_FILES_BUSY_MAX][FZN_BLOB_HASH_LEN];
	size_t n_busy;
	/* Set when a file is wanted, for a caller that fetches on a timer to
	 * fetch now instead; the caller clears it. sec 491. */
	int fresh;
	/* Where the scrub left off, sec 492: the root it checked last. */
	uint8_t scrub_after[FZN_BLOB_HASH_LEN];
	/* THE SHARES' STORE, sec 493 -- the node's, where contacts and groups
	 * live too -- or NULL: then no file is served to a contact and the
	 * share verbs are unsupported. Set by the caller after init. */
	const fzn_persist_ops_t *store;
} fzn_node_files_t;

/* Over `dir`, created mode 0700 when it is not there. */
fzn_node_files_err_t fzn_node_files_init(fzn_node_files_t *files, const char *dir,
                                         const fzn_hash_ops_t *hash, const fzn_aead_ops_t *aead,
                                         const fzn_random_ops_t *rng);

/* SEAL THE FILE AT `path` under a fresh key, and say what references it. A
 * working name holds it until it is whole and named by its root, so a crash
 * leaves the working name, which the next put replaces. */
fzn_node_files_err_t fzn_node_files_put(fzn_node_files_t *files, const char *path,
                                        fzn_node_file_ref_t *ref);

/* Whether the whole of `root` is here, and its length. */
fzn_node_files_err_t fzn_node_files_held(const fzn_node_files_t *files,
                                         const uint8_t root[FZN_BLOB_HASH_LEN],
                                         uint64_t *length);

/* EXPORT the file `ref` names to a new file at `path`, opening every leaf
 * with its key. EXISTS when `path` does; a partial export is removed. */
fzn_node_files_err_t fzn_node_files_export(const fzn_node_files_t *files,
                                           const fzn_node_file_ref_t *ref, const char *path);

/* DELETE every file of `root`: the sidecar first, so it stops being held
 * before its leaves go. ABSENT when nothing of it is here; BUSY while a
 * transfer of it runs. */
fzn_node_files_err_t fzn_node_files_remove(fzn_node_files_t *files,
                                           const uint8_t root[FZN_BLOB_HASH_LEN]);

/* The whole blobs held, `cap` at most, in order of root; `*count` how many
 * there are in all. */
fzn_node_files_err_t fzn_node_files_list(const fzn_node_files_t *files,
                                         uint8_t (*roots)[FZN_BLOB_HASH_LEN], size_t cap,
                                         size_t *count);

/* A TRANSFER'S ROOT, held busy while it runs so it is not deleted under it,
 * and let go. FULL past FZN_NODE_FILES_BUSY_MAX is MALFORMED. */
fzn_node_files_err_t fzn_node_files_busy(fzn_node_files_t *files,
                                         const uint8_t root[FZN_BLOB_HASH_LEN], int busy);

/* ---- carrying files between hosts, sec 491 ----------------------------
 *
 * THE SHELF'S CONVERSATION (`spool/message.h`'s four messages over the
 * remote hop), with the proofs read from the blob's tree on disk: a HAVE
 * query first, so a peer holding nothing costs one round trip, then a WANT
 * for each canonical span still missing and a DATA answering it, every span
 * verified against the root before a byte of it is written.
 *
 * A WANT IS ITS LENGTH ON DISK. Wanting a file writes its `.len` first, so a
 * `.len` with no whole blob beside it is a file this node is fetching, and a
 * restart picks it up from what the sidecar says is here. Nothing else keeps
 * a list. `remove file` takes a want back as it deletes a file.
 *
 * WHO MAY ASK is the caller's: the node answers the members its remote hop
 * admits, as the shelf does. A contact is served no file; tiers are open
 * (sec 490). Only a WHOLE blob is served -- its tree is built when the last
 * leaf lands, from the leaves read back -- so a host part way through a
 * fetch answers as if it held nothing.
 */

/* THE SERVER: a HAVE_QUERY or a WANT for a file held here whole, answered;
 * 0 for anything else, a root not held included, so a caller can ask the
 * shelf next. */
size_t fzn_node_files_answer(const fzn_node_files_t *files, const uint8_t *request,
                             size_t request_len, uint8_t *reply, size_t reply_cap);

/* How a fetch asks a peer: send `request`, fill `reply`. Nonzero on an
 * answer. */
typedef int (*fzn_node_files_ask_t)(void *ctx, const uint8_t *request, size_t request_len,
                                    uint8_t *reply, size_t reply_cap, size_t *reply_len);

/* WANT the file `root` of `length`: its length written down, so it is
 * fetched until it is here. OK at once when it is held already. */
fzn_node_files_err_t fzn_node_files_want(fzn_node_files_t *files,
                                         const uint8_t root[FZN_BLOB_HASH_LEN], uint64_t length);

/* The files wanted and not yet whole, `cap` at most. */
size_t fzn_node_files_wanted(const fzn_node_files_t *files, uint8_t (*roots)[FZN_BLOB_HASH_LEN],
                             uint64_t *lengths, size_t cap);

/* THE FETCHER: up to `budget` leaves of the wanted file `root` from the peer
 * `ask` reaches, resuming what is here, the root held busy while it runs.
 * `*placed` counts leaves placed; OK when the file is whole -- its tree
 * built -- and ABSENT when it is not whole yet, the budget spent. */
fzn_node_files_err_t fzn_node_files_fetch(fzn_node_files_t *files,
                                          const uint8_t root[FZN_BLOB_HASH_LEN],
                                          fzn_node_files_ask_t ask, void *ask_ctx,
                                          uint64_t budget, uint64_t *placed);

/* ---- the scrub, sec 492 -------------------------------------------------
 *
 * RE-VERIFY A FILE AT REST: every leaf read back and hashed at the length
 * the file's length gives it. A leaf placed was proved when it arrived and
 * never again, so this is the only thing that sees a bad sector or a file
 * changed underneath (`spool/spool.h`, "integrity at rest").
 *
 * THE TREE SAYS WHICH LEAF WENT BAD. Each leaf's hash is compared with the
 * tree's level 0, and when the tree itself still folds to the root, exactly
 * the leaves that differ are forgotten. When the tree does not, every leaf
 * goes, and the tree with it; when only the tree is wrong, it is rebuilt
 * from the leaves.
 *
 * REPAIR IS A FETCH. A leaf forgotten stops the blob being whole, and its
 * length stays, so it is a want (sec 491): the next fetch asks for exactly
 * what was dropped. Nothing is deleted -- the bytes stay until overwritten.
 *
 * `*dropped` counts leaves forgotten; ABSENT when the blob is not here
 * whole, which is not checked and not touched. */
fzn_node_files_err_t fzn_node_files_verify(fzn_node_files_t *files,
                                           const uint8_t root[FZN_BLOB_HASH_LEN],
                                           uint64_t *dropped);

/* ONE STEP: the next whole file after the one checked last, in order of
 * root and wrapping, so steps taken on a timer cover the store in turn.
 * `*checked` is 0 or 1. */
fzn_node_files_err_t fzn_node_files_scrub_step(fzn_node_files_t *files, int *checked,
                                               uint64_t *dropped);

/* ---- tiers: who besides the members may fetch a file, sec 493 -----------
 *
 * THE HOLDER'S DECISION, 2026-10-07: a PRIVATE file is served to this
 * estate's members and to the contacts and groups it is shared with; a
 * PUBLIC one to every contact of this node as well. A file is private until
 * it is shared or made public.
 *
 * A SHARE IS A ROW in persist slot 29 -- the root and a grantee: a
 * contact's key, a group's id, or FZN_NODE_FILES_EVERY_CONTACT -- filed
 * under a hash of the two, and CORE: a row rolled back is a contact
 * fetching a file after it was unshared. A group's membership is read at the
 * request, as a notes share's is (sec 471). Deleting a file deletes its
 * rows; forgetting a grantee -- a group removed -- deletes its rows, so a
 * group made again under the name reaches nothing it did not share (sec
 * 478's rule).
 *
 * THE CONTACT ASKING has already been found a contact and served by the
 * share capability (`node/admin.c`); this answers only which files. */
#define FZN_NODE_FILES_SHARES_MAX 256u

/* A grantee meaning every contact of this node. */
extern const uint8_t FZN_NODE_FILES_EVERY_CONTACT[FZN_PUBKEY_LEN];

/* Share the file `root`, held here, with `grantee` -- or with `add` 0,
 * stop. ABSENT when the file is not held (sharing) or the share was not
 * there (stopping). */
fzn_node_files_err_t fzn_node_files_share(fzn_node_files_t *files,
                                          const uint8_t root[FZN_BLOB_HASH_LEN],
                                          const uint8_t grantee[FZN_PUBKEY_LEN], int add,
                                          uint64_t now_ms);

/* The grantees of `root`, `cap` at most; `*count` how many. */
fzn_node_files_err_t fzn_node_files_shares_of(const fzn_node_files_t *files,
                                              const uint8_t root[FZN_BLOB_HASH_LEN],
                                              uint8_t (*grantees)[FZN_PUBKEY_LEN], size_t cap,
                                              size_t *count);

/* Whether the contact `sender` may fetch `root`: the file is public, or
 * shared with it, or with a group it is in. */
int fzn_node_files_shared_with(const fzn_node_files_t *files,
                               const uint8_t root[FZN_BLOB_HASH_LEN],
                               const uint8_t sender[FZN_PUBKEY_LEN]);

/* Every row for `grantee` deleted, `*removed` of them. */
fzn_node_files_err_t fzn_node_files_forget(fzn_node_files_t *files,
                                           const uint8_t grantee[FZN_PUBKEY_LEN],
                                           size_t *removed);

/* THE SERVER FOR A CONTACT: `fzn_node_files_answer` for a HAVE_QUERY or a
 * WANT whose root `sender` may fetch, and 0 for any other -- the root read
 * from the request itself, so the question asked and the one permitted are
 * one. */
size_t fzn_node_files_answer_shared(const fzn_node_files_t *files, const uint8_t *sender,
                                    const uint8_t *request, size_t request_len,
                                    uint8_t *reply, size_t reply_cap);

/* ---- several peers at once, sec 494 ------------------------------------
 *
 * fuzzypickles' second requirement: parallel batches and an adaptive
 * window. A fetch asks every peer whether it holds the file whole, then
 * keeps spans in flight across all that do, `spool/transfer.h` deciding
 * which: two peers are never sent the same span, a span a peer does not
 * answer in time goes back to be asked of another, and the window opens by
 * one a window of deliveries and halves on a loss (AIMD, no slow start).
 * A peer that fails three times running -- spans that did not prove, or
 * did not come -- is asked nothing more this fetch.
 *
 * A PEER IS TWO CALLS: send a request, saying which message it went out as;
 * and poll for the reply to any of them, saying which it answers. The node's
 * are a caller's (`fzn_caller_send`, `fzn_caller_recv_any`); a test's are
 * another store's answer, queued. No socket here.
 */
#define FZN_NODE_FILES_PEERS_MAX 16u
/* How long a span may be out before it is asked of somebody else. */
#define FZN_NODE_FILES_SPAN_DEADLINE_MS 3000u

typedef struct fzn_node_files_peer {
	int (*send)(void *ctx, const uint8_t *request, size_t request_len, uint32_t *msg);
	/* 1 with a reply to one of this peer's messages, 0 when none came in
	 * `timeout_ms`. */
	int (*poll)(void *ctx, uint8_t *reply, size_t reply_cap, size_t *reply_len, uint32_t *msg,
	            unsigned timeout_ms);
	void *ctx;
} fzn_node_files_peer_t;

/* THE FETCHER OVER SEVERAL PEERS: up to `budget` leaves of the wanted file
 * `root`, `now_ms` the caller's clock, at most `window` spans out at once --
 * the window's ceiling, which a peer's reassembly must have the slots for,
 * up to FZN_TRANSFER_MAX_ASSIGNS. `*placed` counts leaves placed and
 * `*holders` the peers that said they hold it whole. OK when the file is
 * whole, ABSENT when the budget ran out first, NOT_THERE when no peer holds
 * it, and otherwise why the last peer was given up on. */
fzn_node_files_err_t fzn_node_files_fetch_many(fzn_node_files_t *files,
                                               const uint8_t root[FZN_BLOB_HASH_LEN],
                                               const fzn_node_files_peer_t *peers, size_t n_peers,
                                               uint64_t (*now_ms)(void), size_t window,
                                               uint64_t budget, uint64_t *placed,
                                               size_t *holders);

/* ---- the fetch as steps, sec 694 ---------------------------------------
 *
 * THE SAME FETCH, ITS STATE IN A STRUCT, so the loop sends each request,
 * goes on answering its own clients, and hands the fetch each answer when
 * it comes -- the holder's choice, 2026-10-22, after sec 693 measured a
 * fetch keeping a host's local socket waiting 22.7 s. The resumable
 * round's shape (sec 636), and `fzn_node_files_fetch_many` above is these
 * steps driven by its peers' blocking `poll`.
 *
 * A REQUEST IS NAMED BY A TAG, which its answer is handed back with: a
 * peer's "do you hold it whole" while the fetch learns who holds it, and a
 * span asked of a holder after. A tag carries a generation, so the answer
 * to a span since asked of somebody else is told apart and dropped.
 *
 *   `fzn_node_files_fetching_begin`  the file claimed: OK, or why not --
 *                                    OK and over at once when it is held
 *   `fzn_node_files_fetching_next`   1 with the next request to send, its
 *                                    peer and its tag; 0 for none now --
 *                                    the window full, the budget spent, or
 *                                    the holders not all answered
 *   `fzn_node_files_fetching_take`   a tag's answer, or with `reply` NULL
 *                                    none: the deadline passed, or it could
 *                                    not be sent
 *   `fzn_node_files_fetching_over`   1 when nothing more will be asked
 *   `fzn_node_files_fetching_end`    the fetch closed: OK when the file is
 *                                    whole, as `fetch_many` answers
 *
 * ONE FETCH AT A TIME IN A PROCESS: what has arrived is kept in one bitmap
 * of the module's, sized for the largest file. */
#define FZN_NODE_FILES_TAG_HOLDS 0x80000000u

typedef struct fzn_node_files_open {
	fzn_spool_file_t file;
	fzn_spool_t spool;
	uint64_t length;
	uint64_t leaves;
	size_t last;
} fzn_node_files_open_t;

typedef struct fzn_node_files_fetching {
	fzn_node_files_t *files;
	uint8_t root[FZN_BLOB_HASH_LEN];
	size_t n_peers, window;
	uint64_t budget, placed, steps;
	int phase; /* 0 asking who holds it, 1 fetching, 2 over */
	int opened, busy;
	fzn_node_files_err_t err, last;
	fzn_node_files_open_t h;
	fzn_transfer_t transfer;
	fzn_transfer_assign_t assigns[FZN_TRANSFER_MAX_ASSIGNS];
	struct {
		int live;
		size_t peer;
		uint32_t transfer;
		uint32_t gen;
		fzn_spool_range_t range;
	} out[FZN_TRANSFER_MAX_ASSIGNS];
	uint8_t cookies[FZN_NODE_FILES_PEERS_MAX][FZN_MSG_COOKIE_LEN];
	unsigned failures[FZN_NODE_FILES_PEERS_MAX];
	int alive[FZN_NODE_FILES_PEERS_MAX];
	int asked[FZN_NODE_FILES_PEERS_MAX];  /* 0 not, 1 out, 2 answered */
	size_t live_peers, holders, n_out, turn;
	uint32_t next_transfer, gen;
	unsigned since_checkpoint;
} fzn_node_files_fetching_t;

fzn_node_files_err_t fzn_node_files_fetching_begin(fzn_node_files_fetching_t *f,
                                                   fzn_node_files_t *files,
                                                   const uint8_t root[FZN_BLOB_HASH_LEN],
                                                   size_t n_peers, size_t window,
                                                   uint64_t budget);

int fzn_node_files_fetching_next(fzn_node_files_fetching_t *f, uint64_t now_ms, size_t *peer,
                                 uint32_t *tag, uint8_t *request, size_t cap,
                                 size_t *request_len);

void fzn_node_files_fetching_take(fzn_node_files_fetching_t *f, uint32_t tag,
                                  const uint8_t *reply, size_t reply_len, uint64_t now_ms);

int fzn_node_files_fetching_over(const fzn_node_files_fetching_t *f);

fzn_node_files_err_t fzn_node_files_fetching_end(fzn_node_files_fetching_t *f, uint64_t *placed,
                                                 size_t *holders);

/* How long a span may be out before it is asked of somebody else, in
 * milliseconds: FZN_NODE_FILES_SPAN_DEADLINE_MS, or sec 692's bench's in a
 * test build -- the deadline a stepped fetch's caller gives each request. */
unsigned long fzn_node_files_span_deadline_ms(void);

/* ---- what the clients ask of a file, sec 495 --------------------------
 *
 * fuzzypickles' clients, measured against what they call today: progress
 * while a file arrives, a ranged read of what has arrived, the tier a file
 * was actually stored under, and a check at rest on request. */

typedef struct fzn_node_file_status {
	uint64_t length;  /* bytes */
	uint64_t held;    /* leaves here */
	uint64_t total;   /* leaves in all */
	int whole;        /* held whole, its tree beside it: served and exported */
	int wanted;       /* being fetched */
	int busy;         /* a transfer is running on it now */
	int public_;      /* served to every contact */
	size_t shares;    /* contacts and groups it is shared with */
} fzn_node_file_status_t;

/* WHERE A FILE STANDS: held whole, or wanted and how much is here. ABSENT
 * when it is neither. */
fzn_node_files_err_t fzn_node_files_status(const fzn_node_files_t *files,
                                           const uint8_t root[FZN_BLOB_HASH_LEN],
                                           fzn_node_file_status_t *status);

/* A RANGED READ of the file `ref` names: `len` bytes from `offset` opened
 * with its key into a new file at `path`, WHILE IT ARRIVES -- every leaf the
 * range touches must be here, and each was proved against the root as it
 * landed. ABSENT, with nothing written, when the fetch has not reached the
 * range; MALFORMED past the file's end. `*whole` says whether the file is. */
fzn_node_files_err_t fzn_node_files_read_range(const fzn_node_files_t *files,
                                               const fzn_node_file_ref_t *ref, uint64_t offset,
                                               uint64_t len, const char *path, int *whole);

/* THE NODE'S VERBS, for `node/admin.h`'s hook; 0 when `request` is not one:
 *
 *     put file PATH [public] seal the file at PATH; answers its reference and
 *                            the tier written: `ok REF private|public`
 *     get file REF PATH      export it to PATH, a file that is not there
 *     get file REF OFFSET LENGTH PATH
 *                            that range, while the file arrives, sec 495:
 *                            `ok whole|partial`; a PATH of two numbers is
 *                            read as a range, so name one absolutely
 *     get file ROOT          `ok HELD TOTAL LENGTH whole|partial|fetching
 *                            private|public SHARES [busy]`, sec 495
 *     get file ROOT check    the check at rest, now: `ok intact` or
 *                            `ok dropped N`, sec 495
 *     fetch file REF         fetch it from the pull peers, the contacts
 *                            sharing with this node and the siblings it
 *                            reaches, secs 491, 493, 579
 *     remove file ROOT       delete it here, or stop fetching it
 *     list file [FROM]       `ok TOTAL FROM ROOT,LENGTH[,public][,shared] ...`,
 *                            files arriving after the whole ones, marked
 *                            `,fetching=HELD/TOTAL`, sec 495
 *     set file ROOT public|private
 *     grant file ROOT NAME|@GROUP     share it with a contact or a group
 *     revoke file ROOT NAME|@GROUP    stop
 *
 * REF is the reference in hex, ROOT the root. All need this node's own
 * user: a put reads a file as the node, an export writes one. */
size_t fzn_node_files_local(void *ctx, fzn_origin_t origin, const fzn_request_t *request,
                            char *reply, size_t reply_cap);

#endif /* FZN_NODE_FILES_H */
