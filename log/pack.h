/* Packing closed log segments: compressed with zstd, each closed by a
 * hash-chain trailer. sec 459, the second half of step 3 in sec 456's
 * order, and the third of sec 428's formats. Built with FZN_LOG_PACK,
 * which links libzstd -- the holder's choice over running the zstd tool.
 *
 * PACKED IS ZSTD SO THAT `zstdgrep` STILL SEARCHES IT (sec 428). A packed
 * segment is `PROGRAM.TIME.PID.log.zst`: the closed segment's bytes and a
 * trailer line, one zstd frame with its content checksum on, so `zstdcat`
 * gives back the classic lines and the trailer, and a flipped bit is found
 * by zstd before anything here reads it.
 *
 * THE TRAILER CHAINS EACH SEGMENT TO THE ONE BEFORE (sec 428), a program's
 * segments in the order they were closed:
 *
 *     #fuzznet-log-trailer 1 prev=HEX hash=HEX
 *
 * `hash` is over the segment's bytes, chained from `prev`, the trailer
 * before it -- 32 zero bytes for a program's first:
 *
 *     state = prev
 *     for each 64 KiB chunk c of the segment:  state = H(state || c)
 *     hash = state
 *
 * with H the caller's 32-byte hash. A chunked chain rather than one hash
 * of the whole, because `fzn_hash_ops_t` is one-shot and a segment is
 * megabytes. Removing, reordering or editing a segment breaks the chain at
 * the next one; the trailer is what a host's key can later sign (sec 428).
 * The chain's last hash is kept in `PROGRAM.chain`.
 *
 * A SEGMENT REPACKED WITHOUT SOME OF ITS LINES (sec 474, the prune and
 * keep rules over entries) carries a version-2 trailer:
 *
 *     #fuzznet-log-trailer 2 prev=HEX hash=HEX was=HEX dropped=N
 *
 * `hash` is the chain over what is left, from the same `prev`; `was` is the
 * hash it was first packed with, which the next segment's `prev` names, so
 * the chain runs on through it; `dropped` counts the lines taken out, over
 * every repack. A reader verifies the bytes against `hash` and carries
 * `was` forward. What a repack costs is said plainly: the lines dropped are
 * gone, and only their count and the old hash witness that there were any.
 *
 * A TRAILER MAY BE SIGNED (sec 482), by the key of the node that packed or
 * repacked it, as a suffix on the line:
 *
 *     ... hash=HEX [was=HEX dropped=N] key=HEX sig=HEX
 *
 * over `fuzznet.log.trailer\0` and the line before ` key=`. An unsigned
 * trailer is still a trailer, so segments packed before signing read as
 * they did. A signed one whose signature does not hold is refused: a
 * changed signed line is what signing exists to show.
 *
 * TAMPER EVIDENCE, NOT PREVENTION: whoever can write the directory can
 * rewrite the whole chain. What it gives is that a rewrite must be of
 * everything after the change, which a signed trailer later pins.
 *
 * PACKING ORDER AND ITS RACE. Segments are packed oldest first, under a
 * POSIX record lock on `PROGRAM.chain`, so two instances never interleave
 * the chain; one finding it locked packs nothing and leaves it to the
 * other. A segment is packed only once it has been closed for `settle_us`:
 * an instance that checked its file just before another rotated it may
 * still write one line into the closed segment, and that line must land
 * before the trailer. The packed file is written as `.zst.new` and renamed;
 * only then is the segment removed.
 */

#ifndef FZN_LOG_PACK_H
#define FZN_LOG_PACK_H

#include <stddef.h>
#include <stdint.h>

#include "../chain/chain.h"
#include "../session/commitment.h"
#include "retain.h"

#define FZN_LOG_PACK_HASH_LEN 32u
/* The chunk the chain folds: 64 KiB. */
#define FZN_LOG_PACK_CHUNK (64u * 1024u)
/* A segment closed this long ago is settled: 10 seconds. */
#define FZN_LOG_PACK_SETTLE_DEFAULT (10u * 1000000u)

typedef enum fzn_log_pack_err {
	FZN_LOG_PACK_OK = 0,
	FZN_LOG_PACK_ERR_MALFORMED = -1, /* a null, a name that is not a segment's */
	FZN_LOG_PACK_ERR_FILE = -2,      /* a file would not read, write or rename */
	FZN_LOG_PACK_ERR_ZSTD = -3,      /* zstd refused, or the packed bytes are not a frame */
	FZN_LOG_PACK_ERR_CHAIN = -4,     /* the trailer is missing or does not verify */
	FZN_LOG_PACK_ERR_SIGNATURE = -5  /* a signature would not sign, or does not hold */
} fzn_log_pack_err_t;

const char *fzn_log_pack_err_str(fzn_log_pack_err_t err);

/* WHO SIGNS, sec 482: the node's key and its signer. NULL where a call
 * takes one: unsigned, as before. */
typedef struct fzn_log_pack_signer {
	uint8_t key[FZN_LOG_PACK_HASH_LEN];
	const fzn_sign_ops_t *sign;
} fzn_log_pack_signer_t;

/* The segment at `log_path` packed into `zst_path`, its trailer chained
 * from `prev` and signed by `signer` when given; the segment's hash in
 * `hash_out`. The segment is not removed here. */
fzn_log_pack_err_t fzn_log_pack_segment(const char *log_path, const char *zst_path,
                                        const uint8_t prev[FZN_LOG_PACK_HASH_LEN],
                                        const fzn_hash_ops_t *hash,
                                        const fzn_log_pack_signer_t *signer,
                                        uint8_t hash_out[FZN_LOG_PACK_HASH_LEN]);

/* A packed segment checked: it decompresses, ends in one trailer, the
 * trailer's prev is `prev` and its hash is the chain over the bytes before
 * it. The hash in `hash_out`, so a reader walks a chain segment by segment. */
fzn_log_pack_err_t fzn_log_pack_verify(const char *zst_path,
                                       const uint8_t prev[FZN_LOG_PACK_HASH_LEN],
                                       const fzn_hash_ops_t *hash,
                                       uint8_t hash_out[FZN_LOG_PACK_HASH_LEN]);

/* As `fzn_log_pack_verify`, and the signature too: `*is_signed` 1 and its
 * key in `signer_out` when the trailer is signed and the signature holds,
 * 0 when it is unsigned; SIGNATURE when it is signed and does not hold. */
fzn_log_pack_err_t fzn_log_pack_verify_signed(const char *zst_path,
                                              const uint8_t prev[FZN_LOG_PACK_HASH_LEN],
                                              const fzn_hash_ops_t *hash,
                                              const fzn_sign_ops_t *sign,
                                              uint8_t hash_out[FZN_LOG_PACK_HASH_LEN],
                                              int *is_signed,
                                              uint8_t signer_out[FZN_LOG_PACK_HASH_LEN]);

/* The prev a packed segment's own trailer names: where a chain held from
 * this segment on starts, for one whose older segments are not here. */
fzn_log_pack_err_t fzn_log_pack_trailer_prev(const char *zst_path,
                                             uint8_t prev[FZN_LOG_PACK_HASH_LEN]);

/* What `fzn_log_pack_check` found. */
typedef struct fzn_log_pack_report {
	size_t segments;      /* packed segments whose chain held */
	size_t signed_count;  /* of them, signed with a signature that held */
	uint8_t signer[FZN_LOG_PACK_HASH_LEN]; /* the first signer met */
	int signers_differ;   /* a second key signed some */
	char broken[256];     /* the segment the walk stopped at, or "" */
} fzn_log_pack_report_t;

/* THE CHAIN OF A DIRECTORY, sec 482: every packed segment of `program`,
 * oldest first, each verified against the one before -- the oldest from
 * the prev its own trailer names, since older ones may have been pruned --
 * and each signature checked. CHAIN, SIGNATURE or ZSTD at the first that
 * fails, named in `report->broken`. */
fzn_log_pack_err_t fzn_log_pack_check(const char *dir, const char *program,
                                      const fzn_hash_ops_t *hash, const fzn_sign_ops_t *sign,
                                      fzn_log_pack_report_t *report);

/* THE PRUNE AND KEEP RULES OVER ENTRIES, sec 474: `program`'s closed
 * segments in `dir`, packed or not, walked newest first through
 * `log/retain.h`'s marks and entry walk. A segment every line of which goes
 * is removed; a PACKED one some of whose lines go is repacked without them,
 * under a version-2 trailer, written beside it and renamed over it; a plain
 * one is left whole until it is packed, its lines still counted. A line
 * that will not read as an entry, and a segment's header, go only with the
 * whole segment. With no rule selecting entries this is
 * `fzn_logger_retain`'s whole-segment plan exactly. Under the chain's lock,
 * as packing is; another instance holding it is not an error. A packed
 * segment past FZN_LOG_PACK_RETAIN_READ_MAX, or one whose own trailer does
 * not verify, is kept whole and its lines not counted. `*removed` and
 * `*repacked` count segments. */
#define FZN_LOG_PACK_RETAIN_READ_MAX (64u * 1024u * 1024u)
fzn_log_pack_err_t fzn_log_pack_retain(const char *dir, const char *program,
                                       const fzn_retain_rule_t *rules, size_t n_rules,
                                       const fzn_hash_ops_t *hash,
                                       const fzn_log_pack_signer_t *signer, uint64_t now_us,
                                       size_t *removed, size_t *repacked);

/* EVERY SETTLED SEGMENT of `program` in `dir`, oldest first: packed,
 * chained, and removed once packed. `*packed` counts them. OK with nothing
 * packed when another instance holds the chain. */
fzn_log_pack_err_t fzn_log_pack_dir(const char *dir, const char *program,
                                    const fzn_hash_ops_t *hash,
                                    const fzn_log_pack_signer_t *signer, uint64_t now_us,
                                    uint64_t settle_us, size_t *packed);

#endif /* FZN_LOG_PACK_H */
