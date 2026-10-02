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

#include "../session/commitment.h"

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
	FZN_LOG_PACK_ERR_CHAIN = -4      /* the trailer is missing or does not verify */
} fzn_log_pack_err_t;

const char *fzn_log_pack_err_str(fzn_log_pack_err_t err);

/* The segment at `log_path` packed into `zst_path`, its trailer chained
 * from `prev`; the segment's hash in `hash_out`. The segment is not
 * removed here. */
fzn_log_pack_err_t fzn_log_pack_segment(const char *log_path, const char *zst_path,
                                        const uint8_t prev[FZN_LOG_PACK_HASH_LEN],
                                        const fzn_hash_ops_t *hash,
                                        uint8_t hash_out[FZN_LOG_PACK_HASH_LEN]);

/* A packed segment checked: it decompresses, ends in one trailer, the
 * trailer's prev is `prev` and its hash is the chain over the bytes before
 * it. The hash in `hash_out`, so a reader walks a chain segment by segment. */
fzn_log_pack_err_t fzn_log_pack_verify(const char *zst_path,
                                       const uint8_t prev[FZN_LOG_PACK_HASH_LEN],
                                       const fzn_hash_ops_t *hash,
                                       uint8_t hash_out[FZN_LOG_PACK_HASH_LEN]);

/* EVERY SETTLED SEGMENT of `program` in `dir`, oldest first: packed,
 * chained, and removed once packed. `*packed` counts them. OK with nothing
 * packed when another instance holds the chain. */
fzn_log_pack_err_t fzn_log_pack_dir(const char *dir, const char *program,
                                    const fzn_hash_ops_t *hash, uint64_t now_us,
                                    uint64_t settle_us, size_t *packed);

#endif /* FZN_LOG_PACK_H */
