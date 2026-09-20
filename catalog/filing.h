/* FILING: where THIS host puts the bytes, and moving them when that changes.
 * project.md sec 317 step 6, and sec 323.
 *
 * WHY THE NAME, kept from catalog/catalog.h because the reasoning survives:
 * `layout` is this tree's word for a WIRE layout and is used two hundred times
 * that way, so reusing it here would be two concepts sharing one word, which
 * code-style.md forbids. A filing is how a host files its catalogue, the verb
 * is what the mover does -- refile -- and the noun survives being said out
 * loud about a directory tree.
 *
 * IT IS A CHOICE AMONG LINKS THE ENTITY ALREADY HAS, not a second structure.
 * sec 315 settled that a curated link is an ATTRIBUTE whose NAME is the
 * dimension and whose VALUE is a path in that dimension's tree, and that an
 * entity linked several times is several assertions merged as UNION. So an
 * entity may sit in many places at once, and a filing says which ONE of them
 * this host writes to disk. That keeps the filing a SUBSET of what the records
 * assert, which is what stops the two disagreeing -- exactly the property the
 * old module got from marking an existing membership edge.
 *
 * AND THE PATH NEEDS NO WALK, which is the piece that got smaller. The old
 * filing was a mark on an edge, so a node's path was found by walking filing
 * parents upward -- bounded at 64, because filing A under B and B under A made
 * a cycle expressible. Here the link's VALUE is already the path, so there is
 * nothing to walk, no depth to bound, and no cycle to express.
 *
 * "EXACTLY ONCE" IS STRUCTURAL AND NOT CHECKED. At most one row per entity,
 * and setting one replaces whatever was there -- so the invariant cannot be
 * violated rather than being validated afterwards. A check that swept the
 * table looking for a second row would be a check somebody has to remember to
 * run.
 *
 * AND IT DOES NOT TRAVEL (C5a HOST). There is no wire form here, no encode and
 * no decode, and nothing takes an issuer, because the only issuer a filing
 * could have is the host reading it. Two hosts sharing a catalogue agree about
 * the links and choose their own filing; a filing that synced would make one
 * host's disk layout an assertion the other had to accept.
 *
 * A STALE FILING IS REFUSED AT READ, NOT CLEARED AT WRITE, AND THAT IS THE ONE
 * RULE THAT HAD TO MOVE. The old module cleared a filing when its edge was
 * unlinked, because it owned the edge table and could hook the removal. This
 * model owns no assertions -- they are the caller's set -- so there is no
 * unlink to hook. `fzn_catalog_filed_under` therefore re-checks the set on
 * every call and answers NOTHING for a filing no live curated assertion backs
 * any more. Otherwise a host computes a path from a membership nobody asserts,
 * which is precisely what the old rule existed to prevent, arriving by a
 * different route. `fzn_catalog_filing_prune` is how the slots come back,
 * deliberately and at a moment of the caller's choosing, for the same reason
 * `fzn_catalog_due` does not reclaim its own rows.
 */

#ifndef FZN_CATALOG_FILING_H
#define FZN_CATALOG_FILING_H

#include <stddef.h>
#include <stdint.h>

#include "catalog.h"
#include "retention.h"

/* The longest dimension name and path value a filing row carries.
 *
 * BOUNDED BECAUSE A ROW OUTLIVES THE CALL THAT WROTE IT, which is the same
 * reason retention.h bounds its key: `fzn_catalog_referenced` and friends
 * borrow a view and never store it, and a table cannot. The bounds are the
 * attribute's own -- a name's length field is one byte, and a path long enough
 * to exceed this is one no filesystem will take either. A longer name or value
 * is refused rather than truncated: a truncated path names a different place,
 * and moving a file there is not a smaller error than refusing. */
#define FZN_CATALOG_FILING_NAME_MAX 64u
#define FZN_CATALOG_FILING_PATH_MAX 192u

/* One host's choice for one entity. */
typedef struct fzn_catalog_filing {
	uint8_t entity[FZN_CATALOG_ENTITY_LEN];
	uint8_t name[FZN_CATALOG_FILING_NAME_MAX];
	size_t  name_len;
	uint8_t path[FZN_CATALOG_FILING_PATH_MAX];
	size_t  path_len;
} fzn_catalog_filing_t;

typedef struct fzn_catalog_filings {
	fzn_catalog_filing_t *rows;
	size_t capacity;
	size_t used;
} fzn_catalog_filings_t;

/* Point a table at caller-owned rows. A zero capacity is legal and gives a
 * host that files nothing -- which is an ordinary state for one that has not
 * placed anything on disk yet, not an error. */
fzn_catalog_err_t fzn_catalog_filings_init(fzn_catalog_filings_t *filings,
                                               fzn_catalog_filing_t *rows,
                                               size_t capacity);

/*
 * File `entity` at `path` in dimension `name`, replacing wherever it was
 * filed before.
 *
 * THE LINK MUST ALREADY BE ASSERTED, which is what keeps a filing a subset of
 * the records. FZN_CATALOG_ERR_ABSENT when no LIVE assertion in `set` names
 * this (entity, name, value) -- a caller filing an entity somewhere the
 * records do not put it has the two out of step, and saying so is more use
 * than quietly inventing the link.
 *
 * A HOLDER ASSERTION IS NOT A LINK and cannot back a filing, for the reason
 * sec 321 records: it says where bytes are, not where they belong.
 *
 * FZN_CATALOG_ERR_RANGE when a new row does not fit, or when the name or
 * path is longer than a row can carry. An entity that already has a row is
 * rewritten in place and cannot fail for want of space.
 */
fzn_catalog_err_t fzn_catalog_file_under(fzn_catalog_filings_t *filings,
                                             const fzn_catalog_assertion_t *set,
                                             size_t count, const uint8_t *entity,
                                             size_t entity_len, const uint8_t *name,
                                             size_t name_len, const uint8_t *path,
                                             size_t path_len);

/* Remove this entity's filing, if it has one. Not an error when it has none. */
fzn_catalog_err_t fzn_catalog_unfile(fzn_catalog_filings_t *filings,
                                         const uint8_t *entity, size_t entity_len);

/*
 * Where this host files `entity`, or NULL when nowhere.
 *
 * RE-CHECKED AGAINST `set` ON EVERY CALL. A row whose link is no longer
 * asserted live answers NULL, because a path computed from a membership nobody
 * asserts is worse than no path -- see the header comment. The row stays until
 * `fzn_catalog_filing_prune` takes it, so this is a read and stays one.
 *
 * An entity with links but no filing is one this host has not placed on disk
 * yet, which is ordinary and not an error.
 */
const fzn_catalog_filing_t *fzn_catalog_filed_under(
        const fzn_catalog_filings_t *filings, const fzn_catalog_assertion_t *set,
        size_t count, const uint8_t *entity, size_t entity_len);

/* Drop every row no live curated assertion backs any more, and return how many
 * were dropped. The counterpart to `filed_under` refusing them: that keeps a
 * host from acting on a stale filing, and this is what gives the slots back. */
size_t fzn_catalog_filing_prune(fzn_catalog_filings_t *filings,
                                  const fzn_catalog_assertion_t *set, size_t count);

/* How many filings are held. */
size_t fzn_catalog_filing_count(const fzn_catalog_filings_t *filings);

/*
 * THE REFILE: moving every file into the formation a new filing describes.
 *
 * The holder's requirements, in their own terms: the catalogue is LOCKED for
 * the duration, PROGRESS can be read, the only thing that can be done during
 * the process is ask for progress, and the job SURVIVES CRASHES AND RESTARTS.
 *
 * THIS LIBRARY MOVES NO FILES. It computes, for each entity, the path it had
 * and the path it should have; a consumer performs the move and says when it
 * is done. That is the division record/store.h and spool/spool.h make, and it
 * is what keeps a catalogue usable on a host whose storage is not a filesystem
 * at all.
 *
 * THE ORDER OF OPERATIONS, because it is not the obvious one:
 *
 *   1. `fzn_catalog_refile_capture` -- snapshot the filing as it stands.
 *      This is the last moment the old arrangement exists.
 *   2. the consumer changes the filing freely.
 *   3. `fzn_catalog_refile_at` gives an entity and both paths; the consumer
 *      moves the file and calls `fzn_catalog_refile_advance`.
 *
 * Capturing BEFORE the change is the only order that works: after it the old
 * paths are gone, and there is nothing to move files from.
 *
 * THE CURSOR IS A COUNT, AND SOMETHING HAS TO MAKE THAT SOUND. The captured
 * moves are sorted by entity, so the order is the same on every machine and
 * after every restart. The old module also LOCKED the catalogue it owned,
 * and said plainly that the lock was not only a safety property but what made
 * resuming from a number sound. This model owns no container, so there is no
 * lock to take and nothing to take it against -- and the requirement does not
 * go away with the mechanism. It becomes the caller's, stated here: the
 * filing table must not change between capture and the last move. A caller
 * that needs the guarantee enforced holds its own lock around the job, which
 * it must anyway, since the files are its to move.
 *
 * CRASH SURVIVAL IS THE CONSUMER'S TO ARRANGE AND THIS IS SHAPED FOR IT. A
 * job is plain data over a caller's array, with no pointers into anything, so
 * a consumer writes it beside its store and reads it back. Re-entering a job
 * already under way is therefore not an error: it is what a restart does.
 */

typedef struct fzn_catalog_move {
	uint8_t entity[FZN_CATALOG_ENTITY_LEN];
	/* Where it was filed when the refile was captured. Carried here rather
	 * than looked up, because the table now holds the NEW filing. */
	uint8_t was_name[FZN_CATALOG_FILING_NAME_MAX];
	size_t  was_name_len;
	uint8_t was_path[FZN_CATALOG_FILING_PATH_MAX];
	size_t  was_path_len;
} fzn_catalog_move_t;

typedef struct fzn_catalog_refile {
	fzn_catalog_move_t *moves;
	size_t capacity;
	size_t used;
	/* How many have been completed. The whole of the resumable state. */
	size_t done;
	int captured;
} fzn_catalog_refile_t;

/*
 * Snapshot the filing as it stands, into caller-owned rows.
 *
 * Every filed entity is captured, sorted by entity. FZN_CATALOG_ERR_RANGE
 * when there are more than there are rows -- loudly, because a capture that
 * silently held some of them would move some of the files and leave the rest
 * where a stale path says they are.
 */
fzn_catalog_err_t fzn_catalog_refile_capture(const fzn_catalog_filings_t *filings,
                                                 fzn_catalog_refile_t *job,
                                                 fzn_catalog_move_t *moves,
                                                 size_t capacity);

/*
 * The move the cursor is on: the entity, where it was, and where it should be.
 *
 * `to` is the filing as it stands NOW, so it reflects every change the
 * consumer made after the capture. It is NULL when the entity is no longer
 * filed anywhere -- which is a real answer and not an error: a consumer
 * unfiled it, and what to do with a file whose entity has no home is the
 * consumer's decision rather than this library's.
 *
 * FZN_CATALOG_ERR_RANGE when the job is done.
 */
fzn_catalog_err_t fzn_catalog_refile_at(const fzn_catalog_refile_t *job,
                                            const fzn_catalog_filings_t *filings,
                                            const fzn_catalog_assertion_t *set,
                                            size_t count,
                                            const fzn_catalog_move_t **from,
                                            const fzn_catalog_filing_t **to);

/* Step past the move the cursor is on, once its file has been moved. */
fzn_catalog_err_t fzn_catalog_refile_advance(fzn_catalog_refile_t *job);

/* How far through. Both outputs are required, because a caller that wanted
 * only one would be computing a fraction from a number it did not ask for. */
fzn_catalog_err_t fzn_catalog_refile_progress(const fzn_catalog_refile_t *job,
                                                  size_t *done_out, size_t *total_out);

#endif /* FZN_CATALOG_FILING_H */
