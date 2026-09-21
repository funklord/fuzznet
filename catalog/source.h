/* SOURCES: where bytes live (C13), and which entries the organiser may write
 * (C14/C15). project.md sec 340.
 *
 * A SOURCE IS A NAME AND A POLICY, AND NOTHING ELSE -- in particular not a
 * root path. C13 says a reference is (SOURCE, RELATIVE PATH) "and never a bare
 * absolute path", so a module that stored the root would be storing the very
 * thing C13 exists to stop being the unit. Turning a reference into somewhere
 * a file can be opened is the consumer's, exactly as moving a file is in
 * filing.h: this library sees a name, a policy and a relative path, and never
 * an absolute path at all.
 *
 * AND IT DOES NOT TRAVEL (C5a HOST, C16a). There is no wire form here, no
 * encode, no decode and nothing takes an issuer -- a path "is what a host
 * records about its own disk; it is not what it publishes", and a source name
 * is the same kind of fact. Two hosts sharing a catalogue agree about the
 * entities and each keeps its own sources, as they each keep their own filing.
 *
 * ---------------------------------------------------------------------------
 * C15, AS THE COPYRIGHT HOLDER SETTLED IT ON 2026-09-21: IN PLACE.
 * ---------------------------------------------------------------------------
 *
 * A referenced source is read-only to the organiser UNTIL AN ENTRY IS
 * PROMOTED. A promoted entry is writable WHERE IT LIES; the bytes do not move,
 * the policy does. This is C14's "one mechanism with a policy per entry"
 * meant literally, and the per-entry reading is what makes it safe enough to
 * have: the alternative on offer was promotion by copying, which keeps the
 * read-only guarantee true BY CONSTRUCTION at the price of a second copy of
 * every promoted file.
 *
 * WHAT THAT COSTS, WRITTEN DOWN RATHER THAN DISCOVERED LATER. The guarantee
 * stops being a property of the code and becomes a question somebody asks. A
 * bug in the asking is now a rename inside a collection built over decades,
 * which breaks every other tool pointing at that path and is not recoverable
 * from this library. Three rules hold that exposure to one file at a time:
 *
 *   - A PROMOTION NAMES ONE ENTITY IN ONE PLACE. Never a directory, never a
 *     prefix, never a subtree. There is no call that makes more than one entry
 *     writable, so there is no call that can make a collection writable by
 *     being given one argument wrong.
 *   - A SOURCE'S POLICY IS FIXED WHEN IT IS DECLARED. Re-declaring one with a
 *     different policy is refused rather than applied, because that single
 *     call is the one gesture that WOULD flip a whole collection at once --
 *     and a typo in an enum argument is exactly how it would happen.
 *   - ASK AT THE MOMENT OF THE WRITE. `fzn_catalog_writable` is a predicate,
 *     not a grant: a caller that reads it once and writes later has a fact
 *     about a moment, and the promotion may have been revoked since.
 *
 * A PROMOTION BINDS TO THE ENTITY AND THE PLACE TOGETHER. C16 says a
 * referenced file may be moved by its owner at any moment; if it is, the
 * promotion no longer matches and `fzn_catalog_writable` answers no. That is
 * the safe direction and it is deliberate -- a promotion is a statement about
 * one file in one place, not a licence that follows an entity around a disk.
 *
 * DEMOTION IS NOT DELETION (C17). Revoking a promotion touches no bytes and
 * asserts nothing about whether the file should exist; it withdraws
 * permission and stops there.
 *
 * AND NOTHING ELSE IN THIS MODULE CREATES A PROMOTION. C17's shape -- a
 * deletion is explicit and never a consequence of a metadata error -- is the
 * right one for a permission too, so materialising a layout, filing, refiling
 * and sweeping all leave the set of promotions exactly as they found it. A
 * promotion exists because somebody asked for it by name.
 *
 * THE PATH RULE IS C22'S, ASKED PER COMPONENT. A relative path here is
 * validated with `fzn_catalog_path_component_ok` over each of its components,
 * which is materialise.h's rule reused rather than restated -- a second
 * statement of it would be a second thing to be wrong, and a reference that
 * may point at `../..` is the same escape from the same root.
 */

#ifndef FZN_CATALOG_SOURCE_H
#define FZN_CATALOG_SOURCE_H

#include <stddef.h>
#include <stdint.h>

#include "catalog.h"
#include "materialise.h"
#include "retention.h"

/* The longest source name and relative path a row carries.
 *
 * BOUNDED BECAUSE A ROW OUTLIVES THE CALL THAT WROTE IT, which is retention.h
 * and filing.h's reason unchanged. A longer name or path is refused rather
 * than truncated: a truncated path names a different place, and a permission
 * to write somewhere else is a worse answer than no permission. */
#define FZN_CATALOG_SOURCE_NAME_MAX 64u
#define FZN_CATALOG_SOURCE_PATH_MAX 192u

/* C14/C15. The policy an entry inherits from its source. */
typedef enum fzn_catalog_policy {
	/* C15: read-only to the organiser, except where an entry is promoted. */
	FZN_CATALOG_POLICY_REFERENCED = 0,
	/* C14: the managed root, writable throughout. */
	FZN_CATALOG_POLICY_MANAGED = 1
} fzn_catalog_policy_t;

/* C13's source: named, carrying a policy. */
typedef struct fzn_catalog_source {
	uint8_t              name[FZN_CATALOG_SOURCE_NAME_MAX];
	size_t               name_len;
	fzn_catalog_policy_t policy;
} fzn_catalog_source_t;

typedef struct fzn_catalog_source_table {
	fzn_catalog_source_t *rows;
	size_t capacity;
	size_t used;
} fzn_catalog_source_table_t;

/* C15. One entry made writable where it lies: an entity, and the place the
 * permission is about. Both halves are compared, per the header. */
typedef struct fzn_catalog_promotion {
	uint8_t entity[FZN_CATALOG_ENTITY_LEN];
	uint8_t source[FZN_CATALOG_SOURCE_NAME_MAX];
	size_t  source_len;
	uint8_t path[FZN_CATALOG_SOURCE_PATH_MAX];
	size_t  path_len;
} fzn_catalog_promotion_t;

typedef struct fzn_catalog_promotions {
	fzn_catalog_promotion_t *rows;
	size_t capacity;
	size_t used;
} fzn_catalog_promotions_t;

/* Point a table at caller-owned rows. A zero capacity is legal: a host with no
 * sources declared yet is an ordinary state, not an error. */
fzn_catalog_err_t fzn_catalog_sources_init(fzn_catalog_source_table_t *sources,
                                           fzn_catalog_source_t *rows,
                                           size_t capacity);

fzn_catalog_err_t fzn_catalog_promotions_init(fzn_catalog_promotions_t *proms,
                                              fzn_catalog_promotion_t *rows,
                                              size_t capacity);

/*
 * Declare a source with a policy.
 *
 * Declaring the same name with the SAME policy again is FZN_CATALOG_OK and
 * changes nothing, so a caller replaying its own configuration is not an
 * error. Declaring it with a DIFFERENT policy is FZN_CATALOG_ERR_KIND and is
 * the guard the header argues for: that one call is the only gesture that
 * could make an entire referenced collection writable at once.
 *
 * FZN_CATALOG_ERR_RANGE when a new row does not fit or the name is longer
 * than a row carries, FZN_CATALOG_ERR_MALFORMED for a null or an empty name,
 * FZN_CATALOG_ERR_KIND for a policy outside the enum (C28/F26).
 */
fzn_catalog_err_t fzn_catalog_source_declare(
        fzn_catalog_source_table_t *sources, const uint8_t *name,
        size_t name_len, fzn_catalog_policy_t policy);

/* The declared source of that name, or NULL when there is none. */
const fzn_catalog_source_t *fzn_catalog_source_find(
        const fzn_catalog_source_table_t *sources, const uint8_t *name,
        size_t name_len);

/* How many sources are declared. */
size_t fzn_catalog_source_count(const fzn_catalog_source_table_t *sources);

/*
 * Is `path` usable as a relative path inside a source?
 *
 * Every component must satisfy `fzn_catalog_path_component_ok`, which is C22's
 * rule and therefore refuses a separator inside a component, `.`, `..`, a
 * control byte and a backslash. An absolute path, an empty path, an empty
 * component (a doubled separator or a trailing one) and a path over
 * FZN_CATALOG_SOURCE_PATH_MAX are refused here.
 */
int fzn_catalog_relative_path_ok(const uint8_t *path, size_t len);

/*
 * C15. Promote one entity, at one place, in a REFERENCED source.
 *
 * FZN_CATALOG_ERR_ABSENT when no source of that name is declared -- a
 * permission about a place this host does not know is not a permission.
 *
 * FZN_CATALOG_ERR_KIND when the source is MANAGED. The entry is already
 * writable by C14, and answering OK would leave a caller believing the
 * promotion is what made it so; the belief matters, because the caller's next
 * thought is that demoting would take it away, and it would not.
 *
 * FZN_CATALOG_ERR_MALFORMED for a null, a wrong entity length or a path
 * `fzn_catalog_relative_path_ok` refuses. FZN_CATALOG_ERR_RANGE when a new
 * row does not fit.
 *
 * Promoting an entity that already has a row REPLACES it, so an entity has at
 * most one promotion and the invariant is structural rather than checked --
 * filing.h's reasoning, and it matters more here: two rows for one entity
 * would be two places a caller could be told yes about.
 */
fzn_catalog_err_t fzn_catalog_promote(
        fzn_catalog_promotions_t *proms,
        const fzn_catalog_source_table_t *sources, const uint8_t *entity,
        size_t entity_len, const uint8_t *source, size_t source_len,
        const uint8_t *path, size_t path_len);

/* Withdraw this entity's promotion, if it has one. Not an error when it has
 * none, and it touches no bytes (C17). */
fzn_catalog_err_t fzn_catalog_demote(fzn_catalog_promotions_t *proms,
                                     const uint8_t *entity, size_t entity_len);

/* This entity's promotion, or NULL when it has none. */
const fzn_catalog_promotion_t *fzn_catalog_promoted(
        const fzn_catalog_promotions_t *proms, const uint8_t *entity,
        size_t entity_len);

/* How many promotions are held. */
size_t fzn_catalog_promotion_count(const fzn_catalog_promotions_t *proms);

/*
 * MAY THE ORGANISER WRITE THIS ENTRY? Ask immediately before writing.
 *
 * 1 when the source is MANAGED (C14), or when it is REFERENCED and this exact
 * (entity, source, path) is promoted (C15). 0 otherwise -- including for an
 * undeclared source, a malformed path and a null, because refusing is the
 * direction that costs a person nothing they cannot redo.
 *
 * NOT A GRANT, AND NOT CACHEABLE. The answer is about this moment: a
 * promotion can be withdrawn between the question and the write, and a
 * referenced file can be moved by its owner between them too (C16).
 */
int fzn_catalog_writable(const fzn_catalog_source_table_t *sources,
                         const fzn_catalog_promotions_t *proms,
                         const uint8_t *entity, size_t entity_len,
                         const uint8_t *source, size_t source_len,
                         const uint8_t *path, size_t path_len);

#endif /* FZN_CATALOG_SOURCE_H */
