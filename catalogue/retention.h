/* RETENTION: what this host keeps, over the new model. project.md sec 317
 * step 3, and sec 320.
 *
 * This is the old catalog/'s tri-state retention re-homed. What it keeps from
 * that module is the shape, which was tested and is unchanged: a per-entity
 * override of DEFAULT / KEEP / DROP, an optional deadline after which the row
 * says something else, and a catalogue-wide bit that a row with nothing to say
 * falls back to. What changes is where it lives and what it is keyed on.
 *
 * IT IS NOT A FIELD OF ANYTHING, and that is the whole re-homing. The old
 * retention was a table inside `fzn_catalog_t`, because that module owned a
 * container. The new model owns none -- every query takes an assertion set the
 * caller holds -- so retention becomes its own caller-owned table, and the
 * caller passes it where it passes the set. A consumer that keeps everything,
 * or nothing, pays for no table at all.
 *
 * IT MUST NOT SYNC, and this is C5a HOST rather than an oversight. One host's
 * keep intent is not another's: a retention that travelled would make one
 * host's disk policy binding on a host with different storage, which is the
 * same argument that keeps WHERE a host puts its bytes off the wire. So there
 * is no wire form here, no encode, no decode, and no resolver -- and nothing
 * in this file takes an issuer, because the only issuer it could ever have is
 * the host reading it.
 *
 * REACHABILITY FEEDS THIS; IT IS NOT DEFINED OVER IT. The direction is worth
 * stating because the first cut of sec 317 had it backwards. Retention is not
 * "a policy over the reachable set": a consumer observes that a chain has
 * become unreachable, DECIDES to mark it DROP, and the sweep acts on the mark.
 * Nothing here consults `fzn_catalogue_referenced`, and a caller that wants
 * that coupling writes it at the call site where its own judgement is.
 *
 * IT RECORDS INTENT AND REMOVES NOTHING (C17). A DROP is a statement that this
 * host is willing to lose these bytes, not a deletion; the removal is the
 * explicit sweep, which has its own guards and which this cannot reach.
 */

#ifndef FZN_CATALOGUE_RETENTION_H
#define FZN_CATALOGUE_RETENTION_H

#include <stddef.h>
#include <stdint.h>

#include "catalogue.h"

/* THE KEY IS A RECORD SUBJECT, so it is fixed where catalogue.h's queries take
 * `(entity, entity_len)`.
 *
 * Those queries are handed a borrowed view and never store it, so they can be
 * indifferent to the length. A row here outlives the call that wrote it and
 * has to carry the bytes, which needs a bound -- and C1 already fixes one: an
 * entity is the content hash the filestore knows a file by, and it reaches
 * this model as a record's subject. Anything else is a caller confusing an
 * entity with something that is not one, so it is refused rather than
 * truncated or padded.
 *
 * The signatures still take `(entity, entity_len)` rather than a fixed array,
 * so a caller passing an assertion's `entity`/`entity_len` straight through
 * cannot silently pass a pointer to the wrong thing. */
#define FZN_CATALOGUE_ENTITY_LEN ((size_t)FZN_SUBJECT_LEN)

/* What a host has said about one entity. DEFAULT is the absence of a word
 * rather than a third opinion, which is why it is zero and why storing it
 * gives the row back. */
typedef enum fzn_catalogue_retention {
	FZN_CATALOGUE_RETAIN_DEFAULT = 0,
	FZN_CATALOGUE_RETAIN_KEEP = 1,
	FZN_CATALOGUE_RETAIN_DROP = 2,
} fzn_catalogue_retention_t;

/* A stable, allocation-free name for a mode. */
const char *fzn_catalogue_retention_str(fzn_catalogue_retention_t mode);

/* One override.
 *
 * `mode` applies until `until`; from `until` onwards the row says `then`.
 * `until` of zero is no deadline, and then `then` is never read.
 *
 * "DELETE THIS IN THIRTY DAYS" IS KEEP UNTIL T, THEN DROP -- worth reading off
 * the fields, because it is the request this shape exists to express. `then`
 * of DEFAULT is the weaker form, keep until T and afterwards follow the
 * catalogue, which is what a consumer wants when the deadline is a budget
 * rather than a promise. */
typedef struct fzn_catalogue_hold {
	uint8_t                   entity[FZN_CATALOGUE_ENTITY_LEN];
	fzn_catalogue_retention_t mode;
	uint64_t                  until;
	fzn_catalogue_retention_t then;
} fzn_catalogue_hold_t;

/* The table, and the catalogue's own bit.
 *
 * KEEPS NOTHING UNTIL `retain_all` SAYS OTHERWISE, deliberately, which is why
 * a zeroed struct is the conservative one. The alternative -- default to
 * keeping -- would make a host that adopted a stranger's catalogue start
 * filling its disk with it, and a default nobody chose is exactly the kind
 * that is discovered when the disk is full. */
typedef struct fzn_catalogue_holds {
	fzn_catalogue_hold_t *rows;
	size_t                capacity;
	size_t                used;
	int                   keep_all;
} fzn_catalogue_holds_t;

/* Point a table at caller-owned rows. `capacity` of zero is legal and gives a
 * table that can hold no override -- a consumer whose policy is entirely the
 * catalogue-wide bit. */
fzn_catalogue_err_t fzn_catalogue_holds_init(fzn_catalogue_holds_t *holds,
                                             fzn_catalogue_hold_t *rows, size_t capacity);

/* What an entity with no word of its own follows. */
fzn_catalogue_err_t fzn_catalogue_retain_all(fzn_catalogue_holds_t *holds, int keep);

/* Say what to do with one entity, overriding the catalogue-wide bit.
 *
 * FZN_CATALOGUE_RETAIN_DEFAULT removes the override rather than storing one,
 * so a consumer changing its mind gives a row back instead of filling the
 * table with entities that say "whatever the catalogue says".
 *
 * FZN_CATALOGUE_ERR_RANGE when a new row does not fit; an entity that already
 * has a row is rewritten in place and cannot fail that way. */
fzn_catalogue_err_t fzn_catalogue_retain(fzn_catalogue_holds_t *holds,
                                         const uint8_t *entity, size_t entity_len,
                                         fzn_catalogue_retention_t mode);

/* Say what to do with one entity, and when to stop saying it.
 *
 * `until` of zero is no deadline and this is exactly `fzn_catalogue_retain`.
 *
 * A DEADLINE WITH `then` OF DEFAULT LEAVES A ROW THAT SAYS NOTHING once it has
 * passed, and this does not reclaim it: giving a row back is a write, and the
 * queries below are reads that a consumer makes from a const table and from
 * inside a sweep whose whole argument is that the decision is taken once.
 * `fzn_catalogue_due` lists exactly those entities, and passing each to
 * `fzn_catalogue_retain` with DEFAULT is how a consumer gets the slots back --
 * deliberately its own act, at a moment of its choosing.
 *
 * FZN_CATALOGUE_ERR_KIND for a `mode` or a `then` outside the three.
 * FZN_CATALOGUE_ERR_MALFORMED for a deadline on a DEFAULT mode: a row saying
 * "follow the catalogue until T" is a row that says nothing at all, and
 * storing it would fill the table with statements this module refuses to
 * keep. */
fzn_catalogue_err_t fzn_catalogue_retain_until(fzn_catalogue_holds_t *holds,
                                               const uint8_t *entity, size_t entity_len,
                                               fzn_catalogue_retention_t mode,
                                               uint64_t until,
                                               fzn_catalogue_retention_t then);

/* What was said about this entity at `now`, or DEFAULT when nothing was.
 *
 * `now` IS A PARAMETER AND NOT STATE, which is this tree's convention rather
 * than this module's taste -- chain/authz.h, chain/chain_store.h,
 * frame/freshness.h, prekey/prekey.h, link/link.h and provision/provision.h
 * all take the moment at the call site. A table holding a clock would also
 * make this answer drift under a sweep, and the sweep's cursor argument is
 * that the decision is taken once. */
fzn_catalogue_retention_t fzn_catalogue_retention_of(const fzn_catalogue_holds_t *holds,
                                                     const uint8_t *entity,
                                                     size_t entity_len, uint64_t now);

/* Whether this host keeps this entity at `now`: the entity's own word if it
 * has one, the catalogue-wide bit otherwise. The question a consumer actually
 * asks before fetching bytes or planning to remove them.
 *
 * A NULL TABLE KEEPS NOTHING, which is the same answer a zeroed one gives and
 * is the conservative direction for a fetch. It is NOT conservative for a
 * removal, which is why the sweep does not rest on this alone: `keeps` being
 * false is where its guard chain STARTS, and four further guards stand between
 * that and a byte being planned for removal. */
int fzn_catalogue_keeps(const fzn_catalogue_holds_t *holds, const uint8_t *entity,
                        size_t entity_len, uint64_t now);

/* Entities whose deadline has passed at `now`.
 *
 * What a consumer draws to say "these have come due", and what it walks to
 * give back the rows whose `then` is DEFAULT. Returns how many were written,
 * never more than `out_cap`; `dropped` receives the rest and is REQUIRED, on
 * `fzn_sync_digest`'s argument -- a count that silently omitted the remainder
 * would let a consumer believe it had seen every deadline. */
size_t fzn_catalogue_due(const fzn_catalogue_holds_t *holds, uint64_t now,
                         uint8_t out[][FZN_CATALOGUE_ENTITY_LEN], size_t out_cap,
                         size_t *dropped);

/* How many overrides are held, so a consumer can size a table and watch it
 * shrink as it gives rows back. */
size_t fzn_catalogue_hold_count(const fzn_catalogue_holds_t *holds);

#endif /* FZN_CATALOGUE_RETENTION_H */
