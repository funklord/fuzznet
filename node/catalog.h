/*
 * THE CATALOGUE AS THIS NODE'S JOURNAL SAYS IT, project.md sec 633: step
 * 6d of sec 608, fuzzypickles' media library (their FZP_CMD_LIBRARY, 0x37)
 * on `catalog/`, whose merge core and ATTRIBUTE encoding the holder settled
 * (sec 314, "follow the new model").
 *
 * WHERE IT LIVES: each host's assertions are records on its own journal
 * stream FZN_CATALOG_STREAM, signed by it and followed by this estate's
 * hosts alone -- a user's library is its own devices', never a contact's.
 * An ATTRIBUTE record (FZN_CATALOG_ATTRIBUTE_KIND) asserts a value; a
 * RETRACT record (FZN_CATALOG_RETRACT_KIND, its body the attribute's name)
 * takes it back. Both name the file's root as their subject.
 *
 * LIVENESS, C5c: computed from what each (issuer, stream) holds -- for each
 * (issuer, entity, attribute) the record latest in its issuer's stream
 * stands, an ATTRIBUTE live, a RETRACT dead. No tombstone needs reconciling,
 * the stream's own order saying which came last.
 *
 * WHO HOLDS A FILE, C8: the issuers of live CAP_HOLDER assertions about it.
 * A host asserts what it holds, which is how the library knows where a file
 * is to be had.
 *
 * In memory, rebuilt from the journal each start: the journal is what is
 * kept, as the notes' index is fed from it (sec 519).
 */
#ifndef FZN_NODE_CATALOG_H
#define FZN_NODE_CATALOG_H

#include <stddef.h>
#include <stdint.h>

#include "../catalog/catalog.h"

#define FZN_CATALOG_STREAM 4u
#define FZN_CATALOG_ATTRIBUTE_KIND 0x38u
#define FZN_CATALOG_RETRACT_KIND 0x138u
/* Entries one host keeps: (entity, issuer, attribute) triples. */
#define FZN_NODE_CATALOG_MAX 1024u
#define FZN_NODE_CATALOG_NAME_MAX 64u
#define FZN_NODE_CATALOG_VALUE_MAX 504u

typedef enum fzn_node_catalog_err {
	FZN_NODE_CATALOG_OK = 0,
	FZN_NODE_CATALOG_ERR_MALFORMED = -1, /* a null, or a body that is not one */
	FZN_NODE_CATALOG_ERR_STALE = -2,     /* a record older than the one standing */
	FZN_NODE_CATALOG_ERR_FULL = -3       /* FZN_NODE_CATALOG_MAX entries */
} fzn_node_catalog_err_t;

const char *fzn_node_catalog_err_str(fzn_node_catalog_err_t err);

typedef struct fzn_node_catalog_entry {
	uint8_t issuer[32];
	uint8_t entity[32];
	uint8_t name[FZN_NODE_CATALOG_NAME_MAX];
	size_t name_len;
	uint8_t value[FZN_NODE_CATALOG_VALUE_MAX];
	size_t value_len;
	fzn_catalog_class_t attr_class;
	fzn_catalog_scope_t scope;
	fzn_catalog_merge_t merge;
	fzn_catalog_capability_t capability;
	uint64_t seq;
	int live;
} fzn_node_catalog_entry_t;

typedef struct fzn_node_catalog {
	fzn_node_catalog_entry_t entries[FZN_NODE_CATALOG_MAX];
	size_t count;
} fzn_node_catalog_t;

void fzn_node_catalog_init(fzn_node_catalog_t *c);

/* TAKE one record of `issuer`'s catalogue stream: place `seq`, `kind`, its
 * subject `entity` and `body`. STALE when a later record of that (issuer,
 * entity, attribute) already stands; a record of another kind is
 * MALFORMED. */
fzn_node_catalog_err_t fzn_node_catalog_take(fzn_node_catalog_t *c, const uint8_t issuer[32],
                                             const uint8_t entity[32], uint64_t seq,
                                             uint32_t kind, const uint8_t *body,
                                             size_t body_len);

/* THE ASSERTIONS about `entity` -- every entity with NULL -- live and dead,
 * as `catalog/` reads them, borrowing from `c`; `cap` of them. */
size_t fzn_node_catalog_assertions(const fzn_node_catalog_t *c, const uint8_t *entity,
                                   fzn_catalog_assertion_t *out, size_t cap);

#endif /* FZN_NODE_CATALOG_H */
