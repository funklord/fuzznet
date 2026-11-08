/* The catalogue as this node's journal says it: project.md sec 633, and the
 * header. */
#include "catalog.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

const char *fzn_node_catalog_err_str(fzn_node_catalog_err_t err)
{
	switch (err) {
	case FZN_NODE_CATALOG_OK:
		return "ok";
	case FZN_NODE_CATALOG_ERR_MALFORMED:
		return "malformed";
	case FZN_NODE_CATALOG_ERR_STALE:
		return "a later record stands";
	case FZN_NODE_CATALOG_ERR_FULL:
		return "no memory for the catalogue";
	}
	return "unknown";
}

void fzn_node_catalog_init(fzn_node_catalog_t *c)
{
	if (c)
		memset(c, 0, sizeof(*c));
}

void fzn_node_catalog_free(fzn_node_catalog_t *c)
{
	size_t i;

	if (!c)
		return;
	for (i = 0; i < c->count; i++)
		free(c->entries[i].value);
	free(c->entries);
	free(c->keys);
	free(c->entities);
	memset(c, 0, sizeof(*c));
}

/* FNV-1a, 64 bits: the tables' hash. Entities are content hashes and
 * issuers keys, so their bytes are spread already. */
static uint64_t mix(uint64_t h, const uint8_t *b, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++) {
		h ^= b[i];
		h *= 1099511628211ull;
	}
	return h;
}

static uint64_t key_hash(const uint8_t *issuer, const uint8_t *entity, const uint8_t *name,
                         size_t name_len)
{
	return mix(mix(mix(14695981039346656037ull, issuer, 32u), entity, 32u), name, name_len);
}

static uint64_t entity_hash(const uint8_t *entity)
{
	return mix(14695981039346656037ull, entity, 32u);
}

static int same_key(const fzn_node_catalog_entry_t *e, const uint8_t *issuer,
                    const uint8_t *entity, const uint8_t *name, size_t name_len)
{
	return e->name_len == name_len && memcmp(e->issuer, issuer, 32u) == 0
	       && memcmp(e->entity, entity, 32u) == 0 && memcmp(e->name, name, name_len) == 0;
}

/* THE SLOT of (issuer, entity, name) in `keys`: its entry's, or the empty
 * one it would take. */
static size_t key_slot(const fzn_node_catalog_t *c, const uint8_t *issuer, const uint8_t *entity,
                       const uint8_t *name, size_t name_len)
{
	size_t at = (size_t)key_hash(issuer, entity, name, name_len) & (c->slots - 1u);

	while (c->keys[at] && !same_key(&c->entries[c->keys[at] - 1u], issuer, entity, name, name_len))
		at = (at + 1u) & (c->slots - 1u);
	return at;
}

static size_t entity_slot(const fzn_node_catalog_t *c, const uint8_t *entity)
{
	size_t at = (size_t)entity_hash(entity) & (c->slots - 1u);

	while (c->entities[at]
	       && memcmp(c->entries[c->entities[at] - 1u].entity, entity, 32u) != 0)
		at = (at + 1u) & (c->slots - 1u);
	return at;
}

/* ROOM FOR ONE MORE ENTRY, the tables at most half full: 0 when memory ran
 * out, and nothing moved. */
static int room_for_one(fzn_node_catalog_t *c)
{
	size_t i;

	if (c->count == c->cap) {
		size_t cap = c->cap ? c->cap * 2u : 64u;
		fzn_node_catalog_entry_t *more = realloc(c->entries, cap * sizeof(*more));

		if (!more)
			return 0;
		c->entries = more;
		c->cap = cap;
	}
	if (2u * (c->count + 1u) > c->slots) {
		size_t slots = c->slots ? c->slots * 2u : 128u;
		size_t *keys = calloc(slots, sizeof(*keys)), *entities = calloc(slots, sizeof(*entities));

		if (!keys || !entities) {
			free(keys);
			free(entities);
			return 0;
		}
		free(c->keys);
		free(c->entities);
		c->keys = keys;
		c->entities = entities;
		c->slots = slots;
		for (i = 0; i < c->count; i++) {
			const fzn_node_catalog_entry_t *e = &c->entries[i];
			size_t at = key_slot(c, e->issuer, e->entity, e->name, e->name_len);

			c->keys[at] = i + 1u;
			/* THE NEWEST OF AN ENTITY'S heads its chain. */
			at = entity_slot(c, e->entity);
			c->entities[at] = i + 1u;
		}
	}
	return 1;
}

fzn_node_catalog_err_t fzn_node_catalog_take(fzn_node_catalog_t *c, const uint8_t issuer[32],
                                             const uint8_t entity[32], uint64_t seq,
                                             uint32_t kind, const uint8_t *body,
                                             size_t body_len)
{
	fzn_catalog_assertion_t a;
	fzn_node_catalog_entry_t *e = NULL;
	const uint8_t *name;
	size_t name_len, at = 0;

	if (!c || !issuer || !entity || !body)
		return FZN_NODE_CATALOG_ERR_MALFORMED;
	memset(&a, 0, sizeof(a));
	if (kind == FZN_CATALOG_ATTRIBUTE_KIND) {
		if (fzn_catalog_attribute_decode(issuer, 32u, entity, 32u, body, body_len, &a)
		            != FZN_CATALOG_OK
		    || a.name_len > FZN_NODE_CATALOG_NAME_MAX || a.value_len > FZN_NODE_CATALOG_VALUE_MAX)
			return FZN_NODE_CATALOG_ERR_MALFORMED;
		name = a.name;
		name_len = a.name_len;
	} else if (kind == FZN_CATALOG_RETRACT_KIND) {
		if (body_len == 0u || body_len > FZN_NODE_CATALOG_NAME_MAX)
			return FZN_NODE_CATALOG_ERR_MALFORMED;
		name = body;
		name_len = body_len;
	} else {
		return FZN_NODE_CATALOG_ERR_MALFORMED;
	}
	if (c->slots) {
		at = key_slot(c, issuer, entity, name, name_len);
		if (c->keys[at])
			e = &c->entries[c->keys[at] - 1u];
	}
	/* THE LATEST IN ITS ISSUER'S STREAM STANDS, C5c. */
	if (e && e->seq >= seq)
		return FZN_NODE_CATALOG_ERR_STALE;
	/* A VALUE'S ROOM before anything changes, so a FULL changes nothing. */
	if (kind == FZN_CATALOG_ATTRIBUTE_KIND && e && a.value_len > e->value_cap) {
		uint8_t *v = realloc(e->value, a.value_len);

		if (!v)
			return FZN_NODE_CATALOG_ERR_FULL;
		e->value = v;
		e->value_cap = a.value_len;
	}
	if (!e) {
		uint8_t *v = NULL;
		size_t head;

		/* A RETRACT of nothing held changes nothing to keep. */
		if (kind == FZN_CATALOG_RETRACT_KIND)
			return FZN_NODE_CATALOG_OK;
		if (a.value_len && !(v = malloc(a.value_len)))
			return FZN_NODE_CATALOG_ERR_FULL;
		if (!room_for_one(c)) {
			free(v);
			return FZN_NODE_CATALOG_ERR_FULL;
		}
		e = &c->entries[c->count];
		memset(e, 0, sizeof(*e));
		memcpy(e->issuer, issuer, 32u);
		memcpy(e->entity, entity, 32u);
		memcpy(e->name, name, name_len);
		e->name_len = name_len;
		e->value = v;
		e->value_cap = a.value_len;
		at = key_slot(c, issuer, entity, name, name_len);
		c->keys[at] = c->count + 1u;
		head = entity_slot(c, entity);
		e->same_entity = c->entities[head] ? c->entities[head] - 1u : SIZE_MAX;
		c->entities[head] = c->count + 1u;
		c->count++;
	}
	c->changed++;
	e->seq = seq;
	if (kind == FZN_CATALOG_RETRACT_KIND) {
		c->live -= e->live != 0;
		e->live = 0;
		return FZN_NODE_CATALOG_OK;
	}
	if (a.value_len)
		memcpy(e->value, a.value, a.value_len);
	e->value_len = a.value_len;
	e->attr_class = a.attr_class;
	e->scope = a.scope;
	e->merge = a.merge;
	e->capability = a.capability;
	c->live += e->live == 0;
	e->live = 1;
	return FZN_NODE_CATALOG_OK;
}

void fzn_node_catalog_assertion_at(const fzn_node_catalog_t *c, size_t i,
                                   fzn_catalog_assertion_t *out)
{
	const fzn_node_catalog_entry_t *e = &c->entries[i];

	memset(out, 0, sizeof(*out));
	out->issuer = e->issuer;
	out->issuer_len = 32u;
	out->entity = e->entity;
	out->entity_len = 32u;
	out->name = e->name;
	out->name_len = e->name_len;
	out->value = e->value;
	out->value_len = e->value_len;
	out->attr_class = e->attr_class;
	out->scope = e->scope;
	out->merge = e->merge;
	out->capability = e->capability;
	out->live = e->live;
}

size_t fzn_node_catalog_count_of(const fzn_node_catalog_t *c, const uint8_t entity[32])
{
	size_t at, i, n = 0;

	if (!c || !entity || !c->slots)
		return 0;
	at = entity_slot(c, entity);
	for (i = c->entities[at] ? c->entities[at] - 1u : SIZE_MAX; i != SIZE_MAX;
	     i = c->entries[i].same_entity)
		n++;
	return n;
}

size_t fzn_node_catalog_assertions(const fzn_node_catalog_t *c, const uint8_t *entity,
                                   fzn_catalog_assertion_t *out, size_t cap)
{
	size_t i, n = 0, at, k;

	if (!c || !out)
		return 0;
	if (!entity) {
		for (i = 0; i < c->count && n < cap; i++)
			fzn_node_catalog_assertion_at(c, i, &out[n++]);
		return n;
	}
	if (!c->slots)
		return 0;
	/* AN ENTITY'S CHAIN runs newest first; the first `cap` taken are the
	 * last `cap` of it, put back in the order they were taken. */
	k = fzn_node_catalog_count_of(c, entity);
	at = entity_slot(c, entity);
	for (i = c->entities[at] ? c->entities[at] - 1u : SIZE_MAX; i != SIZE_MAX;
	     i = c->entries[i].same_entity) {
		k--;
		if (k < cap) {
			fzn_node_catalog_assertion_at(c, i, &out[k]);
			n++;
		}
	}
	return n;
}
