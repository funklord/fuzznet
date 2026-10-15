/* The catalogue as this node's journal says it: project.md sec 633, and the
 * header. */
#include "catalog.h"

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
		return "the catalogue is full";
	}
	return "unknown";
}

void fzn_node_catalog_init(fzn_node_catalog_t *c)
{
	if (c)
		memset(c, 0, sizeof(*c));
}

static fzn_node_catalog_entry_t *entry_of(fzn_node_catalog_t *c, const uint8_t *issuer,
                                          const uint8_t *entity, const uint8_t *name,
                                          size_t name_len)
{
	size_t i;

	for (i = 0; i < c->count; i++) {
		fzn_node_catalog_entry_t *e = &c->entries[i];

		if (e->name_len == name_len && memcmp(e->issuer, issuer, 32u) == 0
		    && memcmp(e->entity, entity, 32u) == 0 && memcmp(e->name, name, name_len) == 0)
			return e;
	}
	return NULL;
}

fzn_node_catalog_err_t fzn_node_catalog_take(fzn_node_catalog_t *c, const uint8_t issuer[32],
                                             const uint8_t entity[32], uint64_t seq,
                                             uint32_t kind, const uint8_t *body,
                                             size_t body_len)
{
	fzn_catalog_assertion_t a;
	fzn_node_catalog_entry_t *e;
	const uint8_t *name;
	size_t name_len;

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
	e = entry_of(c, issuer, entity, name, name_len);
	/* THE LATEST IN ITS ISSUER'S STREAM STANDS, C5c. */
	if (e && e->seq >= seq)
		return FZN_NODE_CATALOG_ERR_STALE;
	if (!e) {
		/* A RETRACT of nothing held changes nothing to keep. */
		if (kind == FZN_CATALOG_RETRACT_KIND)
			return FZN_NODE_CATALOG_OK;
		if (c->count == FZN_NODE_CATALOG_MAX)
			return FZN_NODE_CATALOG_ERR_FULL;
		e = &c->entries[c->count++];
		memset(e, 0, sizeof(*e));
		memcpy(e->issuer, issuer, 32u);
		memcpy(e->entity, entity, 32u);
		memcpy(e->name, name, name_len);
		e->name_len = name_len;
	}
	e->seq = seq;
	if (kind == FZN_CATALOG_RETRACT_KIND) {
		e->live = 0;
		return FZN_NODE_CATALOG_OK;
	}
	memcpy(e->value, a.value, a.value_len);
	e->value_len = a.value_len;
	e->attr_class = a.attr_class;
	e->scope = a.scope;
	e->merge = a.merge;
	e->capability = a.capability;
	e->live = 1;
	return FZN_NODE_CATALOG_OK;
}

size_t fzn_node_catalog_assertions(const fzn_node_catalog_t *c, const uint8_t *entity,
                                   fzn_catalog_assertion_t *out, size_t cap)
{
	size_t i, n = 0;

	if (!c || !out)
		return 0;
	for (i = 0; i < c->count && n < cap; i++) {
		const fzn_node_catalog_entry_t *e = &c->entries[i];

		if (entity && memcmp(e->entity, entity, 32u) != 0)
			continue;
		out[n].issuer = e->issuer;
		out[n].issuer_len = 32u;
		out[n].entity = e->entity;
		out[n].entity_len = 32u;
		out[n].name = e->name;
		out[n].name_len = e->name_len;
		out[n].value = e->value;
		out[n].value_len = e->value_len;
		out[n].attr_class = e->attr_class;
		out[n].scope = e->scope;
		out[n].merge = e->merge;
		out[n].capability = e->capability;
		out[n].live = e->live;
		n++;
	}
	return n;
}
