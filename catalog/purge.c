/* See purge.h. */

#include "purge.h"

#include <string.h>

static int bytes_eq(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
	if (alen != blen)
		return 0;
	if (alen == 0)
		return 1;
	return memcmp(a, b, alen) == 0;
}

static fzn_catalog_purge_t *find(const fzn_catalog_purges_t *purges,
                                 const uint8_t *entity)
{
	size_t i;

	for (i = 0; i < purges->used; i++)
		if (memcmp(purges->rows[i].entity, entity, FZN_CATALOG_ENTITY_LEN) == 0)
			return &purges->rows[i];
	return NULL;
}

static int usable(const fzn_catalog_purges_t *purges, const uint8_t *entity,
                  size_t entity_len)
{
	if (!purges || !entity)
		return 0;
	if (entity_len != FZN_CATALOG_ENTITY_LEN)
		return 0;
	return purges->capacity == 0 || purges->rows != NULL;
}

fzn_catalog_err_t fzn_catalog_purges_init(fzn_catalog_purges_t *purges,
                                          fzn_catalog_purge_t *rows, size_t capacity)
{
	if (!purges)
		return FZN_CATALOG_ERR_MALFORMED;
	if (capacity > 0 && !rows)
		return FZN_CATALOG_ERR_MALFORMED;

	memset(purges, 0, sizeof(*purges));
	purges->rows = rows;
	purges->capacity = capacity;
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_purge_queue(fzn_catalog_purges_t *purges,
                                          const fzn_catalog_assertion_t *set,
                                          size_t count, const uint8_t *entity,
                                          size_t entity_len)
{
	fzn_catalog_source_t who[FZN_CATALOG_PURGE_HOSTS_MAX];
	fzn_catalog_purge_t *row;
	size_t written = 0, dropped = 0, i;

	if (!usable(purges, entity, entity_len))
		return FZN_CATALOG_ERR_MALFORMED;
	if (count != 0 && !set)
		return FZN_CATALOG_ERR_MALFORMED;
	/* RE-PINNING WOULD DISCARD THE AGREEMENT ALREADY COLLECTED and restart
	 * against a different set, so a second queue for one entity is refused
	 * rather than being quietly helpful. */
	if (find(purges, entity))
		return FZN_CATALOG_ERR_KIND;

	if (fzn_catalog_holders(set, count, entity, entity_len, who,
	                        FZN_CATALOG_PURGE_HOSTS_MAX, &written, &dropped) !=
	    FZN_CATALOG_OK)
		return FZN_CATALOG_ERR_MALFORMED;

	/* A SHORT SET CLOSES EARLY, which is the worse of C19a's two failures:
	 * it drops bytes a host still holds. Refused rather than truncated. */
	if (dropped > 0)
		return FZN_CATALOG_ERR_RANGE;
	/* AND AN EMPTY ONE CLOSES INSTANTLY. Nothing holds it here, so there is
	 * no consensus to attain and no purge to queue -- which is not the same
	 * as a purge that is already done. */
	if (written == 0)
		return FZN_CATALOG_ERR_ABSENT;

	if (purges->used >= purges->capacity)
		return FZN_CATALOG_ERR_RANGE;

	row = &purges->rows[purges->used];
	memset(row, 0, sizeof(*row));
	memcpy(row->entity, entity, FZN_CATALOG_ENTITY_LEN);

	/* THE PIN. Copied here and never consulted again: nothing below reads
	 * the assertion set, so a host that starts or stops holding the entity
	 * after this moment changes nothing. C19a names the recomputing version
	 * as the thing an implementation gets wrong by being helpful. */
	for (i = 0; i < written; i++) {
		if (who[i].issuer_len != FZN_CATALOG_PURGE_HOST_LEN)
			return FZN_CATALOG_ERR_RANGE;
		memcpy(row->host[i], who[i].issuer, FZN_CATALOG_PURGE_HOST_LEN);
	}
	row->hosts = written;
	purges->used++;
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_purge_agree(fzn_catalog_purges_t *purges,
                                          const uint8_t *entity, size_t entity_len,
                                          const uint8_t *host, size_t host_len)
{
	fzn_catalog_purge_t *row;
	size_t i;

	if (!usable(purges, entity, entity_len) || !host)
		return FZN_CATALOG_ERR_MALFORMED;

	row = find(purges, entity);
	if (!row)
		return FZN_CATALOG_ERR_ABSENT;

	for (i = 0; i < row->hosts; i++) {
		if (!bytes_eq(row->host[i], FZN_CATALOG_PURGE_HOST_LEN, host, host_len))
			continue;
		/* AGREEING TWICE IS NOT AN ERROR -- it is what a re-delivered
		 * message looks like, and refusing it would make a consumer
		 * distinguish a duplicate from a fault it does not have. */
		row->agreed[i] = 1u;
		return FZN_CATALOG_OK;
	}

	/* NOT IN THE PINNED SET. A host that began holding the entity after the
	 * purge was queued is not part of the consensus, and counting it would
	 * let the queue close while a PINNED host had still not answered. */
	return FZN_CATALOG_ERR_ABSENT;
}

int fzn_catalog_purge_queued(const fzn_catalog_purges_t *purges, const uint8_t *entity,
                             size_t entity_len)
{
	if (!usable(purges, entity, entity_len))
		return 0;
	return find(purges, entity) != NULL;
}

int fzn_catalog_purge_closed(const fzn_catalog_purges_t *purges, const uint8_t *entity,
                             size_t entity_len)
{
	const fzn_catalog_purge_t *row;
	size_t i;

	if (!usable(purges, entity, entity_len))
		return 0;

	row = find(purges, entity);
	if (!row)
		return 0;

	for (i = 0; i < row->hosts; i++)
		if (!row->agreed[i])
			return 0;
	return 1;
}

fzn_catalog_err_t fzn_catalog_purge_eliminate(fzn_catalog_purges_t *purges,
                                              const uint8_t *entity, size_t entity_len)
{
	fzn_catalog_purge_t *row;

	if (!usable(purges, entity, entity_len))
		return FZN_CATALOG_ERR_MALFORMED;

	row = find(purges, entity);
	if (!row)
		return FZN_CATALOG_ERR_ABSENT;
	/* NO EARLIER. A host that has not yet agreed still holds a copy and
	 * will re-send it, so eliminating now does not lose bookkeeping -- it
	 * undoes the deletion at that host's next sync. */
	if (!fzn_catalog_purge_closed(purges, entity, entity_len))
		return FZN_CATALOG_ERR_BUSY;

	*row = purges->rows[purges->used - 1u];
	purges->used--;
	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_purge_progress(const fzn_catalog_purges_t *purges,
                                             const uint8_t *entity, size_t entity_len,
                                             size_t *pinned_out, size_t *agreed_out)
{
	const fzn_catalog_purge_t *row;
	size_t i, n = 0;

	if (!pinned_out || !agreed_out)
		return FZN_CATALOG_ERR_MALFORMED;
	*pinned_out = 0;
	*agreed_out = 0;
	if (!usable(purges, entity, entity_len))
		return FZN_CATALOG_ERR_MALFORMED;

	row = find(purges, entity);
	if (!row)
		return FZN_CATALOG_ERR_ABSENT;

	for (i = 0; i < row->hosts; i++)
		if (row->agreed[i])
			n++;
	*pinned_out = row->hosts;
	*agreed_out = n;
	return FZN_CATALOG_OK;
}

size_t fzn_catalog_purge_count(const fzn_catalog_purges_t *purges)
{
	return purges ? purges->used : 0;
}
