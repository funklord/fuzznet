#include "service.h"

#include "../wire/bytes.h"

#include <string.h>

/* Sixteen bytes, matching `session/commitment.c`'s labels, so that this
 * derivation's inputs cannot collide with any other in the protocol. The
 * version suffix is what lets the scheme change without old capabilities
 * silently meaning something new. */
static const char FZN_SERVICE_LABEL[16] = "fuzznet-cap-v1\0\0";

#define SERVICE_FIXED (4u + 4u)

fzn_chain_err_t fzn_service_capability(uint32_t service, uint32_t product,
                                       const uint8_t *name, size_t name_len,
                                       const fzn_hash_ops_t *hash,
                                       fzn_cap_id_t *out)
{
	uint8_t input[sizeof(FZN_SERVICE_LABEL) + SERVICE_FIXED + FZN_SERVICE_NAME_MAX];
	uint8_t derived[FZN_CAP_ID_LEN];
	size_t at;

	if (!hash || !hash->hash || !out)
		return FZN_CHAIN_ERR_MALFORMED;
	/* THE MANDATORY HALF. A capability that names no service cannot be
	 * built, which is what makes the namespace mandatory: there is no
	 * second way in. */
	if (service == FZN_SERVICE_NONE || product == FZN_PRODUCT_NONE)
		return FZN_CHAIN_ERR_MALFORMED;
	/* A product past the space a stream can carry would authorise
	 * records no stream could hold, so it is refused here rather than
	 * at the stream derivation -- a capability that cannot correspond
	 * to any record is not a narrower capability, it is a bug. */
	if (product > FZN_PRODUCT_MAX && product != FZN_PRODUCT_ANY)
		return FZN_CHAIN_ERR_MALFORMED;
	if (name_len > FZN_SERVICE_NAME_MAX)
		return FZN_CHAIN_ERR_MALFORMED;
	/* A length with no bytes behind it is a caller bug rather than an
	 * empty name; an empty name is `name_len == 0`. */
	if (name_len > 0 && !name)
		return FZN_CHAIN_ERR_MALFORMED;

	memcpy(input, FZN_SERVICE_LABEL, sizeof(FZN_SERVICE_LABEL));
	at = sizeof(FZN_SERVICE_LABEL);
	fzn_put_be32(input + at, service);
	at += 4u;
	fzn_put_be32(input + at, product);
	at += 4u;
	if (name_len > 0)
		memcpy(input + at, name, name_len);
	at += name_len;

	/* Into a scratch buffer and copied out only on success, so `out` holds
	 * either the capability or what it held before -- never half of one.
	 * `session/commitment.c` states the reason: a caller that ignores the
	 * return value otherwise puts a half-written value somewhere a peer
	 * will read. */
	if (!hash->hash(hash->ctx, derived, sizeof(derived), input, at))
		return FZN_CHAIN_ERR_MALFORMED;

	memcpy(out->b, derived, FZN_CAP_ID_LEN);
	return FZN_CHAIN_OK;
}

fzn_chain_err_t fzn_service_capability_pair(uint32_t service, uint32_t product,
                                            const uint8_t *name, size_t name_len,
                                            const fzn_hash_ops_t *hash,
                                            fzn_cap_id_t *scoped_out,
                                            fzn_cap_id_t *any_out)
{
	fzn_chain_err_t err;

	if (!scoped_out || !any_out)
		return FZN_CHAIN_ERR_MALFORMED;
	/* A RECORD BELONGS TO A PROJECT, NOT TO ALL OF THEM. Passing the
	 * wildcard as the subject of a check asks whether a holder may see
	 * every product's records, which is not the question an access check
	 * has. Refused rather than absorbed. */
	if (product == FZN_PRODUCT_ANY)
		return FZN_CHAIN_ERR_MALFORMED;

	err = fzn_service_capability(service, product, name, name_len, hash, scoped_out);
	if (err != FZN_CHAIN_OK)
		return err;
	return fzn_service_capability(service, FZN_PRODUCT_ANY, name, name_len, hash, any_out);
}

fzn_chain_err_t fzn_service_stream(uint32_t product, uint32_t index, uint32_t *out)
{
	if (!out)
		return FZN_CHAIN_ERR_MALFORMED;
	/* NEITHER SENTINEL HAS A STREAM. Nobody's records and everybody's
	 * records are both answers to a question about entitlement, and a
	 * stream is a place bytes actually go.
	 *
	 * ONE RANGE TEST RATHER THAN TWO, and the redundant version was here
	 * until the sabotage harness reported it as a check that could not
	 * fail: FZN_PRODUCT_ANY is FZN_PRODUCT_MAX + 1, so an explicit test
	 * for it is dead behind the bound. Both halves of this one are
	 * reachable -- zero fails the first, the wildcard and everything above
	 * it fails the second. */
	if (product == FZN_PRODUCT_NONE || product > FZN_PRODUCT_MAX)
		return FZN_CHAIN_ERR_MALFORMED;
	if (index > FZN_STREAM_INDEX_MAX)
		return FZN_CHAIN_ERR_MALFORMED;

	*out = (product << FZN_STREAM_PRODUCT_SHIFT) | index;
	return FZN_CHAIN_OK;
}

uint32_t fzn_service_stream_product(uint32_t stream)
{
	return stream >> FZN_STREAM_PRODUCT_SHIFT;
}
