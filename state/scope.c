/* See scope.h. */

#include "scope.h"

#include <string.h>

/* Sixteen bytes, as `chain/service.c`'s and `session/commitment.c`'s labels
 * are, so a scoped subject's input collides with no other derivation. */
static const char FZN_SCOPE_LABEL[16] = "fuzznet-scope-v1";

static const char *const NAMES[FZN_SCOPE_COUNT] = { "host-private", "host", "group",
	                                            "estate" };

const char *fzn_scope_err_str(fzn_scope_err_t err)
{
	switch (err) {
	case FZN_SCOPE_OK:
		return "ok";
	case FZN_SCOPE_ERR_MALFORMED:
		return "malformed";
	case FZN_SCOPE_ERR_PRIVATE:
		return "a host-private value has no cell";
	}
	return "unknown";
}

int fzn_scope_known(uint8_t byte)
{
	return byte < FZN_SCOPE_COUNT;
}

fzn_scope_t fzn_scope_read(uint8_t byte)
{
	return fzn_scope_known(byte) ? (fzn_scope_t)byte : FZN_SCOPE_HOST_PRIVATE;
}

const char *fzn_scope_name(fzn_scope_t scope)
{
	return (unsigned)scope < FZN_SCOPE_COUNT ? NAMES[scope] : NULL;
}

int fzn_scope_parse(const uint8_t *text, size_t len, fzn_scope_t *out)
{
	size_t i;

	if (!text || !out)
		return 0;
	for (i = 0; i < FZN_SCOPE_COUNT; i++)
		if (strlen(NAMES[i]) == len && memcmp(NAMES[i], text, len) == 0) {
			*out = (fzn_scope_t)i;
			return 1;
		}
	return 0;
}

int fzn_scope_replicates(fzn_scope_t scope)
{
	return fzn_scope_reaches(scope, 1);
}

int fzn_scope_reaches(fzn_scope_t scope, int in_group)
{
	switch (scope) {
	case FZN_SCOPE_HOST:
	case FZN_SCOPE_ESTATE:
		return 1;
	case FZN_SCOPE_GROUP:
		return in_group != 0;
	case FZN_SCOPE_HOST_PRIVATE:
		return 0;
	}
	return 0;	/* unknown: the narrowest */
}

int fzn_scope_widens(fzn_scope_t from, fzn_scope_t to)
{
	/* Some host `to` reaches and `from` does not: a member when `to` takes
	 * the group, a non-member when it takes every host. */
	return (fzn_scope_reaches(to, 1) && !fzn_scope_reaches(from, 1))
	       || (fzn_scope_reaches(to, 0) && !fzn_scope_reaches(from, 0));
}

fzn_scope_err_t fzn_scope_subject(fzn_scope_t scope, const uint8_t id[FZN_SUBJECT_LEN],
                                  const fzn_hash_ops_t *hash, uint8_t out[FZN_SUBJECT_LEN])
{
	uint8_t input[sizeof(FZN_SCOPE_LABEL) + 1u + FZN_SUBJECT_LEN];
	uint8_t derived[FZN_SUBJECT_LEN];

	if (!id || !hash || !hash->hash || !out)
		return FZN_SCOPE_ERR_MALFORMED;
	if (scope == FZN_SCOPE_HOST_PRIVATE)
		return FZN_SCOPE_ERR_PRIVATE;
	if ((unsigned)scope >= FZN_SCOPE_COUNT)
		return FZN_SCOPE_ERR_MALFORMED;
	/* THE SCOPE IS IN THE INPUT, so one id under two scopes is two
	 * subjects: a group whose id equals a host's key is not that host. */
	memcpy(input, FZN_SCOPE_LABEL, sizeof(FZN_SCOPE_LABEL));
	input[sizeof(FZN_SCOPE_LABEL)] = (uint8_t)scope;
	memcpy(input + sizeof(FZN_SCOPE_LABEL) + 1u, id, FZN_SUBJECT_LEN);
	if (!hash->hash(hash->ctx, derived, sizeof(derived), input, sizeof(input)))
		return FZN_SCOPE_ERR_MALFORMED;
	memcpy(out, derived, FZN_SUBJECT_LEN);
	return FZN_SCOPE_OK;
}
