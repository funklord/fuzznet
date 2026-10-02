/* cause_test -- the envelope that carries a request's causes. sec 462. */

#include "../cause.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL cause_test.c:%d: %s\n", __LINE__, what);       \
		}                                                                              \
	} while (0)

static fzn_entry_name_t name(uint64_t position)
{
	fzn_entry_name_t n;

	memset(&n, 0, sizeof(n));
	memset(n.machine, 0x3c, sizeof(n.machine));
	strcpy(n.user, "root");
	strcpy(n.program, "fuzznetd");
	n.pid = 4121u;
	n.start_ms = 1727778896123u;
	n.position = position;
	return n;
}

static int same(const fzn_entry_name_t *a, const fzn_entry_name_t *b)
{
	return memcmp(a->machine, b->machine, sizeof(a->machine)) == 0
	       && strcmp(a->user, b->user) == 0 && strcmp(a->program, b->program) == 0
	       && a->pid == b->pid && a->start_ms == b->start_ms && a->position == b->position;
}

int main(void)
{
	static uint8_t env[FZN_CAUSE_OVERHEAD_MAX + 64u];
	static const uint8_t request[] = { 2u, 1u, 0u, 0u }; /* a notes index query */
	fzn_entry_name_t cause = name(7u), origin = name(2u), c, o;
	const uint8_t *inner = NULL;
	size_t len = 0, inner_len = 0;
	/* The name's own length, as entry.situ lays it out: 16 + 1 + 4 + 1 + 8
	 * + 4 + 8 + 8. */
	const size_t name_len = 16u + 1u + 4u + 1u + 8u + 4u + 8u + 8u;

	CHECK(fzn_cause_wrap(&cause, &origin, request, sizeof(request), env, sizeof(env), &len)
	                      == FZN_CAUSE_OK
	              && len == 1u + (2u * name_len) + 2u + sizeof(request) && env[0] == 3u
	              && env[1] == 0x3cu && env[17] == 4u
	              && memcmp(env + 18, "root", 4u) == 0
	              && env[1 + (2u * name_len)] == 0u && env[2 + (2u * name_len)] == 4u
	              && memcmp(env + 3 + (2u * name_len), request, sizeof(request)) == 0,
	      "the version, the two names, the length and the request, where the schema puts them");
	CHECK(fzn_cause_unwrap(env, len, &c, &o, &inner, &inner_len) == FZN_CAUSE_OK
	              && same(&c, &cause) && same(&o, &origin) && inner_len == sizeof(request)
	              && memcmp(inner, request, sizeof(request)) == 0,
	      "and it comes off to the two names and the request inside");

	/* A BARE REQUEST IS NOT AN ENVELOPE, and nothing is written. */
	inner = NULL;
	inner_len = 99u;
	CHECK(fzn_cause_unwrap(request, sizeof(request), &c, &o, &inner, &inner_len)
	                      == FZN_CAUSE_NONE
	              && inner == NULL && inner_len == 99u
	              && fzn_cause_unwrap((const uint8_t *)"get peer", 8u, &c, &o, &inner,
	                                  &inner_len)
	                         == FZN_CAUSE_NONE,
	      "a notes message and a verb line are no envelopes, and are left as they are");

	/* WRAPPED IN PLACE: the request already in the buffer's tail. */
	memcpy(env + sizeof(env) - sizeof(request), request, sizeof(request));
	CHECK(fzn_cause_wrap(&cause, &origin, env + sizeof(env) - sizeof(request), sizeof(request),
	                     env, sizeof(env), &len)
	                      == FZN_CAUSE_OK
	              && fzn_cause_unwrap(env, len, &c, &o, &inner, &inner_len) == FZN_CAUSE_OK
	              && memcmp(inner, request, sizeof(request)) == 0,
	      "a request wrapped where it already sits comes out whole");

	/* ENVELOPES THAT DO NOT READ. */
	(void)fzn_cause_wrap(&cause, &origin, request, sizeof(request), env, sizeof(env), &len);
	CHECK(fzn_cause_unwrap(env, len - 1u, &c, &o, &inner, &inner_len)
	                      == FZN_CAUSE_ERR_MALFORMED
	              && fzn_cause_unwrap(env, len + 1u, &c, &o, &inner, &inner_len)
	                         == FZN_CAUSE_ERR_MALFORMED
	              && fzn_cause_unwrap(env, 10u, &c, &o, &inner, &inner_len)
	                         == FZN_CAUSE_ERR_MALFORMED,
	      "an envelope a byte short, a byte past its length, or cut in a name, is refused");
	env[17] = 0u; /* the cause's user, empty */
	CHECK(fzn_cause_unwrap(env, len, &c, &o, &inner, &inner_len) == FZN_CAUSE_ERR_MALFORMED,
	      "a name that is not one is refused");
	CHECK(fzn_cause_wrap(&cause, &origin, request, 0u, env, sizeof(env), &len)
	                      == FZN_CAUSE_ERR_MALFORMED
	              && fzn_cause_wrap(&cause, &origin, request, sizeof(request), env, 20u, &len)
	                         == FZN_CAUSE_ERR_ROOM,
	      "an empty request is refused, and a short buffer is too small");

	if (failures) {
		fprintf(stderr, "cause_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("cause_test: all %d checks passed\n", checks);
	return 0;
}
