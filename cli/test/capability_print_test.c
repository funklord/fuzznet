/* Tests for cli/capability_print.c.
 *
 * THE CASE THIS FILE EXISTS FOR is that revoked is asked with
 * `fzn_revocation_covers` and never `fzn_revocation_known`. They differ on
 * exactly one state -- an entry whose revocation has since been WITHDRAWN --
 * so a store that has never seen a withdrawal cannot tell them apart, and the
 * fixture builds one. Asking the wrong one reports a RESTORED capability as
 * cut off, which revocation.c calls "the outage the whole withdrawal design
 * exists to end".
 *
 * The second is that expired and revoked call for OPPOSITE actions: an expiry
 * wants renewing and a revocation is somebody's decision, where renewing
 * would be exactly wrong. On a screen that saves a person a guess; here it
 * decides what an automated response does.
 */

#include "../capability_print.h"

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;

	failures++;
	fprintf(stderr, "  FAIL capability_print_test.c:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

static fzn_revocation_t ENTRY;

static void chain_of(fzn_chain_t *chain, uint64_t expires_at)
{
	memset(chain, 0, sizeof(*chain));
	memset(chain->root, 0xa0, sizeof(chain->root));
	memset(chain->grantee, 0xb0, sizeof(chain->grantee));
	memset(&chain->capability, 0xc0, sizeof(chain->capability));
	chain->hop_count = 1;
	chain->expires_at = expires_at;
}

static int store_of(fzn_revocation_store_t *store, const fzn_chain_t *chain, int withdrawn)
{
	memset(&ENTRY, 0, sizeof(ENTRY));
	ENTRY.capability = chain->capability;
	memcpy(ENTRY.grantee, chain->grantee, sizeof(ENTRY.grantee));
	memcpy(ENTRY.issuer, chain->root, sizeof(ENTRY.issuer));
	ENTRY.withdrawn = (uint8_t)withdrawn;

	if (fzn_revocation_store_init(store, &ENTRY, 1u) != FZN_CHAIN_OK)
		return 0;
	store->used = 1u;
	return 1;
}

int main(void)
{
	char line[FZN_CAPABILITY_PRINT_MAX];
	char usable_line[FZN_CAPABILITY_PRINT_MAX];
	fzn_chain_t chain;
	fzn_revocation_store_t store;
	fzn_capability_state_t s;
	size_t len = 0;

	/* NO CHAIN IS THE ZERO VALUE. */
	s = FZN_CAPABILITY_USABLE;
	CHECK(fzn_capability_print(NULL, NULL, 0u, line, sizeof(line), &len, &s) ==
	              FZN_CHAIN_OK,
	      "a null chain would not render");
	CHECK(s == FZN_CAPABILITY_NONE, "a null chain was not reported as none held");

	/* USABLE, AND THE SENTINEL IS NOT AN INSTANT. */
	chain_of(&chain, FZN_NO_EXPIRY);
	CHECK(fzn_capability_print(&chain, NULL, UINT64_MAX, line, sizeof(line), &len, &s) ==
	              FZN_CHAIN_OK,
	      "an unexpiring chain would not render");
	CHECK(s == FZN_CAPABILITY_USABLE,
	      "a chain that never expires was reported as expired at a late now");
	CHECK(strstr(line, "does not expire") != NULL,
	      "the no-expiry sentinel was printed as an instant");
	memcpy(usable_line, line, sizeof(line));

	/* EXPIRED. */
	chain_of(&chain, 1000u);
	CHECK(fzn_capability_print(&chain, NULL, 1000u, line, sizeof(line), &len, &s) ==
	              FZN_CHAIN_OK,
	      "an expired chain would not render");
	CHECK(s == FZN_CAPABILITY_EXPIRED, "a chain expiring at now was not expired");
	CHECK(strstr(line, "expires at 1000") != NULL, "the expiry is not on the line");

	/* THE CASE THIS FILE EXISTS FOR. A withdrawn entry: `known` is 1 and
	 * `covers` is 0, so asking the wrong one cuts off a restored
	 * capability. */
	chain_of(&chain, FZN_NO_EXPIRY);
	CHECK(store_of(&store, &chain, 1), "the store would not init");
	CHECK(fzn_revocation_known(&store, chain.root, &chain.capability, chain.grantee),
	      "the fixture does not hold the triple, so it separates nothing");
	CHECK(!fzn_revocation_covers(&store, chain.root, &chain.capability, chain.grantee),
	      "the fixture is not a withdrawal, so it separates nothing");

	CHECK(fzn_capability_print(&chain, &store, 0u, line, sizeof(line), &len, &s) ==
	              FZN_CHAIN_OK,
	      "a withdrawn revocation would not render");
	CHECK(s == FZN_CAPABILITY_USABLE,
	      "a capability whose revocation was withdrawn was reported as revoked");

	/* AND A LIVE REVOCATION IS STILL ONE. The pair is the assertion. */
	CHECK(store_of(&store, &chain, 0), "the store would not reinit");
	CHECK(fzn_capability_print(&chain, &store, 0u, line, sizeof(line), &len, &s) ==
	              FZN_CHAIN_OK,
	      "a live revocation would not render");
	CHECK(s == FZN_CAPABILITY_REVOKED, "a revoked capability was not revoked");
	CHECK(strstr(line, "REVOKED") != NULL, "the verdict is not on the line");
	CHECK(strcmp(line, usable_line) != 0, "revoked and usable print the same line");

	/* REVOCATION WINS OVER EXPIRY, and the two never share a word. */
	{
		char revoked_line[FZN_CAPABILITY_PRINT_MAX];

		chain_of(&chain, 1000u);
		CHECK(store_of(&store, &chain, 0), "the store would not reinit");
		CHECK(fzn_capability_print(&chain, &store, 5000u, line, sizeof(line), &len,
		                           &s) == FZN_CHAIN_OK,
		      "an expired and revoked chain would not render");
		CHECK(s == FZN_CAPABILITY_REVOKED,
		      "a chain both expired and revoked did not report the revocation, "
		      "which is the half somebody may need to act on");
		memcpy(revoked_line, line, sizeof(line));

		CHECK(fzn_capability_print(&chain, NULL, 5000u, line, sizeof(line), &len,
		                           &s) == FZN_CHAIN_OK,
		      "the same chain with no store would not render");
		CHECK(s == FZN_CAPABILITY_EXPIRED, "without a store it was not expired");
		CHECK(strcmp(line, revoked_line) != 0,
		      "expired and revoked print the same line, and renewing one of them "
		      "would be exactly the wrong response");
	}

	/* IT SAYS USABLE AND NOT ALLOWED: finding a chain is not
	 * authorisation. */
	chain_of(&chain, FZN_NO_EXPIRY);
	CHECK(fzn_capability_print(&chain, NULL, 0u, line, sizeof(line), &len, &s) ==
	              FZN_CHAIN_OK,
	      "a usable chain would not render");
	CHECK(strstr(line, "allowed") == NULL,
	      "the line claims authorisation, which holding a chain is not");

	/* THE STATE IS REQUIRED, and a refusal leaves the conservative value. */
	CHECK(fzn_capability_print(&chain, NULL, 0u, line, sizeof(line), &len, NULL) ==
	              FZN_CHAIN_ERR_MALFORMED,
	      "the state was optional after all");
	{
		char small[4];
		size_t needed = 0;

		memset(small, '@', sizeof(small));
		s = FZN_CAPABILITY_USABLE;
		CHECK(fzn_capability_print(&chain, NULL, 0u, small, sizeof(small), &needed,
		                           &s) == FZN_CHAIN_ERR_MALFORMED,
		      "a buffer too small was written anyway");
		CHECK(needed > sizeof(small), "the size needed was not reported");
		CHECK(small[0] == '@', "a refused render left bytes in the buffer");
		CHECK(s == FZN_CAPABILITY_NONE, "a refused render left a reassuring state");
	}

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("capability_print_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
