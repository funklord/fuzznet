/* The version, checked against itself.
 *
 * `make style` compares this header against the `VERSION` file, which is the
 * copy that matters most. What it cannot check is the header's INTERNAL
 * agreement -- that the string spells the same version as the three numbers.
 * Bumping the numbers and forgetting the string is the drift that survives a
 * VERSION comparison keyed on either one, and it produces a library that
 * reports one version through `fzn_version_string()` and a different one
 * through `FZN_VERSION_NUMBER`.
 *
 * The compile-time half is static asserts, because a version that is wrong
 * should not produce a running program that mentions it.
 */

#include "../version.h"

#include <stdio.h>
#include <string.h>

/* The bound the packing implies, stated rather than assumed. At 100 a minor
 * would carry into the major and 0.1.100 would equal 0.2.0 -- two different
 * releases comparing equal, which is worse than either being wrong. */
_Static_assert(FZN_VERSION_MINOR >= 0 && FZN_VERSION_MINOR <= 99,
                "FZN_VERSION_MINOR is outside what FZN_VERSION_NUMBER can pack");
_Static_assert(FZN_VERSION_PATCH >= 0 && FZN_VERSION_PATCH <= 99,
                "FZN_VERSION_PATCH is outside what FZN_VERSION_NUMBER can pack");
_Static_assert(FZN_VERSION_MAJOR >= 0, "FZN_VERSION_MAJOR is negative");

/* The macro is a comparison and must answer both ways at its own boundary.
 * A version test that is true for everything reads exactly like one that
 * works, which is why the false cases are here at all. */
_Static_assert(FZN_VERSION_AT_LEAST(FZN_VERSION_MAJOR, FZN_VERSION_MINOR, FZN_VERSION_PATCH),
                "FZN_VERSION_AT_LEAST is false for this very version");
_Static_assert(!FZN_VERSION_AT_LEAST(FZN_VERSION_MAJOR, FZN_VERSION_MINOR, FZN_VERSION_PATCH + 1),
                "FZN_VERSION_AT_LEAST is true for a patch this library does not have");
_Static_assert(!FZN_VERSION_AT_LEAST(FZN_VERSION_MAJOR + 1, 0, 0),
                "FZN_VERSION_AT_LEAST is true for a major this library does not have");
_Static_assert(FZN_VERSION_AT_LEAST(0, 0, 0), "FZN_VERSION_AT_LEAST is false for 0.0.0");

static int failures;
static int checks;

static void expect(int ok, const char *what)
{
	checks++;
	if (!ok) {
		failures++;
		printf("  FAIL: %s\n", what);
	}
}

int main(void)
{
	char spelled[32];

	/* THE STRING AGAINST THE NUMBERS. Built from the three macros and
	 * compared, rather than parsed out of the string, because building it
	 * cannot silently accept a trailing suffix the parse would ignore. */
	snprintf(spelled, sizeof(spelled), "%d.%d.%d", FZN_VERSION_MAJOR, FZN_VERSION_MINOR,
	         FZN_VERSION_PATCH);
	expect(strcmp(spelled, FZN_VERSION_STRING) == 0,
	       "FZN_VERSION_STRING does not spell FZN_VERSION_MAJOR.MINOR.PATCH");

	/* THE LIBRARY AGAINST THE HEADER. In this build they cannot disagree,
	 * which is exactly why the check is cheap to keep: what it pins is
	 * that version.c still derives both answers from these macros rather
	 * than from a literal somebody typed a second time. A caller built
	 * against other headers is where they really diverge, and that is the
	 * comparison version.h asks a consumer to make. */
	expect(strcmp(fzn_version_string(), FZN_VERSION_STRING) == 0,
	       "the linked library reports a different version string than the header");
	expect(fzn_version_number() == (unsigned long)FZN_VERSION_NUMBER,
	       "the linked library reports a different version number than the header");
	expect(fzn_version_string() != NULL, "fzn_version_string returned NULL");

	printf("version_test: %d checks, %d failure(s); library reports %s\n", checks, failures,
	       fzn_version_string());
	return failures == 0 ? 0 : 1;
}
