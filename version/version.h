/* Which fuzznet is this?
 *
 * The number lived in `VERSION` and **nothing read it** -- not the Makefile,
 * not any header, and there is no packaging yet to read it either. So a
 * consumer could not log which fuzznet it had linked, and could not answer
 * the question this header exists for.
 *
 * TWO WAYS TO ASK, ON PURPOSE, and the pair is the point rather than a
 * convenience:
 *
 *   - The **macros** are what the CONSUMER'S HEADERS say. They are constant
 *     folded, so they answer at compile time and can drive an `#if`.
 *   - `fzn_version_string()` and `fzn_version_number()` are what the LINKED
 *     LIBRARY says, because they are compiled into it.
 *
 * Within one build these agree trivially. They stop agreeing exactly when a
 * consumer compiles against one fuzznet's headers and links a different
 * fuzznet -- an installed copy that moved on, a stale archive, two versions
 * on one machine. That mismatch is otherwise silent until a struct changes
 * shape underneath somebody, which is the worst possible moment to find out.
 * Comparing them at startup is a one-line check and this header exists to
 * make it possible:
 *
 *     if (fzn_version_number() != FZN_VERSION_NUMBER)
 *             refuse("built against fuzznet %s, linked %s",
 *                    FZN_VERSION_STRING, fzn_version_string());
 *
 * `VERSION` REMAINS THE AUTHORITY and this is a copy of it, deliberately,
 * for the reason wire/test/constants_test.c gives about the field lengths:
 * a header that had to be generated would put a build step between a
 * consumer and a constant. What was missing there and is missing here is
 * anything to notice when a copy stops being one, so `make style` compares
 * these three macros against the `VERSION` file and refuses when they
 * disagree.
 */

#ifndef FZN_VERSION_H
#define FZN_VERSION_H

#define FZN_VERSION_MAJOR 0
#define FZN_VERSION_MINOR 1
#define FZN_VERSION_PATCH 0

#define FZN_VERSION_STRING "0.1.0"

/*
 * WHO WROTE THIS. Attribution, which is a statement of fact and grants
 * nothing -- `CLAUDE.md` draws the line and `harmonization.md` (f511d58)
 * carries the rule: three surfaces, not per-file banners.
 *
 * SEPARATE FROM `FZN_VERSION_STRING`, DELIBERATELY, and this is the whole
 * reason it is a second symbol rather than a longer first one. That string
 * is an INTERFACE with two machine consumers already: `make style` extracts
 * it with a `sed` regex to compare against the `VERSION` file, and
 * `version/test/version_test.c` `strcmp`s it against the spelled
 * MAJOR.MINOR.PATCH. Appending "-- Copyright ..." to it breaks both.
 *
 * apt-emerge's `--version` carries the same caution from the other side: its
 * first line keeps its shape because scripts parse it, and the attribution
 * goes on a line of its own. fuzznet has no `--version` -- it is a library --
 * so the equivalent is a symbol a consumer can print beside the version it
 * already prints, which is what will surface in a consumer's build rather
 * than in a program fuzznet does not have.
 *
 * The year is when the work began, 2026-08-08, rather than one chosen to
 * fill the field.
 */
#define FZN_COPYRIGHT "Copyright (C) 2026 Nabeel Sowan <nabeel@vibes.se>"

/* Packed so that two versions compare with `<`, which is what a caller
 * actually wants to do with them. Minor and patch are bounded at 99 by the
 * arithmetic; `make style` refuses a VERSION that would overflow a field
 * rather than letting 0.1.100 and 0.2.0 collide silently. */
#define FZN_VERSION_NUMBER \
        (FZN_VERSION_MAJOR * 10000 + FZN_VERSION_MINOR * 100 + FZN_VERSION_PATCH)

/* For an `#if` in a consumer that supports more than one fuzznet. */
#define FZN_VERSION_AT_LEAST(major, minor, patch) \
        (FZN_VERSION_NUMBER >= ((major) * 10000 + (minor) * 100 + (patch)))

/* What the LINKED LIBRARY is, as against the macros above. Never NULL, and
 * the string is static storage the caller does not own and must not free. */
const char *fzn_version_string(void);

/* The attribution the LINKED library carries, for a consumer that prints one
 * beside `fzn_version_string()`. Never NULL. */
const char *fzn_copyright(void);

/* The same, packed as FZN_VERSION_NUMBER is, for comparison. */
unsigned long fzn_version_number(void);

#endif /* FZN_VERSION_H */
