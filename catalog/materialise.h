/* MATERIALISING A PATH: turning a pattern and an entity's attributes into a
 * relative path inside a managed source. C22, and project.md sec 338.
 *
 * C22 settles WHEN: "the on-disk layout of a managed source is MATERIALISED
 * when an entity is placed and re-derived only when asked for. A catalogue may
 * change hourly, and a layout that tracked it would silently rearrange a
 * person's disk from a rename nobody here made." The copyright holder settled
 * WHAT on 2026-09-21: a substitution pattern over the entity's attributes.
 *
 * SO THE RESULT IS STORED, NOT A VIEW. This runs once, at placement, and what
 * is kept is the answer. Nothing re-evaluates a pattern because an attribute
 * changed -- that is the rearrangement C22 forbids.
 *
 * THE LANGUAGE IS AS SMALL AS IT CAN BE:
 *
 *     {name}     the value of the attribute called `name`, for this entity
 *     {{  }}     a literal brace
 *     anything else is literal, INCLUDING `/`
 *
 * ===========================================================================
 * THE ONE THAT IS A SECURITY PROPERTY AND NOT A TIDINESS ONE
 * ===========================================================================
 *
 * A TEMPLATE'S LITERAL TEXT MAY CONTAIN `/`. A SUBSTITUTED VALUE MAY NOT.
 *
 * That asymmetry is the whole of it. The pattern is the operator's -- they
 * wrote it, and `{place}/{title}` making a directory is the point. The VALUES
 * are other hosts' assertions: in a cooperative estate anybody may assert an
 * attribute about an entity, so a value is untrusted input that happens to
 * arrive signed. A value containing `/` would create directories the pattern
 * never asked for, and `..` would climb out of the managed source entirely --
 * which is a write outside the one place C14 says an organiser may write.
 *
 * So a value is refused if it holds `/`, `\`, NUL, a control character, or is
 * `.` or `..`. The backslash is refused although this library runs on POSIX
 * hosts, because the estate is mixed and a value that is a filename here is a
 * separator on a host that mounts the same collection.
 *
 * WHAT IS DELIBERATELY NOT REFUSED: platform-reserved names (CON, PRN, AUX and
 * their kind), trailing dots and spaces, and case collisions. Those are
 * properties of a filesystem this library never sees, and guessing at them
 * from here would be the same error as deciding which register is right about
 * what (C26a). A consumer placing files knows its filesystem; this does not.
 *
 * ===========================================================================
 *
 * A MISSING ATTRIBUTE IS REFUSED, not substituted empty. `{artist} - {title}`
 * with no artist gives " - title", which is a name a person did not ask for
 * and would have to notice. Refusing is recoverable -- C22 stores the result,
 * so a consumer may supply a path itself -- and a malformed name is not.
 *
 * TWO LIVE VALUES ARE REFUSED TOO, which is C5b one layer out: "never silently
 * pick a winner". An attribute with two live values is a disagreement between
 * hosts, and choosing one to build a filename from would be resolving it by
 * accident, in the one place nobody would look for a resolution.
 */

#ifndef FZN_CATALOG_MATERIALISE_H
#define FZN_CATALOG_MATERIALISE_H

#include <stddef.h>
#include <stdint.h>

#include "catalog.h"

/* The longest pattern, the longest path it may produce, and the longest one
 * component of that path.
 *
 * The component bound is POSIX's NAME_MAX. The path bound is well under
 * PATH_MAX and is a RELATIVE path inside a source (C13), so the source's own
 * prefix is not counted here and a consumer with a deep root has room. */
#define FZN_CATALOG_PATTERN_MAX 256u
#define FZN_CATALOG_PATH_MAX 1024u
#define FZN_CATALOG_COMPONENT_MAX 255u

/*
 * Materialise `pattern` for `entity` against `set`, writing a relative path.
 *
 * `at_out` is optional and receives the BYTE OFFSET in the pattern where a
 * failure occurred, which is the difference between an error a person can act
 * on and a puzzle: a pattern with six substitutions and one missing attribute
 * otherwise says only that something was missing.
 *
 *   FZN_CATALOG_ERR_MALFORMED  a null, a pattern over its bound, an
 *                              unterminated `{`, or a `}` with no `{`.
 *   FZN_CATALOG_ERR_ABSENT     a named attribute has no live value here.
 *   FZN_CATALOG_ERR_KIND       a named attribute has MORE THAN ONE live value,
 *                              which is a disagreement this must not resolve;
 *                              or a value is not usable in a path.
 *   FZN_CATALOG_ERR_RANGE      the path does not fit `cap`, exceeds
 *                              FZN_CATALOG_PATH_MAX, or a component exceeds
 *                              FZN_CATALOG_COMPONENT_MAX.
 *
 * Writes nothing unless the whole path fits, so a refused call leaves no
 * half-built path for a caller that forgot to read the status.
 */
fzn_catalog_err_t fzn_catalog_materialise(const uint8_t *pattern, size_t pattern_len,
                                          const fzn_catalog_assertion_t *set,
                                          size_t count, const uint8_t *entity,
                                          size_t entity_len, uint8_t *out, size_t cap,
                                          size_t *len_out, size_t *at_out);

/* Is `value` usable as one path component? Exposed because a consumer that
 * builds a name any other way wants the same rule, and a second statement of
 * it would be a second thing to be wrong. */
int fzn_catalog_path_component_ok(const uint8_t *value, size_t len);

#endif /* FZN_CATALOG_MATERIALISE_H */
