/* See version.h.
 *
 * These are deliberately not `static inline` in the header. An inline
 * function would be compiled into the CONSUMER and would then report the
 * consumer's own macros back to it, agreeing with itself always and
 * detecting nothing. The whole value is that these are compiled once, into
 * the library, and can therefore disagree with a caller that was built
 * against different headers. */

#include "version.h"

const char *fzn_version_string(void)
{
	return FZN_VERSION_STRING;
}

unsigned long fzn_version_number(void)
{
	return (unsigned long)FZN_VERSION_NUMBER;
}
