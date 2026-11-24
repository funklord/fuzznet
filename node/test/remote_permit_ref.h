/* THE REMOTE PERMIT'S HAND CHECK, kept whole as the oracle for the one read
 * through situ's code (project.md sec 1440), as node/test/permit_ref.h is
 * for the local permit. node/test/permit_agree_fuzz holds the two to the same
 * verdict and the same words. */

#ifndef FZN_NODE_TEST_REMOTE_PERMIT_REF_H
#define FZN_NODE_TEST_REMOTE_PERMIT_REF_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define REF_HOST_WORD "host:"
#define REF_HOST_WORD_LEN 5u

static inline int ref_hex_value(uint8_t c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

static inline int ref_word_is(const uint8_t *word, size_t n, const char *name)
{
	return n == strlen(name) && memcmp(word, name, n) == 0;
}

static inline int ref_host_word(const uint8_t *word, size_t n)
{
	size_t i;

	if (n != REF_HOST_WORD_LEN + 64u || memcmp(word, REF_HOST_WORD, REF_HOST_WORD_LEN) != 0)
		return 0;
	for (i = REF_HOST_WORD_LEN; i < n; i++)
		if (ref_hex_value(word[i]) < 0)
			return 0;
	return 1;
}

static inline const char *ref_remote_permit_check(const uint8_t *value, size_t len)
{
	static const char *const SHAPE =
	        "a rule is member, admin, root, host:HEX or none, apart by spaces";
	size_t at = 0, words = 0;
	int none = 0;

	if (!value || !len)
		return SHAPE;
	while (at < len) {
		size_t n = 0;

		while (at + n < len && value[at + n] != ' ')
			n++;
		if (!n)
			return SHAPE;
		if (ref_word_is(value + at, n, "none"))
			none = 1;
		else if (!ref_word_is(value + at, n, "member") && !ref_word_is(value + at, n, "admin")
		         && !ref_word_is(value + at, n, "root") && !ref_host_word(value + at, n))
			return SHAPE;
		words++;
		at += n;
		if (at < len && ++at == len)
			return SHAPE;
	}
	return none && words > 1u ? "none stands alone" : NULL;
}

#endif
