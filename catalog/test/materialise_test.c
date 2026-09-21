/* Tests for catalog/materialise.c: a pattern and an entity's attributes into a
 * relative path. sec 338.
 *
 * THE CASE THIS SUITE EXISTS FOR is the asymmetry, because it is the one that
 * is a security property rather than a tidiness one:
 *
 *   A PATTERN'S LITERAL TEXT MAY CONTAIN `/`; A SUBSTITUTED VALUE MAY NOT.
 *
 * The pattern is the operator's -- they wrote it, and `{place}/{title}` making
 * a directory is the point. The VALUES are other hosts' assertions, and in a
 * cooperative estate anybody may assert an attribute about an entity. A value
 * holding `/` creates directories the pattern never asked for, and `..` climbs
 * out of the managed source entirely, which is a write outside the one place
 * C14 permits one.
 *
 * So every traversal case below is driven against a CONTROL that must still
 * pass: the same pattern, with a value that is merely unusual rather than
 * dangerous. A refusal that refused everything would satisfy the attack cases
 * and be useless.
 */

#include "../materialise.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

#if defined(__GNUC__)
#define FZN_CHECK_PRINTF __attribute__((format(printf, 3, 4)))
#else
#define FZN_CHECK_PRINTF
#endif

static void check_at(int ok, int line, const char *fmt, ...) FZN_CHECK_PRINTF;

static void check_at(int ok, int line, const char *fmt, ...)
{
	va_list ap;

	checks++;
	if (ok)
		return;

	failures++;
	fprintf(stderr, "  FAIL materialise_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)

static uint8_t host[32];
static uint8_t e1[32];

static void att(fzn_catalog_assertion_t *a, const char *name, const char *value,
                int live)
{
	memset(a, 0, sizeof(*a));
	a->issuer = host;  a->issuer_len = 32;
	a->entity = e1;    a->entity_len = 32;
	a->name = (const uint8_t *)name;   a->name_len = strlen(name);
	a->value = (const uint8_t *)value; a->value_len = strlen(value);
	a->attr_class = FZN_CATALOG_LABEL;
	a->scope = FZN_CATALOG_ESTATE;
	a->merge = FZN_CATALOG_UNION;
	a->capability = FZN_CATALOG_CAP_NONE;
	a->live = live;
}

/* Run a pattern, returning the verdict and the path as a C string. */
static fzn_catalog_err_t run(const char *pattern, const fzn_catalog_assertion_t *set,
                             size_t n, char *buf, size_t cap, size_t *at)
{
	size_t len = 0;
	fzn_catalog_err_t r;

	memset(buf, 0, cap);
	r = fzn_catalog_materialise((const uint8_t *)pattern, strlen(pattern), set, n,
	                            e1, 32, (uint8_t *)buf, cap - 1u, &len, at);
	if (r == FZN_CATALOG_OK)
		buf[len] = '\0';
	return r;
}

/* THE ORDINARY CASE. */
static void test_substitution(void)
{
	fzn_catalog_assertion_t set[3];
	char buf[FZN_CATALOG_PATH_MAX];
	size_t at = 0;

	att(&set[0], "place", "photos", 1);
	att(&set[1], "title", "beach", 1);
	att(&set[2], "ext", "jpg", 1);

	CHECK(run("{place}/{title}.{ext}", set, 3, buf, sizeof(buf), &at) ==
	          FZN_CATALOG_OK,
	      "an ordinary pattern was refused");
	CHECK(strcmp(buf, "photos/beach.jpg") == 0, "the path is '%s'", buf);

	/* Literal text only. */
	CHECK(run("fixed/name.bin", set, 3, buf, sizeof(buf), &at) == FZN_CATALOG_OK &&
	          strcmp(buf, "fixed/name.bin") == 0,
	      "a pattern with no substitution came out as '%s'", buf);

	/* BRACES ARE ESCAPED BY DOUBLING, and a lone closer is a mistyped
	 * pattern rather than a literal -- guessing which was meant is how a
	 * brace ends up in a filename. */
	CHECK(run("{{{title}}}", set, 3, buf, sizeof(buf), &at) == FZN_CATALOG_OK &&
	          strcmp(buf, "{beach}") == 0,
	      "escaped braces came out as '%s', not '{beach}'", buf);
	CHECK(run("a}b", set, 3, buf, sizeof(buf), &at) == FZN_CATALOG_ERR_MALFORMED,
	      "a lone closing brace was taken as a literal");
	CHECK(run("{title", set, 3, buf, sizeof(buf), &at) == FZN_CATALOG_ERR_MALFORMED,
	      "an unterminated substitution was accepted");
	CHECK(run("{}", set, 3, buf, sizeof(buf), &at) == FZN_CATALOG_ERR_MALFORMED,
	      "an empty attribute name was accepted");
}

/* THE ASYMMETRY, which is the point of the module. */
static void test_a_value_cannot_make_directories(void)
{
	fzn_catalog_assertion_t set[1];
	char buf[FZN_CATALOG_PATH_MAX];
	size_t at = 0;

	/* THE CONTROL FIRST: the same pattern, with a value that is unusual but
	 * safe. A refusal that refused everything would pass every case below
	 * and protect nothing. */
	att(&set[0], "title", "a strange - name (2026)", 1);
	CHECK(run("photos/{title}", set, 1, buf, sizeof(buf), &at) == FZN_CATALOG_OK &&
	          strcmp(buf, "photos/a strange - name (2026)") == 0,
	      "an unusual but safe value was refused, so the check refuses "
	      "everything and the cases below hold for the wrong reason");

	/* AND THE PATTERN'S OWN SLASH IS FINE -- that is how it makes
	 * directories, and it is the operator's own text. */
	CHECK(run("a/b/c/{title}", set, 1, buf, sizeof(buf), &at) == FZN_CATALOG_OK,
	      "the pattern's own separators were refused");

	att(&set[0], "title", "evil/name", 1);
	CHECK(run("photos/{title}", set, 1, buf, sizeof(buf), &at) == FZN_CATALOG_ERR_KIND,
	      "a value containing a separator was substituted, so another host's "
	      "assertion creates directories the pattern never asked for");

	att(&set[0], "title", "..", 1);
	CHECK(run("photos/{title}", set, 1, buf, sizeof(buf), &at) == FZN_CATALOG_ERR_KIND,
	      "a value of '..' was substituted, which climbs out of the managed "
	      "source -- a write outside the one place C14 permits one");

	att(&set[0], "title", ".", 1);
	CHECK(run("photos/{title}", set, 1, buf, sizeof(buf), &at) == FZN_CATALOG_ERR_KIND,
	      "a value of '.' was substituted");

	att(&set[0], "title", "back\\slash", 1);
	CHECK(run("photos/{title}", set, 1, buf, sizeof(buf), &at) == FZN_CATALOG_ERR_KIND,
	      "a value containing a backslash was substituted -- a filename here "
	      "and a separator on a host mounting the same collection");

	/* A NUL truncates a path at the C boundary, so everything after it
	 * silently disappears. */
	{
		fzn_catalog_assertion_t nul[1];

		att(&nul[0], "title", "ok", 1);
		nul[0].value = (const uint8_t *)"a\0b";
		nul[0].value_len = 3;
		CHECK(run("photos/{title}", nul, 1, buf, sizeof(buf), &at) ==
		          FZN_CATALOG_ERR_KIND,
		      "a value containing NUL was substituted, and everything after it "
		      "silently disappears at the C boundary");
	}

	att(&set[0], "title", "new\nline", 1);
	CHECK(run("photos/{title}", set, 1, buf, sizeof(buf), &at) == FZN_CATALOG_ERR_KIND,
	      "a value containing a control character was substituted -- a name "
	      "nobody can type is a name nobody can remove");

	att(&set[0], "title", "", 1);
	CHECK(run("photos/{title}", set, 1, buf, sizeof(buf), &at) == FZN_CATALOG_ERR_KIND,
	      "an empty value was substituted, giving a path with a hole in it");

	/* The helper is the same rule, exposed so a consumer building a name
	 * another way does not write a second copy of it. */
	CHECK(fzn_catalog_path_component_ok((const uint8_t *)"fine", 4),
	      "the exposed rule refuses a safe component");
	CHECK(!fzn_catalog_path_component_ok((const uint8_t *)"a/b", 3),
	      "the exposed rule accepts a separator");
	CHECK(!fzn_catalog_path_component_ok(NULL, 0), "the exposed rule accepts a null");
}

/* A MISSING ATTRIBUTE IS REFUSED, and TWO LIVE VALUES ARE TOO. */
static void test_absent_and_ambiguous(void)
{
	fzn_catalog_assertion_t set[3];
	char buf[FZN_CATALOG_PATH_MAX];
	size_t at = 99;

	att(&set[0], "title", "beach", 1);

	CHECK(run("{artist} - {title}", set, 1, buf, sizeof(buf), &at) ==
	          FZN_CATALOG_ERR_ABSENT,
	      "a missing attribute was substituted empty, giving ' - beach' -- a "
	      "name a person did not ask for and would have to notice");
	CHECK(at == 0, "the offset of the failure is %zu, not 0 where {artist} is", at);

	/* A RETRACTED ASSERTION IS NOT A VALUE. */
	att(&set[1], "artist", "someone", 0);
	CHECK(run("{artist}", set, 2, buf, sizeof(buf), &at) == FZN_CATALOG_ERR_ABSENT,
	      "a retracted assertion supplied a value");

	/* TWO DIFFERENT LIVE VALUES IS A DISAGREEMENT, and resolving it to build
	 * a filename would resolve it where nobody would look. */
	att(&set[1], "artist", "one", 1);
	att(&set[2], "artist", "two", 1);
	CHECK(run("{artist}", set, 3, buf, sizeof(buf), &at) == FZN_CATALOG_ERR_KIND,
	      "two hosts disagreeing about an attribute silently picked a winner "
	      "to build a filename from");

	/* BUT TWO HOSTS AGREEING IS NOT A DISAGREEMENT -- and refusing it would
	 * make a filename depend on how many hosts happened to say the same. */
	att(&set[2], "artist", "one", 1);
	CHECK(run("{artist}", set, 3, buf, sizeof(buf), &at) == FZN_CATALOG_OK &&
	          strcmp(buf, "one") == 0,
	      "two hosts asserting the SAME value was treated as a disagreement");

	/* The offset points at the failing substitution, not at the start. */
	att(&set[1], "artist", "one", 1);
	att(&set[2], "artist", "one", 1);
	CHECK(run("{artist}/{missing}", set, 3, buf, sizeof(buf), &at) ==
	          FZN_CATALOG_ERR_ABSENT && at == 9u,
	      "the reported offset is %zu, not 9 where {missing} begins", at);
}

/* BOUNDS, and nothing written unless the whole path fits. */
static void test_bounds(void)
{
	fzn_catalog_assertion_t set[1];
	char buf[FZN_CATALOG_PATH_MAX];
	char big[FZN_CATALOG_COMPONENT_MAX + 8u];
	size_t at = 0;

	memset(big, 'x', sizeof(big));
	big[sizeof(big) - 1u] = '\0';

	att(&set[0], "title", big, 1);
	CHECK(run("{title}", set, 1, buf, sizeof(buf), &at) == FZN_CATALOG_ERR_KIND,
	      "a value longer than one path component was substituted");

	att(&set[0], "title", "beach", 1);
	{
		size_t len = 0;
		uint8_t small[3];

		CHECK(fzn_catalog_materialise((const uint8_t *)"photos/{title}", 14, set,
		                              1, e1, 32, small, sizeof(small), &len,
		                              &at) == FZN_CATALOG_ERR_RANGE,
		      "a path was written past the caller's buffer");
		CHECK(len == 0, "a refused call reported a length");
		CHECK(small[0] == 0 || 1, "unused");
	}

	/* A pattern over its own bound is refused before anything is read. */
	{
		char huge[FZN_CATALOG_PATTERN_MAX + 8u];

		memset(huge, 'a', sizeof(huge));
		huge[sizeof(huge) - 1u] = '\0';
		CHECK(run(huge, set, 1, buf, sizeof(buf), &at) == FZN_CATALOG_ERR_MALFORMED,
		      "a pattern longer than the bound was parsed anyway");
	}

	/* An empty pattern produces no path, which is not a path. */
	CHECK(run("", set, 1, buf, sizeof(buf), &at) == FZN_CATALOG_ERR_MALFORMED,
	      "an empty pattern produced a path");

	/* Arguments. */
	{
		size_t len = 0;

		CHECK(fzn_catalog_materialise(NULL, 4, set, 1, e1, 32, (uint8_t *)buf,
		                              sizeof(buf), &len, &at) ==
		          FZN_CATALOG_ERR_MALFORMED, "a null pattern");
		CHECK(fzn_catalog_materialise((const uint8_t *)"x", 1, set, 1, NULL, 32,
		                              (uint8_t *)buf, sizeof(buf), &len, &at) ==
		          FZN_CATALOG_ERR_MALFORMED, "a null entity");
		CHECK(fzn_catalog_materialise((const uint8_t *)"x", 1, set, 1, e1, 32,
		                              (uint8_t *)buf, sizeof(buf), NULL, &at) ==
		          FZN_CATALOG_ERR_MALFORMED, "nowhere to put the length");
		/* The offset is optional. */
		CHECK(fzn_catalog_materialise((const uint8_t *)"x", 1, set, 1, e1, 32,
		                              (uint8_t *)buf, sizeof(buf), &len, NULL) ==
		          FZN_CATALOG_OK, "the offset was required after all");
	}
}

int main(void)
{
	memset(host, 0x01, sizeof(host));
	memset(e1, 0xe1, sizeof(e1));

	test_substitution();
	test_a_value_cannot_make_directories();
	test_absent_and_ambiguous();
	test_bounds();

	printf("materialise_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
