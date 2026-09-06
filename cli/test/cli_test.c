/* Tests for cli/cli.c: the shared option vocabulary.
 *
 * THE CASES THIS FILE EXISTS FOR are the ones a hand-written parser gets
 * wrong and nobody notices until a deployment behaves oddly: an option given
 * twice, a value that is empty, a number that overflows, and a value this
 * accepts that the module owning it would refuse. The last is the one worth
 * the most -- a bound written twice is a bound that drifts, so the suite
 * checks this module's answers against `chain/service.h`'s own constants
 * rather than against numbers written here.
 *
 * And the prefix cases, because `option()` matches a prefix: an argument that
 * merely STARTS with a known option's name must not be claimed.
 */

#include "../cli.h"

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
	fprintf(stderr, "  FAIL cli_test.c:%d: ", line);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\n");
}

#define CHECK(cond, ...) check_at((cond) ? 1 : 0, __LINE__, __VA_ARGS__)
#define REQUIRE(cond, ...)                                   \
	do {                                                 \
		int require_ok = (cond) ? 1 : 0;             \
		check_at(require_ok, __LINE__, __VA_ARGS__); \
		if (!require_ok)                             \
			return;                              \
	} while (0)

/* Offer one argument and report both halves of the answer. */
static fzn_cli_err_t offer(fzn_cli_t *cli, const char *arg, int *claimed)
{
	*claimed = -1;
	return fzn_cli_arg(cli, arg, claimed);
}

static void test_every_option_is_read(void)
{
	fzn_cli_t cli;
	int claimed = 0;

	fzn_cli_init(&cli);
	CHECK(offer(&cli, "--fuzznet-dir=/var/lib/fuzznet", &claimed) == FZN_CLI_OK && claimed,
	      "the identity directory was not read");
	CHECK(cli.dir && strcmp(cli.dir, "/var/lib/fuzznet") == 0, "the directory is wrong");
	CHECK(offer(&cli, "--fuzznet-store=/var/lib/fuzznet/store", &claimed) == FZN_CLI_OK,
	      "the store directory was not read");
	CHECK(cli.store && strcmp(cli.store, "/var/lib/fuzznet/store") == 0,
	      "the store is wrong");
	CHECK(offer(&cli, "--fuzznet-service=7", &claimed) == FZN_CLI_OK, "the service was not read");
	CHECK(cli.service == 7u, "the service is wrong");
	CHECK(offer(&cli, "--fuzznet-product=100", &claimed) == FZN_CLI_OK,
	      "the product was not read");
	CHECK(cli.product == 100u, "the product is wrong");
	CHECK(offer(&cli, "--fuzznet-owner=no", &claimed) == FZN_CLI_OK, "the owner was not read");
	CHECK(cli.owner == FZN_CLI_OWNER_NO, "the owner is wrong");
}

/* The unset values are the ones the owning modules refuse, so a field nobody
 * set reaches an error rather than a wrong grant. */
static void test_unset_is_the_value_that_fails_closed(void)
{
	fzn_cli_t cli;

	fzn_cli_init(&cli);
	CHECK(cli.dir == NULL && cli.store == NULL, "a path defaulted to something");
	CHECK(cli.service == FZN_SERVICE_NONE, "the service did not default to the refused value");
	CHECK(cli.product == FZN_PRODUCT_NONE, "the product did not default to the refused value");
	CHECK(cli.owner == FZN_CLI_OWNER_AUTO, "the owner did not default to auto");
	fzn_cli_init(NULL); /* must not crash */
	CHECK(1, "init tolerates a null");
}

/* NOT AN ERROR: somebody else's argument is the caller's business. */
static void test_another_programs_argument_is_left_alone(void)
{
	fzn_cli_t cli;
	int claimed = 0;

	fzn_cli_init(&cli);
	CHECK(offer(&cli, "--verbose", &claimed) == FZN_CLI_OK && claimed == 0,
	      "an unrelated option was claimed or refused");
	CHECK(offer(&cli, "-v", &claimed) == FZN_CLI_OK && claimed == 0,
	      "a short option was claimed");
	CHECK(offer(&cli, "somefile", &claimed) == FZN_CLI_OK && claimed == 0,
	      "a bare argument was claimed");
	CHECK(offer(&cli, "", &claimed) == FZN_CLI_OK && claimed == 0,
	      "an empty argument was claimed");
	CHECK(cli.dir == NULL && cli.service == FZN_SERVICE_NONE,
	      "an unclaimed argument changed something");
}

/* The matcher compares a prefix, so a longer name beginning with a known one
 * must not be swallowed. */
static void test_a_longer_name_is_not_claimed(void)
{
	fzn_cli_t cli;
	int claimed = 0;

	fzn_cli_init(&cli);
	CHECK(offer(&cli, "--fuzznet-directory=/tmp", &claimed) == FZN_CLI_OK && claimed == 0,
	      "an option whose name merely starts with a known one was claimed");
	CHECK(offer(&cli, "--fuzznet-storefront=x", &claimed) == FZN_CLI_OK && claimed == 0,
	      "--fuzznet-storefront was claimed as --fuzznet-store");
	CHECK(offer(&cli, "--fuzznet-dir", &claimed) == FZN_CLI_OK && claimed == 0,
	      "an option with no '=' was claimed");
	CHECK(cli.dir == NULL && cli.store == NULL, "one of those set something");
}

/* Ours, and unusable. `claimed` must still be 1 so the caller can name it. */
static void test_a_bad_value_is_ours_and_refused(void)
{
	fzn_cli_t cli;
	int claimed = 0;

	fzn_cli_init(&cli);
	CHECK(offer(&cli, "--fuzznet-dir=", &claimed) == FZN_CLI_ERR_VALUE && claimed == 1,
	      "an empty directory was accepted, or disowned");
	CHECK(offer(&cli, "--fuzznet-service=0", &claimed) == FZN_CLI_ERR_VALUE,
	      "a service of zero was accepted");
	CHECK(offer(&cli, "--fuzznet-service=x", &claimed) == FZN_CLI_ERR_VALUE,
	      "a service that is not a number was accepted");
	CHECK(offer(&cli, "--fuzznet-service=-1", &claimed) == FZN_CLI_ERR_VALUE,
	      "a negative service was accepted");
	CHECK(offer(&cli, "--fuzznet-service= 7", &claimed) == FZN_CLI_ERR_VALUE,
	      "leading whitespace was accepted");
	CHECK(offer(&cli, "--fuzznet-service=4294967296", &claimed) == FZN_CLI_ERR_VALUE,
	      "a service past a uint32 was accepted");
	CHECK(offer(&cli, "--fuzznet-service=99999999999999999999999", &claimed)
	              == FZN_CLI_ERR_VALUE,
	      "a long run of digits wrapped rather than being refused");
	CHECK(offer(&cli, "--fuzznet-owner=maybe", &claimed) == FZN_CLI_ERR_VALUE && claimed == 1,
	      "an unknown owner value was accepted");
	CHECK(cli.service == FZN_SERVICE_NONE && cli.dir == NULL,
	      "a refused value was written anyway");
}

/*
 * THE BOUND IS THE OWNING MODULE'S. Checked against `chain/service.h`'s
 * constants rather than against numbers written here, because a second set
 * would drift -- and would drift quietly, since a value this accepted and
 * that module refused fails much later and somewhere else.
 */
static void test_the_product_bound_is_service_hs(void)
{
	fzn_cli_t cli;
	char at_max[32], past_max[32], wildcard[32];
	int claimed = 0;

	snprintf(at_max, sizeof(at_max), "--fuzznet-product=%lu",
	         (unsigned long)FZN_PRODUCT_MAX);
	snprintf(past_max, sizeof(past_max), "--fuzznet-product=%lu",
	         (unsigned long)FZN_PRODUCT_MAX + 1ul);
	snprintf(wildcard, sizeof(wildcard), "--fuzznet-product=%lu",
	         (unsigned long)FZN_PRODUCT_ANY);

	fzn_cli_init(&cli);
	CHECK(offer(&cli, "--fuzznet-product=0", &claimed) == FZN_CLI_ERR_VALUE,
	      "a product of zero was accepted");
	CHECK(offer(&cli, past_max, &claimed) == FZN_CLI_ERR_VALUE,
	      "a product past FZN_PRODUCT_MAX was accepted");
	/* THE WILDCARD IS NOT A NODE'S PRODUCT: it is a capability's scope, and
	 * accepting it here would let a node claim to BE every product. */
	CHECK(offer(&cli, wildcard, &claimed) == FZN_CLI_ERR_VALUE,
	      "the see-everything wildcard was accepted as a node's product");
	CHECK(cli.product == FZN_PRODUCT_NONE, "a refused product was written");
	/* THE CONTROL: the largest real product IS accepted, so the refusals
	 * above are the bound rather than this option never working. */
	CHECK(offer(&cli, at_max, &claimed) == FZN_CLI_OK && cli.product == FZN_PRODUCT_MAX,
	      "the largest real product was refused");
}

/* Two values for one setting is an ambiguous invocation, and keeping either
 * silently is how a configuration bug survives being read. */
static void test_a_repeated_option_is_refused(void)
{
	fzn_cli_t cli;
	int claimed = 0;

	fzn_cli_init(&cli);
	REQUIRE(offer(&cli, "--fuzznet-dir=/a", &claimed) == FZN_CLI_OK, "the first was refused");
	CHECK(offer(&cli, "--fuzznet-dir=/b", &claimed) == FZN_CLI_ERR_DUPLICATE && claimed == 1,
	      "a repeated directory was accepted");
	CHECK(strcmp(cli.dir, "/a") == 0, "the refused duplicate overwrote the first value");

	REQUIRE(offer(&cli, "--fuzznet-service=1", &claimed) == FZN_CLI_OK, "service refused");
	CHECK(offer(&cli, "--fuzznet-service=2", &claimed) == FZN_CLI_ERR_DUPLICATE,
	      "a repeated service was accepted");
	CHECK(cli.service == 1u, "the refused duplicate overwrote the service");

	REQUIRE(offer(&cli, "--fuzznet-store=/s", &claimed) == FZN_CLI_OK, "store refused");
	CHECK(offer(&cli, "--fuzznet-store=/t", &claimed) == FZN_CLI_ERR_DUPLICATE,
	      "a repeated store was accepted");

	REQUIRE(offer(&cli, "--fuzznet-product=5", &claimed) == FZN_CLI_OK, "product refused");
	CHECK(offer(&cli, "--fuzznet-product=6", &claimed) == FZN_CLI_ERR_DUPLICATE,
	      "a repeated product was accepted");
	CHECK(cli.product == 5u, "the refused duplicate overwrote the product");
}

/* The one place the duplicate rule bends, and the header says why: AUTO is
 * both the default and a value somebody may type, so "was it set" cannot be
 * read off the field. */
static void test_the_owner_option_may_repeat(void)
{
	fzn_cli_t cli;
	int claimed = 0;

	fzn_cli_init(&cli);
	CHECK(offer(&cli, "--fuzznet-owner=yes", &claimed) == FZN_CLI_OK, "yes refused");
	CHECK(offer(&cli, "--fuzznet-owner=no", &claimed) == FZN_CLI_OK,
	      "the owner option refused a second value where the header says it does not");
	CHECK(cli.owner == FZN_CLI_OWNER_NO, "the last owner value did not win");
	CHECK(offer(&cli, "--fuzznet-owner=auto", &claimed) == FZN_CLI_OK, "auto refused");
	CHECK(cli.owner == FZN_CLI_OWNER_AUTO, "auto did not take");
}

/* Every consumer prints the same text, which is most of why this exists. */
static void test_the_usage_names_every_option(void)
{
	const char *usage = fzn_cli_usage();

	REQUIRE(usage != NULL, "the usage is null");
	CHECK(strstr(usage, "--fuzznet-dir") != NULL, "the usage does not name --fuzznet-dir");
	CHECK(strstr(usage, "--fuzznet-store") != NULL, "the usage does not name --fuzznet-store");
	CHECK(strstr(usage, "--fuzznet-service") != NULL, "the usage does not name the service");
	CHECK(strstr(usage, "--fuzznet-product") != NULL, "the usage does not name the product");
	CHECK(strstr(usage, "--fuzznet-owner") != NULL, "the usage does not name the owner");
	/* The one thing a person will get wrong, so it must be said. */
	CHECK(strstr(usage, "'='") != NULL,
	      "the usage does not say values are given with '=' rather than as a next argument");
	CHECK(usage[strlen(usage) - 1u] == '\n', "the usage does not end in a newline");
}

static void test_the_caller_bugs_are_refused(void)
{
	fzn_cli_t cli;
	int claimed = 0;

	fzn_cli_init(&cli);
	CHECK(fzn_cli_arg(NULL, "--fuzznet-dir=/a", &claimed) == FZN_CLI_ERR_MALFORMED,
	      "a null cli was accepted");
	CHECK(fzn_cli_arg(&cli, NULL, &claimed) == FZN_CLI_ERR_MALFORMED,
	      "a null argument was accepted");
	CHECK(fzn_cli_arg(&cli, "--fuzznet-dir=/a", NULL) == FZN_CLI_ERR_MALFORMED,
	      "a null claimed was accepted");
	CHECK(cli.dir == NULL, "a refused call set something");
}

static void test_the_errors_render(void)
{
	CHECK(fzn_cli_err_str(FZN_CLI_OK)[0] != '\0', "OK renders empty");
	CHECK(fzn_cli_err_str(FZN_CLI_ERR_MALFORMED)[0] != '\0', "MALFORMED renders empty");
	CHECK(fzn_cli_err_str(FZN_CLI_ERR_VALUE)[0] != '\0', "VALUE renders empty");
	CHECK(fzn_cli_err_str(FZN_CLI_ERR_DUPLICATE)[0] != '\0', "DUPLICATE renders empty");
	CHECK(fzn_cli_err_str((fzn_cli_err_t)-99)[0] != '\0', "an unknown error renders empty");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	check_at(0, __LINE__, "deliberate");
	CHECK(failures == before + 1, "a failing check did not count");
	failures = before;
	checks -= 1;
}

int main(void)
{
	test_every_option_is_read();
	test_unset_is_the_value_that_fails_closed();
	test_another_programs_argument_is_left_alone();
	test_a_longer_name_is_not_claimed();
	test_a_bad_value_is_ours_and_refused();
	test_the_product_bound_is_service_hs();
	test_a_repeated_option_is_refused();
	test_the_owner_option_may_repeat();
	test_the_usage_names_every_option();
	test_the_caller_bugs_are_refused();
	test_the_errors_render();
	test_the_suite_can_tell_pass_from_fail();

	printf("cli_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
