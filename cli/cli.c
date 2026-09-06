#include "cli.h"

#include <string.h>

/* Decimal only, and parsed here rather than with `strtoul`.
 *
 * `strtoul` needs `errno` to report overflow, accepts leading whitespace and a
 * sign, and takes its digits from the locale -- three behaviours nobody asked
 * for on a command line, and the last of which makes what this accepts a
 * property of the environment. Fifteen lines with an explicit bound answers
 * exactly the question asked: is this a decimal number that fits.
 *
 * Returns nonzero on success, following this library's convention. */
static int parse_u32(const char *at, uint32_t *out)
{
	uint64_t value = 0;
	size_t digits = 0;

	if (!at || !*at)
		return 0;
	for (; *at; at++) {
		if (*at < '0' || *at > '9')
			return 0;
		value = value * 10u + (uint64_t)(*at - '0');
		/* Bounded as it goes rather than after, so a long run of digits
		 * cannot wrap before anything looks at it. */
		if (value > 0xffffffffu)
			return 0;
		digits++;
	}
	if (digits == 0)
		return 0;

	*out = (uint32_t)value;
	return 1;
}

/* Does `arg` begin with `name=`? If so, hand back what follows. */
static int option(const char *arg, const char *name, const char **value)
{
	size_t len = strlen(name);

	if (strncmp(arg, name, len) != 0)
		return 0;
	if (arg[len] != '=')
		return 0;
	*value = arg + len + 1u;
	return 1;
}

void fzn_cli_init(fzn_cli_t *cli)
{
	if (!cli)
		return;

	cli->dir = NULL;
	cli->store = NULL;
	cli->service = FZN_SERVICE_NONE;
	cli->product = FZN_PRODUCT_NONE;
	cli->owner = FZN_CLI_OWNER_AUTO;
}

fzn_cli_err_t fzn_cli_arg(fzn_cli_t *cli, const char *arg, int *claimed)
{
	const char *value = NULL;
	uint32_t number = 0;

	if (claimed)
		*claimed = 0;
	if (!cli || !arg || !claimed)
		return FZN_CLI_ERR_MALFORMED;

	if (option(arg, "--fuzznet-dir", &value)) {
		*claimed = 1;
		if (!*value)
			return FZN_CLI_ERR_VALUE;
		if (cli->dir)
			return FZN_CLI_ERR_DUPLICATE;
		cli->dir = value;
		return FZN_CLI_OK;
	}

	if (option(arg, "--fuzznet-store", &value)) {
		*claimed = 1;
		if (!*value)
			return FZN_CLI_ERR_VALUE;
		if (cli->store)
			return FZN_CLI_ERR_DUPLICATE;
		cli->store = value;
		return FZN_CLI_OK;
	}

	if (option(arg, "--fuzznet-service", &value)) {
		*claimed = 1;
		if (!parse_u32(value, &number) || number == FZN_SERVICE_NONE)
			return FZN_CLI_ERR_VALUE;
		if (cli->service != FZN_SERVICE_NONE)
			return FZN_CLI_ERR_DUPLICATE;
		cli->service = number;
		return FZN_CLI_OK;
	}

	if (option(arg, "--fuzznet-product", &value)) {
		*claimed = 1;
		/* THE WILDCARD IS NOT A NODE'S PRODUCT. FZN_PRODUCT_ANY is a
		 * capability's scope -- a holder entitled to see across
		 * projects -- and sec 129's pair refuses it as the subject of a
		 * check for the same reason: a record belongs to a project, not
		 * to all of them. Accepting it here would let a node claim to
		 * BE every product. */
		if (!parse_u32(value, &number) || number == FZN_PRODUCT_NONE
		    || number > FZN_PRODUCT_MAX)
			return FZN_CLI_ERR_VALUE;
		if (cli->product != FZN_PRODUCT_NONE)
			return FZN_CLI_ERR_DUPLICATE;
		cli->product = number;
		return FZN_CLI_OK;
	}

	if (option(arg, "--fuzznet-owner", &value)) {
		fzn_cli_owner_t want;

		*claimed = 1;
		if (strcmp(value, "auto") == 0)
			want = FZN_CLI_OWNER_AUTO;
		else if (strcmp(value, "yes") == 0)
			want = FZN_CLI_OWNER_YES;
		else if (strcmp(value, "no") == 0)
			want = FZN_CLI_OWNER_NO;
		else
			return FZN_CLI_ERR_VALUE;
		/* AUTO IS BOTH THE DEFAULT AND A VALUE SOMEBODY MAY TYPE, so
		 * "has it been set" cannot be read off the field. A separate
		 * flag would be a second thing to keep in step; instead an
		 * explicit `--fuzznet-owner=auto` given twice is accepted,
		 * which is the one duplicate this module does not refuse and
		 * the only place its rule bends. */
		cli->owner = want;
		return FZN_CLI_OK;
	}

	return FZN_CLI_OK;
}

const char *fzn_cli_usage(void)
{
	return "fuzznet options:\n"
	       "  --fuzznet-dir=PATH       identity and claim directory\n"
	       "  --fuzznet-store=PATH     record store directory\n"
	       "  --fuzznet-service=N      service number, 1 or above\n"
	       "  --fuzznet-product=N      product number, 1 to 65534\n"
	       "  --fuzznet-owner=WHICH    auto (default), yes, or no\n"
	       "Values are given with '=', not as a following argument.\n";
}

const char *fzn_cli_err_str(fzn_cli_err_t err)
{
	switch (err) {
	case FZN_CLI_OK:
		return "ok";
	case FZN_CLI_ERR_MALFORMED:
		return "malformed";
	case FZN_CLI_ERR_VALUE:
		return "unusable value";
	case FZN_CLI_ERR_DUPLICATE:
		return "given more than once";
	}
	return "unknown";
}
