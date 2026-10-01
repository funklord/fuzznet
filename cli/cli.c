#include "cli.h"

#include "../prekey/prekey.h"

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

/* `len` bytes from `2 * len` lowercase or uppercase hex digits, and nothing
 * after them. Nonzero on success; `out` is untouched otherwise. */
static int parse_hex(const char *text, uint8_t *out, size_t len)
{
	uint8_t bytes[FZN_PREKEY_LEN_TOTAL > FZN_PUBKEY_LEN ? FZN_PREKEY_LEN_TOTAL : FZN_PUBKEY_LEN];
	size_t i;

	if (!text || len > sizeof(bytes) || strlen(text) != len * 2u)
		return 0;
	for (i = 0; i < len * 2u; i++) {
		char c = text[i];
		unsigned v;

		if (c >= '0' && c <= '9')
			v = (unsigned)(c - '0');
		else if (c >= 'a' && c <= 'f')
			v = 10u + (unsigned)(c - 'a');
		else if (c >= 'A' && c <= 'F')
			v = 10u + (unsigned)(c - 'A');
		else
			return 0;
		if (i % 2u == 0u)
			bytes[i / 2u] = (uint8_t)(v << 4);
		else
			bytes[i / 2u] = (uint8_t)(bytes[i / 2u] | v);
	}
	if (out)
		memcpy(out, bytes, len);
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
	cli->socket = NULL;
	cli->has_udp_port = 0;
	cli->udp_port = 0;
	cli->udp6 = 0;
	cli->has_node = 0;
	memset(cli->node, 0, sizeof(cli->node));
	cli->prekey = 0;
	cli->pair = NULL;
	cli->accept = NULL;
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

	/* THE NODE'S, sec 421. */
	if (option(arg, "--socket", &value)) {
		*claimed = 1;
		if (!*value)
			return FZN_CLI_ERR_VALUE;
		if (cli->socket)
			return FZN_CLI_ERR_DUPLICATE;
		cli->socket = value;
		return FZN_CLI_OK;
	}
	if (option(arg, "--udp-port", &value)) {
		*claimed = 1;
		if (!parse_u32(value, &number) || number > 65535u)
			return FZN_CLI_ERR_VALUE;
		if (cli->has_udp_port)
			return FZN_CLI_ERR_DUPLICATE;
		cli->udp_port = (uint16_t)number;
		cli->has_udp_port = 1;
		return FZN_CLI_OK;
	}
	if (strcmp(arg, "--udp6") == 0) {
		*claimed = 1;
		if (cli->udp6)
			return FZN_CLI_ERR_DUPLICATE;
		cli->udp6 = 1;
		return FZN_CLI_OK;
	}
	if (option(arg, "--node", &value)) {
		*claimed = 1;
		if (!parse_hex(value, NULL, FZN_PUBKEY_LEN))
			return FZN_CLI_ERR_VALUE;
		if (cli->has_node)
			return FZN_CLI_ERR_DUPLICATE;
		(void)parse_hex(value, cli->node, FZN_PUBKEY_LEN);
		cli->has_node = 1;
		return FZN_CLI_OK;
	}
	if (strcmp(arg, "--prekey") == 0) {
		*claimed = 1;
		if (cli->prekey)
			return FZN_CLI_ERR_DUPLICATE;
		cli->prekey = 1;
		return FZN_CLI_OK;
	}
	if (option(arg, "--pair", &value)) {
		*claimed = 1;
		/* A PREKEY RECORD'S LENGTH IN HEX, checked here so a truncated
		 * paste is refused as the option it is rather than later as a
		 * record that does not open. */
		if (!parse_hex(value, NULL, FZN_PREKEY_LEN_TOTAL))
			return FZN_CLI_ERR_VALUE;
		if (cli->pair)
			return FZN_CLI_ERR_DUPLICATE;
		cli->pair = value;
		return FZN_CLI_OK;
	}
	if (option(arg, "--accept", &value)) {
		*claimed = 1;
		if (!*value)
			return FZN_CLI_ERR_VALUE;
		if (cli->accept)
			return FZN_CLI_ERR_DUPLICATE;
		cli->accept = value;
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
	       "node options:\n"
	       "  --socket=PATH            this node's own local socket\n"
	       "  --udp-port=PORT          serve the remote hop on PORT, 0 to 65535\n"
	       "  --udp6                   the remote hop over IPv6\n"
	       "  --node=KEY               a node's key, 64 hex digits\n"
	       "  --prekey                 print this node's prekey record\n"
	       "  --pair=PREKEY            pair the device whose prekey record this is\n"
	       "  --accept=CARD            accept a pairing card\n"
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
