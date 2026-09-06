/*
 * The command-line vocabulary for fuzznet's own settings.
 *
 * project.md sec 137. Every consumer needs the same five answers -- where the
 * identity lives, where the store lives, which service and product it speaks
 * for, and whether it should try to be the owner -- and four projects
 * inventing four spellings of `--fuzznet-store` is the divergence sec 2
 * exists to prevent, in a cheaper place than the protocol.
 *
 * THE PRIZE IS `fzn_cli_usage`, more than the parsing. Identical help text
 * across every consuming program is what makes the shared vocabulary visible
 * to the person typing it, and it is the half a consumer cannot get by
 * writing its own parser however carefully.
 *
 * THE CONSUMER OWNS argv. This claims the arguments it recognises and says so
 * through `claimed`, leaving everything else to the caller untouched: no
 * reordering, no permutation, no `getopt`, and no allocation -- which is this
 * library's rule rather than this module's. A consumer walks its own argv and
 * offers each argument here first, or last, as it prefers.
 *
 * `--option=value` IS THE ONLY FORM, and that is what makes the
 * one-argument-at-a-time shape possible at all: a separate-argument form
 * would need to see the NEXT argument, and then this could no longer be a
 * function a caller drives one step at a time. The cost is that
 * `--fuzznet-dir /path` is not accepted, which is worth saying in the usage
 * text rather than guessing at.
 *
 * STRINGS ARE POINTERS INTO argv, NOT COPIES. Nothing is allocated, so a
 * caller that frees or overwrites its argv has invalidated these. For a main
 * function that is free; for anything building an argument list of its own it
 * is a thing to know.
 *
 * BOUNDS COME FROM THE MODULES THAT OWN THEM. A product is checked against
 * `chain/service.h`'s constants rather than against numbers written here,
 * because a second set of bounds is a second thing to be wrong -- and would
 * be wrong quietly, since a value this accepted and that module refused would
 * fail much later and somewhere else.
 */
#ifndef FZN_CLI_H
#define FZN_CLI_H

#include "../chain/service.h"

#include <stddef.h>
#include <stdint.h>

typedef enum fzn_cli_err {
	FZN_CLI_OK = 0,
	/* A null argument: the caller's bug. */
	FZN_CLI_ERR_MALFORMED = -1,
	/* The option is one of ours and the value is not usable -- out of
	 * range, empty, or not a number. Distinct from an unrecognised option,
	 * which is not an error here at all: it is the caller's argument and
	 * `claimed` says so. */
	FZN_CLI_ERR_VALUE = -2,
	/* One of ours, given twice. REPORTED RATHER THAN RESOLVED: two values
	 * for one setting means the invocation is ambiguous, and silently
	 * keeping the first or the last is how a configuration bug survives a
	 * person reading the command line and seeing what they meant. */
	FZN_CLI_ERR_DUPLICATE = -3,
} fzn_cli_err_t;

const char *fzn_cli_err_str(fzn_cli_err_t err);

/* Whether this process should try to become the owner -- project.md sec 133's
 * claim. AUTO is the default and means try: a process that gets it is the
 * daemon and one that does not reads the shared store, which is the same
 * program either way. */
typedef enum fzn_cli_owner {
	FZN_CLI_OWNER_AUTO = 0,
	FZN_CLI_OWNER_YES = 1,
	FZN_CLI_OWNER_NO = 2,
} fzn_cli_owner_t;

typedef struct fzn_cli {
	/* NULL when unset, so a consumer can tell "not given" from a value and
	 * apply its own default rather than having one imposed here. This
	 * module does not know where a consumer's identity directory belongs;
	 * sec 129 records that data locations are expected to need later
	 * correction, and a default written here would be one more place to
	 * correct. */
	const char *dir;
	const char *store;
	/* FZN_SERVICE_NONE and FZN_PRODUCT_NONE when unset, which are the same
	 * values `chain/service.h` refuses -- so an unset field passed on
	 * reaches an error rather than a wrong grant. */
	uint32_t service;
	uint32_t product;
	fzn_cli_owner_t owner;
} fzn_cli_t;

/* Set every field to its unset value. */
void fzn_cli_init(fzn_cli_t *cli);

/*
 * Offer one argument.
 *
 * `claimed` receives 1 when the argument was one of fuzznet's and 0 when it
 * was not. An unrecognised argument is NOT an error: it belongs to the
 * caller, which is the whole point of the seam.
 *
 * On FZN_CLI_ERR_VALUE or FZN_CLI_ERR_DUPLICATE the argument WAS ours --
 * `claimed` is 1 -- so a caller reporting the error can name the option
 * rather than saying something unhelpful about an unknown argument.
 *
 * Nothing is written into `cli` unless the whole argument is accepted.
 */
fzn_cli_err_t fzn_cli_arg(fzn_cli_t *cli, const char *arg, int *claimed);

/*
 * The help text for fuzznet's options, as one static string with a trailing
 * newline. Never NULL.
 *
 * A consumer prints this beside its own usage. It is deliberately not
 * assembled from the parser's table at runtime: this library allocates
 * nothing, so a generated string would need a caller's buffer and a length,
 * and every consumer would then print something slightly different depending
 * on how much it gave.
 */
const char *fzn_cli_usage(void);

#endif
