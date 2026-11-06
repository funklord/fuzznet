/* node presets_test -- a profile, sec 908: a fixed value written whenever it is
 * applied, a user's only where the cell is empty, and the consumer's over both.
 */

#include "../presets.h"

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                  \
	do {                                                                               \
		checks++;                                                                  \
		if (!(cond)) {                                                             \
			failures++;                                                        \
			fprintf(stderr, "  FAIL presets_test.c:%d: %s\n", __LINE__, what);  \
		}                                                                          \
	} while (0)

#define CELLS 16

static struct {
	char key[32], value[32];
} cells[CELLS];
static int n_cells, writes, refuse_at;

static int cell_get(void *ctx, const char *key, char *value, size_t cap, size_t *len)
{
	int i;

	(void)ctx;
	(void)cap;
	for (i = 0; i < n_cells; i++)
		if (!strcmp(cells[i].key, key)) {
			*len = strlen(cells[i].value);
			memcpy(value, cells[i].value, *len);
			return 1;
		}
	return 0;
}

static int cell_set(void *ctx, const char *key, const char *value)
{
	int i;

	(void)ctx;
	writes++;
	if (refuse_at && writes == refuse_at)
		return 0;
	for (i = 0; i < n_cells; i++)
		if (!strcmp(cells[i].key, key))
			break;
	if (i == n_cells)
		snprintf(cells[n_cells++].key, sizeof(cells[0].key), "%s", key);
	snprintf(cells[i].value, sizeof(cells[0].value), "%s", value);
	return 1;
}

static const char *cell(const char *key)
{
	static char v[32];
	size_t len = 0;

	if (!cell_get(NULL, key, v, sizeof(v), &len))
		return "";
	v[len] = '\0';
	return v;
}

static const fzn_preset_ops_t OPS = { NULL, cell_get, cell_set };

int main(void)
{
	static const fzn_preset_value_t MINE[] = {
		{ "app/mode", "strict", FZN_PRESET_NOBODY },
		{ "app/colour", "blue", FZN_PRESET_HOST },
		{ "relay/enabled", "off", FZN_PRESET_HOST },
	};
	const fzn_preset_t *vault = fzn_preset_find("vault", 5u);
	size_t i;

	CHECK(vault && fzn_preset_find("userd", 5u) && fzn_preset_find("rootd", 5u)
	              && fzn_preset_find("embedded-device", 15u) && fzn_preset_find("relay", 5u)
	              && fzn_preset_find("ui-client", 9u) && fzn_preset_find("one-shot-client", 15u)
	              && fzn_preset_find("insecure-client", 15u),
	      "the presets are there");
	CHECK(!fzn_preset_find("nobody", 6u) && !fzn_preset_find("vaul", 4u) && !fzn_preset_find(NULL, 0u),
	      "nothing else is");
	for (i = 0; fzn_preset_at(i); i++)
		CHECK(fzn_preset_at(i)->revision && fzn_preset_at(i)->n_values, "a preset says something");

	/* ---- builds, and who may switch */
	CHECK(fzn_preset_fits(vault) && !fzn_preset_fits(fzn_preset_find("embedded-device", 15u))
	              && !fzn_preset_fits(fzn_preset_find("ui-client", 9u)) && !fzn_preset_fits(NULL),
	      "a preset fits only its build");
	CHECK(vault->user && fzn_preset_find("relay", 5u)->user && !fzn_preset_find("rootd", 5u)->user,
	      "some are a user's to switch to");

	/* ---- first applied */
	CHECK(fzn_preset_apply(vault, NULL, 0u, &OPS) == 4, "every value is written to an empty host");
	CHECK(!strcmp(cell("relay/enabled"), "on") && !strcmp(cell("invite/confirm"), "on"),
	      "as the preset says");
	/* ---- who may change what */
	CHECK(!fzn_preset_may(vault, NULL, 0u, "relay/enabled", 13u, FZN_PRESET_HOST)
	              && !fzn_preset_may(vault, NULL, 0u, "relay/enabled", 13u, FZN_PRESET_ADMIN)
	              && fzn_preset_may(vault, NULL, 0u, "relay/enabled", 13u, FZN_PRESET_ROOT),
	      "a voted value is a root's alone to set");
	CHECK(!strcmp(fzn_preset_who_word(FZN_PRESET_VOTE), "vote"), "and said so");
	CHECK(!fzn_preset_may(fzn_preset_find("embedded-device", 15u), NULL, 0u, "relay/enabled", 13u,
	                      FZN_PRESET_ADMIN),
	      "a root's value is a root's");
	CHECK(!fzn_preset_may(vault, NULL, 0u, "invite/confirm", 14u, FZN_PRESET_HOST)
	              && fzn_preset_may(vault, NULL, 0u, "invite/confirm", 14u, FZN_PRESET_ADMIN)
	              && fzn_preset_may(vault, NULL, 0u, "invite/confirm", 14u, FZN_PRESET_ROOT),
	      "an admin's value is an admin's and above");
	CHECK(!fzn_preset_may(vault, NULL, 0u, "location/enabled", 16u, FZN_PRESET_ROOT),
	      "the profile's own is nobody's, a root included");
	CHECK(fzn_preset_may(vault, NULL, 0u, "net/metric", 10u, FZN_PRESET_HOST),
	      "a key it does not name is the user's");
	CHECK(fzn_preset_may(NULL, NULL, 0u, "relay/enabled", 13u, FZN_PRESET_HOST),
	      "no profile binds nothing");
	CHECK(!strcmp(fzn_preset_who_word(FZN_PRESET_ROOT), "root")
	              && !strcmp(fzn_preset_who_word(FZN_PRESET_NOBODY), "nobody"),
	      "said as a word");

	/* ---- again, as an update */
	cell_set(NULL, "invite/confirm", "off");
	cell_set(NULL, "location/enabled", "on");
	writes = 0;
	CHECK(fzn_preset_apply(vault, NULL, 0u, &OPS) == 1 && writes == 1, "only what moved is written");
	CHECK(!strcmp(cell("invite/confirm"), "off"), "a value somebody chose outlives an update");
	CHECK(!strcmp(cell("location/enabled"), "off"), "the profile's own is put back");

	/* ---- the consumer's, over it */
	CHECK(fzn_preset_apply(vault, MINE, 3u, &OPS) >= 2, "the consumer's are written too");
	CHECK(!strcmp(cell("app/mode"), "strict") && !strcmp(cell("app/colour"), "blue"),
	      "its own keys");
	CHECK(!fzn_preset_may(vault, MINE, 3u, "app/mode", 8u, FZN_PRESET_ROOT), "it may fix more");
	CHECK(fzn_preset_may(vault, MINE, 3u, "relay/enabled", 13u, FZN_PRESET_HOST),
	      "and open what the preset holds: the consumer's word stands");

	/* ---- refused */
	n_cells = 0;
	writes = 0;
	refuse_at = 2;
	CHECK(fzn_preset_apply(vault, NULL, 0u, &OPS) == -1, "a write refused is said");
	refuse_at = 0;
	CHECK(fzn_preset_apply(vault, NULL, 0u, NULL) == -1, "no way to write is said");
	CHECK(fzn_preset_apply(NULL, NULL, 0u, &OPS) == 0, "nothing to apply writes nothing");

	printf("presets_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
