/* client_config_test -- a client's own file, sec 908. */

#define _POSIX_C_SOURCE 200809L

#include "../client_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int checks, failures;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL client_config_test.c:%d: %s\n", __LINE__, what); \
		}                                                                              \
	} while (0)

int main(void)
{
	char path[] = "/tmp/fzn-client-XXXXXX";
	int fd = mkstemp(path);
	fzn_client_config_t c;
	fzn_preset_ops_t ops;
	FILE *f;

	if (fd < 0)
		return 1;
	close(fd);
	unlink(path);
	CHECK(fzn_client_config_load(&c, path) && c.n == 0u, "no file is an empty configuration");
	CHECK(fzn_client_config_set(&c, "connect/to", "unix /run/x/sock"), "a value is set");
	CHECK(fzn_client_config_set(&c, "connect/to", "127.0.0.1 7000"), "and set again");
	CHECK(!fzn_client_config_set(&c, "two words", "x") && !fzn_client_config_set(&c, "k", "a\nb")
	              && !fzn_client_config_set(&c, "", "x") && !fzn_client_config_set(&c, "#k", "x"),
	      "what would not read back is refused");
	fzn_client_config_free(&c);
	CHECK(fzn_client_config_load(&c, path) && c.n == 1u
	              && !strcmp(fzn_client_config_get(&c, "connect/to"), "127.0.0.1 7000"),
	      "read back, spaces and all");

	/* ---- a preset, and a user's value kept */
	fzn_client_config_ops(&c, &ops);
	CHECK(fzn_preset_apply(fzn_preset_find("ui-client", 9u), NULL, 0u, &ops) == 2,
	      "a client's preset is written to its file");
	CHECK(fzn_client_config_set(&c, "log/level", "D"), "its user changes one");
	CHECK(fzn_preset_apply(fzn_preset_find("ui-client", 9u), NULL, 0u, &ops) == 0
	              && !strcmp(fzn_client_config_get(&c, "log/level"), "D"),
	      "and an update keeps it");
	fzn_client_config_free(&c);

	/* ---- what a person wrote */
	f = fopen(path, "w");
	if (f) {
		fputs("# a comment\n\nnoword\nkey value here\r\n", f);
		fclose(f);
	}
	CHECK(fzn_client_config_load(&c, path) && c.n == 1u
	              && !strcmp(fzn_client_config_get(&c, "key"), "value here"),
	      "comments and shapeless lines are passed over");
	CHECK(!fzn_client_config_get(&c, "noword"), "a word with no value is no key");
	fzn_client_config_free(&c);
	unlink(path);
	printf("client_config_test: %d checks, %d failure(s)\n", checks, failures);
	return failures ? 1 : 0;
}
