/* node state_dir_test -- a state directory copied out and wiped, sec 620,
 * over real files in a scratch directory this test makes and removes by
 * name, failing when anything is left. */
#define _POSIX_C_SOURCE 200809L

#include "../state_dir.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int checks, failures;

#define CHECK(cond, what)                                                                     \
	do {                                                                                  \
		checks++;                                                                     \
		if (!(cond)) {                                                                \
			failures++;                                                           \
			fprintf(stderr, "  FAIL state_dir_test.c:%d: %s\n", __LINE__, what);   \
		}                                                                             \
	} while (0)

static char base[256];

static const char *at(const char *rel)
{
	static char p[8][512];
	static unsigned k;

	k = (k + 1u) % 8u;
	(void)snprintf(p[k], sizeof(p[k]), "%s/%s", base, rel);
	return p[k];
}

static void put(const char *rel, const char *text)
{
	FILE *f = fopen(at(rel), "w");

	if (f) {
		fputs(text, f);
		fclose(f);
	}
}

static int holds(const char *rel, const char *text)
{
	char buf[64];
	FILE *f = fopen(at(rel), "r");
	size_t n;

	if (!f)
		return 0;
	n = fread(buf, 1, sizeof(buf) - 1u, f);
	fclose(f);
	buf[n] = '\0';
	return strcmp(buf, text) == 0;
}

static void test_a_backup_and_a_wipe(void)
{
	const char *why = NULL;
	size_t files = 9;

	(void)mkdir(at("src"), 0700);
	(void)mkdir(at("src/sub"), 0700);
	put("src/a", "aaa");
	put("src/sub/b", "bbb");
	(void)mkdir(at("dst"), 0755);

	CHECK(!fzn_state_dir_backup_ok(at("none"), &why), "a missing directory took a backup");
	CHECK(!fzn_state_dir_backup_ok(at("dst"), &why), "a directory of mode 0755 took a backup");
	(void)chmod(at("dst"), 0700);
	CHECK(fzn_state_dir_backup_ok(at("dst"), &why), "an empty 0700 directory took no backup");
	(void)symlink(at("dst"), at("dstlink"));
	CHECK(!fzn_state_dir_backup_ok(at("dstlink"), &why), "a link to a directory took a backup");

	CHECK(fzn_state_dir_copy(at("src"), at("dst"), &files, &why) && files == 2u
	              && holds("dst/a", "aaa") && holds("dst/sub/b", "bbb"),
	      "the state did not copy whole");
	CHECK(!fzn_state_dir_backup_ok(at("dst"), &why), "a directory holding a backup took another");
	CHECK(!fzn_state_dir_copy(at("src"), at("dst"), &files, &why),
	      "a copy overwrote what was already there");

	/* A FILE ALREADY THERE, and no directory in the way: the copy refuses
	 * to overwrite it, rather than failing for another reason first. */
	(void)mkdir(at("dst3"), 0700);
	put("dst3/a", "old");
	CHECK(!fzn_state_dir_copy(at("src"), at("dst3"), &files, &why) && holds("dst3/a", "old"),
	      "a copy overwrote a file already in its directory");

	/* A LINK IN THE STATE: the copy refuses it, and a wipe leaves it and
	 * what it points at. */
	put("outside", "keep");
	(void)symlink(at("outside"), at("src/link"));
	(void)mkdir(at("dst2"), 0700);
	CHECK(!fzn_state_dir_copy(at("src"), at("dst2"), &files, &why),
	      "a state holding a link copied as though whole");

	/* THE ROOT IS ASKED OF THE CHECK ALONE, which deletes nothing: asked of
	 * the wipe, a broken guard would take this user's every file with it. */
	CHECK(!fzn_state_dir_wipe_ok("/", &why) && !fzn_state_dir_wipe_ok("", &why)
	              && !fzn_state_dir_wipe(at("dstlink"), &files, &why)
	              && fzn_state_dir_wipe_ok(at("dst"), &why),
	      "the root, nothing, or a link to a directory was taken for a state directory");
	CHECK(fzn_state_dir_wipe(at("src"), &files, &why) && files == 2u
	              && access(at("src/a"), F_OK) != 0 && access(at("src/sub/b"), F_OK) != 0,
	      "the wipe did not remove every regular file");
	CHECK(holds("outside", "keep"), "the wipe followed a link and emptied what it named");
	{
		struct stat st;

		CHECK(lstat(at("src/link"), &st) == 0 && S_ISLNK(st.st_mode)
		              && lstat(at("src/sub"), &st) == 0 && S_ISDIR(st.st_mode),
		      "the wipe removed a link or a directory");
	}
}

/* EVERYTHING THIS TEST MADE, removed by name; the count left is a check. */
static void clean_up(void)
{
	static const char *const files[] = { "src/link", "outside", "dst/a", "dst/sub/b",
		                             "dstlink", "dst2/a", "dst2/sub/b", "src/a",
		                             "src/sub/b", "dst3/a", "dst3/sub/b" };
	static const char *const dirs[] = { "src/sub", "src", "dst/sub", "dst", "dst2/sub",
		                            "dst2", "dst3/sub", "dst3" };
	size_t i;

	for (i = 0; i < sizeof(files) / sizeof(files[0]); i++)
		(void)unlink(at(files[i]));
	for (i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++)
		(void)rmdir(at(dirs[i]));
	CHECK(rmdir(base) == 0, "the scratch directory was not left empty");
}

static void test_the_suite_can_tell_pass_from_fail(void)
{
	int before = failures;

	CHECK(0, "deliberate");
	CHECK(failures == before + 1, "a failure counts");
	failures = before;
	checks -= 1;
}

int main(void)
{
	const char *tmp = getenv("TMPDIR");

	(void)snprintf(base, sizeof(base), "%s/fzn-state-dir.XXXXXX", tmp && *tmp ? tmp : "/tmp");
	if (!mkdtemp(base)) {
		fprintf(stderr, "node state_dir_test: no scratch directory\n");
		return 1;
	}
	test_the_suite_can_tell_pass_from_fail();
	test_a_backup_and_a_wipe();
	clean_up();
	if (failures) {
		fprintf(stderr, "node state_dir_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("node state_dir_test: all %d checks passed\n", checks);
	return 0;
}
