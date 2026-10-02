/* logger_test -- a process's logger: who it is, what goes to the ring and
 * what to the file, the file's header, rotation by size, and two instances
 * of one program sharing a file. sec 458.
 *
 * In a scratch directory of its own, made by mkdtemp; every file it makes
 * is removed by name and the directory must then be empty. */

#define _POSIX_C_SOURCE 200809L

#include "../logger.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int checks, failures;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL logger_test.c:%d: %s\n", __LINE__, what);      \
		}                                                                              \
	} while (0)

static char top[64], dir[160], id_path[200];
static fzn_ring_t ring;
static uint64_t clock_us = 1790944496000000u;

static uint64_t fake_now(void)
{
	return clock_us++;
}

static int rotations;

static void count_rotation(void *ctx)
{
	(*(int *)ctx)++;
}

static size_t read_file(const char *path, char *out, size_t cap)
{
	FILE *f = fopen(path, "r");
	size_t n;

	if (!f)
		return 0;
	n = fread(out, 1u, cap - 1u, f);
	(void)fclose(f);
	out[n] = '\0';
	return n;
}

static int write_file(const char *path, const char *text)
{
	FILE *f = fopen(path, "w");

	return f && fputs(text, f) >= 0 && fclose(f) == 0;
}

/* The files in `dir` whose names begin `prefix`, counted, and every line
 * of them that is an entry parsed back: the positions seen, in file order. */
static size_t lines_in(const char *path, const uint8_t *machine, uint64_t *positions, size_t cap,
                       size_t *n_out, int *header_ok)
{
	static char buf[1u << 16];
	static uint8_t text[FZN_ENTRY_TEXT_MAX];
	char *at, *nl;
	size_t n = 0;

	*header_ok = 0;
	if (!read_file(path, buf, sizeof(buf)))
		return 0;
	at = buf;
	*header_ok = strncmp(at, "#fuzznet-log 1 machine=0123456789abcdeffedcba9876543210 host=",
	                     61u)
	             == 0;
	while ((nl = strchr(at, '\n')) != NULL) {
		fzn_entry_t e;
		char host[FZN_ENTRY_WORD_MAX + 1u];

		if (at[0] != '#') {
			if (fzn_entry_classic_parse(at, (size_t)(nl - at) + 1u, machine, &e, host, text,
			                            sizeof(text))
			    != FZN_ENTRY_OK)
				return 0;
			if (n < cap)
				positions[n] = e.name.position;
			n++;
		}
		at = nl + 1;
	}
	*n_out = n;
	return 1;
}

/* The program's files in `dir`: the current one and every closed segment. */
static size_t segments(const char *program, char names[][128], size_t cap)
{
	DIR *d = opendir(dir);
	struct dirent *e;
	size_t n = 0, plen = strlen(program);

	if (!d)
		return 0;
	while ((e = readdir(d)) != NULL)
		if (strncmp(e->d_name, program, plen) == 0 && e->d_name[plen] == '.' && n < cap)
			(void)snprintf(names[n++], 128u, "%.127s", e->d_name);
	(void)closedir(d);
	return n;
}

int main(void)
{
	static fzn_logger_t a, b;
	fzn_entry_name_t self, first, other;
	char host[FZN_ENTRY_WORD_MAX + 1u], path[300], body[4096], names[64][128];
	uint64_t pos[64];
	size_t n = 0, i, nseg, total;
	int header_ok = 0, all_headers = 1;

	(void)snprintf(top, sizeof(top), "/tmp/fzn-logger-test-XXXXXX");
	if (!mkdtemp(top)) {
		fprintf(stderr, "  FAIL logger_test.c: no scratch directory\n");
		return 1;
	}
	(void)snprintf(dir, sizeof(dir), "%s/state/fuzznet/log", top);
	(void)snprintf(id_path, sizeof(id_path), "%s/machine-id", top);

	/* ---- who it is */
	CHECK(fzn_logger_identify(&self, host, "fuzznetd", id_path) == FZN_LOGGER_ERR_IDENTITY,
	      "no machine-id is refused");
	CHECK(write_file(id_path, "not a machine id\n")
	              && fzn_logger_identify(&self, host, "fuzznetd", id_path)
	                         == FZN_LOGGER_ERR_IDENTITY,
	      "a machine-id that is not one is refused");
	CHECK(write_file(id_path, "0123456789abcdeffedcba9876543210\n")
	              && fzn_logger_identify(&self, host, "fuzznetd", id_path) == FZN_LOGGER_OK
	              && self.machine[0] == 0x01u && self.machine[15] == 0x10u
	              && strcmp(self.program, "fuzznetd") == 0 && self.pid == (uint32_t)getpid()
	              && self.start_ms > 1600000000000u && host[0] && self.user[0]
	              && self.position == 0u,
	      "the machine, the program, the pid, a start in milliseconds, a host and an account");
	CHECK(fzn_logger_identify(&self, host, "a/b", id_path) == FZN_LOGGER_ERR_MALFORMED,
	      "a program with a slash is refused");

	/* ---- where its files go */
	if (geteuid() != 0) {
		char d[FZN_LOGGER_PATH_MAX];

		CHECK(setenv("XDG_STATE_HOME", "/x/state", 1) == 0
		              && fzn_logger_default_dir(d, sizeof(d)) == FZN_LOGGER_OK
		              && strcmp(d, "/x/state/fuzznet/log") == 0,
		      "a user's files go under XDG_STATE_HOME");
		CHECK(setenv("XDG_STATE_HOME", "relative", 1) == 0 && setenv("HOME", "/h", 1) == 0
		              && fzn_logger_default_dir(d, sizeof(d)) == FZN_LOGGER_OK
		              && strcmp(d, "/h/.local/state/fuzznet/log") == 0,
		      "a relative XDG_STATE_HOME is ignored, and HOME's .local/state used");
	}

	/* ---- what goes where */
	fzn_ring_init(&ring);
	CHECK(fzn_logger_open(&a, &self, host, dir, FZN_ENTRY_INFO, &ring, 0u) == FZN_LOGGER_OK,
	      "a logger opens, making its directories");
	a.now_us = fake_now;
	CHECK(fzn_logger_log(&a, FZN_ENTRY_WARNING, "notes/sync", NULL, NULL,
	                     (const uint8_t *)"kept", 4u, &first)
	                      == FZN_LOGGER_OK
	              && first.position == 0u,
	      "a warning is logged as the first entry");
	CHECK(fzn_logger_log(&a, FZN_ENTRY_DEBUG, "notes/sync", NULL, NULL,
	                     (const uint8_t *)"ring only", 9u, NULL)
	              == FZN_LOGGER_OK,
	      "a debug entry is logged");
	CHECK(fzn_logger_log(&a, FZN_ENTRY_INFO, "notes/sync", &first, &first,
	                     (const uint8_t *)"because", 7u, NULL)
	              == FZN_LOGGER_OK,
	      "an entry caused by the first is logged");
	(void)snprintf(path, sizeof(path), "%s/fuzznetd.log", dir);
	CHECK(lines_in(path, self.machine, pos, 64u, &n, &header_ok) && header_ok && n == 2u
	              && pos[0] == 0u && pos[1] == 2u,
	      "the file opens with its header and holds the kept entries, not the debug one");
	CHECK(ring.held == 3u, "the ring holds all three, the debug one included");
	CHECK(read_file(path, body, sizeof(body))
	              && strstr(body, " <0123456789abcdeffedcba9876543210/") != NULL
	              && strstr(body, "#0 <<") != NULL,
	      "the caused entry names its cause, which ends in the first entry's instance field");
	CHECK(fzn_logger_log(&a, FZN_ENTRY_INFO, "bad//path", NULL, NULL, NULL, 0u, NULL)
	                      == FZN_LOGGER_ERR_MALFORMED
	              && fzn_logger_log(&a, FZN_ENTRY_INFO, "x", &first, NULL, NULL, 0u, NULL)
	                         == FZN_LOGGER_ERR_MALFORMED
	              && a.self.position == 3u && ring.held == 3u,
	      "a bad subsystem, or a cause without an origin, is refused and takes no position");

	/* ---- two instances sharing a file, and rotation by size */
	other = self;
	other.pid = self.pid + 1u;
	CHECK(fzn_logger_open(&b, &other, host, dir, FZN_ENTRY_INFO, NULL, 600u) == FZN_LOGGER_OK,
	      "a second instance opens the same program's file");
	b.now_us = fake_now;
	a.segment_max = 600u;
	a.rotated = count_rotation;
	a.rotated_ctx = &rotations;
	b.rotated = count_rotation;
	b.rotated_ctx = &rotations;
	for (i = 0; i < 12u; i++)
		CHECK(fzn_logger_log(i % 2u ? &b : &a, FZN_ENTRY_INFO, "apply/exec", NULL, NULL,
		                     (const uint8_t *)"a line of some length, to fill a segment", 40u,
		                     NULL)
		              == FZN_LOGGER_OK,
		      "each instance logs in turn");
	nseg = segments("fuzznetd", names, 64u);
	total = 0;
	for (i = 0; i < nseg; i++) {
		size_t k = 0;

		(void)snprintf(path, sizeof(path), "%s/%s", dir, names[i]);
		if (!lines_in(path, self.machine, pos, 64u, &k, &header_ok) || !header_ok)
			all_headers = 0;
		total += k;
	}
	CHECK(nseg >= 3u, "past the segment size, the file was rotated, more than once");
	CHECK(rotations == (int)nseg - 1,
	      "and the rotated hook was called once for each rotation, so a packer can follow");
	CHECK(all_headers && total == 14u,
	      "every segment opens with its header, and the 14 kept lines are all there, whole");
	/* THE OTHER INSTANCE FOLLOWS a rotation it did not make: the file is
	 * moved away under it here, as another instance's rotation would. */
	{
		char moved[300];

		/* NO ROTATION HERE, so nothing but the file's identity can send
		 * b's line to the right file: a rotation of its own would mask a
		 * stale handle. */
		a.segment_max = FZN_LOGGER_SEGMENT_DEFAULT;
		b.segment_max = FZN_LOGGER_SEGMENT_DEFAULT;
		(void)snprintf(path, sizeof(path), "%s/fuzznetd.log", dir);
		(void)snprintf(moved, sizeof(moved), "%s/fuzznetd.moved.log", dir);
		CHECK(fzn_logger_log(&b, FZN_ENTRY_INFO, "apply/exec", NULL, NULL,
		                     (const uint8_t *)"before", 6u, NULL)
		                      == FZN_LOGGER_OK
		              && rename(path, moved) == 0,
		      "fixture: b writes, and its file is rotated away by somebody else");
		/* ANOTHER INSTANCE MAKES THE NEW FILE FIRST, so the path names
		 * a file again and only its identity says it is not b's. */
		CHECK(fzn_logger_log(&a, FZN_ENTRY_INFO, "apply/exec", NULL, NULL,
		                     (const uint8_t *)"a first", 7u, NULL)
		              == FZN_LOGGER_OK,
		      "fixture: the other instance writes first, making the new file");
		CHECK(fzn_logger_log(&b, FZN_ENTRY_ERROR, "apply/exec", NULL, NULL,
		                     (const uint8_t *)"after", 5u, NULL)
		                      == FZN_LOGGER_OK
		              && read_file(path, body, sizeof(body))
		              && strncmp(body, "#fuzznet-log 1 ", 15u) == 0
		              && strstr(body, " E apply/exec - - after\n") != NULL
		              && read_file(moved, body, sizeof(body))
		              && strstr(body, " - - after\n") == NULL,
		      "the next line goes to a new current file with its header, not to the moved one");
	}

	fzn_logger_close(&a);
	fzn_logger_close(&b);

	/* REMOVED BY NAME, AND WHAT IS LEFT IS AN ASSERTION. */
	nseg = segments("fuzznetd", names, 64u);
	for (i = 0; i < nseg; i++) {
		(void)snprintf(path, sizeof(path), "%s/%s", dir, names[i]);
		(void)remove(path);
	}
	(void)remove(id_path);
	(void)snprintf(path, sizeof(path), "%s/state/fuzznet", top);
	CHECK(rmdir(dir) == 0 && rmdir(path) == 0
	              && (snprintf(path, sizeof(path), "%s/state", top), rmdir(path) == 0)
	              && rmdir(top) == 0,
	      "the scratch directories empty, and go");

	if (failures) {
		fprintf(stderr, "logger_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("logger_test: all %d checks passed\n", checks);
	return 0;
}
