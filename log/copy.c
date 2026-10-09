/* See copy.h. */

#define _POSIX_C_SOURCE 200809L

#include "copy.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define PATH_MAX_ 512u

static const char HEX[] = "0123456789abcdef";

static int program_ok(const char *p, size_t n)
{
	size_t i;

	if (n == 0u || n > FZN_ENTRY_WORD_MAX)
		return 0;
	for (i = 0; i < n; i++)
		if (p[i] == '/' || p[i] == '.' || (unsigned char)p[i] < 0x21u
		    || (unsigned char)p[i] > 0x7eu)
			return 0;
	return 1;
}

/* `PROGRAM.TIME.PID.log.zst`, `program` given or any: its closing time, or
 * 0. The only names this module reads, serves or writes. */
static uint64_t packed_key(const char *name, const char *program)
{
	const char *dot = strchr(name, '.'), *t, *end;
	size_t n = strlen(name), i;
	uint64_t v = 0;

	if (!dot || n < 9u || strcmp(name + n - 8u, ".log.zst") != 0 || strchr(name, '/'))
		return 0;
	if (!program_ok(name, (size_t)(dot - name))
	    || (program && (strlen(program) != (size_t)(dot - name)
	                    || memcmp(name, program, (size_t)(dot - name)) != 0)))
		return 0;
	t = dot + 1;
	end = strchr(t, '.');
	if (!end || end == t)
		return 0;
	for (; t < end; t++) {
		if (*t < '0' || *t > '9' || v > (UINT64_MAX - 9u) / 10u)
			return 0;
		v = (v * 10u) + (uint64_t)(*t - '0');
	}
	t = end + 1;
	end = strchr(t, '.');
	if (!end || end == t || end != name + n - 8u)
		return 0;
	for (i = 0; t + i < end; i++)
		if (t[i] < '0' || t[i] > '9')
			return 0;
	return v;
}

static int make_dir(const char *path);

uint64_t fzn_log_copy_packed_time(const char *name)
{
	return name ? packed_key(name, NULL) : 0u;
}

int fzn_log_copy_dir(const char *dir, const uint8_t host[FZN_LOG_PACK_HASH_LEN], char *out,
                     size_t cap)
{
	char hex[(FZN_LOG_PACK_HASH_LEN * 2u) + 1u];
	size_t i;
	int k;

	if (!dir || !host || !out)
		return 0;
	for (i = 0; i < FZN_LOG_PACK_HASH_LEN; i++) {
		hex[2u * i] = HEX[host[i] >> 4];
		hex[(2u * i) + 1u] = HEX[host[i] & 15u];
	}
	hex[sizeof(hex) - 1u] = '\0';
	k = snprintf(out, cap, "%s/copy/%s", dir, hex);
	return k > 0 && (size_t)k < cap;
}

int fzn_log_copy_make_dir(const char *path)
{
	return path && make_dir(path);
}

static int make_dir(const char *path)
{
	char at[PATH_MAX_];
	size_t i, n = strlen(path);

	if (n == 0u || n >= sizeof(at))
		return 0;
	memcpy(at, path, n + 1u);
	/* EACH LEVEL, owner-only: a copy is somebody else's log. */
	for (i = 1; i <= n; i++)
		if (at[i] == '/' || at[i] == '\0') {
			char c = at[i];

			at[i] = '\0';
			if (mkdir(at, 0700) != 0 && errno != EEXIST)
				return 0;
			at[i] = c;
		}
	return 1;
}
