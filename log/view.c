/* See view.h. */

#include "view.h"

#include "capture.h"

#include <stdio.h>
#include <string.h>

/* `pid@start`, the instance without the position. */
static void instance(const fzn_entry_name_t *n, char *out, size_t cap)
{
	(void)snprintf(out, cap, "%lu@%llu", (unsigned long)n->pid, (unsigned long long)n->start_ms);
}

/* Append `fmt` to `out` at `*at`; 0 when it does not fit. */
static int put(char *out, size_t cap, size_t *at, const char *s)
{
	size_t n = strlen(s);

	if (cap - *at <= n)
		return 0;
	memcpy(out + *at, s, n);
	*at += n;
	out[*at] = '\0';
	return 1;
}

fzn_entry_err_t fzn_entry_view(const fzn_entry_t *prev, const char *prev_host,
                               const fzn_entry_t *cur, const char *cur_host, char *out, size_t cap,
                               size_t *len)
{
	/* The worst text, every byte an escape. */
	static char text[(FZN_ENTRY_TEXT_MAX * 4u) + 1u];
	char now[FZN_ENTRY_TIME_TEXT], before[FZN_ENTRY_TIME_TEXT], buf[128];
	char ci[64], pi[64];
	const char *tree_cur[5], *tree_prev[5];
	size_t at = 0, from = 0, k;
	char letter;
	int ok = 1;

	if (!cur || !cur_host || !out || !len || cap == 0u || (prev && !prev_host)
	    || fzn_entry_time_text(cur->time_us, now) != FZN_ENTRY_OK
	    || !(letter = fzn_entry_level_letter(cur->level)) || (!cur->text && cur->text_len)
	    || cur->text_len > FZN_ENTRY_TEXT_MAX)
		return FZN_ENTRY_ERR_MALFORMED;
	out[0] = '\0';
	/* THE DATE, a line of its own when it changes. */
	if (!prev || fzn_entry_time_text(prev->time_us, before) != FZN_ENTRY_OK
	    || memcmp(now, before, 10u) != 0) {
		(void)snprintf(buf, sizeof(buf), "-- %.10s --\n", now);
		ok = put(out, cap, &at, buf);
		prev = NULL;
	}
	/* THE TIME OF DAY. */
	(void)snprintf(buf, sizeof(buf), "%.15s", now + 11);
	ok = ok && put(out, cap, &at, buf);
	/* THE TREE, from the first field that differs. */
	instance(&cur->name, ci, sizeof(ci));
	tree_cur[0] = cur_host;
	tree_cur[1] = cur->name.user;
	tree_cur[2] = cur->name.program;
	tree_cur[3] = ci;
	tree_cur[4] = cur->subsystem;
	if (prev) {
		instance(&prev->name, pi, sizeof(pi));
		tree_prev[0] = prev_host;
		tree_prev[1] = prev->name.user;
		tree_prev[2] = prev->name.program;
		tree_prev[3] = pi;
		tree_prev[4] = prev->subsystem;
		while (from < 5u && strcmp(tree_cur[from], tree_prev[from]) == 0)
			from++;
	}
	for (k = from; k < 4u && ok; k++)
		ok = put(out, cap, &at, " ") && put(out, cap, &at, tree_cur[k]);
	(void)snprintf(buf, sizeof(buf), " #%llu %c", (unsigned long long)cur->name.position, letter);
	ok = ok && put(out, cap, &at, buf);
	if (from < 5u && ok)
		ok = put(out, cap, &at, " ") && put(out, cap, &at, tree_cur[4]);
	/* CAUSES, as what a grep would follow. */
	if (cur->caused && ok) {
		(void)snprintf(buf, sizeof(buf), " <%lu@%llu#%llu", (unsigned long)cur->cause.pid,
		               (unsigned long long)cur->cause.start_ms,
		               (unsigned long long)cur->cause.position);
		ok = put(out, cap, &at, buf);
		if (ok && (cur->origin.pid != cur->cause.pid
		           || cur->origin.start_ms != cur->cause.start_ms
		           || cur->origin.position != cur->cause.position)) {
			(void)snprintf(buf, sizeof(buf), " <<%lu@%llu#%llu",
			               (unsigned long)cur->origin.pid,
			               (unsigned long long)cur->origin.start_ms,
			               (unsigned long long)cur->origin.position);
			ok = put(out, cap, &at, buf);
		}
	}
	(void)fzn_capture_escape(cur->text, cur->text_len, text, sizeof(text));
	ok = ok && put(out, cap, &at, " ") && put(out, cap, &at, text) && put(out, cap, &at, "\n");
	if (!ok) {
		out[0] = '\0';
		return FZN_ENTRY_ERR_ROOM;
	}
	*len = at;
	return FZN_ENTRY_OK;
}
