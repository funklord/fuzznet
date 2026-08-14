/* See peer.h. */

#include "peer.h"

#include <string.h>

/* The line we want, and the two that are not it.
 *
 * `/proc/<pid>/status` has `Groups:` and, on some kernels, nothing else
 * beginning with those bytes -- but matching a prefix against a line that
 * merely starts the same way is the sort of thing that works until a field
 * is added. So the match is anchored at a line start and requires the
 * colon, and `Ngid:` and `Gid:` cannot satisfy it. */
static const char GROUPS_KEY[] = "Groups:";

static int is_line_start(const char *text, size_t i)
{
	return i == 0 || text[i - 1] == '\n';
}

int fzn_peer_groups_parse(const char *text, size_t len, fzn_peer_t *peer)
{
	const size_t keylen = sizeof(GROUPS_KEY) - 1;
	size_t i, end;
	size_t count = 0;

	if (!peer)
		return 0;

	/* Cleared first, so every failure below leaves the same state and no
	 * path can return with a stale list still readable. */
	peer->group_count = 0;
	peer->groups_known = 0;
	memset(peer->groups, 0, sizeof(peer->groups));

	if (!text || len == 0)
		return 0;

	for (i = 0; i + keylen <= len; i++) {
		if (is_line_start(text, i) && memcmp(text + i, GROUPS_KEY, keylen) == 0)
			break;
	}
	if (i + keylen > len)
		return 0; /* no Groups: line -- could not tell, not "none" */

	i += keylen;
	for (end = i; end < len && text[end] != '\n'; end++)
		;

	while (i < end) {
		uint64_t value = 0;
		int digits = 0;

		while (i < end && (text[i] == ' ' || text[i] == '\t'))
			i++;
		if (i >= end)
			break;

		while (i < end && text[i] >= '0' && text[i] <= '9') {
			value = value * 10u + (uint64_t)(text[i] - '0');
			/* A gid is 32 bits. A longer run of digits is not a
			 * large gid, it is a line this parser does not
			 * understand, and guessing at it would be the partial
			 * success peer.h refuses. */
			if (value > 0xffffffffu)
				return 0;
			digits++;
			i++;
		}

		if (digits == 0)
			return 0; /* something that is not a number */

		/* Overflow marks the whole list unknown rather than truncating
		 * it. A truncated list answers "not a member" definitely and
		 * wrongly, which is what the tri-state exists to prevent. */
		if (count == FZN_PEER_MAX_GROUPS)
			return 0;

		peer->groups[count++] = (uint32_t)value;
	}

	/* Reached only by a Groups: line every entry of which parsed. An
	 * empty one is a real empty membership and says so. */
	peer->group_count = count;
	peer->groups_known = 1;

	return 1;
}

fzn_peer_verdict_t fzn_peer_in_group(const fzn_peer_t *peer, uint32_t gid)
{
	if (!peer)
		return FZN_PEER_UNKNOWN;

	/* The primary gid is checked first and is always knowable, so a group
	 * that IS somebody's primary one is answered definitely even when the
	 * supplementary list could not be read. Refusing that would be the
	 * mirror of the bug this module exists for. */
	if (peer->primary_gid == gid)
		return FZN_PEER_MEMBER;

	if (!peer->groups_known)
		return FZN_PEER_UNKNOWN;

	for (size_t i = 0; i < peer->group_count; i++) {
		if (peer->groups[i] == gid)
			return FZN_PEER_MEMBER;
	}

	return FZN_PEER_NOT_MEMBER;
}
