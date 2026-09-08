#include "peer_print.h"

#include <string.h>

#define DIGITS_MAX 21u

struct sink {
	char *out;
	size_t used;
};

static void put(struct sink *s, const char *bytes, size_t len)
{
	if (s->out)
		memcpy(s->out + s->used, bytes, len);
	s->used += len;
}

static void put_str(struct sink *s, const char *text)
{
	put(s, text, strlen(text));
}

static void put_u64(struct sink *s, uint64_t value)
{
	char digits[DIGITS_MAX];
	size_t at = sizeof(digits);

	do {
		digits[--at] = (char)('0' + (value % 10u));
		value /= 10u;
	} while (value);

	put(s, digits + at, sizeof(digits) - at);
}

static void put_i64(struct sink *s, int64_t value)
{
	if (value < 0) {
		put_str(s, "-");
		/* Negated in the unsigned domain, so the most negative value
		 * does not overflow on the way. */
		put_u64(s, ~(uint64_t)value + 1u);
		return;
	}

	put_u64(s, (uint64_t)value);
}

/*
 * A VERB IS BYTES A STRANGER CHOSE. See the header: unescaped, a newline in a
 * verb forges a log entry beneath this peer's own denial. Printable ASCII goes
 * through; everything else, and the two characters that would let an escape be
 * faked, become \xNN.
 */
static void put_verb(struct sink *s, const uint8_t *verb, size_t verb_len)
{
	static const char HEX[] = "0123456789abcdef";
	size_t i;

	if (!verb) {
		/* NOT AN EMPTY STRING. A caller that passed no verb and one
		 * that passed "" are different mistakes, and `""` on a line
		 * would read as the second. */
		put_str(s, "(none)");
		return;
	}

	put_str(s, "\"");
	for (i = 0u; i < verb_len; i++) {
		uint8_t c = verb[i];
		char esc[4];

		if (c >= 0x20u && c < 0x7fu && c != '"' && c != '\\') {
			put(s, (const char *)&c, 1u);
			continue;
		}

		esc[0] = '\\';
		esc[1] = 'x';
		esc[2] = HEX[(c >> 4) & 0x0fu];
		esc[3] = HEX[c & 0x0fu];
		put(s, esc, sizeof(esc));
	}
	put_str(s, "\"");
}

static void render(struct sink *s, const fzn_peer_t *peer, const uint8_t *verb,
                   size_t verb_len, fzn_peer_verdict_t verdict, int named)
{
	if (!peer) {
		put_str(s, "no peer -- nothing is known about who is asking");
		return;
	}

	put_str(s, "pid ");
	put_i64(s, peer->pid);
	put_str(s, " uid ");
	put_u64(s, peer->uid);
	put_str(s, " gid ");
	put_u64(s, peer->primary_gid);

	/* UNREADABLE IS NOT EMPTY, which is peer.h's whole subject. A count of
	 * zero beside a peer whose list could not be read would be the wrong
	 * definite answer that module exists to prevent -- and `group_count` is
	 * documented as meaningless when the list is unknown, so it is not read
	 * here at all. */
	if (!peer->groups_known) {
		put_str(s, " (supplementary groups unreadable)");
	} else {
		put_str(s, " (");
		put_u64(s, peer->group_count);
		put_str(s, peer->group_count == 1u ? " group)" : " groups)");
	}

	put_str(s, " asked ");
	put_verb(s, verb, verb_len);
	put_str(s, ": ");

	switch (verdict) {
	case FZN_PEER_MEMBER:
		put_str(s, "admitted");
		return;
	case FZN_PEER_UNKNOWN:
		/* WHY IT CANNOT TELL DEPENDS ON WHETHER THE TABLE COVERS THE
		 * VERB. With no rule naming it there is nothing to be unsure
		 * about and the verdict would be a definite no -- so an UNKNOWN
		 * here is always about the peer, except when there was no peer
		 * at all, which returned above. */
		put_str(s, named ? "cannot tell -- a rule names this verb and this peer's "
		                   "supplementary groups could not be read"
		                 : "cannot tell");
		return;
	case FZN_PEER_NOT_MEMBER:
		break;
	}

	/* THE PAIR THIS PRINTER EXISTS FOR. */
	put_str(s, named ? "denied -- the policy reserves this verb to a group this peer "
	                   "does not hold"
	                 : "denied -- no rule names this verb, so the policy does not "
	                   "cover it");
}

int fzn_peer_print(const fzn_peer_t *peer, const uint8_t *verb, size_t verb_len,
                   const fzn_verb_rule_t *rules, size_t rule_count, char *out, size_t cap,
                   size_t *len_out, fzn_peer_verdict_t *verdict_out, int *named_out)
{
	struct sink measure = { NULL, 0u };
	struct sink write;
	fzn_peer_verdict_t verdict;
	int named;

	/* Deny and claim nothing, so a refusal below cannot be read as an
	 * admission or as knowledge of the table. */
	if (verdict_out)
		*verdict_out = FZN_PEER_UNKNOWN;
	if (named_out)
		*named_out = 0;
	if (len_out)
		*len_out = 0u;

	if (!out || !len_out || !verdict_out || !named_out)
		return -1;

	/* BOTH ANSWERS COME FROM `local/`, and neither is re-derived here. */
	verdict = fzn_vocabulary_admit(peer, verb, verb_len, rules, rule_count);
	named = fzn_vocabulary_names(verb, verb_len, rules, rule_count);

	render(&measure, peer, verb, verb_len, verdict, named);
	if (measure.used + 1u > cap) {
		*len_out = measure.used + 1u;
		return -1;
	}

	write.out = out;
	write.used = 0u;
	render(&write, peer, verb, verb_len, verdict, named);
	out[write.used] = '\0';

	*len_out = write.used;
	*verdict_out = verdict;
	*named_out = named;
	return 0;
}
