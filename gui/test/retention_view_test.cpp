/*
 * retention_view_test -- the retention rules on a widget, against a node of
 * the test's own: this node's rules kept by `log/rules` and parsed by
 * `log/retain`, the real modules, and the estate's held as their canonical
 * texts. sec 485.
 */

extern "C" {
#include "../../log/rules.h"
}

#include "../retention_view.h"

#include <QApplication>

#include <stdio.h>
#include <string.h>

static int checks, failures;

#define CHECK(cond, what)                                                                      \
	do {                                                                                   \
		checks++;                                                                      \
		if (!(cond)) {                                                                 \
			failures++;                                                            \
			fprintf(stderr, "  FAIL retention_view_test.cpp:%d: %s\n", __LINE__, what); \
		}                                                                              \
	} while (0)


#define MEM_ROWS 80u

struct row {
	int used;
	fzn_persist_slot_t slot;
	uint8_t subject[FZN_PUBKEY_LEN];
	uint8_t bytes[512];
	size_t len;
};

static struct row rows[MEM_ROWS];
static int no_list;

static struct row *find(fzn_persist_slot_t slot, const uint8_t *subject)
{
	size_t i;

	for (i = 0; i < MEM_ROWS; i++)
		if (rows[i].used && rows[i].slot == slot && subject
		    && memcmp(rows[i].subject, subject, FZN_PUBKEY_LEN) == 0)
			return &rows[i];
	return NULL;
}

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	struct row *r = find(slot, subject);

	(void)ctx;
	if (!r || r->len > cap)
		return 0;
	memcpy(out, r->bytes, r->len);
	*len = r->len;
	return 1;
}

static int mem_save(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject,
                    const uint8_t *bytes, size_t len)
{
	struct row *r = find(slot, subject);
	size_t i;

	(void)ctx;
	for (i = 0; !r && i < MEM_ROWS; i++)
		if (!rows[i].used)
			r = &rows[i];
	if (!r || !subject || len > sizeof(r->bytes))
		return 0;
	r->used = 1;
	r->slot = slot;
	memcpy(r->subject, subject, FZN_PUBKEY_LEN);
	memcpy(r->bytes, bytes, len);
	r->len = len;
	return 1;
}

static int mem_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max, size_t *count)
{
	size_t i, n = 0;

	(void)ctx;
	if (no_list)
		return 0;
	for (i = 0; i < MEM_ROWS; i++)
		if (rows[i].used && rows[i].slot == slot) {
			if (n == max)
				return 0;
			memcpy(out + (n * FZN_PUBKEY_LEN), rows[i].subject, FZN_PUBKEY_LEN);
			n++;
		}
	*count = n;
	return 1;
}

static int mem_remove(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject)
{
	struct row *r = find(slot, subject);

	(void)ctx;
	if (r)
		r->used = 0;
	return 1;
}

static const fzn_persist_ops_t OPS = { mem_load, mem_save, mem_list, mem_remove, NULL };

static int toy_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	size_t i;

	(void)ctx;
	memset(out, 0x5c, out_len);
	for (i = 0; i < in_len; i++)
		out[i % out_len] = (uint8_t)((out[i % out_len] * 31u) ^ in[i]);
	return 1;
}

static const fzn_hash_ops_t HASH = { toy_hash, NULL };

/* THE NODE: `silent` answers nothing, `not_root` refuses the estate's
 * writes as a node that stands as neither. */
static int silent, not_root;
static QStringList estate;

/* `ok COUNT RULE ...`, each rule escaped into one word as `node/admin.c`
 * does. */
static size_t listing(const QStringList &rules, char *reply, size_t cap)
{
	QByteArray out = QByteArray("ok ") + QByteArray::number(rules.size());
	int i, j;

	for (i = 0; i < rules.size(); i++) {
		QByteArray r = rules[i].toUtf8();

		out.append(' ');
		for (j = 0; j < r.size(); j++) {
			unsigned char c = (unsigned char)r[j];

			if (c < 0x21u || c == '%' || c == ',' || c == 0x7fu)
				out.append(QByteArray("%") + QByteArray::number(c, 16).toUpper().rightJustified(2, '0'));
			else
				out.append((char)c);
		}
	}
	out.append('\n');
	return (size_t)snprintf(reply, cap, "%s", out.constData());
}

static QString canonical(const char *text, bool *ok)
{
	fzn_retain_rule_t r;
	char t[FZN_RETAIN_TEXT_MAX];
	size_t len = 0;

	*ok = fzn_retain_parse(text, strlen(text), &r) == FZN_RETAIN_OK
	      && fzn_retain_text(&r, t, sizeof(t), &len) == FZN_RETAIN_OK;
	return *ok ? QString::fromUtf8(t) : QString();
}

static size_t node_ask(void *ctx, const char *line, char *reply, size_t cap)
{
	fzn_retain_rule_t rules[FZN_LOG_RULES_MAX], r;
	size_t n = 0, i;
	bool ok = false;

	(void)ctx;
	if (silent)
		return 0;
	if (!strcmp(line, "list retention")) {
		QStringList all;
		char t[FZN_RETAIN_TEXT_MAX];
		size_t len = 0;

		if (fzn_log_rules_list(&OPS, rules, FZN_LOG_RULES_MAX, &n) != FZN_LOG_RULES_OK)
			return (size_t)snprintf(reply, cap, "error the rules did not read\n");
		for (i = 0; i < n; i++)
			if (fzn_retain_text(&rules[i], t, sizeof(t), &len) == FZN_RETAIN_OK)
				all << QString::fromUtf8(t);
		return listing(all, reply, cap);
	}
	if (!strcmp(line, "list estate-retention"))
		return listing(estate, reply, cap);
	if (!strncmp(line, "add retention ", 14u) || !strncmp(line, "remove retention ", 17u)) {
		int add = line[0] == 'a';
		const char *text = line + (add ? 14 : 17);
		fzn_log_rules_err_t err;

		if (fzn_retain_parse(text, strlen(text), &r) != FZN_RETAIN_OK)
			return (size_t)snprintf(reply, cap, "malformed not a rule\n");
		err = add ? fzn_log_rules_add(&OPS, &HASH, &r, 1u) : fzn_log_rules_remove(&OPS, &HASH, &r);
		return (size_t)snprintf(reply, cap, err == FZN_LOG_RULES_OK ? "ok\n" : "error %s\n",
		                        fzn_log_rules_err_str(err));
	}
	if (!strncmp(line, "add estate-retention ", 21u)
	    || !strncmp(line, "remove estate-retention ", 24u)) {
		int add = line[0] == 'a';
		QString c = canonical(line + (add ? 21 : 24), &ok);

		if (!ok)
			return (size_t)snprintf(reply, cap, "malformed not a rule\n");
		if (not_root)
			return (size_t)snprintf(reply, cap,
			                        "error this node stands as neither a root nor an admin\n");
		if (add && estate.contains(c))
			return (size_t)snprintf(reply, cap, "error the rule is the estate's already\n");
		if (!add && !estate.contains(c))
			return (size_t)snprintf(reply, cap, "error no such estate rule\n");
		if (add)
			estate << c;
		else
			estate.removeAll(c);
		return (size_t)snprintf(reply, cap, "ok\n");
	}
	return (size_t)snprintf(reply, cap, "unsupported\n");
}

int main(int argc, char **argv)
{
	QApplication app(argc, argv);

	{
		fzn_retention_view w(node_ask, nullptr);

		CHECK(w.node_rules().isEmpty() && w.status() == QStringLiteral("No rules.")
		              && w.estate_status() == QStringLiteral("No rules."),
		      "an empty node shows no rules on either side, and says so");

		w.set_rule(QStringLiteral("prune fuzznetd level=TD text=link%20up age 48h"));
		CHECK(w.add(false)
		              && w.node_rules()
		                         == QStringList{ QStringLiteral(
		                                 "prune fuzznetd level=DT text=link%20up age 2d") }
		              && w.status() == QStringLiteral("1 rule(s)."),
		      "a rule added here is listed once, in the node's canonical spelling");
		w.set_rule(QStringLiteral("prune fuzznetd level=DT text=link%20up age 2d"));
		CHECK(!w.add(false) && w.status() == QStringLiteral("the rule is held already"),
		      "the same rule again is refused in the node's words");
		w.set_rule(QStringLiteral("prune * ages 1d"));
		CHECK(!w.add(false) && w.status() == QStringLiteral("not a rule"),
		      "a line that is no rule is refused");

		w.set_rule(QStringLiteral("keep * level=CEW age 90d"));
		CHECK(w.add(true) && w.estate_rules() == QStringList{ QStringLiteral("keep * level=CEW age 90d") }
		              && w.node_rules().size() == 1,
		      "an estate rule is listed on the estate's side, and only there");

		w.set_rule(QString());
		w.select(false, 0);
		CHECK(w.remove(false) && w.node_rules().isEmpty(),
		      "the row selected is removed by the spelling it was listed in");

		not_root = 1;
		w.set_rule(QStringLiteral("prune * age 1d"));
		CHECK(!w.add(true)
		              && w.estate_status()
		                         == QStringLiteral("this node stands as neither a root nor an admin"),
		      "a node that is neither root nor admin is told so, in its words");
		not_root = 0;

		silent = 1;
		CHECK(!w.refresh() && w.status() == QStringLiteral("The node did not answer.")
		              && w.node_rules().isEmpty(),
		      "a node that does not answer says so, rather than showing no rules");
		silent = 0;
		CHECK(w.refresh() && w.estate_rules().size() == 1, "and answering again, shows them");
		w.set_rule(QString());
		CHECK(!w.remove(false) && w.status() == QStringLiteral("Type or select a rule first."),
		      "removing with nothing typed or selected asks for a rule");
	}
	if (failures) {
		fprintf(stderr, "retention_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("retention_view_test: all %d checks passed\n", checks);
	return 0;
}
