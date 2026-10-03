/* See rules.h. */

#include "rules.h"

#include "../wire/bytes.h"

#include <stdlib.h>
#include <string.h>

#define LABEL "fuzznet.log.rule"
/* text_len, the text, added_at. */
#define BODY_LEN(n) (1u + (size_t)(n) + 8u)
#define BLOB_MAX ((size_t)FZN_PERSIST_HEAD_LEN + BODY_LEN(FZN_RETAIN_TEXT_MAX - 1u))

const char *fzn_log_rules_err_str(fzn_log_rules_err_t err)
{
	switch (err) {
	case FZN_LOG_RULES_OK:
		return "ok";
	case FZN_LOG_RULES_ERR_MALFORMED:
		return "not a rule";
	case FZN_LOG_RULES_ERR_TAKEN:
		return "the rule is held already";
	case FZN_LOG_RULES_ERR_ABSENT:
		return "no such rule";
	case FZN_LOG_RULES_ERR_FULL:
		return "the rules are full";
	case FZN_LOG_RULES_ERR_BACKEND:
		return "the store or the hash refused";
	case FZN_LOG_RULES_ERR_SHAPE:
		return "a held rule will not read";
	}
	return "unknown";
}

/* The rule's canonical text and the subject it is filed under. */
static fzn_log_rules_err_t key_of(const fzn_hash_ops_t *hash, const fzn_retain_rule_t *rule,
                                  char text[FZN_RETAIN_TEXT_MAX], size_t *len,
                                  uint8_t subject[FZN_PUBKEY_LEN])
{
	uint8_t in[sizeof(LABEL) + FZN_RETAIN_TEXT_MAX];

	if (!hash || !hash->hash || !rule
	    || fzn_retain_text(rule, text, FZN_RETAIN_TEXT_MAX, len) != FZN_RETAIN_OK)
		return FZN_LOG_RULES_ERR_MALFORMED;
	memcpy(in, LABEL, sizeof(LABEL));
	memcpy(in + sizeof(LABEL), text, *len);
	/* NONZERO IS SUCCESS on this seam (`session/commitment.h`). */
	if (!hash->hash(hash->ctx, subject, FZN_PUBKEY_LEN, in, sizeof(LABEL) + *len))
		return FZN_LOG_RULES_ERR_BACKEND;
	return FZN_LOG_RULES_OK;
}

/* One held rule read back; its text into `text` when given. */
static fzn_log_rules_err_t get(const fzn_persist_ops_t *store, const uint8_t *subject,
                               fzn_retain_rule_t *out, char text[FZN_RETAIN_TEXT_MAX])
{
	uint8_t blob[BLOB_MAX];
	const uint8_t *body = blob + FZN_PERSIST_HEAD_LEN;
	size_t len = 0, n;

	if (!store->load(store->ctx, FZN_PERSIST_LOG_RULE, subject, blob, sizeof(blob), &len))
		return FZN_LOG_RULES_ERR_ABSENT;
	if (len < FZN_PERSIST_HEAD_LEN + 1u)
		return FZN_LOG_RULES_ERR_SHAPE;
	n = body[0];
	if (n == 0u || n >= FZN_RETAIN_TEXT_MAX
	    || fzn_persist_head_check(blob, len, BODY_LEN(n), FZN_PERSIST_BLOB_LOG_RULE)
	               != FZN_PERSIST_OK
	    || fzn_retain_parse((const char *)body + 1, n, out) != FZN_RETAIN_OK)
		return FZN_LOG_RULES_ERR_SHAPE;
	if (text) {
		memcpy(text, body + 1, n);
		text[n] = '\0';
	}
	return FZN_LOG_RULES_OK;
}

fzn_log_rules_err_t fzn_log_rules_add(const fzn_persist_ops_t *store, const fzn_hash_ops_t *hash,
                                      const fzn_retain_rule_t *rule, uint64_t now_ms)
{
	static uint8_t subjects[FZN_LOG_RULES_MAX + 1u][FZN_PUBKEY_LEN];
	uint8_t blob[BLOB_MAX], subject[FZN_PUBKEY_LEN];
	char text[FZN_RETAIN_TEXT_MAX];
	fzn_retain_rule_t held;
	size_t len = 0, count = 0;
	fzn_log_rules_err_t err;

	if (!store || !store->load || !store->save || !store->list)
		return FZN_LOG_RULES_ERR_MALFORMED;
	err = key_of(hash, rule, text, &len, subject);
	if (err != FZN_LOG_RULES_OK)
		return err;
	err = get(store, subject, &held, NULL);
	if (err == FZN_LOG_RULES_OK)
		return FZN_LOG_RULES_ERR_TAKEN;
	if (err != FZN_LOG_RULES_ERR_ABSENT)
		return err;
	/* A STORE THAT CANNOT LIST REFUSES, rather than growing past what a
	 * list call can return. */
	if (!store->list(store->ctx, FZN_PERSIST_LOG_RULE, (uint8_t *)subjects,
	                 FZN_LOG_RULES_MAX + 1u, &count))
		return FZN_LOG_RULES_ERR_BACKEND;
	if (count >= FZN_LOG_RULES_MAX)
		return FZN_LOG_RULES_ERR_FULL;
	if (fzn_persist_head_write(blob, sizeof(blob), BODY_LEN(len), FZN_PERSIST_BLOB_LOG_RULE)
	    != FZN_PERSIST_OK)
		return FZN_LOG_RULES_ERR_MALFORMED;
	blob[FZN_PERSIST_HEAD_LEN] = (uint8_t)len;
	memcpy(blob + FZN_PERSIST_HEAD_LEN + 1u, text, len);
	fzn_put_be64(blob + FZN_PERSIST_HEAD_LEN + 1u + len, now_ms);
	if (!store->save(store->ctx, FZN_PERSIST_LOG_RULE, subject, blob,
	                 FZN_PERSIST_HEAD_LEN + BODY_LEN(len)))
		return FZN_LOG_RULES_ERR_BACKEND;
	return FZN_LOG_RULES_OK;
}

fzn_log_rules_err_t fzn_log_rules_remove(const fzn_persist_ops_t *store,
                                         const fzn_hash_ops_t *hash,
                                         const fzn_retain_rule_t *rule)
{
	uint8_t subject[FZN_PUBKEY_LEN];
	char text[FZN_RETAIN_TEXT_MAX];
	fzn_retain_rule_t held;
	size_t len = 0;
	fzn_log_rules_err_t err;

	if (!store || !store->load || !store->remove)
		return FZN_LOG_RULES_ERR_MALFORMED;
	err = key_of(hash, rule, text, &len, subject);
	if (err != FZN_LOG_RULES_OK)
		return err;
	err = get(store, subject, &held, NULL);
	if (err != FZN_LOG_RULES_OK && err != FZN_LOG_RULES_ERR_SHAPE)
		return err;
	if (!store->remove(store->ctx, FZN_PERSIST_LOG_RULE, subject))
		return FZN_LOG_RULES_ERR_BACKEND;
	return FZN_LOG_RULES_OK;
}

struct listed {
	char text[FZN_RETAIN_TEXT_MAX];
	fzn_retain_rule_t rule;
};

static int by_text(const void *a, const void *b)
{
	return strcmp(((const struct listed *)a)->text, ((const struct listed *)b)->text);
}

fzn_log_rules_err_t fzn_log_rules_list(const fzn_persist_ops_t *store, fzn_retain_rule_t *out,
                                       size_t cap, size_t *count)
{
	static uint8_t subjects[FZN_LOG_RULES_MAX][FZN_PUBKEY_LEN];
	static struct listed all[FZN_LOG_RULES_MAX];
	size_t held = 0, i;
	fzn_log_rules_err_t err;

	if (!store || !store->load || !store->list || (!out && cap) || !count)
		return FZN_LOG_RULES_ERR_MALFORMED;
	*count = 0;
	if (!store->list(store->ctx, FZN_PERSIST_LOG_RULE, (uint8_t *)subjects, FZN_LOG_RULES_MAX,
	                 &held))
		return FZN_LOG_RULES_ERR_BACKEND;
	for (i = 0; i < held; i++) {
		err = get(store, subjects[i], &all[i].rule, all[i].text);
		if (err != FZN_LOG_RULES_OK)
			return err == FZN_LOG_RULES_ERR_ABSENT ? FZN_LOG_RULES_ERR_SHAPE : err;
	}
	qsort(all, held, sizeof(all[0]), by_text);
	for (i = 0; i < held && i < cap; i++)
		out[i] = all[i].rule;
	*count = i;
	return FZN_LOG_RULES_OK;
}
