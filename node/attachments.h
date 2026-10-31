/*
 * THE FILES A CONVERSATION SENT, and the attachment rules over them, sec
 * 795: the holder's `prune|keep attachments ...` of sec 793 applied.
 *
 * TAKEN AS LINES ARE: each line whose text is an attachment's reference
 * (`messages/attachment.h`), in or out, is noted once in its
 * conversation's index -- its month, the size its reference claims and
 * its file's root -- and holds that file (`node/file_holds.h`) by an id
 * drawn from the conversation, the direction and the line's id. A line
 * told again changes nothing.
 *
 * TRIMMED AS MESSAGES ARE, BY THE MONTH (sec 531): newest first, a month
 * goes when every attachment of it would, and the current month never
 * does. Each, one contact's, all together and a default are weighed as
 * sec 793 weighs messages, every contact's together over the attachments
 * this index holds. A MONTH GONE RELEASES ITS HOLDS: a file whose last
 * hold that was, and that neither the catalogue nor a saved sticker pack
 * names (`held_elsewhere`), is removed first and its hold released after;
 * one held otherwise is released and kept. A removal that cannot run now
 * -- the file in a transfer -- leaves the entry for the next trim.
 *
 * Persist slot FZN_PERSIST_ATTACHMENT, bulk: each entry a row keyed by a
 * hash of its conversation and its place, each conversation's count, and
 * the list of conversations.
 */
#ifndef FZN_NODE_ATTACHMENTS_H
#define FZN_NODE_ATTACHMENTS_H

#include <stddef.h>
#include <stdint.h>

#include "../log/retain.h"
#include "../messages/attachment.h"
#include "file_holds.h"

typedef struct fzn_attachments {
	const fzn_persist_ops_t *store;
	const fzn_hash_ops_t *hash;
} fzn_attachments_t;

/* THE ATTACHMENT `att` A LINE OF `contact`'s CONVERSATION SENT, line `id`
 * of month `epoch` going `direction`: noted and its file held. `*added` 1
 * when it is new here. 1 on success. */
int fzn_attachments_take(const fzn_attachments_t *a, const uint8_t contact[32], uint8_t direction,
                         const uint8_t id[16], uint32_t epoch, const fzn_attachment_t *att,
                         int *added);

/* How many attachments `contact`'s conversation has noted. */
uint64_t fzn_attachments_count(const fzn_attachments_t *a, const uint8_t contact[32]);

/* THE LINES KEPT BEFORE THIS INDEX, sec 796: the caller tells every line
 * kept to `fzn_attachments_take` once, then ends it here. Each file a line
 * then holds lets go of the hold it had from before the record of holds
 * began (LEGACY), so the rules reach it, and the index is marked told.
 * `*released` counts the holds let go. A file no kept line names keeps its
 * hold from before. Until it is told, the caller trims nothing: a file
 * two lines sent may be noted for one and not yet the other. */
int fzn_attachments_backfilled(const fzn_attachments_t *a);
int fzn_attachments_backfill_end(const fzn_attachments_t *a, size_t *released);

typedef struct fzn_attachments_tally {
	size_t months;   /* conversation months whose attachments went */
	size_t released; /* holds released */
	size_t removed;  /* files removed, their last hold released */
	size_t waiting;  /* removals that could not run now */
} fzn_attachments_tally_t;

/* TRIM BY THE RULES (`rules`, the attachment rules that reach this node)
 * at `now_ms`. `held_elsewhere` says a file another holder names, which is
 * never removed; `remove` removes one, 1 when it is gone. */
int fzn_attachments_trim(const fzn_attachments_t *a, const fzn_retain_rule_t *rules,
                         size_t n_rules, uint64_t now_ms,
                         int (*held_elsewhere)(void *ctx, const uint8_t root[32]),
                         int (*remove)(void *ctx, const uint8_t root[32]), void *ctx,
                         fzn_attachments_tally_t *tally);

#endif /* FZN_NODE_ATTACHMENTS_H */
