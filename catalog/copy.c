/* See copy.h. */

#include "copy.h"

#include <string.h>

/* HOW MANY HOLDERS FIT BEFORE THE ANSWER STOPS BEING CERTAIN. The same bound
 * and the same reasoning as catalog/sweep.c: this host's own membership is
 * what a short list can hide, and "did not fit" must not be read as "is not a
 * holder". Kept as its own constant rather than shared, because the two
 * modules are free to want different sizes and a shared one would make that a
 * change to both. */
#define HOLDER_SCRATCH 16u

static int bytes_eq(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
	if (alen != blen)
		return 0;
	if (alen == 0)
		return 1;
	return memcmp(a, b, alen) == 0;
}

/* Does this host hold `entity`? Returns 0 when that cannot be determined, and
 * writes nothing.
 *
 * THE OLD MODULE'S CALLBACK SEAM, ANSWERED FROM THE RECORDS. `host_holds` used
 * to ask a consumer, and an absent seam answered "this host holds nothing" --
 * the easy case for a host adopting a catalogue, and a direction chosen so a
 * partly-filled ops struct could not make a host advertise bytes it cannot
 * serve. There is no seam to leave out now: a HOLDER assertion can only be
 * issued by a host that has the bytes, so the question is asked of the set. */
static int self_holds(const fzn_catalog_assertion_t *set, size_t count,
                      const uint8_t *entity, size_t entity_len,
                      const uint8_t *self, size_t self_len, int *out)
{
	fzn_catalog_source_t who[HOLDER_SCRATCH];
	size_t written = 0, dropped = 0, i;
	int mine = 0;

	if (fzn_catalog_holders(set, count, entity, entity_len, who, HOLDER_SCRATCH,
	                          &written, &dropped) != FZN_CATALOG_OK)
		return 0;

	for (i = 0; i < written; i++)
		if (bytes_eq(who[i].issuer, who[i].issuer_len, self, self_len))
			mine = 1;

	/* A `self` that did not fit is indistinguishable from a `self` that is
	 * not a holder, and those lead to opposite answers -- announce the
	 * bytes, or go and fetch them. Refuse to pick. */
	if (!mine && dropped > 0)
		return 0;

	*out = mine;
	return 1;
}

/* Is `entity` in this host's view at all?
 *
 * DELIBERATELY BROADER THAN `fzn_catalog_referenced`, and the two must not
 * be confused. `referenced` asks what WANTS an entity, and skips holder
 * assertions for that reason; the scope check asks whether this host's set
 * mentions the entity in any way, because an entity this host holds and
 * nothing curates is still one it may serve. Using `referenced` here would
 * refuse to serve exactly the bytes a peer is most likely to be catching up
 * on. */
static int known_here(const fzn_catalog_assertion_t *set, size_t count,
                      const uint8_t *entity, size_t entity_len)
{
	size_t i;

	for (i = 0; i < count; i++)
		if (bytes_eq(set[i].entity, set[i].entity_len, entity, entity_len))
			return 1;
	return 0;
}

static int already_listed(const fzn_catalog_entity_t *out, size_t written,
                          const uint8_t *entity)
{
	size_t i;

	for (i = 0; i < written; i++)
		if (memcmp(out[i].b, entity, FZN_CATALOG_ENTITY_LEN) == 0)
			return 1;
	return 0;
}

/* Append, or count the truncation. Nothing is written past `out_cap`, and a
 * truncated walk keeps walking so the counters describe the whole set rather
 * than the prefix that fitted -- a caller sizing its array needs the total,
 * and `truncated` is the number to add. */
static void emit(fzn_catalog_entity_t *out, size_t out_cap,
                 fzn_catalog_copy_t *plan, const uint8_t *entity)
{
	if (already_listed(out, plan->written, entity)) {
		plan->duplicates++;
		return;
	}
	if (plan->written >= out_cap) {
		plan->truncated++;
		return;
	}

	memcpy(out[plan->written].b, entity, FZN_CATALOG_ENTITY_LEN);
	plan->written++;
}

static int seen_before(const fzn_catalog_assertion_t *set, size_t upto,
                       const uint8_t *entity, size_t entity_len)
{
	size_t i;

	for (i = 0; i < upto; i++)
		if (bytes_eq(set[i].entity, set[i].entity_len, entity, entity_len))
			return 1;
	return 0;
}

/* Both walks over the set share everything but one question, so they share the
 * walk. `retained_only` is that question: a want list asks what this host has
 * chosen to keep and what still wants fetching, and a holdings announcement
 * asks nothing about policy at all -- see copy.h, where the difference between
 * an intention and a fact is argued. */
static fzn_catalog_err_t walk(const fzn_catalog_assertion_t *set, size_t count,
                                const fzn_catalog_holds_t *holds, int retained_only,
                                const uint8_t *self, size_t self_len, uint64_t now,
                                int want_missing,
                                fzn_catalog_entity_t *out, size_t out_cap,
                                fzn_catalog_copy_t *plan)
{
	size_t i;

	if (!plan)
		return FZN_CATALOG_ERR_MALFORMED;
	memset(plan, 0, sizeof(*plan));
	if ((count != 0 && !set) || !self || self_len == 0 || (!out && out_cap > 0))
		return FZN_CATALOG_ERR_MALFORMED;

	for (i = 0; i < count; i++) {
		const fzn_catalog_assertion_t *a = &set[i];
		int held = 0;

		if (a->entity_len != FZN_CATALOG_ENTITY_LEN)
			continue;
		if (seen_before(set, i, a->entity, a->entity_len))
			continue;

		/* WANT DEPENDS ON RETENTION, and the order matters: an entity
		 * this host has decided not to keep is not a candidate for
		 * fetching however loudly the estate curates it. */
		if (retained_only &&
		    !fzn_catalog_keeps(holds, a->entity, a->entity_len, now)) {
			plan->not_retained++;
			continue;
		}
		/* AND ON SOMETHING WANTING IT. C9: a curated link is what says
		 * an entity is wanted; a holder assertion says only where it
		 * is. Without this a host would fetch bytes nothing links to. */
		if (retained_only &&
		    !fzn_catalog_referenced(set, count, a->entity, a->entity_len)) {
			plan->not_referenced++;
			continue;
		}

		if (!self_holds(set, count, a->entity, a->entity_len, self, self_len,
		                &held)) {
			plan->incomplete++;
			continue;
		}

		/* CLASSIFY FIRST, EMIT SECOND, and both walks classify
		 * identically. Counting only the class a walk emits would leave
		 * each walk's counters describing a different population, and
		 * the two sums copy.h states could not both be checked. */
		if (held)
			plan->already_held++;
		else
			plan->missing++;

		/* A want list emits what is missing; a holdings announcement
		 * emits what is here. */
		if (want_missing) {
			if (!held)
				emit(out, out_cap, plan, a->entity);
		} else if (held) {
			emit(out, out_cap, plan, a->entity);
		}
	}

	return FZN_CATALOG_OK;
}

fzn_catalog_err_t fzn_catalog_copy_want(const fzn_catalog_assertion_t *set,
                                            size_t count,
                                            const fzn_catalog_holds_t *holds,
                                            const uint8_t *self, size_t self_len,
                                            uint64_t now,
                                            fzn_catalog_entity_t *out,
                                            size_t out_cap, fzn_catalog_copy_t *plan)
{
	return walk(set, count, holds, 1, self, self_len, now, 1, out, out_cap, plan);
}

fzn_catalog_err_t fzn_catalog_copy_holdings(const fzn_catalog_assertion_t *set,
                                                size_t count,
                                                const uint8_t *self, size_t self_len,
                                                fzn_catalog_entity_t *out,
                                                size_t out_cap,
                                                fzn_catalog_copy_t *plan)
{
	return walk(set, count, NULL, 0, self, self_len, 0, 0, out, out_cap, plan);
}

fzn_catalog_err_t fzn_catalog_copy_offer(const fzn_catalog_assertion_t *set,
                                             size_t count,
                                             const uint8_t *self, size_t self_len,
                                             const fzn_catalog_entity_t *wants,
                                             size_t want_count,
                                             fzn_catalog_entity_t *out,
                                             size_t out_cap, fzn_catalog_copy_t *plan)
{
	size_t i;

	if (!plan)
		return FZN_CATALOG_ERR_MALFORMED;
	memset(plan, 0, sizeof(*plan));
	if ((count != 0 && !set) || !self || self_len == 0 ||
	    (!wants && want_count > 0) || (!out && out_cap > 0))
		return FZN_CATALOG_ERR_MALFORMED;

	for (i = 0; i < want_count; i++) {
		int held = 0;

		/* THE SCOPE CHECK. Without it a want list is a request for any
		 * bytes whose hash a peer can name. */
		if (!known_here(set, count, wants[i].b, FZN_CATALOG_ENTITY_LEN)) {
			plan->unknown++;
			continue;
		}
		if (!self_holds(set, count, wants[i].b, FZN_CATALOG_ENTITY_LEN, self,
		                self_len, &held)) {
			plan->incomplete++;
			continue;
		}
		if (!held) {
			/* Known here and not held. Not an error and not a
			 * refusal: the peer asks again next round. */
			plan->missing++;
			continue;
		}
		plan->already_held++;
		emit(out, out_cap, plan, wants[i].b);
	}

	return FZN_CATALOG_OK;
}
