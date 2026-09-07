/* Tests for gui/capability_view.cpp.
 *
 * THE CASE THIS FILE EXISTS FOR is that the widget asks the two questions
 * the library owns, and asks the right one of each.
 *
 *   - Expiry is `fzn_chain_expired_at`. FZN_NO_EXPIRY is 0, so the naive
 *     `expires_at <= now` is not a weaker test but an inverted one: it
 *     reports every unexpiring chain as expired. The case that separates
 *     them is a chain that never expires, read at a very late `now`.
 *
 *   - Revocation is `fzn_revocation_covers`, not `fzn_revocation_known`.
 *     They differ on exactly one state, an entry whose revocation has been
 *     withdrawn, and a store that has never seen a withdrawal cannot tell
 *     them apart at all. So the case is built with `withdrawn` set, and it
 *     is the only case in this file that could ever have caught it.
 *
 * Both are chosen so that the plausible wrong answer and the right one
 * differ, rather than so that the right one passes -- a store with no
 * withdrawal and a chain with a real expiry agree under every version of
 * this widget that has ever been written.
 */

#include "../capability_view.h"

extern "C" {
#include "../../trust/trust.h"
}

#include <QApplication>

#include <stdio.h>
#include <string.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;
	failures++;
	fprintf(stderr, "  FAIL capability_view_test.cpp:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

/* A chain as a host has already decided to believe it. Nothing here is
 * verified -- `fzn_chain_t` is the verdict form, and this widget renders a
 * verdict somebody else reached. */
static void chain_of(fzn_chain_t *chain, uint64_t expires_at)
{
	memset(chain, 0, sizeof(*chain));
	memset(chain->root, 0xa0, sizeof(chain->root));
	memset(chain->grantee, 0xb0, sizeof(chain->grantee));
	memset(&chain->capability, 0xc0, sizeof(chain->capability));
	chain->hop_count = 1;
	chain->expires_at = expires_at;
}

/* One entry naming this chain's triple, put in by hand.
 *
 * Admitting a record would need a signing fixture and would prove the
 * admission path, which `chain/test/revocation_test.c` already does at
 * length. What this file needs is a store in a particular STATE, and the
 * store is caller-owned memory whose shape is public. */
static void store_of(fzn_revocation_store_t *store, fzn_revocation_t *entries,
                     const fzn_chain_t *chain, int withdrawn)
{
	memset(entries, 0, sizeof(*entries));
	entries->capability = chain->capability;
	memcpy(entries->grantee, chain->grantee, sizeof(entries->grantee));
	memcpy(entries->issuer, chain->root, sizeof(entries->issuer));
	entries->withdrawn = (uint8_t)withdrawn;

	fzn_revocation_store_init(store, entries, 1);
	store->used = 1;
}

int main(int argc, char **argv)
{
	qputenv("QT_QPA_PLATFORM", "offscreen");

	QApplication app(argc, argv);
	fzn_capability_view view;
	fzn_chain_t chain;
	fzn_revocation_store_t store;
	fzn_revocation_t entry;

	/* THE CASE THE SENTINEL DECIDES. A chain that never expires, read as
	 * late as a uint64 goes. `expires_at <= now` answers "expired" here
	 * and `fzn_chain_expired_at` answers "not", so this is the one input
	 * on which the widget's own arithmetic and the library's disagree. */
	chain_of(&chain, FZN_NO_EXPIRY);
	view.show_capability(&chain, nullptr, UINT64_MAX);
	CHECK(view.shown_state() == fzn_capability_view::USABLE,
	      "a chain that never expires was shown as expired at a late now");
	CHECK(view.expiry_text() == QStringLiteral("does not expire"),
	      "the no-expiry sentinel was printed as an instant");

	/* The library agrees, asked directly. Two readings of one rule, and
	 * the widget is not allowed to be the only one that holds it. */
	CHECK(!fzn_chain_expired_at(&chain, UINT64_MAX),
	      "fzn_chain_expired_at called an unexpiring chain expired");

	/* A REAL EXPIRY STILL EXPIRES. Without this the case above is
	 * satisfied by a widget that never reports expiry at all. */
	chain_of(&chain, 1000u);
	view.show_capability(&chain, nullptr, 1000u);
	CHECK(view.shown_state() == fzn_capability_view::EXPIRED,
	      "a chain expiring at now was not shown as expired");
	CHECK(view.expiry_text() == QStringLiteral("1000"),
	      "a real expiry was not shown");

	view.show_capability(&chain, nullptr, 999u);
	CHECK(view.shown_state() == fzn_capability_view::USABLE,
	      "a chain was shown as expired a moment before it expires");

	/* THE CASE THAT SEPARATES `covers` FROM `known`, and the only one
	 * that can. The store holds this triple, so `known` is 1; the record
	 * is a withdrawal, so `covers` is 0. A widget asking the replication
	 * question shows a restored capability as revoked. */
	chain_of(&chain, FZN_NO_EXPIRY);
	store_of(&store, &entry, &chain, 1);
	CHECK(fzn_revocation_known(&store, chain.root, &chain.capability, chain.grantee),
	      "the fixture does not hold the triple, so it separates nothing");
	CHECK(!fzn_revocation_covers(&store, chain.root, &chain.capability, chain.grantee),
	      "the fixture is not a withdrawal, so it separates nothing");

	view.show_capability(&chain, &store, 0u);
	CHECK(view.shown_state() == fzn_capability_view::USABLE,
	      "a capability whose revocation was withdrawn was shown as revoked");

	/* AND A LIVE REVOCATION IS STILL A REVOCATION. The pair of these is
	 * the assertion; either alone passes for a widget that answers one
	 * way about everything. */
	store_of(&store, &entry, &chain, 0);
	view.show_capability(&chain, &store, 0u);
	CHECK(view.shown_state() == fzn_capability_view::REVOKED,
	      "a revoked capability was not shown as revoked");

	/* REVOCATION WINS OVER EXPIRY, and the two never share a word. */
	{
		QString revoked_text;

		chain_of(&chain, 1000u);
		store_of(&store, &entry, &chain, 0);
		view.show_capability(&chain, &store, 5000u);
		CHECK(view.shown_state() == fzn_capability_view::REVOKED,
		      "an expired chain that was also revoked did not show as revoked");
		revoked_text = view.state_text();

		view.show_capability(&chain, nullptr, 5000u);
		CHECK(view.shown_state() == fzn_capability_view::EXPIRED,
		      "the same chain with no revocation store did not show as expired");
		CHECK(view.state_text() != revoked_text,
		      "expired and revoked are shown in the same words, so a reader "
		      "cannot tell a schedule running out from somebody's decision");
	}

	/* A CORRUPT STORE REACHES THE LIBRARY AND GETS ITS ANSWER. `covers`
	 * fails closed on a store it cannot scan; a widget that checked the
	 * store itself and passed NULL instead would fail open. */
	{
		fzn_revocation_store_t broken;

		chain_of(&chain, FZN_NO_EXPIRY);
		store_of(&broken, &entry, &chain, 1);
		broken.used = broken.capacity + 1u;

		view.show_capability(&chain, &broken, 0u);
		CHECK(view.shown_state() == fzn_capability_view::REVOKED,
		      "a store that cannot be scanned was treated as holding nothing");
	}

	/* NO CHAIN IS ITS OWN STATE, not a dead capability and not whatever
	 * was on the screen before. */
	chain_of(&chain, FZN_NO_EXPIRY);
	view.show_capability(&chain, nullptr, 0u);
	view.show_capability(nullptr, nullptr, 0u);
	CHECK(view.shown_state() == fzn_capability_view::HOLDS_NOTHING,
	      "a null chain left the previous capability on screen");
	CHECK(view.capability_text() == QStringLiteral("none held"),
	      "a null chain shows a capability id");

	/* The two identifiers are spelled as the anchor spells them, and are
	 * not the same value read twice. */
	chain_of(&chain, FZN_NO_EXPIRY);
	view.show_capability(&chain, nullptr, 0u);
	{
		char text[FZN_TRUST_FINGERPRINT_LEN];

		CHECK(fzn_trust_fingerprint(chain.capability.b, text, sizeof(text)) ==
		              FZN_TRUST_OK &&
		              view.capability_text() == QString::fromLatin1(text),
		      "the capability is not spelled the way trust_view spells a key");
		CHECK(view.capability_text() != view.grantee_text(),
		      "the capability and the grantee are shown as the same value");
	}

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("capability_view_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
