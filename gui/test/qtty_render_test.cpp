/*
 * The widgets, rendered by qtty onto a character cell grid. sec 158.
 *
 * WHY THIS EXISTS SEPARATELY FROM THE OTHER GUI SUITES. Those assert what a
 * widget HOLDS -- the strings a user would read -- and they all passed while
 * the trust view showed a user 63 hex digits of a 64-digit fingerprint at 80
 * columns. The text was whole and the screen was not, and no assertion over
 * the text can see that.
 *
 * So this one asserts the SCREEN, through the same renderer a terminal uses,
 * and it is the only thing here that would have caught that defect.
 *
 * IT IS NOT PART OF `make check`, and that is deliberate rather than
 * reluctant. It needs a qtty checkout, and qtty is pre-alpha with the API
 * movement its README promises -- so a target wired into the default gate
 * would break this tree whenever that one moved, and a gate that breaks for
 * somebody else's reasons is a gate people switch off. `make qtty
 * QTTY_DIR=../qtty` is the same arrangement `make schema SITU_DIR=../situ`
 * uses for the same reason, down to extracting their HEAD read-only rather
 * than building in their tree.
 *
 * THE PROTOCOL IS THEIRS AND GETTING IT WRONG LOOKS LIKE A DEFECT IN US. A
 * widget must have WA_DontShowOnScreen, be resized in CELL units through
 * `GridMetrics::cells`, be shown, and have its events pumped -- read out of
 * qtty's own `test/suite_render.cpp`. The first version of this probe did
 * none of it and reported a truncated label that was entirely the probe's
 * doing.
 */

#include "../trust_view.h"
#include "../log_view.h"
#include "../qr_view.h"
#include "../authz_view.h"
#include "../capability_view.h"
#include "../sweep_view.h"
#include "../revocation_view.h"
#include "../journal_view.h"
#include "../sync_view.h"
#include "../transfer_view.h"
#include "../state_view.h"
#include "../provision_view.h"
#include "../config_view.h"
#include "../link_view.h"
#include "../peer_view.h"
#include "../manifest_view.h"
#include "../ledger_view.h"
#include "../sched_view.h"
#include "../persist_view.h"

extern "C" {
#include "../../log/log.h"
#include "../../record/journal.h"
#include "../../record/record.h"
}

#include <qtty/grid.h>
#ifdef FZN_HAVE_QUIRC
#include <qtty/application.h>
#include <qtty/cell.h>
#include <qtty/color.h>
#include <QColor>
extern "C" {
#include <quirc.h>
}
#endif
#include <qtty/testing.h>

#include <QApplication>
#include <QString>
#include <QStringList>

#include <cstdio>
#include <cstring>

static uint8_t ISSUER[FZN_PUBKEY_LEN];
static uint8_t SUBJECT[FZN_SUBJECT_LEN];
static uint8_t SLOTS[8][FZN_RECORD_MAX_LEN];

/* The same stub signer log_view_test.cpp uses: this renders records, it does
 * not verify them, and a real signature would only make the fixture slower. */
static void tag(uint8_t out[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	uint64_t h = 1469598103934665603u;
	size_t i;

	for (i = 0; i < msg_len; i++) {
		h ^= msg[i];
		h *= 1099511628211u;
	}
	for (i = 0; i < FZN_SIG_LEN; i++) {
		h ^= h << 13;
		h ^= h >> 7;
		h ^= h << 17;
		out[i] = (uint8_t)(h >> 32);
	}
}

static int stub_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	(void)ctx;
	tag(sig, msg, msg_len);
	return 1;
}

static int make(fzn_record_t *r, size_t which, uint64_t seq, const uint8_t *body,
                size_t body_len)
{
	fzn_sign_ops_t ops;
	size_t wrote = 0;

	memset(&ops, 0, sizeof(ops));
	ops.sign = stub_sign;
	if (fzn_record_sign(ISSUER, SUBJECT, 5u, 3u, seq, 1u, body, body_len, &ops,
	                    SLOTS[which], FZN_RECORD_MAX_LEN, &wrote) != FZN_RECORD_OK)
		return 0;
	return fzn_record_open(SLOTS[which], wrote, r) == FZN_RECORD_OK;
}

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;
	failures++;
	fprintf(stderr, "  FAIL qtty_render_test.cpp:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, (what))

#ifdef FZN_HAVE_QUIRC
/* A cell's background as a grey level, which is what carries a QR module: the
 * code is filled rectangles and has no glyphs at all. */
static int cell_grey(const Qtty::Cell &c)
{
	if (c.bg.kind() == Qtty::Color::Rgb) {
		QColor q = QColor::fromRgba(c.bg.value());
		return qGray(q.red(), q.green(), q.blue());
	}
	if (c.bg.kind() == Qtty::Color::Indexed)
		return c.bg.index() == 0 ? 0 : 255;
	/* The terminal's own colour, which for a code drawn on a painted quiet
	 * zone is the light one. */
	return 255;
}

/* Render `view` at `cols` by `rows` cells, rebuild the pixels a terminal
 * would show, and ask quirc what it reads. Returns 1 when the payload comes
 * back whole, 0 for anything else -- no code found, no decode, or a payload
 * that differs. */
static int decodes_off_a_terminal(fzn_qr_view &view, int cols, int rows, const char *want)
{
	const int cw = Qtty::GridMetrics::cw();
	const int ch = Qtty::GridMetrics::ch();
	struct quirc *q;
	struct quirc_code code;
	struct quirc_data data;
	uint8_t *image;
	int w = cols * cw;
	int h = rows * ch;
	int ok = 0;
	int cx;
	int cy;

	view.setAttribute(Qt::WA_DontShowOnScreen);
	view.resize(Qtty::GridMetrics::cells(cols, rows));
	view.show();
	QCoreApplication::processEvents();

	Qtty::CellBuffer buf(cols, rows);
	Qtty::render_once(view, buf);

	q = quirc_new();
	if (!q || quirc_resize(q, w, h) < 0) {
		if (q)
			quirc_destroy(q);
		return 0;
	}
	image = quirc_begin(q, &w, &h);
	for (cy = 0; cy < rows; cy++) {
		for (cx = 0; cx < cols; cx++) {
			int grey = cell_grey(buf.at(cx, cy));
			int py;

			for (py = 0; py < ch; py++) {
				int px;

				for (px = 0; px < cw; px++)
					image[(cy * ch + py) * w + cx * cw + px] =
					        (uint8_t)grey;
			}
		}
	}
	quirc_end(q);

	if (quirc_count(q) == 1) {
		quirc_extract(q, 0, &code);
		if (quirc_decode(&code, &data) == QUIRC_SUCCESS &&
		    data.payload_len == (int)strlen(want) &&
		    memcmp(data.payload, want, strlen(want)) == 0)
			ok = 1;
	}
	quirc_destroy(q);
	return ok;
}
#endif

/* Render one widget and hand back what the cells hold, glyphs only. */
static QString rendered(QWidget &w, int cols, int rows)
{
	w.setAttribute(Qt::WA_DontShowOnScreen);
	w.resize(Qtty::GridMetrics::cells(cols, rows));
	w.show();
	QCoreApplication::processEvents();
	return Qtty::test::snapshot_of(w, cols, rows).section(QStringLiteral("--- attrs"), 0, 0);
}

/* Whether every line of the fingerprint is on the screen, character for
 * character.
 *
 * ASKED OF THE SNAPSHOT AND NOT OF THE WIDGET, which is the whole point: the
 * widget's own answer was right throughout the defect this guards.
 *
 * A FIRST VERSION COUNTED ALPHANUMERICS AND SUBTRACTED A RENDER OF THE SAME
 * WIDGET WITH NO ANCHOR, meaning to cancel the source label's own letters. It
 * does not cancel: an anchored view says "configured out of band" where an
 * empty one says "no anchor", so the subtraction was between two different
 * strings and reported a missing character at 41 columns that was not
 * missing. Containment needs no arithmetic and cannot make that mistake. */
static int lines_on_screen(const QString &snapshot, const QString &fingerprint)
{
	const QStringList lines = fingerprint.split(QLatin1Char('\n'));

	for (const QString &line : lines)
		if (!snapshot.contains(line))
			return 0;
	return 1;
}

/*
 * EVERY WIDGET ON A TERMINAL, AND HOW NARROW ONE CAN GET.
 *
 * project.md sec 187. Thirteen of these objects exist and three had ever been
 * rendered on a character grid -- the rest carried sec 140's claim and a
 * static gate saying they use no pixel geometry, which is not the same as
 * having been drawn. sec 159 found a real defect by rendering one, so ten
 * unrendered widgets were ten unasked questions.
 *
 * WHAT IS ASSERTED: the words a widget says are ON the grid at 80x24, and the
 * narrowest width at which they still are. The second is the useful number --
 * a consumer sizing a pane needs it, and sec 158 measured 41 columns for the
 * fingerprint the same way.
 *
 * CONTAINMENT, NOT ARITHMETIC, for sec 158's reason: counting characters and
 * subtracting a second render compares two different strings.
 */
struct terminal_case {
	const char *name;
	QWidget *widget;
	const char *must_show;
};

/* The narrowest column count at which `must_show` is still whole on the grid,
 * or 0 if it never is within the range swept. Rows are held at 24. */
static int narrowest(QWidget &w, const char *must_show)
{
	const QString want = QString::fromLatin1(must_show);
	int cols;

	for (cols = 20; cols <= 120; cols++)
		if (rendered(w, cols, 24).contains(want))
			return cols;
	return 0;
}

/* A store that is never read from or written to. `fzn_spool_open` requires
 * the vtable rather than accepting NULL, and this renders rather than
 * transfers -- refusing is the honest stub. */
static int no_read(void *ctx, uint64_t offset, uint8_t *out, size_t len)
{
	(void)ctx; (void)offset; (void)out; (void)len;
	return 0;
}

static int no_write(void *ctx, uint64_t offset, const uint8_t *bytes, size_t len)
{
	(void)ctx; (void)offset; (void)bytes; (void)len;
	return 0;
}

static int no_sync_op(void *ctx)
{
	(void)ctx;
	return 0;
}

static void test_every_widget_survives_a_terminal(void)
{
	fzn_authz_view authz;
	fzn_capability_view capability;
	fzn_sweep_view sweep;
	fzn_revocation_view revocation;
	fzn_journal_view journal_v;
	fzn_sync_view sync;
	fzn_transfer_view transfer;
	fzn_state_view state_v;
	fzn_config_view config;
	fzn_link_view link_v;
	fzn_peer_view peer_v;
	fzn_provision_view provision;
	fzn_manifest_view manifest_v;
	fzn_manifest_view_row manifest_rows[1];
	fzn_ledger_view ledger_v;
	fzn_sched_view sched_v;
	fzn_persist_view persist_v;
	fzn_persist_view_row persist_rows[5];
	fzn_sched_candidate_t sched_links[3];
	fzn_ledger_view_row ledger_rows[1];
	static fzn_ledger_entry_t ledger_entries[1];
	fzn_ledger_t ledger;
	uint8_t subject[FZN_SUBJECT_LEN];
	fzn_authz_view authz_guarded;
	fzn_link_entry_t link_entries[4];
	fzn_link_table_t links;
	fzn_peer_t asker;

	fzn_authz_policy_t policy;
	fzn_authz_policy_t guarded_policy;
	fzn_chain_t chain;
	fzn_catalog_sweep_plan_t plan;
	static fzn_revocation_t rev_rows[2];
	fzn_revocation_store_t rev_store;
	static fzn_journal_entry_t j_rows[2];
	fzn_journal_t j;
	static fzn_manifest_issuer_t m_issuers[2];
	static fzn_manifest_deficit_t m_deficits[4];
	fzn_manifest_state_t m;
	uint8_t peer[FZN_PUBKEY_LEN];
	size_t i;

	memset(peer, 0xa7, sizeof(peer));

	/* Each widget is put into the state a person most needs to read: the
	 * one that says something went wrong or is being held back. */
	policy = fzn_authz_unguarded(FZN_ORIGIN_ANY);
	authz.show_policy(&policy);

	{
		/* THE LONG VARIANT, WHICH THIS SWEEP NEVER DREW. sec 207: the
		 * unguarded fixture above says `no capability -- UNGUARDED`
		 * and is short, so the case where a 64-character capability
		 * precedes the answer was never rendered here -- and that is
		 * exactly the case whose answer fell off the edge. A fixture
		 * that cannot reach the hazard reports on the safe path in the
		 * hazard's name. */
		static fzn_cap_id_t cap;

		memset(&cap, 0xc5, sizeof(cap));
		guarded_policy = fzn_authz_requires(&cap, FZN_ORIGIN_ANY);
		authz_guarded.show_policy(&guarded_policy);
	}

	memset(&chain, 0, sizeof(chain));
	memset(chain.root, 0xa0, sizeof(chain.root));
	memset(chain.grantee, 0xb0, sizeof(chain.grantee));
	memset(&chain.capability, 0xc0, sizeof(chain.capability));
	chain.hop_count = 1;
	chain.expires_at = 1000u;
	capability.show_capability(&chain, NULL, 5000u);

	memset(&plan, 0, sizeof(plan));
	plan.last_copy = 3u;
	sweep.show_sweep(&plan, NULL);

	memset(rev_rows, 0, sizeof(rev_rows));
	rev_rows[0].withdrawn = 1u;
	if (fzn_revocation_store_init(&rev_store, rev_rows, 2u) == FZN_CHAIN_OK) {
		rev_store.used = 1u;
		revocation.show_store(&rev_store);
	}

	if (fzn_journal_init(&j, j_rows, 2u) == FZN_JOURNAL_OK) {
		fzn_journal_anchor(&j, peer, 5u, 0u);
		journal_v.show_stream(&j, peer, 5u);
	}

	if (fzn_manifest_init(&m, m_issuers, 2u, m_deficits, 4u) == FZN_MANIFEST_OK) {
		sync.show_peer(&m, peer);

		/* AND THE STATE THIS SWEEP EXISTS FOR. sec 226: the issuer
		 * whose count is a FLOOR is the row a person must not lose off
		 * the edge, so the fixture is an overflowed issuer rather than
		 * a sound one. */
		memcpy(m_issuers[0].issuer, peer, FZN_PUBKEY_LEN);
		m_issuers[0].overflowed = 1;
		m.issuer_used = 1u;
		manifest_rows[0].issuer = peer;
		manifest_rows[0].label = QStringLiteral("estate root");
		manifest_v.show_issuers(&m, manifest_rows, 1u);
	}

	/* AND THE LEDGER IN THE STATE THAT VOIDS A SCREEN. sec 228: a table
	 * nobody can walk answers every accessor in the voice of a readable
	 * one, so the sentence saying nothing here is evidence is the one a
	 * terminal must not clip. */
	memset(subject, 0x5a, sizeof(subject));
	if (fzn_ledger_init(&ledger, ledger_entries, 1u) == FZN_LEDGER_OK) {
		ledger.used = ledger.capacity + 1u;
		ledger_rows[0].peer = peer;
		ledger_rows[0].label = QStringLiteral("relay");
		ledger_v.show_peers(&ledger, subject, 1u, 5u, ledger_rows, 1u);
	}

	/* THE CLASS NOTHING CAN CARRY, and for three different reasons -- the
	 * state whose line names no bound to change. sec 248. */
	{
		static const fzn_class_t voice = { 50u, 20u, 1200u, 0u, 1u, 0u };

		memset(sched_links, 0, sizeof(sched_links));
		for (i = 0; i < 3u; i++) {
			sched_links[i].id = (uint32_t)i + 1u;
			sched_links[i].metric = 10u;
			sched_links[i].latency_ms = 10u;
			sched_links[i].loss_permille = 0u;
			sched_links[i].mtu = 1500u;
			sched_links[i].usable = 1;
		}
		sched_links[0].latency_ms = 500u;
		sched_links[1].loss_permille = 900u;
		sched_links[2].mtu = 500u;
		sched_v.show_choice(sched_links, 3u, &voice, FZN_SCHED_ERR_NONE, 0u);
	}

	/* FOUR SLOTS BACK AND THE ANCHOR GONE, which is the state a person most
	 * needs to read off this one. sec 254. */
	{
		static const fzn_persist_slot_t slots[5] = { FZN_PERSIST_TRUST,
			                                     FZN_PERSIST_OWN_PREKEY,
			                                     FZN_PERSIST_PEER,
			                                     FZN_PERSIST_SEND_CHAIN,
			                                     FZN_PERSIST_RECV_CHAIN };

		for (i = 0; i < 5u; i++) {
			persist_rows[i].slot = slots[i];
			persist_rows[i].err = FZN_PERSIST_OK;
			persist_rows[i].had_stored = 1;
		}
		persist_rows[0].err = FZN_PERSIST_ERR_ABSENT;
		persist_v.show_slots(persist_rows, 5u);
	}

	/* THE FOUR sec 187 LEFT UNDRAWN, and each was a fixture cost rather
	 * than a reason -- which is only worth saying if the cost is then
	 * paid. sec 190. */
	{
		static uint8_t present[FZN_SPOOL_BITMAP_LEN(16u)];
		static fzn_transfer_assign_t assigns[2];
		static fzn_spool_ops_t spool_ops;
		static uint8_t spool_root[FZN_BLOB_HASH_LEN];
		fzn_spool_t spool;
		fzn_transfer_t xfer;

		memset(present, 0, sizeof(present));
		memset(spool_root, 0xd1, sizeof(spool_root));
		present[0] |= 1u; /* one leaf held, so the state is STALLED */
		spool_ops.read_at = no_read;
		spool_ops.write_at = no_write;
		spool_ops.sync = no_sync_op;
		spool_ops.ctx = NULL;

		if (fzn_spool_open(&spool, spool_root, 16u, present, sizeof(present),
		                   &spool_ops) == FZN_SPOOL_OK &&
		    fzn_transfer_open(&xfer, &spool, assigns, 2u) == FZN_TRANSFER_OK)
			transfer.show_transfer(&spool, &xfer, 100u);
	}

	{
		static fzn_state_entry_t cells[2];
		fzn_state_t st;
		fzn_record_t rec;

		/* Set a cell and clear it, so the widget is in the state it
		 * exists for -- CLEARED, which fzn_state_get cannot report. */
		if (fzn_state_init(&st, cells, 2u) == FZN_STATE_OK &&
		    make(&rec, 6u, 1u, (const uint8_t *)"on", 2u) &&
		    fzn_state_apply(&st, &rec) == FZN_STATE_OK &&
		    make(&rec, 7u, 2u, NULL, 0) &&
		    fzn_state_clear(&st, &rec) == FZN_STATE_OK)
			state_v.show_cell(&st, SUBJECT, 3u);
	}

	{
		/* ONE MEASURED LINK AND ONE THAT IS STILL A CLAIM, which is the
		 * pair sec 202 is about: the terminal has to keep them apart in
		 * a row, and a column-aligned table is exactly the thing a
		 * character grid can lose. */
		if (fzn_link_table_init(&links, link_entries, 4u) == FZN_LINK_OK &&
		    fzn_link_register(&links, 1u, 10u, 40u, 0u, 1200u) == FZN_LINK_OK &&
		    fzn_link_register(&links, 2u, 20u, 90u, 25u, 1200u) == FZN_LINK_OK &&
		    fzn_link_observe_ack(&links, 1u, 40u, 1000u) == FZN_LINK_OK)
			link_v.show_links(&links);
	}

	{
		/* A PEER WHOSE GROUPS COULD NOT BE READ, so the word the
		 * terminal has to carry is the tri-state's third one. sec 204:
		 * if `cannot tell` does not survive the grid, the distinction
		 * peer.h spent a module on is gone at the last inch. */
		static const uint8_t DESTROY[] = "destroy";
		static const fzn_verb_rule_t rules[] = {
			{ 99u, DESTROY, sizeof(DESTROY) - 1u },
		};

		memset(&asker, 0, sizeof(asker));
		asker.pid = 4021;
		asker.uid = 1000u;
		asker.primary_gid = 1000u;
		asker.groups_known = 0;
		peer_v.show_peer(&asker, DESTROY, sizeof(DESTROY) - 1u, rules, 1u);
	}

	{
		/* NO CARD, which is the one provisioning state that needs no
		 * signer. Its signed states are its own suite's business; what
		 * is asked here is only whether this widget's words reach a
		 * grid at all -- and until now they were never asked, because
		 * `provision_view.h` was included by this file and no
		 * `fzn_provision_view` was ever built. */
		provision.show_card(nullptr, 0u, nullptr, 0u);
	}

	{
		fzn_cli_t cli;

		/* A SPELLED config. The unspelled one was tried first and
		 * renders NOTHING -- which is how the row-label finding below
		 * was found, since an empty form is all label and no value. */
		fzn_cli_init(&cli);
		cli.dir = "/var/lib/fuzznet";
		cli.service = 7u;
		config.show_config(&cli);
	}

	{
		const struct terminal_case cases[] = {
			{ "authz_view", &authz, "UNGUARDED" },
			/* sec 207: the answer, on the widget that carries a
			 * 64-character capability ahead of it. */
			{ "authz_view (guarded)", &authz_guarded, "reachable from" },
			{ "capability_view", &capability, "expired" },
			{ "sweep_view", &sweep, "needs more replicas" },
			{ "revocation_view", &revocation, "work again" },
			{ "journal_view", &journal_v, "nothing received" },
			{ "sync_view", &sync, "cannot say" },
			{ "transfer_view", &transfer, "STALLED" },
			{ "state_view", &state_v, "taken back" },
			/* A LABEL RATHER THAN A VALUE, because an unspelled config has
			 * no values -- that is its point. This asks whether the
			 * form's structure survives a terminal, which is the
			 * question for a widget made of rows. */
			{ "config_view", &config, "/var/lib/fuzznet" },
			/* THE MARKER ON A ROW, not the summary above it. sec
			 * 202's whole claim is that the row says WHICH link is
			 * still a stranger's word, so that is the string a
			 * terminal has to carry. */
			{ "link_view", &link_v, "declared" },
			/* THE THIRD VALUE OF THE TRI-STATE. sec 204. */
			{ "peer_view", &peer_v, "cannot tell" },
			{ "provision_view", &provision, "no card" },
			/* THE FLOOR, NOT THE COUNT. sec 226: a host that
			 * reports less than it is missing is the one reading
			 * this widget has to survive a terminal for, and the
			 * summary is where it says so. */
			{ "manifest_view", &manifest_v, "less than they are missing" },
			/* THE SENTENCE THAT VOIDS THE SCREEN. sec 228. */
			{ "ledger_view", &ledger_v, "nothing here is evidence" },
			/* THE ONE WITH NO FIX TO NAME. sec 247: every other line
			 * this printer draws points at a bound, and this one
			 * exists to say that pointing at any of them would be
			 * wrong. The substring is short on purpose -- the whole
			 * line is 79 characters and the label wraps, so a
			 * phrase near its end could be folded. */
			{ "sched_view", &sched_v, "no single change" },
			/* THE LOSS AMONG THE RECOVERIES. sec 254: a person
			 * scanning five rows reads the first sentence and
			 * stops, so the summary has to be about the one slot
			 * that is gone. */
			{ "persist_view", &persist_v, "did not come back" },
		};

		for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
			const QString want = QString::fromLatin1(cases[i].must_show);
			int floor_cols;

			char msg[192];

			/* THE MESSAGE NAMES THE WIDGET AND THE STRING. Without
			 * it a failure here says only that one of a dozen
			 * widgets is wrong, and the reader has to bisect the
			 * table to find out which -- the same complaint the
			 * style gate makes about a sabotage failure nobody can
			 * attribute. Two of these fired at once when the sweep
			 * was first repaired and neither said whose. */
			snprintf(msg, sizeof(msg),
			         "%s does not say \"%s\" on an 80x24 terminal",
			         cases[i].name, cases[i].must_show);
			/* THE SCREEN ITSELF ON A FAILURE. A render test that
			 * says only "the word is not there" leaves the reader
			 * to rebuild the terminal by hand; this is how
			 * capability_view's clipped verdict was found rather
			 * than guessed at. */
			if (!rendered(*cases[i].widget, 80, 24).contains(want))
				fprintf(stderr, "---- %s at 80x24 ----\n%s\n----\n",
				        cases[i].name,
				        rendered(*cases[i].widget, 80, 24).toLatin1().constData());
			check_at(rendered(*cases[i].widget, 80, 24).contains(want), __LINE__,
			         msg);

			floor_cols = narrowest(*cases[i].widget, cases[i].must_show);
			snprintf(msg, sizeof(msg),
			         "%s shows \"%s\" at no width up to 120 columns",
			         cases[i].name, cases[i].must_show);
			check_at(floor_cols > 0, __LINE__, msg);
			printf("  %-18s needs %d columns to say \"%s\"\n", cases[i].name,
			       floor_cols, cases[i].must_show);
		}

		/* DO QFormLayout's OWN ROW LABELS REACH THE GRID? Every widget
		 * here is built of `addRow(text, widget)`, and every assertion
		 * above matches a VALUE. config_view has no values in its
		 * unspelled state, so it is the one that asks this question --
		 * and it renders nothing. */
		{
			const QString snap = rendered(authz, 80, 24);

			/* PINNED AS MEASURED, NOT AS WANTED. Every widget here
			 * is built of `addRow(text, widget)`, and qtty renders
			 * the VALUE and not the row label -- so on a terminal
			 * these objects show their answers with nothing saying
			 * what each answer is about. Reported to qtty; the
			 * assertion is written the way the world IS so that it
			 * goes red when they fix it, which is the notice this
			 * tree wants rather than a silent improvement. */
			check_at(snap.contains(QStringLiteral("UNGUARDED")), __LINE__,
			         "a form's value does not reach the grid");
			check_at(!snap.contains(QStringLiteral("Requires")), __LINE__,
			         "a form's ROW LABEL now reaches the grid -- qtty has "
			         "changed, and every widget here can stop working around "
			         "it: see project.md sec 190");
		}
	}
}

int main(int argc, char **argv)
{
	fzn_trust_t trust;
	uint8_t root[FZN_PUBKEY_LEN];
	int cols;

	qputenv("QT_QPA_PLATFORM", "offscreen");
	QApplication app(argc, argv);

	memset(root, 0xa7, sizeof(root));
	fzn_trust_init(&trust);
	CHECK(fzn_trust_pin(&trust, root) == FZN_TRUST_OK, "the fixture could not pin");

	/* THE CASE THIS FILE EXISTS FOR. Every width from the floor up must
	 * show every hex digit. 76 to 80 is where they were being lost, and 80
	 * is the width a terminal is by default. */
	{
		int lost = 0;

		for (cols = 41; cols <= 96; cols++) {
			fzn_trust_view view;

			view.show_anchor(&trust);
			if (!lines_on_screen(rendered(view, cols, 12),
			                     view.fingerprint_text())) {
				char msg[128];

				snprintf(msg, sizeof(msg),
				         "a fingerprint line is not on the screen whole at "
				         "%d columns", cols);
				check_at(0, __LINE__, msg);
				lost = 1;
				break;
			}
			checks++;
		}
		/* AND THE SWEEP MUST HAVE RUN. A loop that stopped at the first
		 * width would report one silent pass, which is the vacuous pass
		 * this whole file exists to refuse. */
		CHECK(!lost && cols == 97,
		      "the width sweep did not reach 96 columns, so its passes cover less "
		      "than they appear to");
	}

	/* AND THE FORMAT DOES NOT MOVE. The same fingerprint must occupy the
	 * same number of lines whatever the terminal is, or a user comparing
	 * two screens is comparing two arrangements. */
	{
		fzn_trust_view a;
		fzn_trust_view b;
		QString wide;
		QString narrow;

		a.show_anchor(&trust);
		b.show_anchor(&trust);
		wide = rendered(a, 96, 12);
		narrow = rendered(b, 44, 12);
		CHECK(wide.count(QLatin1Char('\n')) == narrow.count(QLatin1Char('\n')),
		      "the fingerprint occupies different line counts at two widths, so its "
		      "format still moves with the window");
	}

	/* THE LOG VIEW FITS A SMALL TERMINAL. qtty's sec 16 finding is that a
	 * resize below minimumSizeHint is refused and the content overflows
	 * rather than compacting, so a widget whose minimum is large is one a
	 * terminal cannot show at all. */
	{
		fzn_log_view view;
		QSize minimum;
		int wide_cells;
		int tall_cells;

		(void)rendered(view, 60, 10);
		minimum = view.minimumSizeHint();
		wide_cells = (minimum.width() + Qtty::GridMetrics::cw() - 1) /
		             Qtty::GridMetrics::cw();
		tall_cells = (minimum.height() + Qtty::GridMetrics::ch() - 1) /
		             Qtty::GridMetrics::ch();
		CHECK(wide_cells <= 40 && tall_cells <= 12,
		      "the log view's minimum does not fit a 40x12 terminal, so a small "
		      "terminal cannot lay it out at all");
	}

	{
		fzn_trust_view view;
		QSize minimum;

		(void)rendered(view, 60, 10);
		minimum = view.minimumSizeHint();
		CHECK((minimum.width() + Qtty::GridMetrics::cw() - 1) / Qtty::GridMetrics::cw() <=
		              40,
		      "the trust view's minimum does not fit a 40-column terminal");
	}

	/*
	 * THE LOG VIEW DRAWS NO BORDER, AND ITS ENTRIES ARE CONSECUTIVE.
	 * sec 159.
	 *
	 * TWO ASSERTIONS AND ONLY ONE OF THEM GUARDS THE FIX, which is worth
	 * saying because the first version of this case had it the other way
	 * round and did not notice.
	 *
	 * The border one is the guard: `setFrameShape(NoFrame)` is what this
	 * widget does about a frame qtty renders as a left edge and nothing
	 * else, and putting the frame back turns exactly this red.
	 *
	 * The consecutive-rows one is NOT a guard for that -- it passes with
	 * the frame and without it. It was written believing the frame
	 * double-spaced the entries; it does, with a PROPORTIONAL font, and
	 * this widget has set a monospace hint since sec 141. It is kept
	 * because consecutive entries are a property worth holding on their
	 * own, and labelled because a reader would otherwise take it for the
	 * frame's guard and be wrong the way its author was.
	 */
	{
		fzn_log_view view;
		fzn_log_entry_t rows[4];
		fzn_journal_entry_t positions[2];
		fzn_log_t log;
		fzn_journal_t journal;
		fzn_record_t rec;
		QStringList screen;
		uint64_t seq;
		int first = -1;
		int seen = 0;
		int consecutive = 1;

		memset(ISSUER, 0x11, sizeof(ISSUER));
		memset(SUBJECT, 0x51, sizeof(SUBJECT));
		CHECK(fzn_log_init(&log, rows, 4) == FZN_LOG_OK, "the log would not init");
		CHECK(fzn_journal_init(&journal, positions, 2) == FZN_JOURNAL_OK,
		      "the journal would not init");
		CHECK(fzn_journal_anchor(&journal, ISSUER, 5u, 0u) == FZN_JOURNAL_OK,
		      "the stream could not be followed");
		for (seq = 1u; seq <= 3u; seq++) {
			const uint8_t body[3] = { 'a', (uint8_t)('0' + seq), 'z' };

			CHECK(make(&rec, (size_t)seq, seq, body, sizeof(body)),
			      "the fixture could not build a record");
			CHECK(fzn_log_append(&log, &rec) == FZN_LOG_OK, "append refused");
			CHECK(fzn_journal_admit(&journal, ISSUER, 5u, seq) == FZN_JOURNAL_OK,
			      "the journal refused the record");
		}
		view.show_stream(&log, &journal, ISSUER, 5u);

		screen = rendered(view, 60, 12).split(QLatin1Char('\n'));
		for (int row = 0; row < screen.size(); row++) {
			if (!screen[row].contains(QLatin1String("a1z")) &&
			    !screen[row].contains(QLatin1String("a2z")) &&
			    !screen[row].contains(QLatin1String("a3z")))
				continue;
			if (first < 0)
				first = row;
			else if (row != first + seen)
				consecutive = 0;
			seen++;
		}
		/* THE GUARD: no box-drawing anywhere in the render. A border
		 * that draws one of its four sides is worse than none, and this
		 * is what putting the frame back breaks. */
		{
			QString flat = screen.join(QLatin1Char(' '));

			CHECK(!flat.contains(QChar(0x250C)) && !flat.contains(QChar(0x2514)) &&
			              !flat.contains(QChar(0x2502)),
			      "the log view drew a box-drawing character, so it is asking "
			      "for a frame qtty renders as a left edge and nothing else");
		}

		CHECK(seen == 3, "not every log entry reached the screen");
		CHECK(consecutive,
		      "the log entries are spread over more rows than they occupy, so a "
		      "reader sees fewer of them than the terminal has room for");
	}

	/*
	 * A QR CODE ON A CHARACTER CELL GRID. sec 161.
	 *
	 * THE CELL IS NOT SQUARE -- 8 by 16 here -- so a module painted one
	 * cell each way arrives at a scanner stretched two to one, and a
	 * stretched code is one a decoder may refuse. `fzn_qr_view` paints
	 * squares in PIXELS, so at two cells per module horizontally and one
	 * vertically the result is square on screen. This is the assertion
	 * that the arithmetic came out.
	 *
	 * READ FROM THE COLOUR LAYER, because the code is drawn as filled
	 * rectangles and carries no glyphs at all: the glyph half of the
	 * snapshot is blank, which is how the first probe here concluded
	 * nothing had rendered.
	 */
	{
		fzn_qr_view view;
		int across;
		int cols;
		int rows;
		QString snap;
		QStringList colours;
		int at;

		view.show_text(QStringLiteral("HELLO WORLD"), FZN_QR_LEVEL_L);
		CHECK(view.modules_across() == 21, "the fixture is not a version-1 code");
		across = view.modules_across() + 2 * (int)FZN_QR_QUIET;
		cols = across * 2;
		rows = across;

		view.setAttribute(Qt::WA_DontShowOnScreen);
		view.resize(Qtty::GridMetrics::cells(cols, rows));
		view.show();
		QCoreApplication::processEvents();
		snap = Qtty::test::snapshot_of(view, cols, rows);

		CHECK(snap.contains(QStringLiteral("--- colours ---")),
		      "the snapshot carries no colour layer, so nothing can be read back");
		colours = snap.section(QStringLiteral("--- colours ---"), 1)
		                  .section(QStringLiteral("--- legend"), 0, 0)
		                  .split(QLatin1Char('\n'));

		/* The top-left finder's first row is seven dark modules, which
		 * at two cells a module is fourteen identical cells -- and the
		 * four quiet modules before it are eight. */
		at = -1;
		for (int i = 0; i < colours.size(); i++) {
			const QString &row = colours[i];

			if (row.contains(QStringLiteral("aaaaaaaaaaaaaa"))) {
				at = i;
				break;
			}
		}
		CHECK(at >= 0,
		      "no row of fourteen identical cells, so a module is not two cells "
		      "wide and the code is not square on screen");
		if (at >= 0) {
			CHECK(colours[at].indexOf(QLatin1Char('a')) == 2 * (int)FZN_QR_QUIET,
			      "the finder does not begin after four quiet modules, so the "
			      "quiet zone is the wrong width");
			/* And the row below it is the finder's second row: dark,
			 * five light, dark -- two cells each. */
			CHECK(at + 1 < colours.size() &&
			              colours[at + 1].contains(QStringLiteral("aa..........aa")),
			      "the finder's second row is not a ring, so the modules are not "
			      "landing on cell boundaries");
		}
	}

#ifdef FZN_HAVE_QUIRC
	/*
	 * THE LOOP CLOSED: widget, terminal, independent decoder. sec 162.
	 *
	 * Everything above asserts SHAPE, and sec 160 is the standing reminder
	 * that a QR code can satisfy every shape assertion and decode as
	 * nothing. This renders the widget onto a character grid, rebuilds the
	 * pixels a terminal would actually show, and hands them to quirc.
	 *
	 * NO ASSUMPTION ABOUT MODULE SIZE. Each CELL becomes its own rectangle
	 * of the reconstructed screen, so nothing here encodes how many cells a
	 * module is meant to be -- if the widget got that wrong, the picture is
	 * wrong and the decode fails, which is the point.
	 *
	 * AND THE STRETCHED CASE IS THE CONTROL. At one cell per module the
	 * code is twice as tall as it is wide, and quirc finds no code at all.
	 * That is what makes the square-module design a measurement rather than
	 * a reasonable-sounding claim, and it is why the pass above means
	 * something.
	 */
	{
		fzn_qr_view view;
		const char *want = "HELLO WORLD";
		int across;
		int wide;
		int narrow;

		view.show_text(QString::fromLatin1(want), FZN_QR_LEVEL_L);
		across = view.modules_across() + 2 * (int)FZN_QR_QUIET;

		wide = decodes_off_a_terminal(view, across * 2, across, want);
		narrow = decodes_off_a_terminal(view, across, across, want);

		CHECK(wide == 1,
		      "a QR code rendered two cells to a module did not decode off the "
		      "terminal, so the widget draws something a scanner cannot read");
		CHECK(narrow == 0,
		      "a QR code rendered ONE cell to a module decoded anyway, so the "
		      "control cannot fail and the square-module design is untested");
	}
#endif

	test_every_widget_survives_a_terminal();

	/* The suite can tell pass from fail. */
	{
		int before = failures;

		check_at(0, __LINE__, "deliberate");
		CHECK(failures == before + 1, "a failing check was not counted");
		failures = before;
		checks -= 1;
	}

	printf("qtty_render_test: %d checks, %d failure(s)\n", checks, failures);
	return failures == 0 ? 0 : 1;
}
