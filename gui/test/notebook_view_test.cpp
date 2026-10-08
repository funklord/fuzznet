/* Tests for gui/notebook_view.cpp, headless. sec 439.
 *
 * THE NODE IS REAL AND IN-PROCESS: the widget's ask callback splits the line
 * as a local client's reaches a node and hands it to `fzn_node_notes_local`
 * over `persist/`'s seam in memory, so every verb the widget speaks is the
 * one `node/notes.c` answers. Only `list received` -- an admin verb -- is
 * answered here, from a string the case sets.
 *
 * WHAT IT IS FOR is the three things the widget carries from fuzzypickles:
 * a node that does not answer is said rather than shown as an empty
 * notebook; the un-share warning is on screen before anybody shares; and a
 * refresh keeps the reader's place.
 */

extern "C" {
#include "../../node/notes.h"
#include "../../contact/contact.h"
#include "../../contact/group.h"
#include "../../notes/received.h"
#include "../../notes/text.h"
#include "../../notes/test/blob_stub.h"
#include "../../notes/test/chain_stub.h"
#include "../../local/vocabulary.h"
}

#include "../notebook_view.h"

#include <QApplication>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QScrollBar>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int failures;
static int checks;

static void check_at(int ok, int line, const char *what)
{
	checks++;
	if (ok)
		return;
	failures++;
	fprintf(stderr, "  FAIL notebook_view_test.cpp:%d: %s\n", line, what);
}

#define CHECK(cond, what) check_at((cond) ? 1 : 0, __LINE__, what)

/* ---- a hash, a toy signer, and randomness --------------------------------- */

static void fnv(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len, uint8_t *out,
                size_t out_len)
{
	uint64_t h = 0xcbf29ce484222325ull;
	size_t i;

	for (i = 0; i < a_len; i++) {
		h ^= a[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < b_len; i++) {
		h ^= b[i];
		h *= 0x100000001b3ull;
	}
	for (i = 0; i < out_len; i++) {
		h ^= (uint64_t)i + 0x9e3779b97f4a7c15ull;
		h *= 0x100000001b3ull;
		out[i] = (uint8_t)(h >> 32);
	}
}

static int stub_hash(void *ctx, uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len)
{
	(void)ctx;
	fnv(in, in_len, NULL, 0, out, out_len);
	return 1;
}

static const fzn_hash_ops_t HASH = { stub_hash, NULL };

static uint8_t SELF[FZN_PUBKEY_LEN];

static int toy_sign(void *ctx, uint8_t sig[FZN_SIG_LEN], const uint8_t *msg, size_t msg_len)
{
	fnv((const uint8_t *)ctx, FZN_PUBKEY_LEN, msg, msg_len, sig, FZN_SIG_LEN);
	return 1;
}

static int toy_verify(void *ctx, const uint8_t pubkey[FZN_PUBKEY_LEN], const uint8_t *msg,
                      size_t msg_len, const uint8_t sig[FZN_SIG_LEN])
{
	uint8_t want[FZN_SIG_LEN];

	(void)ctx;
	fnv(pubkey, FZN_PUBKEY_LEN, msg, msg_len, want, sizeof(want));
	return memcmp(want, sig, FZN_SIG_LEN) == 0;
}

static fzn_sign_ops_t SIGN = { toy_verify, toy_sign, SELF };

static uint64_t counter = 11;

static int counter_fill(void *ctx, uint8_t *out, size_t len)
{
	size_t i;

	(void)ctx;
	for (i = 0; i < len; i++)
		out[i] = (uint8_t)((counter * 131u + i * 7u) >> (i % 5u));
	counter++;
	return 1;
}

static const fzn_random_ops_t RNG = { counter_fill, NULL };

static uint64_t clock_ms = 1000;

static uint64_t now_ms(void)
{
	return clock_ms++;
}

/* ---- a persist backend over memory -------------------------------------- */

#define MEM_ROWS 128u

struct row {
	int used;
	fzn_persist_slot_t slot;
	int has_subject;
	uint8_t subject[FZN_PUBKEY_LEN];
	uint8_t bytes[FZN_PERSIST_HEAD_LEN + (2u * FZN_PUBKEY_LEN) + FZN_RECORD_MAX_LEN];
	size_t len;
};

static struct row rows[MEM_ROWS];

static struct row *find_row(fzn_persist_slot_t slot, const uint8_t *subject)
{
	size_t i;

	for (i = 0; i < MEM_ROWS; i++)
		if (rows[i].used && rows[i].slot == slot && rows[i].has_subject == (subject != NULL)
		    && (!subject || memcmp(rows[i].subject, subject, FZN_PUBKEY_LEN) == 0))
			return &rows[i];
	return NULL;
}

static int mem_load(void *ctx, fzn_persist_slot_t slot, const uint8_t *subject, uint8_t *out,
                    size_t cap, size_t *len)
{
	struct row *r = find_row(slot, subject);

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
	struct row *r = find_row(slot, subject);
	size_t i;

	(void)ctx;
	for (i = 0; !r && i < MEM_ROWS; i++)
		if (!rows[i].used)
			r = &rows[i];
	if (!r || len > sizeof(r->bytes))
		return 0;
	r->used = 1;
	r->slot = slot;
	r->has_subject = subject != NULL;
	if (subject)
		memcpy(r->subject, subject, FZN_PUBKEY_LEN);
	memcpy(r->bytes, bytes, len);
	r->len = len;
	return 1;
}

static int mem_list(void *ctx, fzn_persist_slot_t slot, uint8_t *out, size_t max, size_t *count)
{
	size_t i, n = 0;

	(void)ctx;
	for (i = 0; i < MEM_ROWS; i++)
		if (rows[i].used && rows[i].slot == slot && rows[i].has_subject) {
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
	struct row *r = find_row(slot, subject);

	(void)ctx;
	if (r)
		r->used = 0;
	return 1;
}

static fzn_persist_ops_t OPS = { mem_load, mem_save, mem_list, mem_remove, NULL };

/* ---- the node, asked as the widget asks it ------------------------------ */

static fzn_node_notes_t notes;
static int quiet;            /* the node does not answer */
static const char *received; /* the `list received` reply, or NULL for none */
static unsigned asked;

/* `list contact`, as admin answers it, from the contacts in the store -- a
 * contact named `gone` marked suspended, as the roster would mark one
 * removed on another member (sec 489). */
static size_t list_contacts(char *reply, size_t cap)
{
	static fzn_contact_t all[FZN_CONTACTS_MAX];
	size_t count = 0, i, used;
	int n;

	if (fzn_contact_list(&OPS, all, FZN_CONTACTS_MAX, &count) != FZN_CONTACT_OK)
		return 0;
	n = snprintf(reply, cap, "ok %zu 0", count);
	used = n > 0 ? (size_t)n : 0u;
	for (i = 0; i < count && used < cap; i++) {
		n = snprintf(reply + used, cap - used, " %s,00%s", all[i].name,
		             strcmp(all[i].name, "gone") ? "" : ",suspended");
		used += n > 0 ? (size_t)n : 0u;
	}
	if (used + 1u < cap)
		reply[used++] = '\n';
	return used;
}

/* `list group`, as admin answers it. */
static size_t list_groups(char *reply, size_t cap)
{
	static fzn_group_t all[FZN_GROUPS_MAX];
	size_t count = 0, i, used;
	int n;

	if (fzn_group_list(&OPS, all, FZN_GROUPS_MAX, &count) != FZN_CONTACT_OK)
		return 0;
	n = snprintf(reply, cap, "ok %zu 0", count);
	used = n > 0 ? (size_t)n : 0u;
	for (i = 0; i < count && used < cap; i++) {
		n = snprintf(reply + used, cap - used, " %s,%zu", all[i].name, all[i].count);
		used += n > 0 ? (size_t)n : 0u;
	}
	if (used + 1u < cap)
		reply[used++] = '\n';
	return used;
}

static size_t node_ask(void *ctx, const char *line, char *reply, size_t cap)
{
	fzn_request_t request;
	size_t n;

	(void)ctx;
	asked++;
	if (quiet)
		return 0;
	if (!strcmp(line, "list received"))
		return (size_t)snprintf(reply, cap, "%s\n", received ? received : "ok 0");
	if (!strcmp(line, "list contact"))
		return list_contacts(reply, cap);
	if (!strcmp(line, "list group"))
		return list_groups(reply, cap);
	memset(&request, 0, sizeof(request));
	if (!fzn_vocabulary_split((const uint8_t *)line, strlen(line), &request))
		return (size_t)snprintf(reply, cap, "malformed\n");
	n = fzn_node_notes_local(&notes, FZN_ORIGIN_SAME_USER, &request, reply, cap);
	return n ? n : (size_t)snprintf(reply, cap, "unsupported\n");
}

static void setup(void)
{
	memset(rows, 0, sizeof(rows));
	CHECK(fzn_node_notes_init(&notes, &OPS, &HASH, &SIGN, &RNG, SELF, NULL, 0u, NULL, 0u,
	                          now_ms)
	              == FZN_NOTES_OK,
	      "fixture: the node's notes open");
	notes.seal = blob_stub_seal;
	notes.open = blob_stub_open;
	notes.chain = chain_stub_chain;
	quiet = 0;
	received = NULL;
}

static int index_of(const QStringList &ids, const QString &id)
{
	return ids.indexOf(id);
}

/* ---- cases --------------------------------------------------------------- */

static void test_an_empty_notebook_and_a_silent_node_read_differently(void)
{
	setup();
	{
		fzn_notebook_view w(node_ask, nullptr);

		CHECK(w.list()->count() == 0 && w.status().contains(QStringLiteral("Nothing here")),
		      "an empty notebook says there is nothing here");
		quiet = 1;
		w.refresh();
		CHECK(w.status().contains(QStringLiteral("did not answer")),
		      "a node that does not answer says so, rather than showing an empty notebook");
		CHECK(!w.status().contains(QStringLiteral("Nothing here")),
		      "and the two never share words");
	}
}

static void test_notes_are_made_saved_and_read_back(void)
{
	QString folder, note;
	QStringList ids;

	setup();
	fzn_notebook_view w(node_ask, nullptr);
	QStringList log;

	w.set_log([&log](const QString &l) { log << l; });
	CHECK(w.new_folder(QStringLiteral("Recipes")), "a folder is made");
	CHECK(w.list()->count() == 1 && w.list()->item(0)->text() == QStringLiteral("Recipes/"),
	      "and listed as a folder");
	folder = w.listed_ids().value(0);
	CHECK(w.descend(folder, QStringLiteral("Recipes")) && w.location() == QStringLiteral("Recipes"),
	      "the folder opens, and the location says where");
	CHECK(w.status().contains(QStringLiteral("Nothing here")), "an empty folder says so");
	CHECK(w.new_note(QStringLiteral("Bread")) && w.title_text() == QStringLiteral("Bread"),
	      "a note is made in it and opened");
	note = w.open_id();
	CHECK(w.editable(), "this user's own note can be edited");
	/* SAVED THROUGH A FILE: newlines, and more than one request line. */
	{
		QString text = QStringLiteral("flour, water, salt\n");
		int i;

		for (i = 0; i < 40; i++)
			text += QStringLiteral("knead and wait, line %1\n").arg(i);
		w.findChild<QPlainTextEdit *>()->setPlainText(text);
		CHECK(w.save(), "a text of several lines, past one request line, is saved");
		w.findChild<QPlainTextEdit *>()->clear();
		CHECK(w.open_note(note) && w.body_text() == text, "and reads back whole");
	}
	CHECK(w.ascend() && w.location() == QStringLiteral("/"), "back up to the top");
	CHECK(!w.ascend(), "and no further");
	CHECK(log.contains(QStringLiteral("Saved.")), "the log is told what was saved");
	ids = w.listed_ids();
	CHECK(index_of(ids, folder) == 0 && index_of(ids, note) < 0,
	      "the top lists the folder and not the note inside it");
}

static void test_the_trash_is_its_own_view(void)
{
	QString a, b;

	setup();
	fzn_notebook_view w(node_ask, nullptr);

	CHECK(w.new_note(QStringLiteral("keep")), "fixture: a note to keep");
	a = w.open_id();
	CHECK(w.new_note(QStringLiteral("bin")), "fixture: a note to bin");
	b = w.open_id();
	CHECK(w.trash() && w.open_id().isEmpty(), "the open note goes to the trash");
	CHECK(index_of(w.listed_ids(), b) < 0 && index_of(w.listed_ids(), a) >= 0,
	      "and leaves the notebook's list");
	w.show_trash(true);
	CHECK(w.listed_ids() == QStringList{ b }, "the trash lists only what was trashed");
	CHECK(w.open_note(b) && w.restore(), "a trashed note is restored");
	CHECK(w.status().contains(QStringLiteral("trash is empty")), "and the trash says it is empty");
	w.show_trash(false);
	CHECK(index_of(w.listed_ids(), b) >= 0, "the restored note is back in the notebook");
	CHECK(w.open_note(b) && w.trash() && w.empty_trash(), "trashed again and emptied");
	w.show_trash(true);
	CHECK(w.list()->count() == 0, "with no other node to ask, it is gone at once");
}

static void test_sharing_is_warned_before_and_said_after(void)
{
	uint8_t carol[FZN_PUBKEY_LEN];
	QString note;
	QStringList log;

	setup();
	memset(carol, 0xc4, sizeof(carol));
	CHECK(fzn_contact_add(&OPS, carol, "carol", 5u, 1u) == FZN_CONTACT_OK,
	      "fixture: the contact carol");
	fzn_notebook_view w(node_ask, nullptr);

	w.set_log([&log](const QString &l) { log << l; });
	CHECK(w.warning().contains(QStringLiteral("stays with them")),
	      "the un-share warning is on screen before anybody shares");
	CHECK(w.new_folder(QStringLiteral("trip")), "fixture: a folder");
	note = w.listed_ids().value(0);
	CHECK(w.open_note(note) && w.shared_with() == QStringLiteral("Not shared."),
	      "an unshared folder says so");
	CHECK(w.share_with(QStringLiteral("carol"))
	              && w.shared_with() == QStringLiteral("Shared with carol."),
	      "shared, and the widget says with whom");
	CHECK(!w.share_with(QStringLiteral("nobody")), "a name that is no contact is refused");
	CHECK(w.unshare_with(QStringLiteral("carol"))
	              && w.shared_with() == QStringLiteral("Not shared.")
	              && log.last().contains(QStringLiteral("stays with them")),
	      "unshared, and told again what stays");

	/* A GROUP, sec 471: offered as `@NAME` beside the contacts. And a
	 * contact the roster marks suspended, sec 489, not offered at all. */
	memset(carol, 0x9e, sizeof(carol));
	CHECK(fzn_group_add(&OPS, &RNG, "family", 6u, 1u) == FZN_CONTACT_OK
	              && fzn_contact_add(&OPS, carol, "gone", 4u, 1u) == FZN_CONTACT_OK,
	      "fixture: the group family, and the suspended contact gone");
	CHECK(w.open_note(note)
	              && w.share_targets()
	                         == QStringList({ QStringLiteral("carol"), QStringLiteral("@family") }),
	      "the share chooser offers the contact and then the group, and not the suspended "
	      "one");
	CHECK(w.share_with(QStringLiteral("@family"))
	              && w.shared_with() == QStringLiteral("Shared with @family."),
	      "shared with the group, and the widget says so by its name");
	CHECK(w.unshare_with(QStringLiteral("@family"))
	              && w.shared_with() == QStringLiteral("Not shared."),
	      "and unshared");
}

static void test_a_shared_tree_reads_and_cannot_be_written(void)
{
	uint8_t carol[FZN_PUBKEY_LEN], gid[FZN_TREE_ID_LEN];
	uint8_t record[FZN_RECORD_MAX_LEN];
	fzn_notes_received_t seam;
	fzn_persist_ops_t ops;
	fzn_notes_store_t tree;
	QString f, g;
	size_t len = 0;
	int wrote = 0, i;

	setup();
	memset(carol, 0xc4, sizeof(carol));
	CHECK(fzn_contact_add(&OPS, carol, "carol", 5u, 1u) == FZN_CONTACT_OK,
	      "fixture: the contact carol");
	{
		fzn_notebook_view own(node_ask, nullptr);

		CHECK(own.new_folder(QStringLiteral("hers")), "fixture: F");
		f = own.listed_ids().value(0);
		CHECK(own.descend(f, QStringLiteral("hers")) && own.new_note(QStringLiteral("shared")),
		      "fixture: G under F");
		g = own.open_id();
	}
	/* G INTO CAROL'S TREE, as a pull of a share of G would file it. */
	for (i = 0; i < (int)FZN_TREE_ID_LEN; i++)
		gid[i] = (uint8_t)g.mid(2 * i, 2).toUInt(nullptr, 16);
	CHECK(fzn_notes_received_ops(&seam, &OPS, &HASH, carol, &ops) == FZN_NOTES_OK
	              && fzn_notes_store_init(&tree, &ops, &HASH) == FZN_NOTES_OK
	              && fzn_notes_get(&notes.store, gid, SELF, record, sizeof(record), &len)
	                         == FZN_NOTES_OK
	              && fzn_notes_put(&tree, record, len, notes.author.policy, &SIGN, &wrote,
	                               nullptr)
	                         == FZN_NOTES_OK,
	      "fixture: G in carol's tree");
	/* AND ITS WRAP KEY, sec 520, as carol's node would give it. */
	{
		uint8_t key[FZN_NOTE_WRAP_KEY_LEN];

		CHECK(fzn_notes_wrap_get(&notes.store, gid, key) == FZN_NOTES_OK
		              && fzn_notes_wrap_put(&tree, gid, key) == FZN_NOTES_OK,
		      "fixture: G's wrap key in carol's tree");
	}
	received = "ok 1 carol,127.0.0.1,7000";
	fzn_notebook_view w(node_ask, nullptr);

	CHECK(w.open_tree(QStringLiteral("carol")), "carol's tree opens");
	CHECK(w.listed_ids() == QStringList{ g }, "its top is what she shared, not this user's F");
	CHECK(w.open_note(g) && w.title_text() == QStringLiteral("shared"), "the note reads");
	CHECK(!w.editable() && w.warning().isEmpty(), "and nothing in carol's tree is editable");
	CHECK(!w.new_note(QStringLiteral("x")) && !w.save() && !w.trash()
	              && !w.share_with(QStringLiteral("carol")),
	      "no action writes to it");
	CHECK(w.open_tree(QString()) && index_of(w.listed_ids(), f) >= 0
	              && index_of(w.listed_ids(), g) < 0,
	      "back in this user's own tree, F is at the top again");
}

static void test_an_export_is_imported_into_the_open_folder(void)
{
	static const char ics[] = "BEGIN:VCALENDAR\r\nBEGIN:VJOURNAL\r\nSUMMARY:knote\r\n"
	                          "CREATED:20231114T221320Z\r\nEND:VJOURNAL\r\nEND:VCALENDAR\r\n";
	char path[64];
	QStringList log;
	FILE *f;

	setup();
	fzn_notebook_view w(node_ask, nullptr);

	w.set_log([&log](const QString &l) { log << l; });
	snprintf(path, sizeof(path), "/tmp/fzn-view-import-%ld.ics", (long)getpid());
	f = fopen(path, "wb");
	CHECK(f && fwrite(ics, 1u, sizeof(ics) - 1u, f) == sizeof(ics) - 1u, "fixture: a calendar");
	if (f)
		(void)fclose(f);
	CHECK(w.new_folder(QStringLiteral("old")), "fixture: a folder");
	CHECK(w.descend(w.listed_ids().value(0), QStringLiteral("old")), "fixture: opened");
	CHECK(w.import_file(QString::fromLatin1(path)) && w.list()->count() == 1
	              && w.list()->item(0)->text() == QStringLiteral("knote"),
	      "the calendar's note lands in the open folder");
	CHECK(log.last() == QStringLiteral("Imported 1 note(s); 0 were here already."),
	      "and the log says how many");
	CHECK(w.import_file(QString::fromLatin1(path))
	              && log.last() == QStringLiteral("Imported 0 note(s); 1 were here already."),
	      "a second import is recognised");
	CHECK(!w.import_file(QStringLiteral("/nonexistent.ics")) && log.last().startsWith("Nothing"),
	      "a path that is not there is said");
	(void)unlink(path);
}

static void test_a_checklist_is_lines_ticked_one_at_a_time(void)
{
	setup();
	fzn_notebook_view w(node_ask, nullptr);

	CHECK(w.new_list(QStringLiteral("shopping")) && w.title_text() == QStringLiteral("shopping"),
	      "a checklist is made and opened");
	CHECK(w.add_item(QStringLiteral("milk, two pints")) && w.add_item(QStringLiteral("eggs")),
	      "two items are added");
	CHECK(w.body_text() == QStringLiteral("[ ] milk, two pints\n[ ] eggs"),
	      "the body shows them as lines, unticked, the comma and spaces intact");
	CHECK(w.toggle_item(1) && w.body_text() == QStringLiteral("[ ] milk, two pints\n[x] eggs"),
	      "the second is ticked");
	CHECK(w.toggle_item(1) && w.body_text().endsWith(QStringLiteral("[ ] eggs")),
	      "and unticked");
	CHECK(!w.toggle_item(2) && !w.toggle_item(-1), "an item that is not there is not toggled");
	CHECK(w.save() && w.open_note(w.open_id())
	              && w.body_text() == QStringLiteral("[ ] milk, two pints\n[ ] eggs"),
	      "saving a list keeps its items, rather than writing the lines back as text -- "
	      "read back from the node, not from the screen");
	CHECK(w.remove_item(0) && w.body_text() == QStringLiteral("[ ] eggs"),
	      "the first item is removed and the second moves up, sec 453");
	CHECK(!w.remove_item(1) && !w.remove_item(-1), "an item that is not there is not removed");
	CHECK(w.open_note(w.open_id()) && w.body_text() == QStringLiteral("[ ] eggs"),
	      "and the node holds one item, read back from it");
	CHECK(w.new_note(QStringLiteral("plain")) && !w.add_item(QStringLiteral("x"))
	              && !w.remove_item(0),
	      "a note that is no list takes no items and loses none");
}

/* MOVING, sec 453: cut, open the folder, move it there. */
static void test_a_note_is_cut_and_moved(void)
{
	QString folder, sub, note;
	QStringList log;

	setup();
	fzn_notebook_view w(node_ask, nullptr);

	w.set_log([&log](const QString &l) { log << l; });
	CHECK(w.new_folder(QStringLiteral("Recipes")) && w.new_note(QStringLiteral("Bread")),
	      "fixture: a folder and a note beside it");
	note = w.open_id();
	folder = w.listed_ids().value(0) == note ? w.listed_ids().value(1) : w.listed_ids().value(0);
	CHECK(!w.move_here(), "nothing cut, nothing moves");
	CHECK(w.cut() && w.cut_id() == note, "the note is cut");
	CHECK(w.descend(folder, QStringLiteral("Recipes")) && w.move_here()
	              && w.listed_ids() == QStringList{ note } && w.cut_id().isEmpty(),
	      "opened in the folder, it moves there and is listed there");
	CHECK(log.contains(QStringLiteral("Moved Bread to Recipes.")), "and the log says where");
	CHECK(w.ascend() && !w.listed_ids().contains(note), "it has left the top");

	/* A FOLDER NOT UNDER ITS OWN DESCENDANT: the node refuses, and nothing
	 * moves. */
	CHECK(w.descend(folder, QStringLiteral("Recipes")) && w.new_folder(QStringLiteral("Cakes")),
	      "fixture: a folder inside the folder");
	sub = w.listed_ids().value(0) == note ? w.listed_ids().value(1) : w.listed_ids().value(0);
	CHECK(w.ascend() && w.open_note(folder) && w.cut()
	              && w.descend(folder, QStringLiteral("Recipes"))
	              && w.descend(sub, QStringLiteral("Cakes")),
	      "fixture: the folder cut, and its own subfolder open");
	CHECK(!w.move_here() && w.cut_id() == folder
	              && log.last().startsWith(QStringLiteral("Not moved")),
	      "it is not moved under its own subfolder, and stays cut");
	CHECK(w.ascend() && w.ascend() && w.listed_ids().contains(folder),
	      "it is still at the top");
}

static void test_pinned_first_and_the_archive_apart(void)
{
	QString a, b, c;

	setup();
	fzn_notebook_view w(node_ask, nullptr);

	CHECK(w.new_note(QStringLiteral("first")) && w.new_note(QStringLiteral("second"))
	              && w.new_note(QStringLiteral("third")),
	      "fixture: three notes");
	a = w.listed_ids().value(0);
	b = w.listed_ids().value(1);
	c = w.listed_ids().value(2);
	CHECK(w.open_note(c) && w.pin(true), "the third is pinned");
	CHECK(w.listed_ids() == (QStringList{ c, a, b })
	              && w.list()->item(0)->text().startsWith(QStringLiteral("* ")),
	      "and is listed first, marked, the others in their order");
	CHECK(w.open_note(c) && w.pin(false) && w.listed_ids() == (QStringList{ a, b, c }),
	      "unpinned, it goes back to its place");
	CHECK(w.open_note(a) && w.archive(true) && w.open_id().isEmpty()
	              && w.listed_ids() == (QStringList{ b, c }),
	      "an archived note leaves the notebook's list");
	w.show_archived(true);
	CHECK(w.listed_ids() == QStringList{ a }, "and is the archive's");
	CHECK(w.open_note(a) && w.archive(false) && w.status().contains(QStringLiteral("archived")),
	      "brought back, the archive is empty and says so");
	w.show_archived(false);
	CHECK(w.listed_ids().contains(a), "and the note is in the notebook again");
	CHECK(w.open_note(b) && w.trash(), "fixture: a note trashed");
	w.show_archived(true);
	CHECK(!w.listed_ids().contains(b), "a trashed note is not in the archive");
}

static void test_a_refresh_keeps_the_readers_place(void)
{
	int i, kept;

	setup();
	fzn_notebook_view w(node_ask, nullptr);

	w.resize(400, 300);
	for (i = 0; i < 40; i++)
		CHECK(w.new_note(QStringLiteral("note%1").arg(i)), "fixture: many notes");
	w.show();
	QApplication::processEvents();
	CHECK(w.open_note(w.listed_ids().value(39)), "fixture: the last note open");
	w.list()->verticalScrollBar()->setValue(0);
	kept = w.list()->verticalScrollBar()->value();
	w.refresh();
	CHECK(w.list()->verticalScrollBar()->maximum() > 0, "fixture: the list scrolls");
	CHECK(w.list()->verticalScrollBar()->value() == kept,
	      "a refresh leaves the reader where they were, not at the open note");
	w.hide();
}

/* NOT HERE YET, AND LABELLED, secs 514 and 522: a note whose blob has not
 * arrived is a row saying so, not an empty one; a labelled note shows its
 * labels on hover. */
static void test_a_pending_note_says_so_and_labels_show(void)
{
	static const uint8_t labels[] = { 'h', 'o', 'm', 'e', 0, 'w', 'o', 'r', 'k' };
	static const uint8_t top[FZN_TREE_ID_LEN] = { 0 };
	static uint8_t record[FZN_RECORD_MAX_LEN];
	uint8_t unseen[FZN_TREE_ID_LEN], seen[FZN_TREE_ID_LEN];
	fzn_note_blob_ref_t ref;
	fzn_tree_node_t node;
	fzn_record_t rec;
	fzn_note_t fields;
	size_t len = 0;
	int i, row = -1;

	setup();
	blob_stub_attach(&notes.author);
	chain_stub_attach(&notes.author);
	memset(&fields, 0, sizeof(fields));
	fields.title = (const uint8_t *)"never listed";
	fields.title_len = 12u;
	CHECK(fzn_notes_create(&notes.author, top, FZN_NOTE_TYPE_NOTE, &fields, 1u, unseen)
	              == FZN_NOTES_OK,
	      "fixture: a note never listed");
	fields.title = (const uint8_t *)"tagged";
	fields.title_len = 6u;
	fields.labels = labels;
	fields.labels_len = sizeof(labels);
	CHECK(fzn_notes_create(&notes.author, top, FZN_NOTE_TYPE_NOTE, &fields, 2u, seen)
	              == FZN_NOTES_OK,
	      "fixture: a labelled note");
	CHECK(fzn_notes_get(&notes.store, unseen, SELF, record, sizeof(record), &len) == FZN_NOTES_OK
	              && fzn_record_open(record, len, &rec) == FZN_RECORD_OK
	              && fzn_tree_open(rec, &node) == FZN_TREE_OK && fzn_notes_ref_of(&node, &ref),
	      "fixture: the first note's blob");
	blob_stub_drop(&ref);
	fzn_notebook_view w(node_ask, nullptr);

	CHECK(w.listed_texts().contains(QStringLiteral("(not here yet)"))
	              && !w.listed_texts().contains(QStringLiteral("never listed")),
	      "a note whose blob has not arrived lists as not here yet");
	for (i = 0; i < w.list()->count(); i++)
		if (w.list()->item(i)->text() == QStringLiteral("tagged"))
			row = i;
	CHECK(row >= 0 && w.list()->item(row)->toolTip() == QStringLiteral("home, work"),
	      "a labelled note shows its labels on hover");
	{
		char hex[65];
		int k;

		for (k = 0; k < (int)FZN_TREE_ID_LEN; k++)
			snprintf(hex + (2 * k), 3u, "%02x", unseen[k]);
		CHECK(w.open_note(QString::fromLatin1(hex)), "fixture: the pending note opens");
		CHECK(!w.editable(), "opened, a pending note's content cannot be edited");
	}
}

int main(int argc, char **argv)
{
	QApplication app(argc, argv);

	memset(SELF, 0x51, sizeof(SELF));
	test_an_empty_notebook_and_a_silent_node_read_differently();
	test_notes_are_made_saved_and_read_back();
	test_the_trash_is_its_own_view();
	test_sharing_is_warned_before_and_said_after();
	test_a_shared_tree_reads_and_cannot_be_written();
	test_an_export_is_imported_into_the_open_folder();
	test_a_checklist_is_lines_ticked_one_at_a_time();
	test_a_note_is_cut_and_moved();
	test_pinned_first_and_the_archive_apart();
	test_a_refresh_keeps_the_readers_place();
	test_a_pending_note_says_so_and_labels_show();
	if (failures) {
		fprintf(stderr, "notebook_view_test: %d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("notebook_view_test: all %d checks passed\n", checks);
	return 0;
}
