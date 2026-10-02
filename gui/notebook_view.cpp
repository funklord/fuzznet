/* See notebook_view.h. */

#include "notebook_view.h"

extern "C" {
#include "../local/client.h"
#include "../local/vocabulary.h"
#include "../notes/note.h"
}

#include <QCheckBox>
#include <QComboBox>
#include <QFile>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QScrollBar>
#include <QTemporaryFile>
#include <QVBoxLayout>

#include <string.h>

/* A reply line, the grammar's bound and room for its newline. */
#define REPLY_CAP (FZN_REPLY_MAX + 2u)

static const int ROLE_ID = Qt::UserRole;
static const int ROLE_TYPE = Qt::UserRole + 1;
static const int ROLE_TITLE = Qt::UserRole + 2;

size_t fzn_notebook_view_socket_ask(void *ctx, const char *line, char *reply, size_t reply_cap)
{
	const char *path = (const char *)ctx;
	const char *space;
	size_t verb_len, len = 0;
	int fd = -1;

	if (!path || !line || !reply || reply_cap < 2u)
		return 0;
	space = strchr(line, ' ');
	verb_len = space ? (size_t)(space - line) : strlen(line);
	if (fzn_client_connect(path, &fd) != FZN_CLIENT_OK)
		return 0;
	if (fzn_client_send(fd, (const uint8_t *)line, verb_len,
	                    space ? (const uint8_t *)space + 1 : nullptr,
	                    space ? strlen(space + 1) : 0u)
	            != FZN_CLIENT_OK
	    || fzn_client_recv(fd, (uint8_t *)reply, reply_cap - 1u, &len, 5000u) != FZN_CLIENT_OK)
		len = 0;
	fzn_client_close(fd);
	reply[len] = '\0';
	return len;
}

/* `%XX` back to the byte, as `node/notes.c` escapes a title. */
static QString unescape(const QString &text)
{
	QByteArray in = text.toUtf8(), out;
	int i;

	for (i = 0; i < in.size(); i++) {
		if (in[i] == '%' && i + 2 < in.size()) {
			bool ok = false;
			int v = in.mid(i + 1, 2).toInt(&ok, 16);

			if (ok) {
				out.append((char)v);
				i += 2;
				continue;
			}
		}
		out.append(in[i]);
	}
	return QString::fromUtf8(out);
}

fzn_notebook_view::fzn_notebook_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent)
        : QWidget(parent), m_ask(ask), m_ask_ctx(ask_ctx)
{
	auto *outer = new QVBoxLayout(this);
	auto *top = new QHBoxLayout();
	auto *edit_row = new QHBoxLayout();
	auto *trash_row = new QHBoxLayout();
	auto *share_row = new QHBoxLayout();

	m_trees = new QComboBox(this);
	m_up = new QPushButton(QStringLiteral("Up"), this);
	m_location = new QLabel(this);
	m_status = new QLabel(this);
	m_status->setWordWrap(true);
	m_list = new QListWidget(this);
	m_show_trash = new QCheckBox(QStringLiteral("Show trash"), this);
	m_title = new QLineEdit(this);
	/* PLAIN TEXT BY CONSTRUCTION: a note's own text never renders as rich
	 * text (fuzzypickles' sec 28). */
	m_body = new QPlainTextEdit(this);
	m_new_note = new QPushButton(QStringLiteral("New note"), this);
	m_new_folder = new QPushButton(QStringLiteral("New folder"), this);
	m_save = new QPushButton(QStringLiteral("Save"), this);
	m_trash_button = new QPushButton(QStringLiteral("Trash"), this);
	m_restore = new QPushButton(QStringLiteral("Restore"), this);
	m_empty = new QPushButton(QStringLiteral("Empty trash"), this);
	m_import = new QPushButton(QStringLiteral("Import"), this);
	m_new_list = new QPushButton(QStringLiteral("New list"), this);
	m_item_text = new QLineEdit(this);
	m_item_text->setPlaceholderText(QStringLiteral("New item"));
	m_add_item = new QPushButton(QStringLiteral("Add item"), this);
	m_toggle = new QPushButton(QStringLiteral("Tick / untick"), this);
	auto *item_row = new QHBoxLayout();
	m_share_to = new QComboBox(this);
	m_share = new QPushButton(QStringLiteral("Share"), this);
	m_unshare = new QPushButton(QStringLiteral("Unshare"), this);
	m_shared_with = new QLabel(this);
	m_shared_with->setWordWrap(true);
	m_warning = new QLabel(QStringLiteral("Sharing sends this note and everything below it to "
	                                      "the contact, and keeps sending changes. Unsharing "
	                                      "stops what comes next; what they already fetched "
	                                      "stays with them."),
	                       this);
	m_warning->setWordWrap(true);

	top->addWidget(m_trees);
	top->addWidget(m_up);
	top->addWidget(m_location, 1);
	edit_row->addWidget(m_new_note);
	edit_row->addWidget(m_new_folder);
	edit_row->addWidget(m_new_list);
	edit_row->addWidget(m_save);
	item_row->addWidget(m_item_text, 1);
	item_row->addWidget(m_add_item);
	item_row->addWidget(m_toggle);
	edit_row->addWidget(m_import);
	trash_row->addWidget(m_show_trash);
	trash_row->addWidget(m_trash_button);
	trash_row->addWidget(m_restore);
	trash_row->addWidget(m_empty);
	share_row->addWidget(m_share_to, 1);
	share_row->addWidget(m_share);
	share_row->addWidget(m_unshare);
	outer->addLayout(top);
	outer->addWidget(m_status);
	outer->addWidget(m_list, 1);
	outer->addLayout(trash_row);
	outer->addWidget(m_title);
	outer->addWidget(m_body, 1);
	outer->addLayout(item_row);
	outer->addLayout(edit_row);
	outer->addWidget(m_warning);
	outer->addLayout(share_row);
	outer->addWidget(m_shared_with);

	connect(m_trees, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) {
		if (!m_updating)
			open_tree(m_trees->currentData().toString());
	});
	connect(m_up, &QPushButton::clicked, this, [this]() { ascend(); });
	connect(m_list, &QListWidget::itemActivated, this, [this](QListWidgetItem *item) {
		if (item && item->data(ROLE_TYPE).toInt() == FZN_NOTE_TYPE_FOLDER)
			descend(item->data(ROLE_ID).toString(), item->data(ROLE_TITLE).toString());
	});
	connect(m_list, &QListWidget::currentItemChanged, this,
	        [this](QListWidgetItem *item, QListWidgetItem *) {
		        if (!m_updating && item)
			        open_note(item->data(ROLE_ID).toString());
	        });
	connect(m_show_trash, &QCheckBox::toggled, this, [this](bool on) { show_trash(on); });
	connect(m_save, &QPushButton::clicked, this, [this]() { save(); });
	connect(m_new_note, &QPushButton::clicked, this,
	        [this]() { new_note(QStringLiteral("Untitled")); });
	connect(m_new_folder, &QPushButton::clicked, this,
	        [this]() { new_folder(QStringLiteral("New folder")); });
	connect(m_trash_button, &QPushButton::clicked, this, [this]() { trash(); });
	connect(m_new_list, &QPushButton::clicked, this,
	        [this]() { new_list(QStringLiteral("New list")); });
	connect(m_add_item, &QPushButton::clicked, this, [this]() {
		if (add_item(m_item_text->text()))
			m_item_text->clear();
	});
	/* THE ITEM AT THE CURSOR: one line of the body is one item. */
	connect(m_toggle, &QPushButton::clicked, this,
	        [this]() { toggle_item(m_body->textCursor().blockNumber()); });
	connect(m_restore, &QPushButton::clicked, this, [this]() { restore(); });
	connect(m_empty, &QPushButton::clicked, this, [this]() { empty_trash(); });
	connect(m_import, &QPushButton::clicked, this, [this]() {
		QString path = QFileDialog::getOpenFileName(
		        this, QStringLiteral("Import notes"), QString(),
		        QStringLiteral("Keep or KNotes exports (*.json *.ics)"));

		if (!path.isEmpty())
			import_file(path);
	});
	connect(m_share, &QPushButton::clicked, this,
	        [this]() { share_with(m_share_to->currentText()); });
	connect(m_unshare, &QPushButton::clicked, this,
	        [this]() { unshare_with(m_share_to->currentText()); });
	refresh();
}

/* ---- asking -------------------------------------------------------------- */

int fzn_notebook_view::ask(const QString &line, QString *detail)
{
	char reply[REPLY_CAP];
	const uint8_t *d = nullptr;
	size_t len, d_len = 0;
	QByteArray bytes = line.toUtf8();
	fzn_reply_t kind;

	if (detail)
		detail->clear();
	if (!m_ask || bytes.size() >= (int)FZN_REQUEST_MAX || bytes.contains('\n'))
		return 0;
	len = m_ask(m_ask_ctx, bytes.constData(), reply, sizeof(reply));
	if (len == 0u || len >= sizeof(reply)) {
		m_answered = false;
		return -1;
	}
	m_answered = true;
	while (len && (reply[len - 1u] == '\n' || reply[len - 1u] == '\r'))
		len--;
	kind = fzn_reply_of((const uint8_t *)reply, len, &d, &d_len);
	if (detail && d)
		*detail = QString::fromUtf8((const char *)d, (int)d_len);
	return kind == FZN_REPLY_OK ? 1 : 0;
}

void fzn_notebook_view::say(const QString &line)
{
	if (m_log)
		m_log(line);
}

void fzn_notebook_view::set_status(const QString &text)
{
	m_status->setText(text);
	m_status->setVisible(!text.isEmpty());
}

QString fzn_notebook_view::parent_id() const
{
	return m_path.isEmpty() ? QStringLiteral("top") : m_path.last();
}

/* ---- reading ------------------------------------------------------------- */

void fzn_notebook_view::refresh()
{
	refresh_trees();
	refresh_list();
	refresh_note();
	refresh_shares();
}

void fzn_notebook_view::refresh_trees()
{
	QString detail;
	int at = 0, i;

	m_updating = true;
	m_trees->clear();
	m_trees->addItem(QStringLiteral("My notes"), QString());
	/* `ok COUNT NAME,HOST,PORT ...`: a contact whose share this node took. */
	if (ask(QStringLiteral("list received"), &detail) == 1) {
		QStringList words = detail.split(QLatin1Char(' '), Qt::SkipEmptyParts);

		for (i = 1; i < words.size(); i++) {
			QString name = words[i].section(QLatin1Char(','), 0, 0);

			m_trees->addItem(QStringLiteral("Shared by %1").arg(name), name);
		}
	}
	for (i = 0; i < m_trees->count(); i++)
		if (m_trees->itemData(i).toString() == m_tree)
			at = i;
	m_trees->setCurrentIndex(at);
	m_updating = false;
}

void fzn_notebook_view::refresh_list()
{
	QScrollBar *bar = m_list->verticalScrollBar();
	int keep = bar ? bar->value() : 0;
	QString base = shared() ? QStringLiteral("list shared %1 %2").arg(m_tree, parent_id())
	                        : QStringLiteral("list note %1").arg(parent_id());
	size_t from = 0, total = 0, guard;
	int got;

	m_updating = true;
	m_list->clear();
	/* EVERY PAGE, until the total is reached or a page brings nothing: a
	 * reply holds as many items as fit, and the next is asked from there. */
	for (guard = 0; guard < 64u; guard++) {
		QString detail;
		QStringList words;
		int i, before = m_list->count();

		got = ask(QStringLiteral("%1 %2").arg(base).arg(from), &detail);
		if (got != 1)
			break;
		words = detail.split(QLatin1Char(' '), Qt::SkipEmptyParts);
		if (words.size() < 2)
			break;
		total = words[0].toULongLong();
		for (i = 2; i < words.size(); i++) {
			QStringList f = words[i].split(QLatin1Char(','));
			unsigned flags;
			int type;
			bool trashed;

			from++;
			if (f.size() < 6)
				continue;
			type = f[1].toInt();
			flags = f[2].toUInt();
			trashed = (flags & FZN_NOTE_FLAG_TRASHED) != 0u;
			/* THE TRASH, or everything but: one list, two views. */
			if (trashed != m_trash)
				continue;
			QString title = unescape(f[5]);
			auto *item = new QListWidgetItem(
			        type == FZN_NOTE_TYPE_FOLDER ? title + QStringLiteral("/") : title);

			item->setData(ROLE_ID, f[0]);
			item->setData(ROLE_TYPE, type);
			item->setData(ROLE_TITLE, title);
			m_list->addItem(item);
			if (item->data(ROLE_ID).toString() == m_open)
				m_list->setCurrentItem(item);
		}
		if (from >= total || (words.size() == 2 && m_list->count() == before))
			break;
	}
	/* THE READER'S PLACE, put back after the selection above scrolled to
	 * the open note. */
	if (bar)
		bar->setValue(keep);
	m_updating = false;
	if (!m_answered)
		set_status(QStringLiteral("The node did not answer; what is shown may be out of "
		                          "date."));
	else if (m_list->count() == 0)
		set_status(m_trash ? QStringLiteral("The trash is empty.")
		                   : QStringLiteral("Nothing here yet."));
	else
		set_status(QString());
	m_location->setText(m_path_titles.isEmpty() ? QStringLiteral("/")
	                                            : m_path_titles.join(QStringLiteral(" / ")));
	m_up->setEnabled(!m_path.isEmpty());
}

void fzn_notebook_view::refresh_note()
{
	QString detail;
	bool editing = !shared();
	bool have = !m_open.isEmpty();

	m_title->clear();
	m_body->clear();
	m_is_list = false;
	m_ticks.clear();
	if (have) {
		QString get = shared() ? QStringLiteral("get shared %1 %2").arg(m_tree, m_open)
		                       : QStringLiteral("get note %1").arg(m_open);
		/* `TYPE FLAGS CREATED EDITED PARENT inline|blob LEN TITLE`. */
		if (ask(get, &detail) == 1) {
			QStringList f = detail.split(QLatin1Char(' '));
			int type = f.value(0).toInt();

			m_title->setText(unescape(f.mid(7).join(QLatin1Char(' '))));
			m_is_list = type == FZN_NOTE_TYPE_LIST;
			if (m_is_list) {
				QStringList lines;
				size_t from = 0, total = 0, guard;

				/* `TOTAL FROM FLAGS,TEXT ...`, every page. */
				for (guard = 0; guard < 256u; guard++) {
					QStringList w;
					int i;

					if (ask(QStringLiteral("%1 items %2").arg(get).arg(from), &detail) != 1)
						break;
					w = detail.split(QLatin1Char(' '), Qt::SkipEmptyParts);
					total = w.value(0).toULongLong();
					for (i = 2; i < w.size(); i++) {
						bool ticked = (w[i].section(QLatin1Char(','), 0, 0).toUInt()
						               & FZN_NOTE_ITEM_FLAG_CHECKED)
						              != 0u;

						m_ticks << ticked;
						lines << (ticked ? QStringLiteral("[x] ") : QStringLiteral("[ ] "))
						                         + unescape(w[i].section(QLatin1Char(','), 1));
						from++;
					}
					if (from >= total || w.size() <= 2)
						break;
				}
				m_body->setPlainText(lines.join(QLatin1Char('\n')));
			} else if (type != FZN_NOTE_TYPE_FOLDER) {
				QTemporaryFile file;

				if (file.open()) {
					QString path = file.fileName(), why;

					file.close();
					if (ask(QStringLiteral("%1 file %2").arg(get, path), &why) == 1) {
						QFile in(path);

						if (in.open(QIODevice::ReadOnly))
							m_body->setPlainText(QString::fromUtf8(in.readAll()));
					} else {
						set_status(QStringLiteral("The text is not here yet: %1").arg(why));
					}
				}
			}
			m_body->setEnabled(type != FZN_NOTE_TYPE_FOLDER);
		} else {
			m_open.clear();
			have = false;
		}
	}
	m_title->setReadOnly(!editing);
	m_body->setReadOnly(!editing || m_is_list);
	m_new_list->setEnabled(editing);
	m_item_text->setEnabled(editing && m_is_list);
	m_add_item->setEnabled(editing && m_is_list);
	m_toggle->setEnabled(editing && m_is_list);
	m_new_note->setEnabled(editing);
	m_new_folder->setEnabled(editing);
	m_save->setEnabled(editing && have);
	m_trash_button->setEnabled(editing && have && !m_trash);
	m_restore->setEnabled(editing && have && m_trash);
	m_empty->setEnabled(editing);
	m_import->setEnabled(editing);
	m_share->setEnabled(editing && have);
	m_unshare->setEnabled(editing && have);
	m_share_to->setEnabled(editing);
	m_warning->setVisible(editing);
}

void fzn_notebook_view::refresh_shares()
{
	QString detail;
	QStringList with;
	QString keep = m_share_to->currentText();
	int i;

	m_shared_with->clear();
	if (shared())
		return;
	m_share_to->clear();
	/* `ok TOTAL FROM NAME,KEY ...`. */
	if (ask(QStringLiteral("list contact"), &detail) == 1) {
		QStringList words = detail.split(QLatin1Char(' '), Qt::SkipEmptyParts);

		for (i = 2; i < words.size(); i++)
			m_share_to->addItem(words[i].section(QLatin1Char(','), 0, 0));
	}
	i = m_share_to->findText(keep);
	if (i >= 0)
		m_share_to->setCurrentIndex(i);
	if (m_open.isEmpty())
		return;
	/* `ok TOTAL FROM SUBTREE,NAME ...`: where the open note goes. */
	if (ask(QStringLiteral("list share"), &detail) == 1) {
		QStringList words = detail.split(QLatin1Char(' '), Qt::SkipEmptyParts);

		for (i = 2; i < words.size(); i++)
			if (words[i].section(QLatin1Char(','), 0, 0) == m_open)
				with << words[i].section(QLatin1Char(','), 1, 1);
	}
	m_shared_with->setText(with.isEmpty() ? QStringLiteral("Not shared.")
	                                      : QStringLiteral("Shared with %1.")
	                                                .arg(with.join(QStringLiteral(", "))));
}

/* ---- acting -------------------------------------------------------------- */

bool fzn_notebook_view::open_tree(const QString &contact)
{
	m_tree = contact;
	m_path.clear();
	m_path_titles.clear();
	m_open.clear();
	refresh();
	return m_answered;
}

bool fzn_notebook_view::descend(const QString &id, const QString &title)
{
	m_path << id;
	m_path_titles << title;
	m_open.clear();
	refresh_list();
	refresh_note();
	refresh_shares();
	return m_answered;
}

bool fzn_notebook_view::ascend()
{
	if (m_path.isEmpty())
		return false;
	m_path.removeLast();
	m_path_titles.removeLast();
	m_open.clear();
	refresh_list();
	refresh_note();
	refresh_shares();
	return true;
}

bool fzn_notebook_view::open_note(const QString &id)
{
	m_open = id;
	refresh_note();
	refresh_shares();
	return !m_open.isEmpty();
}

bool fzn_notebook_view::new_note(const QString &title)
{
	QString id;
	QString one_line = QString(title).replace(QLatin1Char('\n'), QLatin1Char(' '));

	if (shared() || one_line.isEmpty())
		return false;
	if (ask(QStringLiteral("add note %1 %2").arg(parent_id(), one_line), &id) != 1) {
		say(QStringLiteral("The note was not made: %1").arg(id));
		return false;
	}
	m_open = id;
	refresh_list();
	refresh_note();
	refresh_shares();
	say(QStringLiteral("Made the note %1.").arg(one_line));
	return true;
}

bool fzn_notebook_view::new_folder(const QString &title)
{
	QString id;
	QString one_line = QString(title).replace(QLatin1Char('\n'), QLatin1Char(' '));

	if (shared() || one_line.isEmpty())
		return false;
	if (ask(QStringLiteral("add folder %1 %2").arg(parent_id(), one_line), &id) != 1) {
		say(QStringLiteral("The folder was not made: %1").arg(id));
		return false;
	}
	refresh_list();
	say(QStringLiteral("Made the folder %1.").arg(one_line));
	return true;
}

bool fzn_notebook_view::new_list(const QString &title)
{
	QString id;
	QString one_line = QString(title).replace(QLatin1Char('\n'), QLatin1Char(' '));

	if (shared() || one_line.isEmpty())
		return false;
	if (ask(QStringLiteral("add list %1 %2").arg(parent_id(), one_line), &id) != 1) {
		say(QStringLiteral("The list was not made: %1").arg(id));
		return false;
	}
	m_open = id;
	refresh_list();
	refresh_note();
	refresh_shares();
	say(QStringLiteral("Made the list %1.").arg(one_line));
	return true;
}

bool fzn_notebook_view::add_item(const QString &text)
{
	QString why;
	QString one_line = QString(text).replace(QLatin1Char('\n'), QLatin1Char(' '));

	if (shared() || !m_is_list || one_line.isEmpty())
		return false;
	if (ask(QStringLiteral("add item %1 %2").arg(m_open, one_line), &why) != 1) {
		say(QStringLiteral("The item was not added: %1").arg(why));
		return false;
	}
	refresh_note();
	return true;
}

bool fzn_notebook_view::toggle_item(int index)
{
	QString why;

	if (shared() || !m_is_list || index < 0 || index >= m_ticks.size())
		return false;
	if (ask(QStringLiteral("set note %1 item %2 %3")
	                .arg(m_open)
	                .arg(index)
	                .arg(m_ticks[index] ? QStringLiteral("uncheck") : QStringLiteral("check")),
	        &why)
	    != 1) {
		say(QStringLiteral("The item was not changed: %1").arg(why));
		return false;
	}
	refresh_note();
	return true;
}

bool fzn_notebook_view::save()
{
	QString why;
	QString title = m_title->text().replace(QLatin1Char('\n'), QLatin1Char(' '));
	QTemporaryFile file;

	if (shared() || m_open.isEmpty())
		return false;
	if (!title.isEmpty()
	    && ask(QStringLiteral("set note %1 title %2").arg(m_open, title), &why) != 1) {
		say(QStringLiteral("The title was not saved: %1").arg(why));
		return false;
	}
	/* THE TEXT THROUGH A FILE: it may hold newlines and be far past one
	 * request line. A folder has none to save. */
	if (m_body->isEnabled() && !m_is_list) {
		if (!file.open() || file.write(m_body->toPlainText().toUtf8()) < 0) {
			say(QStringLiteral("The text could not be written out to save."));
			return false;
		}
		file.close();
		if (ask(QStringLiteral("set note %1 file %2").arg(m_open, file.fileName()), &why)
		    != 1) {
			say(QStringLiteral("The text was not saved: %1").arg(why));
			return false;
		}
	}
	refresh_list();
	say(QStringLiteral("Saved."));
	return true;
}

bool fzn_notebook_view::trash()
{
	QString why;

	if (shared() || m_open.isEmpty())
		return false;
	if (ask(QStringLiteral("set note %1 trash").arg(m_open), &why) != 1) {
		say(QStringLiteral("Not moved to the trash: %1").arg(why));
		return false;
	}
	m_open.clear();
	refresh_list();
	refresh_note();
	refresh_shares();
	say(QStringLiteral("Moved to the trash."));
	return true;
}

bool fzn_notebook_view::restore()
{
	QString why;

	if (shared() || m_open.isEmpty())
		return false;
	if (ask(QStringLiteral("set note %1 untrash").arg(m_open), &why) != 1) {
		say(QStringLiteral("Not restored: %1").arg(why));
		return false;
	}
	m_open.clear();
	refresh_list();
	refresh_note();
	say(QStringLiteral("Restored."));
	return true;
}

bool fzn_notebook_view::empty_trash()
{
	QString detail;
	QStringList f;

	if (shared())
		return false;
	if (ask(QStringLiteral("remove note trash"), &detail) != 1) {
		say(QStringLiteral("The trash was not emptied: %1").arg(detail));
		return false;
	}
	/* `QUEUED PENDING`: what waits is waiting on other nodes, and says so. */
	f = detail.split(QLatin1Char(' '));
	if (f.value(1).toInt() > 0)
		say(QStringLiteral("Emptying %1 note(s); %2 wait for the other nodes holding them.")
		            .arg(f.value(0), f.value(1)));
	else
		say(QStringLiteral("Emptied %1 note(s).").arg(f.value(0)));
	m_open.clear();
	refresh_list();
	refresh_note();
	return true;
}

bool fzn_notebook_view::import_file(const QString &path)
{
	QString detail;
	QStringList f;

	if (shared() || path.isEmpty())
		return false;
	if (ask(QStringLiteral("add import %1 %2").arg(parent_id(), path), &detail) != 1) {
		say(QStringLiteral("Nothing was imported: %1").arg(detail));
		return false;
	}
	/* `IMPORTED ALREADY UNDATED REFUSED NAME ...`: what did not come across
	 * is named while the user still has the export. */
	f = detail.split(QLatin1Char(' '), Qt::SkipEmptyParts);
	say(QStringLiteral("Imported %1 note(s); %2 were here already.")
	            .arg(f.value(0), f.value(1)));
	if (f.value(3).toInt() > 0) {
		QStringList refused;
		int i;

		for (i = 4; i < f.size(); i++)
			refused << unescape(f[i]);
		say(QStringLiteral("%1 could not be imported: %2")
		            .arg(f.value(3), refused.join(QStringLiteral(", "))));
	}
	refresh_list();
	return true;
}

bool fzn_notebook_view::share_with(const QString &contact)
{
	QString why;

	if (shared() || m_open.isEmpty() || contact.isEmpty())
		return false;
	if (ask(QStringLiteral("add share %1 %2").arg(m_open, contact), &why) != 1) {
		say(QStringLiteral("Not shared: %1").arg(why));
		return false;
	}
	refresh_shares();
	say(QStringLiteral("Shared with %1.").arg(contact));
	return true;
}

bool fzn_notebook_view::unshare_with(const QString &contact)
{
	QString why;

	if (shared() || m_open.isEmpty() || contact.isEmpty())
		return false;
	if (ask(QStringLiteral("remove share %1 %2").arg(m_open, contact), &why) != 1) {
		say(QStringLiteral("Not unshared: %1").arg(why));
		return false;
	}
	refresh_shares();
	/* SAID AGAIN AFTER, in the words the warning used before. */
	say(QStringLiteral("No longer shared with %1; what they already fetched stays with them.")
	            .arg(contact));
	return true;
}

void fzn_notebook_view::show_trash(bool on)
{
	m_trash = on;
	if (m_show_trash->isChecked() != on)
		m_show_trash->setChecked(on);
	m_open.clear();
	refresh_list();
	refresh_note();
}

/* ---- what is on screen ---------------------------------------------------- */

QString fzn_notebook_view::status() const
{
	return m_status->text();
}

QString fzn_notebook_view::location() const
{
	return m_location->text();
}

QString fzn_notebook_view::title_text() const
{
	return m_title->text();
}

QString fzn_notebook_view::body_text() const
{
	return m_body->toPlainText();
}

QString fzn_notebook_view::shared_with() const
{
	return m_shared_with->text();
}

QString fzn_notebook_view::warning() const
{
	return m_warning->isHidden() ? QString() : m_warning->text();
}

bool fzn_notebook_view::editable() const
{
	return !m_title->isReadOnly() && m_save->isEnabled();
}

QStringList fzn_notebook_view::listed_ids() const
{
	QStringList ids;
	int i;

	for (i = 0; i < m_list->count(); i++)
		ids << m_list->item(i)->data(ROLE_ID).toString();
	return ids;
}
