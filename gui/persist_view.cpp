#include "persist_view.h"

#include <QFontDatabase>
#include <QFormLayout>
#include <QLabel>

/* Column width for the slot's own name, fixed so the verdicts line up in the
 * string rather than in a layout. `gui/link_view.cpp` has the argument. */
#define COL_SLOT 30

static QString column(const QString &text)
{
	/* LEFT-ALIGNED AND NEVER TRUNCATED. A slot name cut to fit names a
	 * different slot, so one too wide pushes the row out instead. */
	return text.leftJustified(COL_SLOT, QLatin1Char(' '));
}

/* A short label for the row's left column. The printer's own words are a
 * sentence fragment -- "this host's trust anchor" -- which reads well inside
 * a line and badly as a column, so the column gets its own spelling and the
 * verdict beside it is the printer's, unaltered. */
static QString slot_label(fzn_persist_slot_t slot)
{
	switch (slot) {
	case FZN_PERSIST_TRUST:
		return QStringLiteral("trust anchor");
	case FZN_PERSIST_OWN_PREKEY:
		return QStringLiteral("own prekey");
	case FZN_PERSIST_PEER:
		return QStringLiteral("pinned peer");
	case FZN_PERSIST_SEND_CHAIN:
		return QStringLiteral("send chain");
	case FZN_PERSIST_RECV_CHAIN:
		return QStringLiteral("receive chain");
	}
	/* NO `default:` ABOVE, so a slot added to persist.h fails to compile
	 * here rather than being drawn as this. */
	return QStringLiteral("unknown slot");
}

fzn_persist_view::fzn_persist_view(QWidget *parent)
        : QWidget(parent), state_(NOTHING), missing_(0u), summary_(new QLabel(this)),
          rows_(new QLabel(this))
{
	QFormLayout *form = new QFormLayout(this);

	form->addRow(QStringLiteral("Recovered"), summary_);
	form->addRow(QStringLiteral("Stored state"), rows_);

	summary_->setWordWrap(true);
	/* THE ROWS MUST NOT WRAP. Their alignment is in the string, and a
	 * wrapped row folds one slot's verdict under another's name. */
	rows_->setWordWrap(false);
	rows_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));

	show_slots(nullptr, 0u);
}

void fzn_persist_view::show_slots(const fzn_persist_view_row *rows, size_t count)
{
	QString drawn;
	size_t i;
	size_t read_back = 0u;
	size_t fresh = 0u;

	state_ = NOTHING;
	missing_ = 0u;

	if (!rows || !count) {
		summary_->setText(QStringLiteral("nothing was read"));
		rows_->setText(QString());
		return;
	}

	for (i = 0; i < count; i++) {
		char line[FZN_PERSIST_PRINT_MAX];
		size_t len = 0u;
		fzn_persist_line_t said = FZN_PERSIST_LINE_NONE;

		if (fzn_persist_print(rows[i].slot, rows[i].err, rows[i].had_stored, line,
		                      sizeof(line), &len, &said) != FZN_PERSIST_OK)
			continue;

		/*
		 * THE THREE OUTCOMES THAT ARE NOT LOSSES, counted apart. A slot
		 * read back and a slot that was never written are both fine and
		 * they are not the same fine, which is why the summary can tell
		 * a first run from a recovery.
		 */
		if (said == FZN_PERSIST_LINE_LOADED)
			read_back++;
		else if (said == FZN_PERSIST_LINE_FRESH)
			fresh++;
		else if (said != FZN_PERSIST_LINE_NONE)
			missing_++;

		if (i > 0u)
			drawn += QLatin1Char('\n');
		drawn += column(slot_label(rows[i].slot))
		         + QString::fromLatin1(line).trimmed();
	}

	rows_->setText(drawn);

	/*
	 * THE WORST ROW DECIDES. A person scanning five lines reads the first
	 * sentence and stops, so one loss among four recoveries has to be what
	 * the first sentence is about.
	 */
	if (missing_ > 0u) {
		state_ = INCOMPLETE;
		summary_->setText(QStringLiteral("%1 of %2 did not come back -- the rows "
		                                 "below say which and why")
		                          .arg(missing_)
		                          .arg(count));
	} else if (read_back == 0u) {
		/* NOTHING STORED ANYWHERE AND NOTHING LOST: a first run, which
		 * is the most common startup there is and must not read as a
		 * partial recovery. */
		state_ = FRESH;
		summary_->setText(QStringLiteral("nothing had been stored yet, which is a "
		                                 "first run rather than a loss"));
	} else {
		state_ = RECOVERED;
		summary_->setText(QStringLiteral("%1 of %2 read back, and nothing is "
		                                 "missing")
		                          .arg(read_back)
		                          .arg(count));
	}
}

fzn_persist_view::state fzn_persist_view::shown_state() const
{
	return state_;
}

QString fzn_persist_view::summary_text() const
{
	return summary_->text();
}

QString fzn_persist_view::rows_text() const
{
	return rows_->text();
}

size_t fzn_persist_view::missing() const
{
	return missing_;
}
