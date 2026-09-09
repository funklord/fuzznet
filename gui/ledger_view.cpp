#include "ledger_view.h"

#include <QFontDatabase>
#include <QFormLayout>
#include <QLabel>

/* Column width for the label, fixed so the verdicts line up in the string
 * rather than in a layout. `gui/link_view.cpp` has the argument. */
#define COL_LABEL 20

static QString label_column(const QString &text)
{
	/* LEFT-ALIGNED AND NEVER TRUNCATED. A label cut to fit its column names
	 * a different peer, which is the hazard this widget refuses to draw a
	 * key for, so one too wide pushes the row out instead. */
	return text.leftJustified(COL_LABEL, QLatin1Char(' '));
}

fzn_ledger_view::fzn_ledger_view(QWidget *parent)
        : QWidget(parent), state_(NOTHING), outstanding_(0u), rows_truncated_(false),
          summary_(new QLabel(this)), rows_(new QLabel(this))
{
	QFormLayout *form = new QFormLayout(this);

	form->addRow(QStringLiteral("Delivery"), summary_);
	form->addRow(QStringLiteral("Peers"), rows_);

	summary_->setWordWrap(true);
	/* THE ROWS MUST NOT WRAP. Their alignment is in the string, and a
	 * wrapped row folds one peer's verdict under another's label. */
	rows_->setWordWrap(false);
	rows_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));

	show_peers(nullptr, nullptr, 0u, 0u, nullptr, 0u);
}

void fzn_ledger_view::show_peers(const fzn_ledger_t *ledger,
                                 const uint8_t subject[FZN_SUBJECT_LEN], uint32_t kind,
                                 uint64_t current, const fzn_ledger_view_row *rows,
                                 size_t count)
{
	QString drawn_rows;
	size_t drawn = 0u;
	size_t outstanding = 0u;
	size_t asked = 0u;
	size_t i;

	state_ = NOTHING;
	outstanding_ = 0u;
	rows_truncated_ = false;

	if (!ledger || !subject || !rows || !count) {
		/* NOT "EVERYBODY IS CURRENT". A host with no ledger has
		 * confirmed nothing about anybody, and `cli/ledger_print`
		 * refuses the same reading for the same reason. */
		summary_->setText(QStringLiteral("nothing is being tracked"));
		rows_->setText(QString());
		return;
	}

	/*
	 * ASKED ONCE, BEFORE ANY ROW, BECAUSE IT IS A PROPERTY OF THE TABLE.
	 *
	 * The first version counted UNREADABLE rows and compared the count --
	 * and that comparison could never be false in a useful way, because
	 * unreadability belongs to the ledger rather than to a peer: every row
	 * is unreadable or none is. Two sabotages proved it by SURVIVING, one
	 * of them a majority rule that behaved identically on every reachable
	 * input. sec 228.
	 *
	 * So the question is asked here, where it is true or false once, and
	 * no rows are drawn at all -- a list of identical "cannot say" lines is
	 * a screen pretending to have per-peer answers.
	 */
	if (!fzn_ledger_sound(ledger)) {
		state_ = UNREADABLE;
		summary_->setText(QStringLiteral("this ledger cannot be read, so nothing here "
		                                 "is evidence"));
		rows_->setText(QString());
		return;
	}

	for (i = 0u; i < count; i++) {
		char line[FZN_LEDGER_PRINT_MAX];
		fzn_ledger_line_t said = FZN_LEDGER_LINE_NONE;
		size_t len = 0u;

		if (!rows[i].peer)
			continue;
		/* ONE DECISION AND ONE WORDING, BOTH THE PRINTER'S. sec 193. */
		if (fzn_ledger_print(ledger, rows[i].peer, subject, kind, current, line,
		                     sizeof(line), &len, &said) != FZN_LEDGER_OK)
			continue;

		asked++;
		if (said == FZN_LEDGER_LINE_BEHIND || said == FZN_LEDGER_LINE_UNKNOWN)
			/* COLLAPSED HERE AND KEPT APART IN THE ROW. The action
			 * is identical -- send it -- so a summary that split
			 * them would offer a distinction nobody acts on. */
			outstanding++;

		if (drawn >= FZN_LEDGER_VIEW_ROWS_MAX) {
			rows_truncated_ = true;
			continue;
		}
		if (drawn)
			drawn_rows += QLatin1Char('\n');
		drawn_rows += label_column(rows[i].label) + QString::fromLatin1(line).trimmed();
		drawn++;
	}

	if (!asked) {
		summary_->setText(QStringLiteral("nothing is being tracked"));
		rows_->setText(QString());
		return;
	}

	if (outstanding) {
		state_ = BEHIND;
		outstanding_ = outstanding;
		summary_->setText(QString::number(static_cast<qulonglong>(outstanding)) +
		                  QStringLiteral(" of ") +
		                  QString::number(static_cast<qulonglong>(asked)) +
		                  QStringLiteral(" peers have not confirmed this version"));
	} else {
		state_ = CURRENT;
		outstanding_ = 0u;
		summary_->setText(QStringLiteral("all ") +
		                  QString::number(static_cast<qulonglong>(asked)) +
		                  QStringLiteral(" peers have confirmed this version"));
	}

	if (rows_truncated_)
		drawn_rows += QStringLiteral("\n(more peers than this list shows)");

	rows_->setText(drawn_rows);
}

fzn_ledger_view::state fzn_ledger_view::shown_state() const
{
	return state_;
}

QString fzn_ledger_view::summary_text() const
{
	return summary_->text();
}

QString fzn_ledger_view::rows_text() const
{
	return rows_->text();
}

size_t fzn_ledger_view::outstanding() const
{
	return outstanding_;
}

bool fzn_ledger_view::rows_truncated() const
{
	return rows_truncated_;
}
