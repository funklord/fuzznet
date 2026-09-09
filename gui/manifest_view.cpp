#include "manifest_view.h"

#include <QFontDatabase>
#include <QFormLayout>
#include <QLabel>

/* Column width for the label, fixed so the verdicts line up in the string
 * rather than in a layout. See `gui/link_view.cpp`: a table whose columns move
 * with the window cannot be compared against a second reading of itself or
 * against a CLI. */
#define COL_LABEL 20

static QString label_column(const QString &text)
{
	/* LEFT-ALIGNED AND NEVER TRUNCATED. A label cut to fit its column names
	 * a different issuer -- which is the whole hazard this widget refuses
	 * to draw a key for -- so one too wide pushes the row out instead. */
	return text.leftJustified(COL_LABEL, QLatin1Char(' '));
}

fzn_manifest_view::fzn_manifest_view(QWidget *parent)
        : QWidget(parent), state_(NOTHING), understated_(0u), rows_truncated_(false),
          summary_(new QLabel(this)), rows_(new QLabel(this))
{
	QFormLayout *form = new QFormLayout(this);

	form->addRow(QStringLiteral("Revocations"), summary_);
	form->addRow(QStringLiteral("Issuers"), rows_);

	summary_->setWordWrap(true);
	/* THE ROWS MUST NOT WRAP. Their alignment is in the string, and a
	 * wrapped row folds one issuer's verdict under another's label. */
	rows_->setWordWrap(false);
	rows_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));

	show_issuers(nullptr, nullptr, 0u);
}

void fzn_manifest_view::show_issuers(const fzn_manifest_state_t *state,
                                     const fzn_manifest_view_row *rows, size_t count)
{
	QString drawn_rows;
	size_t drawn = 0u;
	size_t understated = 0u;
	size_t pending_rows = 0u;
	size_t asked = 0u;
	size_t i;

	state_ = NOTHING;
	understated_ = 0u;
	rows_truncated_ = false;

	if (!state || !rows || !count) {
		/* NOT "UP TO DATE". A host with no manifest state is tracking
		 * nothing, and `cli/manifest_print` refuses the same reading
		 * for the same reason: a zero where there is nothing to measure
		 * is read as a measurement. */
		summary_->setText(QStringLiteral("nothing is being tracked"));
		rows_->setText(QString());
		return;
	}

	for (i = 0u; i < count; i++) {
		char line[FZN_MANIFEST_PRINT_MAX];
		fzn_manifest_line_t said = FZN_MANIFEST_LINE_NONE;
		size_t len = 0u;

		if (!rows[i].issuer)
			continue;
		/* ONE DECISION AND ONE WORDING, BOTH THE PRINTER'S. sec 193.
		 * The row is the printer's line verbatim; what this widget adds
		 * is that there are several of them and which is worst. */
		if (fzn_manifest_print(state, rows[i].issuer, line, sizeof(line), &len, &said) !=
		    FZN_MANIFEST_OK)
			continue;

		asked++;
		if (said == FZN_MANIFEST_LINE_UNDERSTATED)
			understated++;
		else if (said == FZN_MANIFEST_LINE_PENDING)
			pending_rows++;

		if (drawn >= FZN_MANIFEST_VIEW_ROWS_MAX) {
			rows_truncated_ = true;
			continue;
		}
		if (drawn)
			drawn_rows += QLatin1Char('\n');
		drawn_rows += label_column(rows[i].label) + QString::fromLatin1(line).trimmed();
		drawn++;
	}

	understated_ = understated;

	if (!asked) {
		summary_->setText(QStringLiteral("nothing is being tracked"));
		rows_->setText(QString());
		return;
	}

	/*
	 * THE WORST ROW DECIDES, NOT THE MAJORITY. manifest.h calls a dropped
	 * pair the one refusal here that fails OPEN, so four sound issuers and
	 * one understated is not "mostly fine": the understated one is the only
	 * row that can be hiding an authority this host still honours.
	 */
	if (understated) {
		state_ = UNDERSTATED;
		summary_->setText(QString::number(static_cast<qulonglong>(understated)) +
		                  QStringLiteral(" of ") +
		                  QString::number(static_cast<qulonglong>(asked)) +
		                  QStringLiteral(" issuers report less than they are missing"));
	} else if (pending_rows) {
		state_ = PENDING;
		summary_->setText(QString::number(static_cast<qulonglong>(pending_rows)) +
		                  QStringLiteral(" of ") +
		                  QString::number(static_cast<qulonglong>(asked)) +
		                  QStringLiteral(" issuers have revocations outstanding"));
	} else {
		state_ = COMPLETE;
		summary_->setText(QStringLiteral("all ") +
		                  QString::number(static_cast<qulonglong>(asked)) +
		                  QStringLiteral(" issuers are up to date"));
	}

	if (rows_truncated_)
		drawn_rows += QStringLiteral("\n(more issuers than this list shows)");

	rows_->setText(drawn_rows);
}

fzn_manifest_view::state fzn_manifest_view::shown_state() const
{
	return state_;
}

QString fzn_manifest_view::summary_text() const
{
	return summary_->text();
}

QString fzn_manifest_view::rows_text() const
{
	return rows_->text();
}

size_t fzn_manifest_view::understated() const
{
	return understated_;
}

bool fzn_manifest_view::rows_truncated() const
{
	return rows_truncated_;
}
