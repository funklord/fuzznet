#include "sched_view.h"

#include <QFontDatabase>
#include <QFormLayout>
#include <QLabel>

/* Column widths, fixed so the reasons line up in the string rather than in a
 * layout. `gui/link_view.cpp` has the argument. */
#define COL_ID 10
#define COL_COST 22

static QString column(const QString &text, int width)
{
	/* LEFT-ALIGNED AND NEVER TRUNCATED. A cost cut to fit its column is a
	 * different number, so one too wide pushes the row out instead. */
	return text.leftJustified(width, QLatin1Char(' '));
}

/* Why this link is not carrying the class, in the module's own terms. Asked of
 * `fzn_sched_excluded_by` rather than re-derived, so a row cannot disagree
 * with what `fzn_sched_select` skipped. */
static QString reason_for(const fzn_sched_candidate_t &link, const fzn_class_t &wanted)
{
	switch (fzn_sched_excluded_by(&link, &wanted)) {
	case FZN_SCHED_ADMITTED:
		return QStringLiteral("qualifies");
	case FZN_SCHED_EXCLUDED_UNUSABLE:
		return QStringLiteral("down");
	case FZN_SCHED_EXCLUDED_LATENCY:
		return QStringLiteral("too slow");
	case FZN_SCHED_EXCLUDED_LOSS:
		return QStringLiteral("too lossy");
	case FZN_SCHED_EXCLUDED_MTU:
		return QStringLiteral("MTU too small");
	case FZN_SCHED_EXCLUDED_MALFORMED:
		return QStringLiteral("cannot say");
	}
	/* NO `default:` ABOVE, so an exclusion added later fails to compile
	 * rather than rendering as this. */
	return QStringLiteral("cannot say");
}

fzn_sched_view::fzn_sched_view(QWidget *parent)
        : QWidget(parent), state_(NOTHING), unusable_(0u), rows_truncated_(false),
          summary_(new QLabel(this)), rows_(new QLabel(this))
{
	QFormLayout *form = new QFormLayout(this);

	form->addRow(QStringLiteral("Class"), summary_);
	form->addRow(QStringLiteral("Links"), rows_);

	summary_->setWordWrap(true);
	/* THE ROWS MUST NOT WRAP. Their alignment is in the string, and a
	 * wrapped row folds one link's reason under another's id. */
	rows_->setWordWrap(false);
	rows_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));

	show_choice(nullptr, 0u, nullptr, FZN_SCHED_ERR_NONE, 0u);
}

void fzn_sched_view::show_choice(const fzn_sched_candidate_t *links, size_t link_count,
                                 const fzn_class_t *wanted, fzn_sched_err_t err, size_t chosen)
{
	char line[FZN_SCHED_PRINT_MAX];
	size_t len = 0u;
	fzn_sched_line_t said = FZN_SCHED_LINE_NONE;
	QString drawn;
	size_t drawn_rows = 0u;
	size_t i;

	state_ = NOTHING;
	unusable_ = 0u;
	rows_truncated_ = false;

	if (!links || !link_count || !wanted) {
		summary_->setText(QStringLiteral("no links to choose between"));
		rows_->setText(QString());
		return;
	}

	/*
	 * THE PRINTER'S LINE IS THE VERDICT, not a sentence composed here.
	 * sec 193: the fact that several links were excluded and for what is
	 * the printer's to state, and a widget restating it would be a second
	 * wording to keep in step.
	 */
	if (fzn_sched_print(links, link_count, wanted, err, chosen, line, sizeof(line), &len,
	                    &said) != FZN_SCHED_OK) {
		summary_->setText(QStringLiteral("the selection could not be rendered"));
		rows_->setText(QString());
		return;
	}
	summary_->setText(QString::fromLatin1(line).trimmed());
	state_ = (said == FZN_SCHED_LINE_CHOSEN) ? CARRIED : DROPPED;

	for (i = 0; i < link_count; i++) {
		QString reason;

		if (fzn_sched_excluded_by(&links[i], wanted) != FZN_SCHED_ADMITTED)
			unusable_++;

		if (drawn_rows >= (size_t)FZN_SCHED_VIEW_ROWS_MAX) {
			rows_truncated_ = true;
			continue;
		}

		/* THE CHOSEN LINK SAYS SO RATHER THAN "qualifies", because on a
		 * table where three qualify a reader needs to see which one is
		 * carrying the traffic without comparing costs by eye. */
		if (state_ == CARRIED && i == chosen)
			reason = QStringLiteral("CARRYING");
		else
			reason = reason_for(links[i], *wanted);

		if (drawn_rows > 0u)
			drawn += QLatin1Char('\n');
		drawn += column(QStringLiteral("link ") + QString::number(links[i].id), COL_ID)
		         + column(QStringLiteral("cost ")
		                          + QString::number(fzn_sched_cost(&links[i], wanted)),
		                  COL_COST)
		         + reason;
		drawn_rows++;
	}

	rows_->setText(drawn);
}

fzn_sched_view::state fzn_sched_view::shown_state() const
{
	return state_;
}

QString fzn_sched_view::summary_text() const
{
	return summary_->text();
}

QString fzn_sched_view::rows_text() const
{
	return rows_->text();
}

size_t fzn_sched_view::unusable() const
{
	return unusable_;
}

bool fzn_sched_view::rows_truncated() const
{
	return rows_truncated_;
}
