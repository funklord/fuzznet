#include "link_view.h"

#include <QFontDatabase>
#include <QFormLayout>
#include <QLabel>

/* Column widths, fixed so the rows line up in the string rather than in a
 * layout. See the header: a table whose columns move with the window cannot
 * be compared against a second reading of itself or against a CLI. */
#define COL_ID 6
#define COL_USE 5
#define COL_LATENCY 10
#define COL_LOSS 8
#define COL_SAMPLES 10

static QString column(const QString &text, int width)
{
	/* RIGHT-ALIGNED, AND NEVER TRUNCATED. A number cut to fit its column
	 * is a different number, so a value too wide pushes the row out
	 * instead -- one ugly row beats one wrong one. */
	return text.rightJustified(width, QLatin1Char(' '));
}

static QString row_for(const fzn_link_entry_t *e)
{
	QString row;

	row += column(QString::number(e->id), COL_ID);
	row += column(e->usable ? QStringLiteral("yes") : QStringLiteral("no"), COL_USE);
	row += column(QString::number(e->latency_ms) + QStringLiteral(" ms"), COL_LATENCY);

	if (!e->observations) {
		/* THE ROW IS THE POINT OF THIS WIDGET. `fzn_link_print` can say
		 * that N usable links are on a declared metric; only a row can
		 * say WHICH, and an operator taking a path out of service needs
		 * that. The loss column is a dash rather than the declared
		 * figure because a loss nobody has observed is not a rate. */
		row += column(QStringLiteral("-"), COL_LOSS);
		row += column(QStringLiteral("declared"), COL_SAMPLES);
		return row;
	}

	row += column(QString::number(e->loss_permille / 10u) + QStringLiteral(".") +
	                      QString::number(e->loss_permille % 10u) + QStringLiteral("%"),
	              COL_LOSS);
	row += column(QString::number(static_cast<qulonglong>(e->observations)), COL_SAMPLES);
	return row;
}

QString fzn_link_view::rows_text() const
{
	return rows_->text();
}

fzn_link_view::fzn_link_view(QWidget *parent)
        : QWidget(parent), state_(NONE), unmeasured_(0u), rows_truncated_(false),
          summary_(new QLabel(this)), rows_(new QLabel(this))
{
	QFormLayout *form = new QFormLayout(this);

	form->addRow(QStringLiteral("Links"), summary_);
	form->addRow(QStringLiteral("Paths"), rows_);

	summary_->setWordWrap(true);
	/* THE ROWS MUST NOT WRAP. Their alignment is in the string, and a
	 * wrapped row folds one link's numbers under another's. */
	rows_->setWordWrap(false);
	rows_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));

	show_links(nullptr);
}

void fzn_link_view::show_links(const fzn_link_table_t *table)
{
	char line[FZN_LINK_PRINT_MAX];
	fzn_link_line_t said = FZN_LINK_LINE_NONE;
	size_t len = 0u;
	size_t unmeasured = 0u;
	QString rows;
	size_t drawn = 0u;
	size_t i;

	state_ = NONE;
	unmeasured_ = 0u;
	rows_truncated_ = false;

	/* ONE DECISION AND ONE WORDING, BOTH THE PRINTER'S. sec 193. */
	if (fzn_link_print(table, line, sizeof(line), &len, &said, &unmeasured) !=
	    FZN_LINK_OK) {
		summary_->setText(QStringLiteral("no links"));
		rows_->setText(QString());
		return;
	}

	summary_->setText(QString::fromLatin1(line));
	unmeasured_ = unmeasured;

	switch (said) {
	case FZN_LINK_LINE_NONE:
		state_ = NONE;
		break;
	case FZN_LINK_LINE_ALL_DOWN:
		state_ = ALL_DOWN;
		break;
	case FZN_LINK_LINE_UNMEASURED:
		state_ = UNMEASURED;
		break;
	case FZN_LINK_LINE_MEASURED:
		state_ = MEASURED;
		break;
	}

	/* NO HEADER OVER NO ROWS. A column header with nothing under it reads
	 * as a table that failed to load rather than as a host with no path,
	 * and the summary has already said which. */
	if (!table || !table->entries || !table->used) {
		rows_->setText(QString());
		return;
	}

	rows = column(QStringLiteral("id"), COL_ID) +
	       column(QStringLiteral("use"), COL_USE) +
	       column(QStringLiteral("latency"), COL_LATENCY) +
	       column(QStringLiteral("loss"), COL_LOSS) +
	       column(QStringLiteral("samples"), COL_SAMPLES);

	for (i = 0u; i < table->used; i++) {
		if (drawn >= FZN_LINK_VIEW_ROWS_MAX) {
			rows_truncated_ = true;
			break;
		}
		rows += QLatin1Char('\n') + row_for(&table->entries[i]);
		drawn++;
	}

	if (rows_truncated_) {
		/* SAID ON THE SCREEN AS WELL AS IN THE ACCESSOR, because the
		 * person who needs to know is looking at the rows and will not
		 * call `rows_truncated`. */
		rows += QLatin1Char('\n') +
		        QStringLiteral("... %1 more not shown")
		                .arg(static_cast<qulonglong>(table->used - drawn));
	}

	rows_->setText(rows);
}

fzn_link_view::state fzn_link_view::shown_state() const
{
	return state_;
}

QString fzn_link_view::summary_text() const
{
	return summary_->text();
}

size_t fzn_link_view::unmeasured() const
{
	return unmeasured_;
}

bool fzn_link_view::rows_truncated() const
{
	return rows_truncated_;
}
