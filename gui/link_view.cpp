#include "link_view.h"
#include "rpc_ask.h"

#include <QFontDatabase>
#include <QFormLayout>
#include <QScrollArea>
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
	/* A NEGATIVE WIDTH LEFT-ALIGNS, for a word rather than a number. */
	return width < 0 ? text.leftJustified(-width, QLatin1Char(' '))
	                 : text.rightJustified(width, QLatin1Char(' '));
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

	/* THE PATHS SCROLL SIDEWAYS rather than set the view's width, sec 1120:
	 * their rows must not wrap, and as the view's own width they made it
	 * 332 px, past a folding phone's 320 px cover screen. */
	QScrollArea *paths = new QScrollArea(this);
	paths->setWidget(rows_);
	paths->setWidgetResizable(true);
	paths->setFrameShape(QFrame::NoFrame);
	paths->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
	paths->setAccessibleName(QStringLiteral("Paths"));
	form->addRow(QStringLiteral("Links"), summary_);
	form->addRow(QStringLiteral("Paths"), paths);

	summary_->setWordWrap(true);
	/* THE ROWS MUST NOT WRAP. Their alignment is in the string, and a
	 * wrapped row folds one link's numbers under another's. */
	rows_->setWordWrap(false);
	rows_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));

	show_links(nullptr);
}

fzn_link_view::fzn_link_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent)
        : fzn_link_view(parent)
{
	rpc_ = new fzn_gui_rpc;
	fzn_gui_rpc_init(rpc_, ask, ask_ctx);
}

fzn_link_view::~fzn_link_view() { delete rpc_; }

/* A HOSTED ROW'S COLUMNS: where, how fast, how much of what was asked came
 * back, and how long since anything did. */
#define COL_ADDRESS 24
#define COL_ANSWERED 10
#define COL_HEARD 11

bool fzn_link_view::refresh()
{
	if (!rpc_)
		return false;
	auto *legs = new fzn_rpc_link_list_resp_t;
	if (fzn_rpc_link_list(&rpc_->c, legs) != FZN_RPC_OK) {
		summary_->setText(QString::fromUtf8(fzn_gui_rpc_silent(rpc_)));
		rows_->setText(QString());
		delete legs;
		return rpc_->c.answered;
	}
	size_t answering = 0, i;
	QString rows = column(QStringLiteral("address"), -COL_ADDRESS)
	               + column(QStringLiteral("rtt"), COL_LATENCY)
	               + column(QStringLiteral("loss"), COL_LOSS)
	               + column(QStringLiteral("answered"), COL_ANSWERED)
	               + column(QStringLiteral("heard"), COL_HEARD);
	for (i = 0; i < legs->count; i++) {
		const fzn_rpc_link_entry_t *l = &legs->entries[i];
		answering += l->replied > 0;
		if (i >= FZN_LINK_VIEW_ROWS_MAX)
			continue;
		rows += QLatin1Char('\n')
		        + column(QString::fromUtf8(l->address, (int)l->address_len), -COL_ADDRESS)
		        + column(l->replied ? QString::number(l->rtt_ms) + QStringLiteral(" ms")
		                            : QStringLiteral("-"),
		                 COL_LATENCY)
		        /* THE NODE'S ESTIMATE, where it has observed anything (sec
		         * 1125); a dash where it has not, a loss nobody saw not being
		         * a rate -- the model-fed rows' rule. */
		        + column(l->observations ? QString::number(l->loss_permille / 10u) + QStringLiteral(".")
		                                           + QString::number(l->loss_permille % 10u)
		                                           + QStringLiteral("%")
		                                 : QStringLiteral("-"),
		                 COL_LOSS)
		        + column(QStringLiteral("%1/%2").arg(l->replied).arg(l->sent), COL_ANSWERED)
		        + column(l->replied ? QString::number(l->since_success_ms / 1000u)
		                                      + QStringLiteral(" s ago")
		                            : QStringLiteral("never"),
		                 COL_HEARD);
	}
	/* THE SAME FOUR STATES as a table handed in, from what the node said:
	 * no leg, or legs none of which has answered, or some that have. */
	state_ = !legs->count ? NONE : answering ? MEASURED : UNMEASURED;
	unmeasured_ = legs->count - answering;
	rows_truncated_ = legs->count > FZN_LINK_VIEW_ROWS_MAX;
	QString said = QStringLiteral("%1 link(s), %2 answering").arg(legs->count).arg(answering);
	if (rows_truncated_)
		said += QStringLiteral(", %1 not drawn").arg(legs->count - FZN_LINK_VIEW_ROWS_MAX);
	summary_->setText(legs->count ? said : QStringLiteral("no links"));
	rows_->setText(legs->count ? rows : QString());
	delete legs;
	return true;
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
