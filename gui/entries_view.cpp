/* See entries_view.h. */

#include "entries_view.h"

extern "C" {
#include "../log/entry.h"
#include "../log/view.h"
}

#include <QCheckBox>
#include <QComboBox>
#include <QFont>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QVBoxLayout>

#include <cstring>
#include <ctime>

int fzn_entries_view_dir_ask(void *ctx, const uint8_t *request, size_t request_len,
                             uint8_t *reply, size_t reply_cap, size_t *reply_len)
{
	if (!ctx || !reply_len)
		return 0;
	*reply_len = fzn_gather_answer((const char *)ctx, request, request_len, reply, reply_cap);
	return *reply_len > 0u;
}

/* The spans the chooser offers, in seconds; 0 is everything. */
static const unsigned long SPANS[] = { 0ul, 3600ul, 86400ul, 7ul * 86400ul };
static const char *const SPAN_NAMES[] = { "Everything", "The last hour", "The last day",
	                                  "The last week" };

fzn_entries_view::fzn_entries_view(fzn_gather_ask_t ask, void *ask_ctx, QWidget *parent)
        : QWidget(parent), m_ask(ask), m_ask_ctx(ask_ctx)
{
	auto *outer = new QVBoxLayout(this);
	auto *row = new QHBoxLayout();
	size_t i;

	m_program = new QLineEdit(QStringLiteral("fuzznetd"), this);
	m_program->setPlaceholderText(QStringLiteral("Program"));
	m_match = new QLineEdit(this);
	m_match->setPlaceholderText(QStringLiteral("Lines holding (an instance field gives what "
	                                           "it caused)"));
	m_span = new QComboBox(this);
	for (i = 0; i < sizeof(SPANS) / sizeof(SPANS[0]); i++)
		m_span->addItem(QString::fromLatin1(SPAN_NAMES[i]), QVariant::fromValue(SPANS[i]));
	m_short = new QCheckBox(QStringLiteral("Short"), this);
	m_short->setChecked(true);
	m_refresh = new QPushButton(QStringLiteral("Refresh"), this);
	m_text = new QPlainTextEdit(this);
	m_text->setReadOnly(true);
	m_text->setLineWrapMode(QPlainTextEdit::NoWrap);
	/* PLAIN TEXT BY CONSTRUCTION: a log line never renders as rich text,
	 * and the lines are escaped already. */
	m_text->setFont(QFont(QStringLiteral("monospace")));
	m_status = new QLabel(this);
	m_status->setWordWrap(true);

	row->addWidget(m_program);
	row->addWidget(m_match, 1);
	row->addWidget(m_span);
	row->addWidget(m_short);
	row->addWidget(m_refresh);
	outer->addLayout(row);
	outer->addWidget(m_status);
	outer->addWidget(m_text, 1);

	connect(m_refresh, &QPushButton::clicked, this, [this]() { refresh(); });
	connect(m_short, &QCheckBox::toggled, this, [this](bool) { show_lines(); });
	connect(m_span, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
	        [this](int at) { m_since = SPANS[at < 0 ? 0 : at]; });
}

void fzn_entries_view::set_program(const QString &program)
{
	m_program->setText(program);
}

void fzn_entries_view::set_match(const QString &match)
{
	m_match->setText(match);
}

void fzn_entries_view::set_since(unsigned long seconds)
{
	int i, at = -1;

	m_since = seconds;
	for (i = 0; i < m_span->count(); i++)
		if (m_span->itemData(i).toULongLong() == seconds)
			at = i;
	m_span->blockSignals(true);
	m_span->setCurrentIndex(at);
	m_span->blockSignals(false);
}

void fzn_entries_view::set_short(bool on)
{
	m_short->setChecked(on);
	show_lines();
}

static void keep(void *ctx, const char *line, size_t len)
{
	static_cast<QStringList *>(ctx)->append(QString::fromUtf8(line, (int)len));
}

bool fzn_entries_view::refresh()
{
	fzn_gather_query_t q;
	QByteArray program = m_program->text().toUtf8(), match = m_match->text().toUtf8();
	size_t got = 0;
	fzn_gather_err_t err;
	uint64_t now_us = (uint64_t)time(nullptr) * 1000000u;

	m_lines.clear();
	std::memset(&q, 0, sizeof(q));
	if (program.isEmpty() || program.size() > (int)FZN_ENTRY_WORD_MAX
	    || match.size() > (int)FZN_GATHER_MATCH_MAX) {
		m_status->setText(QStringLiteral("A program's name, and a match of at most %1 bytes.")
		                          .arg(FZN_GATHER_MATCH_MAX));
		show_lines();
		return false;
	}
	std::memcpy(q.program, program.constData(), (size_t)program.size());
	std::memcpy(q.match, match.constData(), (size_t)match.size());
	q.since_us = m_since && m_since * 1000000ull < now_us ? now_us - (m_since * 1000000ull) : 0u;
	q.until_us = UINT64_MAX;
	err = m_ask ? fzn_gather_fetch(m_ask, m_ask_ctx, &q, 4096u, keep, &m_lines, &got)
	            : FZN_GATHER_ERR_NO_ANSWER;
	if (err == FZN_GATHER_ERR_NO_ANSWER)
		m_status->setText(QStringLiteral("The host did not answer."));
	else if (err != FZN_GATHER_OK)
		m_status->setText(QStringLiteral("The host's answer was not a log: %1")
		                          .arg(QString::fromLatin1(fzn_gather_err_str(err))));
	else if (m_lines.isEmpty())
		m_status->setText(QStringLiteral("No lines."));
	else
		m_status->setText(QStringLiteral("%1 line(s).").arg(m_lines.size()));
	show_lines();
	return err == FZN_GATHER_OK;
}

void fzn_entries_view::show_lines()
{
	static uint8_t text_a[FZN_ENTRY_TEXT_MAX], text_b[FZN_ENTRY_TEXT_MAX];
	static char shown[FZN_ENTRY_LINE_MAX + 64u];
	static const uint8_t no_machine[FZN_ENTRY_MACHINE_LEN] = { 0 };
	QString all;
	fzn_entry_t cur, prev;
	char cur_host[FZN_ENTRY_WORD_MAX + 1u], prev_host[FZN_ENTRY_WORD_MAX + 1u];
	bool have_prev = false;
	int k;

	for (k = 0; k < m_lines.size(); k++) {
		QByteArray line = m_lines[k].toUtf8();
		size_t len = 0;

		/* SHORTENED WHEN ASKED, a line that will not read shown whole. */
		if (m_short->isChecked()
		    && fzn_entry_classic_parse(line.constData(), (size_t)line.size(), no_machine, &cur,
		                               cur_host, k % 2 ? text_b : text_a, FZN_ENTRY_TEXT_MAX)
		               == FZN_ENTRY_OK
		    && fzn_entry_view(have_prev ? &prev : nullptr, prev_host, &cur, cur_host, shown,
		                      sizeof(shown), &len)
		               == FZN_ENTRY_OK) {
			all += QString::fromUtf8(shown, (int)len);
			prev = cur;
			std::memcpy(prev_host, cur_host, sizeof(prev_host));
			have_prev = true;
		} else {
			all += m_lines[k] + QLatin1Char('\n');
		}
	}
	m_text->setPlainText(all);
}

QString fzn_entries_view::text() const
{
	return m_text->toPlainText();
}

QString fzn_entries_view::status() const
{
	return m_status->text();
}
