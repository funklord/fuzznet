/* Adding a device to this user's hosts, as a widget: gui/devices_view.h, sec 1122. */
#include "devices_view.h"

#include "qr_view.h"
#include "rpc_ask.h"

#include <QByteArray>
#include <QCheckBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QListWidget>
#include <QPushButton>
#include <QVBoxLayout>
#include <QVector>

#include <string.h>

/* The most devices listed as waiting at once: a code is good for ten
 * minutes, and each waiting device is one person's to answer. */
#define WAITING_MAX 64u

struct fzn_devices_view::keys {
	QVector<QByteArray> waiting; /* each waiting device's key, 32 bytes */
};

static QString failed_words(const fzn_gui_rpc *r)
{
	return QString::fromUtf8(fzn_gui_rpc_silent(r));
}

fzn_devices_view::fzn_devices_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent)
    : QWidget(parent), m_rpc(new fzn_gui_rpc), m_keys(new keys)
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);

	m_code = new QLabel(this);
	m_code->setWordWrap(true);
	m_code->setTextInteractionFlags(Qt::TextSelectableByMouse);
	m_qr = new fzn_qr_view(this);
	m_invite = new QPushButton(tr("Make a code"), this);
	m_invite->setAccessibleName(tr("Make a code for a new device"));
	m_confirm = new QCheckBox(tr("Ask me before a device joins"), this);
	m_confirm_note = new QLabel(this);
	m_confirm_note->setWordWrap(true);
	m_waiting = new QListWidget(this);
	m_waiting->setAccessibleName(tr("Devices waiting to join"));
	m_let_in = new QPushButton(tr("Let in"), this);
	m_turn_away = new QPushButton(tr("Turn away"), this);
	m_refresh = new QPushButton(tr("Refresh"), this);
	m_status = new QLabel(this);
	m_status->setWordWrap(true);

	auto *make = new QHBoxLayout;
	make->addWidget(m_invite);
	make->addStretch(1);
	auto *answer_row = new QHBoxLayout;
	answer_row->addWidget(m_let_in);
	answer_row->addWidget(m_turn_away);
	answer_row->addWidget(m_refresh);
	answer_row->addStretch(1);
	/* WRAPPED, so a sentence never sets the view's width (sec 1120). */
	auto *intro = new QLabel(tr("Add a device: give it a code made here."), this);
	intro->setWordWrap(true);
	/* THE EXPIRY A LINE OF ITS OWN: at the end of the sentence above, a
	 * terminal's 80 columns cut it off. */
	auto *expiry = new QLabel(tr("A code is good for ten minutes."), this);
	expiry->setWordWrap(true);
	auto *col = new QVBoxLayout(this);
	col->addWidget(intro);
	col->addWidget(expiry);
	col->addLayout(make);
	col->addWidget(m_code);
	col->addWidget(m_qr);
	col->addWidget(m_confirm);
	col->addWidget(m_confirm_note);
	col->addWidget(new QLabel(tr("Waiting to join"), this));
	col->addWidget(m_waiting, 1);
	col->addLayout(answer_row);
	col->addWidget(m_status);

	connect(m_invite, &QPushButton::clicked, [this]() { invite(); });
	/* A CLICK, not a toggle: setting the box from what the node said must
	 * not write it back. */
	connect(m_confirm, &QCheckBox::clicked, [this](bool on) { set_confirm(on); });
	connect(m_waiting, &QListWidget::currentRowChanged, [this](int r) { select_waiting(r); });
	connect(m_let_in, &QPushButton::clicked, [this]() { answer(true); });
	connect(m_turn_away, &QPushButton::clicked, [this]() { answer(false); });
	connect(m_refresh, &QPushButton::clicked, [this]() { refresh(); });
	m_qr->hide();
	select_waiting(-1);
}

fzn_devices_view::~fzn_devices_view()
{
	delete m_keys;
	delete m_rpc;
}

/* WHAT THE SWITCH MEANS, said beside it: off is anyone holding the code. */
static QString confirm_words(bool on)
{
	return on ? QObject::tr("A device that holds a code waits below until you let it in.")
	          : QObject::tr("Whoever holds a code joins without asking you.");
}

bool fzn_devices_view::refresh()
{
	int on = 0;
	uint8_t keys[WAITING_MAX][32];
	size_t count = 0, i;

	if (fzn_rpc_device_confirm_get(&m_rpc->c, &on) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return m_rpc->c.answered;
	}
	m_confirm->setChecked(on != 0);
	m_confirm_note->setText(confirm_words(on != 0));
	if (fzn_rpc_device_waiting(&m_rpc->c, keys, WAITING_MAX, &count) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return m_rpc->c.answered;
	}
	m_waiting->clear();
	m_keys->waiting.clear();
	for (i = 0; i < count; i++) {
		m_waiting->addItem(QString::fromLatin1(QByteArray((const char *)keys[i], 8).toHex()));
		m_keys->waiting.append(QByteArray((const char *)keys[i], 32));
	}
	m_status->setText(count ? QString() : tr("No device is waiting to join."));
	select_waiting(-1);
	return true;
}

bool fzn_devices_view::invite()
{
	char code[512];

	if (fzn_rpc_device_invite(&m_rpc->c, code, sizeof code) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	m_code->setText(QString::fromLatin1(code));
	/* M: a code photographed off a screen, at arm's length. */
	m_qr->show_text(QString::fromLatin1(code), FZN_QR_LEVEL_M);
	m_qr->show();
	m_status->setText(tr("Give this code to the new device within ten minutes."));
	return true;
}

bool fzn_devices_view::set_confirm(bool on)
{
	/* SHOWN AS ASKED, as a click shows it, and put back if refused. */
	m_confirm->setChecked(on);
	if (fzn_rpc_device_confirm_set(&m_rpc->c, on ? 1 : 0) != FZN_RPC_OK) {
		m_confirm->setChecked(!on);
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	m_confirm->setChecked(on);
	m_confirm_note->setText(confirm_words(on));
	m_status->setText(QString());
	return true;
}

void fzn_devices_view::select_waiting(int row)
{
	bool chosen = row >= 0 && row < m_keys->waiting.size();
	if (chosen && m_waiting->currentRow() != row)
		m_waiting->setCurrentRow(row);
	m_let_in->setEnabled(chosen);
	m_turn_away->setEnabled(chosen);
}

bool fzn_devices_view::answer(bool let_in)
{
	int row = m_waiting->currentRow();
	if (row < 0 || row >= m_keys->waiting.size())
		return false;
	QString who = m_waiting->item(row)->text();
	if (fzn_rpc_device_answer(&m_rpc->c, (const uint8_t *)m_keys->waiting.at(row).constData(),
	                          let_in ? 1 : 0)
	    != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	refresh();
	m_status->setText(let_in ? tr("%1 is let in.").arg(who) : tr("%1 is turned away.").arg(who));
	return true;
}

QString fzn_devices_view::code() const { return m_code->text(); }

bool fzn_devices_view::code_drawn() const { return m_qr->has_code(); }

bool fzn_devices_view::confirm() const { return m_confirm->isChecked(); }

QStringList fzn_devices_view::waiting() const
{
	QStringList out;
	for (int i = 0; i < m_waiting->count(); i++)
		out << m_waiting->item(i)->text();
	return out;
}

QString fzn_devices_view::status() const { return m_status->text(); }
