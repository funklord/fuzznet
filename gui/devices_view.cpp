/* Adding a device to this user's hosts, as a widget: gui/devices_view.h, sec 1122. */
#include "devices_view.h"
#include "choose_accessible.h"
#include "keep_place.h"

#include "camera_feed.h"
#include "qr_view.h"
#include "rpc_ask.h"

#include <QByteArray>
#include <QFileDialog>
#include <QImage>
#include <QCheckBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTextOption>
#include <QTimer>
#include <QVBoxLayout>
#include <QVector>

#include <string.h>

#ifdef FZN_QR_DECODE_ON
#include "../qr/decode.h"
#endif
extern "C" {
#include "../node/invite.h"
}

/* The most devices listed as waiting at once: a code is good for ten
 * minutes, and each waiting device is one person's to answer. */
#define WAITING_MAX 64u

/* A LOOK A SECOND for the five minutes the node goes on asking. */
#define JOIN_LOOK_MS 1000
/* HOW LONG A LOOK WAITS for hosts to answer before listing them, sec 1288:
 * an answer on one network comes back in milliseconds. */
#define FOUND_WAIT_MS 1500
/* An offer's window, fuzznet's default. */
#define OFFER_S 300u
#define FOUND_MAX 16
#define JOIN_LOOKS 300

struct fzn_devices_view::keys {
	QVector<QByteArray> waiting; /* each waiting device's key, 32 bytes */
	uint8_t before[32];          /* whom this host served as when it joined */
};

static QString failed_words(const fzn_gui_rpc *r)
{
	return QString::fromUtf8(fzn_gui_rpc_silent(r));
}

fzn_devices_view::fzn_devices_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent)
    : QWidget(parent), m_rpc(new fzn_gui_rpc), m_keys(new keys), m_scanner(nullptr), m_scan_width(0),
      m_scan_height(0), m_join_looks(0)
{
	fzn_gui_rpc_init(m_rpc, ask, ask_ctx);

	/* THE CODE, sec 1409: some 150 characters with no space, which a
	 * label's word wrap cannot break, so the page scrolled sideways at a
	 * phone's width (fuzzypickles, fuzznet inbox 20261123T1250Z). Read-only
	 * text wrapping anywhere keeps it inside the width and selectable
	 * whole; hidden until there is a code. */
	m_code = new QPlainTextEdit(this);
	m_code->setReadOnly(true);
	m_code->setLineWrapMode(QPlainTextEdit::WidgetWidth);
	m_code->setWordWrapMode(QTextOption::WrapAnywhere);
	m_code->setAccessibleName(tr("The code for the new device"));
	m_code->setMaximumHeight(m_code->fontMetrics().lineSpacing() * 4 + 2 * m_code->frameWidth() + 8);
	m_code->hide();
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
	m_join_code = new QLineEdit(this);
	m_join_code->setPlaceholderText(QStringLiteral("FZI1:..."));
	m_join_code->setAccessibleName(tr("A code from another of your hosts"));
	m_join = new QPushButton(tr("Join"), this);
	m_join->setAccessibleName(tr("Join with that code"));
	m_scan_file = new QPushButton(tr("Scan a picture..."), this);
	m_scan_file->setAccessibleName(tr("Join with the code in a picture"));
	m_scan_file->setEnabled(can_scan());
	m_scan_camera = new QPushButton(tr("Scan with the camera"), this);
	m_scan_camera->setAccessibleName(tr("Join with a code the camera sees"));
	m_scan_camera->setEnabled(can_scan() && fzn_camera_feed::built());
	m_camera = new fzn_camera_feed(
	        this,
	        [this](const QImage &frame) {
		        if (scan_frame(frame))
			        stop_camera();
	        },
	        [this]() {
		        m_scan_camera->setText(tr("Scan with the camera"));
		        m_status->setText(m_camera->why());
	        });
	/* A CODE TO READ, not a face to show: the luma plane is enough. */
	m_camera->set_gray(true);
	m_offer = new QPushButton(tr("Let a device on this network find this host"), this);
	m_look = new QPushButton(tr("Look for my hosts on this network"), this);
	m_found = new QListWidget(this);
	m_found->setAccessibleName(tr("Hosts found on this network"));
	m_found->hide();
	m_join_found = new QPushButton(tr("Ask to join the host chosen"), this);
	m_join_found->hide();
	m_look_timer = new QTimer(this);
	m_look_timer->setSingleShot(true);
	m_look_timer->setInterval(FOUND_WAIT_MS);
	m_join_timer = new QTimer(this);
	m_join_timer->setInterval(JOIN_LOOK_MS);
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
	/* NO CODE CARRIED, sec 1288: on one network, the device finds this
	 * host itself. A row of its own, a phone's width. */
	col->addWidget(m_offer);
	col->addWidget(m_code);
	col->addWidget(m_qr);
	col->addWidget(m_confirm);
	col->addWidget(m_confirm_note);
	col->addWidget(new QLabel(tr("Waiting to join"), this));
	col->addWidget(m_waiting, 1);
	col->addLayout(answer_row);
	auto *joining = new QLabel(tr("Or join this device to your other hosts with their code:"), this);
	joining->setWordWrap(true);
	col->addWidget(joining);
	auto *join_row = new QHBoxLayout;
	join_row->addWidget(m_join_code, 1);
	join_row->addWidget(m_join);
	/* A ROW OF ITS OWN: beside the code and Join, they made the view wider
	 * than a phone. */
	auto *scan_row = new QHBoxLayout;
	scan_row->addWidget(m_scan_camera);
	scan_row->addWidget(m_scan_file);
	scan_row->addStretch(1);
	col->addLayout(join_row);
	col->addLayout(scan_row);
	col->addWidget(m_look);
	col->addWidget(m_found);
	col->addWidget(m_join_found);
	col->addWidget(m_status);

	connect(m_invite, &QPushButton::clicked, [this]() { invite(); });
	/* A CLICK, not a toggle: setting the box from what the node said must
	 * not write it back. */
	connect(m_confirm, &QCheckBox::clicked, [this](bool on) { set_confirm(on); });
	connect(m_waiting, &QListWidget::currentRowChanged, [this](int r) { select_waiting(r); });
	/* A SCREEN READER CHOOSES TOO, sec 1423: its double tap only selects. */
	fzn_choose_on_accessible_select(m_waiting, nullptr);
	connect(m_let_in, &QPushButton::clicked, [this]() { answer(true); });
	connect(m_turn_away, &QPushButton::clicked, [this]() { answer(false); });
	connect(m_refresh, &QPushButton::clicked, [this]() { refresh(); });
	connect(m_join, &QPushButton::clicked, [this]() { join(m_join_code->text()); });
	connect(m_join_timer, &QTimer::timeout, [this]() { poll_join(); });
	connect(m_offer, &QPushButton::clicked, [this]() { m_offering ? end_offer() : offer(); });
	/* THE WINDOW CLOSES OF ITSELF on the node's side; the button follows. */
	m_offer_timer = new QTimer(this);
	m_offer_timer->setSingleShot(true);
	m_offer_timer->setInterval(OFFER_S * 1000);
	connect(m_offer_timer, &QTimer::timeout, [this]() {
		m_offering = false;
		m_offer->setText(tr("Let a device on this network find this host"));
	});
	connect(m_look, &QPushButton::clicked, [this]() { look(); });
	connect(m_look_timer, &QTimer::timeout, [this]() { show_found(); });
	connect(m_join_found, &QPushButton::clicked, [this]() { join_found(m_found->currentRow()); });
	connect(m_scan_camera, &QPushButton::clicked, [this]() {
		if (camera_running())
			stop_camera();
		else
			scan_camera();
	});
	connect(m_scan_file, &QPushButton::clicked, [this]() {
		QString path = QFileDialog::getOpenFileName(this, tr("A picture of the code"), QString(),
		                                            tr("Pictures (*.png *.jpg *.jpeg *.bmp *.webp)"));
		if (!path.isEmpty())
			scan_file(path);
	});
	m_qr->hide();
	select_waiting(-1);
}

fzn_devices_view::~fzn_devices_view()
{
	delete m_camera;
#ifdef FZN_QR_DECODE_ON
	fzn_qr_scanner_free(m_scanner);
#endif
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
	fzn_keep_answer answer(m_status);

	if (fzn_rpc_device_confirm_get(&m_rpc->c, &on) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		fzn_keep_answer::said(m_status);
		return m_rpc->c.answered;
	}
	m_confirm->setChecked(on != 0);
	m_confirm_note->setText(confirm_words(on != 0));
	if (fzn_rpc_device_waiting(&m_rpc->c, keys, WAITING_MAX, &count) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		fzn_keep_answer::said(m_status);
		return m_rpc->c.answered;
	}
	/* THE PERSON'S PLACE AND THEIR LAST ANSWER, kept across the refill
	 * (sec 1225). */
	fzn_keep_place place(m_waiting);
	m_waiting->clear();
	m_keys->waiting.clear();
	for (i = 0; i < count; i++) {
		m_waiting->addItem(QString::fromLatin1(QByteArray((const char *)keys[i], 8).toHex()));
		m_keys->waiting.append(QByteArray((const char *)keys[i], 32));
	}
	m_status->setText(count ? QString() : tr("No device is waiting to join."));
	select_waiting(place.restore());
	answer.restore();
	return true;
}

bool fzn_devices_view::invite()
{
	char code[512];

	if (fzn_rpc_device_invite(&m_rpc->c, code, sizeof code) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	m_code->setPlainText(QString::fromLatin1(code));
	m_code->show();
	/* M: a code photographed off a screen, at arm's length. */
	m_qr->show_text(QString::fromLatin1(code), FZN_QR_LEVEL_M);
	m_qr->show();
	m_status->setText(tr("Give this code to the new device within ten minutes."));
	return true;
}

bool fzn_devices_view::offer()
{
	if (fzn_rpc_device_offer(&m_rpc->c, OFFER_S) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	m_status->setText(tr("For five minutes, a device on this network that looks for hosts finds this "
	                     "one. It waits under \"Waiting to join\" until you let it in: compare the key "
	                     "it shows with the one listed here."));
	m_offering = true;
	m_offer->setText(tr("Stop letting devices find this host"));
	m_offer_timer->start();
	refresh();
	return true;
}

bool fzn_devices_view::end_offer()
{
	if (fzn_rpc_device_offer_end(&m_rpc->c) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	m_offering = false;
	m_offer_timer->stop();
	m_offer->setText(tr("Let a device on this network find this host"));
	m_status->setText(tr("No device on this network finds this host now."));
	return true;
}

bool fzn_devices_view::look()
{
	m_found->clear();
	m_found_codes.clear();
	m_found->hide();
	m_join_found->hide();
	if (fzn_rpc_device_look(&m_rpc->c) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	m_status->setText(tr("Looking for hosts on this network..."));
	m_look_timer->start();
	return true;
}

int fzn_devices_view::show_found()
{
	fzn_rpc_offer_t hosts[FOUND_MAX];
	size_t n = 0;

	if (fzn_rpc_device_found(&m_rpc->c, hosts, FOUND_MAX, &n) != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return 0;
	}
	m_found->clear();
	m_found_codes.clear();
	for (size_t i = 0; i < n; i++) {
		/* THE NAME AND THE KEY, so a person compares the key with what the
		 * host shows before asking it -- a name anyone can claim. */
		m_found->addItem(tr("%1 -- key %2").arg(QString::fromUtf8(hosts[i].name),
		                                        QString::fromLatin1(hosts[i].fingerprint)));
		m_found_codes << QString::fromLatin1(hosts[i].code);
	}
	m_found->setVisible(n > 0);
	m_join_found->setVisible(n > 0);
	if (n)
		m_found->setCurrentRow(0);
	m_status->setText(n ? tr("Choose your host, check its key, and ask to join.")
	                    : tr("No host on this network is letting devices find it. On the host, choose "
	                         "\"Let a device on this network find this host\", then look again."));
	return (int)n;
}

bool fzn_devices_view::join_found(int row)
{
	if (row < 0 || row >= m_found_codes.size())
		return false;
	return join(m_found_codes[row]);
}

QStringList fzn_devices_view::found() const
{
	QStringList rows;

	for (int i = 0; i < m_found->count(); i++)
		rows << m_found->item(i)->text();
	return rows;
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
	/* NOTHING CHOSEN CLEARS THE ROW TOO: an act reads the current row, and a
	 * refresh no longer clears it (sec 1225). */
	if (!chosen && m_waiting->currentRow() >= 0)
		m_waiting->setCurrentRow(-1);
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

bool fzn_devices_view::join(const QString &code)
{
	QByteArray text = code.trimmed().toLatin1();

	if (fzn_rpc_device_join_begin(&m_rpc->c, text.constData(), (size_t)text.size(), m_keys->before)
	    != FZN_RPC_OK) {
		m_status->setText(failed_words(m_rpc));
		return false;
	}
	m_join->setEnabled(false);
	m_join_looks = JOIN_LOOKS;
	m_join_timer->start();
	m_status->setText(tr("Asking the code's host. This can take a few minutes."));
	return true;
}

int fzn_devices_view::poll_join()
{
	int joined = 0;

	if (!m_join_looks)
		return 0;
	(void)fzn_rpc_device_joined(&m_rpc->c, m_keys->before, &joined);
	if (joined) {
		m_join_looks = 0;
		m_join_timer->stop();
		m_join->setEnabled(true);
		m_join_code->clear();
		m_status->setText(tr("This device is one of your hosts now."));
		return 1;
	}
	if (--m_join_looks == 0) {
		m_join_timer->stop();
		m_join->setEnabled(true);
		m_status->setText(tr("The code's host did not answer. Make a new code there and try again."));
	}
	return 0;
}

bool fzn_devices_view::can_scan()
{
#ifdef FZN_QR_DECODE_ON
	return true;
#else
	return false;
#endif
}

bool fzn_devices_view::scan_frame(const QImage &frame)
{
#ifdef FZN_QR_DECODE_ON
	uint8_t text[FZN_INVITE_TEXT_MAX + 64u];
	unsigned w = (unsigned)frame.width(), h = (unsigned)frame.height();
	QImage gray;
	QByteArray rows;
	int n;

	/* A JOIN UNDER WAY takes no second code: the frames that follow the one
	 * read are the same code, again and again. */
	if (m_join_looks || frame.isNull())
		return false;
	gray = frame.convertToFormat(QImage::Format_Grayscale8);
	if (!m_scanner || m_scan_width != w || m_scan_height != h) {
		fzn_qr_scanner_free(m_scanner);
		m_scanner = fzn_qr_scanner_new(w, h);
		m_scan_width = m_scanner ? w : 0;
		m_scan_height = m_scanner ? h : 0;
		if (!m_scanner)
			return false;
	}
	/* ROWS END TO END, as the decoder reads them: a QImage pads each row to
	 * four bytes. */
	rows.resize((int)(w * h));
	for (unsigned y = 0; y < h; y++)
		memcpy(rows.data() + (size_t)y * w, gray.constScanLine((int)y), w);
	n = fzn_qr_scan_frame(m_scanner, (const uint8_t *)rows.constData(), w, h, text, sizeof(text));
	if (n <= 0)
		return false;
	if ((size_t)n < sizeof(FZN_INVITE_TEXT_PREFIX) - 1u
	    || memcmp(text, FZN_INVITE_TEXT_PREFIX, sizeof(FZN_INVITE_TEXT_PREFIX) - 1u)) {
		m_status->setText(tr("That code is not a join code. Scan the code shown under \"Make a code\" on your other host."));
		return false;
	}
	m_join_code->setText(QString::fromLatin1((const char *)text, n));
	return join(m_join_code->text());
#else
	(void)frame;
	m_status->setText(tr("This build cannot read a code from a picture. Type the code instead."));
	return false;
#endif
}

bool fzn_devices_view::scan_camera()
{
	if (!can_scan()) {
		m_status->setText(tr("This build cannot read a code from a picture. Type the code instead."));
		return false;
	}
	if (!m_camera->start()) {
		m_status->setText(m_camera->why());
		return false;
	}
	m_scan_camera->setText(tr("Stop the camera"));
	m_status->setText(tr("Point the camera at the code on your other host."));
	return true;
}

void fzn_devices_view::stop_camera()
{
	m_camera->stop();
	m_scan_camera->setText(tr("Scan with the camera"));
}

bool fzn_devices_view::camera_running() const { return m_camera->running(); }

bool fzn_devices_view::scan_file(const QString &path)
{
	QImage picture(path);

	if (picture.isNull()) {
		m_status->setText(tr("That file is not a picture this program can read."));
		return false;
	}
	if (m_join_looks)
		return false;
	/* CLEARED FIRST, so a scan that found nothing is told from one that
	 * said why. */
	m_status->clear();
	if (scan_frame(picture))
		return true;
	if (m_status->text().isEmpty())
		m_status->setText(tr("No code was found in that picture."));
	return false;
}

QString fzn_devices_view::code() const { return m_code->toPlainText(); }

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
