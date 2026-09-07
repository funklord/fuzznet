#include "qr_view.h"

#include <QPaintEvent>
#include <QPainter>

#include <string.h>

/* One module is at least this many pixels, so a code has somewhere to be
 * drawn before a layout has decided anything. Three rather than one because a
 * one-pixel module is a code no camera resolves and no cell grid can halve. */
static const int FZN_QR_VIEW_MIN_MODULE = 3;

fzn_qr_view::fzn_qr_view(QWidget *parent) : QWidget(parent), size_(0)
{
	memset(modules_, 0, sizeof(modules_));
}

void fzn_qr_view::show_text(const QString &text, fzn_qr_level_t level)
{
	const QByteArray utf8 = text.toUtf8();
	size_t produced = 0;
	fzn_qr_err_t err;

	size_ = 0;
	message_.clear();
	if (utf8.isEmpty()) {
		/* NOBODY ASKED, which is not the same as a refusal and must not
		 * read like one. */
		update();
		return;
	}

	err = fzn_qr_encode(utf8.constData(), (size_t)utf8.size(), level, modules_,
	                    sizeof(modules_), &produced);
	if (err != FZN_QR_OK) {
		/* THE LIBRARY'S OWN WORDS. A widget that invented its own
		 * wording would give a consumer a second vocabulary for the
		 * same refusal, and a user comparing a dialog against a log
		 * would be comparing two spellings of one fact. */
		message_ = QString::fromUtf8(fzn_qr_err_str(err));
		update();
		return;
	}

	size_ = (int)produced;
	update();
}

bool fzn_qr_view::has_code() const
{
	return size_ > 0;
}

int fzn_qr_view::modules_across() const
{
	return size_;
}

QString fzn_qr_view::message_text() const
{
	return message_;
}

int fzn_qr_view::preferred_side() const
{
	if (size_ <= 0)
		return 0;
	return (size_ + 2 * (int)FZN_QR_QUIET) * FZN_QR_VIEW_MIN_MODULE;
}

QSize fzn_qr_view::minimumSizeHint() const
{
	/* A WIDGET WITH NO CODE STILL NEEDS A MINIMUM, or a layout gives it
	 * nothing and the message never appears. */
	if (size_ <= 0)
		return QSize(FZN_QR_VIEW_MIN_MODULE * 8, FZN_QR_VIEW_MIN_MODULE * 4);
	return QSize(preferred_side(), preferred_side());
}

QSize fzn_qr_view::sizeHint() const
{
	return minimumSizeHint();
}

void fzn_qr_view::paintEvent(QPaintEvent *event)
{
	QPainter painter(this);
	const int quiet = (int)FZN_QR_QUIET;
	int across;
	int module;
	int side;
	int ox;
	int oy;
	int x;
	int y;

	(void)event;

	if (size_ <= 0) {
		/* The message, or nothing at all. `QPainter::drawText` over the
		 * whole rect so a terminal backend gets one string to place
		 * rather than a position in pixels. */
		if (!message_.isEmpty())
			painter.drawText(rect(), Qt::AlignCenter, message_);
		return;
	}

	across = size_ + 2 * quiet;

	/* SQUARE MODULES, AND AN INTEGER NUMBER OF PIXELS EACH. A fractional
	 * module leaves the edges of the code on half-pixels, which a camera
	 * reads as blur and a character-cell backend rounds -- and rounding one
	 * module differently from its neighbour is how a row of the code stops
	 * being a row. */
	module = qMin(width(), height()) / across;
	if (module < 1)
		module = 1;
	side = module * across;

	/* Centred, so the quiet zone is not eaten by whichever edge the layout
	 * gave the widget more of. */
	ox = (width() - side) / 2;
	oy = (height() - side) / 2;

	/* THE QUIET ZONE IS PAINTED, not left to whatever is behind. A code on
	 * a dark dialog with a transparent margin is a code with no quiet zone
	 * at all, and the scanner never finds it. */
	painter.fillRect(ox, oy, side, side, Qt::white);

	for (y = 0; y < size_; y++) {
		for (x = 0; x < size_; x++) {
			if (!modules_[(size_t)y * (size_t)size_ + (size_t)x])
				continue;
			painter.fillRect(ox + (x + quiet) * module,
			                 oy + (y + quiet) * module, module, module,
			                 Qt::black);
		}
	}
}
