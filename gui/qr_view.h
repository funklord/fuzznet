/*
 * A QR code on screen, so that every consumer shows a card the same way.
 *
 * project.md sec 161. sec 160 built `qr/qr.h`, which hands out modules and
 * draws nothing; this is the half that draws them, and `cli/` printing them
 * as half-blocks would be a third. The split is deliberate -- deciding what a
 * pixel is belongs to whoever has the screen.
 *
 * IT ENCODES WHAT IT IS GIVEN AND SAYS SO WHEN IT CANNOT. A payload past
 * every version this library encodes leaves the widget showing why, not a
 * blank square: a QR code that failed to generate and a QR code nobody asked
 * for look identical once they are both empty, and a consumer showing a
 * provisioning card needs to tell them apart.
 *
 * NO Q_OBJECT AND THEREFORE NO moc, on sec 140's rule. This displays and
 * emits nothing.
 *
 * THE QUIET ZONE IS DRAWN, and that is not decoration. Four modules of
 * background on every side is what a scanner uses to find the code at all, so
 * a widget that left it to the layout would produce something that reads only
 * when the surrounding margin happened to be pale and wide enough. It is part
 * of the code rather than part of the arrangement.
 *
 * SQUARE MODULES, WHICH IS THE WHOLE OF THE qtty QUESTION. A character cell
 * is not square -- this machine's is 8 by 16 -- so a module painted one cell
 * wide and one cell tall arrives at the scanner stretched two to one, and a
 * stretched code is one a decoder may refuse. Painting squares in PIXELS and
 * letting the backend map them is what keeps the geometry right on both
 * targets, and `make qtty` renders this widget through a terminal to check
 * that the result still decodes.
 */

#ifndef FZN_GUI_QR_VIEW_H
#define FZN_GUI_QR_VIEW_H

extern "C" {
#include "../qr/qr.h"
}

#include <QString>
#include <QWidget>

class fzn_qr_view : public QWidget {
public:
	explicit fzn_qr_view(QWidget *parent = nullptr);

	/*
	 * Show `text` as a QR code at `level`.
	 *
	 * An empty payload clears the widget, which is the "nobody asked"
	 * state. Anything the encoder refuses leaves the widget saying what was
	 * refused -- `fzn_qr_err_str`'s words, so the reason a consumer sees is
	 * the one the library gives.
	 */
	void show_text(const QString &text, fzn_qr_level_t level);

	/* Whether a code is currently displayed, and how many modules across it
	 * is -- zero when there is none. A test reads these instead of the
	 * pixels, and a consumer sizing a dialog wants the second. */
	bool has_code() const;
	int modules_across() const;

	/* What the widget says when it has no code to show: empty while none
	 * was asked for, and the encoder's own reason when one was refused. */
	QString message_text() const;

	/* The side of the square this wants, in pixels, for a code of
	 * `modules_across()` -- the quiet zone included. A consumer that wants
	 * the code crisp gives it a multiple of this. */
	int preferred_side() const;

	QSize minimumSizeHint() const override;
	QSize sizeHint() const override;

protected:
	void paintEvent(QPaintEvent *event) override;

private:
	uint8_t modules_[FZN_QR_MODULES_MAX];
	int size_;
	QString message_;
};

#endif /* FZN_GUI_QR_VIEW_H */
