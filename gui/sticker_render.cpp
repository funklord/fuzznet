#include "sticker_render.h"

#include <QImage>
#include <QFont>
#include <QFontMetrics>
#include <QObject>
#include <QPainter>

/* LOTTIE ONLY WHERE THORVG IS VENDORED, fuzznet sec 1151: the Makefile
 * defines FZN_THORVG_ON when thorvg/ holds its headers. Without it a Lottie
 * sticker says why it is not drawn, and the caller shows its words. */
#ifdef FZN_THORVG_ON
#include <thorvg.h>
#endif

/*
 * Lottie, via ThorVG.
 *
 * WHY THORVG AND NOT QtLottie. Qt's Lottie module ships as
 * `qml6-module-qt-labs-lottieqt` -- a QML type, with no Widgets or C++
 * painting API at all. this workspace uses Qt Widgets, never QML or QtQuick, so it is not a
 * trade to weigh; and
 * it is a `Qt.labs.*` module besides, which is not a stable API. Nor rlottie, which is
 * effectively unmaintained.
 *
 * ThorVG renders into a RAW BUFFER, which is the property that matters:
 * a plain QWidget blits one, so vector stickers cost this project no scene
 * graph and no QML. So animation needs no QML.
 *
 * ONE FRAME, NOT A PLAYER. A sticker in a chat log is drawn by a delegate
 * during a paint event, and starting a timer per sticker in a scrolling log
 * is how a chat window comes to burn a core doing nothing. Which frame to
 * draw belongs to the caller; this renders the one asked for. Frame 0 is the
 * still that a log shows until something decides otherwise.
 */
static fzn_sticker_render_result render_lottie(const uint8_t *bytes, size_t len,
                                               const QSize &target, float progress) {
	fzn_sticker_render_result r;

	/* A sensible square when the caller had no opinion: a Lottie has no
	 * natural pixel size, being vector, so something has to choose one. */
	const int w = (target.isValid() && target.width() > 0) ? target.width() : 240;
	const int h = (target.isValid() && target.height() > 0) ? target.height() : 240;

#ifndef FZN_THORVG_ON
	(void)bytes, (void)len, (void)progress, (void)w, (void)h;
	r.unavailable_reason = QStringLiteral("this build has no vector renderer");
	return r;
#else
	if (tvg::Initializer::init(0) != tvg::Result::Success) {
		r.unavailable_reason = QStringLiteral("the vector renderer could not start");
		return r;
	}

	{
		auto canvas = tvg::SwCanvas::gen();
		auto animation = tvg::Animation::gen();
		/*
		 * ARGB8888 straight into a QImage's own buffer: ThorVG writes where
		 * Qt will read, so a frame costs no copy of its own. ThorVG's
		 * ARGB8888 is ALPHA-PREMULTIPLIED (its ARGB8888S is the un-multiplied
		 * one), which is why the QImage is Format_ARGB32_Premultiplied --
		 * pairing those wrong shows as dark fringes around every antialiased
		 * edge rather than as an error, so it is worth naming.
		 */
		QImage img(w, h, QImage::Format_ARGB32_Premultiplied);
		img.fill(Qt::transparent);

		bool ok = canvas && animation &&
		          canvas->target(reinterpret_cast<uint32_t *>(img.bits()),
		                         static_cast<uint32_t>(img.bytesPerLine() / 4),
		                         static_cast<uint32_t>(w), static_cast<uint32_t>(h),
		                         tvg::ColorSpace::ARGB8888) == tvg::Result::Success;

		if (ok) {
			auto picture = animation->picture();
			/* `copy = true`: the buffer this is handed is the caller's, freed
			 * when it returns, and ThorVG would otherwise hold a pointer
			 * into it. A use-after-free here would be intermittent and blamed
			 * on the pack. */
			ok = picture->load(reinterpret_cast<const char *>(bytes), static_cast<uint32_t>(len),
			                   "lottie", "", true) == tvg::Result::Success;
			if (ok) {
				/* Fitted, not stretched: a Lottie's own aspect is part of the
				 * art, and a squashed sticker is worse than a smaller one. */
				float pw = 0.0f, ph = 0.0f;
				picture->size(&pw, &ph);
				if (pw > 0.0f && ph > 0.0f) {
					const float scale = qMin(static_cast<float>(w) / pw, static_cast<float>(h) / ph);
					picture->scale(scale);
					picture->translate((static_cast<float>(w) - pw * scale) / 2.0f,
					                   (static_cast<float>(h) - ph * scale) / 2.0f);
				}
				const float total = animation->totalFrame();
				if (total > 0.0f) {
					const float want = qBound(0.0f, progress, 1.0f) * (total - 1.0f);
					animation->frame(want);
				}
				ok = canvas->add(picture) == tvg::Result::Success &&
				     canvas->draw(true) == tvg::Result::Success &&
				     canvas->sync() == tvg::Result::Success;
			}
		}

		if (ok) {
			/* Detached, because the QImage above owns a buffer on this
			 * stack frame and the pixmap must outlive it. */
			r.pixmap = QPixmap::fromImage(img.copy());
		} else {
			r.unavailable_reason = QStringLiteral("this sticker's animation could not be drawn");
		}
	}

	tvg::Initializer::term();
	return r;
#endif
}

static fzn_sticker_render_result render_raster(const uint8_t *bytes, size_t len,
                                               const QSize &target) {
	fzn_sticker_render_result r;
	QImage img;
	/*
	 * Format sniffed by Qt rather than taken from the manifest. The manifest
	 * says what the pack CLAIMS a rendition is, and this is bytes from
	 * whoever built it: trusting the claim would mean handing PNG data to a
	 * WebP decoder on request. Qt looks at the bytes, and a mismatch simply
	 * fails to load.
	 */
	if (!img.loadFromData(bytes, static_cast<int>(len))) {
		r.unavailable_reason = QStringLiteral("this sticker's image could not be decoded");
		return r;
	}
	if (target.isValid() && !target.isEmpty() &&
	    (img.width() > target.width() || img.height() > target.height())) {
		/* Only ever DOWN. Enlarging a 96x74 chat thumbnail to fill a message
		 * looks worse than showing it small, and a larger rendition is a
		 * different asset rather than the same one scaled -- so if a bigger one exists, picking it is the answer, not
		 * stretching this. */
		img = img.scaled(target, Qt::KeepAspectRatio, Qt::SmoothTransformation);
	}
	r.pixmap = QPixmap::fromImage(img);
	if (r.pixmap.isNull()) {
		r.unavailable_reason = QStringLiteral("this sticker's image could not be decoded");
	}
	return r;
}

fzn_sticker_render_result fzn_sticker_render_art(const uint8_t *art, size_t art_len, uint8_t format,
                                                 const QSize &target, float progress) {
	if (format == FZN_STICKER_LOTTIE) return render_lottie(art, art_len, target, progress);
	return render_raster(art, art_len, target);
}

QPixmap fzn_sticker_with_text(const QPixmap &drawn, const fzn_sticker_entry_t *entry,
                              const QString &text) {
	if (drawn.isNull() || !entry || text.isEmpty() || entry->text_w == 0 || entry->text_h == 0)
		return drawn;
	/* The box is the main rendition's: scaled by what was drawn over it. */
	const fzn_sticker_rendition_t *main = fzn_sticker_pick(entry, FZN_STICKER_MAIN);
	const qreal base_w = main && main->width ? main->width : drawn.width() / drawn.devicePixelRatio();
	const qreal base_h = main && main->height ? main->height : drawn.height() / drawn.devicePixelRatio();
	const qreal sx = (drawn.width() / drawn.devicePixelRatio()) / base_w;
	const qreal sy = (drawn.height() / drawn.devicePixelRatio()) / base_h;
	const QRectF placed(entry->text_x * sx, entry->text_y * sy, entry->text_w * sx, entry->text_h * sy);

	/* An image with an alpha channel, whatever `drawn` had: a pixmap of
	 * opaque art carries none, and a clear fill on it would come out black. */
	QImage out = drawn.toImage().convertToFormat(QImage::Format_ARGB32_Premultiplied);
	out.setDevicePixelRatio(drawn.devicePixelRatio());
	QPainter p(&out);
	p.setRenderHint(QPainter::Antialiasing);
	p.setRenderHint(QPainter::TextAntialiasing);
	/* Turned about its own centre for words set on a slant, and everything
	 * below is drawn in the turned box. */
	p.translate(placed.center());
	if (entry->text_turn) p.rotate(entry->text_turn);
	const QRectF box(-placed.width() / 2, -placed.height() / 2, placed.width(), placed.height());
	const QColor fill(int(entry->text_fill >> 24 & 0xff), int(entry->text_fill >> 16 & 0xff),
	                  int(entry->text_fill >> 8 & 0xff), int(entry->text_fill & 0xff));
	/* The fill REPLACES the box's pixels rather than painting over them:
	 * LINE draws a name's placeholder on clear art, and only a clear fill
	 * put in place of the asterisks takes them away. 0 is no fill, so a
	 * clear one is written FFFFFF00. */
	if (entry->text_fill) {
		p.setCompositionMode(QPainter::CompositionMode_Source);
		p.fillRect(box, fill);
		p.setCompositionMode(QPainter::CompositionMode_SourceOver);
	}
	/* Ink that reads on the fill; with none, dark ink, since stickers sit
	 * on light art more often than not. */
	const bool light_fill = (entry->text_fill & 0xff) &&
	                        (0.299 * fill.red() + 0.587 * fill.green() + 0.114 * fill.blue()) < 128;
	/* The sticker's own ink where it has one, as LINE draws a name in its
	 * placeholder's colour. */
	if (entry->text_ink & 0xff)
		p.setPen(QColor(int(entry->text_ink >> 24 & 0xff), int(entry->text_ink >> 16 & 0xff),
		                int(entry->text_ink >> 8 & 0xff), int(entry->text_ink & 0xff)));
	else
		p.setPen(light_fill ? Qt::white : Qt::black);

	/* The largest size at which the text fits the box: a name on one line,
	 * a message wrapped. Searched down from the box's own height. */
	const bool one_line = entry->type == FZN_STICKER_NAMED;
	const int flags = Qt::AlignCenter | (one_line ? 0 : Qt::TextWordWrap);
	QFont font = p.font();
	font.setBold(true);
	int size = qMax(4, int(box.height()));
	for (; size > 4; size--) {
		font.setPixelSize(size);
		const QRectF need = QFontMetricsF(font).boundingRect(box, flags, text);
		if (need.width() <= box.width() + 0.5 && need.height() <= box.height() + 0.5) break;
	}
	font.setPixelSize(size);
	p.setFont(font);
	p.drawText(box, flags, text);
	p.end();
	return QPixmap::fromImage(out);
}
