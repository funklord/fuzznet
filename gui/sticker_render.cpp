#include "sticker_render.h"

#include <QBuffer>
#include <QImage>
#include <QImageReader>
#include <QFont>
#include <QFontMetrics>
#include <QObject>
#include <QPainter>

/* LOTTIE ONLY WHERE THORVG IS VENDORED, fuzznet sec 1151: the Makefile
 * defines FZN_THORVG_ON when thorvg/ holds its headers. Without it a Lottie
 * sticker says why it is not drawn, and the caller shows its words. */
#ifdef FZN_THORVG_ON
#include <thorvg.h>

#include <memory>
#endif

#include <algorithm>
#include <string.h>
#include <vector>

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
		/* OWNED HERE, sec 1160: thorvg 1.0's gen() hands back a bare
		 * pointer where earlier versions gave a unique_ptr, so `auto` kept
		 * the old spelling and dropped the ownership -- a canvas, an
		 * animation and the whole parsed Lottie leaked per sticker drawn.
		 * The picture between them is counted, each holding it, so the
		 * order they go in does not matter; both go before term(). */
		std::unique_ptr<tvg::SwCanvas> canvas(tvg::SwCanvas::gen());
		std::unique_ptr<tvg::Animation> animation(tvg::Animation::gen());
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

/* ---- APNG, sec 1322 --------------------------------------------------------
 *
 * Qt's PNG reader draws an APNG's default image and no more. So the frames
 * are put back together here: each frame's data rebuilt as a PNG of its own
 * -- the signature, an IHDR of the frame's size, the chunks before the first
 * IDAT that every frame shares (a palette, transparency, gamma...), the
 * frame's data as IDAT, IEND -- decoded by Qt, then laid onto the canvas by
 * its fcTL's blend and disposal, frame by frame up to the one wanted. The
 * PNG spec's APNG section is the reference. Bounded: at most APNG_FRAMES_MAX
 * frames, a canvas of at most 1024 pixels a side, art at most 256 KiB as the
 * callers read it. */
#define APNG_FRAMES_MAX 300
#define APNG_SIDE_MAX 1024u

static uint32_t be32(const uint8_t *p) {
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3];
}

static void put_be32(QByteArray &out, uint32_t v) {
	out.append((char)(v >> 24)).append((char)(v >> 16)).append((char)(v >> 8)).append((char)v);
}

static uint32_t png_crc(const char *type, const uint8_t *data, size_t len) {
	static uint32_t table[256];
	static bool made;
	uint32_t c = 0xffffffffu;
	if (!made) {
		for (uint32_t n = 0; n < 256u; n++) {
			uint32_t k = n;
			for (int b = 0; b < 8; b++)
				k = (k & 1u) ? 0xedb88320u ^ (k >> 1) : k >> 1;
			table[n] = k;
		}
		made = true;
	}
	for (int i = 0; i < 4; i++)
		c = table[(c ^ (uint8_t)type[i]) & 0xffu] ^ (c >> 8);
	for (size_t i = 0; i < len; i++)
		c = table[(c ^ data[i]) & 0xffu] ^ (c >> 8);
	return c ^ 0xffffffffu;
}

static void put_chunk(QByteArray &out, const char *type, const uint8_t *data, size_t len) {
	put_be32(out, (uint32_t)len);
	out.append(type, 4);
	if (len)
		out.append((const char *)data, (int)len);
	put_be32(out, png_crc(type, data, len));
}

struct apng_frame {
	uint32_t w, h, x, y;
	uint8_t dispose, blend;
	QByteArray data; /* the frame's compressed bytes, IDAT's or fdAT's */
};

struct apng {
	uint32_t width = 0, height = 0;
	QByteArray ihdr, shared; /* IHDR's 13 bytes; the chunks every frame repeats */
	std::vector<apng_frame> frames;
};

/* AN APNG READ: 1 with its frames, 0 for anything else -- a PNG with no
 * acTL included, which is a still. */
static bool apng_read(const uint8_t *b, size_t len, apng &a) {
	static const uint8_t sig[8] = { 0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a };
	size_t at = 8;
	bool animated = false, seen_idat = false;

	if (len < 8 || memcmp(b, sig, 8) != 0)
		return false;
	while (at + 12 <= len) {
		const uint32_t n = be32(b + at);
		const uint8_t *type = b + at + 4, *data = b + at + 8;
		if (n > len - at - 12)
			return false;
		if (!memcmp(type, "IHDR", 4) && n == 13) {
			a.ihdr = QByteArray((const char *)data, 13);
			a.width = be32(data);
			a.height = be32(data + 4);
		} else if (!memcmp(type, "acTL", 4) && n == 8) {
			animated = true;
		} else if (!memcmp(type, "fcTL", 4) && n == 26) {
			apng_frame f;
			if (a.frames.size() >= APNG_FRAMES_MAX)
				return false;
			f.w = be32(data + 4);
			f.h = be32(data + 8);
			f.x = be32(data + 12);
			f.y = be32(data + 16);
			f.dispose = data[24];
			f.blend = data[25];
			if (!f.w || !f.h || f.x > a.width || f.y > a.height || f.w > a.width - f.x || f.h > a.height - f.y)
				return false;
			a.frames.push_back(f);
		} else if (!memcmp(type, "IDAT", 4)) {
			/* THE DEFAULT IMAGE IS FRAME 0 only where an fcTL came first. */
			if (!a.frames.empty() && a.frames.size() == 1)
				a.frames[0].data.append((const char *)data, (int)n);
			seen_idat = true;
		} else if (!memcmp(type, "fdAT", 4) && n >= 4) {
			if (a.frames.empty())
				return false;
			a.frames.back().data.append((const char *)data + 4, (int)(n - 4));
		} else if (!memcmp(type, "IEND", 4)) {
			break;
		} else if (!seen_idat && memcmp(type, "acTL", 4) != 0) {
			/* A PALETTE, TRANSPARENCY, GAMMA ...: every frame's too. */
			put_chunk(a.shared, (const char *)type, data, n);
		}
		at += 12 + n;
	}
	if (!animated || a.ihdr.size() != 13 || a.frames.empty() || !a.width || !a.height || a.width > APNG_SIDE_MAX
	    || a.height > APNG_SIDE_MAX)
		return false;
	for (const apng_frame &f : a.frames)
		if (f.data.isEmpty())
			return false;
	return true;
}

/* FRAME `index` OF `a`, composed onto its canvas: a null image where a
 * frame does not decode. */
static QImage apng_draw(const apng &a, size_t index) {
	static const uint8_t sig[8] = { 0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a };
	QImage canvas((int)a.width, (int)a.height, QImage::Format_ARGB32_Premultiplied), saved;
	canvas.fill(Qt::transparent);
	for (size_t i = 0; i <= index && i < a.frames.size(); i++) {
		const apng_frame &f = a.frames[i];
		QByteArray png((const char *)sig, 8), ihdr = a.ihdr;
		QImage part;
		ihdr[0] = (char)(f.w >> 24), ihdr[1] = (char)(f.w >> 16), ihdr[2] = (char)(f.w >> 8), ihdr[3] = (char)f.w;
		ihdr[4] = (char)(f.h >> 24), ihdr[5] = (char)(f.h >> 16), ihdr[6] = (char)(f.h >> 8), ihdr[7] = (char)f.h;
		put_chunk(png, "IHDR", (const uint8_t *)ihdr.constData(), 13);
		png.append(a.shared);
		put_chunk(png, "IDAT", (const uint8_t *)f.data.constData(), (size_t)f.data.size());
		put_chunk(png, "IEND", nullptr, 0);
		if (!part.loadFromData(png, "PNG"))
			return QImage();
		/* DISPOSE_OP_PREVIOUS keeps what lay under it, to put back. */
		if (f.dispose == 2u)
			saved = canvas.copy((int)f.x, (int)f.y, (int)f.w, (int)f.h);
		{
			QPainter p(&canvas);
			p.setCompositionMode(f.blend == 0u ? QPainter::CompositionMode_Source
			                                  : QPainter::CompositionMode_SourceOver);
			p.drawImage((int)f.x, (int)f.y, part);
		}
		if (i == index)
			break;
		/* THEN ITS DISPOSAL, before the next is laid on: cleared, or what
		 * lay under it put back. */
		if (f.dispose == 1u || (f.dispose == 2u && saved.isNull())) {
			QPainter p(&canvas);
			p.setCompositionMode(QPainter::CompositionMode_Source);
			p.fillRect((int)f.x, (int)f.y, (int)f.w, (int)f.h, Qt::transparent);
		} else if (f.dispose == 2u) {
			QPainter p(&canvas);
			p.setCompositionMode(QPainter::CompositionMode_Source);
			p.drawImage((int)f.x, (int)f.y, saved);
		}
	}
	return canvas;
}

int fzn_sticker_render_frames(const uint8_t *art, size_t art_len, uint8_t format) {
	apng a;
	if (!art || !art_len)
		return 0;
	if (format == FZN_STICKER_LOTTIE) {
#ifdef FZN_THORVG_ON
		return 2; /* a Lottie is motion, however many frames it says */
#else
		return 0;
#endif
	}
	if (apng_read(art, art_len, a))
		return (int)a.frames.size();
	QByteArray bytes = QByteArray::fromRawData((const char *)art, (int)art_len);
	QBuffer buf(&bytes);
	QImageReader reader(&buf);
	if (!reader.canRead())
		return 0;
	return reader.supportsAnimation() && reader.imageCount() > 1 ? reader.imageCount() : 1;
}

static fzn_sticker_render_result render_raster(const uint8_t *bytes, size_t len,
                                               const QSize &target, float progress) {
	fzn_sticker_render_result r;
	QImage img;
	apng a;

	/* ANIMATED, sec 1322: an APNG composed here, any other the frame Qt's
	 * reader reaches -- an animated WebP's. A still is drawn as it always
	 * was, its frame 0. */
	if (apng_read(bytes, len, a)) {
		const size_t at = std::min(a.frames.size() - 1u,
		                           (size_t)(qBound(0.0f, progress, 1.0f) * (float)a.frames.size()));
		img = apng_draw(a, at);
	} else if (progress > 0.0f) {
		QByteArray raw = QByteArray::fromRawData((const char *)bytes, (int)len);
		QBuffer buf(&raw);
		QImageReader reader(&buf);
		const int count = reader.supportsAnimation() ? reader.imageCount() : 0;
		if (count > 1) {
			const int at = std::min(count - 1, (int)(qBound(0.0f, progress, 1.0f) * (float)count));
			for (int i = 0; i <= at; i++)
				if (!reader.read(&img))
					break;
		}
	}
	if (!img.isNull()) {
		if (target.isValid() && !target.isEmpty() && (img.width() > target.width() || img.height() > target.height()))
			img = img.scaled(target, Qt::KeepAspectRatio, Qt::SmoothTransformation);
		r.pixmap = QPixmap::fromImage(img);
		return r;
	}
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
	return render_raster(art, art_len, target, progress);
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
