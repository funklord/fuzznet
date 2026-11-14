#ifndef FZN_GUI_STICKER_RENDER_H
#define FZN_GUI_STICKER_RENDER_H

#include <QPixmap>
#include <QSize>
#include <QString>

extern "C" {
#include "../local/rpc_err.h"
#include "../sticker/pack.h"
}

/*
 * A sticker's art, drawn: fuzznet sec 1151 (taken from fuzzypickles' gui/,
 * with fuzznet's names).
 *
 * TWO PATHS, BECAUSE A STICKER IS ONE OF TWO KINDS. RASTER (PNG, APNG's first
 * frame, WebP), which is what an imported LINE pack holds, decoded by Qt; and
 * VECTOR (Lottie), the native-authoring path and the only one that scales
 * without loss, drawn by the vendored ThorVG into a raw buffer a plain widget
 * blits -- no scene graph and no QML. The node draws a rendition's bytes
 * (`fzn_rpc_sticker_art`); this turns them into pixels.
 *
 * A BUILD WITHOUT THORVG (an empty `thorvg/`, or FZN_THORVG_ON unset) still
 * draws raster stickers, and says why a Lottie one is not drawn, so a caller
 * falls back to the sticker's description.
 */

/* What could not be drawn, so a caller can say something better than
 * nothing. Empty when the pixmap came back valid. */
struct fzn_sticker_render_result {
	QPixmap pixmap;
	QString unavailable_reason;
};

/*
 * Renders one sticker from a rendition's own bytes and format, as a node draws
 * one (sec 284): its packs are fuzznet's layout, which is not opened here, so
 * the node writes the rendition and this draws it.
 *
 * `target` is a hint: a raster rendition is scaled to fit it while keeping
 * its aspect, and never scaled UP past its natural size, because enlarging a
 * 96x74 chat thumbnail to fill a message looks worse than showing it small.
 * A vector one has no natural size and is fitted to the hint.
 *
 * `progress` is where in an animation to draw, 0..1, and is ignored for a
 * still. ONE FRAME, NOT A PLAYER: a sticker is drawn by a delegate during a
 * paint event, and a timer per sticker in a scrolling log is how a chat
 * window comes to burn a core doing nothing. Whoever wants motion advances
 * this and repaints; 0 is the still a log shows until something decides
 * otherwise.
 */
fzn_sticker_render_result fzn_sticker_render_art(const uint8_t *art, size_t art_len, uint8_t format,
                                                 const QSize &target, float progress = 0.0f);

/*
 * A MESSAGE or NAME sticker as sent: `drawn`, the art at whatever size it
 * was drawn, with `text` -- the sender's words, carried by the message --
 * fitted into the sticker's box over its fill. The box is in the main
 * rendition's pixels and is scaled to `drawn`, then turned about its centre
 * by the sticker's angle, for words set on a slant. The text is fitted, not
 * clipped: the largest size at which it fits, wrapped for a message, one
 * line for a name. Without a box, or without text, `drawn` comes back as it
 * was.
 */
QPixmap fzn_sticker_with_text(const QPixmap &drawn, const fzn_sticker_entry_t *entry,
                              const QString &text);
#endif /* FZN_GUI_STICKER_RENDER_H */
