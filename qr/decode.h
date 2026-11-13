/*
 * decode.h -- recognising a QR code in a captured frame. Taken from
 * fuzzypickles' recogniser, fuzznet sec 1095: built and run by `make qrcheck`
 * over the vendored quirc, and not yet in the library -- so this header is
 * not installed until it is.
 *
 * The other half of camera pairing. `qr.h` lets a host publish its contact
 * card as a symbol on a screen; this reads one back out of a camera frame, so
 * a Linux host with a webcam can be the side holding the camera. The rule is
 * unchanged and merely stops being phone-specific: whoever holds the camera is
 * the requester, because scanning is what tells you where to send a pairing
 * request, and the request carries everything the far side needs in return.
 *
 * Recognition is delegated to quirc (`quirc/`, ISC, submodule), for the same
 * reason Monocypher is not hand-written here: it is a fiddly, entirely solved,
 * non-differentiating problem, and the parts that matter -- perspective
 * correction and Reed-Solomon error correction -- are exactly where a
 * hand-rolled version quietly goes wrong. It stays dependency-light: quirc is
 * pure C with no runtime dependencies of its own.
 *
 * This wrapper exists so that choice stays reversible. Nothing outside this
 * file mentions quirc, so a different recogniser -- or our own, later -- is a
 * change to one implementation file.
 *
 * Known, and not ours to fix in the tree: a sanitised build reports
 *
 *   quirc.c:84 runtime error: null pointer passed as argument 2, which is
 *   declared to never be null
 *
 * from quirc_resize on a freshly created decoder. It is memcpy(dst, NULL, 0)
 * -- there is no old image to copy on the first call -- which is harmless in
 * practice and undefined behaviour on paper. Recorded here so a future
 * `make SANITIZE=1 test` does not start an investigation into our own code,
 * and because patching a submodule in place is worse than knowing about it.
 *
 * Note the asymmetry with qr.h: encoding is ours because the card is ours and
 * the symbol must be exactly right; decoding is somebody else's symbol, seen
 * through a lens, and being liberal about it is the whole job.
 */
#ifndef FZN_QR_DECODE_H
#define FZN_QR_DECODE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fzn_qr_scanner fzn_qr_scanner_t;

/*
 * Creates a scanner for frames of the given size. Reused across frames rather
 * than rebuilt: recognition allocates working buffers proportional to the
 * frame, and a camera hands over one of these thirty times a second.
 *
 * Returns NULL if the size is unusable or memory is short.
 */
fzn_qr_scanner_t *fzn_qr_scanner_new(unsigned width, unsigned height);
void fzn_qr_scanner_free(fzn_qr_scanner_t *s);

/*
 * Looks for a QR code in one 8-bit grayscale frame, one byte per pixel, top
 * row first, as a camera module produces (fuzzypickles' camera.h).
 *
 * Returns the number of payload bytes written to out on success, 0 when no
 * symbol was found or none decoded cleanly, and -1 on a usage error. Finding
 * nothing is the overwhelmingly common case -- most frames of a hand-held
 * camera are motion-blurred, half-aimed, or aimed at the room -- so it is not
 * reported as an error and callers are expected simply to try the next frame.
 */
int fzn_qr_scan_frame(fzn_qr_scanner_t *s, const uint8_t *gray, unsigned width, unsigned height,
       uint8_t *out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif /* FZN_QR_DECODE_H */
