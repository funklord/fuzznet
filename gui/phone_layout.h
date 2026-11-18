/*
 * Whether a view lays itself out for a phone: fuzznet sec 1271, from
 * fuzzypickles' 20261118T1445Z -- three views each switched at 400 px, under
 * a Pixel's 411 dp, so the phone layout reached only the smallest phones.
 *
 * BELOW 600 IS A PHONE, as Android has drawn the line since 3.2's sw600dp
 * qualifier (2011) and still does as the compact window class. Widths are
 * Qt's logical pixels, which are a phone's dp.
 *
 * A HOST THAT KNOWS ITS LAYOUT says so: fzn_phone_layout_pin(1) or (0) for
 * every view in the process, -1 to follow the width again -- the choice not
 * to choose, the default. Pin before the views are shown; a view reads it at
 * its next resize.
 *
 * Header-only, so a host needs nothing compiled for it.
 */
#ifndef FZN_GUI_PHONE_LAYOUT_H
#define FZN_GUI_PHONE_LAYOUT_H

#define FZN_PHONE_LAYOUT_WIDTH_PX 600

inline int &fzn_phone_layout_pinned()
{
	static int pinned = -1;
	return pinned;
}

inline void fzn_phone_layout_pin(int phone) { fzn_phone_layout_pinned() = phone < 0 ? -1 : phone ? 1 : 0; }

/* Whether a view `width` logical pixels wide is laid out for a phone. */
inline bool fzn_phone_layout(int width)
{
	const int pinned = fzn_phone_layout_pinned();
	return pinned >= 0 ? pinned == 1 : width < FZN_PHONE_LAYOUT_WIDTH_PX;
}

#endif /* FZN_GUI_PHONE_LAYOUT_H */
