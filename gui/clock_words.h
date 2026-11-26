/* A LENGTH AS A CLOCK READS IT, sec 1490: M:SS, and H:MM:SS from an hour
 * -- where the library, photo and music views each kept a copy saying
 * "87:03" of an hour and a half (fuzzypickles, inbox 20261126T2240Z).
 * Header-only, as size_words.h, so a view takes it without a link rule. */

#ifndef FZN_GUI_CLOCK_WORDS_H
#define FZN_GUI_CLOCK_WORDS_H

#include <QChar>
#include <QString>

#include <stdint.h>

static inline QString fzn_clock_words(uint64_t s)
{
	return s >= 3600u ? QStringLiteral("%1:%2:%3")
	                            .arg(s / 3600u)
	                            .arg(s / 60u % 60u, 2, 10, QLatin1Char('0'))
	                            .arg(s % 60u, 2, 10, QLatin1Char('0'))
	                  : QStringLiteral("%1:%2").arg(s / 60u).arg(s % 60u, 2, 10, QLatin1Char('0'));
}

#endif
