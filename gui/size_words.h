/* A SIZE AS A PERSON READS IT, sec 1228: whole bytes below a kilobyte, one
 * decimal above. Header-only, so a view takes it without a link rule, here
 * or in a consumer's build -- and one copy, where three views each kept
 * their own and one of them said "B". */

#ifndef FZN_GUI_SIZE_WORDS_H
#define FZN_GUI_SIZE_WORDS_H

#include <QObject>
#include <QString>

#include <stdint.h>

static inline QString fzn_size_words(uint64_t bytes)
{
	if (bytes < 1024u)
		return QObject::tr("%1 bytes").arg(bytes);
	if (bytes < 1024u * 1024u)
		return QObject::tr("%1 KB").arg((double)bytes / 1024.0, 0, 'f', 1);
	if (bytes < 1024u * 1024u * 1024u)
		return QObject::tr("%1 MB").arg((double)bytes / (1024.0 * 1024.0), 0, 'f', 1);
	return QObject::tr("%1 GB").arg((double)bytes / (1024.0 * 1024.0 * 1024.0), 0, 'f', 1);
}

#endif
