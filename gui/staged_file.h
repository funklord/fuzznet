#ifndef FZN_GUI_STAGED_FILE_H
#define FZN_GUI_STAGED_FILE_H

/*
 * A PHONE'S content:// FILES, sec 1532: an Android picker hands back a
 * content:// URI, which this app can open and the node cannot. A path going
 * to the node is staged first -- copied to a private file in this app's
 * cache, which goes with the QTemporaryFile holding it -- and a file the node
 * writes for one is written to a fresh name there and copied out. A plain
 * path passes through untouched. One copy of what the conversation view
 * wrote first (sec 1524) and the library had inline (sec 1493).
 */

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QIODevice>
#include <QStandardPaths>
#include <QString>
#include <QTemporaryFile>

/* EVERY PATH STAGED AS A PICKED ONE, sec 1537: a test's seam, so a
 * desktop suite walks the phone's path with plain files. Off by default,
 * and nothing but a test sets it. */
inline bool &fzn_stage_forced()
{
	static bool forced = false;
	return forced;
}

inline void fzn_stage_force(bool on) { fzn_stage_forced() = on; }

inline bool fzn_picked_uri(const QString &path)
{
	return fzn_stage_forced() || path.startsWith(QLatin1String("content:"));
}

/* A template for a staged file in this app's cache, the directory made. */
inline QString fzn_staged_template(const char *what)
{
	const QString dir = QStandardPaths::writableLocation(QStandardPaths::CacheLocation);

	QDir().mkpath(dir);
	return dir + QLatin1Char('/') + QLatin1String(what) + QStringLiteral("-XXXXXX");
}

/* Every byte of `from` into `to`. */
inline bool fzn_copy_whole(QIODevice &from, QIODevice &to)
{
	while (!from.atEnd()) {
		const QByteArray chunk = from.read(1 << 16);
		if (chunk.isEmpty() || to.write(chunk) != chunk.size())
			return false;
	}
	return true;
}

/* THE PATH THE NODE READS for `picked`: itself, or a copy staged in
 * `staged` (made from fzn_staged_template). Empty when it could not be
 * read. */
inline QString fzn_stage_in(const QString &picked, QTemporaryFile &staged)
{
	if (!fzn_picked_uri(picked))
		return picked;
	QFile in(picked);
	if (!in.open(QIODevice::ReadOnly) || !staged.open() || !fzn_copy_whole(in, staged) || !staged.flush())
		return QString();
	return staged.fileName();
}

/* THE PATH THE NODE WRITES for `where`: itself, or a fresh name in the
 * cache, made and let go so the node finds none there. Empty when none
 * could be made. */
inline QString fzn_stage_out(const QString &where, QTemporaryFile &staged)
{
	if (!fzn_picked_uri(where))
		return where;
	if (!staged.open())
		return QString();
	staged.close();
	QFile::remove(staged.fileName());
	return staged.fileName();
}

/* What the node wrote, copied out to `where` when it is a picked one. */
inline bool fzn_stage_out_done(const QString &where, const QTemporaryFile &staged)
{
	if (!fzn_picked_uri(where))
		return true;
	QFile in(staged.fileName()), to(where);
	return in.open(QIODevice::ReadOnly) && to.open(QIODevice::WriteOnly | QIODevice::Truncate)
	       && fzn_copy_whole(in, to);
}

/* The name a picked file goes under: its provider's, not the URI's last
 * segment; a path's last segment otherwise. */
inline QString fzn_picked_name(const QString &path)
{
	return fzn_picked_uri(path) ? QFileInfo(path).fileName() : path.section(QLatin1Char('/'), -1);
}

#endif
