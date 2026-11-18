/*
 * What another program shares, sent to a conversation: fuzznet sec 1257,
 * the register's share target (sec 1070), which the holder put with the
 * conversation screens ("all belong in fuzznet").
 *
 * A HOST HANDS IT WHAT WAS SHARED -- a file by its path, or a text -- from
 * its platform: Android's SEND intent, a desktop's "open with", a drop.
 * The view says what it is (a file's name and size, the text itself, which
 * the person may change), lists this user's contacts and groups, which a
 * filter narrows, and sends to the one chosen: a file stored here, private,
 * and sent as a line that grants it to the conversation, as the
 * conversation's own Send a file does; a text as a line. The host is told
 * where it went, to open that conversation.
 *
 * Through the typed client on the host's ask callback (`rpc_ask.h`), as the
 * other views are. NO Q_OBJECT AND THEREFORE NO moc.
 */
#ifndef FZN_GUI_SHARE_VIEW_H
#define FZN_GUI_SHARE_VIEW_H

#include "notebook_view.h"

#include <QString>
#include <QStringList>
#include <QWidget>

#include <functional>

class QLabel;
class QLineEdit;
class QListWidget;
class QPushButton;
class fzn_notice_line;
struct fzn_gui_rpc;

class fzn_share_view : public QWidget {
public:
	fzn_share_view(fzn_notebook_view_ask_t ask, void *ask_ctx, QWidget *parent = nullptr);
	~fzn_share_view() override;

	/* WHAT WAS SHARED: a file by its path, or a text. Each replaces the
	 * other. Whether there is something to send. */
	bool set_file(const QString &path);
	bool set_text(const QString &text);

	/* Ask for this user's contacts and groups. Whether the node answered. */
	bool refresh();

	/* WHAT A PERSON DOES, public because a headless test cannot click: the
	 * filter, a conversation chosen by its row as listed (groups as
	 * `@NAME`), and Send. Whether it went. */
	void set_filter(const QString &words);
	void choose(int row);
	bool send();

	/* WHERE IT WENT, a contact's name or `@GROUP`, once sent. */
	void on_sent(std::function<void(const QString &to)> told);

	/* WHAT IS ON SCREEN: what is shared, the conversations listed, the
	 * one chosen, and the notice. */
	QString shared() const;
	QStringList listed() const;
	QString chosen() const;
	QString status() const;

private:
	struct fzn_gui_rpc *m_rpc;
	QString m_file;
	QStringList m_all;
	std::function<void(const QString &)> m_sent;
	void fill();

	QLabel *m_what;
	QLineEdit *m_text;
	QLineEdit *m_filter;
	QListWidget *m_list;
	QPushButton *m_send;
	fzn_notice_line *m_notice;
};

#endif /* FZN_GUI_SHARE_VIEW_H */
