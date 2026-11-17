/* A PERSON'S PLACE IN A LIST, KEPT ACROSS A REFRESH, sec 1225.
 *
 * Every view here refreshes by clearing its tables and filling them again,
 * and a host refreshes on its own clock -- fuzzypickles every two seconds
 * while a page shows. Each refresh dropped the row the person had chosen
 * (and with it whatever the choice enabled: Advertise, Ask, Show on a map)
 * and threw the reader back to the top of the list. fuzzypickles put the
 * row back by its cells and kept each table's scroll value around every
 * refresh, in each page it hosted a view in; this is that, once, in the
 * view.
 *
 * Made before the table is cleared, it notes the chosen row's KEY -- the
 * text of one column, or a value under a role -- and the scroll position.
 * restore(), after the refill, chooses the row holding that key again,
 * wherever it now is, and puts the scroll back; the destructor restores
 * if nobody did. A key no longer there chooses nothing, which is the
 * honest answer: the thing chosen has gone.
 *
 * fzn_keep_answer, below, does the same for the status line.
 *
 * Header-only, so a view takes it without a line in any link rule, here
 * or in a consumer's build. */

#ifndef FZN_GUI_KEEP_PLACE_H
#define FZN_GUI_KEEP_PLACE_H

#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QItemSelectionModel>
#include <QLabel>
#include <QScrollBar>
#include <QVariant>

class fzn_keep_place {
public:
	explicit fzn_keep_place(QAbstractItemView *view, int column = 0, int role = Qt::DisplayRole)
	        : m_view(view), m_column(column), m_role(role)
	{
		if (!m_view || !m_view->model())
			return;
		const QModelIndex at = m_view->currentIndex();
		const bool chosen = at.isValid() && m_view->selectionModel()
		                    && m_view->selectionModel()->isSelected(at);
		if (chosen)
			m_key = m_view->model()->index(at.row(), m_column, at.parent()).data(m_role);
		m_scroll = m_view->verticalScrollBar() ? m_view->verticalScrollBar()->value() : 0;
	}

	~fzn_keep_place() { restore(); }

	fzn_keep_place(const fzn_keep_place &) = delete;
	fzn_keep_place &operator=(const fzn_keep_place &) = delete;

	/* Choose the kept key's row again and put the scroll back. The row it
	 * chose, under its own parent, or -1; again after the first call, the
	 * same answer. */
	int restore()
	{
		if (m_done || !m_view || !m_view->model())
			return m_row;
		m_done = true;
		if (m_key.isValid()) {
			const QModelIndex at = find(QModelIndex());
			if (at.isValid()) {
				m_view->setCurrentIndex(at);
				m_row = at.row();
			}
		}
		/* The geometry first: a scroll bar's range is set when the items
		 * are laid out, and a value past it now would be cut to the top. */
		m_view->doItemsLayout();
		if (m_view->verticalScrollBar())
			m_view->verticalScrollBar()->setValue(m_scroll);
		return m_row;
	}

	/* Whether a row was chosen when this was made. */
	bool had_choice() const { return m_key.isValid(); }

private:
	/* The first row under PARENT, at any depth, holding the key: a list
	 * kept under headings -- conversations under People and Groups -- has
	 * its rows one level down. Column 0 of that row. */
	QModelIndex find(const QModelIndex &parent) const
	{
		const QAbstractItemModel *model = m_view->model();
		for (int r = 0; r < model->rowCount(parent); r++) {
			if (model->index(r, m_column, parent).data(m_role) == m_key)
				return model->index(r, 0, parent);
			const QModelIndex below = find(model->index(r, 0, parent));
			if (below.isValid())
				return below;
		}
		return QModelIndex();
	}

	QAbstractItemView *m_view;
	int m_column, m_role;
	QVariant m_key;
	int m_scroll = 0, m_row = -1;
	bool m_done = false;
};

/* AND THE ANSWER TO THE PERSON'S LAST ACT, sec 1225. A view's status line
 * carries two kinds of words: the view's own -- a refresh's failure, "No
 * contacts yet.", a choice's grant -- and the answer to something the person
 * did: "Asked 3 hosts", "alice is let in.". A refresh says its own again,
 * and used to blank the line on success, taking the answer with it two
 * seconds after the person read it.
 *
 * So the view marks what it says itself, with said() after writing it, and
 * a refresh that succeeds calls restore() last: an answer -- anything in
 * the line the view did not mark -- is put back; the view's own words stay
 * as the refresh left them. A refresh that fails restores nothing, and
 * marks its failure, which the next success then replaces. The mark is a
 * property on the label, so a view needs no member for it. */
class fzn_keep_answer {
public:
	explicit fzn_keep_answer(QLabel *status) : m_status(status)
	{
		if (!m_status)
			return;
		m_before = m_status->text();
		m_answered = !m_before.isEmpty() && m_before != m_status->property(SAID).toString();
	}

	/* The line holds the view's own words now. */
	static void said(QLabel *status)
	{
		if (status)
			status->setProperty(SAID, status->text());
	}

	/* After a refresh that worked: the answer back, if there was one. */
	void restore()
	{
		said(m_status);
		if (m_status && m_answered)
			m_status->setText(m_before);
	}

private:
	static constexpr const char *SAID = "fzn_view_said";
	QLabel *m_status;
	QString m_before;
	bool m_answered = false;
};

#endif
