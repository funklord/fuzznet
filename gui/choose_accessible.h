/*
 * A row a screen reader activates, chosen as a click chooses it: fuzznet
 * sec 1423, from fuzzypickles' gui/src/in_window.cpp (inbox
 * 20261123T1921Z), which found it on a Fold under TalkBack.
 *
 * TalkBack's double tap reaches a Qt widget as the accessibility click; on
 * Android Qt runs the node's press action, else its toggle (qtbase,
 * androidjniaccessibility.cpp). An item view's cell offers toggle alone,
 * and toggle only selects (QAccessibleTableCell): no click, activation or
 * current-row signal, and in a single selection the selected row cannot be
 * toggled at all. So a view that chooses on those signals cannot be chosen
 * from under TalkBack -- in the settings view, a TalkBack user could not
 * change a setting.
 *
 * HEADER-ONLY, as combo.h and keep_place.h are: every view includes it and
 * no link line names it.
 */
#ifndef FZN_GUI_CHOOSE_ACCESSIBLE_H
#define FZN_GUI_CHOOSE_ACCESSIBLE_H

#include <QAbstractItemView>
#include <QGuiApplication>
#include <QItemSelectionModel>
#include <QMetaObject>
#include <QModelIndex>
#include <QPersistentModelIndex>

#include <functional>
#include <memory>

/* WHAT A SCREEN READER'S ACTIVATE ON A ROW OF `view` DOES: the row becomes
 * the current one -- so a view choosing on its current row, and every button
 * that reads it after, sees what a click would have given it -- and then
 * `act`, when given, is called with the row's first-column index, for a view
 * that chooses on a click or an activation. A mouse, a finger and the
 * keyboard reach neither: a mouse or a finger selects with a button held,
 * and the keyboard moves the current index before it selects. The decision
 * waits until the selection settles, queued, as a single selection's select
 * clears first. */
inline void fzn_choose_on_accessible_select(QAbstractItemView *view, std::function<void(const QModelIndex &)> act)
{
	QItemSelectionModel *model = view ? view->selectionModel() : nullptr;

	if (!model)
		return;
	auto current = std::make_shared<QPersistentModelIndex>(view->currentIndex());
	auto pending = std::make_shared<bool>(false);
	/* THE ROW LAST CHOSEN THIS WAY, sec 1425: a selection that re-chooses it
	 * with the current row unmoved is no second tap but a re-widening --
	 * an `act` that moved the current row itself, on a tree whose cells
	 * widen to rows, narrowed the row, the widening reselected it, and the
	 * helper queued `act` again without end (fuzzypickles, inbox
	 * 20261124T0020Z). Forgotten when the selection empties or the current
	 * row moves by anything else. */
	auto last = std::make_shared<QPersistentModelIndex>();
	QObject::connect(model, &QItemSelectionModel::currentChanged, view,
	                 [current, last](const QModelIndex &now) {
		                 *current = now;
		                 if (!last->isValid() || now.row() != last->row() || now.parent() != last->parent())
			                 *last = QPersistentModelIndex();
	                 });
	QObject::connect(model, &QItemSelectionModel::selectionChanged, view,
	                 [view, current, pending, last, act](const QItemSelection &on, const QItemSelection &) {
		/* ONLY WHAT SELECTS: a toggle always does, while a pure
		 * deselection is somebody clearing -- a list emptied keeps its
		 * current row, and taken for a choice a refresh re-chose its
		 * restored row (fuzzypickles' window suite, 2026-11-23). */
		if (on.isEmpty()) {
			if (!view->selectionModel() || !view->selectionModel()->hasSelection())
				*last = QPersistentModelIndex();
			return;
		}
		if (QGuiApplication::mouseButtons() != Qt::NoButton)
			return;
		if (view->currentIndex() != QModelIndex(*current))
			return;
		if (*pending)
			return;
		*pending = true;
		/* JUDGED ONCE THE SELECTION HAS SETTLED, and queued: a single
		 * selection's select clears first, and a choice that refills the
		 * list is not made inside its own selection signal. */
		QMetaObject::invokeMethod(
		        view,
		        [view, pending, last, act] {
			        *pending = false;
			        QItemSelectionModel *now = view->selectionModel();
			        const QModelIndexList picked = now ? now->selectedIndexes() : QModelIndexList();

			        if (picked.isEmpty())
				        return;
			        if (last->isValid() && picked.first().row() == last->row()
			            && picked.first().parent() == last->parent())
				        return;
			        *last = QPersistentModelIndex(picked.first().siblingAtColumn(0));
			        /* THE ROW CURRENT, as a click makes it: the view's own
			         * current-row choice runs, and its buttons read this row. */
			        now->setCurrentIndex(picked.first(), QItemSelectionModel::NoUpdate);
			        if (act)
				        act(picked.first().siblingAtColumn(0));
		        },
		        Qt::QueuedConnection);
	});
}

/* A TREE THAT SELECTS ROWS, MADE ABLE TO BY A SCREEN READER: cells selected
 * one at a time (SelectItems), each widened at once to its whole row, so a
 * mouse, a finger and the keyboard see what they did before. With
 * SelectRows, Qt's toggle selects by a cell's row within its parent read as
 * a visible position, and so picks another row wherever rows nest or hide
 * (Qt 6.12, QAccessibleTableCell::selectCell into QAccessibleTree::selectRow). */
inline void fzn_select_rows_through_cells(QAbstractItemView *view)
{
	QItemSelectionModel *model;

	if (!view)
		return;
	view->setSelectionBehavior(QAbstractItemView::SelectItems);
	model = view->selectionModel();
	if (!model)
		return;
	QObject::connect(model, &QItemSelectionModel::selectionChanged, view, [view] {
		QItemSelectionModel *now = view->selectionModel();
		const QAbstractItemModel *items = view->model();
		QItemSelection rows;

		if (!now || !items)
			return;
		for (const QModelIndex &at : now->selectedIndexes())
			if (!now->isRowSelected(at.row(), at.parent()))
				rows.select(at.siblingAtColumn(0), at.siblingAtColumn(items->columnCount(at.parent()) - 1));
		/* SELECTING WHAT IS MISSING SETTLES IT: the next signal finds every
		 * row whole and selects nothing. */
		if (!rows.isEmpty())
			now->select(rows, QItemSelectionModel::Select);
	});
}

#endif /* FZN_GUI_CHOOSE_ACCESSIBLE_H */
