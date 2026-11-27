/*
 * One line saying what just happened, or offering the one thing to do next,
 * with a Dismiss: fuzznet sec 1253, fuzzypickles' notice bar (its sec 209,
 * the inline replacement for a message box), asked of the conversation
 * (fuzzypickles' 1700Z item: "notices with one action each").
 *
 * SAID: what an act came to, or why it failed, with no action. OFFERED: one
 * action, its words on the button -- "Keep this sticker pack", "Save the
 * file" -- so a page carries the button that fits the line chosen rather
 * than every button any line could want, most of them disabled.
 *
 * WHOSE IT IS, for the fault sec 1224 found in every view -- a refresh
 * dropping the answer to the person's last act: a host's refresh says
 * through `say(text, true)` and clears only what it said itself
 * (`from_refresh`), so "Saved ..." survives the next poll and is gone when
 * the person dismisses it or does something else.
 *
 * TOUCH: `set_touch(true)` makes both buttons at least
 * FZN_NOTICE_LINE_TOUCH_PX tall, a finger's target on a phone.
 *
 * Header-only, with no Q_OBJECT, so a host needs no moc for it.
 */
#ifndef FZN_GUI_NOTICE_LINE_H
#define FZN_GUI_NOTICE_LINE_H

#include "plain_label.h"
#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QString>

#include <functional>
#include <utility>

/* A FINGER'S TARGET, in logical pixels: Android's 48 dp, which Qt's logical
 * pixel is on a phone. */
#define FZN_NOTICE_LINE_TOUCH_PX 48

class fzn_notice_line : public QFrame {
public:
	explicit fzn_notice_line(QWidget *parent = nullptr) : QFrame(parent)
	{
		setFrameShape(QFrame::StyledPanel);
		m_text = fzn_plain_label(this);
		m_text->setWordWrap(true);
		m_text->setTextInteractionFlags(Qt::TextSelectableByMouse);
		m_action = new QPushButton(this);
		m_dismiss = new QPushButton(tr("Dismiss"), this);
		m_dismiss->setAccessibleName(tr("Dismiss this notice"));
		auto *row = new QHBoxLayout(this);
		row->addWidget(m_text, 1);
		row->addWidget(m_action);
		row->addWidget(m_dismiss);
		connect(m_action, &QPushButton::clicked, [this]() { (void)act(); });
		connect(m_dismiss, &QPushButton::clicked, [this]() { clear(); });
		clear();
	}

	/* SAID, with no action. Empty clears. A refresh passes `from_refresh`. */
	void say(const QString &text, bool from_refresh = false)
	{
		m_act = nullptr;
		m_refresh = from_refresh;
		m_text->setText(text);
		m_action->setText(QString());
		m_action->hide();
		setVisible(!text.isEmpty());
		/* TOLD, sec 1533: what an act came to, for a host's log -- not a
		 * refresh's word, nor an offer. */
		if (m_said && !text.isEmpty() && !from_refresh)
			m_said(text);
	}

	/* WHO HEARS what is said: a host's log. */
	void on_said(std::function<void(const QString &)> said) { m_said = std::move(said); }

	/* OFFERED: one action, `action` its words. */
	void offer(const QString &text, const QString &action, std::function<void()> act)
	{
		m_act = std::move(act);
		m_refresh = false;
		m_text->setText(text);
		m_action->setText(action);
		m_action->setVisible(!action.isEmpty() && m_act);
		setVisible(!text.isEmpty());
	}

	void clear() { say(QString()); }

	/* THE ACTION PRESSED, as the button does, for a host or a test. Whether
	 * there was one. The action runs first and says what it came to, so the
	 * offer is not cleared after it. */
	bool act()
	{
		if (!m_act)
			return false;
		const std::function<void()> run = m_act;
		run();
		return true;
	}

	QString text() const { return m_text->text(); }
	QString action() const { return m_act ? m_action->text() : QString(); }
	bool from_refresh() const { return m_refresh; }
	bool offering() const { return static_cast<bool>(m_act); }

	void set_touch(bool on)
	{
		for (QPushButton *b : { m_action, m_dismiss })
			b->setMinimumHeight(on ? FZN_NOTICE_LINE_TOUCH_PX : 0);
	}

private:
	QLabel *m_text;
	QPushButton *m_action;
	QPushButton *m_dismiss;
	std::function<void()> m_act;
	std::function<void(const QString &)> m_said;
	bool m_refresh = false;
};

#endif /* FZN_GUI_NOTICE_LINE_H */
