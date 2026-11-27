/*
 * What a person is told when a peer's clock and this device's disagree by
 * more than a request lives (fuzznet sec 717): nothing gets through between
 * them, and where both ends used to see only silence, this says why and what
 * to check. For a host's notice line, not a log the person whose clock is
 * wrong would never open. Moved from fuzzypickles' gui/src/clock_notice
 * (sec 1507), the holder's rule being that what every consumer would show
 * is fuzznet's.
 *
 * `names` maps a host key (32 bytes) to the name this device knows it by,
 * a contact or one of the user's own devices; a key it does not know is
 * named by its first eight hex digits. The seconds fuzznetd reports are how
 * long a request had already expired, a lower bound on how far apart the
 * clocks are, so the words say "more than". The row seen most recently is
 * the one named; any others are counted.
 *
 * `estate` is fuzznet's verdict on THIS device's clock against the user's
 * other devices (sec 719's `get clock`), and it says whose clock to set:
 * - wrong: this device's, by how far, shown with or without rows -- the
 *   device whose clock is off is the one that shows it;
 * - right: the peer's, since this one agrees with the user's others;
 * - unsure (fewer than two others measured): the rows alone cannot say,
 *   so the person is asked to check this device's.
 * Empty when there are no rows and the clock is not wrong.
 *
 * `fzn_clock_notice_read` asks the node for all of it through the host's
 * ask callback -- the verdict, the rows, and the names from its contacts
 * and siblings -- so a host shows the notice with one call.
 *
 * NO Q_OBJECT AND THEREFORE NO moc.
 */
#ifndef FZN_GUI_CLOCK_NOTICE_H
#define FZN_GUI_CLOCK_NOTICE_H

#include "notebook_view.h"

#include <QByteArray>
#include <QHash>
#include <QString>

extern "C" {
#include "../local/rpc.h"
}

QString fzn_clock_notice_text(const fzn_rpc_clock_estate_t &estate, const fzn_rpc_clock_list_t &rows,
                              const QHash<QByteArray, QString> &names);

/* The verdict and the rows' keys and directions, so a notice dismissed
 * stays dismissed until that changes -- a new peer, one turning ahead or
 * behind, or this device's clock turning wrong. */
QString fzn_clock_notice_signature(const fzn_rpc_clock_estate_t &estate, const fzn_rpc_clock_list_t &rows);

/* ALL OF IT FROM THE NODE: the notice's text and its signature, both empty
 * where there is nothing to say. Whether the node answered. */
bool fzn_clock_notice_read(fzn_notebook_view_ask_t ask, void *ask_ctx, QString *text, QString *signature);

#endif /* FZN_GUI_CLOCK_NOTICE_H */
