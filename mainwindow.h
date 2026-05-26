#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "tchat.h"

#include <QSystemTrayIcon>

QT_BEGIN_NAMESPACE
namespace Ui {
class Tchatooine;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
protected:
	// virtual bool event(QEvent *e) override;

private slots:
	void afficheMessage(QString message);
	void on_edtMessage_editingFinished();
	void on_cbxPair_currentIndexChanged(int index);
	void on_edtPseudo_editingFinished();
	void onClientConnected();
	void onServeurConnected();
	void affichePeers();
private:
	Ui::Tchatooine *ui;

    Tchat _tchat;
	QSystemTrayIcon _trayIcon;
};
#endif // MAINWINDOW_H
