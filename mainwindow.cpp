#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QMessageBox>
#include <QMenu>

MainWindow::MainWindow(QWidget *parent)
	: QMainWindow(parent), ui(new Ui::Tchatooine) {
    ui->setupUi(this);
	ui->lblMessages->clear();
	ui->edtMessage->clear();
	ui->statusbar->showMessage("Not connected");
	QString pseudo = qgetenv("USER");
	if (pseudo.isEmpty())
		pseudo = qgetenv("USERNAME");
	ui->edtPseudo->setText(pseudo);

	ui->cbxPair->addItem("87.88.38.108:9158");
	ui->cbxPair->addItem("176.187.157.48:9158");

	// Check if the system tray is available
	if (!QSystemTrayIcon::isSystemTrayAvailable()) {
		QMessageBox::warning(nullptr, "Avertissement", "Cet OS n'offre pas de service de système tray.");
	} else {
		// Set a tooltip and an icon for the tray icon
		_trayIcon.setToolTip("Tchatooine");
		_trayIcon.setIcon(QIcon(":/icones/Tatooine.png")); // Make sure to use a valid icon path

		// Set up a menu for the tray icon
		QMenu *trayMenu = new QMenu();
		trayMenu->addAction("Show Window");
		trayMenu->addSeparator();
		trayMenu->addAction("Exit");
		_trayIcon.setContextMenu(trayMenu);

		_trayIcon.show();
	}
	connect(&_tchat, &Tchat::clientConnected, this, &MainWindow::onClientConnected);
	connect(&_tchat, &Tchat::serveurConnected, this, &MainWindow::onServeurConnected);
	connect(&_tchat, &Tchat::nouvMessage, this, &MainWindow::afficheMessage);
	connect(&_tchat, &Tchat::annuaireChanged, this, &MainWindow::affichePeers);
}

MainWindow::~MainWindow() {
    _tchat.close();
    delete ui;
}

void MainWindow::onClientConnected() {
	ui->statusbar->showMessage("Connected to " + _tchat.peerAddress().toString());
}

void MainWindow::onServeurConnected()
{
	ui->lblNbClients->setText(QString::number(_tchat.nbClients()));
}

void MainWindow::affichePeers()
{
	ui->lblPeers->setText(_tchat.peers().join('\n'));
}

void MainWindow::afficheMessage(QString message)
{
	ui->lblMessages->setText(ui->lblMessages->text() + message + "\n");
	if (!isActiveWindow()) {
		// Show a notification balloon
		_trayIcon.showMessage(
			"Nouveau message",
			message,
			QSystemTrayIcon::Information,
			5000 // Display time in milliseconds
			);
		QApplication::alert(this);
	}
}

void MainWindow::on_edtMessage_editingFinished()
{
	_tchat.envoie(ui->edtMessage->text());
	ui->edtMessage->clear();
}

void MainWindow::on_cbxPair_currentIndexChanged(int index)
{
	auto pair = ui->cbxPair->currentText().split(':');
	_tchat.init(pair.at(0), pair.at(1).toInt());
}

void MainWindow::on_edtPseudo_editingFinished()
{
	_tchat.setPseudo(ui->edtPseudo->text());
}

