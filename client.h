#ifndef CLIENT_H
#define CLIENT_H

#include <QTcpSocket>
#include <QUrl>
#include <QThread>
#include <QCborStreamWriter>
#include <QCborStreamReader>
#include <QUuid>
#include "dbmanager.h"

class Client : public QObject {
	Q_OBJECT
public:
	explicit Client(QObject *parent = nullptr);
  ~Client();

	void setUrl_pair(const QUrl &newUrl_pair);
	bool envoie(const QString message);
	bool envoie(const QString commande, const QString parametre);
	QHostAddress peerAddress() const;
    QStringList peers() const;
	QUuid uuid() const;

private slots:
	void onConnected();
	void processReadyRead();
	void reconnect();
private:
	QTcpSocket _socket;
    QUrl _url_pair;
	QCborStreamWriter _ecrivain;
	QCborStreamReader _lecteur;
	QUuid _uuid;
	QMap<QUuid, QString>_pseudos;
    DbManager *_historique;

	void traiteMessage(QMap<QString, QString> message);
    void traiteAnciensMessages();
signals:
	void resultReady(const QString &s);
    void nouvMessage(QString message, bool isAncienMessage = false);
	void connected();
	void annuaireChanged();
};

#endif // CLIENT_H
