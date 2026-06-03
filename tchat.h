#ifndef TCHAT_H
#define TCHAT_H

#include <QObject>

#include "client.h"
#include "serveuravecupnp.h"

class Tchat : public QObject {
    Q_OBJECT
public:
    Tchat();
	void init(QString ip, int port);
    void exec();
    void close();
	void envoie(const QString message);
	void setPseudo(const QString pseudo);
	QHostAddress peerAddress() const;
	int nbClients() const;
	QStringList peers() const;
	QUuid uuid() const;
	UpnpManager &upnp();
    ServeurAvecUPNP &serveurVideo();
    bool canSendVideo();
    qint64 sendVideoPacket(const QByteArray &packet);

private:
    Client _client;
    ServeurAvecUPNP _serveur;
    ServeurAvecUPNP _serveurVideo;
    UpnpManager _upnp;
    QTcpSocket _clientVideo;
signals:
    void nouvMessage(QString message, bool isAncienMessage = false);
	void clientConnected();
	void serveurConnected();
	void annuaireChanged();
    void serveurIndisponible();
    void peerImage(const QUuid &pair, const QImage &img);
private slots:
    void envoiePortVideo();
    void connectToVideoServeur(int port);
    void onVideoConnected();
    void processReadyRead();
};

#endif // TCHAT_H
