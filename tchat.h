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

private:
    Client _client;
    ServeurAvecUPNP _serveur;
	UpnpManager _upnp;
signals:
    void nouvMessage(QString message, bool isAncienMessage = false);
	void clientConnected();
	void serveurConnected();
	void annuaireChanged();
};

#endif // TCHAT_H
