#ifndef TCHAT_H
#define TCHAT_H

#include <QObject>

#include "client.h"
#include "serveur.h"

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
private:
    Client _client;
    Serveur _serveur;
signals:
    void nouvMessage(QString message, bool isAncienMessage);
	void clientConnected();
	void serveurConnected();
	void annuaireChanged();
};

#endif // TCHAT_H
