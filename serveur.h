#ifndef SERVEUR_H
#define SERVEUR_H

#include <QTcpServer>
#include <QSharedPointer>

#include "connexion.h"

struct UPNPDev;
struct UPNPUrls;
struct IGDdatas;

class Serveur : public QTcpServer {
	Q_OBJECT
public:
	explicit Serveur(QObject *parent = nullptr);
	void getUpNP();
	void demarre();

	uint16_t port() const; //Seul le port public est visible de l'extérieur
	QString ip() const; //Seule l'IP externe est visible de l'extérieur
	unsigned int nbClients() const;

public slots:
	void transfere(QByteArray message);
	void onDeconnecter();
signals:
	void connexionsChanged();

protected:
	void incomingConnection(qintptr socketDescriptor) override;
private:
	int redirectUPnP(UPNPDev *devlist, UPNPUrls *urls, IGDdatas *data);
	uint16_t _portPrive;
	uint16_t _portPublic;
	QString _ipExterne;

	QList<QSharedPointer<Connexion>> _pConn;
};

#endif // SERVEUR_H
