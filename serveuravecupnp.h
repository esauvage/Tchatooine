#ifndef SERVEURAVECUPNP_H
#define SERVEURAVECUPNP_H

#include <QTcpServer>
#include <QSharedPointer>

#include "upnpmanager.h"
#include "connexion.h"

class ServeurAvecUPNP : public QTcpServer {
	Q_OBJECT
public:
	explicit ServeurAvecUPNP(UpnpManager &upnp, QObject *parent = nullptr);
	void getUpNP();
	void demarre();

	uint16_t port() const; //Seul le port public est visible de l'extérieur
	void setPort(uint16_t v);
	unsigned int nbClients() const;

public slots:
	void transfere(QByteArray message);
	void onDeconnecter();
signals:
	void connexionsChanged();

protected:
	void incomingConnection(qintptr socketDescriptor) override;
private:
	uint16_t _portPrive;
	uint16_t _portPublic;

	QList<QSharedPointer<Connexion>> _pConn;
	UpnpManager &_upnp;
};

#endif // SERVEURAVECUPNP_H
