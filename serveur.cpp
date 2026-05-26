#include "serveur.h"

#include "connexion.h"
#include <miniupnpc.h>
#include <upnpcommands.h>
#include <upnperrors.h>

using namespace std;
Serveur::Serveur(QObject *parent)
	: QTcpServer(parent), _portPrive(9158), _portPublic(9158)
{
}

void Serveur::incomingConnection(qintptr socketDescriptor)
{
	QSharedPointer<Connexion> connexion =
		QSharedPointer<Connexion>(new Connexion(socketDescriptor, this), &QObject::deleteLater);
	_pConn << connexion;
	connect(connexion.get(), &Connexion::aTransferer, this, &Serveur::transfere);
	connect(connexion.get(), &QTcpSocket::disconnected, this, &Serveur::onDeconnecter);
	emit connexionsChanged();
}

int Serveur::redirectUPnP(struct UPNPDev *devlist, struct UPNPUrls *urls,
				 struct IGDdatas *data) {
	/*struct UPNPDev *devlist = NULL;
	struct UPNPUrls urls;
	struct IGDdatas data;*/
	int error = 0;

	QString strPortPublic = QString::number(_portPublic);
	QString strPortPrive = QString::number(_portPrive);

    char lanaddr[16];
    char wanaddr[16];

	qDebug() << "Recherche d'un IGD...";
	devlist = upnpDiscover(2000, NULL, NULL, 0, 0, 2, &error);

	if (error != 0) {
		qWarning() << "Erreur pendant la découverte d'équipements upnp : " << strupnperror(error);
		return 1;
	}

#ifdef _WIN32
    int status = UPNP_GetValidIGD(devlist, urls, data, lanaddr, sizeof(lanaddr), wanaddr, sizeof(wanaddr));
#elif __linux__
	int status = UPNP_GetValidIGD(devlist, urls, data, lanaddr, sizeof(lanaddr));
#endif
	if (status != 1) {
		qWarning() <<  "Aucun IGD valide trouvé.";
		freeUPNPDevlist(devlist);
		return 1;
	}
	qDebug() << "status = " << status << "lan_addr = " << lanaddr;

	qDebug() << "IGD valide trouvé : " << urls->controlURL;
	error =
		UPNP_AddPortMapping(urls->controlURL, data->first.servicetype,
							strPortPublic.toStdString().c_str(),  // external port
							strPortPrive.toStdString().c_str(), // internal port
							lanaddr, "Tchatooine", "TCP",
							0,  // remote host
							"0" // lease duration, recommended 0 as some NAT
							// implementations may not support another value
							);

	if (error) {
		qWarning() << "failed to map port";
		qWarning() << "error: " << strupnperror(error);
		return 1;
	}
	qDebug() << "Association des ports faite.";
	error = UPNP_GetExternalIPAddress(urls->controlURL, data->first.servicetype, lanaddr);
	if (error) {
		qWarning() << "Erreur de récupération d'IP externe : " << strupnperror(error);
	}
	_ipExterne = lanaddr;
	qDebug() << "IP externe : " << _ipExterne;
	return 0;
}

QString Serveur::ip() const
{
	return _ipExterne;
}

unsigned int Serveur::nbClients() const
{
	return _pConn.size();
}

uint16_t Serveur::port() const
{
	return _portPublic;
}

void Serveur::getUpNP()
{
	struct UPNPDev *devlist = nullptr;
	struct UPNPUrls urls;
	struct IGDdatas data;
	int resUPnP = redirectUPnP(devlist, &urls, &data);

	if (resUPnP) {
		qWarning() << "La redirection de ports a échoué.";
		return;
	}
}

void Serveur::demarre()
{
	listen(QHostAddress::Any, _portPrive);
}

void Serveur::transfere(QByteArray message) {
	for (auto & c : _pConn) {
		c->envoie(message);
	}
}

void Serveur::onDeconnecter()
{
	for (auto &c : _pConn) {
		if (c.get() == sender()) {
			_pConn.removeAll(c);
			emit connexionsChanged();
			break;
		}
	}
}
