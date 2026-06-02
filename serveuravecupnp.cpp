#include "serveuravecupnp.h"

#include "connexion.h"

using namespace std;
ServeurAvecUPNP::ServeurAvecUPNP(UpnpManager &upnp, QObject *parent)
	: QTcpServer(parent), _portPrive(9158), _portPublic(9158), _upnp(upnp)
{
}

void ServeurAvecUPNP::incomingConnection(qintptr socketDescriptor)
{
	QSharedPointer<Connexion> connexion =
		QSharedPointer<Connexion>(new Connexion(socketDescriptor, this), &QObject::deleteLater);
	_pConn << connexion;
    connect(connexion.get(), &Connexion::aTransferer, this, &ServeurAvecUPNP::transfere);
    connect(connexion.get(), &QTcpSocket::disconnected, this, &ServeurAvecUPNP::onDeconnecter);
	emit connexionsChanged();
}

unsigned int ServeurAvecUPNP::nbClients() const
{
	return _pConn.size();
}

uint16_t ServeurAvecUPNP::port() const
{
	return _portPublic;
}

void ServeurAvecUPNP::setPort(uint16_t v)
{
	_portPrive = v;
	_portPublic = v;
}

void ServeurAvecUPNP::getUpNP()
{
	int resUPnP = _upnp.redirectUPnP(_portPublic, _portPrive);

	if (resUPnP) {
		qWarning() << "La redirection de ports a échoué.";
		return;
	}
}

void ServeurAvecUPNP::demarre()
{
	listen(QHostAddress::Any, _portPrive);
}

void ServeurAvecUPNP::transfere(QByteArray message) {
	for (auto & c : _pConn) {
		c->envoie(message);
	}
}

void ServeurAvecUPNP::onDeconnecter()
{
	for (auto &c : _pConn) {
		if (c.get() == sender()) {
			_pConn.removeAll(c);
			emit connexionsChanged();
			break;
		}
	}
}
