#include "tchat.h"

using namespace std;

Tchat::Tchat() :
	_serveur(_upnp){

	connect(&_client, &Client::connected, this, &Tchat::clientConnected);
	connect (&_serveur, &ServeurAvecUPNP::connexionsChanged, this, &Tchat::serveurConnected);
	connect(&_client, &Client::nouvMessage, this, &Tchat::nouvMessage);
	connect(&_client, &Client::annuaireChanged, this, &Tchat::annuaireChanged);
}

void Tchat::init(QString ip, int port)
{
	_serveur.getUpNP();
	_serveur.demarre();
	_client.setUrl_pair(QUrl("https://" + ip + ":" + QString::number(port)));
}

void Tchat::close()
{
}

void Tchat::envoie(const QString message)
{
	_client.envoie(message);
}

void Tchat::setPseudo(const QString pseudo)
{
	_client.envoie("pseudo", pseudo);
}

QHostAddress Tchat::peerAddress() const
{
	return _client.peerAddress();
}

int Tchat::nbClients() const
{
	return _serveur.nbClients();
}

QStringList Tchat::peers() const
{
	return _client.peers();
}

QUuid Tchat::uuid() const
{
	return _client.uuid();
}

UpnpManager &Tchat::upnp()
{
	return _upnp;
}
