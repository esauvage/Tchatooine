#include "tchat.h"

#include <QImage>

using namespace std;

Tchat::Tchat() :
    _serveur(_upnp), _serveurVideo(_upnp){

    connect(&_client, &Client::connected, this, &Tchat::clientConnected);
    connect(&_client, &Client::serveurIndisponible, this, &Tchat::serveurIndisponible);
    connect (&_serveur, &ServeurAvecUPNP::connexionsChanged, this, &Tchat::serveurConnected);
	connect(&_client, &Client::nouvMessage, this, &Tchat::nouvMessage);
    connect(&_client, &Client::annuaireChanged, this, &Tchat::annuaireChanged);
    connect(&_client, &Client::portVideoDemande, this, &Tchat::envoiePortVideo);
    connect(&_client, &Client::portVideo, this, &Tchat::connectToVideoServeur);
    _serveur.getUpNP();
    _serveur.demarre();
    _serveurVideo.setPort(9159);
    _serveurVideo.getUpNP();
    _serveurVideo.demarre();
}

void Tchat::init(QString ip, int port)
{
	_client.setUrl_pair(QUrl("https://" + ip + ":" + QString::number(port)));
}

void Tchat::close()
{
}

void Tchat::envoie(const QString message)
{
	_client.envoie(message);
}

void Tchat::envoiePortVideo()
{
    _client.envoie("portVideo", QString::number(_serveurVideo.port()));
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

ServeurAvecUPNP &Tchat::serveurVideo()
{
    return _serveurVideo;
}

bool Tchat::canSendVideo()
{
    return _clientVideo.state() == QAbstractSocket::ConnectedState;
}

qint64 Tchat::sendVideoPacket(const QByteArray &packet)
{
    return _clientVideo.write(packet);
}

void Tchat::connectToVideoServeur(int port)
{
    connect(&_clientVideo, &QTcpSocket::connected, this, &Tchat::onVideoConnected);
    _clientVideo.connectToHost(_upnp.ip(), port);
}

void Tchat::onVideoConnected()
{
    connect(&_clientVideo, &QTcpSocket::readyRead, this, &Tchat::processReadyRead);
}

void Tchat::processReadyRead() {
    QTcpSocket *client = qobject_cast<QTcpSocket*>(sender());
    if (!client) return;
    QDataStream in(client);

    in.startTransaction();

    QUuid uuid;
    QByteArray imageData;

    in >> uuid;
    in >> imageData;

    if (!in.commitTransaction())
    {
        return;
    }
    // 3. décoder
    QImage image;
    image.loadFromData(imageData, "JPEG");

    if (!image.isNull()) {
        emit peerImage(uuid, image);
    }
}
