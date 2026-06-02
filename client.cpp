/* Création de l'historique et suppression : ok
 */

#include "client.h"

using namespace Qt::StringLiterals;

Client::Client(QObject *parent) : QObject(parent), _ecrivain((QIODevice *)nullptr), _lecteur((QIODevice *)nullptr)
{
	_uuid = QUuid::createUuid();
	QString nom = qgetenv("USER");
	if (nom.isEmpty())
		nom = qgetenv("USERNAME");

	_pseudos[_uuid] = nom;
	connect(&_socket, &QTcpSocket::connected, this, &Client::onConnected);
	connect(&_socket, &QTcpSocket::connected, this, &Client::connected);
	connect(&_socket, &QTcpSocket::readyRead, this, &Client::processReadyRead);
    connect(&_socket, &QTcpSocket::errorOccurred, this, &Client::reconnect);
    connect(&_socket, &QTcpSocket::disconnected, this, &Client::reconnect);

    _historique = new DbManager("historique");
}

Client::~Client()
{
    delete _historique;
    qDebug() << "Database closed\n";
}

void Client::onConnected()
{
	_ecrivain.setDevice(&_socket);
	_lecteur.setDevice(&_socket);
	envoie("quelPseudo", "?");

    traiteAnciensMessages();
}

void Client::setUrl_pair(const QUrl &newUrl_pair)
{
    _url_pair = newUrl_pair;
    _socket.connectToHost(_url_pair.host(), _url_pair.port());
}

bool Client::envoie(const QString message)
{
	if (message.isEmpty())
		return false;
	_ecrivain.startMap(2);
	_ecrivain.append("message"_L1);
	_ecrivain.append(message);
	_ecrivain.append("id"_L1);
	_ecrivain.append(_uuid.toString());
	_ecrivain.endMap();
	return true;
}

bool Client::envoie(const QString commande, const QString parametre)
{
	if (commande.isEmpty() || parametre.isEmpty())
		return false;
	_ecrivain.startMap(3);
	_ecrivain.append("commande"_L1);
	_ecrivain.append(commande);
	_ecrivain.append("parametre"_L1);
	_ecrivain.append(parametre);
	_ecrivain.append("id"_L1);
	_ecrivain.append(_uuid.toString());
	_ecrivain.endMap();
	return true;
}

QHostAddress Client::peerAddress() const
{
	return _socket.peerAddress();
}

QStringList Client::peers() const
{
    return _pseudos.values();
}

QUuid Client::uuid() const
{
	return _uuid;
}

void Client::traiteMessage(QMap <QString, QString> message) {
	qDebug() << "Traitement du message : " << message;
	if (message.contains("commande"_L1)) {
		if (message["commande"_L1] == "quelPseudo") {
			envoie("pseudo", _pseudos[_uuid]);
		}
		if (message["commande"_L1] == "pseudo") {
			if (message.contains("parametre")) {
				_pseudos[QUuid::fromString(message["id"])] = message["parametre"];
				emit annuaireChanged();
			}
		}
	}
	else if (_pseudos.contains(QUuid::fromString(message["id"]))) {
		emit nouvMessage(_pseudos[QUuid::fromString(message["id"])] + " dit : " + message["message"_L1]);

        _historique->ajouterMessage(_pseudos[QUuid::fromString(message["id"])] + " dit : " + message["message"_L1]);
	} else {
		emit nouvMessage(message["id"] + " dit : " + message["message"_L1]);

        _historique->ajouterMessage(message["id"] + " dit : " + message["message"_L1]);
	}
}

void Client::traiteAnciensMessages()
{
    // Récupérer les anciens messages
    auto messages = _historique->recupererMessages();

    for (const auto& message : messages) {
        qDebug() << message;
        emit nouvMessage(message, true);
    }
}

void Client::processReadyRead()
{
	QString buffer;
	// we've got more data, let's parse
	_lecteur.reparse();
	while (_lecteur.lastError() == QCborError::NoError) {
		qDebug() << _lecteur.type();
		if (_lecteur.isContainer()) { //Cas normal : on reçoit une map
			QMap <QString, QString> message;
			_lecteur.enterContainer();
			while (_lecteur.hasNext()) {
				if (_lecteur.isString()) {
					auto clef = _lecteur.readString();
					_lecteur.next();
					auto valeur = _lecteur.readString();
					_lecteur.next();
					message[clef.data] = valeur.data;
				}
			}
			_lecteur.leaveContainer();
			traiteMessage(message);
		} else if (_lecteur.isString()) {//Au cas où on n'ait qu'une chaîne TODO : c'est une erreur à gérer
			auto r = _lecteur.readString();
			buffer += r.data;
			if (r.status != QCborStreamReader::EndOfString)
				continue;
		} else if (_lecteur.isNull()) {
			_lecteur.next();
		} else {
			break; // protocol error
		}
	}
	if (!buffer.isEmpty()) {
		emit nouvMessage(buffer);
	}
	if (_lecteur.lastError() != QCborError::EndOfFile) {
		qDebug() << _lecteur.lastError().toString();
		//		abort();       // parse error
	}
	_lecteur.setDevice(&_socket);
}

void Client::reconnect()
{
	_socket.connectToHost(_url_pair.host(), _url_pair.port());
}
