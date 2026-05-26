#include "connexion.h"
#include <QDebug>

Connexion::Connexion(QObject *parent)
	: QTcpSocket{parent}, _ecrivain(this), _pseudo("")
{
	connect(this, &QTcpSocket::readyRead, this,
			&Connexion::processReadyRead);
}

Connexion::Connexion(qintptr socketDescriptor, QObject *parent)
	: Connexion(parent)
{
	setSocketDescriptor(socketDescriptor);
	_lecteur.setDevice(this);
}

Connexion::~Connexion()
{
	disconnect(this, &QTcpSocket::readyRead, this,
			&Connexion::processReadyRead);
}

void Connexion::processReadyRead()
{
	auto buffer = readAll();
	emit aTransferer(buffer);
// 	QString buffer;
// 	// we've got more data, let's parse
// 	_lecteur.reparse();
// 	while (_lecteur.lastError() == QCborError::NoError) {
// 		qDebug() << _lecteur.type();
// 		if (_lecteur.isMap()) {//La clef est une commande, la valeur est les paramètres
// 			_lecteur.enterContainer();
// 			auto commande = _lecteur.readString();
// 			_lecteur.next();
// 			auto parametre = _lecteur.readString();
// 			_lecteur.leaveContainer();
// 		} else if (_lecteur.isString()) {
// 			auto r = _lecteur.readString();
// 			buffer += r.data;
// 			if (r.status != QCborStreamReader::EndOfString)
// 				continue;
// 		} else if (_lecteur.isNull()) {
// 			_lecteur.next();
// 		} else {
// 			break; // protocol error
// 		}
// 	}
// 	if (_pseudo.isEmpty()) {
// 		_pseudo = buffer;
// 		buffer.clear();
// 	}
// 	if (!buffer.isEmpty()) {
// 		emit nouvMessage(_pseudo + " dit : " + buffer);
// 	}
// 	if (_lecteur.lastError() != QCborError::EndOfFile) {
// 		qDebug() << _lecteur.lastError().toString();
// //		abort();       // parse error
// 	}
// 	_lecteur.setDevice(this);
}

// bool Connexion::envoie(const QString message)
// {
// 	if (message.isEmpty())
// 		return false;
// 	_ecrivain.append(message);
// 	return true;
// }

bool Connexion::envoie(const QByteArray message)
{
	if (message.isEmpty())
		return false;
	write(message);
	return true;
}
