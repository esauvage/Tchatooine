#include "connexion.h"
#include <QDebug>

Connexion::Connexion(QObject *parent)
    : QTcpSocket{parent}
{
	connect(this, &QTcpSocket::readyRead, this,
			&Connexion::processReadyRead);
}

Connexion::Connexion(qintptr socketDescriptor, QObject *parent)
	: Connexion(parent)
{
	setSocketDescriptor(socketDescriptor);
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
}

bool Connexion::envoie(const QByteArray message)
{
	if (message.isEmpty())
		return false;
	write(message);
	return true;
}
