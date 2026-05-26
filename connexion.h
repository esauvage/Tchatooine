#ifndef CONNEXION_H
#define CONNEXION_H

#include <QCborStreamReader>
#include <QCborStreamWriter>
#include <QTcpSocket>

class Connexion : public QTcpSocket
{
	Q_OBJECT
public:
	explicit Connexion(QObject *parent = nullptr);
	explicit Connexion(qintptr socketDescriptor, QObject *parent = nullptr);
	virtual ~Connexion();
	// bool envoie(const QString message);
	bool envoie(const QByteArray message);
private slots:
	void processReadyRead();
private:
	QCborStreamReader _lecteur;
	QCborStreamWriter _ecrivain;
	QString _pseudo;
signals:
	void nouvMessage(QString message);
	void aTransferer(QByteArray message);
};

#endif // CONNEXION_H
