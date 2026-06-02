#include "upnpmanager.h"

#include <upnpcommands.h>
#include <upnperrors.h>

#include <QString>
#include <QDebug>

UpnpManager::UpnpManager()
	:_devlist(nullptr), _ipExterne("localhost"){}

UpnpManager::~UpnpManager() {
	QString proto = "TCP";
	for (auto port : _mappedPorts) {
		QString strPort = QString::number(port);
		UPNP_DeletePortMapping(_urls.controlURL, _data.first.servicetype, strPort.toLocal8Bit(), proto.toLocal8Bit(), nullptr);
	}
	FreeUPNPUrls(&_urls);
	if (_devlist)
		freeUPNPDevlist(_devlist);
}

QString UpnpManager::ip() const
{
	return _ipExterne;
}

int UpnpManager::redirectUPnP(uint16_t &portPublic, uint16_t portPrive) {
	if (_mappedPorts.contains(portPublic)) {
		qDebug() << "Port déjà géré, suivant :" << portPublic;
		portPublic++;
		redirectUPnP(portPublic, portPrive);
		return 0;
	}
	int error = 0;

	char lanaddr[16];

	if (!_devlist) {
		qDebug() << "Recherche d'un IGD...";
		_devlist = upnpDiscover(2000, NULL, NULL, 0, 0, 2, &error);
	}

	if (error != 0) {
		qWarning() << "Erreur pendant la découverte d'équipements upnp : " << strupnperror(error);
		return 1;
	}

	QString proto = "TCP";

#ifdef _WIN32
	char wanaddr[16];
	int status = UPNP_GetValidIGD(_devlist, _urls, _data, lanaddr, sizeof(lanaddr), wanaddr, sizeof(wanaddr));
#elif __linux__
	int status = UPNP_GetValidIGD(_devlist, &_urls, &_data, lanaddr, sizeof(lanaddr));
#endif
	if (status != 1) {
		qWarning() <<  "Aucun IGD valide trouvé.";
		freeUPNPDevlist(_devlist);
		_devlist = nullptr;
		return 1;
	}
	qDebug() << "status = " << status << "lan_addr = " << lanaddr;

	qDebug() << "IGD valide trouvé : " << _urls.controlURL;
	char intClient[40];
	char intPort[6];
	char desc[80];
	char enabled[4];
	char lease[16];

	QString strPortPublic = QString::number(portPublic);
	QString strPortPrive = QString::number(portPrive);

	auto r = UPNP_GetSpecificPortMappingEntry(
		_urls.controlURL,
		_data.first.servicetype,
		strPortPublic.toLocal8Bit(),
		proto.toLocal8Bit(),
		nullptr,
		intClient, intPort, desc, enabled, lease);
	if (r == 0) {
		qDebug() << "Port déjà mappé, on skip :" << portPublic;
		portPublic++;
		redirectUPnP(portPublic, portPrive);
		return 0;
	}
	error =
		UPNP_AddPortMapping(_urls.controlURL, _data.first.servicetype,
							strPortPublic.toLocal8Bit(),  // external port
							strPortPrive.toLocal8Bit(), // internal port
							lanaddr, ("Tchatooine" + strPortPrive).toLocal8Bit(), proto.toLocal8Bit(),
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
	_mappedPorts.insert(portPublic);
	error = UPNP_GetExternalIPAddress(_urls.controlURL, _data.first.servicetype, lanaddr);
	if (error) {
		qWarning() << "Erreur de récupération d'IP externe : " << strupnperror(error);
	}
	_ipExterne = lanaddr;
	qDebug() << "IP externe : " << _ipExterne;
	return 0;
}
