#ifndef UPNPMANAGER_H
#define UPNPMANAGER_H

#include <miniupnpc.h>
#include <QString>
#include <QSet>

class UpnpManager
{
public:
	UpnpManager();
	~UpnpManager();
	int redirectUPnP(uint16_t &portPublic, uint16_t portPrive);
	QString ip() const;
private:
	UPNPDev *_devlist;
	UPNPUrls _urls;
	IGDdatas _data;
	QString _ipExterne;
	QSet<int> _mappedPorts;
};

#endif //
