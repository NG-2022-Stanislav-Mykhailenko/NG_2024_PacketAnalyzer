#ifndef PACKETMANAGER_H
#define PACKETMANAGER_H

#include <QObject>
#include <GeneralUtils.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <Packet.h>

class PacketManager : public QObject
{
    Q_OBJECT
public:
    explicit PacketManager(QObject *parent = nullptr);
    static QString getProtocolTypeAsString(pcpp::ProtocolType);
    static QStringList getPacketSourceAndDestination(pcpp::Packet*);
    static QString getPacketData(pcpp::RawPacket*);

signals:
};

#endif // PACKETMANAGER_H
