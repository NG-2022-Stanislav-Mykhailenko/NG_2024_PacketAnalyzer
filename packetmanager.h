#ifndef PACKETMANAGER_H
#define PACKETMANAGER_H

#include <QObject>
#include <GeneralUtils.h>
#include <EthLayer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <TcpLayer.h>
#include <HttpLayer.h>
#include <Packet.h>
#include <SystemUtils.h>

class PacketManager : public QObject
{
    Q_OBJECT
public:
    explicit PacketManager(QObject *parent = nullptr);
    static QString getProtocolTypeAsString(pcpp::ProtocolType);
    static QString printHttpMethod(pcpp::HttpRequestLayer::HttpMethod);
    static QStringList getPacketSourceAndDestination(pcpp::Packet*);
    static QString getPacketData(pcpp::RawPacket*);
    static QString getTcpFlags(pcpp::TcpLayer*);

signals:
};

#endif // PACKETMANAGER_H
