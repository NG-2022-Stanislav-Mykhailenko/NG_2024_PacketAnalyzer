#include "packetmanager.h"

PacketManager::PacketManager(QObject *parent)
    : QObject{parent}
{}

QString PacketManager::getProtocolTypeAsString(pcpp::ProtocolType protocolType)
{
    switch (protocolType)
    {
    case pcpp::Ethernet:
        return "Ethernet";
    case pcpp::IPv4:
        return "IPv4";
    case pcpp::IPv6:
        return "IPv6";
    case pcpp::TCP:
        return "TCP";
    case pcpp::UDP:
        return "UDP";
    case pcpp::HTTPRequest:
    case pcpp::HTTPResponse:
        return "HTTP";
    case pcpp::ARP:
        return "ARP";
    case pcpp::VLAN:
        return "VLAN";
    case pcpp::ICMP:
        return "ICMP";
    case pcpp::PPPoESession:
    case pcpp::PPPoEDiscovery:
        return "PPPoE";
    case pcpp::DNS:
        return "DNS";
    case pcpp::MPLS:
        return "MPLS";
    case pcpp::GREv0:
    case pcpp::GREv1:
        return "GRE";
    case pcpp::PPP_PPTP:
        return "PPP_PPTP";
    case pcpp::SSL:
        return "SSL";
    case pcpp::SLL:
        return "SLL";
    case pcpp::DHCP:
        return "DHCP";
    case pcpp::NULL_LOOPBACK:
        return "NULL_LOOPBACK";
    case pcpp::IGMPv1:
    case pcpp::IGMPv2:
    case pcpp::IGMPv3:
        return "IGMP";
    case pcpp::GenericPayload:
        return "GenericPayload";
    case pcpp::VXLAN:
        return "VXLAN";
    case pcpp::SIPRequest:
    case pcpp::SIPResponse:
        return "SIP";
    case pcpp::SDP:
        return "SDP";
    case pcpp::PacketTrailer:
        return "PacketTrailer";
    case pcpp::Radius:
        return "Radius";
    case pcpp::GTPv1:
        return "GTP";
    case pcpp::EthernetDot3:
        return "EthernetDot3";
    case pcpp::BGP:
        return "BGP";
    case pcpp::SSH:
        return "SSH";
    case pcpp::AuthenticationHeader:
    case pcpp::ESP:
        return "IPsec";
    case pcpp::DHCPv6:
        return "DHCPv6";
    case pcpp::NTP:
        return "NTP";
    case pcpp::Telnet:
        return "Telnet";
    case pcpp::FTP:
        return "FTP";
    case pcpp::ICMPv6:
        return "ICMPv6";
    case pcpp::STP:
        return "STP";
    case pcpp::LLC:
        return "LLC";
    case pcpp::SomeIP:
        return "SomeIP";
    case pcpp::WakeOnLan:
        return "WakeOnLan";
    case pcpp::NFLOG:
        return "NFLOG";
    case pcpp::TPKT:
        return "TPKT";
    case pcpp::VRRPv2:
    case pcpp::VRRPv3:
        return "VRRP";
    case pcpp::COTP:
        return "COTP";
    case pcpp::SLL2:
        return "SLL2";
    case pcpp::S7COMM:
        return "S7COMM";
    default:
        return "Unknown";
    }
}

QStringList PacketManager::getPacketSourceAndDestination(pcpp::Packet* packet)
{
    QString sourceIP = "Unknown";
    QString destinationIP = "Unknown";

    pcpp::IPv4Layer* ipv4Layer = packet->getLayerOfType<pcpp::IPv4Layer>();
    if (ipv4Layer != NULL)
    {
        sourceIP = QString::fromStdString(ipv4Layer->getSrcIPAddress().toString());
        destinationIP = QString::fromStdString(ipv4Layer->getSrcIPAddress().toString());
    }

    pcpp::IPv6Layer* ipv6Layer = packet->getLayerOfType<pcpp::IPv6Layer>();
    if (ipv6Layer != NULL)
    {
        sourceIP = QString::fromStdString(ipv6Layer->getSrcIPAddress().toString());
        destinationIP = QString::fromStdString(ipv6Layer->getSrcIPAddress().toString());
    }

    QStringList sourceAndDestination;

    sourceAndDestination.append(sourceIP);
    sourceAndDestination.append(destinationIP);

    return sourceAndDestination;
}

QString PacketManager::getPacketData(pcpp::RawPacket *rawPacket)
{
    return QString::fromStdString(pcpp::byteArrayToHexString(rawPacket->getRawData(), rawPacket->getRawDataLen()));
}
