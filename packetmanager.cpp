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

QString PacketManager::printHttpMethod(pcpp::HttpRequestLayer::HttpMethod httpMethod)
{
    switch (httpMethod)
    {
    case pcpp::HttpRequestLayer::HttpGET:
        return "GET";
    case pcpp::HttpRequestLayer::HttpPOST:
        return "POST";
    case pcpp::HttpRequestLayer::HttpHEAD:
        return "HEAD";
    case pcpp::HttpRequestLayer::HttpPUT:
        return "PUT";
    case pcpp::HttpRequestLayer::HttpDELETE:
        return "DELETE";
    case pcpp::HttpRequestLayer::HttpCONNECT:
        return "CONNECT";
    case pcpp::HttpRequestLayer::HttpOPTIONS:
        return "OPTIONS";
    case pcpp::HttpRequestLayer::HttpTRACE:
        return "TRACE";
    case pcpp::HttpRequestLayer::HttpPATCH:
        return "PATCH";
    default:
        return "Other";
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
    pcpp::Packet parsedPacket(rawPacket);
    QString packetData = "";

    QStringList sourceAndDestination = getPacketSourceAndDestination(&parsedPacket);

    QString protocol = "Unknown";

    for (pcpp::Layer* curLayer = parsedPacket.getFirstLayer(); curLayer != NULL; curLayer = curLayer->getNextLayer())
    {
        protocol = PacketManager::getProtocolTypeAsString(curLayer->getProtocol());
    }

    packetData.append("Protocol: " + protocol + '\n');

    packetData.append("Source: " + sourceAndDestination[0] + '\n'
                      + "Destination: " + sourceAndDestination[1] + '\n');

    pcpp::EthLayer* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
    if (ethernetLayer)
    {
        packetData.append("Source MAC address: " + QString::fromStdString(ethernetLayer->getSourceMac().toString()) + '\n'
                          + "Destination MAC address: " + QString::fromStdString(ethernetLayer->getDestMac().toString()) + '\n'
                          + "Ether type = 0x" + QString::number(pcpp::netToHost16(ethernetLayer->getEthHeader()->etherType), 16) + '\n');
    }

    pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    if (ipLayer)
    {
        packetData.append("Source IP address: " + QString::fromStdString(ipLayer->getSrcIPAddress().toString()) + '\n'
                          + "Destination IP address: " + QString::fromStdString(ipLayer->getDstIPAddress().toString() + '\n')
                          + "IP ID = 0x" + QString::number(pcpp::netToHost16(ipLayer->getIPv4Header()->ipId), 16) + '\n'
                          + "TTL: " + QString::number(ipLayer->getIPv4Header()->timeToLive) + '\n');
    }

    pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
    if (tcpLayer)
    {
        packetData.append("Source TCP port: " + QString::number(tcpLayer->getSrcPort()) + '\n'
                          + "Destination TCP port: " + QString::number(tcpLayer->getDstPort()) + '\n'
                          + "Window size: " + QString::number(pcpp::netToHost16(tcpLayer->getTcpHeader()->windowSize), 16) + '\n'
                          + "TCP flags: " + getTcpFlags(tcpLayer) + '\n');
    }

    pcpp::HttpRequestLayer* httpRequestLayer = parsedPacket.getLayerOfType<pcpp::HttpRequestLayer>();
    if (httpRequestLayer)
    {
        packetData.append("HTTP method: " + printHttpMethod(httpRequestLayer->getFirstLine()->getMethod()) + '\n'
                          + "HTTP URI: " + QString::fromStdString(httpRequestLayer->getFirstLine()->getUri()) + '\n');
    }

    packetData.append("Raw bytes: " + QString::fromStdString(pcpp::byteArrayToHexString(rawPacket->getRawData(), rawPacket->getRawDataLen())));
    return packetData;
}

QString PacketManager::getTcpFlags(pcpp::TcpLayer *tcpLayer)
{
    QString result = "";
    if (tcpLayer->getTcpHeader()->synFlag == 1)
        result += "SYN ";
    if (tcpLayer->getTcpHeader()->ackFlag == 1)
        result += "ACK ";
    if (tcpLayer->getTcpHeader()->pshFlag == 1)
        result += "PSH ";
    if (tcpLayer->getTcpHeader()->cwrFlag == 1)
        result += "CWR ";
    if (tcpLayer->getTcpHeader()->urgFlag == 1)
        result += "URG ";
    if (tcpLayer->getTcpHeader()->eceFlag == 1)
        result += "ECE ";
    if (tcpLayer->getTcpHeader()->rstFlag == 1)
        result += "RST ";
    if (tcpLayer->getTcpHeader()->finFlag == 1)
        result += "FIN ";

    return result;
}
