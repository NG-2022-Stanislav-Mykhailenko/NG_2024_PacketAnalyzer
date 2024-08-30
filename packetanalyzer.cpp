#include "packetanalyzer.h"
#include "ui_packetanalyzer.h"

PacketAnalyzer::PacketAnalyzer(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::PacketAnalyzer)
{
    ui->setupUi(this);

    connect(ui->cb_interfaces, &QComboBox::currentTextChanged, this, &PacketAnalyzer::changeInterface);
    connect(ui->b_refresh, &QPushButton::clicked, this, &PacketAnalyzer::refresh);
    connect(ui->t_packets, &QTableWidget::itemSelectionChanged, this, &PacketAnalyzer::packetSelected);
    connect(ui->b_start, &QPushButton::clicked, this, &PacketAnalyzer::start);
    connect(ui->b_stop, &QPushButton::clicked, this, &PacketAnalyzer::stop);
    connect(ui->b_save, &QPushButton::clicked, this, &PacketAnalyzer::save);
    connect(ui->b_load, &QPushButton::clicked, this, &PacketAnalyzer::load);
    connect(ui->b_llm, &QPushButton::clicked, this, &PacketAnalyzer::llmRequest);
    connect (m_manager, &QNetworkAccessManager::finished, this, &PacketAnalyzer::llmResponse);

    QList<QNetworkInterface> interfaces = QNetworkInterface::allInterfaces();

    for (QNetworkInterface &interface : interfaces)
        ui->cb_interfaces->addItem(interface.name());
}

PacketAnalyzer::~PacketAnalyzer()
{
    delete ui;

    stop();
}

void PacketAnalyzer::changeInterface(QString)
{
    stop();

    clear();
    m_packets.clear();
    m_dev = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByName(ui->cb_interfaces->currentText().toStdString());
}

void PacketAnalyzer::clear()
{
    ui->t_packets->setRowCount(0);
    ui->e_selected->clear();
}

void PacketAnalyzer::refresh()
{
    clear();
    for (pcpp::RawPacketVector::ConstVectorIterator iter = m_packets.begin(); iter != m_packets.end(); iter++) {
        pcpp::Packet parsedPacket(*iter);
        ui->t_packets->insertRow( ui->t_packets->rowCount() );
        for (pcpp::Layer* curLayer = parsedPacket.getFirstLayer(); curLayer != NULL; curLayer = curLayer->getNextLayer())
        {
            QTableWidgetItem* numberItem = new QTableWidgetItem();
            numberItem->setData(Qt::DisplayRole, ui->t_packets->rowCount());
            ui->t_packets->setItem( ui->t_packets->rowCount()-1,
                                   0,
                                   numberItem);
            ui->t_packets->setItem( ui->t_packets->rowCount()-1,
                                   3,
                                   new QTableWidgetItem(getProtocolTypeAsString(curLayer->getProtocol())));
            ui->t_packets->setItem( ui->t_packets->rowCount()-1,
                                   4,
                                   new QTableWidgetItem(QString::number((int)curLayer->getDataLen())));

            QString sourceIP = "Unknown";
            QString destinationIP = "Unknown";

            pcpp::IPv4Layer* ipv4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
            if (ipv4Layer != NULL)
            {
                sourceIP = QString::fromStdString(ipv4Layer->getSrcIPAddress().toString());
                destinationIP = QString::fromStdString(ipv4Layer->getSrcIPAddress().toString());
            }

            pcpp::IPv6Layer* ipv6Layer = parsedPacket.getLayerOfType<pcpp::IPv6Layer>();
            if (ipv6Layer != NULL)
            {
                sourceIP = QString::fromStdString(ipv6Layer->getSrcIPAddress().toString());
                destinationIP = QString::fromStdString(ipv6Layer->getSrcIPAddress().toString());
            }

            ui->t_packets->setItem( ui->t_packets->rowCount()-1,
                                   1,
                                   new QTableWidgetItem(sourceIP));
            ui->t_packets->setItem( ui->t_packets->rowCount()-1,
                                   2,
                                   new QTableWidgetItem(destinationIP));
        }
    }
}

void PacketAnalyzer::packetSelected()
{
    int packetId = ui->t_packets->selectedItems()[0]->text().toInt();
    pcpp::RawPacket* packet = m_packets.at(packetId-1);
    ui->e_selected->setText(QString::fromStdString(pcpp::byteArrayToHexString(packet->getRawData(), packet->getRawDataLen())));
    ui->b_llm->setEnabled(true);
}

void PacketAnalyzer::start()
{
    if (!m_dev->open())
    {
        QMessageBox::critical(
            this,
            tr("Error"),
            tr("Cannot open device.") );
        return;
    }
    clear();
    m_packets.clear();
    m_dev->startCapture(m_packets);
    ui->b_start->setEnabled(false);
    ui->b_stop->setEnabled(true);
    ui->b_save->setEnabled(false);
}

void PacketAnalyzer::stop()
{
    if (m_dev == NULL || !m_dev->captureActive())
        return;
    m_dev->stopCapture();
    ui->b_start->setEnabled(true);
    ui->b_stop->setEnabled(false);
    ui->b_save->setEnabled(true);
}

void PacketAnalyzer::save()
{
    QString fileName = QFileDialog::getSaveFileName(this, "Select file", "", "pcap-ng files (*.pcapng)");

    if (fileName.isEmpty())
        return;

    pcpp::PcapNgFileWriterDevice writer(fileName.toStdString());

    if (!writer.open())
    {
        QMessageBox::critical(
            this,
            tr("Error"),
            tr("Cannot open output file for writing.") );
        return;
    }

    writer.writePackets(m_packets);

    writer.close();
}

void PacketAnalyzer::load()
{
    QString fileName = QFileDialog::getOpenFileName(this, "Select file", "", "pcap-ng files (*.pcapng)");

    if (fileName.isEmpty())
        return;

    pcpp::PcapNgFileReaderDevice reader(fileName.toStdString());

    if (!reader.open())
    {
        QMessageBox::critical(
            this,
            tr("Error"),
            tr("Cannot open input file for reading.") );
        return;
    }

    stop();
    clear();
    m_packets.clear();

    reader.getNextPackets(m_packets);

    reader.close();

    refresh();
}

void PacketAnalyzer::llmRequest()
{
    QNetworkRequest request(QUrl("http://127.0.0.1:11434/api/generate"));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QJsonObject json;
    json["model"] = "llama3.1:8b";
    json["prompt"] = "Please analyze the following packet for anomalies.\n" + ui->e_selected->toPlainText();
    json["stream"] = false;

    m_manager->post(request, QJsonDocument(json).toJson());

    ui->b_llm->setEnabled(false);
    ui->b_load->setEnabled(false);
    ui->b_refresh->setEnabled(false);
    if (m_dev == NULL || !m_dev->captureActive())
        ui->b_start->setEnabled(false);
    else
        ui->b_stop->setEnabled(false);
    ui->cb_interfaces->setEnabled(false);
    ui->t_packets->setSelectionMode(QAbstractItemView::NoSelection);
}


void PacketAnalyzer::llmResponse(QNetworkReply *reply)
{
    if (reply->error() == QNetworkReply::NoError) {
        QByteArray textReply = reply->readAll();
        QString responseText = QJsonDocument::fromJson(textReply).object().value("response").toString();
        QMessageBox::information(
            this,
            tr("LLM response"),
            responseText );
    } else {
        QMessageBox::critical(
            this,
            tr("Error"),
            tr("Could not connect to LLM.") );
    }
    ui->b_llm->setEnabled(true);
    ui->b_load->setEnabled(true);
    ui->b_refresh->setEnabled(true);
    if (m_dev == NULL || !m_dev->captureActive())
        ui->b_start->setEnabled(true);
    else
        ui->b_stop->setEnabled(true);
    ui->cb_interfaces->setEnabled(true);
    ui->t_packets->setSelectionMode(QAbstractItemView::SingleSelection);
}

QString PacketAnalyzer::getProtocolTypeAsString(pcpp::ProtocolType protocolType)
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
