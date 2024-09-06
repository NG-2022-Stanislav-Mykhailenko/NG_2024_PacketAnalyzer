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

    connect(m_llm, &LlmManager::responseReceived, this, &PacketAnalyzer::llmResponse);
    connect(m_llm, &LlmManager::errorReceived, this, &PacketAnalyzer::llmError);

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
                                   new QTableWidgetItem(PacketManager::getProtocolTypeAsString(curLayer->getProtocol())));
            ui->t_packets->setItem( ui->t_packets->rowCount()-1,
                                   4,
                                   new QTableWidgetItem(QString::number((int)curLayer->getDataLen())));

            QStringList sourceAndDestination = PacketManager::getPacketSourceAndDestination(&parsedPacket);

            ui->t_packets->setItem( ui->t_packets->rowCount()-1,
                                   1,
                                   new QTableWidgetItem(sourceAndDestination[0]));
            ui->t_packets->setItem( ui->t_packets->rowCount()-1,
                                   2,
                                   new QTableWidgetItem(sourceAndDestination[1]));
        }
    }
}

void PacketAnalyzer::packetSelected()
{
    if (ui->t_packets->selectedItems().length() == 0)
        return;
    int packetId = ui->t_packets->selectedItems()[0]->text().toInt();
    pcpp::RawPacket* packet = m_packets.at(packetId-1);
    ui->e_selected->setText(PacketManager::getPacketData(packet));
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
    uiLock();
    m_llm->llmRequest("Please analyze the following packet for anomalies.\n" + ui->e_selected->toPlainText());
}

void PacketAnalyzer::llmResponse(QString responseText)
{
    uiUnlock();
    QMessageBox::information(
        this,
        tr("LLM response"),
        responseText );
}

void PacketAnalyzer::llmError()
{
    uiUnlock();
    QMessageBox::critical(
        this,
        tr("Error"),
        tr("Could not connect to LLM.") );

}

void PacketAnalyzer::uiLock()
{
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


void PacketAnalyzer::uiUnlock()
{
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
