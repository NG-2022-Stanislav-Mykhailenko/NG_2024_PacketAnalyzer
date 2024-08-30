#ifndef PACKETANALYZER_H
#define PACKETANALYZER_H

#include <QFileDialog>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMainWindow>
#include <QMessageBox>
#include <QNetworkInterface>
#include <QNetworkReply>
#include <QTableWidgetItem>
#include <GeneralUtils.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <PcapFileDevice.h>
#include <PcapLiveDeviceList.h>
#include <SystemUtils.h>

QT_BEGIN_NAMESPACE
namespace Ui {
class PacketAnalyzer;
}
QT_END_NAMESPACE

class PacketAnalyzer : public QMainWindow
{
    Q_OBJECT

public:
    PacketAnalyzer(QWidget *parent = nullptr);
    ~PacketAnalyzer();

private slots:
    void changeInterface(QString);
    void refresh();
    void packetSelected();
    void start();
    void stop();
    void save();
    void load();
    void llmRequest();
    void llmResponse(QNetworkReply *);

private:
    Ui::PacketAnalyzer *ui;
    pcpp::PcapLiveDevice* m_dev = nullptr;
    pcpp::RawPacketVector m_packets;
    QNetworkAccessManager *m_manager = new QNetworkAccessManager();
    QString getProtocolTypeAsString(pcpp::ProtocolType);
    void clear();
};
#endif // PACKETANALYZER_H
