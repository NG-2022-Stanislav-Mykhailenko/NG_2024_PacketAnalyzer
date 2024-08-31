#ifndef PACKETANALYZER_H
#define PACKETANALYZER_H

#include <QFileDialog>
#include <QMainWindow>
#include <QMessageBox>
#include <QNetworkInterface>
#include <QTableWidgetItem>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <PcapFileDevice.h>
#include <PcapLiveDeviceList.h>
#include "llmmanager.h"
#include "packetmanager.h"

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
    void llmResponse(QString);
    void llmError();

private:
    Ui::PacketAnalyzer *ui;
    pcpp::PcapLiveDevice* m_dev = nullptr;
    pcpp::RawPacketVector m_packets;
    LlmManager *m_llm = new LlmManager();

    void clear();
    void uiLock();
    void uiUnlock();
};
#endif // PACKETANALYZER_H
