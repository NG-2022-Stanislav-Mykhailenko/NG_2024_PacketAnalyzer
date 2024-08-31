#ifndef LLMMANAGER_H
#define LLMMANAGER_H

#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkReply>
#include <QObject>

class LlmManager : public QObject
{
    Q_OBJECT
public:
    explicit LlmManager(QObject *parent = nullptr);
    void llmRequest(QString);

signals:
    void responseReceived(QString);
    void errorReceived();

private slots:
    void llmResponse(QNetworkReply *);

private:
    QNetworkAccessManager *m_manager = new QNetworkAccessManager();
};

#endif // LLMMANAGER_H
