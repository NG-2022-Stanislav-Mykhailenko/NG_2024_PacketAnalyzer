#include "llmmanager.h"

LlmManager::LlmManager(QObject *parent)
    : QObject{parent}
{
    connect (m_manager, &QNetworkAccessManager::finished, this, &LlmManager::llmResponse);
}

void LlmManager::llmRequest(QString prompt)
{
    QNetworkRequest request(QUrl("http://127.0.0.1:11434/api/generate"));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    QJsonObject json;
    json["model"] = "llama3.1:8b";
    json["prompt"] = prompt;
    json["stream"] = false;

    m_manager->post(request, QJsonDocument(json).toJson());
}

void LlmManager::llmResponse(QNetworkReply *reply)
{
    if (reply->error() == QNetworkReply::NoError) {
        QByteArray textReply = reply->readAll();
        QString responseText = QJsonDocument::fromJson(textReply).object().value("response").toString();
        emit responseReceived(responseText);
    } else {
        emit errorReceived();
    }
}
