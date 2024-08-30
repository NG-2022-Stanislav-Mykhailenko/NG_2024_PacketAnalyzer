#include "packetanalyzer.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    PacketAnalyzer w;
    w.show();
    return a.exec();
}
