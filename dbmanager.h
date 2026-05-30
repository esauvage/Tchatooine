#ifndef DBMANAGER_H
#define DBMANAGER_H

#include <QString>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QSqlRecord>
#include <QDebug>
#include <QStringList>

class DbManager
{
  public:
    DbManager(const QString& path);
    bool ajouterMessage(const QString& message);
    QStringList recupererMessages();

  private:
    QSqlDatabase _m_db;
};

#endif // DBMANAGER_H
