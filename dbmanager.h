#ifndef DBMANAGER_H
#define DBMANAGER_H

#include <QString>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QDebug>

class DbManager
{
  public:
    DbManager(const QString& path);
    bool ajouterMessage(const QString& message);

  private:
    QSqlDatabase _m_db;
};

#endif // DBMANAGER_H
