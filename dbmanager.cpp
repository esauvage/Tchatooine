#include "dbmanager.h"

DbManager::DbManager(const QString& path)
{
    _m_db = QSqlDatabase::addDatabase("QSQLITE");
    _m_db.setDatabaseName(path);

    if (!_m_db.open())
    {
        qDebug() << "Error: connection with database failed";
    }
    else
    {
        qDebug() << "Database: connection ok";
    }

    QSqlQuery query;
    query.prepare("CREATE TABLE IF NOT EXISTS messages (\"id\" INTEGER, \"message\" TEXT, PRIMARY KEY(\"id\" AUTOINCREMENT));");
    if (!query.exec()) {
        qDebug() << "Erreur lors de la création de la table : "
                 << query.lastError();
    }
}

bool DbManager::ajouterMessage(const QString &message)
{
    bool success = false;
    // you should check if args are ok first...
    QSqlQuery query;
    query.prepare("INSERT INTO messages (message) VALUES (:message)");
    query.bindValue(":message", message);
    if(query.exec())
    {
        success = true;
    }
    else
    {
        qDebug() << "Erreur lors de l'ajout d'un message dans l'historique :"
                 << query.lastError();
    }

    return success;
}
