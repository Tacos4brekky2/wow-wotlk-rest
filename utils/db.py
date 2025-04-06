import mysql.connector
from mysql.connector import MySQLConnection
from typing import Optional


def get_connection(
    host: str,
    user: str,
    port: int,
    password: str,
    database: str,
) -> Optional[MySQLConnection | None]:
    """Returns a MongoClient object for making database transactions"""
    connection = mysql.connector.connect(
        host=host, user=user, password=password, database=database, port=port
    )
    if isinstance(connection, MySQLConnection):
        return connection
    else:
        return None
