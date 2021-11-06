import sqlite3
from sqlite3 import Connection
from datetime import datetime

from os import path
import exceptions


class DbQuery:
    def __init__(self):
        self._conn: Connection = None
        self.__create()

    def _connect(self) -> bool:
        if self._conn:
            self._conn.close()
        try:
            self._conn = sqlite3.connect('server.db')
            self._conn.text_factory = str
        except Exception as e:
            exceptions.log_error("failed to connect the db.", e)
            return False
        return True
    
    def __create(self) -> None:
        if path.exists('server.db'):
            return
        try:
            exceptions.log_info("creating the db table")
            if not self._connect():
                raise exceptions.ConnectionException("Failed to connect the db.")
            client_tableStr = '''CREATE TABLE ClientTbl
                                              (ID VARBINARY(16) PRIMARY KEY,
                                               PublicKey VARBINARY(160) NOT NULL,
                                               UName VARCHAR(255) NOT NULL UNIQUE,
                                               LastSeen TEXT)'''
            message_table = '''CREATE TABLE message_table
                                              (ID INTEGER PRIMARY KEY AUTOINCREMENT,
                                               ToClient VARBINARY(16) ,
                                               FromClient VARBINARY(16) ,
                                               Type TEXT,
                                               Content BLOB,
                                               FOREIGN KEY(ToClient,FromClient) REFERENCES ClientTbl(ID,ID))'''
            curs = self._conn.cursor()
            curs.execute(client_tableStr)
            curs.execute(message_table)

        except sqlite3.Error as e:
            exceptions.log_error("failed to create the db tables.", e)
            print("failed creating the data base tables.")
        finally:
            curs.close()


class ClientTbl(DbQuery):
    def __init__(self):
        super().__init__()

    def insert(self, usr_id, uname, pubkey):
        if self._connect():
            try:
                exceptions.log_info("inserting the user, to the db")
                cur = self._conn.cursor()
                cur.execute("INSERT INTO ClientTbl(ID,PublicKey,UName,LastSeen) VALUES(?,?,?,?)",
                            [usr_id, pubkey, uname, datetime.now()])
                self._conn.commit()
                return True
            except Exception as ex:
                exceptions.log_error("failed to insert client to the db.", ex)
                self._conn.rollback()
            finally:
                if cur:
                    cur.close()
                if self._conn:
                    self._conn.close()
        return False

    def update(self, usr_id):
        if self._connect():
            try:
                cur = self._conn.cursor()
                cur.execute("SELECT COUNT(*) FROM ClientTbl WHERE ID = ?", [usr_id])
                if not cur.fetchone()[0]:  # already exist a user with  usr_id
                    raise Exception("Error : already exist a user with  usr_id: ", usr_id)
                cur.execute("UPDATE ClientTbl SET LastSeen = ? WHERE ID = ?", [datetime.now(), usr_id])
                self._conn.commit()
                cur.close()
                return True
            except Exception as ex:
                exceptions.log_error("failed to update client to the db.", ex)
                self._conn.rollback()
            finally:
                if self._conn:
                    self._conn.close()
        return False

    def get_usr(self, user_id):
        self.update(user_id)
        if self._connect():
            try:
                cur = self._conn.cursor()
                cur.execute("SELECT ID, PublicKey FROM ClientTbl WHERE ID = ?", [user_id])
                return cur.fetchone()
            except Exception as ex:
                exceptions.log_error("failed to get client from the db.", ex)
            finally:
                if cur:
                    cur.close()
                if self._conn:
                    self._conn.close()
        return ""

    def get_usrs(self, uid):
        self.update(uid)
        if self._connect():
            try:
                exceptions.log_info("loading the users list.")
                cur = self._conn.cursor()
                cur.execute("SELECT ID, UName FROM ClientTbl WHERE ID <> ?", [uid])
                return cur.fetchall()
            except Exception as ex:
                exceptions.log_error("failed to get clients from the db.", ex)
            finally:
                if cur:
                    cur.close()
                if self._conn:
                    self._conn.close()
        return []


class MsgTbl(DbQuery):
    def __init__(self):
        super().__init__()

    def __content_converter(self, content: bytes):
        res = ''
        for byte in content:
            res += chr(byte)
        return res

    def pull(self, usr_id):
        ClientTbl().update(usr_id)
        exceptions.log_info("pulling messages from the db")
        if self._connect():
            try:
                cur = self._conn.cursor()
                cur.execute("SELECT FromClient, ID, Type, Content FROM message_table WHERE ToClient = ?", [usr_id])
                pulled_msgs = cur.fetchall()
                # id_lst = [x[1] for x in pulled_msgs]
                # cur.execute("DELETE FROM message_table WHERE ID IN ({})".format(", ".join("?" * len(id_lst))), id_lst)
                self._conn.commit()
                return pulled_msgs
            except Exception as ex:
                exceptions.log_error("failed to pull client messages from the db.", ex)
                self._conn.rollback()
            finally:
                if cur:
                    cur.close()
                if self._conn:
                    self._conn.close()
        return ""

    def insert(self, from_usr, to_usr, msg_type, msg_cntnt) -> int:
        ClientTbl().update(from_usr)
        exceptions.log_info("inserting message to the db")
        if self._connect():
            try:
                cur = self._conn.cursor()
                cur.execute("INSERT INTO message_table(FromClient, ToClient, Type, Content) VALUES(?,?,?,?)",
                            [from_usr, to_usr, str(msg_type), msg_cntnt])
                self._conn.commit()
                cur.execute("SELECT COUNT(ID) FROM message_table")
                return cur.fetchone()[0]
            except Exception as ex:
                exceptions.log_error("failed to insert message to the db", ex)
                self._conn.rollback()
            finally:
                if cur:
                    cur.close()
                if self._conn:
                    self._conn.close()
        return 0
