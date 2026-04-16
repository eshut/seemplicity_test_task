import psycopg2
import psycopg2.extras
from logger.logger import Logger


class SQLUtil(Logger):
    def __init__(self, host, user, password, database, port, dictionary=False, logger=__file__):
        super().__init__(logger)
        self._conn_params = dict(host=host, user=user, password=password, dbname=database, port=int(port))
        self.db = psycopg2.connect(**self._conn_params)
        self.dictionary = dictionary

    def ensure_connection(self):
        if self.db.closed:
            self.db = psycopg2.connect(**self._conn_params)

    def cursor(self, dictionary=None):
        self.ensure_connection()
        if dictionary is None:
            dictionary = self.dictionary
        if dictionary:
            return self.db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        return self.db.cursor()

    def run_script(self, script, args=None, dictionary=None):
        try:
            cursor = self.cursor(dictionary=dictionary)
            cursor.execute(script, args)
            result = cursor.fetchall()
            cursor.close()
            return result
        except psycopg2.Error as err:
            self.logger.error(f"Error executing script: {err}")
            return None

    def update_data(self, query, args=None):
        try:
            cursor = self.cursor()
            cursor.execute(query, args)
            row_count = cursor.rowcount
            self.db.commit()
            cursor.close()
            self.logger.debug(f"Query executed successfully: {query}")
            return row_count
        except psycopg2.Error as err:
            self.logger.error(f"Error executing update query: {err}")
            self.db.rollback()
            return None

    def close_connect(self):
        if not self.db.closed:
            self.db.close()

    def commit(self):
        self.ensure_connection()
        return self.db.commit()
