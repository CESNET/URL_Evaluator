import pysqlite3 as sqlite3
import logging

LOGFORMAT = "%(asctime)-15s %(name)s [%(levelname)s] %(message)s"
LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
logger = logging.getLogger("db.py")

class SQLiteWrapper:
    def __init__(self, db_path):
        """
        Connect to the DB
        """
        try:
            logger.debug(f"Connecting to {db_path}")
            self.conn = sqlite3.connect(db_path, timeout=30.0)
            self.cursor = self.conn.cursor()
            self.conn.execute('PRAGMA journal_mode=WAL')
        except Exception as e:
            logger.exception(f"Error connecting to DB: {e}")
            raise

    def __enter__(self):
        """
        Enter context manager
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Exit context manager
        """
        logger.debug("Closing the connection")
        self.close()

    def close(self):
        """
        Close the DB connection
        """
        logger.debug("Closing the connection")
        self.cursor.close()
        self.conn.close()

    def execute(self, query, params=None):
        """
        Execute an SQL command and commit changes
        """
        try:
            logger.debug(f"Executing SQL: {query}")
            self.cursor.execute(query, params if params else [])
            self.conn.commit()
        except Exception as e:
            logger.exception(f"Error executing SQL: {e}")
            self.conn.rollback()
            raise
        return self.cursor
