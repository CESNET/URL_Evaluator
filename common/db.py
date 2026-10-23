import pysqlite3 as sqlite3
import logging
from contextlib import contextmanager

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
            self.in_transaction = False
            self.conn.execute('PRAGMA journal_mode=WAL')
            # Enforce foreign key constraints (incl. ON DELETE CASCADE rules
            # introduced by migration 005). SQLite keeps this off by default
            # for backwards compatibility, so every connection must enable it.
            self.conn.execute('PRAGMA foreign_keys=ON')
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
        Execute an SQL command and commit changes (deferred to the end of an
        enclosing transaction(), if any)
        """
        try:
            logger.debug(f"Executing SQL: {query}")
            self.cursor.execute(query, params if params else [])
            if not self.in_transaction:
                self.conn.commit()
        except Exception as e:
            logger.exception(f"Error executing SQL: {e}")
            if not self.in_transaction:
                self.conn.rollback()
            raise
        return self.cursor

    @contextmanager
    def transaction(self):
        """
        Run the enclosed execute() / record_classification() calls in a single
        transaction: committed when the block ends, rolled back as a whole if
        it raises. Unlike execute_many, results of the individual statements
        (lastrowid, rowcount, fetched rows) stay available inside the block.
        """
        if self.in_transaction:
            yield self
            return
        self.conn.execute("BEGIN")
        self.in_transaction = True
        try:
            yield self
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        finally:
            self.in_transaction = False

    def execute_many(self, statements):
        """
        Execute several SQL statements atomically inside a single transaction.

        `statements` is an iterable of (query, params) tuples. Either every
        statement is committed (returns the cursor of the last one) or the
        whole batch is rolled back and the exception is re-raised -- partial
        writes are never persisted. Use this for operations that must stay
        consistent, e.g. deleting a URL together with its dependent data.
        """
        try:
            self.conn.execute("BEGIN")
            last_cursor = None
            for query, params in statements:
                logger.debug(f"Executing SQL (txn): {query}")
                last_cursor = self.cursor.execute(query, params if params else [])
            self.conn.commit()
            return last_cursor
        except Exception as e:
            logger.exception(f"Error executing transactional batch: {e}")
            self.conn.rollback()
            raise

    def record_classification(self, url, classification, reason=None, note=None, actor="system"):
        """
        Append one entry to the classification_history audit trail for `url`.

        Centralised so every writer (evaluator, back-propagation, session
        heuristics, web UI edits) logs decisions in a consistent format.

        `actor` identifies who/what performed the classification: a human
        username from the web UI or a system module identifier
        (e.g. 'evaluator', 'evaluator-backprop', 'session-ddos').

        """
        try:
            logger.debug(f"Recording classification history for {url}: {classification} by {actor}")
            self.cursor.execute(
                "INSERT INTO classification_history (url, classification, reason, note, actor) "
                "VALUES (?, ?, ?, ?, ?)",
                (url, classification, reason, note, actor)
            )
            if not self.in_transaction:
                self.conn.commit()
        except Exception as e:
            logger.warning(f"Could not record classification history for {url}: {e}")
            # A failed statement does not abort an enclosing transaction, so
            # only roll back when there is none (the audit entry is best-effort)
            if not self.in_transaction:
                self.conn.rollback()
