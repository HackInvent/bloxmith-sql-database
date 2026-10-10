"""Statement execution on a node-private SQLite file or an explicitly configured PostgreSQL server."""

from __future__ import annotations

import math
import os
from pathlib import Path
import sqlite3
import stat
import threading
import time
from urllib.parse import quote

from .logic import RowCollector, SqlError, column_names

BUSY_SLICE_MS = 200
FETCH_CHUNK = 256
POLL_SEC = 0.05
READ_ACTIONS = frozenset({sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION,
                          getattr(sqlite3, "SQLITE_RECURSIVE", 33)})
ALWAYS_DENIED = frozenset({sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH})
DENIED_FUNCTIONS = frozenset({"load_extension", "readfile", "writefile", "edit", "fts3_tokenizer"})
# Informational pragma reads used by FTS5/R*Tree constructors and pragma_* table functions.
# Nothing that changes state, and not database_list (it would reveal storage paths).
PRAGMA_READS_WITH_ARGUMENT = frozenset({"table_info", "table_xinfo", "table_list", "index_list", "index_info",
                                        "index_xinfo", "foreign_key_list"})
PRAGMA_READS = frozenset({"data_version", "page_size", "page_count", "freelist_count", "encoding", "schema_version",
                          "user_version", "application_id", "collation_list", "function_list", "module_list",
                          "pragma_list", "compile_options"})


def _quiet(call, *args):
    try:
        call(*args)
    except Exception:  # noqa: BLE001 - best-effort cleanup must not hide the primary outcome.
        pass


class Watchdog:
    """The only poller of cancel_requested during an operation; it interrupts the database call.

    The interrupt target is attached/detached under a lock so it is never invoked on a
    connection that the executing thread is closing.
    """

    def __init__(self, cancel, deadline):
        self._cancel, self._deadline = cancel, deadline
        self._lock, self._stop, self._target = threading.Lock(), threading.Event(), None
        self.reason = self._poll()
        self._thread = threading.Thread(target=self._run, name="sql-database-watchdog", daemon=True)
        self._thread.start()

    def _poll(self):
        try:
            if self._cancel():
                return "cancelled"
        except Exception:  # noqa: BLE001 - an unavailable cancellation service is not a cancellation.
            pass
        return "timeout" if time.monotonic() >= self._deadline else ""

    def _run(self):
        while not self._stop.is_set() and not self.reason:
            reason = self._poll()
            if reason:
                self.reason = reason
                with self._lock:
                    if self._target is not None:
                        _quiet(self._target)
                return
            self._stop.wait(POLL_SEC)

    def attach(self, interrupt):
        with self._lock:
            self._target = interrupt

    def detach(self):
        with self._lock:
            self._target = None

    def close(self):
        self._stop.set()
        self.detach()
        self._thread.join(5)

    def triggered(self):
        return bool(self.reason) or time.monotonic() >= self._deadline

    def error(self, *, committed=False, parameter_set=None):
        if self.reason == "cancelled":
            return SqlError("cancelled", "The operation was cancelled" + _outcome(committed),
                            committed=committed, parameter_set=parameter_set)
        return SqlError("timeout", "The operation exceeded timeout_sec" + _outcome(committed),
                        transient=True, committed=committed, parameter_set=parameter_set)

    def check(self, parameter_set=None):
        if self.triggered():
            raise self.error(parameter_set=parameter_set)


def _outcome(committed):
    return "; the commit outcome is unknown, verify before retrying." if committed is None else "; nothing was committed."


def _drain(cursor, collector, *, keep_going):
    """Fetch in chunks; a query stops at the bound, a write still completes its RETURNING rows."""
    while True:
        rows = cursor.fetchmany(FETCH_CHUNK)
        if not rows:
            return
        for row in rows:
            if not collector.add(collector.columns, row) and not keep_going:
                return


# ---------------------------------------------------------------- SQLite


def database_file(directory, name, *, create):
    """Return the database path inside the node directory, refusing links and foreign files."""
    directory = Path(directory)
    if not directory.is_absolute() or directory.is_symlink() or not directory.is_dir() or directory.resolve() != directory:
        raise SqlError("storage", "A canonical node storage directory is required; no other location is used.")
    path = directory / name
    for suffix in ("", "-journal", "-wal", "-shm"):
        try:
            info = os.lstat(str(path) + suffix)
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise SqlError("storage", "Database and journal files must be private regular files, never links.")
    if os.path.lexists(path):
        return path
    if not create:
        return None
    try:
        handle = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        return database_file(directory, name, create=False)
    except OSError:
        raise SqlError("storage", "The SQLite database file cannot be created in node storage.") from None
    os.close(handle)
    return path


def _authorizer(read_only):
    """Deny attachment (also used by VACUUM INTO), pragma changes and, for queries, every write action."""
    def decide(action, first, second, _database, _source):
        if action in ALWAYS_DENIED:
            return sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_PRAGMA:
            name = str(first or "").lower()
            allowed = name in PRAGMA_READS_WITH_ARGUMENT or (name in PRAGMA_READS and second is None)
            return sqlite3.SQLITE_OK if allowed else sqlite3.SQLITE_DENY
        if action == sqlite3.SQLITE_FUNCTION and str(second or "").lower() in DENIED_FUNCTIONS:
            return sqlite3.SQLITE_DENY
        if read_only and action not in READ_ACTIONS:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    return decide


def _busy(exc):
    name = str(getattr(exc, "sqlite_errorname", "") or "")
    text = str(exc).lower()
    return name.startswith(("SQLITE_BUSY", "SQLITE_LOCKED")) or "database is locked" in text or "table is locked" in text


def _retry_busy(call, watchdog, *args):
    """Lock waits use short busy slices so Stop and the deadline stay observable."""
    while True:
        watchdog.check()
        try:
            return call(*args)
        except sqlite3.OperationalError as exc:
            if not _busy(exc) or watchdog.triggered():
                raise


def _sqlite_error(exc, watchdog, read_only, parameter_set):
    if watchdog.triggered():
        return watchdog.error(parameter_set=parameter_set)
    name = str(getattr(exc, "sqlite_errorname", "") or "")
    text = " ".join(str(exc).split())[:300] or "SQLite reported an error."
    low = text.lower()
    if isinstance(exc, OverflowError):
        return SqlError("params", "A parameter value is outside the SQLite integer range.", parameter_set=parameter_set)
    if isinstance(exc, sqlite3.IntegrityError) or name.startswith("SQLITE_CONSTRAINT"):
        code = "constraint"
    elif name == "SQLITE_AUTH" or "not authorized" in low or "authorization denied" in low:
        code = "read_only" if read_only else "not_authorized"
    elif name.startswith("SQLITE_READONLY") or "readonly database" in low:
        code = "read_only"
    elif _busy(exc):
        code = "busy"
    elif name == "SQLITE_FULL" or "database or disk is full" in low:
        code = "storage_limit"
    elif (name in {"SQLITE_NOTADB", "SQLITE_CORRUPT", "SQLITE_CANTOPEN"} or name.startswith("SQLITE_IOERR")
          or "not a database" in low or "malformed" in low or "unable to open" in low or "disk i/o" in low):
        code = "storage"
    elif isinstance(exc, (sqlite3.InterfaceError, sqlite3.DataError)) or "binding" in low or "unsupported type" in low:
        code = "params"
    elif isinstance(exc, (sqlite3.OperationalError, sqlite3.ProgrammingError)):
        code = "sql"
    else:
        code = "database"
    return SqlError(code, text, transient=code == "busy", parameter_set=parameter_set)


def run_sqlite(plan, sets, config, directory, cancel, deadline):
    """Run one statement for each parameter set in a single transaction (queries are read-only)."""
    read_only = plan["read_only"]
    path = database_file(directory, config["sqlite_file"], create=not read_only)
    watchdog = Watchdog(cancel, deadline)
    database, parameter_set = None, None
    try:
        watchdog.check()
        try:
            if path is None:
                # A query on a database that does not exist yet reads an empty database; no file is created.
                database = sqlite3.connect(":memory:", isolation_level=None, timeout=0)
            elif read_only:
                database = sqlite3.connect("file:" + quote(str(path)) + "?mode=ro", uri=True, isolation_level=None, timeout=0)
            else:
                database = sqlite3.connect(str(path), isolation_level=None, timeout=0)
        except sqlite3.Error:
            raise SqlError("storage", "The SQLite database file cannot be opened.") from None
        watchdog.attach(database.interrupt)
        database.set_progress_handler(lambda: 1 if watchdog.triggered() else 0, 1000)
        if hasattr(database, "enable_load_extension"):
            database.enable_load_extension(False)
        if hasattr(database, "setlimit"):
            database.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
        database.execute(f"PRAGMA busy_timeout={BUSY_SLICE_MS}")
        database.execute("PRAGMA trusted_schema=OFF")
        database.execute("PRAGMA foreign_keys=ON")
        if read_only:
            database.execute("PRAGMA query_only=ON")
        else:
            page = int(database.execute("PRAGMA page_size").fetchone()[0])
            database.execute(f"PRAGMA max_page_count={max(1, config['sqlite_max_database_mb'] * 1048576 // page)}")
        database.set_authorizer(_authorizer(read_only))
        collector, rowcount, last_id = RowCollector(config), 0, None
        cursor = database.cursor()
        if not read_only:
            _retry_busy(database.execute, watchdog, "BEGIN IMMEDIATE")
        for parameter_set, values in enumerate(sets):
            watchdog.check(parameter_set)
            if read_only:
                _retry_busy(cursor.execute, watchdog, plan["sql"], values)
            else:
                cursor.execute(plan["sql"], values)
            if cursor.description is not None:
                if collector.columns is None:
                    collector.columns = column_names(cursor.description)
                _drain(cursor, collector, keep_going=not read_only)
            if not read_only and cursor.rowcount and cursor.rowcount > 0:
                rowcount += cursor.rowcount
                if plan["inserts"] and cursor.lastrowid:
                    last_id = cursor.lastrowid
        parameter_set = None
        watchdog.check()
        if not read_only:
            _retry_busy(database.execute, watchdog, "COMMIT")
        return {"columns": collector.columns, "rows": collector.items, "truncated": collector.truncated,
                "rowcount": len(collector.items) if read_only else rowcount, "last_id": last_id,
                "parameter_sets": len(sets), "committed": not read_only}
    except SqlError as exc:
        if exc.parameter_set is None:
            exc.parameter_set = parameter_set
        raise
    except (sqlite3.Error, OverflowError) as exc:
        raise _sqlite_error(exc, watchdog, read_only, parameter_set) from None
    finally:
        watchdog.close()
        if database is not None:
            _quiet(database.set_progress_handler, None, 0)
            if database.in_transaction:
                _quiet(database.execute, "ROLLBACK")
            _quiet(database.close)


# ---------------------------------------------------------------- PostgreSQL


def _pg_error(exc, watchdog, phase, parameter_set, password, writes):
    committed = None if writes and phase == "commit" else False
    if watchdog.reason:
        return watchdog.error(committed=committed, parameter_set=parameter_set)
    state = str(getattr(exc, "sqlstate", "") or "")
    diag = getattr(exc, "diag", None)
    primary = getattr(diag, "message_primary", None) if diag is not None else None
    lines = str(primary or exc).splitlines() or [""]
    text = " ".join(lines[0].split())[:300]
    if password and len(password) >= 4:
        text = text.replace(password, "***")
    if state == "57014":
        return SqlError("timeout", "The statement exceeded timeout_sec" + _outcome(committed), sqlstate=state,
                        transient=True, committed=committed, parameter_set=parameter_set)
    if phase == "connect":
        return SqlError("connection", ("PostgreSQL connection failed: " + text) if text else "PostgreSQL connection failed.",
                        sqlstate=state or None, transient=not state.startswith("28"), committed=False)
    if state.startswith("23"):
        code = "constraint"
    elif state == "25006":
        code = "read_only"
    elif state == "42501":
        code = "permission"
    elif state.startswith(("42", "0A", "2B", "3F", "34", "26", "3D")):
        code = "sql"
    elif state.startswith("22"):
        code = "params"
    elif state in {"40001", "40P01"}:
        code = "conflict"
    elif state.startswith("55"):
        code = "busy"
    elif not state or state.startswith(("08", "28", "57P")):
        code = "connection"
    else:
        code = "database"
    if committed is None and code != "connection":
        committed = False  # The server answered the COMMIT with an error: the transaction was rolled back.
    message = text or "PostgreSQL reported an error."
    if committed is None:
        message += " The commit outcome is unknown; verify before retrying."
    return SqlError(code, message, sqlstate=state or None, transient=code in {"conflict", "busy", "connection"},
                    committed=committed, parameter_set=parameter_set)


def _cancel_target(connection):
    method = getattr(connection, "cancel_safe", None)
    if callable(method):
        return lambda: method(timeout=5)
    return connection.cancel


def run_postgresql(plan, sets, config, password, cancel, deadline):
    """One connection per activation; queries use a read-only transaction and a server cursor."""
    try:
        import psycopg  # Optional dependency, imported here so the block loads without it.
    except ImportError:
        raise SqlError("dependency", "PostgreSQL needs the optional psycopg package (psycopg>=3.1) "
                       "in the Studio Python environment; nothing was sent.") from None
    writes = not plan["read_only"]
    watchdog = Watchdog(cancel, deadline)
    connection, phase, parameter_set = None, "connect", None
    cursor = None
    try:
        watchdog.check()
        settings = {"host": config["pg_host"], "port": config["pg_port"], "dbname": config["pg_database"],
                    "user": config["pg_user"], "password": password, "passfile": os.devnull,
                    "sslmode": config["pg_sslmode"], "application_name": "bloxsmith-sql-database",
                    "connect_timeout": max(2, math.ceil(max(0.0, deadline - time.monotonic())))}
        if config["pg_sslrootcert"]:
            settings["sslrootcert"] = config["pg_sslrootcert"]
        connection = psycopg.connect(**settings)
        watchdog.attach(_cancel_target(connection))
        watchdog.check()
        phase = "execute"
        connection.read_only = not writes
        milliseconds = str(max(1, int((deadline - time.monotonic()) * 1000)))
        cursor = connection.cursor()
        cursor.execute("SELECT set_config('statement_timeout', %(ms)s, true), set_config('lock_timeout', %(ms)s, true)",
                       {"ms": milliseconds})
        cursor.close()
        collector, rowcount = RowCollector(config), 0
        if not writes:
            parameter_set = 0
            cursor = connection.cursor(name="bloxsmith_sql_query")
            cursor.execute(plan["sql"], sets[0])
            if cursor.description is not None:
                collector.columns = column_names(cursor.description)
                _drain(cursor, collector, keep_going=False)
            rowcount = len(collector.items)
            _quiet(cursor.close)
            cursor, parameter_set = None, None
            watchdog.check()
            connection.rollback()
        else:
            cursor = connection.cursor()
            for parameter_set, values in enumerate(sets):
                watchdog.check(parameter_set)
                cursor.execute(plan["sql"], values, prepare=True)
                if cursor.description is not None:
                    if collector.columns is None:
                        collector.columns = column_names(cursor.description)
                    _drain(cursor, collector, keep_going=True)
                if cursor.rowcount and cursor.rowcount > 0:
                    rowcount += cursor.rowcount
            _quiet(cursor.close)
            cursor, parameter_set = None, None
            watchdog.check()
            phase = "commit"
            connection.commit()
        return {"columns": collector.columns, "rows": collector.items, "truncated": collector.truncated,
                "rowcount": rowcount, "last_id": None, "parameter_sets": len(sets), "committed": writes}
    except SqlError as exc:
        if exc.parameter_set is None:
            exc.parameter_set = parameter_set
        raise
    except psycopg.Error as exc:
        raise _pg_error(exc, watchdog, phase, parameter_set, password, writes) from None
    finally:
        watchdog.close()
        if cursor is not None:
            _quiet(cursor.close)
        if connection is not None:
            if phase != "commit":
                _quiet(connection.rollback)
            _quiet(connection.close)
