"""Test double of the psycopg 3 API subset used by the SQL Database block.

It is NOT PostgreSQL. It records every call the block makes (connection keywords with
the password replaced by its SHA-256, statements, parameter names, prepare flags,
read-only mode, cancellation) and runs the translated statements on a private SQLite
file so that the block's PostgreSQL code path returns real rows. Like psycopg, it reads
every ``%`` of a query as a format marker, so unescaped literal percent signs fail.

State lives in ``SQL_DATABASE_PG_DOUBLE_DIR`` when set, otherwise next to this file
(tests copy the package into a disposable server root). ``fixture.json`` may declare
``password_sha256`` and ``unreachable_hosts``.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
import time
from urllib.parse import quote

from . import errors
from .errors import (DatabaseError, DataError, Error, IntegrityError, InterfaceError, InternalError,  # noqa: F401
                     NotSupportedError, OperationalError, ProgrammingError)

__version__ = "0.0.0-test-double"
PLACEHOLDER = re.compile(r"%\(([^)]*)\)s")
DECLARABLE = ("SELECT", "WITH", "VALUES", "TABLE")


def state_dir():
    return Path(os.environ.get("SQL_DATABASE_PG_DOUBLE_DIR") or Path(__file__).resolve().parent)


def record(event):
    with (state_dir() / "calls.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, sort_keys=True) + "\n")


def fixture():
    path = state_dir() / "fixture.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def _digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest() if value else ""


def connect(conninfo="", **kwargs):
    """Accept keyword parameters only, as the block passes them."""
    if conninfo:
        raise ProgrammingError("the test double expects keyword connection parameters")
    secret = kwargs.get("password")
    params = {key: value for key, value in kwargs.items() if key != "password"}
    params["password_sha256"] = _digest(secret or "")
    params["password_type"] = type(secret).__name__
    record({"event": "connect", "params": params})
    settings = fixture()
    if kwargs.get("host") in settings.get("unreachable_hosts", []):
        raise OperationalError(f'connection to server at "{kwargs.get("host")}", port {kwargs.get("port")} failed: Connection refused')
    expected = settings.get("password_sha256")
    if expected is not None and params["password_sha256"] != expected:
        raise OperationalError(f'connection to server failed: FATAL:  password authentication failed for user "{kwargs.get("user")}"')
    return Connection(kwargs)


def _scan(query):
    """Split outside single/double quotes; return (segments, inside_flags)."""
    parts, start, quote_char, index = [], 0, "", 0
    while index < len(query):
        char = query[index]
        if quote_char:
            if char == quote_char:
                if index + 1 < len(query) and query[index + 1] == quote_char:
                    index += 2
                    continue
                parts.append((query[start:index + 1], True))
                start, quote_char = index + 1, ""
        elif char in "'\"":
            parts.append((query[start:index], False))
            start, quote_char = index, char
        index += 1
    parts.append((query[start:], bool(quote_char)))
    return parts


def translate(query, params):
    """psycopg semantics for % markers, then PostgreSQL-like checks, then SQLite named style."""
    names, out, index = [], [], 0
    while index < len(query):
        char = query[index]
        if char != "%":
            out.append(char)
            index += 1
            continue
        if query.startswith("%%", index):
            out.append("%")
            index += 2
            continue
        match = PLACEHOLDER.match(query, index)
        if not match:
            raise ProgrammingError(f"only '%s', '%b', '%t' are allowed as placeholders, got '{query[index:index + 2]}'")
        name = match.group(1)
        if name not in params:
            raise ProgrammingError(f"query parameter missing: {name}")
        names.append(name)
        out.append("\x00" + name + "\x00")
        index = match.end()
    text = "".join(out).strip()
    if text.endswith(";"):
        text = text[:-1]
    for segment, quoted in _scan(text):
        if quoted:
            continue
        if ";" in segment:
            raise errors.SyntaxError("cannot insert multiple commands into a prepared statement")
        if re.search(r"(?<!:):[A-Za-z_]", segment):
            raise errors.SyntaxError('syntax error at or near ":"')
    return re.sub(r"\x00([^\x00]*)\x00", r":\1", text), list(dict.fromkeys(names))


class Column:
    def __init__(self, name):
        self.name = name


class Connection:
    def __init__(self, params):
        self.params, self.autocommit, self.closed = params, False, False
        self._read_only, self._db, self._statement_timeout = False, None, None
        self._cancelled = threading.Event()

    @property
    def read_only(self):
        return self._read_only

    @read_only.setter
    def read_only(self, value):
        if self._db is not None:
            raise ProgrammingError("can't change 'read_only' now: connection in transaction status INTRANS")
        self._read_only = bool(value)

    def cursor(self, name=None, **_options):
        return Cursor(self, name)

    def _database(self):
        if self._db is None:
            path = state_dir() / "server.sqlite3"
            if not path.exists():
                sqlite3.connect(path).close()
            if self._read_only:
                self._db = sqlite3.connect("file:" + quote(str(path)) + "?mode=ro", uri=True,
                                           isolation_level=None, check_same_thread=False)
            else:
                self._db = sqlite3.connect(path, isolation_level=None, check_same_thread=False, timeout=5)
            self._db.execute("BEGIN")
            record({"event": "begin", "read_only": self._read_only})
        return self._db

    def _finish(self, statement):
        if self._db is not None:
            try:
                self._db.execute(statement)
            finally:
                self._db.close()
                self._db = None

    def commit(self):
        record({"event": "commit"})
        self._finish("COMMIT")

    def rollback(self):
        record({"event": "rollback"})
        self._finish("ROLLBACK")

    def cancel(self):
        record({"event": "cancel"})
        self._cancelled.set()

    def cancel_safe(self, *, timeout=30.0):
        record({"event": "cancel_safe", "timeout": timeout})
        self._cancelled.set()

    def close(self):
        if self._db is not None:
            self._finish("ROLLBACK")
        self.closed = True
        record({"event": "close"})


def _mapped(exc):
    text = str(exc)
    low = text.lower()
    if isinstance(exc, sqlite3.IntegrityError):
        if "unique" in low:
            return errors.UniqueViolation("duplicate key value violates unique constraint")
        if "not null" in low:
            return errors.NotNullViolation("null value violates not-null constraint")
        return IntegrityError(text)
    if "readonly" in low:
        return errors.ReadOnlySqlTransaction("cannot execute this statement in a read-only transaction")
    if "no such table" in low:
        return errors.UndefinedTable(text.replace("no such table", "relation does not exist"))
    if "no such column" in low:
        return errors.UndefinedColumn(text)
    if "syntax error" in low:
        return errors.SyntaxError(text)
    return DatabaseError(text, sqlstate="XX000")


class Cursor:
    def __init__(self, connection, name):
        self.connection, self.name = connection, name
        self.description, self.rowcount, self._rows, self.closed = None, -1, [], False

    def execute(self, query, params=None, *, prepare=None, binary=None):
        if not isinstance(query, str):
            raise ProgrammingError("the test double accepts text queries only")
        if not isinstance(params, dict):
            raise ProgrammingError("the SQL Database block must always pass a parameter mapping")
        sql, names = translate(query, params)
        record({"event": "execute", "query": query, "params": sorted(params), "prepare": prepare,
                "server_cursor": self.name is not None, "read_only": self.connection.read_only})
        if self.name is not None and sql.lstrip("( \n\t").split(None, 1)[0].upper() not in DECLARABLE:
            raise errors.SyntaxError("DECLARE CURSOR accepts SELECT or VALUES statements only")
        self.connection._database()
        if "set_config(" in sql:
            self.connection._statement_timeout = int(params["ms"])
            record({"event": "timeouts", "statement_timeout": int(params["ms"])})
            self.description, self._rows, self.rowcount = [Column("set_config"), Column("set_config")], [(params["ms"],) * 2], 1
            return self
        sleep = re.fullmatch(r"SELECT pg_sleep\(:(\w+)\)", sql.strip())
        if sleep:
            limit = min(float(params[sleep.group(1)]), (self.connection._statement_timeout or 10 ** 9) / 1000)
            if self.connection._cancelled.wait(limit):
                raise errors.QueryCanceled("canceling statement due to user request")
            if limit < float(params[sleep.group(1)]):
                raise errors.QueryCanceled("canceling statement due to statement timeout")
            self.description, self._rows, self.rowcount = [Column("pg_sleep")], [("",)], 1
            return self
        try:
            cursor = self.connection._db.execute(sql, {name: params[name] for name in names})
            rows = cursor.fetchall() if cursor.description else []
        except sqlite3.Error as exc:
            raise _mapped(exc) from None
        except (OverflowError, sqlite3.InterfaceError) as exc:
            raise DataError(str(exc)) from None
        self.description = [Column(item[0]) for item in cursor.description] if cursor.description else None
        self._rows = rows
        self.rowcount = len(rows) if cursor.description else cursor.rowcount
        return self

    def fetchmany(self, size=1):
        chunk, self._rows = self._rows[:size], self._rows[size:]
        if self.name is not None:
            record({"event": "fetch", "size": size, "returned": len(chunk)})
        return chunk

    def fetchall(self):
        return self.fetchmany(len(self._rows))

    def close(self):
        self.closed = True
