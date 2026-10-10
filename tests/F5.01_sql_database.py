"""FB1/FB2/FB3/FB4/FB5: statement policy, parameter binding, real SQLite and the psycopg double.

No real PostgreSQL server or credential is used: the PostgreSQL path runs against the
package-owned psycopg test double in ``pg_double/`` (it records what the block hands to
psycopg and executes translated statements on a private SQLite file).
"""

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile
import time
from types import MappingProxyType, SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]
from blocs.sql_database import drivers, engine, logic
from blocs.sql_database.block import SqlDatabaseBlock
from bloxsmith_app.block_api import BlockRuntimeContext

# - FB5 - The block must load without the optional driver: nothing imports psycopg at module level.
assert "psycopg" not in sys.modules, "psycopg must be imported lazily"
sys.path.insert(0, str(Path(__file__).resolve().parent / "pg_double"))

PASSWORD = "fixture-pg-password-7Q"
REF = "secret://workspace/pg_fixture"
OUTPUTS = (SimpleNamespace(id=1, name="rows"), SimpleNamespace(id=2, name="result"), SimpleNamespace(id=3, name="error"))
INPUTS = (SimpleNamespace(id=1, name="params"),)


def config_error(raw, fragment=""):
    """Invalid settings are refused with an explicit message, before any side effect."""
    try:
        logic.configuration(raw)
    except logic.ConfigError as exc:
        assert fragment.lower() in str(exc).lower(), (fragment, str(exc))
        return str(exc)
    raise AssertionError(f"Accepted invalid settings: {raw}")


def sql_rejected(sql, driver="sqlite", operation="query", fragment=""):
    try:
        logic.compile_sql(sql, driver, operation)
    except logic.ConfigError as exc:
        assert fragment.lower() in str(exc).lower(), (sql, str(exc))
        return
    raise AssertionError(f"Accepted unsafe or ambiguous SQL: {sql!r}")


def run(settings, params, directory=None, *, cancel=lambda: False, secret=PASSWORD, raise_secret=False):
    config = logic.configuration(settings)

    def resolve(reference):
        assert reference == REF, reference
        if raise_secret:
            raise RuntimeError("wallet locked: " + PASSWORD)
        return secret
    return engine.execute(params, config, {"cancel_requested": cancel, "resolve_secret": resolve,
                                           "get_block_storage_dir": (lambda: directory) if directory else None})


def ok(values):
    assert "error" not in values, values.get("error")
    return values


def failed(values, code):
    assert set(values) == {"error"}, values
    assert values["error"]["code"] == code, values["error"]
    return values["error"]


def check_configuration():
    """FB1: trusted settings, allowlisted statements, identifiers, TLS and wallet references."""
    # - FB1 - Defaults are a harmless SQLite connectivity check, valid in every form.
    default = logic.configuration({})
    assert default["plans"]["default"]["sql"] == "SELECT 1 AS ok" and default["plans"]["default"]["read_only"]
    frozen = MappingProxyType({**SqlDatabaseBlock().default_config(), "columns": ("a",), "statements": MappingProxyType({})})
    assert logic.configuration(frozen)["columns"] == ["a"]
    config_error({"unknown": 1}, "unknown setting")
    config_error({"driver": "mysql"}, "driver")
    config_error({"operation": "drop"}, "operation")
    config_error({"operation": "execute", "sql": "DELETE FROM t"}, "allow_writes")
    config_error({"operation": "insert_rows", "table": "t", "columns": ["a"]}, "allow_writes")
    config_error({"allow_writes": "yes"}, "allow_writes")
    for key, value in (("timeout_sec", 0), ("timeout_sec", 301), ("max_rows", True), ("max_rows", 10001),
                       ("max_result_bytes", 100), ("max_batch_rows", 0), ("sqlite_max_database_mb", 5000), ("pg_port", 70000)):
        config_error({key: value}, key)
    for name in ("../escape.sqlite3", "/abs/path.db", "dir/file.db", "notes.txt", ".hidden.db", "a..b.db", ""):
        config_error({"sqlite_file": name}, "sqlite_file")
    writes = {"allow_writes": True}
    insert = {**writes, "operation": "insert_rows", "table": "items", "columns": ["sku", "name"]}
    assert logic.configuration(insert)["plans"]["default"]["sql"] == 'INSERT INTO "items" ("sku", "name") VALUES (:sku, :name)'
    for table in ("items; DROP TABLE x", 'it"ems', "a.b.c", "1items", ""):
        config_error({**insert, "table": table}, "table")
    config_error({**insert, "columns": []}, "columns")
    config_error({**insert, "columns": ["sku", "SKU"]}, "duplicate")
    config_error({**insert, "columns": ["name with space"]}, "columns")
    upsert = {**insert, "operation": "upsert", "conflict_columns": ["sku"]}
    plan = logic.configuration(upsert)["plans"]["default"]
    assert plan["sql"].endswith('ON CONFLICT ("sku") DO UPDATE SET "name" = excluded."name"'), plan["sql"]
    pg_plan = logic.configuration({**upsert, **pg_settings(), "table": "app.items"})["plans"]["default"]
    assert pg_plan["sql"].startswith('INSERT INTO "app"."items"') and "VALUES (%(sku)s, %(name)s)" in pg_plan["sql"]
    nothing = logic.configuration({**upsert, "columns": ["sku"], "conflict_columns": ["sku"]})["plans"]["default"]
    assert nothing["sql"].endswith("DO NOTHING")
    config_error({**upsert, "conflict_columns": ["other"]}, "conflict_columns")
    config_error({**upsert, "update_columns": ["sku"]}, "conflict column")
    config_error({**upsert, "conflict_columns": []}, "conflict_columns")
    # - FB5 - PostgreSQL needs explicit connection settings; passwords are only wallet references.
    config_error({"driver": "postgresql"}, "pg_host")
    config_error({**pg_settings(), "pg_password_ref": "hunter2-plain-password"}, "wallet reference")
    config_error({**pg_settings(), "pg_host": "postgresql://user:pw@db/app"}, "pg_host")
    config_error({**pg_settings(), "pg_host": " db.example.test"}, "spaces")
    config_error({**pg_settings(), "pg_sslmode": "prefer"}, "pg_sslmode")
    config_error({**pg_settings(), "pg_sslmode": "disable"}, "local")
    for host in ("localhost", "127.0.0.1", "::1", "/run/postgresql"):
        assert logic.configuration({**pg_settings(), "pg_host": host, "pg_sslmode": "disable"})
    config_error({**pg_settings(), "pg_sslrootcert": "relative.pem"}, "pg_sslrootcert")
    assert logic.configuration({**pg_settings(), "pg_sslrootcert": "system"})
    assert logic.configuration({**pg_settings(), "pg_password_ref": "secret://project/demo/pg_app"})
    # Named statements share the same validation and the same write gate.
    named = {**writes, "statements": {"init": {"operation": "execute", "sql": "CREATE TABLE IF NOT EXISTS t (a)"},
                                      "list_rows": {"operation": "query", "sql": "SELECT a FROM t WHERE a > :low"}}}
    plans = logic.configuration(named)["plans"]
    assert set(plans) == {"default", "init", "list_rows"} and plans["list_rows"]["placeholders"] == ["low"]
    config_error({"statements": {"init": named["statements"]["init"]}}, "allow_writes")
    config_error({**named, "statements": {"default": {"operation": "query", "sql": "SELECT 1"}}}, "statement names")
    config_error({**named, "statements": {"bad-name": {"operation": "query", "sql": "SELECT 1"}}}, "statement names")
    config_error({**named, "statements": {"x": {"operation": "query", "sql": "SELECT 1", "extra": 1}}}, "accepts")
    config_error({**named, "statements": {"x": {"operation": "query", "sql": "SELECT 1; SELECT 2"}}}, "statement x")
    config_error({"statements": {f"s{index}": {"operation": "query", "sql": "SELECT 1"} for index in range(17)}}, "at most")
    config_error({"statements": []}, "statements")


def pg_settings(**extra):
    return {"driver": "postgresql", "pg_host": "db.example.test", "pg_database": "app", "pg_user": "app_user",
            "pg_password_ref": REF, **extra}


def check_statements():
    """FB1: one statement, allowlisted keyword, named placeholders, string/comment awareness."""
    # - FB1 - Chained statements, transaction control, ATTACH/PRAGMA/VACUUM/COPY and positional markers are refused.
    for sql in ("SELECT 1; SELECT 2", "SELECT 1; DROP TABLE t", "SELECT 1;;", "SELECT 1 /* x */ ; DELETE FROM t"):
        sql_rejected(sql, fragment="one sql statement")
    sql_rejected("DELETE FROM t", fragment="query accepts")
    sql_rejected("/* SELECT */ DELETE FROM t", fragment="DELETE")
    sql_rejected("-- SELECT\nUPDATE t SET a = 1", fragment="UPDATE")
    for sql in ("ATTACH DATABASE 'x.db' AS x", "PRAGMA writable_schema = ON", "VACUUM INTO 'copy.db'",
                "BEGIN", "COMMIT", "SELECT 1", "EXPLAIN DELETE FROM t", "DETACH x", "REINDEX"):
        sql_rejected(sql, operation="execute")
    for sql in ("COPY t TO PROGRAM 'id'", "DO $$ BEGIN END $$", "CALL p()", "SET search_path = x", "LOAD 'x'", "GRANT ALL ON t TO u"):
        sql_rejected(sql, driver="postgresql", operation="execute")
    sql_rejected("SELECT ?", fragment="placeholders")
    sql_rejected("SELECT @x", fragment="placeholders")
    sql_rejected("SELECT $x", fragment="placeholders")
    sql_rejected("SELECT :1", fragment="numbered")
    sql_rejected("SELECT $1", driver="postgresql", fragment="positional")
    sql_rejected("SELECT %s", fragment="positional")
    sql_rejected("SELECT 10 %(x)", fragment="malformed")
    sql_rejected("SELECT :naïve", fragment="placeholder names")
    for sql in ("SELECT 'unterminated", "SELECT \"x", "SELECT /* open", "", "   ", "SELECT 1\x00"):
        sql_rejected(sql)
    sql_rejected("SELECT $$ open", driver="postgresql", fragment="dollar")
    # Strings, identifiers and comments never hide placeholders or separators.
    compiled = logic.compile_sql("SELECT ':no;', \"col;:x\", [b;:y], `c;` FROM t -- ; :z\nWHERE a = :a AND b = %(b)s;", "sqlite", "query")
    assert compiled["placeholders"] == ["a", "b"] and compiled["sql"].endswith("b = :b"), compiled
    pg = logic.compile_sql("SELECT x::int, E'it\\'s :no %', $tag$ ; :no % $tag$, '%(no)s' FROM t "
                           "/* outer /* nested ; */ still */ WHERE j ? 'k' AND a = :a AND b LIKE 'v%'", "postgresql", "query")
    assert pg["placeholders"] == ["a"], pg
    assert "x::int" in pg["sql"] and "'v%%'" in pg["sql"] and "'%%(no)s'" in pg["sql"] and "%(a)s" in pg["sql"], pg["sql"]
    sql_rejected("SELECT 1 /* a /* b */ ; DELETE FROM t */", driver="sqlite")
    assert logic.compile_sql("SELECT 1 /* a /* b */ ; DELETE FROM t */", "postgresql", "query")["keyword"] == "SELECT"
    assert logic.compile_sql("(SELECT 1) UNION (SELECT 2)", "sqlite", "query")["keyword"] == "SELECT"
    assert logic.compile_sql("SELECT 10 % 3 AS m, 5 %salary FROM t", "postgresql", "query")["sql"].count("%%") == 2
    trigger = ("CREATE TRIGGER audit AFTER INSERT ON items BEGIN INSERT INTO log VALUES (new.sku); "
               "UPDATE stats SET n = CASE WHEN n IS NULL THEN 1 ELSE n + 1 END; END;")
    assert logic.compile_sql(trigger, "sqlite", "execute")["keyword"] == "CREATE"
    sql_rejected(trigger + " DROP TABLE items", operation="execute", fragment="after the trigger")
    sql_rejected("CREATE TRIGGER t AFTER INSERT ON a BEGIN SELECT 1; END; SELECT 2", operation="execute")


def check_parameters():
    """FB2: strict JSON, required placeholders, envelope selection and safe value binding."""
    config = logic.configuration({"allow_writes": True, "sql": "SELECT :a AS a, %(b)s AS b",
                                  "statements": {"save": {"operation": "insert_rows", "table": "t", "columns": ["a", "b"]}},
                                  "max_batch_rows": 3, "max_params_bytes": 1024})
    plan, sets = logic.request('{"a": 1, "b": {"nested": [1, 2]}, "unused": "ignored"}', config)
    assert plan["name"] == "default" and sets == [{"a": 1, "b": '{"nested":[1,2]}'}]
    plan, sets = logic.request({"$statement": "save", "$params": [{"a": None, "b": True}, {"a": "x", "b": 2.5}]}, config)
    assert plan["name"] == "save" and sets == [{"a": None, "b": True}, {"a": "x", "b": 2.5}]
    assert logic.request({"$statement": "default", "$params": {"a": 1, "b": 2}}, config)[0]["name"] == "default"
    assert logic.request({"$statement": "save", "$params": []}, config)[1] == []

    def bad(raw, fragment):
        try:
            logic.request(raw, config)
        except logic.SqlError as exc:
            assert exc.code == "params" and fragment.lower() in str(exc).lower(), (raw, str(exc))
            assert "secret-value" not in str(exc)
            return exc
        raise AssertionError(f"Accepted invalid params: {raw!r}")
    # - FB2 - Missing values and malformed messages fail before any database access, without echoing values.
    assert bad('{"a": "secret-value"}', "missing value for b").parameter_set == 0
    bad('{"a": 1, "a": 2, "b": 3}', "duplicate")
    bad('{"a": NaN, "b": 1}', "nan")
    bad('{"a": 1, "b": Infinity}', "nan")
    bad("not json", "strict json")
    bad("", "empty")
    bad("[1, 2]", "query accepts one")
    bad("42", "object")
    bad('{"$statement": "missing"}', "unknown $statement")
    bad('{"$statement": "save", "$params": {}, "extra": 1}', "accepts $statement")
    bad('{"$params": {}}', "reserved")
    bad({"$statement": "save", "$params": [{"a": 1, "b": 1}] * 4}, "max_batch_rows")
    bad({"$statement": "save", "$params": [{"a": 1, "b": 1}, 3]}, "every item")
    bad({"a": "x" * 2000, "b": 1}, "max_params_bytes")
    bad({"a": float("inf"), "b": 1}, "nan")
    bad({"a": 2 ** 70, "b": 1}, "64-bit")
    deep = current = {}
    for _ in range(40):
        current["x"] = {}
        current = current["x"]
    bad({"a": deep, "b": 1}, "depth")


def check_results():
    """FB4: deterministic JSON cells and explicit row/byte limits."""
    import datetime
    import decimal
    import uuid
    assert logic.cell(decimal.Decimal("12.50")) == "12.50" and logic.cell(b"\x00\xff") == {"base64": "AP8="}
    assert logic.cell(datetime.datetime(2026, 1, 2, 3, 4, 5)) == "2026-01-02T03:04:05"
    assert logic.cell(datetime.timedelta(minutes=2)) == 120.0 and logic.cell(float("nan")) == "nan"
    assert logic.cell(uuid.UUID(int=1)) == "00000000-0000-0000-0000-000000000001"
    assert logic.cell({"a": (1, decimal.Decimal("2"))}) == {"a": [1, "2"]}
    try:
        logic.column_names([("id",), ("id",)])
        raise AssertionError("Duplicate column names accepted")
    except logic.SqlError as exc:
        assert exc.code == "sql" and "alias" in str(exc)


def check_sqlite(root):
    """FB3/FB4: real SQLite in a node directory, read-only queries, atomic writes, bounds and Stop."""
    node = root / "node"
    node.mkdir(mode=0o700)
    base = {"allow_writes": True, "timeout_sec": 5}
    # - FB3 - Reading a database that does not exist yet reads an empty database and creates no file.
    rows = ok(run({}, "{}", node))
    assert rows["rows"] == [{"ok": 1}] and rows["result"]["rowcount"] == 1 and not rows["result"]["committed"]
    assert not list(node.iterdir())
    failed(run({"sql": "SELECT * FROM items"}, "{}", node), "sql")
    schema = ("CREATE TABLE items (sku TEXT PRIMARY KEY, name TEXT NOT NULL, stock INTEGER NOT NULL CHECK (stock >= 0), "
              "price NUMERIC, data BLOB)")
    created = ok(run({**base, "operation": "execute", "sql": schema}, "{}", node))
    assert created["result"]["committed"] and "rows" not in created
    database = node / "database.sqlite3"
    assert stat.S_IMODE(database.stat().st_mode) == 0o600
    insert = {**base, "operation": "insert_rows", "table": "items", "columns": ["sku", "name", "stock"]}
    inserted = ok(run(insert, [{"sku": "A-1", "name": "Widget", "stock": 3}, {"sku": "B-2", "name": "Gadget", "stock": 5, "x": 1}], node))
    assert inserted["result"]["rowcount"] == 2 and inserted["result"]["last_id"] == 2 and inserted["result"]["parameter_sets"] == 2
    # - FB3 - A failing row rolls the whole message back; nothing is half written.
    error = failed(run(insert, [{"sku": "C-3", "name": "New", "stock": 1}, {"sku": "A-1", "name": "Dup", "stock": 1}], node), "constraint")
    assert error["parameter_set"] == 1 and error["committed"] is False and "UNIQUE" in error["message"]
    failed(run(insert, [{"sku": "D-4", "name": "Negative", "stock": -1}], node), "constraint")
    count = {"sql": "SELECT count(*) AS n FROM items"}
    assert ok(run(count, "{}", node))["rows"] == [{"n": 2}]
    upsert = {**insert, "operation": "upsert", "conflict_columns": ["sku"], "update_columns": ["stock"]}
    upserted = ok(run(upsert, [{"sku": "A-1", "name": "Ignored", "stock": 9}, {"sku": "E-5", "name": "Fresh", "stock": 7}], node))
    assert upserted["result"]["rowcount"] == 2
    query = {"sql": "SELECT sku, name, stock FROM items WHERE stock >= :low ORDER BY sku"}
    listed = ok(run(query, {"low": 4}, node))
    assert listed["rows"] == [{"sku": "A-1", "name": "Widget", "stock": 9}, {"sku": "B-2", "name": "Gadget", "stock": 5},
                              {"sku": "E-5", "name": "Fresh", "stock": 7}], listed["rows"]
    assert listed["result"]["columns"] == ["sku", "name", "stock"] and listed["result"]["truncated"] is False
    # - FB2 - Values are bound, never interpolated: an injection attempt is stored as plain text.
    hostile = "x'); DROP TABLE items; --"
    ok(run(insert, {"sku": "Z-9", "name": hostile, "stock": 0}, node))
    assert ok(run({"sql": "SELECT name FROM items WHERE sku = %(sku)s"}, {"sku": "Z-9"}, node))["rows"] == [{"name": hostile}]
    returning = ok(run({**base, "operation": "execute", "sql": "INSERT INTO items (sku, name, stock, data) VALUES (:sku, :name, 1, :data) RETURNING sku, data"},
                       [{"sku": "R-1", "name": "Ret", "data": None}, {"sku": "R-2", "name": "Ret", "data": None}], node))
    assert returning["rows"] == [{"sku": "R-1", "data": None}, {"sku": "R-2", "data": None}] and returning["result"]["rowcount"] == 2
    ok(run({**base, "operation": "execute", "sql": "UPDATE items SET data = X'00FF' WHERE sku = :sku"}, {"sku": "R-1"}, node))
    assert ok(run({"sql": "SELECT data FROM items WHERE sku = 'R-1'"}, "{}", node))["rows"] == [{"data": {"base64": "AP8="}}]
    # - FB3 - Queries cannot write, even through a data-modifying statement the configuration would refuse.
    for sql in ("DELETE FROM items", "INSERT INTO items (sku, name, stock) VALUES ('Q', 'q', 1)", "CREATE TABLE other (x)"):
        plan = {"name": "default", "operation": "query", "read_only": True, "sql": sql, "placeholders": [], "inserts": False}
        try:
            drivers.run_sqlite(plan, [{}], logic.configuration({}), node, lambda: False, time.monotonic() + 5)
            raise AssertionError("A read-only plan wrote data: " + sql)
        except logic.SqlError as exc:
            assert exc.code == "read_only", (sql, exc.code, str(exc))
    # - FB4 - Even a crafted write plan cannot attach files, copy the database elsewhere, change pragmas or load code.
    for sql in ("ATTACH DATABASE 'other.sqlite3' AS other", "VACUUM INTO 'copy.sqlite3'", "PRAGMA writable_schema = ON",
                "PRAGMA user_version = 7", "SELECT load_extension('x')", "SELECT 1; DROP TABLE items"):
        plan = {"name": "default", "operation": "execute", "read_only": False, "sql": sql, "placeholders": [], "inserts": False}
        try:
            drivers.run_sqlite(plan, [{}], logic.configuration(base), node, lambda: False, time.monotonic() + 5)
            raise AssertionError("Crafted statement accepted: " + sql)
        except logic.SqlError as exc:
            assert exc.code in {"not_authorized", "sql"}, (sql, exc.code, str(exc))
    assert sorted(path.name for path in node.iterdir()) == ["database.sqlite3"]
    assert ok(run(count, "{}", node))["rows"][0]["n"] == 6
    # Read-only queries still use views, CTEs, window functions and FTS5.
    ok(run({**base, "operation": "execute", "sql": "CREATE VIEW stocked AS SELECT sku FROM items WHERE stock > 0"}, "{}", node))
    ok(run({**base, "operation": "execute", "sql": "CREATE VIRTUAL TABLE notes USING fts5(body)"}, "{}", node))
    ok(run({**base, "operation": "execute", "sql": "INSERT INTO notes (body) VALUES (:body)"}, [{"body": "café restart"}, {"body": "other"}], node))
    assert ok(run({"sql": "SELECT body FROM notes WHERE notes MATCH :q"}, {"q": "restart"}, node))["rows"] == [{"body": "café restart"}]
    assert len(ok(run({"sql": "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 3) "
                              "SELECT x, row_number() OVER (ORDER BY x DESC) AS r FROM c"}, "{}", node))["rows"]) == 3
    assert len(ok(run({"sql": "SELECT * FROM stocked"}, "{}", node))["rows"]) == 5
    columns = ok(run({"sql": "SELECT name FROM pragma_table_info('items') ORDER BY cid"}, "{}", node))["rows"]
    assert [row["name"] for row in columns] == ["sku", "name", "stock", "price", "data"]
    # - FB4 - Row and byte bounds fail explicitly unless truncation was chosen; truncation is reported.
    every = {"sql": "SELECT sku FROM items ORDER BY sku"}
    failed(run({**every, "max_rows": 2}, "{}", node), "row_limit")
    cut = ok(run({**every, "max_rows": 2, "truncate_results": True}, "{}", node))
    assert len(cut["rows"]) == 2 and cut["result"]["truncated"] is True
    wide = {"sql": "SELECT hex(zeroblob(1000)) AS big FROM items", "max_result_bytes": 4096}
    failed(run(wide, "{}", node), "byte_limit")
    clipped = ok(run({**wide, "truncate_results": True}, "{}", node))
    assert clipped["result"]["truncated"] and len(clipped["rows"]) == 2 and len(clipped["rows"][0]["big"]) == 2000
    failed(run({"sql": "SELECT sku AS v, name AS v FROM items"}, "{}", node), "sql")
    # - FB4 - Timeout and Stop interrupt a running statement promptly.
    endless = {"sql": "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT count(*) AS n FROM c", "timeout_sec": 1}
    started = time.monotonic()
    assert failed(run(endless, "{}", node), "timeout")["transient"] and time.monotonic() - started < 2.5
    started = time.monotonic()
    error = failed(run({**endless, "timeout_sec": 30}, "{}", node, cancel=lambda: time.monotonic() - started > 0.3), "cancelled")
    assert error["committed"] is False and time.monotonic() - started < 2.5
    assert failed(run(endless, "{}", node, cancel=lambda: True), "cancelled")
    # A writer holding the lock delays, then times out, another writer; nothing is lost afterwards.
    blocker = sqlite3.connect(database, isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    started = time.monotonic()
    failed(run({**insert, "timeout_sec": 1}, {"sku": "L-1", "name": "Late", "stock": 1}, node), "timeout")
    assert time.monotonic() - started < 2.5
    assert ok(run(count, "{}", node))["rows"][0]["n"] == 6
    blocker.execute("ROLLBACK")
    blocker.close()
    ok(run(insert, {"sku": "L-1", "name": "Late", "stock": 1}, node))
    # The file cannot grow beyond sqlite_max_database_mb; the failing write is rolled back.
    sized = {**base, "operation": "execute", "sql": "INSERT INTO items (sku, name, stock, data) VALUES (:sku, 'big', 0, zeroblob(:size))",
             "sqlite_max_database_mb": 1}
    failed(run(sized, {"sku": "BIG", "size": 3 * 1048576}, node), "storage_limit")
    assert ok(run({"sql": "SELECT count(*) AS n FROM items WHERE sku = 'BIG'"}, "{}", node))["rows"] == [{"n": 0}]
    # - FB4 - Links never redirect the database outside node storage.
    linked = root / "linked"
    linked.mkdir()
    outside = root / "outside.sqlite3"
    sqlite3.connect(outside).close()
    (linked / "database.sqlite3").symlink_to(outside)
    failed(run({}, "{}", linked), "storage")
    hard = root / "hard"
    hard.mkdir()
    os.link(outside, hard / "database.sqlite3")
    failed(run(insert, {"sku": "H", "name": "h", "stock": 1}, hard), "storage")
    journal = root / "journal"
    journal.mkdir()
    sqlite3.connect(journal / "database.sqlite3").close()
    (journal / "database.sqlite3-journal").symlink_to(outside)
    failed(run(insert, {"sku": "J", "name": "j", "stock": 1}, journal), "storage")
    (root / "corrupt").mkdir()
    (root / "corrupt" / "database.sqlite3").write_bytes(b"not a database file" * 64)
    failed(run({"sql": "SELECT 1 AS one FROM sqlite_master"}, "{}", root / "corrupt"), "storage")
    assert failed(run({}, "{}", None), "storage")["message"].startswith("SQLite needs")
    return database


def records(directory):
    path = Path(directory) / "calls.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


def check_postgresql(state):
    """FB2/FB3/FB4/FB5: the PostgreSQL path through the psycopg double (no server is contacted)."""
    os.environ["SQL_DATABASE_PG_DOUBLE_DIR"] = str(state)
    (state / "fixture.json").write_text(json.dumps({"password_sha256": hashlib.sha256(PASSWORD.encode()).hexdigest(),
                                                    "unreachable_hosts": ["unreachable.example.test"]}), encoding="utf-8")
    import psycopg
    assert psycopg.__version__ == "0.0.0-test-double", "The double, never a real driver, must be loaded"
    writes = pg_settings(allow_writes=True, statements={
        "init": {"operation": "execute", "sql": "CREATE TABLE IF NOT EXISTS items (sku TEXT PRIMARY KEY, name TEXT NOT NULL, stock INTEGER NOT NULL)"},
        "save": {"operation": "upsert", "table": "items", "columns": ["sku", "name", "stock"], "conflict_columns": ["sku"]},
        "find": {"operation": "query", "sql": "SELECT sku, name, stock FROM items WHERE stock >= :low AND name LIKE 'W%' ORDER BY sku"},
        "slow": {"operation": "query", "sql": "SELECT pg_sleep(:seconds)"},
        "sneaky": {"operation": "query", "sql": "WITH gone AS (SELECT 1) DELETE FROM items"}})
    ok(run(writes, {"$statement": "init"}))
    saved = ok(run(writes, {"$statement": "save", "$params": [{"sku": "A-1", "name": "Widget", "stock": 3},
                                                             {"sku": "B-2", "name": "Wrench", "stock": 8},
                                                             {"sku": "C-3", "name": "Gadget", "stock": 9}]}))
    assert saved["result"]["rowcount"] == 3 and saved["result"]["committed"] and saved["result"]["last_id"] is None
    found = ok(run(writes, {"$statement": "find", "$params": {"low": 3}}))
    assert found["rows"] == [{"sku": "A-1", "name": "Widget", "stock": 3}, {"sku": "B-2", "name": "Wrench", "stock": 8}]
    calls = records(state)
    connect = [item["params"] for item in calls if item["event"] == "connect"]
    assert connect and all(item["password_sha256"] == hashlib.sha256(PASSWORD.encode()).hexdigest() for item in connect)
    first = connect[0]
    # - FB5 - Explicit connection keywords: TLS mode, no password file, bounded connect timeout.
    assert (first["host"], first["port"], first["dbname"], first["user"], first["sslmode"]) == ("db.example.test", 5432, "app", "app_user", "verify-full")
    assert first["passfile"] == os.devnull and first["password_type"] == "str" and 2 <= first["connect_timeout"] <= 30
    assert first["application_name"] == "bloxsmith-sql-database" and "sslrootcert" not in first
    executes = [item for item in calls if item["event"] == "execute"]
    query = [item for item in executes if "LIKE" in item["query"]][0]
    # - FB3 - Queries use a read-only transaction on a server cursor; % is escaped for psycopg; placeholders are pyformat.
    assert query["server_cursor"] and query["read_only"] and "'W%%'" in query["query"] and "%(low)s" in query["query"]
    writes_seen = [item for item in executes if item["query"].startswith(("INSERT", "CREATE"))]
    assert writes_seen and all(item["prepare"] is True and not item["read_only"] and not item["server_cursor"] for item in writes_seen)
    assert all(":" not in item["query"].replace("::", "") for item in writes_seen)
    timeouts = [item["statement_timeout"] for item in calls if item["event"] == "timeouts"]
    assert timeouts and all(0 < value <= 30000 for value in timeouts)
    assert [item["event"] for item in calls].count("commit") == 2
    error = failed(run(writes, {"$statement": "sneaky"}), "read_only")
    assert error["sqlstate"] == "25006" and error["committed"] is False
    before = len(records(state))
    error = failed(run(writes, {"$statement": "save", "$params": [{"sku": "D-4", "name": "Wheel", "stock": 1},
                                                                 {"sku": "E-5", "name": None, "stock": 1}]}), "constraint")
    assert error["parameter_set"] == 1 and error["sqlstate"] == "23502" and error["committed"] is False
    assert "commit" not in [item["event"] for item in records(state)[before:]]
    assert len(ok(run(writes, {"$statement": "find", "$params": {"low": 0}}))["rows"]) == 2
    hostile = "W'); DROP TABLE items; --"
    ok(run(writes, {"$statement": "save", "$params": {"sku": "Z-9", "name": hostile, "stock": 99}}))
    assert hostile in [row["name"] for row in ok(run(writes, {"$statement": "find", "$params": {"low": 99}}))["rows"]]
    # - FB4 - Stop and the deadline cancel a running PostgreSQL statement through the driver.
    started = time.monotonic()
    error = failed(run(writes, {"$statement": "slow", "$params": {"seconds": 30}}, cancel=lambda: time.monotonic() - started > 0.3), "cancelled")
    assert time.monotonic() - started < 3 and any(item["event"] == "cancel_safe" for item in records(state))
    started = time.monotonic()
    failed(run({**writes, "timeout_sec": 1}, {"$statement": "slow", "$params": {"seconds": 30}}), "timeout")
    assert time.monotonic() - started < 3
    # - FB5 - Wallet failures and wrong credentials never reach the server or leak the password.
    before = len(records(state))
    error = failed(run(writes, {"$statement": "find", "$params": {"low": 0}}, raise_secret=True), "secret")
    assert len(records(state)) == before and PASSWORD not in json.dumps(error)
    error = failed(run(writes, {"$statement": "find", "$params": {"low": 0}}, secret="wrong-password-123"), "connection")
    assert "password authentication failed" in error["message"] and "wrong-password-123" not in json.dumps(error)
    failed(run({**writes, "pg_host": "unreachable.example.test"}, {"$statement": "find", "$params": {"low": 0}}), "connection")
    no_password = {key: value for key, value in writes.items() if key != "pg_password_ref"}
    failed(run(no_password, {"$statement": "find", "$params": {"low": 0}}), "connection")
    assert [item for item in records(state) if item["event"] == "connect"][-1]["params"]["password_sha256"] == ""
    rooted = ok(run({**writes, "pg_sslrootcert": "system"}, {"$statement": "find", "$params": {"low": 0}}))
    assert rooted["result"]["rowcount"] == 3
    assert [item for item in records(state) if item["event"] == "connect"][-1]["params"]["sslrootcert"] == "system"
    # - FB5 - Without psycopg the block fails explicitly instead of crashing or importing at load time.
    saved_module = sys.modules.pop("psycopg")
    sys.modules["psycopg"] = None
    try:
        error = failed(run(writes, {"$statement": "find", "$params": {"low": 0}}), "dependency")
        assert "psycopg" in error["message"]
        result = SqlDatabaseBlock().initialize_runtime(BlockRuntimeContext(config=writes))
        assert result.status == "failed" and "psycopg" in result.error
    finally:
        sys.modules["psycopg"] = saved_module
    assert SqlDatabaseBlock().initialize_runtime(BlockRuntimeContext(config=writes)).status == "success"
    for item in records(state):
        assert PASSWORD not in json.dumps(item)


def check_block(root):
    """FB6: runtime contract on the block definition (ports, statuses, failure modes)."""
    block = SqlDatabaseBlock()
    node = root / "block-node"
    node.mkdir()
    services = {"get_block_storage_dir": lambda: node}

    def context(config, value=None, events=()):
        return BlockRuntimeContext(config=config, inputs={} if value is None else {"params": value}, input_ports=INPUTS,
                                   output_ports=OUTPUTS, services=services, input_events=events)
    # - FB6 - One message gives rows/result on their declared ports with JSON content.
    result = block.execute_runtime(context(block.default_config(), "{}"))
    assert result.status == "success" and [output.port_id for output in result.outputs] == [1, 2]
    assert all(output.content_type == "application/json" for output in result.outputs)
    assert json.loads(result.outputs[0].value) == [{"ok": 1}] and result.metadata["sql_database"]["status"] == "ok"
    assert block.execute_runtime(context(block.default_config())).status == "skipped"
    errored = block.execute_runtime(context({**block.default_config(), "sql": "SELECT * FROM missing"}, "{}"))
    assert errored.status == "success" and [output.port_id for output in errored.outputs] == [3]
    assert json.loads(errored.outputs[0].value)["code"] == "sql" and "failed: sql" in errored.logs[0]
    invalid = block.execute_runtime(context({**block.default_config(), "operation": "execute", "sql": "DELETE FROM t"}, "{}"))
    assert invalid.status == "failed" and invalid.error.startswith("SQL Database failed:") and not invalid.outputs
    event = SimpleNamespace(input_port_id=1, value="{}")
    double = block.execute_runtime(context(block.default_config(), events=(event, event)))
    assert json.loads(double.outputs[0].value)["code"] == "params"
    single = block.execute_runtime(context(block.default_config(), events=(event,)))
    assert single.outputs[0].port_id == 1
    # Preparation is pure; initialization fails early without instance storage.
    assert block.prepare_runtime(SimpleNamespace(config=MappingProxyType(block.default_config()))) is not None
    try:
        block.prepare_runtime(SimpleNamespace(config={"driver": "oracle"}))
        raise AssertionError("Invalid settings prepared")
    except logic.ConfigError:
        pass
    assert block.initialize_runtime(context(block.default_config())).status == "success"
    unscoped = block.initialize_runtime(BlockRuntimeContext(config=block.default_config(), services={
        "get_block_storage_dir": lambda: (_ for _ in ()).throw(RuntimeError("block_storage.missing_scope"))}))
    assert unscoped.status == "failed" and "block storage" in unscoped.error
    # Apply refuses invalid statements without persisting; valid settings replace the whole configuration.
    current = block.build_node_payload(node_id="db")
    refused = block.handle_ui_action(node=current, action="save_settings",
                                      values={"node_patch": {"config": {"operation": "execute", "sql": "DROP TABLE t"}}})
    assert "allow_writes" in refused["error"] and "graph_operations" not in refused
    accepted = block.handle_ui_action(node=current, action="save_settings",
                                      values={"node_patch": {"title": "Stock", "config": {"sql": "SELECT 2 AS two"}}})
    operation = accepted["graph_operations"][0]
    assert operation["op"] == "update_node_config" and operation["replace"] and operation["config"]["sql"] == "SELECT 2 AS two"
    card = block.render_node_card(node={**current, "config": {**current["config"], "pg_password_ref": REF}})["html"]
    assert "sqlite · query" in card and REF not in card


def main():
    check_configuration()
    check_statements()
    check_parameters()
    check_results()
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder).resolve()  # node storage paths are canonical
        check_sqlite(root)
        state = root / "pg-state"
        state.mkdir()
        check_postgresql(state)
        check_block(root)
    print("[ok] SQL Database statements, parameters, SQLite, PostgreSQL double and block contract")


if __name__ == "__main__":
    main()
