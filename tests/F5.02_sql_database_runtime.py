"""FB3/FB4/FB5/FB6: real Runs in both runtime modes and three package origins, with Stop.

SQLite runs on the node's real instance storage. PostgreSQL runs through the
package-owned psycopg test double, copied into the disposable server root; no
PostgreSQL server, real credential or user wallet is involved.
"""

import hashlib
import json
from pathlib import Path
import shutil
import sqlite3
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]
from blocs.sql_database.block import SqlDatabaseBlock
from block_test_packages import install_test_package, surface_payload
from ui_smoke_common import (create_project_api, create_run_api, data_edge, display_node, graph_payload, graph_storage_dir,
                             http_json, isolated_server, stop_run_api, text_node, wait_for_run_predicate, wait_for_run_terminal)

DOUBLE = Path(__file__).resolve().parent / "pg_double" / "psycopg"
PASSWORD = "fixture-runtime-pg-5Kd"
REF = "secret://workspace/pg_fixture"
SCHEMA = "CREATE TABLE IF NOT EXISTS items (sku TEXT PRIMARY KEY, name TEXT NOT NULL, stock INTEGER NOT NULL)"
SAVE = {"operation": "upsert", "table": "items", "columns": ["sku", "name", "stock"], "conflict_columns": ["sku"]}
ROWS = [{"sku": "A-1", "name": "Widget", "stock": 3}, {"sku": "B-2", "name": "Wrench", "stock": 8},
        {"sku": "C-3", "name": "Gadget", "stock": 9}]


def prepare(root):
    """Install the psycopg double in the disposable server root, with a pre-created table."""
    target = Path(root) / "psycopg"
    shutil.copytree(DOUBLE, target, ignore=shutil.ignore_patterns("__pycache__"))
    (target / "fixture.json").write_text(json.dumps({"password_sha256": hashlib.sha256(PASSWORD.encode()).hexdigest()}),
                                         encoding="utf-8")
    database = sqlite3.connect(target / "server.sqlite3")
    database.execute(SCHEMA)
    database.commit()
    database.close()
    return ()


def calls(server):
    path = server.root_dir / "psycopg" / "calls.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


def document(node, message):
    return graph_payload("SQL Database", [
        text_node("source", "Params", json.dumps(message), 60, 160), node,
        display_node("rows", "Rows", 720, 40), display_node("result", "Result", 720, 220), display_node("error", "Error", 720, 400)], [
        data_edge("params", "source", 1, "db", 1), data_edge("to-rows", "db", 1, "rows", 1),
        data_edge("to-result", "db", 2, "result", 1), data_edge("to-error", "db", 3, "error", 1)])


def start(server, project, node, message, mode):
    graph = document(node, message)
    (graph_storage_dir(server, project) / "graph.json").write_text(json.dumps({**graph, "graph_id": project["graph_id"]}), encoding="utf-8")
    http_json(server.base_url, f"/api/projects/{project['graph_id']}/graph/reload", method="POST", payload={})
    return create_run_api(server, graph, project_id=project["graph_id"], runtime_mode=mode)["run_id"]


def send(server, project, node, message, mode):
    """One Run per message; return the decoded documents published by the SQL node."""
    run = wait_for_run_terminal(server, start(server, project, node, message, mode), timeout_sec=45)
    assert run["status"] == "success", (mode, run.get("status"), run.get("logs"))
    assert PASSWORD not in json.dumps(run), "The wallet password leaked into the Run state"
    values = run.get("output_values", {})
    return {name: json.loads(values[f"db:{port}"]["value"]) for name, port in (("rows", 1), ("result", 2), ("error", 3))
            if values.get(f"db:{port}", {}).get("value")}


def stopped(server, project, node, message, mode):
    """Stop a Run while the statement is running; it must end promptly without rows or result."""
    run_id = start(server, project, node, message, mode)
    wait_for_run_predicate(server, run_id, lambda state: state.get("node_statuses", {}).get("db") == "running",
                           "The SQL node never started running.", timeout_sec=30)
    time.sleep(0.5)
    began = time.monotonic()
    stop_run_api(server, run_id)
    final = wait_for_run_predicate(server, run_id, lambda state: state.get("status") in {"cancelled", "failed", "success"},
                                   "The stopped Run did not end.", timeout_sec=20)
    assert time.monotonic() - began < 15, "Stop did not interrupt the running statement promptly"
    assert final["status"] == "cancelled", (mode, final.get("status"), final.get("logs"))
    values = final.get("output_values", {})
    assert not values.get("db:1", {}).get("value") and not values.get("db:2", {}).get("value"), values
    return final


def main():
    block = SqlDatabaseBlock()
    for mode in ("centralized", "zeromq_active"):
        for origin in (None, "managed", "linked"):
            with isolated_server(prepare=prepare) as server:
                node = block.build_node_payload(node_id="db", position={"x": 380, "y": 160})
                if origin:
                    model = install_test_package(server, "sql_database", origin=origin)
                    node["block_version"] = model["version"]
                sqlite_config = {**block.default_config(), "allow_writes": True,
                                 "sql": "SELECT sku, name, stock FROM items WHERE stock >= :low ORDER BY sku",
                                 "statements": {"init": {"operation": "execute", "sql": SCHEMA}, "save": SAVE}}
                pg_config = {**sqlite_config, "driver": "postgresql", "pg_host": "db.example.test", "pg_database": "app",
                             "pg_user": "app_user", "pg_password_ref": REF,
                             "sql": "SELECT sku, name, stock FROM items WHERE name LIKE 'W%' AND stock >= :low ORDER BY sku"}
                if origin:
                    # - FB7 - Installed surfaces render without template residue, secrets or undeclared assets.
                    for surface in ("modal", "inspector_panel", "node_card"):
                        html = surface_payload(server, model, {**node, "config": pg_config}, surface=surface)["html"]
                        assert "{{" not in html and PASSWORD not in html
                        if surface != "node_card":
                            assert 'data-block-config-field="sql"' in html and 'data-sql-when="driver"' in html
                        else:
                            assert REF not in html and "db.example.test" not in html
                project = create_project_api(server, document=document({**node, "config": sqlite_config}, {}))["project"]
                # - FB3 - SQLite writes persist in the node's instance storage across Runs, then read back read-only.
                sqlite_node = {**node, "config": sqlite_config}
                created = send(server, project, sqlite_node, {"$statement": "init"}, mode)
                assert created["result"]["committed"] and "rows" not in created and "error" not in created, created
                saved = send(server, project, sqlite_node, {"$statement": "save", "$params": ROWS}, mode)
                assert saved["result"]["rowcount"] == 3 and saved["result"]["statement"] == "save", saved
                listed = send(server, project, sqlite_node, {"low": 4}, mode)
                assert listed["rows"] == [ROWS[1], ROWS[2]] and listed["result"]["rows_returned"] == 2, listed
                # - FB2 - A message missing a placeholder value is routed to error; nothing else is published.
                missing = send(server, project, sqlite_node, {"other": 1}, mode)
                assert set(missing) == {"error"} and missing["error"]["code"] == "params", missing
                storage = graph_storage_dir(server, project) / "instances" / "1" / "blocs" / "db" / "database.sqlite3"
                assert storage.is_file() and stat.S_IMODE(storage.stat().st_mode) == 0o600
                # - FB5 - PostgreSQL through the driver double: wallet password, read-only server cursor, prepared writes.
                http_json(server.base_url, "/api/application/secrets/init", method="POST", payload={"password": "disposable-sql-fixture"})
                http_json(server.base_url, "/api/application/secrets", method="POST", payload={"name": "pg_fixture", "value": PASSWORD})
                pg_node = {**node, "config": pg_config}
                saved = send(server, project, pg_node, {"$statement": "save", "$params": ROWS}, mode)
                assert saved["result"]["rowcount"] == 3 and saved["result"]["driver"] == "postgresql", saved
                listed = send(server, project, pg_node, {"low": 3}, mode)
                assert listed["rows"] == [ROWS[0], ROWS[1]], listed
                recorded = calls(server)
                connect = [item["params"] for item in recorded if item["event"] == "connect"]
                assert connect and connect[-1]["password_sha256"] == hashlib.sha256(PASSWORD.encode()).hexdigest()
                assert connect[-1]["sslmode"] == "verify-full" and connect[-1]["host"] == "db.example.test"
                query = [item for item in recorded if item["event"] == "execute" and "LIKE" in item["query"]][-1]
                assert query["server_cursor"] and query["read_only"] and "'W%%'" in query["query"], query
                writes = [item for item in recorded if item["event"] == "execute" and item["query"].startswith("INSERT")]
                assert writes and all(item["prepare"] is True and not item["read_only"] for item in writes)
                assert PASSWORD not in json.dumps(recorded)
                # A locked wallet stops the call before any connection attempt.
                http_json(server.base_url, "/api/application/secrets/lock", method="POST", payload={})
                before = len(calls(server))
                locked = send(server, project, pg_node, {"low": 3}, mode)
                assert set(locked) == {"error"} and locked["error"]["code"] == "secret", locked
                assert not [item for item in calls(server)[before:] if item["event"] == "connect"]
                # - FB4 - Stop interrupts a running statement in both runtimes.
                if origin is None or (origin == "managed" and mode == "zeromq_active"):
                    endless = {**sqlite_config, "timeout_sec": 120,
                               "sql": "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT count(*) AS n FROM c"}
                    stopped(server, project, {**node, "config": endless}, {}, mode)
                if origin is None:
                    http_json(server.base_url, "/api/application/secrets/unlock", method="POST", payload={"password": "disposable-sql-fixture"})
                    before = len(calls(server))
                    sleeping = {**pg_config, "timeout_sec": 120, "sql": "SELECT pg_sleep(:seconds)"}
                    stopped(server, project, {**node, "config": sleeping}, {"seconds": 90}, mode)
                    deadline = time.monotonic() + 10
                    while mode == "centralized" and time.monotonic() < deadline:
                        if "cancel_safe" in [item["event"] for item in calls(server)[before:]]:
                            break
                        time.sleep(0.1)
                    events = [item["event"] for item in calls(server)[before:]]
                    assert "commit" not in events, events
                    if mode == "centralized":
                        # In-process execution: the watchdog cancels the server-side statement itself.
                        assert "cancel_safe" in events, events
            print(f"[ok] SQL Database runtime {mode} {origin or 'bundled'}", flush=True)


if __name__ == "__main__":
    main()
