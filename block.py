"""Parameterized SQL on a node-private SQLite file or an explicitly configured PostgreSQL server."""

import importlib.util
import json

from bloxsmith_app.block_api import (APPLICATION_JSON, BlockDefinition, BlockRuntimeOutput,
                                     BlockRuntimePreparation, BlockRuntimeResult)
from . import engine, logic, ui


def _psycopg_installed():
    """Locate the optional driver without importing it (no libpq load at Run start)."""
    try:
        return importlib.util.find_spec("psycopg") is not None
    except (ImportError, ValueError):
        return False


# FB1 - Accept only trusted statements: one statement, allowlisted leading keyword, named placeholders, validated identifiers.
# FB2 - Bind message values strictly as driver parameters; malformed, missing or oversized parameters fail before any database call.
# FB3 - Keep queries read-only (SQLite mode=ro + authorizer, PostgreSQL read-only transaction) and writes behind allow_writes, atomic per message.
# FB4 - Confine SQLite to node storage without ATTACH, links or extensions; bound rows, bytes, batches and time; Stop interrupts statements.
# FB5 - Resolve the PostgreSQL password only from the wallet, import psycopg lazily and never expose secrets in outputs or logs.
# FB6 - Publish rows/result/error identically in both runtime modes and in bundled, managed and linked installations.
# FB7 - Provide translated responsive settings with conditional fields, draft/Apply validation and release-scoped assets.
class SqlDatabaseBlock(BlockDefinition):
    """SQL text is configuration; an incoming message only ever supplies parameter values."""

    kind = "sql_database"

    def ui_assets(self, surface="modal"):
        """Every installation origin uses the static release manifest."""
        return list(self.model.get("ui_assets", {}).get(surface, []))

    def prepare_runtime(self, context):
        """Validate settings without opening a database, a socket or the wallet."""
        logic.configuration(context.config)
        return BlockRuntimePreparation()

    def initialize_runtime(self, context):
        """Fail the Run early when the selected driver cannot work on this host or instance."""
        try:
            config = logic.configuration(context.config)
            if config["driver"] == "postgresql":
                if not _psycopg_installed():
                    raise logic.SqlError("dependency", "PostgreSQL needs the optional psycopg package (psycopg>=3.1) "
                                         "in the Studio Python environment.")
            else:
                resolver = context.services.get("get_block_storage_dir")
                if not callable(resolver):
                    raise logic.SqlError("storage", engine.STORAGE_MESSAGE)
                try:
                    resolver()
                except Exception:  # noqa: BLE001 - unscoped standalone runs have no instance storage.
                    raise logic.SqlError("storage", engine.STORAGE_MESSAGE) from None
        except (logic.SqlError, ValueError) as exc:
            return self._failed(str(exc) if isinstance(exc, logic.SqlError) else "Invalid SQL Database settings.")
        return BlockRuntimeResult(status="success")

    def execute_runtime(self, context):
        """One params message runs one statement; database failures are routed to the error port."""
        try:
            config = logic.configuration(context.config)
        except (logic.SqlError, ValueError) as exc:
            return self._failed(str(exc) if isinstance(exc, logic.SqlError) else "Invalid SQL Database settings.")
        try:
            value = self._message(context)
            if value is None:
                return BlockRuntimeResult(status="skipped", outputs=[])
            values = engine.execute(value, config, {
                "cancel_requested": context.services.get("cancel_requested", lambda: False),
                "get_block_storage_dir": context.services.get("get_block_storage_dir"),
                "resolve_secret": lambda reference: context.resolve_secret(reference)})
        except logic.SqlError as exc:
            values = {"error": exc.envelope(None, config)}
        except Exception:  # noqa: BLE001 - raw driver, path or credential details never reach outputs.
            values = {"error": logic.SqlError("internal", "The SQL operation ended without a complete result; "
                                              "verify the database before retrying.", committed=None).envelope(None, config)}
        outputs = []
        for port in context.output_ports:
            if port.name not in values:
                continue
            text = json.dumps(values[port.name], ensure_ascii=False, allow_nan=False)
            outputs.append(BlockRuntimeOutput(port_id=int(port.id), port_name=port.name,
                                              value=context.redact_secrets(text) if port.name == "error" else text,
                                              content_type=APPLICATION_JSON))
        error, result = values.get("error"), values.get("result") or {}
        summary = error or result
        label = f"{summary.get('statement') or 'default'} {summary.get('operation') or ''} on {config['driver']}"
        if error:
            log = f"[sql-database] {label} failed: {error['code']}."
        else:
            log = f"[sql-database] {label} completed: rowcount {result.get('rowcount')}."
        return BlockRuntimeResult(
            status="success", outputs=outputs, content_type=APPLICATION_JSON,
            last_message=json.dumps({"code": error["code"]} if error else {"rowcount": result.get("rowcount")}),
            worker_received=str(result.get("parameter_sets", 0)),
            metadata={self.kind: {"status": "error" if error else "ok", "statement": summary.get("statement"),
                                  "operation": summary.get("operation"), "driver": config["driver"],
                                  "rowcount": result.get("rowcount"), "code": error["code"] if error else ""}},
            logs=[context.redact_secrets(log)])

    @staticmethod
    def _message(context):
        """Exactly one params event per activation; a batch would hide which message ran."""
        if context.input_events:
            if len(context.input_events) != 1:
                raise logic.SqlError("params", "One params message per activation is required; nothing was executed.")
            event = context.input_events[0]
            ports = {int(port.id): str(port.name) for port in context.input_ports}
            if ports.get(int(event.input_port_id)) != "params":
                raise logic.SqlError("params", "Unknown input port; nothing was executed.")
            return event.value
        if not context.has_input_value("params", "1"):
            return None
        return context.input_value("params", "1")

    def _failed(self, detail):
        message = self.translate("block.sql_database.error", {"detail": detail}, fallback="SQL Database failed: {detail}")
        return BlockRuntimeResult(status="failed", outputs=[], error=message, exit_code=1,
                                  logs=[f"[sql-database-error] {detail}"])

    def handle_ui_action(self, *, node, action, values, payload=None):
        """Apply validates statements and settings; it never opens a database or reads the wallet."""
        if action in {"save_settings", "modal_update_fields", "inspector_update_fields"}:
            patch = (values or {}).get("node_patch") or {}
            if "config" in patch:
                try:
                    logic.configuration({**self.default_config(), **(node.get("config") or {}), **patch["config"]})
                except (logic.SqlError, ValueError, TypeError) as exc:
                    detail = str(exc) if isinstance(exc, logic.SqlError) else "Invalid SQL Database settings."
                    return {"error": self.translate("block.sql_database.error", {"detail": detail},
                                                    fallback="SQL Database failed: {detail}")}
        result = super().handle_ui_action(node=node, action="modal_update_fields" if action == "save_settings" else action,
                                          values=values, payload=payload)
        return ui.replace_config(result, node)

    def render_modal(self, *, node, payload=None):
        """Statement, driver and limits stay editable as a draft until Apply."""
        return ui.modal(self, node, payload)

    def render_inspector_panel(self, *, node, payload=None):
        """The same validated fields in the narrow inspector."""
        return ui.inspector(self, node, payload)

    def render_node_card(self, *, node, payload=None):
        """Show driver and operation only: never SQL text, hosts or credentials."""
        config = {**self.default_config(), **(node.get("config") or {})}
        named = config.get("statements") if isinstance(config.get("statements"), dict) else {}
        preview = f"{config.get('driver')} · {config.get('operation')}" + (f" · +{len(named)}" if named else "")
        return ui.card(self, node, preview)
