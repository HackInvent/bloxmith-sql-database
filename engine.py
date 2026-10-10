"""One activation: bind parameters, resolve the wallet password, run the driver, shape outputs."""

from __future__ import annotations

import time

from . import drivers, logic

STORAGE_MESSAGE = ("SQLite needs the persistent block storage of a saved blueprint instance; "
                   "no other location is used.")


def password(config, services):
    """The PostgreSQL password exists only in the wallet; nothing is sent when it is unavailable."""
    reference = config["pg_password_ref"]
    if not reference:
        return ""
    resolver = services.get("resolve_secret")
    if not callable(resolver):
        raise logic.SqlError("secret", "The wallet service is unavailable; nothing was sent.")
    try:
        value = resolver(reference)
    except Exception:  # noqa: BLE001 - locked wallet, unknown reference: never echo the provider error.
        raise logic.SqlError("secret", "The wallet secret is unavailable (locked wallet or unknown reference); "
                             "nothing was sent.") from None
    if not isinstance(value, str) or not value or len(value) > 4096 or "\x00" in value:
        raise logic.SqlError("secret", "The wallet secret must be a non-empty text password; nothing was sent.")
    return value


def execute(value, config, services):
    """Return the documents to publish: rows/result on success, error otherwise."""
    plan = None
    try:
        plan, sets = logic.request(value, config)
        started = time.monotonic()
        deadline = started + config["timeout_sec"]
        cancel = services.get("cancel_requested") or (lambda: False)
        if not sets:
            outcome = {"columns": None, "rows": [], "rowcount": 0, "last_id": None, "truncated": False,
                       "parameter_sets": 0, "committed": False}
        elif config["driver"] == "sqlite":
            resolver = services.get("get_block_storage_dir")
            if not callable(resolver):
                raise logic.SqlError("storage", STORAGE_MESSAGE)
            try:
                directory = resolver()
            except Exception:  # noqa: BLE001 - unscoped runs and storage faults have one explicit outcome.
                raise logic.SqlError("storage", STORAGE_MESSAGE) from None
            outcome = drivers.run_sqlite(plan, sets, config, directory, cancel, deadline)
        else:
            secret = password(config, services)
            outcome = drivers.run_postgresql(plan, sets, config, secret, cancel, deadline)
        return logic.outcome_documents(plan, config, outcome, int((time.monotonic() - started) * 1000))
    except logic.SqlError as exc:
        return {"error": exc.envelope(plan, config)}
