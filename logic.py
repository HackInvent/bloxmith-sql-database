"""Pure SQL Database policy: settings, statement scanning, parameter binding and JSON results.

Nothing here opens a database, a socket, a file or the wallet. SQL text is trusted
configuration; message values are only ever bound as driver parameters.
"""

from __future__ import annotations

from collections.abc import Mapping
import base64
import datetime
import decimal
import ipaddress
import json
import math
import re
import uuid

DEFAULTS = {
    "driver": "sqlite", "operation": "query", "sql": "SELECT 1 AS ok", "table": "", "columns": [],
    "conflict_columns": [], "update_columns": [], "statements": {}, "allow_writes": False,
    "sqlite_file": "database.sqlite3", "sqlite_max_database_mb": 256,
    "pg_host": "", "pg_port": 5432, "pg_database": "", "pg_user": "", "pg_password_ref": "",
    "pg_sslmode": "verify-full", "pg_sslrootcert": "",
    "timeout_sec": 30, "max_rows": 1000, "max_result_bytes": 1048576, "max_params_bytes": 1048576,
    "max_batch_rows": 1000, "truncate_results": False,
}
FRAMEWORK_KEYS = {"execution", "runtime_path", "runtime_path_label"}
DRIVERS = ("sqlite", "postgresql")
OPERATIONS = ("query", "execute", "insert_rows", "upsert")
WRITE_OPERATIONS = frozenset({"execute", "insert_rows", "upsert"})
SSL_MODES = ("verify-full", "verify-ca", "require", "disable")
STATEMENT_KEYS = {"operation", "sql", "table", "columns", "conflict_columns", "update_columns"}
LIMITS = {"timeout_sec": (1, 300), "max_rows": (1, 10000), "max_result_bytes": (1024, 8388608),
          "max_params_bytes": (1024, 8388608), "max_batch_rows": (1, 10000),
          "sqlite_max_database_mb": (1, 4096), "pg_port": (1, 65535)}
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}\Z")
PARAMETER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}")
PYFORMAT = re.compile(r"%\(([A-Za-z_][A-Za-z0-9_]{0,62})\)s")
DOLLAR_TAG = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$")
STATEMENT_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}\Z")
SQLITE_FILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z")
SECRET_REF = re.compile(r"secret://(?:workspace/[A-Za-z0-9_.-]{1,80}|project/[A-Za-z0-9_.-]{1,80}/[A-Za-z0-9_.-]{1,80})\Z")
HOST_LABEL = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\Z")
LEADING = {
    ("sqlite", "query"): ("SELECT", "WITH", "VALUES"),
    ("postgresql", "query"): ("SELECT", "WITH", "VALUES", "TABLE"),
    ("sqlite", "execute"): ("INSERT", "UPDATE", "DELETE", "REPLACE", "WITH", "CREATE", "DROP", "ALTER"),
    ("postgresql", "execute"): ("INSERT", "UPDATE", "DELETE", "MERGE", "WITH", "CREATE", "DROP", "ALTER", "TRUNCATE"),
}
MAX_SQL_CHARS = 65536
MAX_STATEMENTS = 16
INT64 = (-(2 ** 63), 2 ** 63 - 1)


class SqlError(ValueError):
    """A stable machine code with an English message; never carries SQL values or secrets."""

    def __init__(self, code, message, *, sqlstate=None, transient=False, committed=False, parameter_set=None):
        super().__init__(message)
        self.code, self.sqlstate, self.transient = code, sqlstate, transient
        self.committed, self.parameter_set = committed, parameter_set

    def envelope(self, plan=None, config=None):
        """Public error document published on the error port."""
        return {"code": self.code, "message": str(self), "statement": (plan or {}).get("name"),
                "operation": (plan or {}).get("operation"), "driver": (config or {}).get("driver"),
                "sqlstate": self.sqlstate, "parameter_set": self.parameter_set,
                "transient": bool(self.transient), "committed": self.committed}


class ConfigError(SqlError):
    """Invalid trusted settings; detected before any database or wallet access."""

    def __init__(self, message):
        super().__init__("config", message)


def thaw(value):
    """Turn immutable preparation snapshots (mappings/tuples) back into plain JSON values."""
    if isinstance(value, Mapping):
        return {key: thaw(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [thaw(item) for item in value]
    return value


# ---------------------------------------------------------------- statement scanning


def _word_char(char):
    return char.isalnum() or char in "_$"


def scan(sql, driver):
    """Tokenize SQL just enough to find statements, placeholders, strings and comments.

    Token kinds: space, comment, string, quoted, word, number, param, semicolon, symbol.
    PostgreSQL rules: nested block comments, E'' escapes, dollar quotes, ``::`` casts.
    SQLite rules: backtick and [bracket] identifiers; ``?``, ``@name``, ``$name`` refused.
    """
    if not isinstance(sql, str) or not sql.strip():
        raise ConfigError("Enter one SQL statement.")
    if len(sql) > MAX_SQL_CHARS:
        raise ConfigError(f"A SQL statement is limited to {MAX_SQL_CHARS} characters.")
    if "\x00" in sql:
        raise ConfigError("SQL must not contain NUL characters.")
    pg = driver == "postgresql"
    tokens, i, n = [], 0, len(sql)
    while i < n:
        char = sql[i]
        if char.isspace():
            j = i + 1
            while j < n and sql[j].isspace():
                j += 1
            tokens.append(("space", sql[i:j]))
        elif sql.startswith("--", i):
            j = sql.find("\n", i)
            j = n if j < 0 else j
            tokens.append(("comment", sql[i:j]))
        elif sql.startswith("/*", i):
            depth, j = 1, i + 2
            while depth:
                if j >= n:
                    raise ConfigError("Unterminated /* comment */ in SQL.")
                if pg and sql.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif sql.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            tokens.append(("comment", sql[i:j]))
        elif char == "'":
            escapes = pg and bool(tokens) and tokens[-1] in (("word", "E"), ("word", "e"))
            j = i + 1
            while True:
                if j >= n:
                    raise ConfigError("Unterminated string literal in SQL.")
                if escapes and sql[j] == "\\":
                    j += 2
                elif sql[j] == "'":
                    if j + 1 < n and sql[j + 1] == "'":
                        j += 2
                    else:
                        j += 1
                        break
                else:
                    j += 1
            tokens.append(("string", sql[i:j]))
        elif char == '"' or (not pg and char == "`"):
            j = i + 1
            while True:
                if j >= n:
                    raise ConfigError("Unterminated quoted identifier in SQL.")
                if sql[j] == char:
                    if j + 1 < n and sql[j + 1] == char:
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            tokens.append(("quoted", sql[i:j]))
        elif not pg and char == "[":
            j = sql.find("]", i + 1)
            if j < 0:
                raise ConfigError("Unterminated [identifier] in SQL.")
            j += 1
            tokens.append(("quoted", sql[i:j]))
        elif pg and char == "$":
            match = DOLLAR_TAG.match(sql, i)
            if match:
                end = sql.find(match.group(0), match.end())
                if end < 0:
                    raise ConfigError("Unterminated dollar-quoted string in SQL.")
                j = end + len(match.group(0))
                tokens.append(("string", sql[i:j]))
            elif i + 1 < n and sql[i + 1].isdigit():
                raise ConfigError("Positional $1 placeholders are not supported; use :name.")
            else:
                j = i + 1
                tokens.append(("symbol", char))
        elif char.isalpha() or char == "_":
            j = i + 1
            while j < n and _word_char(sql[j]):
                j += 1
            tokens.append(("word", sql[i:j]))
        elif char.isdigit():
            j = i + 1
            while j < n and (sql[j].isalnum() or sql[j] in "_."):
                j += 1
            tokens.append(("number", sql[i:j]))
        elif char == ":":
            if sql.startswith("::", i):
                j = i + 2
                tokens.append(("symbol", "::"))
            elif i + 1 < n and (sql[i + 1].isalpha() or sql[i + 1] == "_"):
                match = PARAMETER.match(sql, i + 1)
                j = match.end() if match else i + 1
                if not match or (j < n and _word_char(sql[j])):
                    raise ConfigError("Placeholder names use 1 to 63 ASCII letters, digits or underscores.")
                tokens.append(("param", match.group(0)))
            elif not pg and i + 1 < n and sql[i + 1].isdigit():
                raise ConfigError("Numbered :1 placeholders are not supported; use :name.")
            else:
                j = i + 1
                tokens.append(("symbol", char))
        elif char == "%":
            match = PYFORMAT.match(sql, i)
            if match:
                j = match.end()
                tokens.append(("param", match.group(1)))
            elif sql.startswith("%s", i) and not (i + 2 < n and _word_char(sql[i + 2])):
                raise ConfigError("Positional %s placeholders are not supported; use :name or %(name)s.")
            elif re.match(r"%\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)", sql[i:]):
                raise ConfigError("Malformed %(name)s placeholder; write a modulo as % (x) with a space.")
            else:
                j = i + 1
                tokens.append(("symbol", char))
        elif not pg and char in "?@$":
            if char == "?" or (i + 1 < n and _word_char(sql[i + 1])):
                raise ConfigError("SQLite statements accept :name or %(name)s placeholders only (not ?, @name or $name).")
            j = i + 1
            tokens.append(("symbol", char))
        elif char == ";":
            j = i + 1
            tokens.append(("semicolon", char))
        else:
            j = i + 1
            tokens.append(("symbol", char))
        i = j
    return tokens


def _significant(tokens):
    return [(index, token) for index, token in enumerate(tokens) if token[0] not in ("space", "comment")]


def _is_trigger(significant):
    words = [token[1].upper() for _, token in significant[:3] if token[0] == "word"]
    return words[:2] == ["CREATE", "TRIGGER"] or (len(words) == 3 and words[0] == "CREATE"
                                                      and words[1] in {"TEMP", "TEMPORARY"} and words[2] == "TRIGGER")


def compile_sql(sql, driver, operation):
    """Validate one authored statement and render it for the selected driver."""
    tokens = scan(sql, driver)
    significant = _significant(tokens)
    if not significant:
        raise ConfigError("Enter one SQL statement.")
    position = 0
    while operation == "query" and position < len(significant) and significant[position][1] == ("symbol", "("):
        position += 1
    allowed = LEADING[(driver, operation)]
    keyword = significant[position][1][1].upper() if position < len(significant) and significant[position][1][0] == "word" else ""
    if keyword not in allowed:
        raise ConfigError(f"{operation} accepts one statement starting with {', '.join(allowed)}"
                          + (f"; {keyword} is not allowed." if keyword else "."))
    last = len(significant) - 1
    body = None
    if driver == "sqlite" and _is_trigger(significant):
        begin = next((k for k, (_, token) in enumerate(significant) if token[0] == "word" and token[1].upper() == "BEGIN"), None)
        end = None
        if begin is not None:
            end = next((k for k in range(begin + 2, len(significant)) if significant[k][1][0] == "word"
                        and significant[k][1][1].upper() == "END" and significant[k - 1][1][0] == "semicolon"), None)
        if end is None:
            raise ConfigError("A CREATE TRIGGER body must be written BEGIN ...; END.")
        body = (begin, end)
        if end != last and not (end == last - 1 and significant[last][1][0] == "semicolon"):
            raise ConfigError("Only one SQL statement is allowed; remove the statements after the trigger.")
    trailing = None
    for k, (index, token) in enumerate(significant):
        if token[0] != "semicolon":
            continue
        if body and body[0] < k < body[1]:
            continue
        if k == last:
            trailing = index
            continue
        raise ConfigError("Only one SQL statement is allowed; ';' separated statements are refused.")
    if trailing is not None:
        tokens = tokens[:trailing] + tokens[trailing + 1:]
    names = list(dict.fromkeys(text for kind, text in tokens if kind == "param"))
    if len(names) > 256:
        raise ConfigError("A statement may use at most 256 distinct placeholders.")
    return {"sql": render(tokens, driver), "placeholders": names, "keyword": keyword}


def render(tokens, driver):
    """psycopg reads every % as a format marker, so literal ones are doubled for PostgreSQL."""
    pg = driver == "postgresql"
    parts = []
    for kind, text in tokens:
        if kind == "param":
            parts.append(f"%({text})s" if pg else f":{text}")
        else:
            parts.append(text.replace("%", "%%") if pg else text)
    return "".join(parts).strip()


# ---------------------------------------------------------------- generated statements


def quote_identifier(name):
    """Identifiers are pre-validated, so quoting never needs escaping."""
    return '"' + name + '"'


def identifier(value, label):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ConfigError(f"{label} must be an identifier of 1 to 63 ASCII letters, digits or underscores, not starting with a digit.")
    return value


def table_name(value):
    if not isinstance(value, str) or not value or value.count(".") > 1:
        raise ConfigError("table must be a table name, optionally schema-qualified as schema.table.")
    for part in value.split("."):
        identifier(part, "table")
    return value


def identifier_list(value, label, low, high):
    if not isinstance(value, list) or not low <= len(value) <= high:
        raise ConfigError(f"{label} must be a JSON array of {low} to {high} column names.")
    names = [identifier(item, label) for item in value]
    if len({name.lower() for name in names}) != len(names):
        raise ConfigError(f"{label} contains duplicate column names.")
    return names


def generated(operation, table, columns, conflict, update, driver):
    """INSERT or ON CONFLICT upsert built only from validated identifiers and placeholders."""
    marker = (lambda name: f"%({name})s") if driver == "postgresql" else (lambda name: f":{name}")
    target = ".".join(quote_identifier(part) for part in table.split("."))
    sql = (f"INSERT INTO {target} ({', '.join(map(quote_identifier, columns))}) "
           f"VALUES ({', '.join(marker(name) for name in columns)})")
    if operation == "upsert":
        sql += f" ON CONFLICT ({', '.join(map(quote_identifier, conflict))})"
        if update:
            sql += " DO UPDATE SET " + ", ".join(f"{quote_identifier(name)} = excluded.{quote_identifier(name)}" for name in update)
        else:
            sql += " DO NOTHING"
    return sql


def definition(raw, driver, name, allow_writes):
    """Compile the default statement or one named statement into an executable plan."""
    operation = raw.get("operation")
    if not isinstance(operation, str) or operation not in OPERATIONS:
        raise ConfigError("operation must be query, execute, insert_rows or upsert.")
    if operation in WRITE_OPERATIONS and not allow_writes:
        raise ConfigError(f"{operation} writes data; enable allow_writes explicitly first.")
    plan = {"name": name, "operation": operation, "read_only": operation == "query"}
    if operation in {"query", "execute"}:
        compiled = compile_sql(raw.get("sql"), driver, operation)
        plan.update(sql=compiled["sql"], placeholders=compiled["placeholders"], columns=[],
                    inserts=compiled["keyword"] in {"INSERT", "REPLACE"})
        return plan
    table = table_name(raw.get("table"))
    columns = identifier_list(raw.get("columns"), "columns", 1, 100)
    conflict, update = [], []
    if operation == "upsert":
        conflict = identifier_list(raw.get("conflict_columns"), "conflict_columns", 1, 32)
        lowered = {column.lower() for column in columns}
        if any(column.lower() not in lowered for column in conflict):
            raise ConfigError("conflict_columns must be listed in columns.")
        update = identifier_list(raw.get("update_columns") or [], "update_columns", 0, 100)
        if any(column.lower() not in lowered for column in update):
            raise ConfigError("update_columns must be listed in columns.")
        if {column.lower() for column in update} & {column.lower() for column in conflict}:
            raise ConfigError("update_columns cannot contain a conflict column.")
        if not update:
            update = [column for column in columns if column.lower() not in {item.lower() for item in conflict}]
    plan.update(sql=generated(operation, table, columns, conflict, update, driver), placeholders=columns,
                columns=columns, inserts=True)
    return plan


# ---------------------------------------------------------------- settings


def _text(config, key, high, *, required=False):
    value = config[key]
    if not isinstance(value, str) or len(value) > high or "\x00" in value or any(ord(c) < 32 for c in value):
        raise ConfigError(f"{key} must be a single-line text of at most {high} characters.")
    if required and not value.strip():
        raise ConfigError(f"{key} is required for PostgreSQL.")
    return value


def _host(value):
    """Hostname, IP literal or absolute Unix-socket directory; never a URL with credentials."""
    if value != value.strip():
        raise ConfigError("pg_host must not start or end with spaces.")
    if value.startswith("/"):
        if ".." in value.split("/"):
            raise ConfigError("pg_host socket directory must be a canonical absolute path.")
        return "socket"
    try:
        address = ipaddress.ip_address(value)
        return "loopback" if address.is_loopback else "network"
    except ValueError:
        pass
    labels = value.rstrip(".").split(".")
    if not value or len(value) > 253 or any(not HOST_LABEL.fullmatch(label) for label in labels):
        raise ConfigError("pg_host must be a host name, an IP address or an absolute socket directory.")
    return "loopback" if value.lower() == "localhost" else "network"


def configuration(raw):
    """Validate every setting before any database, file, network or wallet access."""
    raw = thaw(raw)
    if not isinstance(raw, Mapping):
        raise ConfigError("Settings must be a JSON object.")
    unknown = set(raw) - set(DEFAULTS) - FRAMEWORK_KEYS
    if unknown:
        raise ConfigError("Unknown setting: " + ", ".join(sorted(map(str, unknown)))[:200] + ".")
    config = {**DEFAULTS, **{key: value for key, value in raw.items() if key in DEFAULTS}}
    for key in ("allow_writes", "truncate_results"):
        if type(config[key]) is not bool:
            raise ConfigError(f"{key} must be true or false.")
    for key, (low, high) in LIMITS.items():
        if type(config[key]) is not int or not low <= config[key] <= high:
            raise ConfigError(f"{key} must be an integer between {low} and {high}.")
    if config["driver"] not in DRIVERS:
        raise ConfigError("driver must be sqlite or postgresql.")
    driver = config["driver"]
    if not isinstance(config["sql"], str) or len(config["sql"]) > MAX_SQL_CHARS:
        raise ConfigError(f"sql must be a text of at most {MAX_SQL_CHARS} characters.")
    if not isinstance(config["table"], str) or len(config["table"]) > 127:
        raise ConfigError("table must be a text of at most 127 characters.")
    for key in ("columns", "conflict_columns", "update_columns"):
        if not isinstance(config[key], list) or len(config[key]) > 100:
            raise ConfigError(f"{key} must be a JSON array of at most 100 column names.")
    if driver == "sqlite":
        name = config["sqlite_file"]
        if (not isinstance(name, str) or not SQLITE_FILE.fullmatch(name) or ".." in name
                or not name.lower().endswith((".sqlite3", ".sqlite", ".db"))):
            raise ConfigError("sqlite_file must be a plain file name ending in .sqlite3, .sqlite or .db (no folder).")
    else:
        _text(config, "sqlite_file", 100)
    pg = driver == "postgresql"
    host = _text(config, "pg_host", 255, required=pg)
    _text(config, "pg_database", 63, required=pg)
    _text(config, "pg_user", 63, required=pg)
    ref = _text(config, "pg_password_ref", 200)
    if ref and not SECRET_REF.fullmatch(ref):
        raise ConfigError("pg_password_ref must be a wallet reference such as secret://workspace/name, never a password.")
    if config["pg_sslmode"] not in SSL_MODES:
        raise ConfigError("pg_sslmode must be verify-full, verify-ca, require or disable.")
    root = _text(config, "pg_sslrootcert", 4096)
    if root and root != "system" and not root.startswith("/"):
        raise ConfigError("pg_sslrootcert must be empty, system or an absolute CA file path.")
    if pg:
        scope = _host(host)
        if config["pg_sslmode"] == "disable" and scope == "network":
            raise ConfigError("pg_sslmode disable is only accepted for localhost, a loopback address or a local socket.")
    statements = config["statements"]
    if not isinstance(statements, Mapping) or len(statements) > MAX_STATEMENTS:
        raise ConfigError(f"statements must be a JSON object of at most {MAX_STATEMENTS} named statements.")
    plans = {"default": definition(config, driver, "default", config["allow_writes"])}
    for name, item in statements.items():
        if not isinstance(name, str) or not STATEMENT_NAME.fullmatch(name) or name == "default":
            raise ConfigError("Statement names use 1 to 64 letters, digits or underscores, start with a letter and are not default.")
        if not isinstance(item, Mapping) or "operation" not in item or set(item) - STATEMENT_KEYS:
            raise ConfigError(f"Statement {name} accepts operation, sql, table, columns, conflict_columns and update_columns.")
        try:
            plans[name] = definition(dict(item), driver, name, config["allow_writes"])
        except ConfigError as exc:
            raise ConfigError(f"Statement {name}: {exc}") from None
    config["plans"] = plans
    return config


# ---------------------------------------------------------------- messages and parameters


def _unique_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise SqlError("params", "params contains a duplicate JSON key.")
        result[key] = value
    return result


def _reject_constant(_name):
    raise SqlError("params", "params must not contain NaN or Infinity.")


def strict_json(raw, limit):
    """Bounded, finite, duplicate-free JSON; text inputs are parsed, native values are checked."""
    if isinstance(raw, (bytes, bytearray)):
        try:
            raw = bytes(raw).decode("utf-8")
        except UnicodeDecodeError:
            raise SqlError("params", "params must be UTF-8 JSON.") from None
    if isinstance(raw, str):
        if len(raw.encode("utf-8", "surrogatepass")) > limit:
            raise SqlError("params", "params exceed max_params_bytes.")
        if not raw.strip():
            raise SqlError("params", "params is empty; send a JSON object such as {}.")
        try:
            raw = json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=_reject_constant)
        except SqlError:
            raise
        except (ValueError, RecursionError):
            raise SqlError("params", "params must be strict JSON: an object or an array of objects.") from None
    pending, count = [(raw, 0)], 0
    while pending:
        value, depth = pending.pop()
        count += 1
        if depth > 32 or count > 200000:
            raise SqlError("params", "params exceed the JSON depth or element limits.")
        if isinstance(value, dict):
            if any(not isinstance(key, str) for key in value):
                raise SqlError("params", "JSON object keys must be strings.")
            pending.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            pending.extend((item, depth + 1) for item in value)
        elif isinstance(value, float) and not math.isfinite(value):
            raise SqlError("params", "params must not contain NaN or Infinity.")
        elif value is not None and type(value) not in (str, int, float, bool):
            raise SqlError("params", "params must contain JSON values only.")
    try:
        size = len(json.dumps(raw, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8", "surrogatepass"))
    except (ValueError, TypeError, RecursionError):
        raise SqlError("params", "params must be finite JSON.") from None
    if size > limit:
        raise SqlError("params", "params exceed max_params_bytes.")
    return raw


def sql_value(value, driver, index, name):
    """Bind JSON scalars natively; objects/arrays as compact JSON text. Values are never echoed."""
    if value is None or isinstance(value, (bool, str, float)):
        return value
    if isinstance(value, int):
        if driver == "sqlite" and not INT64[0] <= value <= INT64[1]:
            raise SqlError("params", f"Parameter set {index}: {name} exceeds the SQLite 64-bit integer range.", parameter_set=index)
        return value
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def request(raw, config):
    """Select the statement and bind one or several parameter sets, before any database call."""
    value = strict_json(raw, config["max_params_bytes"])
    plan = config["plans"]["default"]
    if isinstance(value, dict) and "$statement" in value:
        if set(value) - {"$statement", "$params"}:
            raise SqlError("params", "A named-statement message accepts $statement and $params only.")
        name = value["$statement"]
        if not isinstance(name, str) or name not in config["plans"]:
            raise SqlError("params", "Unknown $statement; use default or a name declared in statements.")
        plan = config["plans"][name]
        value = value.get("$params", {})
    elif isinstance(value, dict) and any(key.startswith("$") for key in value):
        raise SqlError("params", "Keys starting with $ are reserved for the $statement envelope.")
    if isinstance(value, dict):
        sets = [value]
    elif isinstance(value, list):
        if plan["operation"] == "query":
            raise SqlError("params", "query accepts one parameter object, not an array.")
        if len(value) > config["max_batch_rows"]:
            raise SqlError("params", "The parameter array exceeds max_batch_rows; nothing was executed.")
        if any(not isinstance(item, dict) for item in value):
            raise SqlError("params", "Every item of the parameter array must be a JSON object.")
        sets = value
    else:
        raise SqlError("params", "params must be a JSON object or an array of JSON objects.")
    bound = []
    for index, item in enumerate(sets):
        values = {}
        for name in plan["placeholders"]:
            if name not in item:
                raise SqlError("params", f"Parameter set {index}: missing value for {name}; nothing was executed.",
                               parameter_set=index)
            values[name] = sql_value(item[name], config["driver"], index, name)
        bound.append(values)
    return plan, bound


# ---------------------------------------------------------------- results


def cell(value):
    """Deterministic JSON form of a driver value (exact decimals as text, blobs as base64)."""
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)
    if isinstance(value, decimal.Decimal):
        return str(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"base64": base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat()
    if isinstance(value, datetime.timedelta):
        return value.total_seconds()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): cell(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [cell(item) for item in value]
    return str(value)


def column_names(description):
    """Result keys must be unique, otherwise one value would silently hide another."""
    names = [str(getattr(item, "name", None) or item[0]) for item in description]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise SqlError("sql", "Result column names must be unique; add AS aliases (duplicate: " + ", ".join(duplicates)[:120] + ").")
    return names


class RowCollector:
    """Accumulate rows within max_rows/max_result_bytes; overflow fails unless truncation is enabled."""

    def __init__(self, config):
        self.max_rows, self.max_bytes = config["max_rows"], config["max_result_bytes"]
        self.truncate, self.items, self.size, self.truncated = config["truncate_results"], [], 2, False
        self.columns = None

    def full(self):
        return self.truncated

    def add(self, columns, row):
        """Return False once no further row may be kept."""
        if self.truncated:
            return False
        if len(self.items) >= self.max_rows:
            if not self.truncate:
                raise SqlError("row_limit", f"The statement returned more than max_rows ({self.max_rows}) rows; add LIMIT or raise max_rows.")
            self.truncated = True
            return False
        try:
            item = {name: cell(value) for name, value in zip(columns, row)}
            size = len(json.dumps(item, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8", "surrogatepass")) + 1
        except (ValueError, TypeError, RecursionError):
            raise SqlError("result", "A result value cannot be represented as JSON.") from None
        if self.size + size > self.max_bytes:
            if not self.truncate:
                raise SqlError("byte_limit", f"The result exceeds max_result_bytes ({self.max_bytes}); select fewer rows or columns.")
            self.truncated = True
            return False
        self.items.append(item)
        self.size += size
        return True


def outcome_documents(plan, config, outcome, duration_ms):
    """Build the rows/result documents published after a successful activation."""
    values = {}
    if outcome["columns"] is not None:
        values["rows"] = outcome["rows"]
    values["result"] = {
        "statement": plan["name"], "operation": plan["operation"], "driver": config["driver"],
        "rowcount": outcome["rowcount"], "last_id": outcome["last_id"],
        "rows_returned": None if outcome["columns"] is None else len(outcome["rows"]),
        "truncated": outcome["truncated"], "columns": outcome["columns"],
        "parameter_sets": outcome["parameter_sets"], "committed": outcome["committed"],
        "duration_ms": duration_ms,
    }
    return values
