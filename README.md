# SQL Database

Run parameterized SQL statements on a SQLite database kept in the node's own storage,
or on a PostgreSQL server you configure explicitly. The SQL text is trusted
configuration; an incoming message only supplies parameter values, which the database
driver binds. Message values are never pasted into the SQL text.

<!-- block-metadata:start -->
[![Block version: 0.1.0](https://img.shields.io/badge/block-0.1.0-blue)](model.json)
[![BloxSmith compatibility: 1.0.9](https://img.shields.io/badge/BloxSmith-1.0.9-brightgreen)](compatibility.json)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Verified BloxSmith versions: **1.0.9** (bundled-block tests; see [test evidence](compatibility.json)).
<!-- block-metadata:end -->

[![SQL Database — parameterized SQL on SQLite or PostgreSQL](media/thumbnail.webp)](media/cover.png)

Use it to keep a small local table (SQLite) or to read and write an existing
PostgreSQL database from a graph: look up records, store form submissions,
upsert synchronized rows, or count what a previous step produced.

## Ports

| Direction | Port | Meaning |
| --- | --- | --- |
| Input | `params` | Required. A JSON object (one parameter set), a JSON array of objects (a batch), or a `$statement` envelope |
| Output | `rows` | JSON array of row objects. Published when the statement returns rows: always for `query`, and for writes with `RETURNING` |
| Output | `result` | Summary of a successful message (see [Results](#results)) |
| Output | `error` | Machine-readable failure (see [Errors](#errors)); `rows` and `result` are not published |

Each `params` message runs one statement. A database failure is a normal activation
that publishes `error`, so a graph can route it. Invalid settings fail the Run
before anything is executed.

## Operations

| `operation` | Statement | Writes |
| --- | --- | --- |
| `query` | Your `sql`, which must start with `SELECT`, `WITH` or `VALUES` (PostgreSQL also `TABLE`) | Never: read-only connection or transaction |
| `execute` | Your `sql`, starting with `INSERT`, `UPDATE`, `DELETE`, `WITH`, `CREATE`, `DROP` or `ALTER` (SQLite also `REPLACE`; PostgreSQL also `MERGE`, `TRUNCATE`) | Yes |
| `insert_rows` | Generated `INSERT INTO table (columns) VALUES (...)` | Yes |
| `upsert` | Generated `INSERT ... ON CONFLICT (conflict_columns) DO UPDATE SET ...` (`DO NOTHING` when every column is a conflict column) | Yes |

`execute`, `insert_rows` and `upsert` are refused until `allow_writes` is checked.
A message is applied in **one transaction**: with a batch of 100 parameter sets, either
the 100 statements commit or none does. Queries cannot write: SQLite opens the file
with `mode=ro`, sets `query_only` and denies write actions in an authorizer;
PostgreSQL runs them in a read-only transaction that is always rolled back.

Exactly **one statement** is accepted. `;`-separated statements, transaction control
(`BEGIN`, `COMMIT`...), `ATTACH`, `DETACH`, `PRAGMA`, `VACUUM`, `COPY`, `DO`, `CALL`,
`SET`, `GRANT`, `LOAD`, `EXPLAIN` and every keyword outside the lists above are refused
when you click Apply and again before a Run. A SQLite `CREATE TRIGGER ... BEGIN ...; END`
body is a single statement and is accepted. PostgreSQL function bodies must use dollar
quotes (`$$ ... $$`); `BEGIN ATOMIC` bodies are refused.

## Parameters

Write placeholders as `:name` or `%(name)s`; both mean the same thing for both drivers.
Names use ASCII letters, digits and underscores. Positional markers (`?`, `$1`, `%s`,
`:1`) and SQLite's `@name`/`$name` are refused, so a parameter can never be bound by
position by mistake.

- Every placeholder must have a value in the message (`null` is a value); a missing one
  fails the message before any database access. Other keys are ignored.
- For `insert_rows` and `upsert`, every listed column must be present in each object.
- JSON strings, numbers, booleans and `null` are bound natively. Objects and arrays are
  bound as their compact JSON text (cast them in SQL if needed, e.g. `%(doc)s::jsonb`).
- Placeholders inside string literals, quoted identifiers and comments are ignored.
- Write a literal `%` once (`LIKE 'abc%'`); the block escapes it for psycopg.
- PostgreSQL casts such as `x::int` work. Write array slices with spaces
  (`arr[lo : hi]`), otherwise `:hi` is read as a placeholder.

A message may be an array of objects for `execute`, `insert_rows` and `upsert` (at most
`max_batch_rows`); `query` accepts one object. An empty array is a successful no-op.

## Named statements

A SQLite database belongs to one node (see [SQLite storage](#sqlite-storage)), so one
node may need several statements: create its table, save rows and read them back.
`statements` declares extra named statements with the same fields and the same
validation as the main one:

```json
{
  "init": {"operation": "execute", "sql": "CREATE TABLE IF NOT EXISTS items (sku TEXT PRIMARY KEY, name TEXT NOT NULL, stock INTEGER NOT NULL)"},
  "save": {"operation": "upsert", "table": "items", "columns": ["sku", "name", "stock"], "conflict_columns": ["sku"]}
}
```

A message selects one with the reserved envelope `{"$statement": "save", "$params": [...]}`
(`$params` defaults to `{}`; `default` names the main statement). Any other message runs
the main statement, and other top-level keys starting with `$` are refused. Names use
letters, digits and underscores; at most 16 named statements.

## SQLite storage

- The database is the file `sqlite_file` (default `database.sqlite3`) inside the node's
  persistent block storage, `.../instances/<instance>/blocs/<node>/`. No other location
  is ever used: the name has no folder part, symbolic and hard links (including journal
  files) are refused, and `ATTACH`/`VACUUM INTO` are denied.
- The file is created with owner-only permissions (0600) by the first write. A query on a
  database that does not exist yet reads an empty database and creates nothing.
- Under the framework's block-storage contract the file survives new Runs, Stop, Reset
  and reopening, is included in a full project ZIP export or duplicate, and is deleted
  with the blueprint. Another node, instance or blueprint never sees it.
- Foreign keys are enforced (`PRAGMA foreign_keys=ON`), `trusted_schema` is off, extension
  loading is disabled and the file cannot grow beyond `sqlite_max_database_mb`.
- SQLite needs a saved blueprint instance: an unsaved standalone Run has no block storage,
  so its initialization fails with an explicit message.

## PostgreSQL

Select `driver: postgresql` and set `pg_host`, `pg_port`, `pg_database` and `pg_user`.
Nothing is contacted while you edit settings, prepare or start a Run; the first message
opens the connection.

- **Password**: `pg_password_ref` holds a wallet reference such as
  `secret://workspace/pg_app`, never the password. The wallet resolves it when a message
  is processed; a locked wallet or unknown reference fails the message before any
  connection. Without a reference an empty password is sent explicitly, and libpq's
  password file is disabled, so no ambient credential is picked up.
- **TLS**: `pg_sslmode` is explicit: `verify-full` (default, certificate and host name),
  `verify-ca`, `require`, or `disable` (accepted only for `localhost`, loopback addresses
  and Unix-socket directories). `pg_sslrootcert` may name a PEM file, or `system` with
  libpq 16+.
- **One connection per message.** Queries run in a read-only transaction through a
  server-side cursor, so at most `max_rows` rows are fetched; writes use prepared
  statements in one transaction, then commit. `statement_timeout` and `lock_timeout` are
  set for that transaction only, from `timeout_sec`.
- PostgreSQL has no automatic "last id": `last_id` is `null`; use `RETURNING id` in an
  `execute` statement and read `rows`.
- Use a database role with only the privileges the node needs. A read-only transaction
  does not restrict server functions that open their own connections (for example
  `dblink` or foreign data wrappers).
- Writes use protocol-level prepared statements inside one transaction. Connection poolers
  that do not support them (for example older PgBouncer versions in transaction mode) are
  not supported; no pooler has been qualified.

## Settings

| Setting | Default | Meaning |
| --- | --- | --- |
| `driver` | `sqlite` | `sqlite` or `postgresql` |
| `operation` | `query` | `query`, `execute`, `insert_rows`, `upsert` |
| `sql` | `SELECT 1 AS ok` | Statement for `query`/`execute`, at most 64 KiB |
| `table` | empty | `table` or `schema.table` for `insert_rows`/`upsert` |
| `columns` | `[]` | 1–100 column names for `insert_rows`/`upsert` |
| `conflict_columns` | `[]` | 1–32 unique-key columns for `upsert` |
| `update_columns` | `[]` | Columns updated on conflict; empty = every non-conflict column |
| `statements` | `{}` | Optional named statements |
| `allow_writes` | `false` | Required for every write operation |
| `sqlite_file` | `database.sqlite3` | File name ending in `.sqlite3`, `.sqlite` or `.db` |
| `sqlite_max_database_mb` | `256` | 1–4096 MiB |
| `pg_host`, `pg_port` | empty, `5432` | Host name, IP address or absolute socket directory; port 1–65535 |
| `pg_database`, `pg_user` | empty | Required for PostgreSQL, at most 63 characters |
| `pg_password_ref` | empty | Wallet reference (`secret://workspace/<name>` or `secret://project/<id>/<name>`) |
| `pg_sslmode`, `pg_sslrootcert` | `verify-full`, empty | TLS mode and optional CA |
| `timeout_sec` | `30` | 1–300; one deadline for connecting, lock waits and all statements of a message |
| `max_rows` | `1000` | 1–10,000 rows published |
| `max_result_bytes` | `1048576` | 1 KiB–8 MiB of published rows |
| `truncate_results` | `false` | Publish the first rows with `truncated: true` instead of failing |
| `max_batch_rows` | `1000` | 1–10,000 parameter objects per message |
| `max_params_bytes` | `1048576` | 1 KiB–8 MiB per message |

Identifiers in `table`, `columns`, `conflict_columns` and `update_columns` are ASCII
names quoted exactly as written; in PostgreSQL use the table's real (usually lowercase)
spelling.

## Results

`rows` is an array of objects keyed by column name. Duplicate result column names are
refused (add `AS` aliases) rather than silently hiding a value. Values are converted
deterministically: blobs/`bytea` become `{"base64": "..."}`, PostgreSQL `numeric`
values become exact strings, dates and times ISO 8601 strings, intervals seconds,
UUIDs strings, JSON values stay JSON, and non-finite floats strings.

`result` contains `statement`, `operation`, `driver`, `rowcount` (rows written, or rows
returned by a query), `last_id` (SQLite: rowid of the last row inserted by this message,
otherwise `null`), `rows_returned` (`null` without a result set), `truncated`,
`columns`, `parameter_sets`, `committed` and `duration_ms`.

More than `max_rows` rows or `max_result_bytes` bytes fails with `row_limit` or
`byte_limit`, unless `truncate_results` is enabled. Prefer a `LIMIT` in the SQL.

## Example

Settings (SQLite, writes enabled, main statement is a query, plus the two named
statements shown above):

```json
{"driver": "sqlite", "allow_writes": true, "operation": "query",
 "sql": "SELECT sku, name, stock FROM items WHERE stock >= :low ORDER BY sku"}
```

Messages, sent from any upstream block (for example through Event Or):

```json
{"$statement": "init"}
{"$statement": "save", "$params": [{"sku": "A-1", "name": "Widget", "stock": 3}, {"sku": "B-2", "name": "Wrench", "stock": 8}]}
{"low": 4}
```

The last message publishes `rows` = `[{"sku": "B-2", "name": "Wrench", "stock": 8}]`
and a `result` with `rowcount: 1`. Sending `{"low": "x' OR 1=1 --"}` simply compares
`stock` with that text: it is a value, not SQL.

## Errors

`error` contains `code`, `message`, `statement`, `operation`, `driver`, `sqlstate`
(PostgreSQL), `parameter_set` (index in a batch, when known), `transient` (retrying
later may succeed) and `committed`: `false` means nothing was written, `null` means the
connection was lost during `COMMIT` and the outcome is unknown, so verify before retrying.

| Code | Meaning |
| --- | --- |
| `params` | Malformed message, missing placeholder value, batch or size limit; nothing executed |
| `secret` | Wallet locked, unknown reference or empty secret; nothing sent |
| `dependency` | psycopg is not installed |
| `storage`, `storage_limit` | SQLite storage unavailable, linked/corrupt file, or size limit reached |
| `connection` | PostgreSQL connection, TLS or authentication failure |
| `timeout`, `cancelled` | Deadline reached or Run stopped; the statement was interrupted |
| `read_only`, `not_authorized`, `permission` | A write in a query, a denied SQLite action, a PostgreSQL privilege error |
| `constraint` | Unique, not-null, check or foreign-key violation |
| `sql` | Statement error (syntax, unknown table or column, duplicate result columns) |
| `conflict`, `busy` | Serialization failure, deadlock or lock wait; transient |
| `row_limit`, `byte_limit`, `result` | Result bounds exceeded or not representable as JSON |
| `database`, `internal` | Any other database error, or an unexpected failure |

Messages may quote the database's own text (for example `UNIQUE constraint failed:
items.sku`); they never contain the wallet password. Run logs contain only the
statement name, operation, driver and error code, never values or SQL.

## Execution

- One Shot Simulation and Active Runtime behave identically. In Active Runtime each
  message triggers its own activation, in arrival order (`on_each_event`).
- Settings are validated when you Apply and again at Run preparation (no database,
  file, network or wallet access). Run initialization then fails early when psycopg is
  missing (PostgreSQL) or block storage is unavailable (SQLite).
- Stop and `timeout_sec` interrupt the running statement (SQLite progress handler and
  interrupt, PostgreSQL cancel request). In managed or linked installations the framework
  terminates the host process on Stop instead: an uncommitted SQLite transaction is rolled
  back from its journal, PostgreSQL aborts an uncommitted transaction when the connection
  closes, and `statement_timeout` bounds any statement the server is still running.
- The block opens no inbound port. The node card shows only the driver and operation,
  never SQL, hosts or references. The modal and inspector share the same fields: SQLite
  or PostgreSQL fields and statement or table fields appear according to the draft,
  changes stay local until Apply, and Apply refuses invalid statements without saving.
  Texts are available in English and French.

## Dependencies

- SQLite: the Python standard library `sqlite3` module (FTS5 and other built-in modules
  as compiled in your Python). No SQLite extension is ever loaded.
- PostgreSQL (optional): `psycopg` 3.1 or newer, listed in [requirements.txt](requirements.txt),
  installed in the Studio Python environment, for example `pip install "psycopg[binary]>=3.1"`.
  The block imports it only when a PostgreSQL message is processed, so it always loads.

## Tests and qualification

- `tests/F5.01_sql_database.py`: settings and statement policy (keywords, chained
  statements, strings/comments/dollar quotes, placeholders), strict parameters, JSON
  conversions, and real SQLite end to end: read-only queries, atomic batches,
  injection attempts stored as data, `RETURNING`, FTS5, views, recursive CTEs, row/byte
  limits, timeout, cancellation, lock waits, size limit, link and corrupt-file refusal,
  and crafted `ATTACH`/`VACUUM INTO`/`PRAGMA`/`load_extension` attempts denied by the
  authorizer. The PostgreSQL path is checked against a psycopg test double.
- `tests/F5.02_sql_database_runtime.py`: real graph Runs in One Shot and Active Runtime
  for bundled, managed and linked installations: SQLite persistence across Runs in
  instance storage, named statements, parameter errors, the PostgreSQL path with an
  isolated wallet (including a locked wallet), and Stop during a running statement.
- `tests/F8.01_sql_database_ui.py`: managed and linked browser hosts, conditional fields,
  Cancel/Apply, refused unsafe drafts, persistence, English and French, desktop and mobile
  widths for the modal and the inspector.

**Not qualified against a real PostgreSQL server.** No PostgreSQL server was available:
the PostgreSQL code path is tested with `tests/pg_double/`, a psycopg test double that
records the connection keywords (password replaced by its hash), SQL text, parameter
names, `prepare` flags, read-only mode, server cursors and cancel calls, and executes
the translated statements on a private SQLite file. Real psycopg/libpq versions, TLS
negotiation, authentication methods, PostgreSQL-specific SQL and types, server-side
cancellation and timeouts, and PgBouncer are not certified. SQLite behaviour is tested
with the real library. No real credential or provider was used.

## Framing decisions

These choices complete the block framing where it left options open:

1. **SQLite location**: the node's persistent block storage only. The framework exposes
   no project-level directory to blocks, so "inside the project" is satisfied by block
   storage, which lives under the workspace project. Consequence: one SQLite database per
   node, hence named statements.
2. **Named statements** (`statements` + `$statement` envelope) let one node create,
   write and read its own database while SQL stays configuration.
3. **Placeholders**: `:name` and `%(name)s` are equivalent and normalized per driver;
   every positional style is refused.
4. **Missing database on read**: a query reads an empty database; only writes create the
   file.
5. **Outputs**: `rows` only when a result set exists; `result` on success; `error` alone on
   failure, with `committed` stating whether anything may have been written.
6. **Limits**: overflow fails by default; `truncate_results` opts into explicit truncation.
7. **PostgreSQL TLS**: `verify-full` by default; `disable` only for local connections.
8. **Remote access** is off by default: the default driver is the local SQLite file, and
   PostgreSQL needs an explicit driver, host, database and user.

## License

Apache-2.0. See [LICENSE](LICENSE).
