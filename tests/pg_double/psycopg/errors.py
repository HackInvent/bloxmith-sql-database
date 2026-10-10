"""Error classes of the psycopg test double, with the SQLSTATE values the block maps."""


class Diagnostic:
    """Mirror of psycopg's ``Error.diag`` for the primary message only."""

    def __init__(self, message):
        self.message_primary = message


class Error(Exception):
    sqlstate = None

    def __init__(self, message="", *, sqlstate=None):
        super().__init__(message)
        if sqlstate is not None:
            self.sqlstate = sqlstate
        self.diag = Diagnostic(message)


class InterfaceError(Error):
    pass


class DatabaseError(Error):
    pass


class DataError(DatabaseError):
    sqlstate = "22000"


class OperationalError(DatabaseError):
    pass


class IntegrityError(DatabaseError):
    sqlstate = "23000"


class InternalError(DatabaseError):
    pass


class ProgrammingError(DatabaseError):
    pass


class NotSupportedError(DatabaseError):
    pass


class QueryCanceled(OperationalError):
    sqlstate = "57014"


class ReadOnlySqlTransaction(InternalError):
    sqlstate = "25006"


class UniqueViolation(IntegrityError):
    sqlstate = "23505"


class NotNullViolation(IntegrityError):
    sqlstate = "23502"


class SyntaxError(ProgrammingError):  # noqa: A001 - psycopg exposes this exact name.
    sqlstate = "42601"


class UndefinedTable(ProgrammingError):
    sqlstate = "42P01"


class UndefinedColumn(ProgrammingError):
    sqlstate = "42703"
