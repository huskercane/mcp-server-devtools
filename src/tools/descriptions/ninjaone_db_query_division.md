Run one read-only SQL query against a NinjaOne division database in an
allowlisted QA/dev environment.

Pass `dbHost` and `dbName` from `ninjaone_db_resolve_division`. `dbHost` is resolved through
the selected environment's fixed host allowlist; it is never treated as a raw
network hostname. If the resolved `dbHost` is null, omit it: the query uses the
configured host automatically when exactly one exists, and otherwise asks for
an explicit host key. Only a single `SELECT` or `WITH ... SELECT` is accepted. The
session is forced read-only, has a 10-second statement timeout, and limits the
returned row count. Use a narrow projection and WHERE clause to avoid exposing
unnecessary customer data.
