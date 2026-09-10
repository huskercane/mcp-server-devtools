Run one read-only SQL query against the central database of an allowlisted
NinjaOne QA/dev environment.

Only a single `SELECT` or `WITH ... SELECT` is accepted. The connection target
comes exclusively from `NINJAONE_DB_ENVIRONMENTS`; production and arbitrary
hosts are refused. The session is forced read-only, has a 10-second statement
timeout, and limits the returned row count. Select only the columns and rows
needed, especially when tables may contain customer data or credentials.
