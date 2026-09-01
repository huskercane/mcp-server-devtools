Resolve a NinjaOne division in an allowlisted QA/dev environment.

Use the `divisionUid` from `/ws/webapp/sessionproperties`, an exact `div_...`
database name, a `db_host`, or a partial database/hostname fragment. This tool
queries only that environment's central `division` table and returns the
physical database metadata needed by `ninjaone_db_query_division`. It never connects to
the division database. Production and arbitrary hosts are not supported.
