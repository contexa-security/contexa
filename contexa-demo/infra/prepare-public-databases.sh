#!/bin/sh
set -eu
case "$LAB_GENERATION_HEX" in *[!0-9a-f]*|'') exit 2 ;; esac
[ "${#LAB_GENERATION_HEX}" -eq 32 ] || exit 2
export PGPASSWORD="$(cat /run/secrets/LAB_DB_PASSWORD)"
for role in baseline contexa security; do
    database="lab_${LAB_GENERATION_HEX}_${role}"
    exists="$(psql -h postgres -U lab -d lab_portal -At -v ON_ERROR_STOP=1 -c "SELECT count(*) FROM pg_database WHERE datname='$database'")"
    if [ "$exists" = 0 ]; then createdb -h postgres -U lab "$database"; fi
done
psql -h postgres -U lab -d "lab_${LAB_GENERATION_HEX}_security" -v ON_ERROR_STOP=1 -c 'CREATE EXTENSION IF NOT EXISTS vector'
unset PGPASSWORD
