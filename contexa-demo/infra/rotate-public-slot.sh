#!/bin/sh
set -eu
[ "$#" -eq 2 ] || { echo 'Usage: rotate-public-slot.sh PRIVATE_SETTINGS PROJECT' >&2; exit 1; }
settings=$(realpath "$1")
project=$2
case "$project" in contexa-runtime-lab-*|contexa-lab-*) ;; *) echo 'Unexpected installation project' >&2; exit 1;; esac
case "$project" in *[!a-z0-9-]*) echo 'Invalid project name' >&2; exit 1;; esac
module=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
value() { sed -n "s/^$1=//p" "$settings"; }
previous=$(value LAB_WORKSPACE_GENERATION)
hex=$(printf '%s' "$previous" | tr -d '-')
printf '%s' "$previous" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' || { echo 'Invalid generation' >&2; exit 1; }
[ "$(value LAB_GENERATION_HEX)" = "$hex" ] || { echo 'Generation mismatch' >&2; exit 1; }
postgres="${project}-postgres-1"
[ "$(docker inspect "$postgres" --format '{{index .Config.Labels "com.docker.compose.project"}}')" = "$project" ] || { echo 'Control database ownership mismatch' >&2; exit 1; }
query() { docker exec "$postgres" psql -U lab -d lab_portal -At -v ON_ERROR_STOP=1 -c "$1"; }
[ "$(query "select state from lab.workspace_slot where id='public-one' and generation='$previous'")" = RESET_REQUIRED ] || { echo 'Only retired slots may rotate' >&2; exit 1; }
[ "$(query "select count(*) from lab.workspace_lease where state='ACTIVE' and slot_id='public-one'")" = 0 ] || { echo 'Active lease prevents rotation' >&2; exit 1; }
[ "$(query 'select count(distinct generation) from lab.workspace_slot_worker')" -lt 64 ] || { echo 'Retention capacity reached' >&2; exit 1; }
next=$(cat /proc/sys/kernel/random/uuid)
next_hex=$(printf '%s' "$next" | tr -d '-')
archive="${settings}.${hex}.retired"
[ ! -e "$archive" ] || { echo 'Preserve previous retirement record' >&2; exit 1; }
cp -- "$settings" "$archive"
docker compose -p "$project" --env-file "$settings" -f "$module/compose.public.yml" stop baseline contexa
docker compose -p "$project" --env-file "$settings" -f "$module/compose.public.yml" stop redis kafka zookeeper
temporary="${settings}.next"
[ ! -e "$temporary" ] || { echo 'Preserve pending settings' >&2; exit 1; }
umask 077
sed -e "s/^LAB_WORKSPACE_GENERATION=.*/LAB_WORKSPACE_GENERATION=$next/" -e "s/^LAB_GENERATION_HEX=.*/LAB_GENERATION_HEX=$next_hex/" "$settings" > "$temporary"
mv -- "$temporary" "$settings"
docker compose -p "$project" --env-file "$settings" -f "$module/compose.public.yml" up -d --no-build
printf 'Project=%s PreviousGeneration=%s NewGeneration=%s RawDatabases=Preserved OldVolumes=Preserved\n' "$project" "$previous" "$next"
