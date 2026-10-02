create table lab.identity_snapshot (
    id uuid primary key,
    source_database text not null,
    content_sha256 char(64) not null unique,
    account_count integer not null check(account_count>0),
    captured_at timestamptz not null default current_timestamp
);
create trigger immutable_identity_snapshot before update or delete on lab.identity_snapshot
    for each row execute function lab.reject_evidence_update();
alter table lab.account alter column username type varchar(100);
alter table lab.account_role alter column username type varchar(100);
alter table lab.account_role alter column authority type text;
alter table lab.experiment alter column owner_username type varchar(100);
alter table lab.authentication_observation alter column username type varchar(100);
alter table lab.account add column source_user_id bigint;
alter table lab.account add column source_snapshot_id uuid references lab.identity_snapshot(id);
alter table lab.account add column account_locked boolean not null default false;
alter table lab.account add column credentials_expired boolean not null default false;
alter table lab.account add column external_auth_only boolean not null default false;
alter table lab.account add column lock_expires_at timestamp;
