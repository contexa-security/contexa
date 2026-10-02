create table lab.identity_scope_binding (
    scope_key varchar(60) primary key,
    snapshot_id uuid not null references lab.identity_snapshot(id),
    bound_at timestamptz not null default current_timestamp
);
create trigger immutable_identity_scope before update or delete on lab.identity_scope_binding
    for each row execute function lab.reject_evidence_update();
alter table lab.authentication_observation add column request_method varchar(12);
alter table lab.authentication_observation add column request_path text;
alter table lab.authentication_observation add column authenticated_before boolean;
alter table lab.authentication_observation add column authenticated_after boolean;
alter table lab.authentication_observation add column authentication_type varchar(180);
create index authentication_observation_role_time on lab.authentication_observation(role,occurred_at desc);
