create table lab.experience_journey (
    id uuid primary key,
    visitor_id uuid not null,
    command_id uuid not null,
    created_at timestamptz not null,
    input_sha256 char(64) not null,
    content_sha256 char(64) not null,
    payload text not null,
    unique (visitor_id, command_id)
);
create index experience_journey_owner on lab.experience_journey(visitor_id, created_at desc);
create index comparison_run_journey on lab.comparison_run(visitor_id, (manifest#>>'{plan,journeyStep,journeyId}'));
create trigger experience_journey_immutable before update on lab.experience_journey
    for each row execute function lab.reject_evidence_update();

create table lab.experience_journey_read (
    id uuid primary key,
    journey_id uuid not null references lab.experience_journey(id),
    visitor_id uuid not null,
    command_id uuid not null,
    created_at timestamptz not null,
    input_sha256 char(64) not null,
    payload text not null,
    unique (visitor_id, command_id)
);
create index experience_journey_read_owner on lab.experience_journey_read(visitor_id, journey_id, created_at);
create trigger experience_journey_read_immutable before update on lab.experience_journey_read
    for each row execute function lab.reject_evidence_update();
