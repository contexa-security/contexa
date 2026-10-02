create table lab.experience_report (
    id uuid primary key,
    run_id uuid not null references lab.comparison_run(id),
    visitor_id uuid not null,
    command_id uuid not null,
    created_at timestamptz not null,
    content_sha256 varchar(64) not null,
    payload jsonb not null,
    unique (visitor_id, command_id)
);

create index experience_report_run on lab.experience_report(visitor_id, run_id, created_at desc);

create trigger immutable_experience_report before update on lab.experience_report
    for each row execute function lab.reject_evidence_update();

create table lab.experience_assessment (
    id uuid primary key,
    report_id uuid not null references lab.experience_report(id),
    visitor_id uuid not null,
    command_id uuid not null,
    created_at timestamptz not null,
    input_sha256 varchar(64) not null,
    position varchar(16) not null check (position in ('AGREE', 'DISAGREE', 'UNSURE')),
    request_id uuid,
    comment varchar(1600) not null,
    unique (visitor_id, command_id)
);

create index experience_assessment_report on lab.experience_assessment(visitor_id, report_id, created_at);

create trigger immutable_experience_assessment before update on lab.experience_assessment
    for each row execute function lab.reject_evidence_update();
