create table lab.visitor (
    id uuid primary key,
    token_sha256 char(64) not null unique,
    email varchar(254),
    created_at timestamptz not null default current_timestamp,
    verified_at timestamptz,
    expires_at timestamptz not null,
    check ((email is null) = (verified_at is null))
);
create table lab.email_challenge (
    id uuid primary key,
    visitor_id uuid not null references lab.visitor(id),
    email varchar(254) not null,
    code_hash varchar(255),
    request_ip varchar(64) not null,
    created_at timestamptz not null default current_timestamp,
    expires_at timestamptz not null,
    sent_at timestamptz,
    consumed_at timestamptz,
    attempts integer not null default 0 check(attempts>=0),
    delivery_state varchar(20) not null check(delivery_state in
        ('SENDING','SENT','FAILED','SUPERSEDED','EXPIRED','LOCKED','CONSUMED'))
);
create index email_challenge_visitor_time on lab.email_challenge(visitor_id,created_at desc);
create index email_challenge_email_time on lab.email_challenge(email,created_at desc);
create index email_challenge_ip_time on lab.email_challenge(request_ip,created_at desc);
