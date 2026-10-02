create table lab.workspace (
    id uuid primary key,
    visitor_id uuid not null unique references lab.visitor(id),
    state varchar(30) not null default 'PREPARING',
    allowed_accounts jsonb not null,
    created_at timestamptz not null default current_timestamp,
    expires_at timestamptz not null
);
