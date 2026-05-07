create table public.vector_store
(
    id        uuid default gen_random_uuid() not null
        primary key,
    content   text                           not null,
    metadata  jsonb,
    embedding vector(1024)
);

alter table public.vector_store
    owner to contexa;

create index vector_store_embedding_idx
    on public.vector_store using hnsw (embedding public.vector_cosine_ops);

create index spring_ai_vector_index
    on public.vector_store using hnsw (embedding public.vector_cosine_ops);

create table public.oauth2_authorization
(
    id                            varchar(100) not null
        primary key,
    registered_client_id          varchar(100) not null,
    principal_name                varchar(200) not null,
    authorization_grant_type      varchar(100) not null,
    authorized_scopes             varchar(1000),
    attributes                    text,
    state                         varchar(500),
    authorization_code_value      text,
    authorization_code_issued_at  timestamp,
    authorization_code_expires_at timestamp,
    authorization_code_metadata   text,
    access_token_value            text,
    access_token_issued_at        timestamp,
    access_token_expires_at       timestamp,
    access_token_metadata         text,
    access_token_type             varchar(100),
    access_token_scopes           varchar(1000),
    oidc_id_token_value           text,
    oidc_id_token_issued_at       timestamp,
    oidc_id_token_expires_at      timestamp,
    oidc_id_token_metadata        text,
    refresh_token_value           text,
    refresh_token_issued_at       timestamp,
    refresh_token_expires_at      timestamp,
    refresh_token_metadata        text,
    user_code_value               text,
    user_code_issued_at           timestamp,
    user_code_expires_at          timestamp,
    user_code_metadata            text,
    device_code_value             text,
    device_code_issued_at         timestamp,
    device_code_expires_at        timestamp,
    device_code_metadata          text
);

alter table public.oauth2_authorization
    owner to contexa;

create index idx_oauth2_authorization_registered_client_id
    on public.oauth2_authorization (registered_client_id);

create index idx_oauth2_authorization_principal_name
    on public.oauth2_authorization (principal_name);

create table public.oauth2_registered_client
(
    id                            varchar(100)                        not null
        primary key,
    client_id                     varchar(100)                        not null,
    client_id_issued_at           timestamp default CURRENT_TIMESTAMP not null,
    client_secret                 varchar(200),
    client_secret_expires_at      timestamp,
    client_name                   varchar(200)                        not null,
    client_authentication_methods varchar(1000)                       not null,
    authorization_grant_types     varchar(1000)                       not null,
    redirect_uris                 varchar(1000),
    post_logout_redirect_uris     varchar(1000),
    scopes                        varchar(1000)                       not null,
    client_settings               varchar(2000)                       not null,
    token_settings                varchar(2000)                       not null
);

alter table public.oauth2_registered_client
    owner to contexa;

create unique index idx_oauth2_registered_client_client_id
    on public.oauth2_registered_client (client_id);

create table public.user_credentials
(
    credential_id                varchar(1000) not null
        primary key,
    user_entity_user_id          varchar(1000) not null,
    public_key                   bytea         not null,
    signature_count              bigint,
    uv_initialized               boolean,
    backup_eligible              boolean       not null,
    authenticator_transports     varchar(1000),
    public_key_credential_type   varchar(100),
    backup_state                 boolean       not null,
    attestation_object           bytea,
    attestation_client_data_json bytea,
    created                      timestamp,
    last_used                    timestamp,
    label                        varchar(1000) not null
);

alter table public.user_credentials
    owner to contexa;

create table public.user_entities
(
    id           varchar(1000) not null
        primary key,
    name         varchar(100)  not null,
    display_name varchar(200)
);

alter table public.user_entities
    owner to contexa;

create table public.one_time_tokens
(
    token_value varchar(36) not null
        primary key,
    username    varchar(50) not null,
    expires_at  timestamp   not null
);

alter table public.one_time_tokens
    owner to contexa;

create table public.mcp_client_states
(
    client_name                varchar(100)                                     not null
        primary key,
    enabled                    boolean     default true not null,
    health_status              varchar(30) default 'UNKNOWN'::character varying not null,
    health_message             varchar(500),
    last_health_checked_at     timestamp(6),
    updated_at                 timestamp(6)                                     not null,
    backoff_until              timestamp(6),
    degraded_reason            varchar(500),
    last_successful_connect_at timestamp(6)
);

alter table public.mcp_client_states
    owner to contexa;

create table public.mcp_surface_states
(
    surface_key       varchar(180)         not null
        primary key,
    surface_type      varchar(30)          not null,
    surface_name      varchar(140)         not null,
    client_name       varchar(100)         not null,
    enabled           boolean default true not null,
    version           varchar(64)          not null,
    last_refreshed_at timestamp(6),
    updated_at        timestamp(6)         not null
);

alter table public.mcp_surface_states
    owner to contexa;

create table public.tool_execution_contexts
(
    id                   bigserial
        primary key,
    request_id           varchar(100) not null
        unique
        constraint idx_tool_context_request_id
            unique,
    permit_id            varchar(100)
        unique
        constraint idx_tool_context_permit_id
            unique,
    approval_id          varchar(100),
    status               varchar(20)  not null,
    tool_name            varchar(255) not null,
    tool_type            varchar(50),
    tool_call_id         varchar(255),
    tool_arguments       text,
    tool_definitions     text,
    prompt_content       text         not null,
    execution_class      varchar(30),
    arguments_hash       varchar(128),
    required_scope       varchar(500),
    available_tools      text,
    chat_options         text,
    chat_response        text,
    execution_result     text,
    execution_error      text,
    execution_start_time timestamp(6),
    execution_end_time   timestamp(6),
    incident_id          varchar(100),
    session_id           varchar(100),
    risk_level           varchar(20),
    soar_context         text,
    pipeline_context     text,
    metadata             text,
    max_retries          integer,
    retry_count          integer,
    expires_at           timestamp(6),
    created_at           timestamp(6) not null,
    updated_at           timestamp(6) not null
);

alter table public.tool_execution_contexts
    owner to contexa;

create index idx_tool_context_created_at
    on public.tool_execution_contexts (created_at);

create index idx_tool_context_status
    on public.tool_execution_contexts (status);

create index idx_tool_context_tool_name
    on public.tool_execution_contexts (tool_name);

create table public.tenant_lifecycle_events
(
    id           bigserial
        primary key,
    tenant_id    varchar(120) not null,
    event_type   varchar(80)  not null,
    actor_id     varchar(120),
    payload_json text,
    created_at   timestamp(6) not null
);

alter table public.tenant_lifecycle_events
    owner to contexa;

create index idx_tenant_lifecycle_event_tenant_created
    on public.tenant_lifecycle_events (tenant_id, created_at);

create table public.saas_tenants
(
    id                 bigserial
        primary key,
    tenant_id          varchar(120)                                          not null
        unique,
    display_name       varchar(255)                                          not null,
    organization_id    varchar(120)                                          not null
        unique,
    deployment_mode    varchar(40) default 'SHARED_CLOUD'::character varying not null,
    region             varchar(80)                                           not null,
    status             varchar(40) default 'PENDING'::character varying      not null,
    plan_code          varchar(80)                                           not null,
    billing_account_id varchar(120),
    activated_at       timestamp(6),
    suspended_at       timestamp(6),
    terminated_at      timestamp(6),
    created_at         timestamp(6)                                          not null,
    updated_at         timestamp(6)                                          not null
);

alter table public.saas_tenants
    owner to contexa;

create index idx_saas_tenant_status
    on public.saas_tenants (status);

create index idx_saas_tenant_plan
    on public.saas_tenants (plan_code);

create index idx_saas_tenant_plan_code
    on public.saas_tenants (plan_code);

create index idx_saas_tenant_deployment_mode
    on public.saas_tenants (deployment_mode);

create table public.tenant_subscriptions
(
    id                       bigserial
        primary key,
    tenant_id                varchar(120)                                                not null
        unique,
    plan_code                varchar(80)                                                 not null,
    billing_model            varchar(40)    default 'MONTHLY_TRUE_UP'::character varying not null,
    contract_start_at        timestamp(6)                                                not null,
    contract_end_at          timestamp(6),
    support_tier             varchar(40)    default 'STANDARD'::character varying        not null,
    auto_renew               boolean        default true                                 not null,
    committed_monthly_amount numeric(18, 2) default 0.00                                 not null,
    created_at               timestamp(6)                                                not null,
    updated_at               timestamp(6)                                                not null
);

alter table public.tenant_subscriptions
    owner to contexa;

create index idx_tenant_sub_plan
    on public.tenant_subscriptions (plan_code);

create index idx_tenant_sub_contract_end
    on public.tenant_subscriptions (contract_end_at);

create index idx_tenant_subscription_plan_code
    on public.tenant_subscriptions (plan_code);

create index idx_tenant_subscription_contract_end
    on public.tenant_subscriptions (contract_end_at);

create table public.tenant_environments
(
    id              bigserial
        primary key,
    tenant_id       varchar(120)                                    not null,
    environment_key varchar(80)                                     not null,
    display_name    varchar(120)                                    not null,
    deployment_mode varchar(40)                                     not null,
    region          varchar(80)                                     not null,
    status          varchar(40) default 'ACTIVE'::character varying not null,
    created_at      timestamp(6)                                    not null,
    updated_at      timestamp(6)                                    not null
);

alter table public.tenant_environments
    owner to contexa;

create index idx_tenant_env_key
    on public.tenant_environments (tenant_id, environment_key);

create index idx_tenant_environment_lookup
    on public.tenant_environments (tenant_id, environment_key);

create table public.tenant_entitlements
(
    id                bigserial
        primary key,
    tenant_id         varchar(120)                                  not null,
    entitlement_key   varchar(120)                                  not null,
    entitlement_value varchar(500)                                  not null,
    value_type        varchar(40)                                   not null,
    effective_from    timestamp(6)                                  not null,
    effective_to      timestamp(6),
    source            varchar(40) default 'PLAN'::character varying not null,
    created_at        timestamp(6)                                  not null
);

alter table public.tenant_entitlements
    owner to contexa;

create index idx_tenant_entitlement
    on public.tenant_entitlements (tenant_id, entitlement_key, effective_to);

create index idx_tenant_entitlement_lookup
    on public.tenant_entitlements (tenant_id, entitlement_key, effective_to);

create table public.tenant_operator_assignments
(
    id             bigserial
        primary key,
    tenant_id      varchar(120)                                     not null,
    user_id        varchar(160)                                     not null,
    role_code      varchar(80)                                      not null,
    status         varchar(40) default 'INVITED'::character varying not null,
    invited_at     timestamp(6)                                     not null,
    activated_at   timestamp(6),
    deactivated_at timestamp(6),
    created_by     varchar(160),
    deactivated_by varchar(160),
    created_at     timestamp(6)                                     not null,
    updated_at     timestamp(6)                                     not null
);

alter table public.tenant_operator_assignments
    owner to contexa;

create index idx_tenant_operator_user
    on public.tenant_operator_assignments (tenant_id, user_id);

create index idx_tenant_operator_status
    on public.tenant_operator_assignments (tenant_id, status);

create index idx_tenant_operator_lookup
    on public.tenant_operator_assignments (tenant_id, user_id);

create table public.tenant_provisioning_tasks
(
    id            bigserial
        primary key,
    tenant_id     varchar(120)                                     not null,
    task_type     varchar(120)                                     not null,
    status        varchar(40) default 'PENDING'::character varying not null,
    reference_key varchar(160),
    payload_json  text,
    scheduled_at  timestamp(6),
    started_at    timestamp(6),
    completed_at  timestamp(6),
    failed_at     timestamp(6),
    error_message varchar(1000),
    created_at    timestamp(6)                                     not null,
    updated_at    timestamp(6)                                     not null
);

alter table public.tenant_provisioning_tasks
    owner to contexa;

create index idx_tenant_prov_status
    on public.tenant_provisioning_tasks (tenant_id, task_type, status);

create index idx_tenant_prov_ref
    on public.tenant_provisioning_tasks (tenant_id, reference_key);

create index idx_tenant_provisioning_task_lookup
    on public.tenant_provisioning_tasks (tenant_id, task_type, status);

create index idx_tenant_provisioning_task_reference
    on public.tenant_provisioning_tasks (tenant_id, reference_key);

create table public.tenant_purge_requests
(
    id                   bigserial
        primary key,
    tenant_id            varchar(120) not null,
    provisioning_task_id bigint,
    reference_key        varchar(160) not null,
    status               varchar(40)  not null,
    approval_state       varchar(60)  not null,
    data_domains_json    text,
    requested_by         varchar(120) not null,
    request_reason       varchar(1000),
    approved_by          varchar(120),
    rejected_by          varchar(120),
    executed_by          varchar(120),
    approved_at          timestamp(6),
    rejected_at          timestamp(6),
    executed_at          timestamp(6),
    scheduled_at         timestamp(6) not null,
    execution_summary    varchar(1000),
    metadata_json        text,
    created_at           timestamp(6) not null,
    updated_at           timestamp(6) not null
);

alter table public.tenant_purge_requests
    owner to contexa;

create index idx_tenant_purge_status
    on public.tenant_purge_requests (tenant_id, status, scheduled_at);

create index idx_tenant_purge_prov
    on public.tenant_purge_requests (tenant_id, provisioning_task_id);

create index idx_tenant_purge_request_lookup
    on public.tenant_purge_requests (tenant_id, status, scheduled_at);

create index idx_tenant_purge_request_task
    on public.tenant_purge_requests (tenant_id, provisioning_task_id);

create table public.tenant_backup_policies
(
    id                              bigserial
        primary key,
    tenant_id                       varchar(120) not null
        unique
        constraint idx_tenant_backup_policy_tenant
            unique,
    backup_frequency                varchar(40)  not null,
    backup_window_start_hour        integer      not null,
    backup_window_duration_hours    integer      not null,
    backup_retention_days           integer      not null,
    restore_drill_cadence_days      integer      not null,
    restore_evidence_retention_days integer      not null,
    export_window_start_hour        integer      not null,
    export_window_end_hour          integer      not null,
    purge_approval_required         boolean      not null,
    last_backup_completed_at        timestamp(6),
    last_restore_drill_completed_at timestamp(6),
    notes                           varchar(1000),
    created_at                      timestamp(6) not null,
    updated_at                      timestamp(6) not null
);

alter table public.tenant_backup_policies
    owner to contexa;

create table public.tenant_restore_drills
(
    id                 bigserial
        primary key,
    tenant_id          varchar(120) not null,
    target_environment varchar(80)  not null,
    backup_reference   varchar(255),
    evidence_reference varchar(255),
    status             varchar(40)  not null,
    initiated_by       varchar(120) not null,
    started_at         timestamp(6) not null,
    completed_at       timestamp(6) not null,
    notes              varchar(1000),
    metadata_json      text,
    created_at         timestamp(6) not null,
    updated_at         timestamp(6) not null
);

alter table public.tenant_restore_drills
    owner to contexa;

create index idx_tenant_drill_status
    on public.tenant_restore_drills (tenant_id, status, completed_at);

create index idx_tenant_restore_drill_lookup
    on public.tenant_restore_drills (tenant_id, status, completed_at);

create index idx_tenant_restore_drill_created
    on public.tenant_restore_drills (tenant_id, created_at);

create table public.tenant_quotas
(
    id          bigserial
        primary key,
    tenant_id   varchar(120)                                        not null,
    quota_key   varchar(120)                                        not null,
    limit_value bigint                                              not null,
    policy_type varchar(40) default 'HARD_LIMIT'::character varying not null,
    grace_until timestamp(6),
    updated_at  timestamp(6)                                        not null
);

alter table public.tenant_quotas
    owner to contexa;

create index idx_tenant_quota
    on public.tenant_quotas (tenant_id, quota_key);

create index idx_tenant_quota_lookup
    on public.tenant_quotas (tenant_id, quota_key);

create table public.tenant_quota_violations
(
    id              bigserial
        primary key,
    tenant_id       varchar(120) not null,
    quota_key       varchar(120) not null,
    policy_type     varchar(40)  not null,
    attempted_usage bigint       not null,
    limit_value     bigint       not null,
    message         varchar(500) not null,
    billing_period  varchar(20)  not null,
    metadata_json   text,
    occurred_at     timestamp(6) not null
);

alter table public.tenant_quota_violations
    owner to contexa;

create index idx_tenant_violation_time
    on public.tenant_quota_violations (tenant_id, occurred_at);

create index idx_tenant_violation_key
    on public.tenant_quota_violations (tenant_id, quota_key, billing_period);

create index idx_tenant_quota_violation_lookup
    on public.tenant_quota_violations (tenant_id, occurred_at);

create index idx_tenant_quota_violation_key
    on public.tenant_quota_violations (tenant_id, quota_key, billing_period);

create table public.tenant_isolation_states
(
    id                bigserial
        primary key,
    tenant_id         varchar(120) not null,
    scope_type        varchar(40)  not null,
    scope_key         varchar(160) not null,
    workload_type     varchar(80)  not null,
    status            varchar(40)  not null,
    reason_code       varchar(120) not null,
    message           varchar(500) not null,
    trigger_count     integer      not null,
    contained_until   timestamp(6) not null,
    last_triggered_at timestamp(6) not null,
    created_at        timestamp(6) not null,
    updated_at        timestamp(6) not null
);

alter table public.tenant_isolation_states
    owner to contexa;

create index idx_tenant_isolation_scope
    on public.tenant_isolation_states (tenant_id, scope_type, scope_key, workload_type);

create index idx_tenant_isolation_status
    on public.tenant_isolation_states (tenant_id, status, contained_until);

create index idx_tenant_isolation_state_lookup
    on public.tenant_isolation_states (tenant_id, scope_type, scope_key, workload_type);

create index idx_tenant_isolation_state_status
    on public.tenant_isolation_states (tenant_id, status, contained_until);

create table public.tenant_isolation_events
(
    id              bigserial
        primary key,
    tenant_id       varchar(120) not null,
    scope_type      varchar(40)  not null,
    scope_key       varchar(160) not null,
    workload_type   varchar(80)  not null,
    decision        varchar(60)  not null,
    attempted_value bigint       not null,
    limit_value     bigint       not null,
    window_seconds  integer      not null,
    message         varchar(500) not null,
    metadata_json   text,
    occurred_at     timestamp(6) not null
);

alter table public.tenant_isolation_events
    owner to contexa;

create index idx_tenant_iso_event_time
    on public.tenant_isolation_events (tenant_id, occurred_at);

create index idx_tenant_iso_event_scope
    on public.tenant_isolation_events (tenant_id, scope_type, scope_key, workload_type, decision);

create index idx_tenant_isolation_event_lookup
    on public.tenant_isolation_events (tenant_id, occurred_at);

create index idx_tenant_isolation_event_scope
    on public.tenant_isolation_events (tenant_id, scope_type, scope_key, workload_type, decision);

create table public.tenant_workload_leases
(
    id            bigserial
        primary key,
    tenant_id     varchar(120) not null,
    workload_type varchar(80)  not null,
    owner_id      varchar(160) not null,
    resource_key  varchar(200),
    status        varchar(40)  not null,
    metadata_json text,
    acquired_at   timestamp(6) not null,
    expires_at    timestamp(6) not null,
    released_at   timestamp(6)
);

alter table public.tenant_workload_leases
    owner to contexa;

create index idx_tenant_lease_active
    on public.tenant_workload_leases (tenant_id, workload_type, status, expires_at);

create index idx_tenant_lease_acquired
    on public.tenant_workload_leases (tenant_id, workload_type, acquired_at);

create index idx_tenant_workload_lease_active
    on public.tenant_workload_leases (tenant_id, workload_type, status, expires_at);

create index idx_tenant_workload_lease_window
    on public.tenant_workload_leases (tenant_id, workload_type, acquired_at);

create table public.protected_app_groups
(
    id                bigserial
        primary key,
    app_group_id      varchar(120)                                               not null
        unique,
    tenant_id         varchar(120)                                               not null,
    display_name      varchar(255)                                               not null,
    environment       varchar(80)                                                not null,
    binding_type      varchar(40)                                                not null,
    status            varchar(40) default 'PENDING_HEARTBEAT'::character varying not null,
    last_heartbeat_at timestamp(6),
    created_at        timestamp(6)                                               not null,
    updated_at        timestamp(6)                                               not null
);

alter table public.protected_app_groups
    owner to contexa;

create index idx_app_group_tenant_status
    on public.protected_app_groups (tenant_id, status);

create index idx_app_group_tenant_heartbeat
    on public.protected_app_groups (tenant_id, last_heartbeat_at);

create index idx_protected_app_group_tenant_status
    on public.protected_app_groups (tenant_id, status);

create index idx_protected_app_group_tenant_heartbeat
    on public.protected_app_groups (tenant_id, last_heartbeat_at);

create table public.protected_app_endpoints
(
    id           bigserial
        primary key,
    tenant_id    varchar(120)                                      not null,
    app_group_id varchar(120)                                      not null,
    path_pattern varchar(300)                                      not null,
    http_method  varchar(20)                                       not null,
    sensitivity  varchar(40) default 'STANDARD'::character varying not null,
    status       varchar(40) default 'ACTIVE'::character varying   not null,
    created_at   timestamp(6)                                      not null
);

alter table public.protected_app_endpoints
    owner to contexa;

create index idx_app_endpoint_group
    on public.protected_app_endpoints (app_group_id);

create index idx_app_endpoint_tenant
    on public.protected_app_endpoints (tenant_id, status);

create index idx_protected_app_endpoint_group
    on public.protected_app_endpoints (app_group_id);

create index idx_protected_app_endpoint_tenant
    on public.protected_app_endpoints (tenant_id, status);

create table public.protected_app_bindings
(
    id            bigserial
        primary key,
    app_group_id  varchar(120)                                    not null,
    binding_key   varchar(120)                                    not null,
    binding_value varchar(500)                                    not null,
    status        varchar(40) default 'ACTIVE'::character varying not null,
    created_at    timestamp(6)                                    not null
);

alter table public.protected_app_bindings
    owner to contexa;

create index idx_app_binding_group
    on public.protected_app_bindings (app_group_id);

create index idx_protected_app_binding_group
    on public.protected_app_bindings (app_group_id);

create table public.protected_app_heartbeats
(
    id            bigserial
        primary key,
    tenant_id     varchar(120) not null,
    app_group_id  varchar(120) not null,
    client_id     varchar(160),
    occurred_at   timestamp(6) not null,
    source_module varchar(120) not null,
    metadata_json text
);

alter table public.protected_app_heartbeats
    owner to contexa;

create index idx_app_heartbeat_group
    on public.protected_app_heartbeats (tenant_id, app_group_id, occurred_at);

create index idx_app_heartbeat_client
    on public.protected_app_heartbeats (tenant_id, client_id, occurred_at);

create index idx_protected_app_heartbeat_period
    on public.protected_app_heartbeats (tenant_id, app_group_id, occurred_at);

create index idx_protected_app_heartbeat_client
    on public.protected_app_heartbeats (tenant_id, client_id, occurred_at);

create table public.billing_contracts
(
    id                     bigserial
        primary key,
    tenant_id              varchar(120)                                    not null
        unique,
    billing_channel        varchar(40) default 'DIRECT'::character varying not null,
    billing_model          varchar(40)                                     not null,
    currency               varchar(16) default 'USD'::character varying    not null,
    annual_commit_amount   numeric(18, 2),
    reseller_partner_id    varchar(120),
    marketplace_provider   varchar(80),
    marketplace_account_id varchar(180),
    settlement_account_id  varchar(180),
    effective_from         timestamp(6)                                    not null,
    effective_to           timestamp(6),
    status                 varchar(40) default 'ACTIVE'::character varying not null,
    notes                  text,
    created_at             timestamp(6)                                    not null,
    updated_at             timestamp(6)                                    not null
);

alter table public.billing_contracts
    owner to contexa;

create index idx_billing_contract_channel
    on public.billing_contracts (billing_channel);

create index idx_billing_contract_status
    on public.billing_contracts (status);

create table public.billing_invoices
(
    id               bigserial
        primary key,
    invoice_id       varchar(160)                                      not null
        unique,
    tenant_id        varchar(120)                                      not null,
    billing_period   varchar(20)                                       not null,
    currency         varchar(16)    default 'USD'::character varying   not null,
    committed_amount numeric(18, 2) default 0.00                       not null,
    overage_amount   numeric(18, 2) default 0.00                       not null,
    total_amount     numeric(18, 2) default 0.00                       not null,
    status           varchar(40)    default 'DRAFT'::character varying not null,
    issued_at        timestamp(6),
    due_at           timestamp(6),
    created_at       timestamp(6)                                      not null,
    updated_at       timestamp(6)                                      not null
);

alter table public.billing_invoices
    owner to contexa;

create index idx_billing_invoice_tenant
    on public.billing_invoices (tenant_id, billing_period);

create index idx_billing_invoice_tenant_period
    on public.billing_invoices (tenant_id, billing_period);

create index idx_billing_invoice_status
    on public.billing_invoices (status);

create table public.billing_line_items
(
    id          bigserial
        primary key,
    invoice_id  varchar(160)                not null,
    line_type   varchar(40)                 not null,
    meter_key   varchar(80),
    description varchar(255)                not null,
    quantity    numeric(18, 2) default 0.00 not null,
    unit_price  numeric(18, 2) default 0.00 not null,
    amount      numeric(18, 2) default 0.00 not null,
    created_at  timestamp(6)                not null
);

alter table public.billing_line_items
    owner to contexa;

create index idx_billing_line_invoice
    on public.billing_line_items (invoice_id);

create index idx_billing_line_meter
    on public.billing_line_items (meter_key);

create index idx_billing_line_item_invoice
    on public.billing_line_items (invoice_id);

create index idx_billing_line_item_meter_key
    on public.billing_line_items (meter_key);

create table public.billing_adjustments
(
    id              bigserial
        primary key,
    adjustment_id   varchar(180)                not null
        unique,
    tenant_id       varchar(120)                not null,
    billing_period  varchar(20)                 not null,
    invoice_id      varchar(160),
    adjustment_type varchar(40)                 not null,
    reason_code     varchar(80)                 not null,
    description     varchar(255)                not null,
    amount          numeric(18, 2) default 0.00 not null,
    status          varchar(60)                 not null,
    requested_by    varchar(120)                not null,
    applied_at      timestamp(6),
    voided_at       timestamp(6),
    voided_by       varchar(120),
    void_reason     varchar(255),
    metadata_json   text,
    created_at      timestamp(6)                not null,
    updated_at      timestamp(6)                not null
);

alter table public.billing_adjustments
    owner to contexa;

create index idx_billing_adj_tenant
    on public.billing_adjustments (tenant_id, billing_period);

create index idx_billing_adj_status
    on public.billing_adjustments (status);

create index idx_billing_adj_invoice
    on public.billing_adjustments (invoice_id);

create index idx_billing_adjustment_tenant_period
    on public.billing_adjustments (tenant_id, billing_period);

create index idx_billing_adjustment_status
    on public.billing_adjustments (status);

create index idx_billing_adjustment_invoice
    on public.billing_adjustments (invoice_id);

create table public.invoice_export_batches
(
    id              bigserial
        primary key,
    tenant_id       varchar(120) not null,
    invoice_id      varchar(160),
    billing_period  varchar(20)  not null,
    export_type     varchar(60)  not null,
    export_format   varchar(20)  not null,
    status          varchar(40)  not null,
    requested_by    varchar(120),
    file_name       varchar(220) not null,
    checksum_sha256 varchar(128),
    metadata_json   text,
    exported_at     timestamp(6) not null
);

alter table public.invoice_export_batches
    owner to contexa;

create index idx_invoice_export_tenant
    on public.invoice_export_batches (tenant_id, billing_period);

create index idx_invoice_export_type
    on public.invoice_export_batches (export_type, export_format);

create index idx_invoice_export_batch_tenant_period
    on public.invoice_export_batches (tenant_id, billing_period);

create index idx_invoice_export_batch_type
    on public.invoice_export_batches (export_type, export_format);

create table public.usage_meter_events
(
    id             bigserial
        primary key,
    tenant_id      varchar(120) not null,
    meter_key      varchar(120) not null,
    quantity       bigint       not null,
    unit           varchar(40)  not null,
    source_module  varchar(120) not null,
    source_ref     varchar(180),
    occurred_at    timestamp(6) not null,
    billing_period varchar(20)  not null,
    metadata_json  text,
    constraint uk_usage_meter_event_source_ref
        unique (tenant_id, meter_key, billing_period, source_ref)
);

alter table public.usage_meter_events
    owner to contexa;

create index idx_usage_meter_period
    on public.usage_meter_events (tenant_id, billing_period);

create index idx_usage_meter_key
    on public.usage_meter_events (tenant_id, meter_key, billing_period);

create index idx_usage_tenant_period
    on public.usage_meter_events (tenant_id, billing_period);

create table public.usage_aggregations
(
    id                  bigserial
        primary key,
    tenant_id           varchar(120) not null,
    billing_period      varchar(20)  not null,
    meter_key           varchar(120) not null,
    aggregated_quantity bigint       not null,
    included_quantity   bigint       not null,
    overage_quantity    bigint       not null,
    calculated_at       timestamp(6) not null,
    unique (tenant_id, billing_period, meter_key),
    constraint idx_usage_aggregation_lookup
        unique (tenant_id, billing_period, meter_key)
);

alter table public.usage_aggregations
    owner to contexa;

create table public.dedicated_deployment_profiles
(
    id                bigserial
        primary key,
    tenant_id         varchar(120)                                       not null
        unique,
    region            varchar(80)                                        not null,
    previous_region   varchar(80),
    network_isolation varchar(80)                                        not null,
    retention_policy  varchar(80)                                        not null,
    support_tier      varchar(40)                                        not null,
    billing_model     varchar(40)                                        not null,
    allocation_state  varchar(40) default 'REQUESTED'::character varying not null,
    requested_at      timestamp(6),
    activated_at      timestamp(6),
    notes             text,
    created_at        timestamp(6)                                       not null,
    updated_at        timestamp(6)                                       not null
);

alter table public.dedicated_deployment_profiles
    owner to contexa;

create index idx_dedicated_deploy_state
    on public.dedicated_deployment_profiles (allocation_state);

create index idx_dedicated_profile_state
    on public.dedicated_deployment_profiles (allocation_state);

create table public.oauth2_authorization_consent
(
    registered_client_id varchar(100)  not null
        references public.oauth2_registered_client,
    principal_name       varchar(200)  not null,
    authorities          varchar(1000) not null,
    primary key (registered_client_id, principal_name)
);

alter table public.oauth2_authorization_consent
    owner to contexa;

create table public.behavior_anomaly_events
(
    id                 bigint generated by default as identity
        primary key,
    action_taken       varchar(100),
    action_timestamp   timestamp(6),
    activity           varchar(500),
    admin_feedback     varchar(20),
    ai_analysis_id     varchar(255),
    ai_confidence      real,
    ai_summary         text,
    anomaly_factors    json,
    anomaly_score      double precision not null,
    event_timestamp    timestamp(6)     not null,
    feedback_by        varchar(255),
    feedback_comment   text,
    feedback_timestamp timestamp(6),
    remote_ip          varchar(45),
    risk_level         varchar(20),
    user_id            varchar(255)     not null
);

alter table public.behavior_anomaly_events
    owner to contexa;

create table public.behavior_based_permissions
(
    id                    bigint generated by default as identity
        primary key,
    is_active             boolean,
    applicable_to         varchar(50),
    condition_expression  text,
    created_at            timestamp(6),
    created_by            varchar(255),
    description           text,
    permission_adjustment varchar(50),
    priority              integer
);

alter table public.behavior_based_permissions
    owner to contexa;

create table public.behavior_realtime_cache
(
    user_id                 varchar(255) not null
        primary key,
    current_risk_score      real,
    current_session_id      varchar(255),
    expires_at              timestamp(6),
    last_activity_timestamp timestamp(6),
    recent_activities       json,
    risk_factors            json,
    session_ip              varchar(45),
    session_start_time      timestamp(6)
);

alter table public.behavior_realtime_cache
    owner to contexa;

create table public.ai_native_containment_actions
(
    id                bigint generated by default as identity
        primary key,
    action_type       varchar(80)  not null,
    actor             varchar(160) not null,
    containment_state varchar(80)  not null,
    created_at        timestamp(6) not null,
    executed_action   varchar(120) not null,
    execution_state   varchar(80)  not null,
    expires_at        timestamp(6),
    facts_json        text,
    readiness_state   varchar(80)  not null,
    reason            varchar(1000),
    requested_action  varchar(120) not null,
    target_key        varchar(255),
    target_scope      varchar(120) not null,
    tenant_id         varchar(120) not null,
    updated_at        timestamp(6) not null
);

alter table public.ai_native_containment_actions
    owner to contexa;

create index idx_ai_native_containment_tenant_created
    on public.ai_native_containment_actions (tenant_id, created_at);

create index idx_ai_native_containment_tenant_state
    on public.ai_native_containment_actions (tenant_id, containment_state, created_at);

create table public.ai_native_model_artifact
(
    id                bigint generated by default as identity
        primary key,
    artifact_state    varchar(64),
    artifact_version  varchar(128) not null,
    capabilities_json varchar(4000),
    created_at        timestamp(6) not null,
    deployment_role   varchar(256),
    facts_json        varchar(8000),
    model_id          varchar(256) not null,
    provider_name     varchar(128),
    runtime_deployed  boolean      not null,
    tenant_id         varchar(128) not null,
    model_tier        integer,
    updated_at        timestamp(6) not null,
    constraint idx_ai_native_model_artifact_tenant_model_version
        unique (tenant_id, model_id, artifact_version)
);

alter table public.ai_native_model_artifact
    owner to contexa;

create index idx_ai_native_model_artifact_tenant_updated
    on public.ai_native_model_artifact (tenant_id, updated_at);

create table public.ai_native_runtime_manifest
(
    id                  bigint generated by default as identity
        primary key,
    artifacts_json      varchar(16000),
    created_at          timestamp(6) not null,
    layer1_model        varchar(256),
    layer2_model        varchar(256),
    layers_json         varchar(8000),
    manifest_facts_json varchar(8000),
    manifest_state      varchar(64)  not null,
    manifest_version    varchar(128) not null,
    tenant_id           varchar(128) not null,
    updated_at          timestamp(6) not null,
    constraint idx_ai_native_runtime_manifest_tenant_version
        unique (tenant_id, manifest_version)
);

alter table public.ai_native_runtime_manifest
    owner to contexa;

create index idx_ai_native_runtime_manifest_tenant_updated
    on public.ai_native_runtime_manifest (tenant_id, updated_at);

create table public.ai_native_tevv_execution
(
    id                   bigint generated by default as identity
        primary key,
    canary_ready_count   bigint       not null,
    executed_at          timestamp(6) not null,
    execution_id         varchar(64)  not null,
    execution_source     varchar(64)  not null,
    harness_state        varchar(64)  not null,
    mixed_shift_count    bigint       not null,
    positive_shift_count bigint       not null,
    scenario_count       bigint       not null,
    shadow_ready_count   bigint       not null,
    suite_facts_json     varchar(8000),
    suite_key            varchar(128) not null,
    suite_state          varchar(64)  not null,
    suite_type           varchar(128) not null,
    tenant_id            varchar(128) not null
);

alter table public.ai_native_tevv_execution
    owner to contexa;

create index idx_ai_native_tevv_execution_tenant_time
    on public.ai_native_tevv_execution (tenant_id, executed_at);

create index idx_ai_native_tevv_execution_exec_suite
    on public.ai_native_tevv_execution (execution_id, suite_key);

create table public.baseline_signal_ingestion_records
(
    id                                 bigint generated by default as identity
        primary key,
    access_days_distribution_json      text,
    access_hours_distribution_json     text,
    average_risk_score                 double precision,
    average_trust_score                double precision,
    client_id                          varchar(160) not null,
    escalation_rate                    double precision,
    generated_at                       timestamp(6),
    industry_category                  varchar(120) not null,
    metadata_json                      text,
    operating_system_distribution_json text,
    organization_baseline_count        bigint       not null,
    period_start                       date         not null,
    received_at                        timestamp(6) not null,
    region                             varchar(80)  not null,
    signal_id                          varchar(80)  not null,
    status                             varchar(40)  not null,
    tenant_id                          varchar(120) not null,
    updated_at                         timestamp(6) not null,
    user_baseline_count                bigint       not null,
    constraint idx_baseline_signal_tenant_period
        unique (tenant_id, period_start)
);

alter table public.baseline_signal_ingestion_records
    owner to contexa;

create index idx_baseline_signal_cohort_received
    on public.baseline_signal_ingestion_records (industry_category, region, received_at);

create index idx_baseline_signal_tenant_received
    on public.baseline_signal_ingestion_records (tenant_id, received_at);

create table public.delegated_execution_graph_records
(
    id                             bigint generated by default as identity
        primary key,
    actor_user_id                  varchar(160),
    agent_id                       varchar(160),
    agent_runtime_id               varchar(160),
    allowed_operations_json        text,
    allowed_resource_families_json text,
    allowed_tool_chain_json        text,
    approval_id                    varchar(160),
    approved_scopes_json           text,
    capability                     varchar(160),
    client_id                      varchar(160) not null,
    containment_only               boolean      not null,
    created_at                     timestamp(6) not null,
    delegation_id                  varchar(160),
    execution_fingerprint          varchar(160) not null,
    execution_id                   varchar(160),
    execution_key                  varchar(160) not null,
    execution_mode                 varchar(80)  not null,
    expires_at                     timestamp(6),
    http_method                    varchar(32),
    last_observed_at               timestamp(6) not null,
    lineage_state                  varchar(80)  not null,
    objective_family               varchar(160),
    objective_id                   varchar(200),
    operation_name                 varchar(160),
    parent_execution_id            varchar(160),
    permit_id                      varchar(160),
    privileged_export_allowed      boolean      not null,
    request_fingerprint            varchar(160),
    requested_scopes_json          text,
    resource_fingerprint           varchar(160),
    service_client_principal       boolean      not null,
    source_path                    varchar(500),
    started_at                     timestamp(6),
    task_intent                    varchar(200),
    task_purpose                   varchar(240),
    tenant_id                      varchar(120) not null,
    tool_chain_json                text,
    updated_at                     timestamp(6) not null,
    constraint idx_delegated_execution_tenant_key
        unique (tenant_id, execution_key)
);

alter table public.delegated_execution_graph_records
    owner to contexa;

create index idx_delegated_execution_tenant_observed
    on public.delegated_execution_graph_records (tenant_id, last_observed_at);

create index idx_delegated_execution_tenant_actor
    on public.delegated_execution_graph_records (tenant_id, actor_user_id);

create table public.delegated_execution_step_records
(
    id                     bigint generated by default as identity
        primary key,
    authorization_decision varchar(120),
    created_at             timestamp(6) not null,
    execution_id           varchar(160) not null,
    execution_key          varchar(160) not null,
    observed_at            timestamp(6) not null,
    provenance_json        text,
    purpose_match          boolean,
    resource_fingerprint   varchar(160),
    resource_type          varchar(120),
    step_key               varchar(160) not null,
    step_type              varchar(120) not null,
    tenant_id              varchar(120) not null,
    tool_name              varchar(160),
    updated_at             timestamp(6) not null,
    constraint idx_delegated_execution_step_tenant_key
        unique (tenant_id, execution_id, step_key)
);

alter table public.delegated_execution_step_records
    owner to contexa;

create index idx_delegated_execution_step_tenant_execution
    on public.delegated_execution_step_records (tenant_id, execution_id, observed_at);

create table public.feedback_ingestion_records
(
    id                 bigint generated by default as identity
        primary key,
    admin_action       varchar(80)  not null,
    ai_analysis_level  integer,
    attributes_json    text,
    client_id          varchar(160) not null,
    correlation_id     varchar(160) not null,
    feedback_id        varchar(64)  not null,
    feedback_timestamp timestamp(6),
    feedback_type      varchar(64)  not null,
    hashed_user_id     varchar(160),
    metadata_json      text,
    original_action    varchar(80),
    overridden_action  varchar(80),
    received_at        timestamp(6) not null,
    status             varchar(40)  not null,
    tenant_id          varchar(120) not null,
    updated_at         timestamp(6) not null,
    constraint idx_feedback_ingestion_tenant_feedback
        unique (tenant_id, feedback_id)
);

alter table public.feedback_ingestion_records
    owner to contexa;

create index idx_feedback_ingestion_tenant_received
    on public.feedback_ingestion_records (tenant_id, received_at);

create index idx_feedback_ingestion_tenant_correlation
    on public.feedback_ingestion_records (tenant_id, correlation_id);

create table public.global_threat_signals
(
    id                      bigint generated by default as identity
        primary key,
    application_mode        varchar(80),
    campaign_confidence     double precision,
    canonical_threat_class  varchar(160) not null,
    confidence_band         varchar(40),
    created_at              timestamp(6) not null,
    expires_at              timestamp(6),
    first_observed_at       timestamp(6),
    geo_country             varchar(80)  not null,
    global_source_key       varchar(160) not null,
    last_observed_at        timestamp(6),
    mitre_tactic_hints      text,
    observation_count       integer      not null,
    promoted_at             timestamp(6),
    recommended_action      varchar(1000),
    recommended_risk_weight double precision,
    signal_key              varchar(255) not null
        constraint idx_global_threat_signal_key
            unique,
    signal_tags             text,
    status                  varchar(40)  not null,
    summary                 varchar(1000),
    target_surface_hints    text,
    tenant_count            integer      not null,
    updated_at              timestamp(6) not null
);

alter table public.global_threat_signals
    owner to contexa;

create index idx_global_threat_signal_status_seen
    on public.global_threat_signals (status, last_observed_at);

create table public.knowledge_artifact_access_override
(
    id              bigint generated by default as identity
        primary key,
    access_state    varchar(64)  not null,
    actor_name      varchar(128),
    artifact_family varchar(64)  not null,
    created_at      timestamp(6) not null,
    expires_at      timestamp(6),
    reason_text     varchar(1000),
    tenant_id       varchar(128) not null,
    updated_at      timestamp(6) not null,
    constraint idx_knowledge_artifact_access_override_tenant_family
        unique (tenant_id, artifact_family)
);

alter table public.knowledge_artifact_access_override
    owner to contexa;

create table public.knowledge_artifact_registry
(
    id               bigint generated by default as identity
        primary key,
    approved_by      varchar(128),
    artifact_family  varchar(64)  not null,
    artifact_id      varchar(256),
    artifact_key     varchar(256) not null,
    artifact_type    varchar(128),
    artifact_version varchar(128),
    cohort_scope     varchar(128),
    created_at       timestamp(6) not null,
    lineage_json     varchar(8000),
    owner_name       varchar(128),
    promotion_state  varchar(64),
    quarantined      boolean      not null,
    runtime_ready    boolean      not null,
    tenant_id        varchar(128) not null,
    tenant_scope     varchar(128),
    updated_at       timestamp(6) not null,
    constraint idx_knowledge_artifact_registry_identity
        unique (tenant_id, artifact_family, artifact_key, artifact_version)
);

alter table public.knowledge_artifact_registry
    owner to contexa;

create index idx_knowledge_artifact_registry_current
    on public.knowledge_artifact_registry (tenant_id, artifact_family, artifact_key, updated_at);

create index idx_knowledge_artifact_registry_family
    on public.knowledge_artifact_registry (tenant_id, artifact_family, updated_at);

create table public.model_performance_telemetry_records
(
    id                            bigint generated by default as identity
        primary key,
    block_count                   bigint           not null,
    block_rate                    double precision not null,
    challenge_count               bigint           not null,
    challenge_rate                double precision not null,
    client_id                     varchar(160)     not null,
    escalate_protection_triggered integer          not null,
    generated_at                  timestamp(6),
    layer1_avg_confidence         double precision not null,
    layer1_avg_processing_ms      bigint           not null,
    layer1_escalation_count       bigint           not null,
    layer1_escalation_rate        double precision not null,
    layer1_sample_count           bigint           not null,
    layer2_avg_confidence         double precision not null,
    layer2_avg_processing_ms      bigint           not null,
    layer2_sample_count           bigint           not null,
    metadata_json                 text,
    period                        date             not null,
    received_at                   timestamp(6)     not null,
    status                        varchar(40)      not null,
    telemetry_id                  varchar(64)      not null,
    tenant_id                     varchar(120)     not null,
    total_event_count             bigint           not null,
    updated_at                    timestamp(6)     not null,
    constraint uk_model_performance_telemetry_tenant_period
        unique (tenant_id, period)
);

alter table public.model_performance_telemetry_records
    owner to contexa;

create index idx_model_performance_telemetry_tenant_received
    on public.model_performance_telemetry_records (tenant_id, received_at);

create table public.prompt_context_audit
(
    id                        bigint generated by default as identity
        primary key,
    access_scope              varchar(64),
    allowed_document_count    integer      not null,
    artifact_id               varchar(256),
    artifact_version          varchar(128),
    audit_id                  varchar(64)  not null,
    authorization_decision    varchar(128),
    client_id                 varchar(128) not null,
    context_type              varchar(128),
    correlation_id            varchar(64)  not null,
    created_at                timestamp(6) not null,
    denied_document_count     integer      not null,
    denied_reasons            varchar(2000),
    execution_id              varchar(64),
    included_in_prompt        boolean      not null,
    memory_read_decision      varchar(128),
    prompt_safety_decision    varchar(128),
    provenance_summary        varchar(1000),
    purpose_match             boolean      not null,
    requested_document_count  integer      not null,
    retrieval_purpose         varchar(128) not null,
    similarity_score          double precision,
    source_type               varchar(128),
    tenant_bound              boolean      not null,
    tenant_id                 varchar(128) not null,
    artifact_family           varchar(128),
    artifact_governance_state varchar(64),
    artifact_lineage_state    varchar(64),
    quarantined_artifact      boolean,
    runtime_allowed           boolean,
    runtime_ready_artifact    boolean,
    tenant_access_state       varchar(64),
    tenant_policy_decision    varchar(64)
);

alter table public.prompt_context_audit
    owner to contexa;

create index idx_prompt_context_audit_tenant_corr
    on public.prompt_context_audit (tenant_id, correlation_id, created_at);

create index idx_prompt_context_audit_audit_id
    on public.prompt_context_audit (audit_id);

create table public.security_decision_fact_records
(
    id             bigint generated by default as identity
        primary key,
    correlation_id varchar(160) not null,
    created_at     timestamp(6) not null,
    fact_key       varchar(160) not null,
    fact_source    varchar(80)  not null,
    fact_type      varchar(40)  not null,
    fact_value     varchar(1000),
    importance     varchar(40)  not null,
    position       integer      not null,
    tenant_id      varchar(120) not null
);

alter table public.security_decision_fact_records
    owner to contexa;

create index idx_xai_fact_tenant_correlation_position
    on public.security_decision_fact_records (tenant_id, correlation_id, position);

create table public.security_decision_ingestion_records
(
    id                     bigint generated by default as identity
        primary key,
    canonical_threat_class varchar(160),
    client_id              varchar(160) not null,
    correlation_id         varchar(160) not null,
    decision               varchar(80),
    event_source           varchar(200),
    event_timestamp        timestamp(6),
    fact_count             integer      not null,
    global_source_key      varchar(160),
    hashed_session_id      varchar(160),
    hashed_source_ip       varchar(160),
    hashed_user_id         varchar(160),
    last_error             varchar(1000),
    metadata_json          text,
    payload_json           text,
    processed_at           timestamp(6),
    received_at            timestamp(6) not null,
    report_generated_at    timestamp(6),
    request_path           varchar(500),
    severity_level         varchar(80),
    status                 varchar(40)  not null,
    tenant_id              varchar(120) not null,
    threat_category        varchar(120),
    updated_at             timestamp(6) not null,
    constraint idx_xai_ingestion_tenant_correlation
        unique (tenant_id, correlation_id)
);

alter table public.security_decision_ingestion_records
    owner to contexa;

create index idx_xai_ingestion_tenant_received
    on public.security_decision_ingestion_records (tenant_id, received_at);

create table public.tenant_webhook_endpoints
(
    id                        bigint generated by default as identity
        primary key,
    created_at                timestamp(6) not null,
    endpoint_type             varchar(80)  not null,
    last_delivered_at         timestamp(6),
    last_delivery_error       varchar(1000),
    last_delivery_http_status integer,
    last_delivery_status      varchar(80),
    last_rotated_at           timestamp(6),
    metadata_json             text,
    secret_cipher_text        varchar(4000),
    secret_masked_hint        varchar(120),
    signature_algorithm       varchar(120),
    status                    varchar(40)  not null,
    tenant_id                 varchar(120) not null,
    updated_at                timestamp(6) not null,
    url                       varchar(1000),
    constraint idx_tenant_webhook_endpoint_lookup
        unique (tenant_id, endpoint_type)
);

alter table public.tenant_webhook_endpoints
    owner to contexa;

create index idx_tenant_webhook_endpoint_status
    on public.tenant_webhook_endpoints (status, updated_at);

create table public.threat_campaign_observations
(
    id                      bigint generated by default as identity
        primary key,
    canonical_threat_class  varchar(160) not null,
    client_id               varchar(160) not null,
    confidence              double precision,
    correlation_id          varchar(160) not null,
    decision                varchar(80)  not null,
    event_timestamp         timestamp(6),
    geo_country             varchar(80)  not null,
    global_source_key       varchar(160) not null,
    mitre_tactic_hints      text,
    observed_at             timestamp(6) not null,
    raw_threat_category     varchar(160),
    risk_score              double precision,
    signal_tags             text,
    target_surface_category varchar(120),
    tenant_id               varchar(120) not null,
    constraint idx_threat_obs_tenant_correlation
        unique (tenant_id, correlation_id)
);

alter table public.threat_campaign_observations
    owner to contexa;

create index idx_threat_obs_signal_window
    on public.threat_campaign_observations (global_source_key, canonical_threat_class, geo_country, observed_at);

create table public.threat_knowledge_artifact_releases
(
    id               bigint generated by default as identity
        primary key,
    actor            varchar(160) not null,
    artifact_version varchar(160) not null,
    created_at       timestamp(6) not null,
    governance_state varchar(60),
    reason           varchar(1000),
    release_action   varchar(40)  not null,
    rollback_state   varchar(60),
    runtime_eligible boolean      not null,
    signal_key       varchar(255) not null,
    tenant_id        varchar(120) not null,
    tevv_state       varchar(60)
);

alter table public.threat_knowledge_artifact_releases
    owner to contexa;

create index idx_threat_artifact_release_tenant_created
    on public.threat_knowledge_artifact_releases (tenant_id, created_at);

create index idx_threat_artifact_release_tenant_signal_created
    on public.threat_knowledge_artifact_releases (tenant_id, signal_key, created_at);

create table public.threat_knowledge_promotion_reviews
(
    id                  bigint generated by default as identity
        primary key,
    artifact_version    varchar(160) not null,
    created_at          timestamp(6) not null,
    governance_state    varchar(60),
    rationale           varchar(1000),
    requested_by        varchar(160) not null,
    review_decision     varchar(40)  not null,
    review_eligible     boolean      not null,
    review_window_end   timestamp(6),
    review_window_start timestamp(6),
    reviewed_by         varchar(160) not null,
    rollback_linkage    varchar(255),
    rollback_state      varchar(60),
    signal_key          varchar(255) not null,
    tenant_id           varchar(120) not null,
    tevv_state          varchar(60)
);

alter table public.threat_knowledge_promotion_reviews
    owner to contexa;

create index idx_threat_promotion_review_tenant_created
    on public.threat_knowledge_promotion_reviews (tenant_id, created_at);

create index idx_threat_promotion_review_tenant_signal_created
    on public.threat_knowledge_promotion_reviews (tenant_id, signal_key, created_at);

create table public.threat_knowledge_runtime_overrides
(
    id              bigint generated by default as identity
        primary key,
    active          boolean      not null,
    actor           varchar(160) not null,
    created_at      timestamp(6) not null,
    expires_at      timestamp(6),
    override_action varchar(40)  not null,
    override_scope  varchar(40)  not null,
    reason          varchar(1000),
    signal_key      varchar(255),
    tenant_id       varchar(120) not null,
    updated_at      timestamp(6) not null
);

alter table public.threat_knowledge_runtime_overrides
    owner to contexa;

create index idx_threat_runtime_override_tenant_active
    on public.threat_knowledge_runtime_overrides (tenant_id, active);

create index idx_threat_runtime_override_tenant_signal_active
    on public.threat_knowledge_runtime_overrides (tenant_id, signal_key, active);

create table public.threat_outcome_records
(
    id                bigint generated by default as identity
        primary key,
    attributes_json   text,
    client_id         varchar(160) not null,
    correlation_id    varchar(160) not null,
    final_action      varchar(80),
    final_disposition varchar(64)  not null,
    hashed_user_id    varchar(160),
    metadata_json     text,
    original_action   varchar(80),
    outcome_id        varchar(64)  not null,
    outcome_timestamp timestamp(6),
    outcome_type      varchar(64)  not null,
    received_at       timestamp(6) not null,
    resolution_source varchar(80)  not null,
    status            varchar(40)  not null,
    summary           varchar(1000),
    tenant_id         varchar(120) not null,
    updated_at        timestamp(6) not null,
    constraint idx_threat_outcome_tenant_outcome
        unique (tenant_id, outcome_id)
);

alter table public.threat_outcome_records
    owner to contexa;

create index idx_threat_outcome_tenant_correlation
    on public.threat_outcome_records (tenant_id, correlation_id, received_at);

create index idx_threat_outcome_tenant_received
    on public.threat_outcome_records (tenant_id, received_at);

create table public.xai_analysis_reports
(
    id                        bigint generated by default as identity
        primary key,
    correlation_id            varchar(160) not null,
    counterfactual            varchar(1000),
    decision                  varchar(80),
    delivered_at              timestamp(6),
    delivery_attempt_count    integer      not null,
    delivery_endpoint_id      bigint,
    delivery_skipped_reason   varchar(500),
    delivery_status           varchar(40),
    event_timestamp           timestamp(6),
    generated_at              timestamp(6) not null,
    ingestion_record_id       bigint       not null,
    last_delivery_attempt_at  timestamp(6),
    last_delivery_error       varchar(1000),
    last_delivery_http_status integer,
    next_delivery_attempt_at  timestamp(6),
    rationale                 varchar(4000),
    recommended_action        varchar(1000),
    report_json               text,
    risk_factors              text,
    severity_level            varchar(80),
    status                    varchar(40)  not null,
    summary                   varchar(1000),
    tenant_id                 varchar(120) not null,
    threat_category           varchar(120),
    updated_at                timestamp(6) not null,
    constraint idx_xai_report_tenant_correlation
        unique (tenant_id, correlation_id)
);

alter table public.xai_analysis_reports
    owner to contexa;

create index idx_xai_report_tenant_generated
    on public.xai_analysis_reports (tenant_id, generated_at);

create index idx_xai_report_delivery_due
    on public.xai_analysis_reports (delivery_status, next_delivery_attempt_at);

create table public.prompt_governance_budget_profile
(
    id                             bigint generated by default as identity
        primary key,
    budget_profile_key             varchar(128) not null,
    budget_state                   varchar(128) not null,
    cache_policy_key               varchar(256) not null,
    cache_policy_state             varchar(128) not null,
    compaction_policy_key          varchar(256) not null,
    compaction_policy_state        varchar(128) not null,
    created_at                     timestamp(6) not null,
    expansion_allowed              boolean      not null,
    max_input_tokens               integer      not null,
    output_reserve_tokens          integer      not null,
    prompt_key                     varchar(128) not null,
    prompt_version                 varchar(128) not null,
    registration_source            varchar(128) not null,
    registry_scope                 varchar(128) not null,
    required_context_window_tokens integer      not null,
    system_reserve_tokens          integer      not null,
    token_counting_policy_key      varchar(256) not null,
    updated_at                     timestamp(6) not null,
    user_reserve_tokens            integer      not null,
    constraint idx_prompt_budget_profile_identity
        unique (registry_scope, prompt_key, prompt_version, budget_profile_key)
);

alter table public.prompt_governance_budget_profile
    owner to contexa;

create index idx_prompt_budget_profile_current
    on public.prompt_governance_budget_profile (registry_scope, prompt_key, updated_at);

create table public.prompt_governance_change_ledger
(
    id                  bigint generated by default as identity
        primary key,
    change_reference    varchar(256)  not null,
    change_state        varchar(64)   not null,
    change_summary      varchar(2000) not null,
    change_type         varchar(64)   not null,
    changed_by          varchar(128)  not null,
    contract_version    varchar(128)  not null,
    created_at          timestamp(6)  not null,
    prompt_key          varchar(128)  not null,
    prompt_version      varchar(128)  not null,
    registration_source varchar(128)  not null,
    registry_scope      varchar(128)  not null,
    updated_at          timestamp(6)  not null,
    constraint idx_prompt_governance_change_identity
        unique (registry_scope, prompt_key, prompt_version)
);

alter table public.prompt_governance_change_ledger
    owner to contexa;

create index idx_prompt_governance_change_current
    on public.prompt_governance_change_ledger (registry_scope, prompt_key, updated_at);

create table public.prompt_governance_eval_ledger
(
    id                             bigint generated by default as identity
        primary key,
    cost_gate_state                varchar(64)   not null,
    covered_scenario_count         integer       not null,
    covered_scenario_families_json varchar(4000),
    created_at                     timestamp(6)  not null,
    empirical_evidence_state       varchar(64)   not null,
    evaluated_by                   varchar(128)  not null,
    evaluation_mode                varchar(64)   not null,
    evaluation_reference           varchar(256)  not null,
    evaluation_state               varchar(64)   not null,
    evaluation_summary             varchar(2000) not null,
    latency_gate_state             varchar(64)   not null,
    prompt_injection_state         varchar(64)   not null,
    prompt_key                     varchar(128)  not null,
    prompt_version                 varchar(128)  not null,
    quality_gate_state             varchar(64)   not null,
    registration_source            varchar(128)  not null,
    registry_scope                 varchar(128)  not null,
    required_scenario_count        integer       not null,
    scenario_coverage_state        varchar(64)   not null,
    tevv_gate_state                varchar(64)   not null,
    updated_at                     timestamp(6)  not null,
    constraint idx_prompt_governance_eval_identity
        unique (registry_scope, prompt_key, prompt_version)
);

alter table public.prompt_governance_eval_ledger
    owner to contexa;

create index idx_prompt_governance_eval_current
    on public.prompt_governance_eval_ledger (registry_scope, prompt_key, updated_at);

create table public.prompt_governance_model_compatibility
(
    id                        bigint generated by default as identity
        primary key,
    cache_policy_key          varchar(256) not null,
    compaction_policy_key     varchar(256) not null,
    compatibility_state       varchar(128) not null,
    created_at                timestamp(6) not null,
    model_profile_key         varchar(256) not null,
    profile_category          varchar(128) not null,
    prompt_key                varchar(128) not null,
    prompt_version            varchar(128) not null,
    provider_scope            varchar(256) not null,
    registration_source       varchar(128) not null,
    registry_scope            varchar(128) not null,
    token_counting_policy_key varchar(256) not null,
    updated_at                timestamp(6) not null,
    constraint idx_prompt_model_compatibility_identity
        unique (registry_scope, prompt_key, prompt_version, model_profile_key)
);

alter table public.prompt_governance_model_compatibility
    owner to contexa;

create index idx_prompt_model_compatibility_current
    on public.prompt_governance_model_compatibility (registry_scope, prompt_key, updated_at);

create table public.prompt_governance_registry
(
    id                            bigint generated by default as identity
        primary key,
    change_summary                varchar(2000),
    contract_version              varchar(128) not null,
    created_at                    timestamp(6) not null,
    evaluation_baseline_reference varchar(256),
    owner_name                    varchar(128) not null,
    prompt_artifact_hash_sha256   varchar(64)  not null,
    prompt_key                    varchar(128) not null,
    prompt_version                varchar(128) not null,
    registration_source           varchar(128) not null,
    registry_scope                varchar(128) not null,
    release_approval_reference    varchar(256),
    release_status                varchar(64)  not null,
    rollback_prompt_version       varchar(128),
    supported_model_profiles_json varchar(8000),
    template_class_name           varchar(512) not null,
    template_key                  varchar(128) not null,
    updated_at                    timestamp(6) not null,
    constraint idx_prompt_governance_registry_identity
        unique (registry_scope, prompt_key, prompt_version)
);

alter table public.prompt_governance_registry
    owner to contexa;

create index idx_prompt_governance_registry_current
    on public.prompt_governance_registry (registry_scope, prompt_key, updated_at);

create index idx_prompt_governance_registry_release
    on public.prompt_governance_registry (registry_scope, release_status, updated_at);

create table public.prompt_governance_release_ledger
(
    id                         bigint generated by default as identity
        primary key,
    approval_channel           varchar(64)   not null,
    approval_state             varchar(64)   not null,
    approval_summary           varchar(2000) not null,
    approved_by                varchar(128)  not null,
    created_at                 timestamp(6)  not null,
    prompt_key                 varchar(128)  not null,
    prompt_version             varchar(128)  not null,
    registration_source        varchar(128)  not null,
    registry_scope             varchar(128)  not null,
    release_approval_reference varchar(256)  not null,
    release_status             varchar(64)   not null,
    updated_at                 timestamp(6)  not null,
    constraint idx_prompt_governance_release_identity
        unique (registry_scope, prompt_key, prompt_version)
);

alter table public.prompt_governance_release_ledger
    owner to contexa;

create index idx_prompt_governance_release_current
    on public.prompt_governance_release_ledger (registry_scope, prompt_key, updated_at);

create table public.prompt_governance_release_workflow
(
    id                     bigint generated by default as identity
        primary key,
    actor_name             varchar(128)  not null,
    approval_channel       varchar(128)  not null,
    blockers_json          varchar(8000),
    created_at             timestamp(6)  not null,
    current_release_status varchar(64)   not null,
    gate_state             varchar(64)   not null,
    prompt_key             varchar(128)  not null,
    prompt_version         varchar(128)  not null,
    rationale              varchar(2000) not null,
    registry_scope         varchar(128)  not null,
    target_release_status  varchar(64)   not null,
    workflow_state         varchar(64)   not null
);

alter table public.prompt_governance_release_workflow
    owner to contexa;

create index idx_prompt_release_workflow_scope_created
    on public.prompt_governance_release_workflow (registry_scope, created_at);

create index idx_prompt_release_workflow_prompt_created
    on public.prompt_governance_release_workflow (registry_scope, prompt_key, created_at);

create table public.prompt_governance_rollback_ledger
(
    id                             bigint generated by default as identity
        primary key,
    created_at                     timestamp(6)  not null,
    prepared_by                    varchar(128)  not null,
    prompt_key                     varchar(128)  not null,
    prompt_version                 varchar(128)  not null,
    registration_source            varchar(128)  not null,
    registry_scope                 varchar(128)  not null,
    rollback_readiness_state       varchar(64)   not null,
    rollback_reason                varchar(2000) not null,
    rollback_reference             varchar(256)  not null,
    rollback_state                 varchar(64)   not null,
    rollback_strategy              varchar(64)   not null,
    rollback_target_prompt_version varchar(128)  not null,
    updated_at                     timestamp(6)  not null,
    constraint idx_prompt_governance_rollback_identity
        unique (registry_scope, prompt_key, prompt_version)
);

alter table public.prompt_governance_rollback_ledger
    owner to contexa;

create index idx_prompt_governance_rollback_current
    on public.prompt_governance_rollback_ledger (registry_scope, prompt_key, updated_at);

create table public.document
(
    document_id    bigint generated by default as identity
        primary key,
    content        text,
    created_at     timestamp(6) not null,
    owner_username varchar(255) not null,
    title          varchar(255) not null,
    updated_at     timestamp(6)
);

alter table public.document
    owner to contexa;

create table public.continuous_verification_result
(
    id                          bigint generated by default as identity
        primary key,
    created_at                  timestamp(6) with time zone,
    deterministic_replay_passed boolean                     not null,
    metric_scores_json          text,
    overall_passed              boolean                     not null,
    package_id                  varchar(256)                not null,
    result_id                   varchar(64)                 not null
        constraint ukq53rbkd9uwdi72cha1cnu2okt
            unique,
    tenant_id                   varchar(120),
    verification_mode           varchar(40),
    verified_at                 timestamp(6) with time zone not null
);

alter table public.continuous_verification_result
    owner to contexa;

create index idx_cvr_tenant_verified_at
    on public.continuous_verification_result (tenant_id, verified_at);

create index idx_cvr_package_id
    on public.continuous_verification_result (package_id);

create table public.sealed_evidence_package
(
    id                              bigint generated by default as identity
        primary key,
    auth_state_json                 text,
    baseline_snapshot_json          text,
    canonical_context_json          text,
    captured_at                     timestamp(6) with time zone not null,
    correlation_id                  varchar(160)                not null
        constraint idx_sep_correlation_id
            unique,
    created_at                      timestamp(6) with time zone,
    decision_json                   text,
    expires_at                      timestamp(6) with time zone,
    package_hash                    varchar(128)                not null,
    package_id                      varchar(256)                not null
        constraint ukcxv5wdh68sayg5db05njfv2te
            unique,
    prompt_execution_metadata_json  text,
    prompt_hash                     varchar(128),
    rag_results_json                text,
    raw_system_prompt               text,
    raw_user_prompt                 text,
    request_facts_json              text,
    schema_version                  integer                     not null,
    sealed                          boolean                     not null,
    system_prompt_text              text,
    tenant_id                       varchar(120),
    user_id                         varchar(160),
    user_prompt_text                text,
    request_facts_jsonb             jsonb,
    auth_state_jsonb                jsonb,
    canonical_context_jsonb         jsonb,
    baseline_snapshot_jsonb         jsonb,
    rag_results_jsonb               jsonb,
    prompt_execution_metadata_jsonb jsonb,
    decision_jsonb                  jsonb
);

alter table public.sealed_evidence_package
    owner to contexa;

create index idx_sep_user_id_captured_at
    on public.sealed_evidence_package (user_id, captured_at);

create index idx_sep_tenant_id_captured_at
    on public.sealed_evidence_package (tenant_id, captured_at);

create index idx_sep_captured_at
    on public.sealed_evidence_package (captured_at);

create index idx_sep_request_facts_jsonb
    on public.sealed_evidence_package using gin (request_facts_jsonb);

create index idx_sep_canonical_context_jsonb
    on public.sealed_evidence_package using gin (canonical_context_jsonb);

create index idx_sep_baseline_snapshot_jsonb
    on public.sealed_evidence_package using gin (baseline_snapshot_jsonb);

create index idx_sep_rag_results_jsonb
    on public.sealed_evidence_package using gin (rag_results_jsonb);

create index idx_sep_prompt_execution_metadata_jsonb
    on public.sealed_evidence_package using gin (prompt_execution_metadata_jsonb);

create unique index idx_sep_package_id
    on public.sealed_evidence_package (package_id);

create table public.official_verification_runtime_model_catalog
(
    id                 bigint generated by default as identity
        primary key,
    comparison_enabled boolean      not null,
    created_at         timestamp(6) not null,
    display_name       varchar(128),
    display_order      integer      not null,
    enabled            boolean      not null,
    metric_scope       varchar(64)  not null,
    model_id           varchar(128) not null,
    profile_code       varchar(64)  not null,
    provider           varchar(64),
    recommended        boolean      not null,
    updated_at         timestamp(6) not null,
    constraint idx_official_verification_runtime_model_identity
        unique (metric_scope, profile_code, model_id)
);

alter table public.official_verification_runtime_model_catalog
    owner to contexa;

create index idx_official_verification_runtime_model_metric_profile
    on public.official_verification_runtime_model_catalog (metric_scope, profile_code, enabled, display_order);

create table public.active_sessions
(
    expired          boolean      not null,
    created_at       timestamp(6) not null,
    last_accessed_at timestamp(6),
    client_ip        varchar(45),
    session_id       varchar(128) not null
        primary key,
    user_agent       varchar(512),
    user_id          varchar(255) not null,
    username         varchar(255)
);

alter table public.active_sessions
    owner to contexa;

create index idx_session_user_id
    on public.active_sessions (user_id);

create index idx_session_expired
    on public.active_sessions (expired);

create table public.admin_menu
(
    enabled    boolean      not null,
    menu_order integer      not null,
    id         bigint generated by default as identity
        primary key,
    parent_id  bigint,
    menu_type  varchar(20)  not null,
    data_page  varchar(50),
    name       varchar(100) not null,
    icon       varchar(2000),
    url        varchar(255)
);

alter table public.admin_menu
    owner to contexa;

create table public.admin_menu_role
(
    id        bigint generated by default as identity
        primary key,
    menu_id   bigint       not null
        constraint fkqjfrxelcunj2g0dps0fo5fdy2
            references public.admin_menu,
    role_name varchar(100) not null,
    unique (menu_id, role_name),
    constraint ukpcleae1qljlet1mpd77yt63or
        unique (menu_id, role_name)
);

alter table public.admin_menu_role
    owner to contexa;

create table public.app_group
(
    enabled     boolean      not null,
    created_at  timestamp(6) not null,
    group_id    bigint generated by default as identity
        primary key,
    updated_at  timestamp(6),
    created_by  varchar(100),
    group_name  varchar(100) not null
        unique,
    description varchar(500)
);

alter table public.app_group
    owner to contexa;

create table public.approval_notifications
(
    action_required   boolean      not null,
    is_read           boolean      not null,
    created_at        timestamp(6) not null,
    expires_at        timestamp(6),
    id                bigint generated by default as identity
        primary key,
    read_at           timestamp(6),
    updated_at        timestamp(6) not null,
    priority          varchar(20),
    notification_type varchar(50)  not null,
    target_role       varchar(50),
    group_id          varchar(100),
    read_by           varchar(100),
    request_id        varchar(100) not null,
    user_id           varchar(100),
    action_url        varchar(500),
    message           text,
    notification_data text,
    title             varchar(255) not null
);

alter table public.approval_notifications
    owner to contexa;

create index idx_notification_request_id
    on public.approval_notifications (request_id);

create index idx_notification_user_id
    on public.approval_notifications (user_id);

create index idx_notification_is_read
    on public.approval_notifications (is_read);

create index idx_notification_created_at
    on public.approval_notifications (created_at);

create table public.audit_log
(
    risk_score          double precision,
    id                  bigint generated by default as identity
        primary key,
    timestamp           timestamp(6) not null,
    http_method         varchar(10),
    client_ip           varchar(45),
    decision            varchar(50)  not null,
    event_category      varchar(50),
    event_source        varchar(50),
    outcome             varchar(50),
    correlation_id      varchar(64),
    action              varchar(100),
    session_id          varchar(128),
    resource_identifier varchar(512) not null,
    user_agent          varchar(512),
    reason              varchar(1024),
    resource_uri        varchar(1024),
    request_uri         varchar(2048),
    details             text,
    principal_name      varchar(255) not null
);

alter table public.audit_log
    owner to contexa;

create table public.baseline_signal_outbox
(
    attempt_count                      integer      not null,
    period_start                       date         not null
        constraint uk_baseline_signal_outbox_period
            unique,
    created_at                         timestamp(6) not null,
    delivered_at                       timestamp(6),
    generated_at                       timestamp(6),
    id                                 bigint generated by default as identity
        primary key,
    next_attempt_at                    timestamp(6),
    organization_baseline_count        bigint       not null,
    updated_at                         timestamp(6) not null,
    user_baseline_count                bigint       not null,
    status                             varchar(32)  not null,
    signal_id                          varchar(64)  not null,
    industry_category                  varchar(80),
    last_error                         varchar(2000),
    access_days_distribution_json      text,
    access_hours_distribution_json     text,
    operating_system_distribution_json text
);

alter table public.baseline_signal_outbox
    owner to contexa;

create index idx_baseline_signal_outbox_dispatch
    on public.baseline_signal_outbox (status, next_attempt_at, period_start);

create table public.blocked_user
(
    block_count          integer      not null,
    confidence           double precision,
    mfa_verified         boolean,
    risk_score           double precision,
    blocked_at           timestamp(6) not null,
    id                   bigint generated by default as identity
        primary key,
    mfa_verified_at      timestamp(6),
    resolved_at          timestamp(6),
    unblock_requested_at timestamp(6),
    reasoning            text,
    request_id           varchar(255) not null
        unique,
    resolve_reason       text,
    resolved_action      varchar(255),
    resolved_by          varchar(255),
    source_ip            varchar(255),
    status               varchar(255) not null
        constraint blocked_user_status_check
            check ((status)::text = ANY
                   ((ARRAY ['BLOCKED'::character varying, 'UNBLOCK_REQUESTED'::character varying, 'RESOLVED'::character varying, 'TIMEOUT_RESPONDED'::character varying, 'MFA_FAILED'::character varying])::text[])),
    unblock_reason       text,
    user_agent           varchar(255),
    user_id              varchar(255) not null,
    username             varchar(255)
);

alter table public.blocked_user
    owner to contexa;

create table public.business_action
(
    id          bigint generated by default as identity
        primary key,
    action_type varchar(100) not null,
    description varchar(1024),
    name        varchar(255) not null
        unique
);

alter table public.business_action
    owner to contexa;

create table public.business_resource
(
    id            bigint generated by default as identity
        primary key,
    resource_type varchar(100) not null,
    description   varchar(1024),
    name          varchar(255) not null
        unique
);

alter table public.business_resource
    owner to contexa;

create table public.business_resource_action
(
    business_action_id     bigint       not null
        constraint fkp8b681vlpc7vba0iv3ppsc6lv
            references public.business_action,
    business_resource_id   bigint       not null
        constraint fko0go31nvr2bbo3e77t7yyknnq
            references public.business_resource,
    mapped_permission_name varchar(255) not null,
    primary key (business_action_id, business_resource_id)
);

alter table public.business_resource_action
    owner to contexa;

create table public.condition_template
(
    approval_required    boolean,
    complexity_score     integer,
    context_dependent    boolean,
    is_auto_generated    boolean,
    is_universal         boolean,
    parameter_count      integer,
    created_at           timestamp(6),
    id                   bigint generated by default as identity
        primary key,
    updated_at           timestamp(6),
    description          varchar(1024),
    required_target_type varchar(1024),
    spel_template        varchar(2048) not null,
    category             varchar(255),
    classification       varchar(255)
        constraint condition_template_classification_check
            check ((classification)::text = ANY
                   ((ARRAY ['UNIVERSAL'::character varying, 'CONTEXT_DEPENDENT'::character varying, 'CUSTOM_COMPLEX'::character varying])::text[])),
    name                 varchar(255)  not null
        unique,
    source_method        varchar(255),
    template_type        varchar(255)
);

alter table public.condition_template
    owner to contexa;

create table public.decision_feedback_forwarding_outbox
(
    attempt_count       integer      not null,
    created_at          timestamp(6) not null,
    delivered_at        timestamp(6),
    id                  bigint generated by default as identity
        primary key,
    next_attempt_at     timestamp(6),
    updated_at          timestamp(6) not null,
    status              varchar(32)  not null,
    correlation_id      varchar(64)  not null,
    feedback_id         varchar(64)  not null
        constraint uk_decision_feedback_forwarding_outbox_feedback_id
            unique,
    tenant_external_ref varchar(128) not null,
    last_error          varchar(2000),
    payload_json        text         not null
);

alter table public.decision_feedback_forwarding_outbox
    owner to contexa;

create index idx_decision_feedback_forwarding_outbox_dispatch
    on public.decision_feedback_forwarding_outbox (status, next_attempt_at, created_at);

create table public.function_group
(
    id   bigint generated by default as identity
        primary key,
    name varchar(255) not null
        unique
);

alter table public.function_group
    owner to contexa;

create table public.ip_access_rules
(
    enabled     boolean      not null,
    created_at  timestamp(6) not null,
    expires_at  timestamp(6),
    id          bigint generated by default as identity
        primary key,
    rule_type   varchar(10)  not null
        constraint ip_access_rules_rule_type_check
            check ((rule_type)::text = ANY ((ARRAY ['ALLOW'::character varying, 'DENY'::character varying])::text[])),
    ip_address  varchar(45)  not null,
    description varchar(500),
    created_by  varchar(255)
);

alter table public.ip_access_rules
    owner to contexa;

create index idx_ip_rule_type
    on public.ip_access_rules (rule_type);

create index idx_ip_rule_enabled
    on public.ip_access_rules (enabled);

create index idx_ip_address
    on public.ip_access_rules (ip_address);

create table public.learning_artifact_registry
(
    kill_switch_active    boolean       not null,
    runtime_eligible      boolean       not null,
    runtime_suppressed    boolean       not null,
    created_at            timestamp(6)  not null,
    first_registered_at   timestamp(6)  not null,
    id                    bigint generated by default as identity
        primary key,
    last_ledger_at        timestamp(6)  not null,
    updated_at            timestamp(6)  not null,
    artifact_type         varchar(64)   not null,
    latest_event_type     varchar(64)   not null,
    release_state         varchar(64)   not null,
    rollback_target_state varchar(64),
    tenant_id             varchar(120)  not null,
    policy_state          varchar(128),
    actor                 varchar(160)  not null,
    artifact_version      varchar(160),
    canary_outcome        varchar(160),
    reason                varchar(2000) not null,
    artifact_key          varchar(255)  not null,
    facts_json            text,
    constraint uk_learning_artifact_registry_identity
        unique (tenant_id, artifact_type, artifact_key)
);

alter table public.learning_artifact_registry
    owner to contexa;

create index idx_learning_artifact_registry_tenant_updated
    on public.learning_artifact_registry (tenant_id, updated_at);

create index idx_learning_artifact_registry_artifact_updated
    on public.learning_artifact_registry (artifact_type, artifact_key, updated_at);

create table public.learning_artifact_release_ledger
(
    kill_switch_active    boolean       not null,
    created_at            timestamp(6)  not null,
    id                    bigint generated by default as identity
        primary key,
    artifact_type         varchar(64)   not null,
    event_type            varchar(64)   not null,
    ledger_id             varchar(64)   not null
        constraint uk_learning_artifact_ledger_id
            unique,
    release_state         varchar(64)   not null,
    rollback_target_state varchar(64),
    tenant_id             varchar(120)  not null,
    policy_state          varchar(128),
    actor                 varchar(160)  not null,
    artifact_version      varchar(160),
    canary_outcome        varchar(160),
    reason                varchar(2000) not null,
    artifact_key          varchar(255)  not null,
    facts_json            text
);

alter table public.learning_artifact_release_ledger
    owner to contexa;

create index idx_learning_artifact_ledger_identity
    on public.learning_artifact_release_ledger (tenant_id, artifact_type, artifact_key, created_at);

create index idx_learning_artifact_ledger_artifact
    on public.learning_artifact_release_ledger (artifact_type, artifact_key, created_at);

create table public.learning_governance_snapshot
(
    created_at    timestamp(6) not null,
    generated_at  timestamp(6),
    id            bigint generated by default as identity
        primary key,
    updated_at    timestamp(6) not null,
    artifact_type varchar(64)  not null,
    tenant_id     varchar(120) not null,
    snapshot_json text         not null,
    constraint uk_learning_governance_snapshot_identity
        unique (tenant_id, artifact_type)
);

alter table public.learning_governance_snapshot
    owner to contexa;

create index idx_learning_governance_snapshot_tenant_updated
    on public.learning_governance_snapshot (tenant_id, updated_at);

create table public.managed_resource
(
    created_at                  timestamp(6) not null,
    id                          bigint generated by default as identity
        primary key,
    updated_at                  timestamp(6) not null,
    resource_identifier         varchar(512) not null,
    return_type                 varchar(512),
    api_docs_url                varchar(1024),
    available_context_variables varchar(1024),
    description                 varchar(1024),
    parameter_types             varchar(1024),
    source_code_location        varchar(1024),
    friendly_name               varchar(255) not null,
    http_method                 varchar(255)
        constraint managed_resource_http_method_check
            check ((http_method)::text = ANY
                   ((ARRAY ['GET'::character varying, 'POST'::character varying, 'PUT'::character varying, 'DELETE'::character varying, 'PATCH'::character varying, 'ANY'::character varying])::text[])),
    resource_type               varchar(255) not null
        constraint managed_resource_resource_type_check
            check ((resource_type)::text = ANY
                   ((ARRAY ['URL'::character varying, 'METHOD'::character varying])::text[])),
    service_owner               varchar(255),
    status                      varchar(255) not null
        constraint managed_resource_status_check
            check ((status)::text = ANY
                   ((ARRAY ['NEEDS_DEFINITION'::character varying, 'PERMISSION_CREATED'::character varying, 'POLICY_CONNECTED'::character varying, 'EXCLUDED'::character varying])::text[]))
);

alter table public.managed_resource
    owner to contexa;

create table public.function_catalog
(
    function_group_id   bigint
        constraint fkq7oc3xf6h5751ujccfwra52de
            references public.function_group,
    id                  bigint generated by default as identity
        primary key,
    managed_resource_id bigint       not null
        unique
        constraint fklgnitp52iu5y28w8oslepyb1e
            references public.managed_resource,
    description         varchar(1024),
    friendly_name       varchar(255) not null,
    status              varchar(255) not null
        constraint function_catalog_status_check
            check ((status)::text = ANY
                   ((ARRAY ['UNCONFIRMED'::character varying, 'ACTIVE'::character varying, 'INACTIVE'::character varying])::text[]))
);

alter table public.function_catalog
    owner to contexa;

create table public.model_performance_telemetry_outbox
(
    attempt_count                 integer      not null,
    escalate_protection_triggered integer      not null,
    period                        date         not null
        constraint uk_model_performance_telemetry_outbox_period
            unique,
    block_count                   bigint       not null,
    challenge_count               bigint       not null,
    created_at                    timestamp(6) not null,
    delivered_at                  timestamp(6),
    id                            bigint generated by default as identity
        primary key,
    layer1_escalation_count       bigint       not null,
    layer1_processing_total_ms    bigint       not null,
    layer1_sample_count           bigint       not null,
    layer2_processing_total_ms    bigint       not null,
    layer2_sample_count           bigint       not null,
    next_attempt_at               timestamp(6),
    total_event_count             bigint       not null,
    updated_at                    timestamp(6) not null,
    status                        varchar(32)  not null,
    telemetry_id                  varchar(64)  not null,
    last_error                    varchar(2000)
);

alter table public.model_performance_telemetry_outbox
    owner to contexa;

create index idx_model_performance_telemetry_outbox_dispatch
    on public.model_performance_telemetry_outbox (status, next_attempt_at, period);

create table public.password_history
(
    changed_at    timestamp(6) not null,
    id            bigint generated by default as identity
        primary key,
    user_id       bigint       not null,
    password_hash varchar(512) not null
);

alter table public.password_history
    owner to contexa;

create table public.password_policy
(
    history_count            integer            not null,
    lockout_duration_minutes integer            not null,
    max_failed_attempts      integer            not null,
    max_length               integer            not null,
    min_length               integer            not null,
    password_expiry_days     integer            not null,
    require_digit            boolean            not null,
    require_lowercase        boolean            not null,
    require_special_char     boolean            not null,
    require_uppercase        boolean            not null,
    created_at               timestamp(6)       not null,
    id                       bigint generated by default as identity
        primary key,
    updated_at               timestamp(6),
    ip_max_failed_attempts   integer default 30 not null,
    ip_window_minutes        integer default 15 not null
);

alter table public.password_policy
    owner to contexa;

create table public.permission
(
    auto_created         boolean      not null,
    created_at           timestamp(6) not null,
    managed_resource_id  bigint
        unique
        constraint fkawvdni3oiy1x0mcgbc7bogxow
            references public.managed_resource,
    permission_id        bigint generated by default as identity
        primary key,
    updated_at           timestamp(6),
    action_type          varchar(100),
    target_type          varchar(100),
    description          varchar(1024),
    condition_expression varchar(2048),
    friendly_name        varchar(255),
    permission_name      varchar(255) not null
        unique
);

alter table public.permission
    owner to contexa;

create table public.policy
(
    confidence_score     double precision,
    is_active            boolean      not null,
    priority             integer      not null,
    approved_at          timestamp(6),
    created_at           timestamp(6) not null,
    id                   bigint generated by default as identity
        primary key,
    updated_at           timestamp(6),
    approval_status      varchar(50)
        constraint policy_approval_status_check
            check ((approval_status)::text = ANY
                   ((ARRAY ['PENDING'::character varying, 'APPROVED'::character varying, 'REJECTED'::character varying, 'NOT_REQUIRED'::character varying])::text[])),
    source               varchar(50)
        constraint policy_source_check
            check ((source)::text = ANY
                   ((ARRAY ['MANUAL'::character varying, 'AI_GENERATED'::character varying, 'AI_EVOLVED'::character varying, 'IMPORTED'::character varying])::text[])),
    friendly_description varchar(2048),
    reasoning            varchar(4096),
    ai_model             varchar(255),
    approved_by          varchar(255),
    description          varchar(255),
    effect               varchar(255) not null
        constraint policy_effect_check
            check ((effect)::text = ANY ((ARRAY ['ALLOW'::character varying, 'DENY'::character varying])::text[])),
    name                 varchar(255) not null
        unique
);

alter table public.policy
    owner to contexa;

create table public.policy_template
(
    id                bigint generated by default as identity
        primary key,
    description       varchar(1024),
    category          varchar(255),
    name              varchar(255) not null,
    policy_draft_json jsonb        not null,
    template_id       varchar(255) not null
        unique
);

alter table public.policy_template
    owner to contexa;

create table public.policy_version
(
    version_number integer      not null,
    changed_at     timestamp(6) not null,
    id             bigint generated by default as identity
        primary key,
    policy_id      bigint       not null,
    change_type    varchar(20)  not null
        constraint policy_version_change_type_check
            check ((change_type)::text = ANY
                   ((ARRAY ['CREATED'::character varying, 'UPDATED'::character varying, 'DELETED'::character varying, 'ROLLBACK'::character varying])::text[])),
    change_reason  varchar(1024),
    changed_by     varchar(255) not null,
    snapshot_json  text         not null
);

alter table public.policy_version
    owner to contexa;

create index idx_policy_version_policy_id
    on public.policy_version (policy_id);

create index idx_policy_version_changed_at
    on public.policy_version (changed_at);

create table public.policy_rule
(
    id          bigint generated by default as identity
        primary key,
    policy_id   bigint not null
        constraint fkby055hedoe439lybgocwla58
            references public.policy,
    description varchar(255)
);

alter table public.policy_rule
    owner to contexa;

create table public.policy_condition
(
    id                   bigint generated by default as identity
        primary key,
    rule_id              bigint        not null
        constraint fkl59r5who24fp434tk3h1tyoj2
            references public.policy_rule,
    condition_expression varchar(2048) not null,
    authorization_phase  varchar(255)  not null
        constraint policy_condition_authorization_phase_check
            check ((authorization_phase)::text = ANY
                   ((ARRAY ['PRE_AUTHORIZE'::character varying, 'POST_AUTHORIZE'::character varying, 'PROTECTABLE'::character varying])::text[])),
    description          varchar(255)
);

alter table public.policy_condition
    owner to contexa;

create table public.policy_target
(
    target_order      integer      not null,
    id                bigint generated by default as identity
        primary key,
    policy_id         bigint       not null
        constraint fkgeil8a9d9rtc5dms4pvf1fyef
            references public.policy,
    source_type       varchar(20),
    http_method       varchar(255),
    target_identifier varchar(255) not null,
    target_type       varchar(255) not null
);

alter table public.policy_target
    owner to contexa;

create table public.prompt_context_audit_forwarding_outbox
(
    attempt_count       integer      not null,
    created_at          timestamp(6) not null,
    delivered_at        timestamp(6),
    id                  bigint generated by default as identity
        primary key,
    next_attempt_at     timestamp(6),
    updated_at          timestamp(6) not null,
    status              varchar(32)  not null,
    audit_id            varchar(64)  not null
        constraint uk_prompt_context_audit_forwarding_outbox_audit_id
            unique,
    correlation_id      varchar(64)  not null,
    tenant_external_ref varchar(128) not null,
    last_error          varchar(2000),
    payload_json        text         not null
);

alter table public.prompt_context_audit_forwarding_outbox
    owner to contexa;

create index idx_prompt_context_audit_forwarding_outbox_dispatch
    on public.prompt_context_audit_forwarding_outbox (status, next_attempt_at, created_at);

create table public.role
(
    enabled    boolean      not null,
    expression boolean      not null,
    created_at timestamp(6) not null,
    role_id    bigint generated by default as identity
        primary key,
    updated_at timestamp(6),
    created_by varchar(100),
    role_name  varchar(100) not null
        unique,
    role_desc  varchar(500)
);

alter table public.role
    owner to contexa;

create table public.group_role_permissions
(
    assigned_at   timestamp(6) not null,
    group_id      bigint       not null
        constraint fkgy4mmns4mi9s7oaoidqnvm2cy
            references public.app_group,
    permission_id bigint       not null
        constraint fkeo2a4ew8vfhv8kc3b51uobhvj
            references public.permission,
    role_id       bigint       not null
        constraint fk8mt8acbmcthcii0ibppex6fu4
            references public.role,
    assigned_by   varchar(100),
    primary key (group_id, permission_id, role_id)
);

alter table public.group_role_permissions
    owner to contexa;

create table public.group_roles
(
    assigned_at timestamp(6) not null,
    group_id    bigint       not null
        constraint fk8copjhvgxbkc2gkb6x38xsgjw
            references public.app_group,
    role_id     bigint       not null
        constraint fkfi9xska6g6sl15g8moif7b4yw
            references public.role,
    assigned_by varchar(100),
    primary key (group_id, role_id)
);

alter table public.group_roles
    owner to contexa;

create table public.role_hierarchy_config
(
    is_active        boolean not null,
    hierarchy_id     bigint generated by default as identity
        primary key,
    description      varchar(255),
    hierarchy_string text    not null
        unique
);

alter table public.role_hierarchy_config
    owner to contexa;

create table public.role_permissions
(
    assigned_at   timestamp(6) not null,
    permission_id bigint       not null
        constraint fkh0v7u4w7mttcu81o8wegayr8e
            references public.permission,
    role_id       bigint       not null
        constraint fklodb7xh4a2xjv39gc3lsop95n
            references public.role,
    assigned_by   varchar(100),
    primary key (permission_id, role_id)
);

alter table public.role_permissions
    owner to contexa;

create table public.security_decision_forwarding_outbox
(
    attempt_count       integer          not null,
    created_at          timestamp(6)     not null,
    delivered_at        timestamp(6),
    id                  bigint generated by default as identity
        primary key,
    next_attempt_at     timestamp(6),
    updated_at          timestamp(6)     not null,
    status              varchar(32)      not null,
    correlation_id      varchar(64)      not null
        constraint uk_security_decision_forwarding_outbox_correlation_id
            unique,
    tenant_external_ref varchar(128)     not null,
    last_error          varchar(2000),
    payload_json        text             not null,
    version             bigint default 0 not null
);

alter table public.security_decision_forwarding_outbox
    owner to contexa;

create index idx_security_decision_forwarding_outbox_dispatch
    on public.security_decision_forwarding_outbox (status, next_attempt_at, created_at);

create table public.security_spel
(
    created_at  timestamp(6),
    id          bigint generated by default as identity
        primary key,
    category    varchar(100),
    description varchar(1024),
    expression  varchar(2048) not null,
    name        varchar(255)  not null
        unique
);

alter table public.security_spel
    owner to contexa;

create table public.soar_approval_assignments
(
    step_number       integer      not null,
    assigned_at       timestamp(6),
    created_at        timestamp(6) not null,
    id                bigint generated by default as identity
        primary key,
    responded_at      timestamp(6),
    updated_at        timestamp(6) not null,
    response_decision varchar(30),
    status            varchar(30)  not null,
    assigned_by       varchar(100),
    assignee_id       varchar(100),
    assignee_role     varchar(100),
    request_id        varchar(100) not null,
    response_comment  text
);

alter table public.soar_approval_assignments
    owner to contexa;

create index idx_soar_approval_assignment_request_id
    on public.soar_approval_assignments (request_id);

create index idx_soar_approval_assignment_status
    on public.soar_approval_assignments (status);

create index idx_soar_approval_assignment_step
    on public.soar_approval_assignments (request_id, step_number);

create table public.soar_approval_policies
(
    auto_approve_on_timeout boolean      not null,
    required_approvers      integer      not null,
    timeout_minutes         integer      not null,
    id                      bigint generated by default as identity
        primary key,
    severity                varchar(20),
    action_name             varchar(255),
    policy_name             varchar(255) not null
        unique,
    required_roles          text
);

alter table public.soar_approval_policies
    owner to contexa;

create table public.soar_approval_requests
(
    approval_timeout         integer,
    approved_count           integer,
    break_glass_requested    boolean default false not null,
    current_step_number      integer,
    quorum_satisfied         boolean default false not null,
    rejected_count           integer,
    remaining_approvals      integer,
    required_approvers       integer,
    total_steps              integer,
    approved_at              timestamp(6),
    created_at               timestamp(6)          not null,
    id                       bigint generated by default as identity
        primary key,
    updated_at               timestamp(6)          not null,
    risk_level               varchar(20),
    status                   varchar(30)           not null,
    action_type              varchar(50),
    approval_type            varchar(50),
    incident_id              varchar(100),
    organization_id          varchar(100),
    playbook_instance_id     varchar(100)          not null,
    reopened_from_request_id varchar(100),
    request_id               varchar(100)          not null
        unique,
    session_id               varchar(128),
    action_name              varchar(255)          not null,
    approval_comment         text,
    approved_by              varchar(255),
    break_glass_reason       text,
    description              text,
    parameters               text,
    requested_by             varchar(255),
    required_roles           text,
    reviewer_comment         text,
    reviewer_id              varchar(255),
    tool_name                varchar(255)
);

alter table public.soar_approval_requests
    owner to contexa;

create table public.soar_approval_steps
(
    approved_count      integer      not null,
    rejected_count      integer      not null,
    remaining_approvals integer      not null,
    required_approvers  integer      not null,
    step_number         integer      not null,
    completed_at        timestamp(6),
    created_at          timestamp(6) not null,
    id                  bigint generated by default as identity
        primary key,
    opened_at           timestamp(6),
    updated_at          timestamp(6) not null,
    status              varchar(30)  not null,
    request_id          varchar(100) not null,
    step_name           varchar(150) not null,
    required_roles      text,
    constraint uk_soar_approval_step_request_number
        unique (request_id, step_number)
);

alter table public.soar_approval_steps
    owner to contexa;

create index idx_soar_approval_step_request_id
    on public.soar_approval_steps (request_id);

create index idx_soar_approval_step_status
    on public.soar_approval_steps (status);

create table public.soar_approval_votes
(
    step_number   integer      not null,
    created_at    timestamp(6) not null,
    id            bigint generated by default as identity
        primary key,
    updated_at    timestamp(6) not null,
    decision      varchar(20)  not null,
    approver_id   varchar(100) not null,
    approver_role varchar(100) not null,
    request_id    varchar(100) not null,
    approver_name varchar(150),
    comment       text,
    constraint uk_soar_approval_vote_request_approver_step
        unique (request_id, approver_id, step_number)
);

alter table public.soar_approval_votes
    owner to contexa;

create index idx_soar_approval_vote_request_id
    on public.soar_approval_votes (request_id);

create index idx_soar_approval_vote_decision
    on public.soar_approval_votes (decision);

create index idx_soar_approval_vote_created_at
    on public.soar_approval_votes (created_at);

create index idx_soar_approval_vote_request_step
    on public.soar_approval_votes (request_id, step_number);

create table public.soar_incidents
(
    created_at  timestamp(6) not null,
    updated_at  timestamp(6) not null,
    id          uuid         not null
        primary key,
    severity    varchar(20),
    type        varchar(50),
    incident_id varchar(100),
    description text,
    history     text,
    metadata    text,
    status      varchar(255) not null
        constraint soar_incidents_status_check
            check ((status)::text = ANY
                   ((ARRAY ['NEW'::character varying, 'TRIAGE'::character varying, 'INVESTIGATION'::character varying, 'PLANNING'::character varying, 'PENDING_APPROVAL'::character varying, 'EXECUTION'::character varying, 'REPORTING'::character varying, 'COMPLETED'::character varying, 'AUTO_CLOSED'::character varying, 'FAILED'::character varying, 'CLOSED_BY_ADMIN'::character varying])::text[])),
    title       varchar(255) not null
);

alter table public.soar_incidents
    owner to contexa;

create table public.system_settings
(
    audit_log_retention_days   integer      not null,
    registration_enabled       boolean      not null,
    created_at                 timestamp(6) not null,
    id                         bigint generated by default as identity
        primary key,
    updated_at                 timestamp(6),
    policy_combining_algorithm varchar(50)  not null,
    default_role               varchar(100) not null
);

alter table public.system_settings
    owner to contexa;

create table public.threat_indicators
(
    active               boolean,
    confidence           double precision,
    detection_count      integer,
    false_positive_count integer,
    threat_score         double precision,
    created_at           timestamp(6)  not null,
    detected_at          timestamp(6),
    expires_at           timestamp(6),
    first_seen           timestamp(6),
    last_seen            timestamp(6),
    updated_at           timestamp(6),
    mitre_attack_id      varchar(50),
    campaign_id          varchar(100),
    cis_control          varchar(100),
    indicator_id         varchar(100)  not null
        primary key,
    mitre_tactic         varchar(100),
    mitre_technique      varchar(100),
    nist_csf_category    varchar(100),
    threat_actor_id      varchar(100),
    indicator_value      varchar(1024) not null,
    campaign             varchar(255),
    description          text,
    indicator_type       varchar(255)  not null
        constraint threat_indicators_indicator_type_check
            check ((indicator_type)::text = ANY
                   ((ARRAY ['IP_ADDRESS'::character varying, 'DOMAIN'::character varying, 'URL'::character varying, 'FILE_HASH'::character varying, 'FILE_PATH'::character varying, 'REGISTRY_KEY'::character varying, 'PROCESS_NAME'::character varying, 'EMAIL_ADDRESS'::character varying, 'USER_AGENT'::character varying, 'CERTIFICATE'::character varying, 'MUTEX'::character varying, 'YARA_RULE'::character varying, 'BEHAVIORAL'::character varying, 'UNKNOWN'::character varying, 'PATTERN'::character varying, 'USER_ACCOUNT'::character varying, 'COMPLIANCE'::character varying, 'EVENT'::character varying])::text[])),
    malware_family       varchar(255),
    severity             varchar(255)  not null
        constraint threat_indicators_severity_check
            check ((severity)::text = ANY
                   ((ARRAY ['CRITICAL'::character varying, 'HIGH'::character varying, 'MEDIUM'::character varying, 'LOW'::character varying, 'INFO'::character varying])::text[])),
    source               varchar(255),
    status               varchar(255)
        constraint threat_indicators_status_check
            check ((status)::text = ANY
                   ((ARRAY ['ACTIVE'::character varying, 'INACTIVE'::character varying, 'EXPIRED'::character varying, 'FALSE_POSITIVE'::character varying, 'UNDER_REVIEW'::character varying])::text[])),
    threat_actor         varchar(255)
);

alter table public.threat_indicators
    owner to contexa;

create table public.indicator_metadata
(
    indicator_id varchar(100) not null
        constraint fk8woobi3dw4qnun8tmc9ydeh3a
            references public.threat_indicators,
    meta_key     varchar(255) not null,
    meta_value   varchar(255),
    primary key (indicator_id, meta_key)
);

alter table public.indicator_metadata
    owner to contexa;

create table public.indicator_tags
(
    indicator_id varchar(100) not null
        constraint fk798h0bhyufds0oabwfaircn82
            references public.threat_indicators,
    tag          varchar(255)
);

alter table public.indicator_tags
    owner to contexa;

create table public.related_indicators
(
    indicator_id         varchar(100) not null
        constraint fke955l2l6jjmnhrqktg2xhhqik
            references public.threat_indicators,
    related_indicator_id varchar(100) not null
        constraint fks2jii22s35fvojsokbmq9elij
            references public.threat_indicators,
    primary key (indicator_id, related_indicator_id)
);

alter table public.related_indicators
    owner to contexa;

create table public.threat_outcome_forwarding_outbox
(
    attempt_count       integer      not null,
    created_at          timestamp(6) not null,
    delivered_at        timestamp(6),
    id                  bigint generated by default as identity
        primary key,
    next_attempt_at     timestamp(6),
    updated_at          timestamp(6) not null,
    status              varchar(32)  not null,
    correlation_id      varchar(64)  not null,
    outcome_id          varchar(64)  not null
        constraint uk_threat_outcome_forwarding_outbox_outcome_id
            unique,
    tenant_external_ref varchar(128) not null,
    last_error          varchar(2000),
    payload_json        text         not null
);

alter table public.threat_outcome_forwarding_outbox
    owner to contexa;

create index idx_threat_outcome_forwarding_outbox_dispatch
    on public.threat_outcome_forwarding_outbox (status, next_attempt_at, created_at);

create table public.user_behavior_profiles
(
    cluster_size            integer,
    confidence_score        real,
    learning_count          integer,
    id                      bigint generated by default as identity
        primary key,
    last_updated            timestamp(6),
    profile_type            varchar(50)  not null,
    vector_cluster_id       varchar(100),
    cluster_centroid_vector text,
    common_activities       json,
    common_ip_ranges        json,
    normal_range_metadata   json,
    user_id                 varchar(255) not null
);

alter table public.user_behavior_profiles
    owner to contexa;

create table public.users
(
    account_locked        boolean      not null,
    bridge_managed        boolean      not null,
    credentials_expired   boolean      not null,
    enabled               boolean      not null,
    external_auth_only    boolean      not null,
    failed_login_attempts integer      not null,
    mfa_enabled           boolean      not null,
    created_at            timestamp(6) not null,
    id                    bigint generated by default as identity
        primary key,
    last_bridged_at       timestamp(6),
    last_login_at         timestamp(6),
    last_mfa_used_at      timestamp(6),
    lock_expires_at       timestamp(6),
    password_changed_at   timestamp(6),
    updated_at            timestamp(6),
    locale                varchar(10),
    phone                 varchar(20),
    last_login_ip         varchar(45),
    last_used_mfa_factor  varchar(50),
    preferred_mfa_factor  varchar(50),
    principal_type        varchar(50),
    timezone              varchar(50),
    authentication_source varchar(100),
    department            varchar(100),
    name                  varchar(100) not null,
    position              varchar(100),
    username              varchar(100) not null
        unique,
    bridge_subject_key    varchar(120)
        unique,
    profile_image_url     varchar(500),
    email                 varchar(255)
        unique,
    external_subject_id   varchar(255),
    organization_id       varchar(255),
    password              varchar(255) not null
);

alter table public.users
    owner to contexa;

create table public.bridge_user_profile
(
    mfa_completed_from_customer boolean,
    created_at                  timestamp(6) not null,
    last_synced_at              timestamp(6),
    updated_at                  timestamp(6),
    user_id                     bigint       not null
        primary key
        constraint fk6ln576ijwr4i3kdbqmfjyedeo
            references public.users,
    authentication_assurance    varchar(100),
    authentication_type         varchar(100),
    source_system               varchar(100),
    last_sync_hash              varchar(128),
    last_attributes_json        text,
    last_authorities_json       text,
    session_id                  varchar(255)
);

alter table public.bridge_user_profile
    owner to contexa;

create table public.user_groups
(
    assigned_at timestamp(6) not null,
    group_id    bigint       not null
        constraint fk3w5drcboifiod1drvv522wssu
            references public.app_group,
    user_id     bigint       not null
        constraint fkd37bs5u9hvbwljup24b2hin2b
            references public.users,
    assigned_by varchar(100),
    primary key (group_id, user_id)
);

alter table public.user_groups
    owner to contexa;

create table public.user_role_permissions
(
    assigned_at   timestamp(6) not null,
    permission_id bigint       not null
        constraint fkfd49bwfmff3k09ayncys0whpa
            references public.permission,
    role_id       bigint       not null
        constraint fk46j8ija8flueg29473fskq7lp
            references public.role,
    user_id       bigint       not null
        constraint fkppqv9rlmheqpwdsa5fvqb74ec
            references public.users,
    assigned_by   varchar(100),
    primary key (permission_id, role_id, user_id)
);

alter table public.user_role_permissions
    owner to contexa;

create table public.user_roles
(
    assigned_at timestamp(6) not null,
    role_id     bigint       not null
        constraint fkrhfovtciq1l558cw6udg0h0d3
            references public.role,
    user_id     bigint       not null
        constraint fkhfh9dx7w3ubf1co1vdev94g3f
            references public.users,
    assigned_by varchar(100),
    primary key (role_id, user_id)
);

alter table public.user_roles
    owner to contexa;

create table public.wizard_session
(
    created_at    timestamp(6) not null,
    expires_at    timestamp(6) not null,
    session_id    varchar(36)  not null
        primary key,
    context_data  text         not null,
    owner_user_id varchar(255) not null
);

alter table public.wizard_session
    owner to contexa;

create table public.demo_interaction
(
    id                    bigint generated by default as identity
        primary key,
    action                varchar(16),
    created_at            timestamp(6)          not null,
    geoip_country         varchar(2),
    ip_address            varchar(64),
    persona_id            varchar(64)           not null,
    resource_level        varchar(16),
    risk_score            numeric(4, 3),
    scenario              varchar(32),
    session_id            varchar(128)          not null,
    user_agent            text,
    visitor_tag           varchar(64)           not null,
    is_simulation         boolean default false not null,
    simulation_session_id varchar(64)
);

alter table public.demo_interaction
    owner to contexa;

create index idx_interaction_persona_time
    on public.demo_interaction (persona_id, created_at);

create index idx_interaction_visitor_time
    on public.demo_interaction (visitor_tag, created_at);

create index idx_interaction_simulation
    on public.demo_interaction (is_simulation, simulation_session_id);

create table public.demo_persona
(
    persona_id        varchar(64)                                     not null
        primary key,
    created_at        timestamp(6)                                    not null,
    device_hint       varchar(32)                                     not null,
    role              varchar(32)                                     not null,
    work_style        varchar(32)                                     not null,
    paired_persona_id varchar(64),
    persona_kind      varchar(16) default 'NORMAL'::character varying not null
);

alter table public.demo_persona
    owner to contexa;

create table public.demo_visitor
(
    visitor_tag    varchar(64)  not null
        primary key,
    first_seen_at  timestamp(6) not null,
    geoip_country  varchar(2),
    last_seen_at   timestamp(6) not null,
    persona_id     varchar(64)  not null,
    ua_fingerprint text
);

alter table public.demo_visitor
    owner to contexa;

create index idx_visitor_persona
    on public.demo_visitor (persona_id);

create index idx_visitor_last_seen
    on public.demo_visitor (last_seen_at);

create table public.flyway_schema_history
(
    installed_rank integer                 not null
        constraint flyway_schema_history_pk
            primary key,
    version        varchar(50),
    description    varchar(200)            not null,
    type           varchar(20)             not null,
    script         varchar(1000)           not null,
    checksum       integer,
    installed_by   varchar(100)            not null,
    installed_on   timestamp default now() not null,
    execution_time integer                 not null,
    success        boolean                 not null
);

alter table public.flyway_schema_history
    owner to contexa;

create index flyway_schema_history_s_idx
    on public.flyway_schema_history (success);

create table public.verification_run_ledger
(
    id                        bigint generated by default as identity
        primary key,
    run_id                    varchar(128)                        not null
        unique,
    user_id                   varchar(160)                        not null,
    metric_code               varchar(32)                         not null,
    execution_path            varchar(160)                        not null,
    state                     varchar(80),
    state_tone                varchar(80),
    requested_by              varchar(160),
    request_id                varchar(160),
    endpoint_key              varchar(80),
    endpoint_label            varchar(255),
    round_number              integer,
    score                     double precision,
    passed_checks             integer,
    total_checks              integer,
    processing_time_ms        bigint,
    message                   text,
    evidence_references_json  text,
    checks_json               text,
    request_facts_json        text,
    event_facts_json          text,
    prompt_facts_json         text,
    analysis_facts_json       text,
    events_json               text,
    raw_evidence_json         text,
    requested_at              timestamp,
    started_at                timestamp,
    completed_at              timestamp,
    created_at                timestamp default CURRENT_TIMESTAMP not null,
    package_id                varchar(160),
    evidence_references_jsonb jsonb,
    checks_jsonb              jsonb,
    request_facts_jsonb       jsonb,
    event_facts_jsonb         jsonb,
    prompt_facts_jsonb        jsonb,
    analysis_facts_jsonb      jsonb,
    events_jsonb              jsonb,
    raw_evidence_jsonb        jsonb
);

alter table public.verification_run_ledger
    owner to contexa;

create index idx_verification_run_ledger_user_requested_at
    on public.verification_run_ledger (user_id asc, requested_at desc);

create index idx_verification_run_ledger_user_metric
    on public.verification_run_ledger (user_id asc, metric_code asc, requested_at desc);

create index idx_verification_run_ledger_user_request
    on public.verification_run_ledger (user_id, request_id);

create index idx_verification_run_ledger_package_metric
    on public.verification_run_ledger (package_id asc, metric_code asc, requested_at desc);

create index idx_verification_run_ledger_request_facts_jsonb
    on public.verification_run_ledger using gin (request_facts_jsonb);

create index idx_verification_run_ledger_prompt_facts_jsonb
    on public.verification_run_ledger using gin (prompt_facts_jsonb);

create index idx_verification_run_ledger_analysis_facts_jsonb
    on public.verification_run_ledger using gin (analysis_facts_jsonb);

create index idx_verification_run_ledger_raw_evidence_jsonb
    on public.verification_run_ledger using gin (raw_evidence_jsonb);

create table public.verification_execution_request_ledger
(
    id                                  bigint generated by default as identity
        primary key,
    execution_request_id                varchar(160)                        not null
        unique,
    user_id                             varchar(160)                        not null,
    metric_code                         varchar(32)                         not null,
    execution_mode                      varchar(32)                         not null,
    requested_endpoint_key              varchar(80),
    requested_resource_id               varchar(255),
    requested_request_path              text,
    resolved_endpoint_key               varchar(80),
    resolved_resource_id                varchar(255),
    resolved_request_path               text,
    execution_condition                 varchar(80),
    execution_condition_multi_account   boolean,
    execution_condition_repeated        boolean,
    subject_account                     varchar(255),
    comparison_accounts_json            text,
    comparison_account_count            integer,
    requested_run_count                 integer,
    rerun_requested                     boolean,
    contamination_seed                  boolean,
    baseline_seed_requested             boolean,
    runtime_profile_code                varchar(120),
    runtime_model_id                    varchar(255),
    comparison_model_ids_json           text,
    runtime_comparison_model_count      integer,
    runtime_temperature                 double precision,
    runtime_top_p                       double precision,
    runtime_seed                        integer,
    runtime_max_tokens                  integer,
    runtime_disable_retries             boolean,
    runtime_disable_ollama_thinking     boolean,
    llm_runtime_mode                    varchar(120),
    chat_runtime_provider               varchar(120),
    embedding_runtime_provider          varchar(120),
    embedding_priority                  varchar(120),
    embedding_dedicated_runtime_enabled boolean,
    chat_ollama_base_url                text,
    embedding_ollama_base_url           text,
    browser_observation_json            text,
    raw_request_json                    text,
    request_attributes_json             text,
    linked_run_id                       varchar(160),
    linked_request_id                   varchar(160),
    outcome_state                       varchar(80),
    outcome_message                     text,
    terminal_outcome                    boolean,
    created_at                          timestamp default CURRENT_TIMESTAMP not null,
    updated_at                          timestamp default CURRENT_TIMESTAMP not null
);

alter table public.verification_execution_request_ledger
    owner to contexa;

create index idx_ver_exec_req_metric_created
    on public.verification_execution_request_ledger (metric_code asc, created_at desc);

create index idx_ver_exec_req_user_created
    on public.verification_execution_request_ledger (user_id asc, created_at desc);

create index idx_ver_exec_req_linked_run
    on public.verification_execution_request_ledger (linked_run_id);

create table public.verification_execution_preflight_ledger
(
    id                    bigint generated by default as identity
        primary key,
    execution_request_id  varchar(160)                        not null
        constraint verification_execution_preflight_ledge_execution_request_id_key
            unique,
    metric_code           varchar(32)                         not null,
    preflight_ready       boolean                             not null,
    status_code           varchar(80),
    message               text,
    selection_json        text,
    evaluated_models_json text,
    evaluated_model_count integer,
    created_at            timestamp default CURRENT_TIMESTAMP not null,
    updated_at            timestamp default CURRENT_TIMESTAMP not null
);

alter table public.verification_execution_preflight_ledger
    owner to contexa;

create index idx_ver_exec_pre_metric_created
    on public.verification_execution_preflight_ledger (metric_code asc, created_at desc);

create index idx_ver_exec_pre_ready_created
    on public.verification_execution_preflight_ledger (preflight_ready asc, created_at desc);

create table public.verification_case_ledger
(
    id                       bigint generated by default as identity
        primary key,
    verification_case_id     varchar(160)                        not null
        unique,
    tenant_id                varchar(160),
    source_run_id            varchar(128),
    request_id               varchar(160),
    metric_code              varchar(32)                         not null,
    metric_category          varchar(120),
    scenario_key             varchar(255),
    verified_at              timestamp,
    overall_passed           boolean                             not null,
    case_status              varchar(80)                         not null,
    truth_bundle_json        text                                not null,
    drillback_reference_json text                                not null,
    source_kind              varchar(160),
    created_at               timestamp default CURRENT_TIMESTAMP not null,
    truth_bundle_package_id  varchar(255)
);

alter table public.verification_case_ledger
    owner to contexa;

create index idx_verification_case_ledger_run
    on public.verification_case_ledger (source_run_id);

create index idx_verification_case_ledger_request
    on public.verification_case_ledger (request_id);

create index idx_verification_case_ledger_metric
    on public.verification_case_ledger (metric_code asc, verified_at desc);

create index idx_verification_case_ledger_package
    on public.verification_case_ledger (truth_bundle_package_id, verified_at);

create table public.evaluation_case_ledger
(
    id                       bigint generated by default as identity
        primary key,
    evaluation_case_id       varchar(160)                        not null
        unique,
    verification_case_id     varchar(160)                        not null,
    metric_code              varchar(32)                         not null,
    metric_category          varchar(120),
    suite_keys_json          text                                not null,
    metric_result_json       text                                not null,
    publication_ready        boolean                             not null,
    gate_results_json        text                                not null,
    drillback_reference_json text                                not null,
    evaluated_at             timestamp,
    source_kind              varchar(120),
    created_at               timestamp default CURRENT_TIMESTAMP not null
);

alter table public.evaluation_case_ledger
    owner to contexa;

create index idx_evaluation_case_ledger_verification
    on public.evaluation_case_ledger (verification_case_id);

create index idx_evaluation_case_ledger_metric
    on public.evaluation_case_ledger (metric_code asc, evaluated_at desc);

create table public.unified_truth_audit_ledger
(
    id            bigint generated by default as identity
        primary key,
    recorded_at   timestamp    not null,
    stage         varchar(80)  not null,
    action        varchar(120) not null,
    subject_id    varchar(255),
    note          text,
    metadata_json text         not null
);

alter table public.unified_truth_audit_ledger
    owner to contexa;

create index idx_unified_truth_audit_subject
    on public.unified_truth_audit_ledger (subject_id asc, recorded_at desc);

create index idx_unified_truth_audit_stage
    on public.unified_truth_audit_ledger (stage asc, recorded_at desc);

create table public.published_benchmark_release
(
    id                           bigint generated by default as identity
        primary key,
    slug                         varchar(200)                                         not null,
    version_no                   integer                                              not null,
    publication_status           varchar(40)                                          not null,
    source_type                  varchar(120),
    title                        varchar(400)                                         not null,
    benchmark_version            varchar(120),
    generated_at                 timestamp,
    published_at                 timestamp,
    manifest_identity            varchar(255),
    artifact_sha256              text,
    note                         text,
    summary_json                 text                                                 not null,
    chart_data_json              text                                                 not null,
    manifest_json                text                                                 not null,
    html_report_text             text                                                 not null,
    pdf_base64_text              text                                                 not null,
    created_at                   timestamp   default CURRENT_TIMESTAMP                not null,
    source_kind                  varchar(64) default 'FIRST_PARTY'::character varying not null,
    publication_contract_version varchar(80),
    supersedes_release_id        bigint,
    constraint uq_published_benchmark_release_slug_version
        unique (slug, version_no)
);

alter table public.published_benchmark_release
    owner to contexa;

create index idx_published_benchmark_release_slug_status
    on public.published_benchmark_release (slug asc, publication_status asc, created_at desc);

create index idx_published_benchmark_release_status_generated
    on public.published_benchmark_release (publication_status asc, generated_at desc);

create index idx_published_benchmark_release_source_kind
    on public.published_benchmark_release (source_kind asc, publication_status asc, created_at desc);

create index idx_published_benchmark_release_supersedes
    on public.published_benchmark_release (supersedes_release_id);

create table public.benchmark_run_ledger
(
    id                            bigint generated by default as identity
        primary key,
    benchmark_run_id              varchar(200)                        not null
        unique,
    slug                          varchar(200)                        not null,
    title                         varchar(400)                        not null,
    benchmark_version             varchar(120),
    source_type                   varchar(120),
    generated_at                  timestamp,
    published_at                  timestamp,
    overall_coverage_percent      double precision                    not null,
    submission_ready              boolean                             not null,
    source_verified_case_count    integer                             not null,
    source_evaluation_case_count  integer                             not null,
    verified_metric_count         integer                             not null,
    replay_coverage_rate          double precision                    not null,
    assurance_coverage_rate       double precision                    not null,
    verification_schema_version   varchar(120),
    evaluation_schema_version     varchar(120),
    methodology_version           varchar(120),
    sanitization_profile_version  varchar(120),
    suite_version                 varchar(120),
    last_verified_at              timestamp,
    scenario_families_json        text                                not null,
    missing_official_metrics_json text                                not null,
    available_source_reports_json text                                not null,
    created_at                    timestamp default CURRENT_TIMESTAMP not null,
    raw_summary_json              text      default '{}'::text        not null,
    raw_summary_keys_json         text      default '[]'::text        not null,
    raw_summary_field_count       integer   default 0                 not null,
    exploit_window_result_json    text      default '{}'::text        not null
);

alter table public.benchmark_run_ledger
    owner to contexa;

create index idx_benchmark_run_ledger_slug_generated
    on public.benchmark_run_ledger (slug asc, generated_at desc, created_at desc);

create table public.benchmark_run_case_link_ledger
(
    id                   bigint generated by default as identity
        primary key,
    benchmark_run_id     varchar(200)                        not null,
    evaluation_case_id   varchar(160)                        not null,
    verification_case_id varchar(160)                        not null,
    metric_code          varchar(32)                         not null,
    metric_category      varchar(120),
    request_id           varchar(160),
    source_run_id        varchar(128),
    measured_value       double precision                    not null,
    threshold_value      double precision                    not null,
    passed               boolean                             not null,
    publication_ready    boolean                             not null,
    suite_keys_json      text                                not null,
    failing_gates_json   text                                not null,
    metric_detail_url    text,
    evidence_detail_url  text,
    created_at           timestamp default CURRENT_TIMESTAMP not null,
    constraint uq_benchmark_run_case_link
        unique (benchmark_run_id, evaluation_case_id)
);

alter table public.benchmark_run_case_link_ledger
    owner to contexa;

create index idx_benchmark_case_link_run
    on public.benchmark_run_case_link_ledger (benchmark_run_id);

create index idx_benchmark_case_link_request
    on public.benchmark_run_case_link_ledger (request_id);

create index idx_benchmark_case_link_source_run
    on public.benchmark_run_case_link_ledger (source_run_id);

create index idx_benchmark_case_link_metric
    on public.benchmark_run_case_link_ledger (metric_code);

create table public.benchmark_claim_result_ledger
(
    id                            bigint generated by default as identity
        primary key,
    benchmark_run_id              varchar(200)                        not null,
    claim_key                     varchar(160)                        not null,
    title                         varchar(400)                        not null,
    score                         double precision                    not null,
    passed                        boolean                             not null,
    source_evaluation_case_count  integer                             not null,
    passing_evaluation_case_count integer                             not null,
    supporting_suites_json        text                                not null,
    supporting_metric_codes_json  text                                not null,
    failing_gates_json            text                                not null,
    created_at                    timestamp default CURRENT_TIMESTAMP not null,
    constraint uq_benchmark_claim_result
        unique (benchmark_run_id, claim_key)
);

alter table public.benchmark_claim_result_ledger
    owner to contexa;

create index idx_benchmark_claim_run
    on public.benchmark_claim_result_ledger (benchmark_run_id);

create table public.benchmark_facet_result_ledger
(
    id                             bigint generated by default as identity
        primary key,
    benchmark_run_id               varchar(200)                        not null,
    facet_key                      varchar(160)                        not null,
    title                          varchar(400)                        not null,
    matching_claim_count           integer                             not null,
    matching_evaluation_case_count integer                             not null,
    average_score                  double precision                    not null,
    publication_ready              boolean                             not null,
    created_at                     timestamp default CURRENT_TIMESTAMP not null,
    constraint uq_benchmark_facet_result
        unique (benchmark_run_id, facet_key)
);

alter table public.benchmark_facet_result_ledger
    owner to contexa;

create index idx_benchmark_facet_run
    on public.benchmark_facet_result_ledger (benchmark_run_id);

create table public.benchmark_suite_result_ledger
(
    id                    bigint generated by default as identity
        primary key,
    benchmark_run_id      varchar(200)                        not null,
    suite_key             varchar(160)                        not null,
    title                 varchar(400)                        not null,
    evaluation_case_count integer                             not null,
    passing_case_count    integer                             not null,
    average_score         double precision                    not null,
    passed                boolean                             not null,
    created_at            timestamp default CURRENT_TIMESTAMP not null,
    constraint uq_benchmark_suite_result
        unique (benchmark_run_id, suite_key)
);

alter table public.benchmark_suite_result_ledger
    owner to contexa;

create index idx_benchmark_suite_run
    on public.benchmark_suite_result_ledger (benchmark_run_id);

create table public.benchmark_scenario_result_ledger
(
    id               bigint generated by default as identity
        primary key,
    benchmark_run_id varchar(200)                        not null,
    scenario_key     varchar(255)                        not null,
    label            varchar(400)                        not null,
    category         varchar(160),
    actual           double precision                    not null,
    expected         double precision                    not null,
    delta            double precision                    not null,
    passed           boolean                             not null,
    claim_keys_json  text                                not null,
    suite_keys_json  text                                not null,
    deviation_class  varchar(120),
    created_at       timestamp default CURRENT_TIMESTAMP not null,
    constraint uq_benchmark_scenario_result
        unique (benchmark_run_id, scenario_key)
);

alter table public.benchmark_scenario_result_ledger
    owner to contexa;

create index idx_benchmark_scenario_run
    on public.benchmark_scenario_result_ledger (benchmark_run_id);

create table public.benchmark_trend_point_ledger
(
    id                            bigint generated by default as identity
        primary key,
    benchmark_run_id              varchar(200)                        not null,
    sequence_no                   integer                             not null,
    label                         varchar(255)                        not null,
    generated_at                  timestamp,
    version_marker                varchar(120),
    milestone_label               varchar(120),
    source_label                  varchar(120),
    coverage_percent              double precision                    not null,
    passing_official_metric_count integer                             not null,
    failing_official_metric_count integer                             not null,
    delta_from_previous           double precision,
    created_at                    timestamp default CURRENT_TIMESTAMP not null,
    constraint uq_benchmark_trend_point
        unique (benchmark_run_id, sequence_no)
);

alter table public.benchmark_trend_point_ledger
    owner to contexa;

create index idx_benchmark_trend_run
    on public.benchmark_trend_point_ledger (benchmark_run_id, sequence_no);

create table public.benchmark_official_metric_ledger
(
    id               bigint generated by default as identity
        primary key,
    benchmark_run_id varchar(200)                        not null,
    metric_code      varchar(64)                         not null,
    name             varchar(255)                        not null,
    category         varchar(160),
    mean             double precision                    not null,
    threshold_value  double precision                    not null,
    higher_is_better boolean                             not null,
    stability_class  varchar(120),
    passed           boolean                             not null,
    official         boolean                             not null,
    created_at       timestamp default CURRENT_TIMESTAMP not null,
    constraint uq_benchmark_official_metric
        unique (benchmark_run_id, metric_code)
);

alter table public.benchmark_official_metric_ledger
    owner to contexa;

create index idx_benchmark_official_metric_run
    on public.benchmark_official_metric_ledger (benchmark_run_id);

create table public.published_benchmark_release_artifact
(
    id                   bigint generated by default as identity
        primary key,
    release_id           bigint                              not null,
    artifact_type        varchar(64)                         not null,
    artifact_name        varchar(255)                        not null,
    content_type         varchar(120)                        not null,
    artifact_text        text,
    artifact_base64_text text,
    artifact_sha256      text,
    created_at           timestamp default CURRENT_TIMESTAMP not null,
    constraint uq_published_benchmark_release_artifact
        unique (release_id, artifact_type)
);

alter table public.published_benchmark_release_artifact
    owner to contexa;

create index idx_published_benchmark_release_artifact_release
    on public.published_benchmark_release_artifact (release_id, artifact_type);

create table public.benchmark_exposure_case_ledger
(
    id                               bigint generated by default as identity
        primary key,
    benchmark_run_id                 varchar(200)                        not null,
    signal_id                        varchar(200)                        not null,
    signal_title                     varchar(400),
    source_system                    varchar(160),
    signal_type                      varchar(160),
    severity                         varchar(120),
    priority                         varchar(120),
    detected_at                      timestamp,
    enforced_at                      timestamp,
    signal_to_control_latency_millis bigint                              not null,
    correlated_subject_count         integer                             not null,
    correlated_execution_count       integer                             not null,
    correlated_permit_count          integer                             not null,
    applied_control_count            integer                             not null,
    active_restriction_count         integer                             not null,
    session_subject_count            integer                             not null,
    workload_subject_count           integer                             not null,
    agent_subject_count              integer                             not null,
    control_applied                  boolean                             not null,
    containment_ready                boolean                             not null,
    permit_continuity_preserved      boolean                             not null,
    proof_complete                   boolean                             not null,
    action_types_json                text                                not null,
    created_at                       timestamp default CURRENT_TIMESTAMP not null,
    constraint uq_benchmark_exposure_case
        unique (benchmark_run_id, signal_id)
);

alter table public.benchmark_exposure_case_ledger
    owner to contexa;

create index idx_benchmark_exposure_case_run
    on public.benchmark_exposure_case_ledger (benchmark_run_id);

create index idx_benchmark_exposure_case_signal
    on public.benchmark_exposure_case_ledger (signal_id);

create table public.benchmark_publication_bundle
(
    id             bigint generated by default as identity
        primary key,
    slug           varchar(200)                                         not null,
    source_kind    varchar(64) default 'FIRST_PARTY'::character varying not null,
    current_status varchar(40)                                          not null,
    changed_by     varchar(160),
    note           text,
    changed_at     timestamp                                            not null,
    published_at   timestamp,
    created_at     timestamp   default CURRENT_TIMESTAMP                not null,
    updated_at     timestamp   default CURRENT_TIMESTAMP                not null,
    constraint uq_benchmark_publication_bundle_slug_source
        unique (slug, source_kind)
);

alter table public.benchmark_publication_bundle
    owner to contexa;

create index idx_benchmark_publication_bundle_status
    on public.benchmark_publication_bundle (source_kind asc, current_status asc, changed_at desc);

create index idx_benchmark_publication_bundle_slug
    on public.benchmark_publication_bundle (slug asc, changed_at desc);

create table public.benchmark_certification_profile_projection
(
    id                      bigint generated by default as identity
        primary key,
    profile_key             varchar(120) not null
        constraint uq_benchmark_certification_profile_projection_key
            unique,
    title                   varchar(255) not null,
    summary_text            text,
    required_signals_json   text         not null,
    ready                   boolean      not null,
    matching_report_count   integer      not null,
    matching_slugs_json     text         not null,
    latest_mapped_report    varchar(200),
    mapped_claim_keys_json  text         not null,
    mapped_suite_keys_json  text         not null,
    readiness_basis         text,
    evidence_status_details text,
    profile_note            text,
    updated_at              timestamp    not null
);

alter table public.benchmark_certification_profile_projection
    owner to contexa;

create index idx_benchmark_certification_profile_projection_ready
    on public.benchmark_certification_profile_projection (ready asc, updated_at desc);

create table public.benchmark_publication_bundle_artifact
(
    id                   bigint generated by default as identity
        primary key,
    bundle_id            bigint       not null
        constraint fk_benchmark_publication_bundle_artifact_bundle
            references public.benchmark_publication_bundle
            on delete cascade,
    artifact_type        varchar(64)  not null,
    artifact_name        varchar(255) not null,
    content_type         varchar(120) not null,
    artifact_text        text,
    artifact_base64_text text,
    artifact_sha256      text,
    created_at           timestamp    not null,
    updated_at           timestamp    not null,
    constraint uq_benchmark_publication_bundle_artifact
        unique (bundle_id, artifact_type)
);

alter table public.benchmark_publication_bundle_artifact
    owner to contexa;

create index idx_benchmark_publication_bundle_artifact_bundle
    on public.benchmark_publication_bundle_artifact (bundle_id, artifact_type);

create table public.verification_run_round_ledger
(
    id                 bigint generated by default as identity
        primary key,
    run_id             varchar(128)                        not null
        constraint fk_verification_run_round_ledger_run
            references public.verification_run_ledger (run_id)
            on delete cascade,
    round_no           integer                             not null,
    endpoint_key       varchar(80),
    endpoint_label     varchar(255),
    score              double precision,
    passed_checks      integer,
    total_checks       integer,
    processing_time_ms bigint,
    state              varchar(80),
    state_tone         varchar(80),
    message            text,
    started_at         timestamp,
    completed_at       timestamp,
    created_at         timestamp default CURRENT_TIMESTAMP not null,
    constraint uq_verification_run_round_ledger
        unique (run_id, round_no)
);

alter table public.verification_run_round_ledger
    owner to contexa;

create index idx_verification_run_round_ledger_run
    on public.verification_run_round_ledger (run_id, round_no);

create table public.verification_run_check_ledger
(
    id                        bigint generated by default as identity
        primary key,
    run_id                    varchar(128)                        not null
        constraint fk_verification_run_check_ledger_run
            references public.verification_run_ledger (run_id)
            on delete cascade,
    round_no                  integer,
    sequence_no               integer                             not null,
    label                     varchar(255)                        not null,
    expected_value            text,
    actual_value              text,
    pass                      boolean                             not null,
    source                    varchar(255),
    created_at                timestamp default CURRENT_TIMESTAMP not null,
    check_code                varchar(128),
    severity                  varchar(32),
    failure_type              varchar(80),
    remediation_owner         varchar(128),
    operator_reason           text,
    next_action               text,
    reverify_criterion        text,
    operator_title            varchar(255),
    operator_summary          text,
    problem_statement         text,
    root_cause                text,
    affected_target           varchar(256),
    evidence_summary          text,
    expected_result           text,
    actual_result             text,
    impact                    text,
    customer_visible_severity varchar(64),
    related_process_step      varchar(128),
    constraint uq_verification_run_check_ledger
        unique (run_id, round_no, sequence_no)
);

alter table public.verification_run_check_ledger
    owner to contexa;

create index idx_verification_run_check_ledger_run
    on public.verification_run_check_ledger (run_id, round_no, sequence_no);

create index idx_verification_run_check_ledger_code
    on public.verification_run_check_ledger (run_id, check_code);

create index idx_verification_run_check_ledger_customer_severity
    on public.verification_run_check_ledger (run_id, customer_visible_severity);

create table public.verification_run_fact_ledger
(
    id               bigint generated by default as identity
        primary key,
    run_id           varchar(128)                        not null
        constraint fk_verification_run_fact_ledger_run
            references public.verification_run_ledger (run_id)
            on delete cascade,
    round_no         integer,
    fact_type        varchar(32)                         not null,
    fact_key         varchar(255)                        not null,
    fact_value       text,
    created_at       timestamp default CURRENT_TIMESTAMP not null,
    fact_value_jsonb jsonb,
    constraint uq_verification_run_fact_ledger
        unique (run_id, round_no, fact_type, fact_key)
);

alter table public.verification_run_fact_ledger
    owner to contexa;

create index idx_verification_run_fact_ledger_run
    on public.verification_run_fact_ledger (run_id, round_no, fact_type);

create index idx_verification_run_fact_ledger_jsonb
    on public.verification_run_fact_ledger using gin (fact_value_jsonb);

create table public.verification_run_event_ledger
(
    id           bigint generated by default as identity
        primary key,
    run_id       varchar(128)                        not null
        constraint fk_verification_run_event_ledger_run
            references public.verification_run_ledger (run_id)
            on delete cascade,
    round_no     integer,
    sequence_no  integer                             not null,
    event_type   varchar(255),
    layer        varchar(120),
    event_status varchar(120),
    request_path text,
    created_at   timestamp default CURRENT_TIMESTAMP not null,
    constraint uq_verification_run_event_ledger
        unique (run_id, round_no, sequence_no)
);

alter table public.verification_run_event_ledger
    owner to contexa;

create index idx_verification_run_event_ledger_run
    on public.verification_run_event_ledger (run_id, round_no, sequence_no);

create table public.verification_raw_evidence_artifact_ledger
(
    id                  bigint generated by default as identity
        primary key,
    run_id              varchar(128)                        not null
        constraint fk_verification_raw_evidence_artifact_ledger_run
            references public.verification_run_ledger (run_id)
            on delete cascade,
    artifact_type       varchar(64)                         not null,
    content_type        varchar(120)                        not null,
    artifact_body       text                                not null,
    sha256              varchar(128),
    created_at          timestamp default CURRENT_TIMESTAMP not null,
    artifact_body_jsonb jsonb,
    constraint uq_verification_raw_evidence_artifact_ledger
        unique (run_id, artifact_type)
);

alter table public.verification_raw_evidence_artifact_ledger
    owner to contexa;

create index idx_verification_raw_evidence_artifact_ledger_run
    on public.verification_raw_evidence_artifact_ledger (run_id, artifact_type);

create index idx_verification_raw_evidence_artifact_jsonb
    on public.verification_raw_evidence_artifact_ledger using gin (artifact_body_jsonb);

create table public.benchmark_public_site_projection
(
    id               bigint generated by default as identity
        primary key,
    projection_scope varchar(160) not null
        constraint uq_benchmark_public_site_projection_scope
            unique,
    projection_type  varchar(64)  not null,
    payload_json     text         not null,
    updated_at       timestamp    not null
);

alter table public.benchmark_public_site_projection
    owner to contexa;

create index idx_benchmark_public_site_projection_type
    on public.benchmark_public_site_projection (projection_type asc, updated_at desc);

create table public.demo_verification_linkage_ledger
(
    id                                bigserial
        primary key,
    demo_session_id                   varchar(128)             not null,
    demo_request_id                   varchar(128)             not null,
    lane                              varchar(32)              not null,
    demo_scenario                     varchar(120),
    user_public_id                    varchar(120)             not null,
    result_code                       varchar(120)             not null,
    metric_code                       varchar(32)              not null,
    metric_title                      varchar(255),
    verification_execution_request_id varchar(128),
    verification_run_id               varchar(128),
    verification_request_id           varchar(128),
    benchmark_slug                    varchar(255),
    publication_url                   text,
    evidence_url                      text,
    run_url                           text,
    state                             varchar(64)              not null,
    score                             double precision,
    created_at                        timestamp with time zone not null,
    updated_at                        timestamp with time zone not null
);

alter table public.demo_verification_linkage_ledger
    owner to contexa;

create unique index uq_demo_verification_linkage_ledger_metric
    on public.demo_verification_linkage_ledger (demo_request_id, metric_code);

create index idx_demo_verification_linkage_ledger_session
    on public.demo_verification_linkage_ledger (demo_session_id asc, updated_at desc);

create index idx_demo_verification_linkage_ledger_user
    on public.demo_verification_linkage_ledger (user_public_id asc, result_code asc, updated_at desc);

create table public.demo_result_lookup_ledger
(
    id                        bigserial
        primary key,
    demo_session_id           varchar(128)             not null,
    user_public_id            varchar(120)             not null,
    result_code               varchar(120)             not null,
    persona_id                varchar(120),
    target_level              varchar(64),
    self_request_id           varchar(128),
    attack_request_id         varchar(128),
    latest_verdict            varchar(64),
    latest_verification_state varchar(64),
    latest_benchmark_state    varchar(64),
    latest_public_report_url  text,
    created_at                timestamp with time zone not null,
    updated_at                timestamp with time zone not null
);

alter table public.demo_result_lookup_ledger
    owner to contexa;

create unique index uq_demo_result_lookup_ledger_session
    on public.demo_result_lookup_ledger (demo_session_id);

create unique index uq_demo_result_lookup_ledger_user_result
    on public.demo_result_lookup_ledger (user_public_id, result_code);

create index idx_demo_result_lookup_ledger_user
    on public.demo_result_lookup_ledger (user_public_id asc, updated_at desc);

create table public.prompt_quality_certificate_ledger
(
    id                               bigserial
        primary key,
    certificate_id                   varchar(128)                                                          not null,
    state                            varchar(64)                                                           not null,
    state_label                      varchar(128)                                                          not null,
    usable_for_llm_zero_trust        boolean                                                               not null,
    zero_trust_state                 varchar(64)                                                           not null,
    zero_trust_state_label           varchar(128)                                                          not null,
    resource_operational_state       varchar(64)  default 'PENDING_VERIFICATION'::character varying        not null,
    resource_operational_state_label varchar(128) default '검증 대기'::character varying                       not null,
    issued_at                        varchar(64),
    tenant_id                        varchar(128) default 'default'::character varying                     not null,
    scope_hash                       varchar(128)                                                          not null,
    prompt_contract_version          varchar(128) default 'official-prompt-contract-v1'::character varying not null,
    model_profile                    varchar(128) default 'default-model-profile'::character varying       not null,
    verifier_version                 varchar(128) default 'official-verifier-v1'::character varying        not null,
    expires_at                       timestamp,
    revoked_at                       timestamp,
    revoked_by                       varchar(255),
    revocation_reason                varchar(1000),
    prompt_hash                      varchar(128),
    system_prompt_hash               varchar(128),
    user_prompt_hash                 varchar(128),
    context_hash                     varchar(128),
    evidence_request_ids_json        text,
    run_ids_json                     text,
    resource_key                     varchar(600)                                                          not null,
    resource_url                     varchar(1000)                                                         not null,
    resource_id                      varchar(255)                                                          not null,
    http_method                      varchar(32)                                                           not null,
    protectable_method               varchar(1000),
    criticality                      varchar(64),
    verification_required            boolean                                                               not null,
    total_metric_count               integer                                                               not null,
    verified_metric_count            integer                                                               not null,
    failed_metric_count              integer                                                               not null,
    missing_metric_count             integer                                                               not null,
    summary                          varchar(3000),
    blocking_findings_json           text,
    six_w_json                       text,
    issue_case_json                  text,
    evidence_lineage_json            text,
    remediation_loop_json            text,
    metrics_json                     text,
    recommended_actions_json         text,
    recorded_at                      timestamp                                                             not null,
    evidence_source_type             varchar(64)                                                           not null,
    runtime_decision_hash            varchar(128),
    runtime_prompt_hash              varchar(128),
    runtime_system_prompt_hash       varchar(128),
    runtime_user_prompt_hash         varchar(128),
    sealed_evidence_package_id       varchar(160)
);

alter table public.prompt_quality_certificate_ledger
    owner to contexa;

create unique index idx_pqc_ledger_certificate
    on public.prompt_quality_certificate_ledger (certificate_id);

create index idx_pqc_ledger_scope_latest
    on public.prompt_quality_certificate_ledger (scope_hash asc, recorded_at desc);

create index idx_pqc_ledger_tenant_scope_latest
    on public.prompt_quality_certificate_ledger (tenant_id asc, scope_hash asc, recorded_at desc);

create index idx_pqc_ledger_resource_latest
    on public.prompt_quality_certificate_ledger (resource_key asc, recorded_at desc);

create index idx_pqc_ledger_resource_id_latest
    on public.prompt_quality_certificate_ledger (resource_id asc, recorded_at desc);

create index idx_pqc_ledger_tenant_resource_method_latest
    on public.prompt_quality_certificate_ledger (tenant_id asc, resource_id asc, http_method asc, recorded_at desc);

create index idx_pqc_ledger_zero_trust
    on public.prompt_quality_certificate_ledger (zero_trust_state asc, recorded_at desc);

create index idx_pqc_ledger_operational_state
    on public.prompt_quality_certificate_ledger (resource_operational_state asc, recorded_at desc);

create index idx_pqc_ledger_sealed_source
    on public.prompt_quality_certificate_ledger (evidence_source_type, sealed_evidence_package_id, recorded_at);

create table public.protectable_resource_registry
(
    id                        bigserial
        primary key,
    tenant_id                 varchar(128) default 'default'::character varying              not null,
    resource_id               varchar(255)                                                   not null,
    resource_url              varchar(1000)                                                  not null,
    http_method               varchar(32)                                                    not null,
    criticality               varchar(64),
    verification_required     boolean      default true                                      not null,
    sync_enabled              boolean      default false                                     not null,
    owner_field               varchar(255),
    bean_name                 varchar(255),
    method_identifier         varchar(1000),
    source_class_name         varchar(1000),
    source_method_name        varchar(255),
    annotation_signature_hash varchar(128)                                                   not null,
    certificate_state         varchar(64)  default 'REVIEW_REQUIRED'::character varying      not null,
    operational_state         varchar(64)  default 'PENDING_VERIFICATION'::character varying not null,
    latest_certificate_id     varchar(128),
    last_verified_at          timestamp,
    signature_changed_at      timestamp,
    discovered_at             timestamp                                                      not null,
    updated_at                timestamp                                                      not null,
    retired                   boolean      default false                                     not null
);

alter table public.protectable_resource_registry
    owner to contexa;

create unique index idx_prr_scope
    on public.protectable_resource_registry (tenant_id, resource_id, http_method);

create index idx_prr_url_method
    on public.protectable_resource_registry (tenant_id, resource_url, http_method);

create index idx_prr_operational_state
    on public.protectable_resource_registry (tenant_id asc, operational_state asc, updated_at desc);

create index idx_prr_signature
    on public.protectable_resource_registry (tenant_id, annotation_signature_hash);

create table public.prompt_quality_certificate_audit_event
(
    id             bigserial
        primary key,
    event_id       varchar(128) not null
        unique,
    event_type     varchar(128) not null,
    actor          varchar(255) not null,
    tenant_id      varchar(128) not null,
    certificate_id varchar(128),
    scope_hash     varchar(128),
    resource_url   varchar(1000),
    resource_id    varchar(255),
    http_method    varchar(32),
    previous_state varchar(128),
    next_state     varchar(128),
    reason         varchar(3000),
    recorded_at    timestamp    not null
);

alter table public.prompt_quality_certificate_audit_event
    owner to contexa;

create index idx_pqc_audit_tenant_time
    on public.prompt_quality_certificate_audit_event (tenant_id asc, recorded_at desc);

create index idx_pqc_audit_certificate
    on public.prompt_quality_certificate_audit_event (certificate_id asc, recorded_at desc);

create index idx_pqc_audit_scope
    on public.prompt_quality_certificate_audit_event (scope_hash asc, recorded_at desc);

create index idx_pqc_audit_type
    on public.prompt_quality_certificate_audit_event (event_type asc, recorded_at desc);

create table public.prompt_quality_issue_case
(
    id                       bigserial
        primary key,
    case_id                  varchar(128)      not null
        unique,
    certificate_id           varchar(128),
    source_type              varchar(64)       not null,
    tenant_id                varchar(128)      not null,
    scope_hash               varchar(128),
    resource_url             varchar(1000),
    http_method              varchar(32),
    resource_id              varchar(255),
    state                    varchar(64)       not null,
    symptom                  varchar(3000),
    expected_outcome         varchar(3000),
    actual_outcome           varchar(3000),
    evidence_package_id      varchar(255),
    recurrence_count         integer default 0 not null,
    findings_json            text,
    recommended_actions_json text,
    opened_at                timestamp         not null,
    updated_at               timestamp         not null
);

alter table public.prompt_quality_issue_case
    owner to contexa;

create index idx_pqc_issue_tenant_state
    on public.prompt_quality_issue_case (tenant_id asc, state asc, updated_at desc);

create index idx_pqc_issue_scope
    on public.prompt_quality_issue_case (scope_hash asc, updated_at desc);

create index idx_pqc_issue_resource
    on public.prompt_quality_issue_case (tenant_id asc, resource_id asc, http_method asc, updated_at desc);

create table public.prompt_quality_evidence_bundle
(
    id                           bigserial
        primary key,
    bundle_id                    varchar(128)                                      not null
        unique,
    source_type                  varchar(64)                                       not null,
    source_label                 varchar(255),
    tenant_id                    varchar(128) default 'default'::character varying not null,
    subject_user_id              varchar(255),
    resource_url                 varchar(1000)                                     not null,
    resource_id                  varchar(255),
    http_method                  varchar(32)                                       not null,
    source_request_context_json  text,
    learned_contexts_json        text,
    current_request_context_json text,
    final_prompt_evidence_json   text,
    readiness_state              varchar(64)                                       not null
        constraint prompt_quality_evidence_bundle_readiness_state_check
            check ((readiness_state)::text = ANY
                   ((ARRAY ['READY'::character varying, 'BLOCKED'::character varying])::text[])),
    readiness_summary            varchar(3000),
    findings_json                text,
    prompt_hash                  varchar(128),
    context_hash                 varchar(128),
    created_at                   timestamp                                         not null,
    learning_evidence_json       text,
    metadata_json                text
);

alter table public.prompt_quality_evidence_bundle
    owner to contexa;

create index idx_pqa_evidence_bundle_scope
    on public.prompt_quality_evidence_bundle (tenant_id asc, resource_id asc, http_method asc, created_at desc);

create index idx_pqa_evidence_bundle_resource
    on public.prompt_quality_evidence_bundle (tenant_id asc, resource_url asc, http_method asc, created_at desc);

create table public.prompt_quality_recipe
(
    id             bigserial
        primary key,
    recipe_id      varchar(128)                                      not null
        unique,
    tenant_id      varchar(128) default 'default'::character varying not null,
    recipe_name    varchar(255)                                      not null,
    active_version varchar(128),
    approval_state varchar(64)  default 'DRAFT'::character varying   not null,
    plain_purpose  varchar(3000),
    created_at     timestamp                                         not null,
    updated_at     timestamp                                         not null
);

alter table public.prompt_quality_recipe
    owner to contexa;

create table public.prompt_quality_recipe_version
(
    id                      bigserial
        primary key,
    recipe_id               varchar(128)                                      not null,
    version_id              varchar(128)                                      not null,
    tenant_id               varchar(128) default 'default'::character varying not null,
    system_prompt_hash      varchar(128),
    user_prompt_hash        varchar(128),
    prompt_contract_version varchar(128),
    recipe_json             text,
    change_summary          varchar(3000),
    created_at              timestamp                                         not null,
    unique (recipe_id, version_id)
);

alter table public.prompt_quality_recipe_version
    owner to contexa;

create table public.prompt_assembly_trace
(
    id                  bigserial
        primary key,
    trace_id            varchar(128)                                      not null
        unique,
    bundle_id           varchar(128),
    tenant_id           varchar(128) default 'default'::character varying not null,
    resource_url        varchar(1000),
    resource_id         varchar(255),
    http_method         varchar(32),
    prompt_hash         varchar(128),
    context_hash        varchar(128),
    trace_json          text,
    omitted_fields_json text,
    plain_summary       varchar(3000),
    created_at          timestamp                                         not null
);

alter table public.prompt_assembly_trace
    owner to contexa;

create index idx_pqa_assembly_trace_bundle
    on public.prompt_assembly_trace (bundle_id asc, created_at desc);

create index idx_pqa_assembly_trace_prompt
    on public.prompt_assembly_trace (prompt_hash asc, created_at desc);

create table public.prompt_quality_metric_result
(
    id             bigserial
        primary key,
    result_id      varchar(128)                                      not null
        unique,
    run_id         varchar(128),
    bundle_id      varchar(128),
    certificate_id varchar(128),
    tenant_id      varchar(128) default 'default'::character varying not null,
    metric_code    varchar(32)                                       not null,
    metric_name    varchar(255),
    metric_group   varchar(128),
    status         varchar(64)                                       not null,
    score          numeric(10, 4),
    threshold      numeric(10, 4),
    risk           varchar(3000),
    next_action    varchar(3000),
    evidence_route varchar(1000),
    created_at     timestamp                                         not null
);

alter table public.prompt_quality_metric_result
    owner to contexa;

create index idx_pqa_metric_result_run
    on public.prompt_quality_metric_result (run_id, metric_code);

create index idx_pqa_metric_result_certificate
    on public.prompt_quality_metric_result (certificate_id, metric_code);

create table public.prompt_quality_issue
(
    id                         bigserial
        primary key,
    issue_id                   varchar(256)                                      not null
        unique,
    tenant_id                  varchar(256) default 'default'::character varying not null,
    bundle_id                  varchar(256),
    run_id                     varchar(256),
    certificate_id             varchar(256),
    metric_code                varchar(32),
    severity                   varchar(64)                                       not null,
    issue_title                varchar(255)                                      not null,
    plain_problem              varchar(3000),
    llm_judgement_risk         varchar(3000),
    remediation_target         varchar(1000),
    next_action                varchar(3000),
    prompt_hash                varchar(256),
    context_hash               varchar(256),
    issue_state                varchar(64)  default 'OPEN'::character varying    not null,
    detected_at                timestamp                                         not null,
    resolved_at                timestamp,
    failed_package_id          varchar(256),
    evidence_ref               varchar(1000),
    expected_effect            varchar(3000),
    re_request_method          varchar(3000),
    package_id                 varchar(256),
    aggregate_run_id           varchar(256),
    official_run_id            varchar(256),
    failed_check               varchar(500),
    expected_value             varchar(3000),
    actual_value               varchar(3000),
    evidence_source            varchar(3000),
    prompt_location            varchar(500),
    root_cause_type            varchar(256),
    production_target_type     varchar(256),
    production_target_ref      varchar(1000),
    production_change_kind     varchar(256),
    expected_prompt_delta_json text,
    reverify_criterion         varchar(3000),
    http_method                varchar(32)
);

alter table public.prompt_quality_issue
    owner to contexa;

create index idx_pqa_issue_metric_state
    on public.prompt_quality_issue (tenant_id asc, metric_code asc, issue_state asc, detected_at desc);

create index idx_pqa_issue_prompt_context
    on public.prompt_quality_issue (prompt_hash asc, context_hash asc, detected_at desc);

create index idx_pqa_issue_failed_package
    on public.prompt_quality_issue (failed_package_id asc, issue_state asc, detected_at desc);

create index idx_pqa_issue_handoff_package
    on public.prompt_quality_issue (package_id asc, aggregate_run_id asc, issue_state asc, detected_at desc);

create index idx_pqa_issue_handoff_target
    on public.prompt_quality_issue (root_cause_type asc, production_target_type asc, issue_state asc, detected_at desc);

create index idx_prompt_quality_issue_runtime_identity
    on public.prompt_quality_issue (package_id asc, http_method asc, issue_state asc, detected_at desc);

create table public.prompt_quality_remediation_action
(
    id                         bigserial
        primary key,
    action_id                  varchar(128)                                      not null
        unique,
    issue_id                   varchar(128),
    tenant_id                  varchar(128) default 'default'::character varying not null,
    target_type                varchar(128)                                      not null,
    target_ref                 varchar(1000),
    action_state               varchar(64)                                       not null,
    plain_problem              varchar(3000),
    plain_action               varchar(3000),
    reverify_criterion         varchar(3000),
    created_at                 timestamp                                         not null,
    updated_at                 timestamp                                         not null,
    remediation_case_id        varchar(256),
    finding_ids_json           text,
    remediation_group_ids_json text,
    official_run_id            varchar(256),
    reverify_run_id            varchar(256),
    failed_package_id          varchar(256),
    fixed_package_id           varchar(256)
);

alter table public.prompt_quality_remediation_action
    owner to contexa;

create index idx_pqa_remediation_action_case
    on public.prompt_quality_remediation_action (remediation_case_id);

create index idx_pqa_remediation_action_reverify
    on public.prompt_quality_remediation_action (reverify_run_id);

create table public.prompt_quality_evaluation_run
(
    id                        bigserial
        primary key,
    evaluation_run_id         varchar(128)                                      not null
        unique,
    tenant_id                 varchar(128) default 'default'::character varying not null,
    source_type               varchar(128)                                      not null,
    prompt_contract_version   varchar(128),
    model_profile             varchar(128),
    passed_case_count         integer      default 0                            not null,
    failed_case_count         integer      default 0                            not null,
    token_before              integer      default 0                            not null,
    token_after               integer      default 0                            not null,
    latency_before_ms         bigint       default 0                            not null,
    latency_after_ms          bigint       default 0                            not null,
    subtle_anomaly_visibility varchar(3000),
    findings_json             text,
    created_at                timestamp                                         not null
);

alter table public.prompt_quality_evaluation_run
    owner to contexa;

create index idx_pqa_evaluation_run_tenant_time
    on public.prompt_quality_evaluation_run (tenant_id asc, created_at desc);

create table public.prompt_quality_policy
(
    id            bigserial
        primary key,
    policy_id     varchar(128)                                      not null
        unique,
    tenant_id     varchar(128) default 'default'::character varying not null,
    policy_type   varchar(128)                                      not null,
    policy_state  varchar(64)                                       not null,
    policy_json   text,
    plain_summary varchar(3000),
    created_at    timestamp                                         not null,
    updated_at    timestamp                                         not null
);

alter table public.prompt_quality_policy
    owner to contexa;

create index idx_pqa_policy_type
    on public.prompt_quality_policy (tenant_id, policy_type, policy_state);

create table public.prompt_quality_audit_event
(
    id                  bigserial
        primary key,
    event_id            varchar(128)                                      not null
        unique,
    tenant_id           varchar(128) default 'default'::character varying not null,
    action_type         varchar(128)                                      not null,
    actor               varchar(255)                                      not null,
    occurred_at         timestamp                                         not null,
    what_text           varchar(3000)                                     not null,
    why_text            varchar(3000)                                     not null,
    result_text         varchar(3000)                                     not null,
    related_reference   varchar(1000),
    evidence_bundle_id  varchar(128),
    recipe_id           varchar(128),
    verification_run_id varchar(128),
    issue_id            varchar(128),
    certificate_id      varchar(128),
    resource_id         varchar(255),
    policy_id           varchar(128)
);

alter table public.prompt_quality_audit_event
    owner to contexa;

create index idx_pqa_audit_event_tenant_time
    on public.prompt_quality_audit_event (tenant_id asc, occurred_at desc);

create index idx_pqa_audit_event_action
    on public.prompt_quality_audit_event (tenant_id asc, action_type asc, occurred_at desc);

create index idx_pqa_audit_event_certificate
    on public.prompt_quality_audit_event (tenant_id asc, certificate_id asc, occurred_at desc);

create index idx_pqa_audit_event_resource
    on public.prompt_quality_audit_event (tenant_id asc, resource_id asc, occurred_at desc);

create index idx_pqa_audit_event_policy
    on public.prompt_quality_audit_event (tenant_id asc, policy_id asc, occurred_at desc);

create table public.context_category_definition
(
    id            bigserial
        primary key,
    category_id   varchar(128)          not null
        unique,
    display_name  varchar(255)          not null,
    description   varchar(3000),
    icon_name     varchar(128),
    active        boolean default true  not null,
    deleted       boolean default false not null,
    built_in      boolean default false not null,
    display_order integer default 1000  not null,
    created_at    timestamp             not null,
    updated_at    timestamp             not null,
    created_by    varchar(255),
    updated_by    varchar(255)
);

alter table public.context_category_definition
    owner to contexa;

create index idx_context_category_state
    on public.context_category_definition (active, deleted, display_order);

create table public.context_definition_audit_event
(
    id           bigserial
        primary key,
    event_id     varchar(128)  not null
        unique,
    target_type  varchar(64)   not null,
    target_id    varchar(160)  not null,
    action_type  varchar(64)   not null,
    operator_id  varchar(255)  not null,
    message      varchar(3000) not null,
    details_json text,
    recorded_at  timestamp     not null
);

alter table public.context_definition_audit_event
    owner to contexa;

create index idx_context_definition_audit_target
    on public.context_definition_audit_event (target_type asc, target_id asc, recorded_at desc);

create table public.context_ui_schema_version
(
    id             bigserial
        primary key,
    schema_version varchar(128)         not null
        unique,
    description    varchar(3000),
    active         boolean default true not null,
    created_at     timestamp            not null
);

alter table public.context_ui_schema_version
    owner to contexa;

create table public.protectable_resource_overlay
(
    id                            bigserial
        primary key,
    tenant_id                     varchar(64)  not null,
    resource_id                   varchar(256) not null,
    http_method                   varchar(16)  not null,
    overlay_criticality           varchar(32),
    overlay_verification_required boolean,
    overlay_sync                  boolean,
    overlay_owner_field           varchar(128),
    overlay_resource_url          varchar(512),
    override_reason               text         not null,
    override_approver             varchar(128) not null,
    override_approved_at          timestamp    not null,
    override_expires_at           timestamp,
    created_at                    timestamp    not null,
    updated_at                    timestamp    not null,
    created_by                    varchar(255),
    updated_by                    varchar(255),
    constraint ux_protectable_overlay_scope
        unique (tenant_id, resource_id, http_method)
);

alter table public.protectable_resource_overlay
    owner to contexa;

create index idx_protectable_overlay_expiry
    on public.protectable_resource_overlay (override_expires_at);

create index idx_protectable_overlay_tenant_resource
    on public.protectable_resource_overlay (tenant_id, resource_id);

create table public.context_generation_preset_definition
(
    id            bigserial
        primary key,
    preset_code   varchar(128)         not null
        unique,
    title         varchar(255)         not null,
    description   varchar(3000),
    values_json   text,
    active        boolean default true not null,
    display_order integer default 1000 not null,
    created_at    timestamp            not null,
    updated_at    timestamp            not null
);

alter table public.context_generation_preset_definition
    owner to contexa;

create index idx_context_generation_preset_state
    on public.context_generation_preset_definition (active, display_order);

create table public.context_tuner_type_definition
(
    id                 bigserial
        primary key,
    type_id            varchar(64)                         not null
        unique,
    display_name       varchar(255)                        not null,
    description        varchar(3000),
    control_type       varchar(64)                         not null,
    default_value_json text,
    options_json       text,
    supported_min      integer,
    supported_max      integer,
    active             boolean   default true              not null,
    display_order      integer   default 1000              not null,
    created_at         timestamp default CURRENT_TIMESTAMP not null,
    updated_at         timestamp default CURRENT_TIMESTAMP not null,
    created_by         varchar(255),
    updated_by         varchar(255)
);

alter table public.context_tuner_type_definition
    owner to contexa;

create table public.context_field_definition
(
    id                 bigserial
        primary key,
    field_id           varchar(160)          not null
        unique,
    category_id        varchar(128)          not null
        constraint fk_context_field_category
            references public.context_category_definition (category_id),
    field_key          varchar(128)          not null,
    payload_path       varchar(500)          not null,
    field_label        varchar(255)          not null,
    help_text          varchar(3000),
    control_type       varchar(64)           not null,
    default_value_json text,
    options_json       text,
    min_value          integer,
    max_value          integer,
    step_value         integer,
    required           boolean default false not null,
    active             boolean default true  not null,
    deleted            boolean default false not null,
    built_in           boolean default false not null,
    dynamic            boolean default true  not null,
    display_order      integer default 1000  not null,
    created_at         timestamp             not null,
    updated_at         timestamp             not null,
    created_by         varchar(255),
    updated_by         varchar(255),
    type_id            varchar(64)
        constraint fk_context_field_type
            references public.context_tuner_type_definition (type_id)
            on delete set null
);

alter table public.context_field_definition
    owner to contexa;

create unique index ux_context_field_category_key
    on public.context_field_definition (category_id, field_key);

create index idx_context_field_category_state
    on public.context_field_definition (category_id, active, deleted, display_order);

create index idx_context_field_type
    on public.context_field_definition (type_id);

create index idx_context_type_active
    on public.context_tuner_type_definition (active, display_order);

create table public.context_source_mapping_rule
(
    id                  bigserial
        primary key,
    rule_id             varchar(64)                         not null
        unique,
    field_id            varchar(160)                        not null
        constraint fk_source_mapping_field
            references public.context_field_definition (field_id)
            on delete cascade,
    source_kind         varchar(32)                         not null,
    source_key          varchar(255)                        not null,
    extract_expression  varchar(1000),
    fallback_expression varchar(1000),
    required            boolean   default false             not null,
    active              boolean   default true              not null,
    display_order       integer   default 1000              not null,
    created_at          timestamp default CURRENT_TIMESTAMP not null,
    updated_at          timestamp default CURRENT_TIMESTAMP not null,
    created_by          varchar(255),
    updated_by          varchar(255)
);

alter table public.context_source_mapping_rule
    owner to contexa;

create index idx_source_mapping_field
    on public.context_source_mapping_rule (field_id);

create index idx_source_mapping_active
    on public.context_source_mapping_rule (active, display_order);

create table public.context_projection_rule
(
    id                    bigserial
        primary key,
    rule_id               varchar(64)                         not null
        unique,
    field_id              varchar(160)                        not null
        constraint fk_projection_rule_field
            references public.context_field_definition (field_id)
            on delete cascade,
    projection_kind       varchar(32)                         not null,
    projection_expression varchar(1000),
    section_key           varchar(128),
    priority              integer   default 100               not null,
    active                boolean   default true              not null,
    display_order         integer   default 1000              not null,
    created_at            timestamp default CURRENT_TIMESTAMP not null,
    updated_at            timestamp default CURRENT_TIMESTAMP not null,
    created_by            varchar(255),
    updated_by            varchar(255)
);

alter table public.context_projection_rule
    owner to contexa;

create index idx_projection_rule_field
    on public.context_projection_rule (field_id);

create index idx_projection_rule_active
    on public.context_projection_rule (active, priority);

create table public.context_tuner_layout_definition
(
    id           bigserial
        primary key,
    layout_id    varchar(64)                         not null
        unique,
    display_name varchar(255)                        not null,
    description  varchar(3000),
    layout_json  text                                not null,
    active       boolean   default true              not null,
    is_default   boolean   default false             not null,
    created_at   timestamp default CURRENT_TIMESTAMP not null,
    updated_at   timestamp default CURRENT_TIMESTAMP not null,
    created_by   varchar(255),
    updated_by   varchar(255)
);

alter table public.context_tuner_layout_definition
    owner to contexa;

create unique index idx_context_tuner_layout_default
    on public.context_tuner_layout_definition (is_default)
    where (is_default = true);

create index idx_context_tuner_layout_active
    on public.context_tuner_layout_definition (active, layout_id);

create table public.context_type_dictionary
(
    id               bigserial
        primary key,
    type_id          varchar(64)                         not null
        unique,
    display_name     varchar(255)                        not null,
    description      varchar(3000),
    category         varchar(64)                         not null,
    base_type        boolean   default true              not null,
    tenant_profile   varchar(128),
    industry_profile varchar(128),
    active           boolean   default true              not null,
    display_order    integer   default 1000              not null,
    created_at       timestamp default CURRENT_TIMESTAMP not null,
    updated_at       timestamp default CURRENT_TIMESTAMP not null,
    created_by       varchar(255),
    updated_by       varchar(255)
);

alter table public.context_type_dictionary
    owner to contexa;

create index idx_cge_type_category
    on public.context_type_dictionary (category, active);

create table public.context_dimension_definition
(
    id                    bigserial
        primary key,
    dimension_id          varchar(80)                                       not null
        unique,
    display_name          varchar(255)                                      not null,
    technical_name        varchar(160)                                      not null,
    category              varchar(64)                                       not null,
    data_type             varchar(32)                                       not null,
    required_level        varchar(16) default 'OPTIONAL'::character varying not null,
    sensitivity           varchar(32) default 'NORMAL'::character varying   not null,
    normal_range_json     text,
    variation_policy_json text,
    anomaly_policy_json   text,
    prompt_visibility     varchar(32) default 'VISIBLE'::character varying  not null,
    redaction_policy      varchar(64),
    source                varchar(64),
    owner                 varchar(64),
    active                boolean     default true                          not null,
    display_order         integer     default 1000                          not null,
    created_at            timestamp   default CURRENT_TIMESTAMP             not null,
    updated_at            timestamp   default CURRENT_TIMESTAMP             not null,
    created_by            varchar(255),
    updated_by            varchar(255)
);

alter table public.context_dimension_definition
    owner to contexa;

create index idx_cge_dimension_category
    on public.context_dimension_definition (category, active);

create table public.context_scenario_definition
(
    id                               bigserial
        primary key,
    scenario_id                      varchar(96)                                    not null
        unique,
    scenario_name                    varchar(255)                                   not null,
    tenant_profile                   varchar(128),
    industry_profile                 varchar(128),
    infrastructure_profile           varchar(128),
    resource_profile                 varchar(128),
    user_profile                     varchar(128),
    normal_pattern_json              text,
    learning_variation_plan_json     text,
    subtle_anomaly_plan_json         text,
    expected_context_dimensions_json text,
    expected_prompt_visibility_json  text,
    quality_targets_json             text,
    known_failure_modes_json         text,
    version                          varchar(32) default '1.0.0'::character varying not null,
    status                           varchar(16) default 'DRAFT'::character varying not null,
    created_at                       timestamp   default CURRENT_TIMESTAMP          not null,
    updated_at                       timestamp   default CURRENT_TIMESTAMP          not null,
    created_by                       varchar(255),
    updated_by                       varchar(255)
);

alter table public.context_scenario_definition
    owner to contexa;

create index idx_cge_scenario_status
    on public.context_scenario_definition (status, scenario_id);

create table public.context_generation_profile
(
    id                     bigserial
        primary key,
    profile_id             varchar(96)                         not null
        unique,
    display_name           varchar(255)                        not null,
    tenant_profile         varchar(128),
    industry_profile       varchar(128),
    infrastructure_profile varchar(128),
    description            varchar(3000),
    active                 boolean   default true              not null,
    created_at             timestamp default CURRENT_TIMESTAMP not null,
    updated_at             timestamp default CURRENT_TIMESTAMP not null,
    created_by             varchar(255),
    updated_by             varchar(255)
);

alter table public.context_generation_profile
    owner to contexa;

create table public.generated_request_context
(
    id                      bigserial
        primary key,
    request_context_id      varchar(96)                                     not null
        unique,
    tenant_id               varchar(128),
    subject_user_id         varchar(160),
    resource_url            varchar(512),
    resource_id             varchar(160),
    http_method             varchar(16),
    resource_sensitivity    varchar(32),
    scenario_id             varchar(96),
    payload_json            text,
    dimension_coverage_json text,
    generator_version       varchar(32),
    origin                  varchar(32) default 'MANUAL'::character varying not null,
    created_at              timestamp   default CURRENT_TIMESTAMP           not null,
    created_by              varchar(255)
);

alter table public.generated_request_context
    owner to contexa;

create index idx_cge_request_scenario
    on public.generated_request_context (scenario_id, created_at);

create table public.generated_learning_context_set
(
    id                        bigserial
        primary key,
    set_id                    varchar(96)                         not null
        unique,
    source_request_context_id varchar(96)                         not null,
    tenant_id                 varchar(128),
    subject_user_id           varchar(160),
    scenario_id               varchar(96),
    required_count            integer   default 20                not null,
    generated_count           integer   default 0                 not null,
    baseline_evidence_json    text,
    rag_evidence_json         text,
    variation_summary_json    text,
    coverage_summary_json     text,
    quality_summary_json      text,
    generator_version         varchar(32),
    created_at                timestamp default CURRENT_TIMESTAMP not null,
    updated_at                timestamp default CURRENT_TIMESTAMP not null,
    created_by                varchar(255)
);

alter table public.generated_learning_context_set
    owner to contexa;

create index idx_cge_learning_set_source
    on public.generated_learning_context_set (source_request_context_id);

create table public.generated_learning_context_sample
(
    id                    bigserial
        primary key,
    sample_id             varchar(128)                        not null
        unique,
    set_id                varchar(96)                         not null
        constraint fk_cge_sample_set
            references public.generated_learning_context_set (set_id)
            on delete cascade,
    cycle                 integer                             not null,
    request_context_json  text                                not null,
    variation_reason      varchar(512),
    variation_dimensions  varchar(1000),
    resource_url          varchar(512),
    resource_id           varchar(160),
    http_method           varchar(16),
    access_day            varchar(32),
    sample_timestamp      timestamp,
    baseline_write_result varchar(32),
    rag_write_result      varchar(32),
    lineage_json          text,
    created_at            timestamp default CURRENT_TIMESTAMP not null
);

alter table public.generated_learning_context_sample
    owner to contexa;

create index idx_cge_sample_set
    on public.generated_learning_context_sample (set_id, cycle);

create table public.generated_subtle_anomaly_context
(
    id                        bigserial
        primary key,
    anomaly_id                varchar(96)                         not null
        unique,
    source_request_context_id varchar(96),
    scenario_id               varchar(96),
    anomaly_kind              varchar(64)                         not null,
    changed_dimension         varchar(160)                        not null,
    request_context_json      text                                not null,
    difference_summary        varchar(1000),
    related_metric_codes      varchar(255),
    generator_version         varchar(32),
    created_at                timestamp default CURRENT_TIMESTAMP not null,
    created_by                varchar(255)
);

alter table public.generated_subtle_anomaly_context
    owner to contexa;

create index idx_cge_anomaly_scenario
    on public.generated_subtle_anomaly_context (scenario_id, anomaly_kind);

create table public.context_generation_lineage
(
    id          bigserial
        primary key,
    lineage_id  varchar(128)                        not null
        unique,
    bundle_id   varchar(96),
    target_kind varchar(32)                         not null,
    target_id   varchar(160)                        not null,
    source_kind varchar(32),
    source_id   varchar(160),
    rule_id     varchar(96),
    note        varchar(1000),
    recorded_at timestamp default CURRENT_TIMESTAMP not null,
    recorded_by varchar(255)
);

alter table public.context_generation_lineage
    owner to contexa;

create index idx_cge_lineage_bundle
    on public.context_generation_lineage (bundle_id, target_kind);

create table public.context_generation_version
(
    id            bigserial
        primary key,
    version_id    varchar(96)                                    not null
        unique,
    artifact_kind varchar(48)                                    not null,
    artifact_id   varchar(160)                                   not null,
    version_label varchar(32)                                    not null,
    status        varchar(16) default 'DRAFT'::character varying not null,
    approved_at   timestamp,
    approved_by   varchar(255),
    note          varchar(1000),
    created_at    timestamp   default CURRENT_TIMESTAMP          not null,
    updated_at    timestamp   default CURRENT_TIMESTAMP          not null,
    created_by    varchar(255),
    updated_by    varchar(255)
);

alter table public.context_generation_version
    owner to contexa;

create unique index idx_cge_version_artifact
    on public.context_generation_version (artifact_kind, artifact_id, version_label);

create table public.runtime_context_feedback
(
    id                   bigserial
        primary key,
    feedback_id          varchar(96)                                   not null
        unique,
    source_kind          varchar(48)                                   not null,
    source_reference     varchar(255),
    tenant_id            varchar(128),
    resource_id          varchar(160),
    occurred_at          timestamp,
    observation          varchar(3000),
    failure_modes        varchar(1000),
    promoted_scenario_id varchar(96),
    promoted_at          timestamp,
    promoted_by          varchar(255),
    status               varchar(16) default 'OPEN'::character varying not null,
    created_at           timestamp   default CURRENT_TIMESTAMP         not null,
    updated_at           timestamp   default CURRENT_TIMESTAMP         not null,
    created_by           varchar(255),
    updated_by           varchar(255)
);

alter table public.runtime_context_feedback
    owner to contexa;

create index idx_cge_feedback_status
    on public.runtime_context_feedback (status, occurred_at);

create table public.context_subtle_anomaly_template
(
    id              bigserial
        primary key,
    template_id     varchar(64)             not null
        unique,
    display_name    varchar(255)            not null,
    description     varchar(1000),
    target_category varchar(64),
    target_field    varchar(160),
    anomaly_type    varchar(32)             not null,
    intensity       varchar(16)             not null,
    spec_json       text,
    active          boolean   default true  not null,
    display_order   integer   default 1000  not null,
    created_at      timestamp default now() not null,
    updated_at      timestamp default now() not null,
    created_by      varchar(255),
    updated_by      varchar(255)
);

alter table public.context_subtle_anomaly_template
    owner to contexa;

create index idx_subtle_anomaly_active
    on public.context_subtle_anomaly_template (active);

create index idx_subtle_anomaly_type
    on public.context_subtle_anomaly_template (anomaly_type);

create table public.shedlock
(
    name       varchar(64)  not null
        primary key,
    lock_until timestamp    not null,
    locked_at  timestamp    not null,
    locked_by  varchar(255) not null
);

alter table public.shedlock
    owner to contexa;

create table public.prompt_quality_remediation_loop
(
    id                         bigserial
        primary key,
    case_id                    varchar(160)                                  not null
        unique,
    issue_id                   varchar(160),
    failed_package_id          varchar(160)                                  not null,
    failed_run_id              varchar(160),
    failed_metric_codes_json   text,
    fix_summary                varchar(3000),
    fix_target                 varchar(1000),
    expected_effect            varchar(3000),
    fixed_package_id           varchar(160),
    comparison_state           varchar(64) default 'OPEN'::character varying not null,
    comparison_json            text,
    opened_at                  timestamp                                     not null,
    updated_at                 timestamp                                     not null,
    reverify_run_id            varchar(256),
    finding_ids_json           text,
    issue_ids_json             text,
    remediation_group_ids_json text,
    official_run_id            varchar(256),
    certificate_id             varchar(256),
    source_case_id             varchar(256),
    resource_url               varchar(1024),
    resource_id                varchar(512),
    resource_template_id       varchar(512),
    actual_resource_id         varchar(512),
    http_method                varchar(16)
);

alter table public.prompt_quality_remediation_loop
    owner to contexa;

create index idx_pqa_remediation_loop_failed_package
    on public.prompt_quality_remediation_loop (failed_package_id asc, updated_at desc);

create index idx_pqa_remediation_loop_fixed_package
    on public.prompt_quality_remediation_loop (fixed_package_id asc, updated_at desc);

create index idx_pqa_remediation_loop_issue
    on public.prompt_quality_remediation_loop (issue_id asc, updated_at desc);

create index idx_pqa_remediation_loop_reverify_run
    on public.prompt_quality_remediation_loop (reverify_run_id asc, updated_at desc);

create table public.prompt_quality_assurance_case
(
    id                      bigserial
        primary key,
    case_id                 varchar(128)                                                          not null
        unique,
    case_key                varchar(128)                                                          not null
        unique,
    tenant_id               varchar(128) default 'default'::character varying                     not null,
    resource_url            varchar(1000)                                                         not null,
    resource_id             varchar(255),
    http_method             varchar(32)                                                           not null,
    prompt_contract_version varchar(128) default 'official-prompt-contract-v1'::character varying not null,
    model_profile           varchar(128) default 'default-model-profile'::character varying       not null,
    verifier_version        varchar(128) default 'official-verifier-v1'::character varying        not null,
    current_stage           varchar(64)                                                           not null,
    dirty_state             varchar(64)                                                           not null,
    latest_bundle_id        varchar(128),
    latest_run_id           varchar(128),
    latest_certificate_id   varchar(128),
    latest_issue_count      integer      default 0                                                not null,
    summary                 varchar(3000),
    created_at              timestamp                                                             not null,
    updated_at              timestamp                                                             not null
);

alter table public.prompt_quality_assurance_case
    owner to contexa;

create index idx_pqa_case_scope
    on public.prompt_quality_assurance_case (tenant_id asc, resource_id asc, http_method asc, updated_at desc);

create index idx_pqa_case_resource_url
    on public.prompt_quality_assurance_case (tenant_id asc, resource_url asc, http_method asc, updated_at desc);

create index idx_pqa_case_dirty
    on public.prompt_quality_assurance_case (dirty_state asc, updated_at desc);

create table public.prompt_quality_assurance_case_stage
(
    id             bigserial
        primary key,
    stage_event_id varchar(128) not null
        unique,
    case_id        varchar(128) not null,
    stage_key      varchar(64)  not null,
    stage_status   varchar(64)  not null,
    artifact_ref   varchar(255),
    summary        varchar(3000),
    recorded_at    timestamp    not null
);

alter table public.prompt_quality_assurance_case_stage
    owner to contexa;

create index idx_pqa_case_stage_case_time
    on public.prompt_quality_assurance_case_stage (case_id asc, recorded_at desc);

create index idx_pqa_case_stage_key
    on public.prompt_quality_assurance_case_stage (stage_key asc, recorded_at desc);

create table public.prompt_quality_dependency_impact
(
    id           bigserial
        primary key,
    impact_id    varchar(128) not null
        unique,
    case_id      varchar(128) not null,
    source_type  varchar(64)  not null,
    source_ref   varchar(255),
    impact_state varchar(64)  not null,
    reason_code  varchar(128) not null,
    summary      varchar(3000),
    recorded_at  timestamp    not null
);

alter table public.prompt_quality_dependency_impact
    owner to contexa;

create index idx_pqa_dependency_impact_case_time
    on public.prompt_quality_dependency_impact (case_id asc, recorded_at desc);

create index idx_pqa_dependency_impact_reason
    on public.prompt_quality_dependency_impact (reason_code asc, recorded_at desc);

create table public.context_generation_bundle
(
    id                          bigserial
        primary key,
    bundle_id                   varchar(96)                                      not null
        unique,
    generator_version           varchar(32)                                      not null,
    scenario_id                 varchar(96),
    tenant_profile              varchar(128),
    resource_profile            varchar(128),
    source_request_context_id   varchar(96),
    learning_context_set_id     varchar(96),
    current_request_context_id  varchar(96),
    subtle_anomaly_ids          text,
    baseline_evidence_json      text,
    rag_evidence_json           text,
    coverage_report_json        text,
    lineage_report_json         text,
    privacy_report_json         text,
    prompt_material_readiness   varchar(32) default 'PENDING'::character varying not null,
    exported_evidence_bundle_id varchar(96),
    created_at                  timestamp   default CURRENT_TIMESTAMP            not null,
    updated_at                  timestamp   default CURRENT_TIMESTAMP            not null,
    created_by                  varchar(255),
    updated_by                  varchar(255)
);

alter table public.context_generation_bundle
    owner to contexa;

create index idx_cge_bundle_scenario
    on public.context_generation_bundle (scenario_id, created_at);

create table public.prompt_quality_governance_candidate
(
    id                         bigserial
        primary key,
    candidate_id               varchar(128)                                      not null
        unique,
    tenant_id                  varchar(128) default 'default'::character varying not null,
    source_issue_ids_json      text,
    source_action_ids_json     text,
    root_cause_type            varchar(128)                                      not null,
    change_target_type         varchar(128)                                      not null,
    prompt_key                 varchar(128)                                      not null,
    base_prompt_version        varchar(128),
    candidate_prompt_version   varchar(128)                                      not null,
    registry_scope             varchar(128)                                      not null,
    impact_scope_json          text,
    expected_prompt_delta_json text,
    candidate_state            varchar(64)                                       not null,
    core_registry_state        varchar(64),
    created_by                 varchar(128),
    created_reason             varchar(2000),
    created_at                 timestamp                                         not null,
    updated_at                 timestamp                                         not null
);

alter table public.prompt_quality_governance_candidate
    owner to contexa;

create index idx_pqa_governance_candidate_tenant_state
    on public.prompt_quality_governance_candidate (tenant_id asc, candidate_state asc, updated_at desc);

create index idx_pqa_governance_candidate_registry
    on public.prompt_quality_governance_candidate (registry_scope, prompt_key, candidate_prompt_version);

create table public.prompt_quality_governance_portfolio_case
(
    id                       bigserial
        primary key,
    portfolio_case_id        varchar(128)                                      not null
        unique,
    candidate_id             varchar(128)                                      not null,
    tenant_id                varchar(128) default 'default'::character varying not null,
    resource_id              varchar(256),
    resource_url             varchar(1000),
    http_method              varchar(32),
    verification_state       varchar(64)                                       not null,
    before_package_id        varchar(160),
    after_package_id         varchar(160),
    before_run_id            varchar(160),
    after_run_id             varchar(160),
    failed_metric_codes_json text,
    prompt_delta_json        text,
    created_at               timestamp                                         not null,
    updated_at               timestamp                                         not null
);

alter table public.prompt_quality_governance_portfolio_case
    owner to contexa;

create index idx_pqa_governance_portfolio_candidate
    on public.prompt_quality_governance_portfolio_case (candidate_id asc, verification_state asc, updated_at desc);

create index idx_pqa_governance_portfolio_resource
    on public.prompt_quality_governance_portfolio_case (tenant_id asc, resource_id asc, http_method asc, updated_at desc);

create index idx_pqa_governance_portfolio_before_package
    on public.prompt_quality_governance_portfolio_case (before_package_id asc, updated_at desc);

create index idx_pqa_governance_portfolio_after_package
    on public.prompt_quality_governance_portfolio_case (after_package_id asc, updated_at desc);

create table public.prompt_quality_governance_release_link
(
    id                              bigserial
        primary key,
    link_id                         varchar(128) not null
        unique,
    candidate_id                    varchar(128) not null,
    registry_scope                  varchar(128) not null,
    prompt_key                      varchar(128) not null,
    prompt_version                  varchar(128) not null,
    core_release_status             varchar(64)  not null,
    core_change_reference           varchar(256),
    core_evaluation_reference       varchar(256),
    core_release_approval_reference varchar(256),
    linked_at                       timestamp    not null,
    linked_by                       varchar(128)
);

alter table public.prompt_quality_governance_release_link
    owner to contexa;

create index idx_pqa_governance_release_link_candidate
    on public.prompt_quality_governance_release_link (candidate_id asc, linked_at desc);

create index idx_pqa_governance_release_link_core
    on public.prompt_quality_governance_release_link (registry_scope, prompt_key, prompt_version);

create table public.prompt_governance_runtime_cache_invalidation
(
    id                  bigserial
        primary key,
    event_id            varchar(160)          not null
        unique,
    registry_scope      varchar(128)          not null,
    prompt_key          varchar(128)          not null,
    prompt_version      varchar(128)          not null,
    invalidation_reason varchar(2000),
    published_by        varchar(128),
    published_at        timestamp             not null,
    consumed            boolean default false not null,
    consumed_at         timestamp
);

alter table public.prompt_governance_runtime_cache_invalidation
    owner to contexa;

create index idx_prompt_governance_cache_invalidation_prompt
    on public.prompt_governance_runtime_cache_invalidation (registry_scope asc, prompt_key asc, prompt_version asc,
                                                            published_at desc);

create index idx_prompt_governance_cache_invalidation_pending
    on public.prompt_governance_runtime_cache_invalidation (consumed asc, published_at desc);

create table public.login_attempt_ip
(
    id              bigint generated by default as identity
        primary key,
    blocked_until   timestamp(6),
    failed_attempts integer      not null,
    ip_address      varchar(64)  not null
        constraint idx_login_attempt_ip_address
            unique,
    last_failure_at timestamp(6),
    last_username   varchar(255),
    window_start_at timestamp(6) not null
);

alter table public.login_attempt_ip
    owner to contexa;

create index idx_login_attempt_ip_window
    on public.login_attempt_ip (window_start_at);

create table public.prompt_quality_state_catalog
(
    id                   bigserial
        primary key,
    dimension            varchar(96)                                      not null,
    process_stage        varchar(96)                                      not null,
    state_code           varchar(128)                                     not null,
    label                varchar(300)                                     not null,
    tone                 varchar(48) default 'neutral'::character varying not null,
    aggregate_group      varchar(96) default 'UNKNOWN'::character varying not null,
    allowed_actions_json text        default '[]'::text                   not null,
    next_action          varchar(3000),
    selection_key        varchar(128),
    display_order        integer     default 0                            not null,
    active               boolean     default true                         not null,
    created_at           timestamp   default CURRENT_TIMESTAMP            not null,
    updated_at           timestamp   default CURRENT_TIMESTAMP            not null,
    constraint uq_pqa_state_catalog_code
        unique (dimension, state_code)
);

alter table public.prompt_quality_state_catalog
    owner to contexa;

create index idx_pqa_state_catalog_dimension
    on public.prompt_quality_state_catalog (dimension, active, display_order);

create index idx_pqa_state_catalog_stage
    on public.prompt_quality_state_catalog (process_stage, active, display_order);

create index idx_pqa_state_catalog_selection
    on public.prompt_quality_state_catalog (dimension, selection_key, active);

create table public.prompt_quality_process_definition
(
    id              bigserial
        primary key,
    code            varchar(96)                         not null
        unique,
    name            varchar(255)                        not null,
    version         integer   default 1                 not null,
    type            varchar(20)                         not null,
    parent_id       bigint
        references public.prompt_quality_process_definition,
    sequence_no     integer                             not null,
    timeout_seconds integer,
    is_active       boolean   default true              not null,
    created_at      timestamp default CURRENT_TIMESTAMP not null
);

alter table public.prompt_quality_process_definition
    owner to contexa;

create index idx_pqa_process_definition_parent
    on public.prompt_quality_process_definition (parent_id, sequence_no);

create table public.prompt_quality_process_run
(
    id                      bigserial
        primary key,
    process_id              bigint                              not null
        references public.prompt_quality_process_definition,
    tenant_id               varchar(256)                        not null,
    resource_id             varchar(500)                        not null,
    resource_url            varchar(1000),
    http_method             varchar(24)                         not null,
    business_key            varchar(900)                        not null,
    state                   varchar(32)                         not null,
    current_step_code       varchar(96),
    current_state_dimension varchar(96),
    current_state_code      varchar(128),
    started_at              timestamp,
    ended_at                timestamp,
    started_by              varchar(256),
    error_message           text,
    payload_json            text,
    created_at              timestamp default CURRENT_TIMESTAMP not null,
    updated_at              timestamp default CURRENT_TIMESTAMP not null,
    constraint uq_pqa_process_run_business
        unique (process_id, business_key)
);

alter table public.prompt_quality_process_run
    owner to contexa;

create index idx_pqa_process_run_business
    on public.prompt_quality_process_run (business_key);

create index idx_pqa_process_run_state
    on public.prompt_quality_process_run (tenant_id, state, updated_at);

create index idx_pqa_process_run_resource
    on public.prompt_quality_process_run (tenant_id, resource_id, http_method, updated_at);

create table public.prompt_quality_process_step_run
(
    id                     bigserial
        primary key,
    run_id                 bigint                              not null
        references public.prompt_quality_process_run
            on delete cascade,
    step_process_id        bigint                              not null
        references public.prompt_quality_process_definition,
    sequence_no            integer                             not null,
    state                  varchar(32)                         not null,
    domain_state_dimension varchar(96),
    domain_state_code      varchar(256),
    evidence_ref           varchar(500),
    route                  varchar(1000),
    summary                varchar(3000),
    next_action            varchar(3000),
    started_at             timestamp,
    ended_at               timestamp,
    executor               varchar(256),
    result_json            text,
    error_message          text,
    created_at             timestamp default CURRENT_TIMESTAMP not null,
    updated_at             timestamp default CURRENT_TIMESTAMP not null,
    constraint uq_pqa_process_step_run
        unique (run_id, step_process_id)
);

alter table public.prompt_quality_process_step_run
    owner to contexa;

create index idx_pqa_process_step_run_state
    on public.prompt_quality_process_step_run (run_id, state, sequence_no);

create index idx_pqa_process_step_run_domain_state
    on public.prompt_quality_process_step_run (domain_state_dimension, domain_state_code, updated_at);

create table public.prompt_quality_process_state_history
(
    id                          bigserial
        primary key,
    run_id                      bigint                              not null
        references public.prompt_quality_process_run
            on delete cascade,
    step_run_id                 bigint
        references public.prompt_quality_process_step_run,
    process_code                varchar(96)                         not null,
    step_code                   varchar(96),
    from_state                  varchar(32),
    to_state                    varchar(32)                         not null,
    from_domain_state_dimension varchar(96),
    from_domain_state_code      varchar(256),
    to_domain_state_dimension   varchar(96),
    to_domain_state_code        varchar(256),
    evidence_ref                varchar(500),
    changed_at                  timestamp default CURRENT_TIMESTAMP not null,
    changed_by                  varchar(256),
    reason                      text
);

alter table public.prompt_quality_process_state_history
    owner to contexa;

create index idx_pqa_process_state_history_run
    on public.prompt_quality_process_state_history (run_id, changed_at);

create index idx_pqa_process_state_history_step
    on public.prompt_quality_process_state_history (step_code, to_state, changed_at);

create table public.prompt_quality_process_event
(
    id           bigserial
        primary key,
    run_id       bigint                              not null
        references public.prompt_quality_process_run
            on delete cascade,
    step_run_id  bigint
        references public.prompt_quality_process_step_run,
    type         varchar(160)                        not null,
    payload_json text,
    occurred_at  timestamp default CURRENT_TIMESTAMP not null
);

alter table public.prompt_quality_process_event
    owner to contexa;

create index idx_pqa_process_event_run
    on public.prompt_quality_process_event (run_id, occurred_at);

create index idx_pqa_process_event_type
    on public.prompt_quality_process_event (type, occurred_at);

create table public.enterprise_audit_log
(
    id                      bigserial
        primary key,
    occurred_at             timestamp                           not null,
    recorded_at             timestamp default CURRENT_TIMESTAMP not null,
    tenant_id               varchar(160),
    organization_id         varchar(160),
    principal_name          varchar(255)                        not null,
    request_id              varchar(256),
    approval_id             varchar(256),
    permit_id               varchar(256),
    incident_id             varchar(256),
    correlation_id          varchar(256),
    session_id              varchar(256),
    client_ip               varchar(128),
    user_agent              varchar(512),
    http_method             varchar(32),
    request_uri             varchar(2048),
    resource_identifier     varchar(1024)                       not null,
    resource_uri            varchar(2048),
    action                  varchar(255),
    decision                varchar(100)                        not null,
    outcome                 varchar(100),
    reason                  text,
    risk_score              double precision,
    source_service          varchar(160),
    source_version          varchar(128),
    environment             varchar(128),
    event_category          varchar(100),
    event_source            varchar(100),
    policy_id               varchar(256),
    policy_version          varchar(256),
    protectable_resource_id varchar(512),
    evidence_package_id     varchar(256),
    prompt_hash             varchar(160),
    context_hash            varchar(160),
    prompt_certificate_id   varchar(256),
    model_id                varchar(256),
    model_version           varchar(256),
    parameters_json         text,
    details                 text,
    previous_hash           varchar(160),
    entry_hash              varchar(160),
    chain_position          bigint,
    sealed_at               timestamp,
    retention_until         timestamp,
    legal_hold              boolean   default false             not null,
    retention_policy_id     varchar(256)
);

alter table public.enterprise_audit_log
    owner to contexa;

create index idx_enterprise_audit_tenant_time
    on public.enterprise_audit_log (tenant_id asc, occurred_at desc);

create index idx_enterprise_audit_org_time
    on public.enterprise_audit_log (organization_id asc, occurred_at desc);

create index idx_enterprise_audit_decision_time
    on public.enterprise_audit_log (decision asc, occurred_at desc);

create index idx_enterprise_audit_request
    on public.enterprise_audit_log (request_id);

create index idx_enterprise_audit_permit
    on public.enterprise_audit_log (permit_id);

create index idx_enterprise_audit_approval
    on public.enterprise_audit_log (approval_id);

create index idx_enterprise_audit_incident
    on public.enterprise_audit_log (incident_id);

create index idx_enterprise_audit_chain
    on public.enterprise_audit_log (chain_position);

create index idx_enterprise_audit_retention
    on public.enterprise_audit_log (retention_until, legal_hold);

create table public.official_verification_run_batch
(
    id                          bigint generated by default as identity
        primary key,
    aggregate_run_id            varchar(256)                        not null
        unique,
    package_id                  varchar(256)                        not null,
    scope_type                  varchar(64)                         not null,
    expected_metric_count       integer                             not null,
    actual_metric_count         integer   default 0                 not null,
    passed_metric_count         integer   default 0                 not null,
    failed_metric_count         integer   default 0                 not null,
    insufficient_metric_count   integer   default 0                 not null,
    not_applicable_metric_count integer   default 0                 not null,
    final_decision              varchar(64)                         not null,
    blocked                     boolean   default true              not null,
    block_reason_summary        text,
    prompt_hash                 varchar(160),
    context_hash                varchar(160),
    context_hash_state          varchar(64),
    template_resource_id        varchar(256),
    actual_resource_id          varchar(256),
    resource_url_template       text,
    actual_request_path         text,
    http_method                 varchar(32),
    started_at                  timestamp,
    completed_at                timestamp,
    created_at                  timestamp default CURRENT_TIMESTAMP not null,
    certificate_id              varchar(256),
    case_id                     varchar(256),
    diagnostic_catalog_version  varchar(128)
);

alter table public.official_verification_run_batch
    owner to contexa;

create index idx_official_verification_run_batch_package
    on public.official_verification_run_batch (package_id asc, created_at desc);

create index idx_official_verification_run_batch_certificate
    on public.official_verification_run_batch (certificate_id);

create index idx_official_verification_run_batch_catalog_version
    on public.official_verification_run_batch (diagnostic_catalog_version, created_at);

create table public.official_verification_metric_snapshot
(
    id                         bigint generated by default as identity
        primary key,
    aggregate_run_id           varchar(256)                        not null,
    official_run_id            varchar(256)                        not null,
    package_id                 varchar(256)                        not null,
    metric_code                varchar(32)                         not null,
    metric_name                varchar(255),
    metric_group               varchar(128),
    score                      double precision,
    state                      varchar(80),
    severity                   varchar(32),
    passed_checks              integer,
    total_checks               integer,
    operator_title             varchar(255),
    operator_summary           text,
    primary_failure_reason     text,
    remediation_owner          varchar(128),
    next_action                text,
    reverify_criterion         text,
    created_at                 timestamp default CURRENT_TIMESTAMP not null,
    certificate_id             varchar(256),
    case_id                    varchar(256),
    failed_check_count         integer   default 0,
    diagnostic_catalog_version varchar(128),
    constraint uq_official_verification_metric_snapshot
        unique (aggregate_run_id, metric_code)
);

alter table public.official_verification_metric_snapshot
    owner to contexa;

create index idx_official_verification_metric_snapshot_package
    on public.official_verification_metric_snapshot (package_id, aggregate_run_id, metric_code);

create table public.official_verification_operator_finding
(
    id                         bigint generated by default as identity
        primary key,
    finding_id                 varchar(256)                        not null
        unique,
    aggregate_run_id           varchar(256)                        not null,
    official_run_id            varchar(256),
    package_id                 varchar(256)                        not null,
    metric_code                varchar(32)                         not null,
    check_code                 varchar(128),
    severity                   varchar(32)                         not null,
    operator_title             varchar(255)                        not null,
    operator_reason            text,
    evidence_summary           text,
    evidence_path              varchar(512),
    expected_value             text,
    actual_value               text,
    impact                     text,
    remediation_owner          varchar(128),
    next_action                text,
    reverify_criterion         text,
    related_process_step       varchar(128),
    created_at                 timestamp default CURRENT_TIMESTAMP not null,
    certificate_id             varchar(256),
    case_id                    varchar(256),
    issue_id                   varchar(256),
    operator_summary           text,
    problem_statement          text,
    root_cause                 text,
    affected_target            varchar(256),
    expected_result            text,
    actual_result              text,
    customer_visible_severity  varchar(64),
    diagnostic_catalog_version varchar(128)
);

alter table public.official_verification_operator_finding
    owner to contexa;

create index idx_official_verification_operator_finding_package
    on public.official_verification_operator_finding (package_id, aggregate_run_id, metric_code);

create index idx_official_verification_operator_finding_issue
    on public.official_verification_operator_finding (issue_id);

create index idx_official_operator_finding_customer_severity
    on public.official_verification_operator_finding (package_id, customer_visible_severity, created_at);

create index idx_official_verification_finding_catalog_version
    on public.official_verification_operator_finding (diagnostic_catalog_version, created_at);

create table public.official_verification_metric_definition
(
    id                 bigint generated by default as identity
        primary key,
    metric_code        varchar(32)                         not null,
    definition_version varchar(40)                         not null,
    metric_name        varchar(255)                        not null,
    metric_group       varchar(128)                        not null,
    purpose            text                                not null,
    evidence_contract  text                                not null,
    blocking_scope     varchar(64)                         not null,
    is_active          boolean   default true              not null,
    effective_from     timestamp default CURRENT_TIMESTAMP not null,
    created_at         timestamp default CURRENT_TIMESTAMP not null,
    constraint uq_official_verification_metric_definition
        unique (metric_code, definition_version)
);

alter table public.official_verification_metric_definition
    owner to contexa;

create index idx_official_verification_metric_definition_active
    on public.official_verification_metric_definition (metric_code, is_active);

create table public.official_verification_metric_check_definition
(
    id                 bigint generated by default as identity
        primary key,
    metric_code        varchar(32)                         not null,
    check_code         varchar(128)                        not null,
    definition_version varchar(40)                         not null,
    check_label        varchar(255)                        not null,
    expected_value     text,
    evidence_source    varchar(512),
    severity           varchar(32)                         not null,
    remediation_owner  varchar(128)                        not null,
    is_active          boolean   default true              not null,
    created_at         timestamp default CURRENT_TIMESTAMP not null,
    constraint uq_official_verification_metric_check_definition
        unique (metric_code, check_code, definition_version)
);

alter table public.official_verification_metric_check_definition
    owner to contexa;

create index idx_official_verification_metric_check_definition_metric
    on public.official_verification_metric_check_definition (metric_code, is_active);

create table public.official_verification_operator_remediation_group
(
    id                         bigint generated by default as identity
        primary key,
    group_id                   varchar(256)                        not null
        unique,
    aggregate_run_id           varchar(256)                        not null,
    package_id                 varchar(256)                        not null,
    certificate_id             varchar(256),
    case_id                    varchar(256),
    root_cause_key             varchar(256)                        not null,
    remediation_owner          varchar(128)                        not null,
    operator_title             varchar(255)                        not null,
    operator_reason            text,
    next_action                text,
    reverify_criterion         text,
    affected_metric_codes      varchar(512),
    affected_check_codes       text,
    finding_count              integer   default 0                 not null,
    related_process_step       varchar(128),
    created_at                 timestamp default CURRENT_TIMESTAMP not null,
    diagnostic_catalog_version varchar(128)
);

alter table public.official_verification_operator_remediation_group
    owner to contexa;

create index idx_official_verification_operator_remediation_group_run
    on public.official_verification_operator_remediation_group (package_id, aggregate_run_id);

create index idx_official_verification_operator_remediation_group_owner
    on public.official_verification_operator_remediation_group (remediation_owner, created_at);

create table public.official_verification_metric_regression_package
(
    id                              bigint generated by default as identity
        primary key,
    scenario_id                     varchar(128)                        not null
        unique,
    scenario_name                   varchar(255)                        not null,
    scenario_type                   varchar(64)                         not null,
    target_metric_codes             varchar(512)                        not null,
    fixture_source                  varchar(512)                        not null,
    expected_decision               varchar(64)                         not null,
    is_active                       boolean   default true              not null,
    created_at                      timestamp default CURRENT_TIMESTAMP not null,
    sample_kind                     varchar(16),
    prompt_hash                     varchar(160),
    context_hash                    varchar(160),
    resource_template_id            varchar(256),
    actual_resource_id              varchar(256),
    sample_package_json             text,
    expected_finding_snapshot       text,
    expected_remediation_group      text,
    expected_reverify_criterion     text,
    expected_audit_payload_json     text,
    customer_sentence_contract_json text
);

alter table public.official_verification_metric_regression_package
    owner to contexa;

create index idx_official_metric_regression_package_kind
    on public.official_verification_metric_regression_package (sample_kind, target_metric_codes);

create table public.official_verification_metric_regression_expectation
(
    id                          bigint generated by default as identity
        primary key,
    scenario_id                 varchar(128)                        not null,
    metric_code                 varchar(32)                         not null,
    expected_state              varchar(80)                         not null,
    expected_failed_check_codes text,
    created_at                  timestamp default CURRENT_TIMESTAMP not null,
    expected_score              numeric(7, 2),
    expected_passed_check_count integer,
    expected_failed_check_count integer,
    expected_finding_snapshot   text,
    expected_remediation_group  text,
    expected_reverify_criterion text,
    expected_audit_payload_json text,
    constraint uq_official_verification_metric_regression_expectation
        unique (scenario_id, metric_code)
);

alter table public.official_verification_metric_regression_expectation
    owner to contexa;

create index idx_official_verification_metric_regression_expectation_scenari
    on public.official_verification_metric_regression_expectation (scenario_id);

create index idx_official_metric_regression_expectation_metric
    on public.official_verification_metric_regression_expectation (metric_code, expected_state);

create table public.official_verification_reverify_result
(
    id                         bigint generated by default as identity
        primary key,
    result_id                  varchar(256)                        not null
        unique,
    source_package_id          varchar(256)                        not null,
    source_aggregate_run_id    varchar(256),
    fixed_package_id           varchar(256)                        not null,
    fixed_aggregate_run_id     varchar(256),
    source_finding_id          varchar(256),
    issue_id                   varchar(256),
    metric_code                varchar(32)                         not null,
    check_code                 varchar(128),
    reverify_criterion         text,
    source_operator_reason     text,
    source_expected_value      text,
    source_actual_value        text,
    fixed_actual_value         text,
    resolved                   boolean   default false             not null,
    resolution_state           varchar(64)                         not null,
    operator_summary           text,
    created_by                 varchar(128),
    created_at                 timestamp default CURRENT_TIMESTAMP not null,
    diagnostic_catalog_version varchar(128)
);

alter table public.official_verification_reverify_result
    owner to contexa;

create index idx_official_verification_reverify_source
    on public.official_verification_reverify_result (source_package_id, source_aggregate_run_id);

create index idx_official_verification_reverify_fixed
    on public.official_verification_reverify_result (fixed_package_id, fixed_aggregate_run_id);

create index idx_official_verification_reverify_finding
    on public.official_verification_reverify_result (source_finding_id, issue_id);

create table public.official_verification_audit_snapshot
(
    id                         bigint generated by default as identity
        primary key,
    snapshot_id                varchar(256)                        not null
        unique,
    aggregate_run_id           varchar(256)                        not null,
    package_id                 varchar(256)                        not null,
    certificate_id             varchar(256),
    case_id                    varchar(256),
    state                      varchar(80),
    state_label                varchar(120),
    total_metric_count         integer   default 0                 not null,
    failed_metric_count        integer   default 0                 not null,
    certificate_issued         boolean   default false             not null,
    prompt_hash                varchar(160),
    context_hash               varchar(160),
    blocking_findings_json     text,
    next_actions_json          text,
    payload_json               text                                not null,
    created_by                 varchar(128),
    created_at                 timestamp default CURRENT_TIMESTAMP not null,
    diagnostic_catalog_version varchar(128)
);

alter table public.official_verification_audit_snapshot
    owner to contexa;

create index idx_official_verification_audit_snapshot_run
    on public.official_verification_audit_snapshot (package_id asc, aggregate_run_id asc, created_at desc);

create index idx_official_verification_audit_snapshot_certificate
    on public.official_verification_audit_snapshot (certificate_id asc, created_at desc);

create table public.official_verification_execution_lock
(
    id                       bigint generated by default as identity
        primary key,
    idempotency_key          varchar(256)                        not null
        constraint uq_official_verification_execution_lock_key
            unique,
    base_idempotency_key     varchar(256)                        not null,
    package_id               varchar(256)                        not null,
    aggregate_run_id         varchar(256),
    revision_no              integer   default 1                 not null,
    state                    varchar(64)                         not null,
    progress_percent         integer   default 0                 not null
        constraint ck_official_verification_execution_lock_progress
            check ((progress_percent >= 0) AND (progress_percent <= 100)),
    recoverable              boolean,
    retry_instruction        text,
    failure_reason           text,
    requested_by             varchar(128),
    reverification_reason    text,
    request_fingerprint_json text,
    result_json              text,
    started_at               timestamp,
    completed_at             timestamp,
    failed_at                timestamp,
    created_at               timestamp default CURRENT_TIMESTAMP not null,
    updated_at               timestamp default CURRENT_TIMESTAMP not null,
    attempt_no               integer   default 1                 not null,
    failure_stage            varchar(64)
);

alter table public.official_verification_execution_lock
    owner to contexa;

create index idx_official_verification_execution_lock_package
    on public.official_verification_execution_lock (package_id asc, created_at desc);

create index idx_official_verification_execution_lock_state
    on public.official_verification_execution_lock (state, updated_at);

create index idx_official_verification_execution_lock_base
    on public.official_verification_execution_lock (base_idempotency_key, revision_no);

create table public.official_verification_execution_state_history
(
    id                bigint generated by default as identity
        primary key,
    execution_lock_id bigint                              not null
        constraint fk_official_verification_state_history_lock
            references public.official_verification_execution_lock
            on delete cascade,
    package_id        varchar(256)                        not null,
    aggregate_run_id  varchar(256),
    attempt_no        integer   default 1                 not null,
    state             varchar(64)                         not null,
    progress_percent  integer   default 0                 not null
        constraint ck_official_verification_state_history_progress
            check ((progress_percent >= 0) AND (progress_percent <= 100)),
    recoverable       boolean,
    failure_stage     varchar(64),
    failure_reason    text,
    retry_instruction text,
    message           text,
    created_at        timestamp default CURRENT_TIMESTAMP not null
);

alter table public.official_verification_execution_state_history
    owner to contexa;

create index idx_official_verification_state_history_lock
    on public.official_verification_execution_state_history (execution_lock_id, attempt_no, created_at);

create index idx_official_verification_state_history_package
    on public.official_verification_execution_state_history (package_id asc, created_at desc);

create table public.official_verification_metric_execution_ledger
(
    id                bigint generated by default as identity
        primary key,
    execution_lock_id bigint                              not null
        constraint fk_official_verification_metric_execution_lock
            references public.official_verification_execution_lock
            on delete cascade,
    package_id        varchar(256)                        not null,
    aggregate_run_id  varchar(256),
    attempt_no        integer   default 1                 not null,
    metric_code       varchar(32)                         not null,
    sequence_no       integer                             not null,
    state             varchar(64)                         not null,
    progress_percent  integer   default 0                 not null
        constraint ck_official_verification_metric_progress
            check ((progress_percent >= 0) AND (progress_percent <= 100)),
    recoverable       boolean,
    failure_reason    text,
    retry_instruction text,
    started_at        timestamp,
    completed_at      timestamp,
    created_at        timestamp default CURRENT_TIMESTAMP not null,
    updated_at        timestamp default CURRENT_TIMESTAMP not null,
    constraint uq_official_verification_metric_execution_attempt
        unique (execution_lock_id, attempt_no, metric_code)
);

alter table public.official_verification_metric_execution_ledger
    owner to contexa;

create index idx_official_verification_metric_execution_package
    on public.official_verification_metric_execution_ledger (package_id, aggregate_run_id, metric_code);

create index idx_official_verification_metric_execution_lock
    on public.official_verification_metric_execution_ledger (execution_lock_id, attempt_no, sequence_no);

create table public.official_verification_operational_alert_event
(
    id               bigint generated by default as identity
        primary key,
    alert_key        varchar(256)                        not null
        unique,
    alert_type       varchar(64)                         not null,
    severity         varchar(32)                         not null,
    alert_message    text                                not null,
    observed_value   varchar(128),
    threshold_value  varchar(128),
    occurrence_count integer   default 1                 not null,
    first_seen_at    timestamp default CURRENT_TIMESTAMP not null,
    last_seen_at     timestamp default CURRENT_TIMESTAMP not null
);

alter table public.official_verification_operational_alert_event
    owner to contexa;

create index idx_official_verification_alert_event_seen
    on public.official_verification_operational_alert_event (last_seen_at desc);

create table public.demo_entry_visitor
(
    id         bigserial
        primary key,
    email      varchar(320) not null,
    ip         varchar(64),
    user_agent varchar(512),
    created_at timestamp    not null
);

alter table public.demo_entry_visitor
    owner to contexa;

create index idx_demo_entry_visitor_created_at
    on public.demo_entry_visitor (created_at);

create index idx_demo_entry_visitor_email
    on public.demo_entry_visitor (email);

