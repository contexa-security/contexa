-- Contexa SaaS Platform DDL
-- Auto-generated from entity definitions
-- CONFIDENTIAL: Not distributed via CLI

create table saas_tenants
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


create index idx_saas_tenant_status
    on saas_tenants (status);

create index idx_saas_tenant_plan
    on saas_tenants (plan_code);

create index idx_saas_tenant_plan_code
    on saas_tenants (plan_code);

create index idx_saas_tenant_deployment_mode
    on saas_tenants (deployment_mode);

create table tenant_subscriptions
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


create index idx_tenant_sub_plan
    on tenant_subscriptions (plan_code);

create index idx_tenant_sub_contract_end
    on tenant_subscriptions (contract_end_at);

create index idx_tenant_subscription_plan_code
    on tenant_subscriptions (plan_code);

create index idx_tenant_subscription_contract_end
    on tenant_subscriptions (contract_end_at);

create table tenant_environments
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


create index idx_tenant_env_key
    on tenant_environments (tenant_id, environment_key);

create index idx_tenant_environment_lookup
    on tenant_environments (tenant_id, environment_key);

create table tenant_entitlements
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


create index idx_tenant_entitlement
    on tenant_entitlements (tenant_id, entitlement_key, effective_to);

create index idx_tenant_entitlement_lookup
    on tenant_entitlements (tenant_id, entitlement_key, effective_to);

create table tenant_operator_assignments
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


create index idx_tenant_operator_user
    on tenant_operator_assignments (tenant_id, user_id);

create index idx_tenant_operator_status
    on tenant_operator_assignments (tenant_id, status);

create index idx_tenant_operator_lookup
    on tenant_operator_assignments (tenant_id, user_id);

create table tenant_provisioning_tasks
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


create index idx_tenant_prov_status
    on tenant_provisioning_tasks (tenant_id, task_type, status);

create index idx_tenant_prov_ref
    on tenant_provisioning_tasks (tenant_id, reference_key);

create index idx_tenant_provisioning_task_lookup
    on tenant_provisioning_tasks (tenant_id, task_type, status);

create index idx_tenant_provisioning_task_reference
    on tenant_provisioning_tasks (tenant_id, reference_key);

create table tenant_purge_requests
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


create index idx_tenant_purge_status
    on tenant_purge_requests (tenant_id, status, scheduled_at);

create index idx_tenant_purge_prov
    on tenant_purge_requests (tenant_id, provisioning_task_id);

create index idx_tenant_purge_request_lookup
    on tenant_purge_requests (tenant_id, status, scheduled_at);

create index idx_tenant_purge_request_task
    on tenant_purge_requests (tenant_id, provisioning_task_id);

create table tenant_backup_policies
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

create table tenant_restore_drills
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


create index idx_tenant_drill_status
    on tenant_restore_drills (tenant_id, status, completed_at);

create index idx_tenant_restore_drill_lookup
    on tenant_restore_drills (tenant_id, status, completed_at);

create index idx_tenant_restore_drill_created
    on tenant_restore_drills (tenant_id, created_at);

create table tenant_quotas
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


create index idx_tenant_quota
    on tenant_quotas (tenant_id, quota_key);

create index idx_tenant_quota_lookup
    on tenant_quotas (tenant_id, quota_key);

create table tenant_quota_violations
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


create index idx_tenant_violation_time
    on tenant_quota_violations (tenant_id, occurred_at);

create index idx_tenant_violation_key
    on tenant_quota_violations (tenant_id, quota_key, billing_period);

create index idx_tenant_quota_violation_lookup
    on tenant_quota_violations (tenant_id, occurred_at);

create index idx_tenant_quota_violation_key
    on tenant_quota_violations (tenant_id, quota_key, billing_period);

create table tenant_isolation_states
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


create index idx_tenant_isolation_scope
    on tenant_isolation_states (tenant_id, scope_type, scope_key, workload_type);

create index idx_tenant_isolation_status
    on tenant_isolation_states (tenant_id, status, contained_until);

create index idx_tenant_isolation_state_lookup
    on tenant_isolation_states (tenant_id, scope_type, scope_key, workload_type);

create index idx_tenant_isolation_state_status
    on tenant_isolation_states (tenant_id, status, contained_until);

create table tenant_isolation_events
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


create index idx_tenant_iso_event_time
    on tenant_isolation_events (tenant_id, occurred_at);

create index idx_tenant_iso_event_scope
    on tenant_isolation_events (tenant_id, scope_type, scope_key, workload_type, decision);

create index idx_tenant_isolation_event_lookup
    on tenant_isolation_events (tenant_id, occurred_at);

create index idx_tenant_isolation_event_scope
    on tenant_isolation_events (tenant_id, scope_type, scope_key, workload_type, decision);

create table tenant_workload_leases
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


create index idx_tenant_lease_active
    on tenant_workload_leases (tenant_id, workload_type, status, expires_at);

create index idx_tenant_lease_acquired
    on tenant_workload_leases (tenant_id, workload_type, acquired_at);

create index idx_tenant_workload_lease_active
    on tenant_workload_leases (tenant_id, workload_type, status, expires_at);

create index idx_tenant_workload_lease_window
    on tenant_workload_leases (tenant_id, workload_type, acquired_at);

create table protected_app_groups
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


create index idx_app_group_tenant_status
    on protected_app_groups (tenant_id, status);

create index idx_app_group_tenant_heartbeat
    on protected_app_groups (tenant_id, last_heartbeat_at);

create index idx_protected_app_group_tenant_status
    on protected_app_groups (tenant_id, status);

create index idx_protected_app_group_tenant_heartbeat
    on protected_app_groups (tenant_id, last_heartbeat_at);

create table protected_app_endpoints
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


create index idx_app_endpoint_group
    on protected_app_endpoints (app_group_id);

create index idx_app_endpoint_tenant
    on protected_app_endpoints (tenant_id, status);

create index idx_protected_app_endpoint_group
    on protected_app_endpoints (app_group_id);

create index idx_protected_app_endpoint_tenant
    on protected_app_endpoints (tenant_id, status);

create table protected_app_bindings
(
    id            bigserial
        primary key,
    app_group_id  varchar(120)                                    not null,
    binding_key   varchar(120)                                    not null,
    binding_value varchar(500)                                    not null,
    status        varchar(40) default 'ACTIVE'::character varying not null,
    created_at    timestamp(6)                                    not null
);


create index idx_app_binding_group
    on protected_app_bindings (app_group_id);

create index idx_protected_app_binding_group
    on protected_app_bindings (app_group_id);

create table protected_app_heartbeats
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


create index idx_app_heartbeat_group
    on protected_app_heartbeats (tenant_id, app_group_id, occurred_at);

create index idx_app_heartbeat_client
    on protected_app_heartbeats (tenant_id, client_id, occurred_at);

create index idx_protected_app_heartbeat_period
    on protected_app_heartbeats (tenant_id, app_group_id, occurred_at);

create index idx_protected_app_heartbeat_client
    on protected_app_heartbeats (tenant_id, client_id, occurred_at);

create table billing_contracts
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


create index idx_billing_contract_channel
    on billing_contracts (billing_channel);

create index idx_billing_contract_status
    on billing_contracts (status);

create table billing_invoices
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


create index idx_billing_invoice_tenant
    on billing_invoices (tenant_id, billing_period);

create index idx_billing_invoice_tenant_period
    on billing_invoices (tenant_id, billing_period);

create index idx_billing_invoice_status
    on billing_invoices (status);

create table billing_line_items
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


create index idx_billing_line_invoice
    on billing_line_items (invoice_id);

create index idx_billing_line_meter
    on billing_line_items (meter_key);

create index idx_billing_line_item_invoice
    on billing_line_items (invoice_id);

create index idx_billing_line_item_meter_key
    on billing_line_items (meter_key);

create table billing_adjustments
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


create index idx_billing_adj_tenant
    on billing_adjustments (tenant_id, billing_period);

create index idx_billing_adj_status
    on billing_adjustments (status);

create index idx_billing_adj_invoice
    on billing_adjustments (invoice_id);

create index idx_billing_adjustment_tenant_period
    on billing_adjustments (tenant_id, billing_period);

create index idx_billing_adjustment_status
    on billing_adjustments (status);

create index idx_billing_adjustment_invoice
    on billing_adjustments (invoice_id);

create table invoice_export_batches
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


create index idx_invoice_export_tenant
    on invoice_export_batches (tenant_id, billing_period);

create index idx_invoice_export_type
    on invoice_export_batches (export_type, export_format);

create index idx_invoice_export_batch_tenant_period
    on invoice_export_batches (tenant_id, billing_period);

create index idx_invoice_export_batch_type
    on invoice_export_batches (export_type, export_format);

create table usage_meter_events
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
    metadata_json  text
);


create index idx_usage_meter_period
    on usage_meter_events (tenant_id, billing_period);

create index idx_usage_meter_key
    on usage_meter_events (tenant_id, meter_key, billing_period);

create unique index uk_usage_meter_event_source_ref
    on usage_meter_events (tenant_id, meter_key, billing_period, source_ref)
    where source_ref is not null;

create index idx_usage_tenant_period
    on usage_meter_events (tenant_id, billing_period);

create table usage_aggregations
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

create table dedicated_deployment_profiles
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


create index idx_dedicated_deploy_state
    on dedicated_deployment_profiles (allocation_state);

create index idx_dedicated_profile_state
    on dedicated_deployment_profiles (allocation_state);

create table ai_native_containment_actions
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


create index idx_ai_native_containment_tenant_created
    on ai_native_containment_actions (tenant_id, created_at);

create index idx_ai_native_containment_tenant_state
    on ai_native_containment_actions (tenant_id, containment_state, created_at);

create table ai_native_model_artifact
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


create index idx_ai_native_model_artifact_tenant_updated
    on ai_native_model_artifact (tenant_id, updated_at);

create table ai_native_runtime_manifest
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


create index idx_ai_native_runtime_manifest_tenant_updated
    on ai_native_runtime_manifest (tenant_id, updated_at);

create table ai_native_tevv_execution
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


create index idx_ai_native_tevv_execution_tenant_time
    on ai_native_tevv_execution (tenant_id, executed_at);

create index idx_ai_native_tevv_execution_exec_suite
    on ai_native_tevv_execution (execution_id, suite_key);

create table baseline_signal_ingestion_records
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


create index idx_baseline_signal_cohort_received
    on baseline_signal_ingestion_records (industry_category, region, received_at);

create index idx_baseline_signal_tenant_received
    on baseline_signal_ingestion_records (tenant_id, received_at);

create table delegated_execution_graph_records
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


create index idx_delegated_execution_tenant_observed
    on delegated_execution_graph_records (tenant_id, last_observed_at);

create index idx_delegated_execution_tenant_actor
    on delegated_execution_graph_records (tenant_id, actor_user_id);

create table delegated_execution_step_records
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


create index idx_delegated_execution_step_tenant_execution
    on delegated_execution_step_records (tenant_id, execution_id, observed_at);

create table feedback_ingestion_records
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


create index idx_feedback_ingestion_tenant_received
    on feedback_ingestion_records (tenant_id, received_at);

create index idx_feedback_ingestion_tenant_correlation
    on feedback_ingestion_records (tenant_id, correlation_id);

create table global_threat_signals
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


create index idx_global_threat_signal_status_seen
    on global_threat_signals (status, last_observed_at);

create table model_performance_telemetry_records
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


create index idx_model_performance_telemetry_tenant_received
    on model_performance_telemetry_records (tenant_id, received_at);

create table prompt_context_audit
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


create index idx_prompt_context_audit_tenant_corr
    on prompt_context_audit (tenant_id, correlation_id, created_at);

create index idx_prompt_context_audit_audit_id
    on prompt_context_audit (audit_id);

create table security_decision_fact_records
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


create index idx_xai_fact_tenant_correlation_position
    on security_decision_fact_records (tenant_id, correlation_id, position);

create table security_decision_ingestion_records
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


create index idx_xai_ingestion_tenant_received
    on security_decision_ingestion_records (tenant_id, received_at);

create table tenant_webhook_endpoints
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


create index idx_tenant_webhook_endpoint_status
    on tenant_webhook_endpoints (status, updated_at);

create table threat_campaign_observations
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


create index idx_threat_obs_signal_window
    on threat_campaign_observations (global_source_key, canonical_threat_class, geo_country, observed_at);

create table threat_outcome_records
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


create index idx_threat_outcome_tenant_correlation
    on threat_outcome_records (tenant_id, correlation_id, received_at);

create index idx_threat_outcome_tenant_received
    on threat_outcome_records (tenant_id, received_at);

create table xai_analysis_reports
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


create index idx_xai_report_tenant_generated
    on xai_analysis_reports (tenant_id, generated_at);

create index idx_xai_report_delivery_due
    on xai_analysis_reports (delivery_status, next_delivery_attempt_at);

