-- Contexa Enterprise - SaaS Platform Database Schema
CREATE TABLE mcp_client_states (
    client_name            VARCHAR(100) NOT NULL PRIMARY KEY,
    enabled                BOOLEAN NOT NULL DEFAULT TRUE,
    health_status          VARCHAR(30) NOT NULL DEFAULT 'UNKNOWN',
    health_message         VARCHAR(500),
    last_health_checked_at TIMESTAMP(6),
    created_at             TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             TIMESTAMP(6) NOT NULL
);

CREATE TABLE mcp_surface_states (
    surface_key          VARCHAR(180) NOT NULL PRIMARY KEY,
    surface_type         VARCHAR(30) NOT NULL,
    surface_name         VARCHAR(140) NOT NULL,
    client_name          VARCHAR(100) NOT NULL,
    enabled              BOOLEAN NOT NULL DEFAULT TRUE,
    version              VARCHAR(64) NOT NULL,
    last_refreshed_at    TIMESTAMP(6),
    created_at           TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           TIMESTAMP(6) NOT NULL
);

CREATE TABLE tool_execution_contexts (
    id                   BIGSERIAL PRIMARY KEY,
    request_id           VARCHAR(100) NOT NULL UNIQUE,
    permit_id            VARCHAR(100) UNIQUE,
    approval_id          VARCHAR(100),
    status               VARCHAR(20) NOT NULL,
    tool_name            VARCHAR(255) NOT NULL,
    tool_type            VARCHAR(50),
    tool_call_id         VARCHAR(255),
    tool_arguments       TEXT,
    tool_definitions     TEXT,
    prompt_content       TEXT NOT NULL,
    execution_class      VARCHAR(255),
    arguments_hash       VARCHAR(64),
    required_scope       VARCHAR(100),
    available_tools      TEXT,
    chat_options         TEXT,
    chat_response        TEXT,
    execution_result     TEXT,
    execution_error      TEXT,
    execution_start_time TIMESTAMP(6),
    execution_end_time   TIMESTAMP(6),
    incident_id          VARCHAR(100),
    session_id           VARCHAR(100),
    risk_level           VARCHAR(20),
    soar_context         TEXT,
    pipeline_context     TEXT,
    metadata             TEXT,
    max_retries          INTEGER,
    retry_count          INTEGER,
    expires_at           TIMESTAMP(6),
    created_at           TIMESTAMP(6) NOT NULL,
    updated_at           TIMESTAMP(6) NOT NULL
);
CREATE INDEX idx_tool_context_status ON tool_execution_contexts (status);
CREATE INDEX idx_tool_context_created_at ON tool_execution_contexts (created_at);
CREATE INDEX idx_tool_context_tool_name ON tool_execution_contexts (tool_name);

CREATE TABLE tenant_lifecycle_events (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   VARCHAR(120) NOT NULL,
    event_type  VARCHAR(80) NOT NULL,
    actor_id    VARCHAR(120),
    payload     TEXT,
    created_at  TIMESTAMP(6) NOT NULL
);
CREATE INDEX idx_tenant_lifecycle_event_tenant_created ON tenant_lifecycle_events (tenant_id, created_at);

CREATE TABLE saas_tenants (
    id                 BIGSERIAL PRIMARY KEY,
    tenant_id          VARCHAR(120) NOT NULL UNIQUE,
    display_name       VARCHAR(255) NOT NULL,
    organization_id    VARCHAR(120) NOT NULL UNIQUE,
    deployment_mode    VARCHAR(40) NOT NULL DEFAULT 'SHARED_CLOUD',
    region             VARCHAR(80) NOT NULL,
    status             VARCHAR(40) NOT NULL DEFAULT 'PENDING',
    plan_code          VARCHAR(80) NOT NULL,
    billing_account_id VARCHAR(120),
    activated_at       TIMESTAMP(6),
    suspended_at       TIMESTAMP(6),
    terminated_at      TIMESTAMP(6),
    created_at         TIMESTAMP(6) NOT NULL,
    updated_at         TIMESTAMP(6) NOT NULL
);
CREATE INDEX idx_saas_tenant_status ON saas_tenants (status);
CREATE INDEX idx_saas_tenant_plan ON saas_tenants (plan_code);

CREATE TABLE tenant_subscriptions (
    id                       BIGSERIAL PRIMARY KEY,
    tenant_id                VARCHAR(120) NOT NULL UNIQUE,
    plan_code                VARCHAR(80) NOT NULL,
    billing_model            VARCHAR(40) NOT NULL DEFAULT 'MONTHLY_TRUE_UP',
    contract_start_at        TIMESTAMP(6) NOT NULL,
    contract_end_at          TIMESTAMP(6),
    support_tier             VARCHAR(40) NOT NULL DEFAULT 'STANDARD',
    auto_renew               BOOLEAN NOT NULL DEFAULT TRUE,
    committed_monthly_amount DECIMAL(18,2) NOT NULL DEFAULT 0.00,
    created_at               TIMESTAMP(6) NOT NULL,
    updated_at               TIMESTAMP(6) NOT NULL
);
CREATE INDEX idx_tenant_sub_plan ON tenant_subscriptions (plan_code);

CREATE TABLE tenant_environments (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       VARCHAR(120) NOT NULL,
    environment_key VARCHAR(80) NOT NULL,
    display_name    VARCHAR(120) NOT NULL,
    deployment_mode VARCHAR(40) NOT NULL,
    region          VARCHAR(80) NOT NULL,
    status          VARCHAR(40) NOT NULL DEFAULT 'ACTIVE',
    created_at      TIMESTAMP(6) NOT NULL,
    updated_at      TIMESTAMP(6) NOT NULL
);
CREATE INDEX idx_tenant_env_key ON tenant_environments (tenant_id, environment_key);

CREATE TABLE tenant_entitlements (
    id                BIGSERIAL PRIMARY KEY,
    tenant_id         VARCHAR(120) NOT NULL,
    entitlement_key   VARCHAR(120) NOT NULL,
    entitlement_value VARCHAR(500) NOT NULL,
    value_type        VARCHAR(40) NOT NULL,
    effective_from    TIMESTAMP(6) NOT NULL,
    effective_to      TIMESTAMP(6),
    source            VARCHAR(40) NOT NULL DEFAULT 'PLAN',
    created_at        TIMESTAMP(6) NOT NULL
);
CREATE INDEX idx_tenant_entitlement ON tenant_entitlements (tenant_id, entitlement_key, effective_to);

CREATE TABLE tenant_operator_assignments (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       VARCHAR(120) NOT NULL,
    user_id         VARCHAR(160) NOT NULL,
    role_code       VARCHAR(80) NOT NULL,
    status          VARCHAR(40) NOT NULL DEFAULT 'INVITED',
    invited_at      TIMESTAMP(6) NOT NULL,
    activated_at    TIMESTAMP(6),
    deactivated_at  TIMESTAMP(6),
    created_by      VARCHAR(160),
    deactivated_by  VARCHAR(160),
    created_at      TIMESTAMP(6) NOT NULL,
    updated_at      TIMESTAMP(6) NOT NULL
);
CREATE INDEX idx_tenant_operator_user ON tenant_operator_assignments (tenant_id, user_id);
CREATE INDEX idx_tenant_operator_status ON tenant_operator_assignments (tenant_id, status);

CREATE TABLE tenant_provisioning_tasks (
    id            BIGSERIAL PRIMARY KEY,
    tenant_id     VARCHAR(120) NOT NULL,
    task_type     VARCHAR(120) NOT NULL,
    status        VARCHAR(40) NOT NULL DEFAULT 'PENDING',
    reference_key VARCHAR(160),
    payload       TEXT,
    scheduled_at  TIMESTAMP(6),
    started_at    TIMESTAMP(6),
    completed_at  TIMESTAMP(6),
    failed_at     TIMESTAMP(6),
    error_message VARCHAR(1000),
    created_at    TIMESTAMP(6) NOT NULL,
    updated_at    TIMESTAMP(6) NOT NULL
);
CREATE INDEX idx_tenant_prov_status ON tenant_provisioning_tasks (tenant_id, task_type, status);

CREATE TABLE tenant_purge_requests (
    id                   BIGSERIAL PRIMARY KEY,
    tenant_id            VARCHAR(120) NOT NULL,
    provisioning_task_id BIGINT,
    reference_key        VARCHAR(160) NOT NULL,
    status               VARCHAR(40) NOT NULL,
    approval_state       VARCHAR(60) NOT NULL,
    data_domains         TEXT,
    requested_by         VARCHAR(120) NOT NULL,
    request_reason       VARCHAR(1000),
    approved_by          VARCHAR(120),
    rejected_by          VARCHAR(120),
    executed_by          VARCHAR(120),
    approved_at          TIMESTAMP(6),
    rejected_at          TIMESTAMP(6),
    executed_at          TIMESTAMP(6),
    scheduled_at         TIMESTAMP(6) NOT NULL,
    execution_summary    VARCHAR(1000),
    metadata             TEXT,
    created_at           TIMESTAMP(6) NOT NULL,
    updated_at           TIMESTAMP(6) NOT NULL
);
CREATE INDEX idx_tenant_purge_status ON tenant_purge_requests (tenant_id, status, scheduled_at);

CREATE TABLE tenant_backup_policies (
    id                              BIGSERIAL PRIMARY KEY,
    tenant_id                       VARCHAR(120) NOT NULL UNIQUE,
    backup_frequency                VARCHAR(40) NOT NULL,
    backup_window_start_hour        INTEGER NOT NULL,
    backup_window_duration_hours    INTEGER NOT NULL,
    backup_retention_days           INTEGER NOT NULL,
    restore_drill_cadence_days      INTEGER NOT NULL,
    restore_evidence_retention_days INTEGER NOT NULL,
    export_window_start_hour        INTEGER NOT NULL,
    export_window_end_hour          INTEGER NOT NULL,
    purge_approval_required         BOOLEAN NOT NULL,
    last_backup_completed_at        TIMESTAMP(6),
    last_restore_drill_completed_at TIMESTAMP(6),
    notes                           VARCHAR(1000),
    created_at                      TIMESTAMP(6) NOT NULL,
    updated_at                      TIMESTAMP(6) NOT NULL
);

CREATE TABLE tenant_restore_drills (
    id                 BIGSERIAL PRIMARY KEY,
    tenant_id          VARCHAR(120) NOT NULL,
    target_environment VARCHAR(80) NOT NULL,
    backup_reference   VARCHAR(255),
    evidence_reference VARCHAR(255),
    status             VARCHAR(40) NOT NULL,
    initiated_by       VARCHAR(120) NOT NULL,
    started_at         TIMESTAMP(6) NOT NULL,
    completed_at       TIMESTAMP(6) NOT NULL,
    notes              VARCHAR(1000),
    metadata           TEXT,
    created_at         TIMESTAMP(6) NOT NULL,
    updated_at         TIMESTAMP(6) NOT NULL
);
CREATE INDEX idx_tenant_drill_status ON tenant_restore_drills (tenant_id, status, completed_at);

CREATE TABLE tenant_quotas (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   VARCHAR(120) NOT NULL,
    quota_key   VARCHAR(120) NOT NULL,
    limit_value BIGINT NOT NULL,
    policy_type VARCHAR(40) NOT NULL DEFAULT 'HARD_LIMIT',
    grace_until TIMESTAMP(6),
    created_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP(6) NOT NULL
);
CREATE INDEX idx_tenant_quota ON tenant_quotas (tenant_id, quota_key);

CREATE TABLE tenant_quota_violations (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       VARCHAR(120) NOT NULL,
    quota_key       VARCHAR(120) NOT NULL,
    policy_type     VARCHAR(40) NOT NULL,
    attempted_usage BIGINT NOT NULL,
    limit_value     BIGINT NOT NULL,
    message         VARCHAR(500) NOT NULL,
    billing_period  VARCHAR(20) NOT NULL,
    metadata        TEXT,
    occurred_at     TIMESTAMP(6) NOT NULL
);
CREATE INDEX idx_tenant_violation_time ON tenant_quota_violations (tenant_id, occurred_at);

CREATE TABLE tenant_isolation_states (
    id                BIGSERIAL PRIMARY KEY,
    tenant_id         VARCHAR(120) NOT NULL,
    scope_type        VARCHAR(40) NOT NULL,
    scope_key         VARCHAR(160) NOT NULL,
    workload_type     VARCHAR(80) NOT NULL,
    status            VARCHAR(40) NOT NULL,
    reason_code       VARCHAR(120) NOT NULL,
    message           VARCHAR(500) NOT NULL,
    trigger_count     INTEGER NOT NULL,
    contained_until   TIMESTAMP(6) NOT NULL,
    last_triggered_at TIMESTAMP(6) NOT NULL,
    created_at        TIMESTAMP(6) NOT NULL,
    updated_at        TIMESTAMP(6) NOT NULL
);
CREATE INDEX idx_tenant_isolation_scope ON tenant_isolation_states (tenant_id, scope_type, scope_key, workload_type);
CREATE INDEX idx_tenant_isolation_status ON tenant_isolation_states (tenant_id, status, contained_until);

CREATE TABLE tenant_isolation_events (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       VARCHAR(120) NOT NULL,
    scope_type      VARCHAR(40) NOT NULL,
    scope_key       VARCHAR(160) NOT NULL,
    workload_type   VARCHAR(80) NOT NULL,
    decision        VARCHAR(60) NOT NULL,
    attempted_value BIGINT NOT NULL,
    limit_value     BIGINT NOT NULL,
    window_seconds  INTEGER NOT NULL,
    message         VARCHAR(500) NOT NULL,
    metadata        TEXT,
    occurred_at     TIMESTAMP(6) NOT NULL
);
CREATE INDEX idx_tenant_iso_event_time ON tenant_isolation_events (tenant_id, occurred_at);

CREATE TABLE tenant_workload_leases (
    id            BIGSERIAL PRIMARY KEY,
    tenant_id     VARCHAR(120) NOT NULL,
    workload_type VARCHAR(80) NOT NULL,
    owner_id      VARCHAR(160) NOT NULL,
    resource_key  VARCHAR(200),
    status        VARCHAR(40) NOT NULL,
    metadata      TEXT,
    acquired_at   TIMESTAMP(6) NOT NULL,
    expires_at    TIMESTAMP(6) NOT NULL,
    released_at   TIMESTAMP(6)
);
CREATE INDEX idx_tenant_lease_active ON tenant_workload_leases (tenant_id, workload_type, status, expires_at);

CREATE TABLE protected_app_groups (
    id                BIGSERIAL PRIMARY KEY,
    app_group_id      VARCHAR(120) NOT NULL UNIQUE,
    tenant_id         VARCHAR(120) NOT NULL,
    display_name      VARCHAR(255) NOT NULL,
    environment       VARCHAR(80) NOT NULL,
    binding_type      VARCHAR(40) NOT NULL,
    status            VARCHAR(40) NOT NULL DEFAULT 'PENDING_HEARTBEAT',
    last_heartbeat_at TIMESTAMP(6),
    created_at        TIMESTAMP(6) NOT NULL,
    updated_at        TIMESTAMP(6) NOT NULL
);
CREATE INDEX idx_app_group_tenant_status ON protected_app_groups (tenant_id, status);

CREATE TABLE protected_app_endpoints (
    id           BIGSERIAL PRIMARY KEY,
    tenant_id    VARCHAR(120) NOT NULL,
    app_group_id VARCHAR(120) NOT NULL,
    path_pattern VARCHAR(300) NOT NULL,
    http_method  VARCHAR(20) NOT NULL,
    sensitivity  VARCHAR(40) NOT NULL DEFAULT 'STANDARD',
    status       VARCHAR(40) NOT NULL DEFAULT 'ACTIVE',
    created_at   TIMESTAMP(6) NOT NULL
);
CREATE INDEX idx_app_endpoint_group ON protected_app_endpoints (app_group_id);

CREATE TABLE protected_app_bindings (
    id           BIGSERIAL PRIMARY KEY,
    app_group_id VARCHAR(120) NOT NULL,
    binding_key  VARCHAR(120) NOT NULL,
    binding_value VARCHAR(500) NOT NULL,
    status       VARCHAR(40) NOT NULL DEFAULT 'ACTIVE',
    created_at   TIMESTAMP(6) NOT NULL
);
CREATE INDEX idx_app_binding_group ON protected_app_bindings (app_group_id);

CREATE TABLE protected_app_heartbeats (
    id            BIGSERIAL PRIMARY KEY,
    tenant_id     VARCHAR(120) NOT NULL,
    app_group_id  VARCHAR(120) NOT NULL,
    client_id     VARCHAR(160),
    occurred_at   TIMESTAMP(6) NOT NULL,
    source_module VARCHAR(120) NOT NULL,
    metadata      TEXT
);
CREATE INDEX idx_app_heartbeat_group ON protected_app_heartbeats (tenant_id, app_group_id, occurred_at);

CREATE TABLE billing_contracts (
    id                     BIGSERIAL PRIMARY KEY,
    tenant_id              VARCHAR(120) NOT NULL UNIQUE,
    billing_channel        VARCHAR(40) NOT NULL DEFAULT 'DIRECT',
    billing_model          VARCHAR(40) NOT NULL,
    currency               VARCHAR(16) NOT NULL DEFAULT 'USD',
    annual_commit_amount   DECIMAL(18,2),
    reseller_partner_id    VARCHAR(120),
    marketplace_provider   VARCHAR(80),
    marketplace_account_id VARCHAR(180),
    settlement_account_id  VARCHAR(180),
    effective_from         TIMESTAMP(6) NOT NULL,
    effective_to           TIMESTAMP(6),
    status                 VARCHAR(40) NOT NULL DEFAULT 'ACTIVE',
    notes                  TEXT,
    created_at             TIMESTAMP(6) NOT NULL,
    updated_at             TIMESTAMP(6) NOT NULL
);
CREATE INDEX idx_billing_contract_channel ON billing_contracts (billing_channel);
CREATE INDEX idx_billing_contract_status ON billing_contracts (status);

CREATE TABLE billing_invoices (
    id               BIGSERIAL PRIMARY KEY,
    invoice_id       VARCHAR(160) NOT NULL UNIQUE,
    tenant_id        VARCHAR(120) NOT NULL,
    billing_period   VARCHAR(20) NOT NULL,
    currency         VARCHAR(16) NOT NULL DEFAULT 'USD',
    committed_amount DECIMAL(18,2) NOT NULL DEFAULT 0.00,
    overage_amount   DECIMAL(18,2) NOT NULL DEFAULT 0.00,
    total_amount     DECIMAL(18,2) NOT NULL DEFAULT 0.00,
    status           VARCHAR(40) NOT NULL DEFAULT 'DRAFT',
    issued_at        TIMESTAMP(6),
    due_at           TIMESTAMP(6),
    created_at       TIMESTAMP(6) NOT NULL,
    updated_at       TIMESTAMP(6) NOT NULL
);
CREATE INDEX idx_billing_invoice_tenant ON billing_invoices (tenant_id, billing_period);

CREATE TABLE billing_line_items (
    id          BIGSERIAL PRIMARY KEY,
    invoice_id  VARCHAR(160) NOT NULL,
    line_type   VARCHAR(40) NOT NULL,
    meter_key   VARCHAR(80),
    description VARCHAR(255) NOT NULL,
    quantity    DECIMAL(18,2) NOT NULL DEFAULT 0.00,
    unit_price  DECIMAL(18,2) NOT NULL DEFAULT 0.00,
    amount      DECIMAL(18,2) NOT NULL DEFAULT 0.00,
    created_at  TIMESTAMP(6) NOT NULL
);
CREATE INDEX idx_billing_line_invoice ON billing_line_items (invoice_id);

CREATE TABLE billing_adjustments (
    id              BIGSERIAL PRIMARY KEY,
    adjustment_id   VARCHAR(180) NOT NULL UNIQUE,
    tenant_id       VARCHAR(120) NOT NULL,
    billing_period  VARCHAR(20) NOT NULL,
    invoice_id      VARCHAR(160),
    adjustment_type VARCHAR(40) NOT NULL,
    reason_code     VARCHAR(80) NOT NULL,
    description     VARCHAR(255) NOT NULL,
    amount          DECIMAL(18,2) NOT NULL DEFAULT 0.00,
    status          VARCHAR(60) NOT NULL,
    requested_by    VARCHAR(120) NOT NULL,
    applied_at      TIMESTAMP(6),
    voided_at       TIMESTAMP(6),
    voided_by       VARCHAR(120),
    void_reason     VARCHAR(255),
    metadata        TEXT,
    created_at      TIMESTAMP(6) NOT NULL,
    updated_at      TIMESTAMP(6) NOT NULL
);
CREATE INDEX idx_billing_adj_tenant ON billing_adjustments (tenant_id, billing_period);

CREATE TABLE invoice_export_batches (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       VARCHAR(120) NOT NULL,
    invoice_id      VARCHAR(160),
    billing_period  VARCHAR(20) NOT NULL,
    export_type     VARCHAR(60) NOT NULL,
    export_format   VARCHAR(20) NOT NULL,
    status          VARCHAR(40) NOT NULL,
    requested_by    VARCHAR(120),
    file_name       VARCHAR(220) NOT NULL,
    checksum_sha256 VARCHAR(128),
    metadata        TEXT,
    exported_at     TIMESTAMP(6) NOT NULL
);
CREATE INDEX idx_invoice_export_tenant ON invoice_export_batches (tenant_id, billing_period);

CREATE TABLE usage_meter_events (
    id             BIGSERIAL PRIMARY KEY,
    tenant_id      VARCHAR(120) NOT NULL,
    meter_key      VARCHAR(120) NOT NULL,
    quantity       BIGINT NOT NULL,
    unit           VARCHAR(40) NOT NULL,
    source_module  VARCHAR(120) NOT NULL,
    source_ref     VARCHAR(180),
    occurred_at    TIMESTAMP(6) NOT NULL,
    billing_period VARCHAR(20) NOT NULL,
    metadata       TEXT
);
CREATE INDEX idx_usage_meter_period ON usage_meter_events (tenant_id, billing_period);

CREATE TABLE usage_aggregations (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           VARCHAR(120) NOT NULL,
    billing_period      VARCHAR(20) NOT NULL,
    meter_key           VARCHAR(120) NOT NULL,
    aggregated_quantity BIGINT NOT NULL,
    included_quantity   BIGINT NOT NULL,
    overage_quantity    BIGINT NOT NULL,
    calculated_at       TIMESTAMP(6) NOT NULL,
    UNIQUE (tenant_id, billing_period, meter_key)
);

CREATE TABLE dedicated_deployment_profiles (
    id                BIGSERIAL PRIMARY KEY,
    tenant_id         VARCHAR(120) NOT NULL UNIQUE,
    region            VARCHAR(80) NOT NULL,
    previous_region   VARCHAR(80),
    network_isolation VARCHAR(80) NOT NULL,
    retention_policy  VARCHAR(80) NOT NULL,
    support_tier      VARCHAR(40) NOT NULL,
    billing_model     VARCHAR(40) NOT NULL,
    allocation_state  VARCHAR(40) NOT NULL DEFAULT 'REQUESTED',
    requested_at      TIMESTAMP(6),
    activated_at      TIMESTAMP(6),
    notes             TEXT,
    created_at        TIMESTAMP(6) NOT NULL,
    updated_at        TIMESTAMP(6) NOT NULL
);
CREATE INDEX idx_dedicated_deploy_state ON dedicated_deployment_profiles (allocation_state);
