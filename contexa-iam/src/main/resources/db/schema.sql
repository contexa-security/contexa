create extension if not exists vector;

create table users
(
    id                    bigserial
        primary key,
    username              varchar(100)                           not null
        unique,
    email                 varchar(255)                           not null
        unique,
    password              varchar(255)                           not null,
    name                  varchar(100)                           not null,
    phone                 varchar(20),
    department            varchar(100),
    position              varchar(100),
    profile_image_url     varchar(500),
    enabled               boolean      default true              not null,
    account_locked        boolean      default false             not null,
    credentials_expired   boolean      default false             not null,
    failed_login_attempts integer      default 0                 not null,
    lock_expires_at       timestamp(6),
    mfa_enabled           boolean      default false             not null,
    preferred_mfa_factor  varchar(50),
    last_used_mfa_factor  varchar(50),
    last_mfa_used_at      timestamp(6),
    last_login_at         timestamp(6),
    last_login_ip         varchar(45),
    password_changed_at   timestamp(6),
    locale                varchar(10)  default 'ko'::character varying,
    timezone              varchar(50)  default 'Asia/Seoul'::character varying,
    created_at            timestamp(6) default CURRENT_TIMESTAMP not null,
    updated_at            timestamp(6),
    authentication_source varchar(100),
    bridge_subject_key    varchar(120)
        constraint uk5rjvurnq36ksjjr71o1siari7
            unique,
    external_subject_id   varchar(255),
    last_bridged_at       timestamp(6),
    organization_id       varchar(255),
    principal_type        varchar(50),
    bridge_managed        boolean      default false             not null,
    external_auth_only    boolean      default false             not null
);


create index idx_users_email
    on users (email);

create index idx_users_department
    on users (department);

create index idx_users_enabled
    on users (enabled);

create table app_group
(
    group_id    bigserial
        primary key,
    group_name  varchar(100)                           not null
        unique,
    description varchar(500),
    enabled     boolean      default true              not null,
    created_at  timestamp(6) default CURRENT_TIMESTAMP not null,
    updated_at  timestamp(6),
    created_by  varchar(100)
);


create table role
(
    role_id       bigserial
        primary key,
    role_name     varchar(100)                           not null
        unique,
    role_desc     varchar(500),
    expression    boolean      default false             not null,
    enabled       boolean      default true              not null,
    created_at    timestamp(6) default CURRENT_TIMESTAMP not null,
    updated_at    timestamp(6),
    created_by    varchar(100),
    is_expression varchar(255)
);


create table managed_resource
(
    id                          bigserial
        primary key,
    resource_identifier         varchar(512)                                               not null
        unique,
    resource_type               varchar(255)                                               not null,
    http_method                 varchar(255),
    friendly_name               varchar(255),
    description                 varchar(1024),
    service_owner               varchar(255),
    parameter_types             varchar(1024),
    return_type                 varchar(512),
    api_docs_url                varchar(1024),
    source_code_location        varchar(1024),
    status                      varchar(255) default 'NEEDS_DEFINITION'::character varying not null,
    created_at                  timestamp(6) default CURRENT_TIMESTAMP                     not null,
    updated_at                  timestamp(6) default CURRENT_TIMESTAMP                     not null,
    available_context_variables varchar(1024)
);


create table permission
(
    permission_id        bigserial
        primary key,
    permission_name      varchar(255)                           not null
        unique,
    friendly_name        varchar(255),
    description          varchar(1024),
    target_type          varchar(100),
    action_type          varchar(100),
    condition_expression varchar(2048),
    managed_resource_id  bigint
        unique
                                                                references managed_resource
                                                                    on delete set null,
    auto_created         boolean      default false             not null,
    created_at           timestamp(6) default CURRENT_TIMESTAMP not null,
    updated_at           timestamp(6)
);


create table user_groups
(
    user_id     bigint                                 not null
        references users
            on delete cascade,
    group_id    bigint                                 not null
        references app_group
            on delete cascade,
    assigned_at timestamp(6) default CURRENT_TIMESTAMP not null,
    assigned_by varchar(100),
    primary key (user_id, group_id)
);


create table group_roles
(
    group_id    bigint                                 not null
        references app_group
            on delete cascade,
    role_id     bigint                                 not null
        references role
            on delete cascade,
    assigned_at timestamp(6) default CURRENT_TIMESTAMP not null,
    assigned_by varchar(100),
    primary key (group_id, role_id)
);


create table role_permissions
(
    role_id       bigint                                 not null
        references role
            on delete cascade,
    permission_id bigint                                 not null
        references permission
            on delete cascade,
    assigned_at   timestamp(6) default CURRENT_TIMESTAMP not null,
    assigned_by   varchar(100),
    primary key (role_id, permission_id)
);


create table policy
(
    id                   bigserial
        primary key,
    name                 varchar(255)                           not null
        unique,
    description          varchar(255),
    effect               varchar(255)                           not null,
    priority             integer                                not null,
    friendly_description varchar(2048),
    ai_model             varchar(255),
    approval_status      varchar(50)
        constraint policy_approval_status_check
            check ((approval_status)::text = ANY
                   (ARRAY [('PENDING'::character varying)::text, ('APPROVED'::character varying)::text, ('REJECTED'::character varying)::text, ('NOT_REQUIRED'::character varying)::text])),
    approved_at          timestamp(6),
    approved_by          varchar(255),
    confidence_score     double precision,
    source               varchar(50)
        constraint policy_source_check
            check ((source)::text = ANY
                   (ARRAY [('MANUAL'::character varying)::text, ('AI_GENERATED'::character varying)::text, ('AI_EVOLVED'::character varying)::text, ('IMPORTED'::character varying)::text])),
    updated_at           timestamp(6),
    created_at           timestamp(6) default CURRENT_TIMESTAMP not null,
    is_active            boolean      default true              not null,
    reasoning            varchar(4096)
);


create table policy_target
(
    id                bigserial
        primary key,
    policy_id         bigint                not null
        references policy
            on delete cascade,
    target_type       varchar(255)          not null,
    target_identifier varchar(255)          not null,
    http_method       varchar(255),
    target_order      integer     default 0 not null,
    source_type       varchar(20) default 'RESOURCE'::character varying
);


create table policy_rule
(
    id          bigserial
        primary key,
    policy_id   bigint not null
        references policy
            on delete cascade,
    description varchar(255)
);


create table policy_condition
(
    id                   bigserial
        primary key,
    rule_id              bigint                                                  not null
        references policy_rule
            on delete cascade,
    condition_expression varchar(2048)                                           not null,
    authorization_phase  varchar(255) default 'PRE_AUTHORIZE'::character varying not null,
    description          varchar(255)
);


create table role_hierarchy_config
(
    hierarchy_id     bigserial
        primary key,
    description      varchar(255),
    hierarchy_string text                  not null
        unique,
    is_active        boolean default false not null
);


create table audit_log
(
    id                  bigserial
        primary key,
    timestamp           timestamp(6) default CURRENT_TIMESTAMP not null,
    principal_name      varchar(255)                           not null,
    resource_identifier varchar(512)                           not null,
    action              varchar(100),
    decision            varchar(50)                            not null,
    reason              varchar(1024),
    client_ip           varchar(45),
    details             text,
    outcome             varchar(50),
    resource_uri        varchar(1024),
    session_id          varchar(128),
    correlation_id      varchar(64),
    event_category      varchar(50),
    event_source        varchar(50),
    http_method         varchar(10),
    request_uri         varchar(2048),
    risk_score          double precision,
    user_agent          varchar(512),
    parameters          varchar(255),
    status              varchar(255)
);


create table business_resource
(
    id            bigserial
        primary key,
    name          varchar(255) not null
        unique,
    resource_type varchar(100) not null,
    description   varchar(1024)
);


create table business_action
(
    id          bigserial
        primary key,
    name        varchar(255) not null
        unique,
    action_type varchar(100) not null,
    description varchar(1024)
);


create table business_resource_action
(
    business_resource_id   bigint       not null
        references business_resource
            on delete cascade,
    business_action_id     bigint       not null
        references business_action
            on delete cascade,
    mapped_permission_name varchar(255) not null,
    primary key (business_resource_id, business_action_id)
);


create table condition_template
(
    id                   bigserial
        primary key,
    name                 varchar(255)      not null
        unique,
    spel_template        varchar(2048)     not null,
    category             varchar(255),
    parameter_count      integer default 0 not null,
    description          varchar(1024),
    required_target_type varchar(1024),
    created_at           timestamp(6),
    is_auto_generated    boolean,
    is_universal         boolean,
    source_method        varchar(255),
    template_type        varchar(255),
    updated_at           timestamp(6),
    approval_required    boolean,
    classification       varchar(255)
        constraint condition_template_classification_check
            check ((classification)::text = ANY
                   (ARRAY [('UNIVERSAL'::character varying)::text, ('CONTEXT_DEPENDENT'::character varying)::text, ('CUSTOM_COMPLEX'::character varying)::text])),
    complexity_score     integer,
    context_dependent    boolean
);


create table wizard_session
(
    session_id    varchar(36)  not null
        primary key,
    context_data  text         not null,
    owner_user_id varchar(255) not null,
    created_at    timestamp(6) not null,
    expires_at    timestamp(6) not null
);


create table function_group
(
    id   bigserial
        primary key,
    name varchar(255) not null
        unique
);


create table function_catalog
(
    id                  bigserial
        primary key,
    description         varchar(1024),
    friendly_name       varchar(255) not null,
    status              varchar(255) not null
        constraint function_catalog_status_check
            check ((status)::text = ANY
                   (ARRAY [('UNCONFIRMED'::character varying)::text, ('ACTIVE'::character varying)::text, ('INACTIVE'::character varying)::text])),
    function_group_id   bigint
        references function_group,
    managed_resource_id bigint       not null
        unique
        references managed_resource
);


create table policy_template
(
    id                bigserial
        primary key,
    category          varchar(255),
    description       varchar(1024),
    name              varchar(255) not null,
    policy_draft_json jsonb        not null,
    template_id       varchar(255) not null
        unique
);


create table vector_store
(
    id        uuid default gen_random_uuid() not null
        primary key,
    content   text                           not null,
    metadata  jsonb,
    embedding vector(1024)
);


create index vector_store_embedding_idx
    on vector_store using hnsw (embedding vector_cosine_ops);

create index spring_ai_vector_index
    on vector_store using hnsw (embedding vector_cosine_ops);

create table user_behavior_profiles
(
    id                      bigserial
        primary key,
    cluster_centroid_vector text,
    cluster_size            integer,
    common_activities       json,
    common_ip_ranges        json,
    confidence_score        real,
    last_updated            timestamp(6),
    learning_count          integer,
    normal_range_metadata   json,
    profile_type            varchar(50)  not null,
    user_id                 varchar(255) not null,
    vector_cluster_id       varchar(100)
);


create table soar_incidents
(
    id          uuid         not null
        primary key,
    created_at  timestamp(6) not null,
    history     text,
    severity    varchar(20),
    status      varchar(255) not null
        constraint soar_incidents_status_check
            check ((status)::text = ANY
                   (ARRAY [('NEW'::character varying)::text, ('TRIAGE'::character varying)::text, ('INVESTIGATION'::character varying)::text, ('PLANNING'::character varying)::text, ('PENDING_APPROVAL'::character varying)::text, ('EXECUTION'::character varying)::text, ('REPORTING'::character varying)::text, ('COMPLETED'::character varying)::text, ('AUTO_CLOSED'::character varying)::text, ('FAILED'::character varying)::text, ('CLOSED_BY_ADMIN'::character varying)::text])),
    title       varchar(255) not null,
    updated_at  timestamp(6) not null,
    description text,
    incident_id varchar(100),
    metadata    text,
    type        varchar(50)
);


create table soar_approval_policies
(
    id                      bigserial
        primary key,
    action_name             varchar(255),
    auto_approve_on_timeout boolean      not null,
    policy_name             varchar(255) not null
        unique,
    required_approvers      integer      not null,
    required_roles          text,
    severity                varchar(20),
    timeout_minutes         integer      not null
);


create table soar_approval_requests
(
    id                       bigserial
        primary key,
    action_name              varchar(255) not null,
    created_at               timestamp(6) not null,
    description              text,
    organization_id          varchar(100),
    parameters               text,
    playbook_instance_id     varchar(100) not null,
    required_approvers       integer,
    required_roles           text,
    reviewer_comment         text,
    reviewer_id              varchar(255),
    status                   varchar(30)  not null,
    updated_at               timestamp(6) not null,
    request_id               varchar(100) not null
        unique,
    action_type              varchar(50),
    approval_comment         text,
    approval_timeout         integer,
    approval_type            varchar(50),
    approved_at              timestamp(6),
    approved_by              varchar(255),
    incident_id              varchar(100),
    requested_by             varchar(255),
    risk_level               varchar(20),
    session_id               varchar(128),
    tool_name                varchar(255),
    approved_count           integer,
    rejected_count           integer,
    remaining_approvals      integer,
    quorum_satisfied         boolean default false,
    current_step_number      integer,
    total_steps              integer,
    reopened_from_request_id varchar(100),
    break_glass_requested    boolean default false,
    break_glass_reason       text
);


create table soar_approval_steps
(
    id                  bigserial
        primary key,
    request_id          varchar(100) not null,
    step_number         integer      not null,
    step_name           varchar(150) not null,
    status              varchar(30)  not null,
    required_approvers  integer      not null,
    approved_count      integer      not null,
    rejected_count      integer      not null,
    remaining_approvals integer      not null,
    required_roles      text,
    opened_at           timestamp(6),
    completed_at        timestamp(6),
    created_at          timestamp(6) not null,
    updated_at          timestamp(6) not null,
    constraint uk_soar_approval_step_request_number
        unique (request_id, step_number)
);


create index idx_soar_approval_step_request_id
    on soar_approval_steps (request_id);

create index idx_soar_approval_step_status
    on soar_approval_steps (status);

create table soar_approval_assignments
(
    id                bigserial
        primary key,
    request_id        varchar(100) not null,
    step_number       integer      not null,
    assignee_id       varchar(100),
    assignee_role     varchar(100),
    status            varchar(30)  not null,
    assigned_by       varchar(100),
    assigned_at       timestamp(6),
    responded_at      timestamp(6),
    response_decision varchar(30),
    response_comment  text,
    created_at        timestamp(6) not null,
    updated_at        timestamp(6) not null
);


create index idx_soar_approval_assignment_request_id
    on soar_approval_assignments (request_id);

create index idx_soar_approval_assignment_status
    on soar_approval_assignments (status);

create index idx_soar_approval_assignment_step
    on soar_approval_assignments (request_id, step_number);

create table soar_approval_votes
(
    id            bigserial
        primary key,
    request_id    varchar(100) not null,
    approver_id   varchar(100) not null,
    approver_name varchar(150),
    approver_role varchar(100) not null,
    decision      varchar(20)  not null,
    comment       text,
    step_number   integer      not null,
    created_at    timestamp(6) not null,
    updated_at    timestamp(6) not null,
    constraint uk_soar_approval_vote_request_approver_step
        unique (request_id, approver_id, step_number)
);


create index idx_soar_approval_vote_request_id
    on soar_approval_votes (request_id);

create index idx_soar_approval_vote_created_at
    on soar_approval_votes (created_at);

create index idx_soar_approval_vote_request_step
    on soar_approval_votes (request_id, step_number);

create table approval_notifications
(
    id                bigserial
        primary key,
    action_required   boolean      not null,
    action_url        varchar(500),
    created_at        timestamp(6) not null,
    expires_at        timestamp(6),
    group_id          varchar(100),
    is_read           boolean      not null,
    message           text,
    notification_data text,
    notification_type varchar(50)  not null,
    priority          varchar(20),
    read_at           timestamp(6),
    read_by           varchar(100),
    request_id        varchar(100) not null,
    target_role       varchar(50),
    title             varchar(255) not null,
    updated_at        timestamp(6) not null,
    user_id           varchar(100)
);


create index idx_notification_request_id
    on approval_notifications (request_id);

create index idx_notification_user_id
    on approval_notifications (user_id);

create index idx_notification_is_read
    on approval_notifications (is_read);

create index idx_notification_created_at
    on approval_notifications (created_at);

create table threat_indicators
(
    indicator_id         varchar(100)  not null
        primary key,
    active               boolean,
    campaign             varchar(255),
    campaign_id          varchar(100),
    cis_control          varchar(100),
    confidence           double precision,
    created_at           timestamp(6)  not null,
    description          text,
    detected_at          timestamp(6),
    detection_count      integer,
    expires_at           timestamp(6),
    false_positive_count integer,
    first_seen           timestamp(6),
    last_seen            timestamp(6),
    malware_family       varchar(255),
    mitre_attack_id      varchar(50),
    mitre_tactic         varchar(100),
    mitre_technique      varchar(100),
    nist_csf_category    varchar(100),
    severity             varchar(255)  not null
        constraint threat_indicators_severity_check
            check ((severity)::text = ANY
                   (ARRAY [('CRITICAL'::character varying)::text, ('HIGH'::character varying)::text, ('MEDIUM'::character varying)::text, ('LOW'::character varying)::text, ('INFO'::character varying)::text])),
    source               varchar(255),
    status               varchar(255)
        constraint threat_indicators_status_check
            check ((status)::text = ANY
                   (ARRAY [('ACTIVE'::character varying)::text, ('INACTIVE'::character varying)::text, ('EXPIRED'::character varying)::text, ('FALSE_POSITIVE'::character varying)::text, ('UNDER_REVIEW'::character varying)::text])),
    threat_actor         varchar(255),
    threat_actor_id      varchar(100),
    threat_score         double precision,
    indicator_type       varchar(255)  not null
        constraint threat_indicators_indicator_type_check
            check ((indicator_type)::text = ANY
                   (ARRAY [('IP_ADDRESS'::character varying)::text, ('DOMAIN'::character varying)::text, ('URL'::character varying)::text, ('FILE_HASH'::character varying)::text, ('FILE_PATH'::character varying)::text, ('REGISTRY_KEY'::character varying)::text, ('PROCESS_NAME'::character varying)::text, ('EMAIL_ADDRESS'::character varying)::text, ('USER_AGENT'::character varying)::text, ('CERTIFICATE'::character varying)::text, ('MUTEX'::character varying)::text, ('YARA_RULE'::character varying)::text, ('BEHAVIORAL'::character varying)::text, ('UNKNOWN'::character varying)::text, ('PATTERN'::character varying)::text, ('USER_ACCOUNT'::character varying)::text, ('COMPLIANCE'::character varying)::text, ('EVENT'::character varying)::text])),
    updated_at           timestamp(6),
    indicator_value      varchar(1024) not null
);


create table indicator_metadata
(
    indicator_id varchar(100) not null
        references threat_indicators,
    meta_value   varchar(255),
    meta_key     varchar(255) not null,
    primary key (indicator_id, meta_key)
);


create table indicator_tags
(
    indicator_id varchar(100) not null
        references threat_indicators,
    tag          varchar(255)
);


create table related_indicators
(
    indicator_id         varchar(100) not null
        references threat_indicators,
    related_indicator_id varchar(100) not null
        references threat_indicators,
    primary key (indicator_id, related_indicator_id)
);


create table blocked_user
(
    id                   bigserial
        primary key,
    block_count          integer      not null,
    blocked_at           timestamp(6) not null,
    confidence           double precision,
    reasoning            text,
    request_id           varchar(255) not null
        unique,
    resolve_reason       text,
    resolved_action      varchar(255),
    resolved_at          timestamp(6),
    resolved_by          varchar(255),
    risk_score           double precision,
    source_ip            varchar(255),
    status               varchar(255) not null
        constraint blocked_user_status_check
            check ((status)::text = ANY
                   (ARRAY [('BLOCKED'::character varying)::text, ('UNBLOCK_REQUESTED'::character varying)::text, ('RESOLVED'::character varying)::text, ('TIMEOUT_RESPONDED'::character varying)::text, ('MFA_FAILED'::character varying)::text])),
    user_agent           varchar(255),
    user_id              varchar(255) not null,
    username             varchar(255),
    unblock_requested_at timestamp(6),
    unblock_reason       text,
    mfa_verified         boolean,
    mfa_verified_at      timestamp(6)
);


create table oauth2_authorization
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


create index idx_oauth2_authorization_registered_client_id
    on oauth2_authorization (registered_client_id);

create index idx_oauth2_authorization_principal_name
    on oauth2_authorization (principal_name);

create table oauth2_registered_client
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


create unique index idx_oauth2_registered_client_client_id
    on oauth2_registered_client (client_id);

create table user_credentials
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


create table user_entities
(
    id           varchar(1000) not null
        primary key,
    name         varchar(100)  not null,
    display_name varchar(200)
);


create table one_time_tokens
(
    token_value varchar(36) not null
        primary key,
    username    varchar(50) not null,
    expires_at  timestamp   not null
);


create table oauth2_authorization_consent
(
    registered_client_id varchar(100)  not null
        references oauth2_registered_client,
    principal_name       varchar(200)  not null,
    authorities          varchar(1000) not null,
    primary key (registered_client_id, principal_name)
);


create table baseline_signal_outbox
(
    id                                 bigint generated by default as identity
        primary key,
    access_days_distribution_json      text,
    access_hours_distribution_json     text,
    attempt_count                      integer      not null,
    created_at                         timestamp(6) not null,
    delivered_at                       timestamp(6),
    generated_at                       timestamp(6),
    industry_category                  varchar(80),
    last_error                         varchar(2000),
    next_attempt_at                    timestamp(6),
    operating_system_distribution_json text,
    organization_baseline_count        bigint       not null,
    period_start                       date         not null
        constraint uk_baseline_signal_outbox_period
            unique,
    signal_id                          varchar(64)  not null,
    status                             varchar(32)  not null,
    updated_at                         timestamp(6) not null,
    user_baseline_count                bigint       not null
);


create index idx_baseline_signal_outbox_dispatch
    on baseline_signal_outbox (status, next_attempt_at, period_start);

create table decision_feedback_forwarding_outbox
(
    id                  bigint generated by default as identity
        primary key,
    attempt_count       integer      not null,
    correlation_id      varchar(64)  not null,
    created_at          timestamp(6) not null,
    delivered_at        timestamp(6),
    feedback_id         varchar(64)  not null
        constraint uk_decision_feedback_forwarding_outbox_feedback_id
            unique,
    last_error          varchar(2000),
    next_attempt_at     timestamp(6),
    payload_json        text         not null,
    status              varchar(32)  not null,
    tenant_external_ref varchar(128) not null,
    updated_at          timestamp(6) not null
);


create index idx_decision_feedback_forwarding_outbox_dispatch
    on decision_feedback_forwarding_outbox (status, next_attempt_at, created_at);

create table model_performance_telemetry_outbox
(
    id                            bigint generated by default as identity
        primary key,
    attempt_count                 integer      not null,
    block_count                   bigint       not null,
    challenge_count               bigint       not null,
    created_at                    timestamp(6) not null,
    delivered_at                  timestamp(6),
    escalate_protection_triggered integer      not null,
    last_error                    varchar(2000),
    layer1_escalation_count       bigint       not null,
    layer1_processing_total_ms    bigint       not null,
    layer1_sample_count           bigint       not null,
    layer2_processing_total_ms    bigint       not null,
    layer2_sample_count           bigint       not null,
    next_attempt_at               timestamp(6),
    period                        date         not null
        constraint uk_model_performance_telemetry_outbox_period
            unique,
    status                        varchar(32)  not null,
    telemetry_id                  varchar(64)  not null,
    total_event_count             bigint       not null,
    updated_at                    timestamp(6) not null
);


create index idx_model_performance_telemetry_outbox_dispatch
    on model_performance_telemetry_outbox (status, next_attempt_at, period);

create table prompt_context_audit_forwarding_outbox
(
    id                  bigint generated by default as identity
        primary key,
    attempt_count       integer      not null,
    audit_id            varchar(64)  not null
        constraint uk_prompt_context_audit_forwarding_outbox_audit_id
            unique,
    correlation_id      varchar(64)  not null,
    created_at          timestamp(6) not null,
    delivered_at        timestamp(6),
    last_error          varchar(2000),
    next_attempt_at     timestamp(6),
    payload_json        text         not null,
    status              varchar(32)  not null,
    tenant_external_ref varchar(128) not null,
    updated_at          timestamp(6) not null
);


create index idx_prompt_context_audit_forwarding_outbox_dispatch
    on prompt_context_audit_forwarding_outbox (status, next_attempt_at, created_at);

create table security_decision_forwarding_outbox
(
    id                  bigint generated by default as identity
        primary key,
    attempt_count       integer      not null,
    correlation_id      varchar(64)  not null
        constraint uk_security_decision_forwarding_outbox_correlation_id
            unique,
    created_at          timestamp(6) not null,
    delivered_at        timestamp(6),
    last_error          varchar(2000),
    next_attempt_at     timestamp(6),
    payload_json        text         not null,
    status              varchar(32)  not null,
    tenant_external_ref varchar(128) not null,
    updated_at          timestamp(6) not null
);


create index idx_security_decision_forwarding_outbox_dispatch
    on security_decision_forwarding_outbox (status, next_attempt_at, created_at);

create table threat_outcome_forwarding_outbox
(
    id                  bigint generated by default as identity
        primary key,
    attempt_count       integer      not null,
    correlation_id      varchar(64)  not null,
    created_at          timestamp(6) not null,
    delivered_at        timestamp(6),
    last_error          varchar(2000),
    next_attempt_at     timestamp(6),
    outcome_id          varchar(64)  not null
        constraint uk_threat_outcome_forwarding_outbox_outcome_id
            unique,
    payload_json        text         not null,
    status              varchar(32)  not null,
    tenant_external_ref varchar(128) not null,
    updated_at          timestamp(6) not null
);


create index idx_threat_outcome_forwarding_outbox_dispatch
    on threat_outcome_forwarding_outbox (status, next_attempt_at, created_at);

create table user_roles
(
    role_id     bigint       not null
        constraint fkrhfovtciq1l558cw6udg0h0d3
            references role,
    user_id     bigint       not null
        constraint fkhfh9dx7w3ubf1co1vdev94g3f
            references users,
    assigned_at timestamp(6) not null,
    assigned_by varchar(100),
    primary key (role_id, user_id)
);


create table password_policy
(
    id                       bigint generated by default as identity
        primary key,
    created_at               timestamp(6)       not null,
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
    updated_at               timestamp(6),
    ip_max_failed_attempts   integer default 30 not null,
    ip_window_minutes        integer default 15 not null
);


create table behavior_anomaly_events
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


create table behavior_based_permissions
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


create table behavior_realtime_cache
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


create table bridge_user_profile
(
    user_id                     bigint       not null
        primary key
        constraint fk6ln576ijwr4i3kdbqmfjyedeo
            references users,
    authentication_assurance    varchar(100),
    authentication_type         varchar(100),
    created_at                  timestamp(6) not null,
    last_attributes_json        text,
    last_authorities_json       text,
    last_sync_hash              varchar(128),
    last_synced_at              timestamp(6),
    mfa_completed_from_customer boolean,
    session_id                  varchar(255),
    source_system               varchar(100),
    updated_at                  timestamp(6)
);


create table active_sessions
(
    session_id       varchar(128) not null
        primary key,
    client_ip        varchar(45),
    created_at       timestamp(6) not null,
    expired          boolean      not null,
    last_accessed_at timestamp(6),
    user_agent       varchar(512),
    user_id          varchar(255) not null,
    username         varchar(255)
);


create index idx_session_user_id
    on active_sessions (user_id);

create index idx_session_expired
    on active_sessions (expired);

create table ip_access_rules
(
    id          bigint generated by default as identity
        primary key,
    created_at  timestamp(6) not null,
    created_by  varchar(255),
    description varchar(500),
    enabled     boolean      not null,
    expires_at  timestamp(6),
    ip_address  varchar(45)  not null,
    rule_type   varchar(10)  not null
        constraint ip_access_rules_rule_type_check
            check ((rule_type)::text = ANY
                   (ARRAY [('ALLOW'::character varying)::text, ('DENY'::character varying)::text]))
);


create index idx_ip_rule_type
    on ip_access_rules (rule_type);

create index idx_ip_rule_enabled
    on ip_access_rules (enabled);

create index idx_ip_address
    on ip_access_rules (ip_address);

create table security_spel
(
    id          bigserial
        primary key,
    name        varchar(255)  not null
        unique,
    expression  varchar(2048) not null,
    description varchar(1024),
    category    varchar(100),
    created_at  timestamp default now()
);


create table admin_menu
(
    id         bigserial
        primary key,
    name       varchar(100) not null,
    menu_type  varchar(20)  not null,
    enabled    boolean      not null,
    menu_order integer      not null,
    parent_id  bigint,
    data_page  varchar(50),
    icon       varchar(2000),
    url        varchar(255)
);


create unique index ux_admin_menu_data_page
    on admin_menu (data_page)
    where (data_page IS NOT NULL);

create table admin_menu_role
(
    id        bigserial
        primary key,
    menu_id   bigint       not null
        references admin_menu,
    role_name varchar(100) not null,
    unique (menu_id, role_name)
);


create table group_role_permissions
(
    group_id      bigint       not null
        references app_group,
    role_id       bigint       not null
        references role,
    permission_id bigint       not null
        references permission,
    assigned_at   timestamp(6) not null,
    assigned_by   varchar(100),
    primary key (group_id, role_id, permission_id)
);


create table user_role_permissions
(
    user_id       bigint       not null
        references users,
    role_id       bigint       not null
        references role,
    permission_id bigint       not null
        references permission,
    assigned_at   timestamp(6) not null,
    assigned_by   varchar(100),
    primary key (user_id, role_id, permission_id)
);


create table password_history
(
    id            bigserial
        primary key,
    user_id       bigint       not null,
    password_hash varchar(512) not null,
    changed_at    timestamp(6) not null
);


create table policy_version
(
    id             bigserial
        primary key,
    policy_id      bigint       not null,
    version_number integer      not null,
    change_type    varchar(20)  not null
        constraint policy_version_change_type_check
            check ((change_type)::text = ANY
                   (ARRAY [('CREATED'::character varying)::text, ('UPDATED'::character varying)::text, ('DELETED'::character varying)::text, ('ROLLBACK'::character varying)::text])),
    change_reason  varchar(1024),
    changed_by     varchar(255) not null,
    changed_at     timestamp(6) not null,
    snapshot_json  text         not null
);


create index idx_policy_version_changed_at
    on policy_version (changed_at);

create index idx_policy_version_policy_id
    on policy_version (policy_id);

create table system_settings
(
    id                         bigserial
        primary key,
    audit_log_retention_days   integer      not null,
    registration_enabled       boolean      not null,
    policy_combining_algorithm varchar(50)  not null,
    default_role               varchar(100) not null,
    created_at                 timestamp(6) not null,
    updated_at                 timestamp(6)
);

alter table system_settings add column if not exists hcad_medium_risk_score integer default 30 not null;
alter table system_settings add column if not exists hcad_high_risk_score integer default 50 not null;
alter table system_settings add column if not exists hcad_redline_score integer default 70 not null;
alter table system_settings add column if not exists hcad_failed_login_burst_threshold integer default 3 not null;
alter table system_settings add column if not exists hcad_request_burst_threshold integer default 12 not null;
alter table system_settings add column if not exists hcad_semantic_risk_similarity_threshold double precision default 0.80 not null;
alter table system_settings add column if not exists hcad_semantic_normal_similarity_threshold double precision default 0.85 not null;
alter table system_settings add column if not exists hcad_pre_trigger_mode varchar(20) default 'SHADOW' not null;
alter table system_settings add column if not exists security_zerotrust_mode varchar(20) default 'SHADOW' not null;
alter table system_settings add column if not exists mvc_resource_scanner_base_packages text default 'io.contexa.contexaiam.' not null;


create table learning_artifact_registry
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


create index idx_learning_artifact_registry_tenant_updated
    on learning_artifact_registry (tenant_id, updated_at);

create index idx_learning_artifact_registry_artifact_updated
    on learning_artifact_registry (artifact_type, artifact_key, updated_at);

create table learning_artifact_release_ledger
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


create index idx_learning_artifact_ledger_identity
    on learning_artifact_release_ledger (tenant_id, artifact_type, artifact_key, created_at);

create index idx_learning_artifact_ledger_artifact
    on learning_artifact_release_ledger (artifact_type, artifact_key, created_at);

create table learning_governance_snapshot
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


create index idx_learning_governance_snapshot_tenant_updated
    on learning_governance_snapshot (tenant_id, updated_at);

CREATE TABLE IF NOT EXISTS sealed_evidence_package (
    id BIGSERIAL PRIMARY KEY,
    package_id VARCHAR(256) NOT NULL,
    correlation_id VARCHAR(160) NOT NULL,
    tenant_id VARCHAR(120),
    user_id VARCHAR(160),
    captured_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    request_facts_json TEXT,
    auth_state_json TEXT,
    canonical_context_json TEXT,
    baseline_snapshot_json TEXT,
    rag_results_json TEXT,
    raw_system_prompt TEXT,
    raw_user_prompt TEXT,
    system_prompt_text TEXT,
    user_prompt_text TEXT,
    prompt_hash VARCHAR(128),
    system_prompt_hash VARCHAR(128),
    user_prompt_hash VARCHAR(128),
    raw_system_prompt_hash VARCHAR(128),
    raw_user_prompt_hash VARCHAR(128),
    prompt_execution_metadata_json TEXT,
    prompt_evidence_manifest_json TEXT,
    seal_state VARCHAR(32) NOT NULL DEFAULT 'SEALED',
    seal_failure_reason TEXT,
    decision_json TEXT,
    package_hash VARCHAR(128) NOT NULL,
    schema_version INTEGER NOT NULL DEFAULT 2,
    sealed BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at TIMESTAMP(6) WITH TIME ZONE,
    created_at TIMESTAMP(6) WITH TIME ZONE,
    CONSTRAINT uq_sealed_evidence_package_package_id UNIQUE (package_id)
);


create unique index if not exists idx_sep_correlation_id
    on sealed_evidence_package (correlation_id);

create index if not exists idx_sep_user_id_captured_at
    on sealed_evidence_package (user_id, captured_at);

create index if not exists idx_sep_tenant_id_captured_at
    on sealed_evidence_package (tenant_id, captured_at);

create index if not exists idx_sep_captured_at
    on sealed_evidence_package (captured_at);

create table login_attempt_ip
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


create index idx_login_attempt_ip_window
    on login_attempt_ip (window_start_at);

CREATE TABLE IF NOT EXISTS hcad_detection_evaluation (
    evaluation_id VARCHAR(64) PRIMARY KEY,
    event_id VARCHAR(128),
    request_id VARCHAR(160),
    correlation_id VARCHAR(160),
    test_run_id VARCHAR(160),
    user_id VARCHAR(160),
    context_binding_hash VARCHAR(128),
    actor_session_key VARCHAR(128),
    window_id VARCHAR(64),
    trigger_scope VARCHAR(32),
    request_count INTEGER DEFAULT 1,
    http_method VARCHAR(16),
    request_path VARCHAR(2048),
    normalized_path VARCHAR(2048),
    resource_id VARCHAR(512),
    client_ip VARCHAR(64),
    mode VARCHAR(32) NOT NULL,
    early_analysis_score INTEGER,
    band VARCHAR(32),
    eligible BOOLEAN,
    triggered_llm BOOLEAN NOT NULL DEFAULT FALSE,
    duplicate_suppressed BOOLEAN NOT NULL DEFAULT FALSE,
    duplicate_suppressed_count INTEGER DEFAULT 0,
    negative_cache_hit BOOLEAN NOT NULL DEFAULT FALSE,
    negative_cache_hit_count INTEGER DEFAULT 0,
    protectable_observed BOOLEAN NOT NULL DEFAULT FALSE,
    protectable_resource_id VARCHAR(512),
    protectable_resource_url VARCHAR(2048),
    protectable_http_method VARCHAR(16),
    resource_families TEXT,
    sample_paths TEXT,
    anchor_signals TEXT,
    corroborating_signals TEXT,
    reason_codes TEXT,
    non_trigger_reason VARCHAR(64),
    evidence_gap_codes TEXT,
    baseline_available BOOLEAN,
    baseline_established BOOLEAN,
    baseline_update_count BIGINT,
    baseline_min_samples INTEGER,
    baseline_compared_dimensions INTEGER,
    baseline_mismatch_count INTEGER,
    baseline_match_ratio DOUBLE PRECISION,
    baseline_mismatched_dimensions TEXT,
    baseline_current_values_json TEXT,
    baseline_reference_values_json TEXT,
    trigger_decision_reason VARCHAR(128),
    signal_snapshot_json TEXT,
    signal_provenance_json TEXT,
    score_breakdown_json TEXT,
    signal_explanations_json TEXT,
    context_explanation_json TEXT,
    baseline_explanation_json TEXT,
    semantic_evidence_explanation_json TEXT,
    freshness_explanation_json TEXT,
    trigger_explanation_json TEXT,
    llm_action VARCHAR(64),
    llm_proposed_action VARCHAR(64),
    llm_risk_score DOUBLE PRECISION,
    llm_confidence DOUBLE PRECISION,
    llm_latency_ms BIGINT,
    llm_reasoning_summary VARCHAR(1024),
    llm_reasoning_hash VARCHAR(64),
    llm_parser_failure BOOLEAN NOT NULL DEFAULT FALSE,
    llm_technical_fallback BOOLEAN NOT NULL DEFAULT FALSE,
    llm_fallback_category VARCHAR(128),
    llm_fallback_reason VARCHAR(1024),
    outcome_class VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN',
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    triggered_at TIMESTAMP(6),
    decided_at TIMESTAMP(6)
);

ALTER TABLE hcad_detection_evaluation
    ADD COLUMN IF NOT EXISTS actor_session_key VARCHAR(128),
    ADD COLUMN IF NOT EXISTS test_run_id VARCHAR(160),
    ADD COLUMN IF NOT EXISTS window_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS trigger_scope VARCHAR(32),
    ADD COLUMN IF NOT EXISTS request_count INTEGER DEFAULT 1,
    ADD COLUMN IF NOT EXISTS normalized_path VARCHAR(2048),
    ADD COLUMN IF NOT EXISTS resource_id VARCHAR(512),
    ADD COLUMN IF NOT EXISTS duplicate_suppressed_count INTEGER DEFAULT 0,
    ADD COLUMN IF NOT EXISTS negative_cache_hit BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS negative_cache_hit_count INTEGER DEFAULT 0,
    ADD COLUMN IF NOT EXISTS protectable_observed BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS protectable_resource_id VARCHAR(512),
    ADD COLUMN IF NOT EXISTS protectable_resource_url VARCHAR(2048),
    ADD COLUMN IF NOT EXISTS protectable_http_method VARCHAR(16),
    ADD COLUMN IF NOT EXISTS resource_families TEXT,
    ADD COLUMN IF NOT EXISTS sample_paths TEXT,
    ADD COLUMN IF NOT EXISTS non_trigger_reason VARCHAR(64),
    ADD COLUMN IF NOT EXISTS evidence_gap_codes TEXT,
    ADD COLUMN IF NOT EXISTS baseline_available BOOLEAN,
    ADD COLUMN IF NOT EXISTS baseline_established BOOLEAN,
    ADD COLUMN IF NOT EXISTS baseline_update_count BIGINT,
    ADD COLUMN IF NOT EXISTS baseline_min_samples INTEGER,
    ADD COLUMN IF NOT EXISTS baseline_compared_dimensions INTEGER,
    ADD COLUMN IF NOT EXISTS baseline_mismatch_count INTEGER,
    ADD COLUMN IF NOT EXISTS baseline_match_ratio DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS baseline_mismatched_dimensions TEXT,
    ADD COLUMN IF NOT EXISTS baseline_current_values_json TEXT,
    ADD COLUMN IF NOT EXISTS baseline_reference_values_json TEXT,
    ADD COLUMN IF NOT EXISTS trigger_decision_reason VARCHAR(128),
    ADD COLUMN IF NOT EXISTS score_breakdown_json TEXT,
    ADD COLUMN IF NOT EXISTS signal_explanations_json TEXT,
    ADD COLUMN IF NOT EXISTS context_explanation_json TEXT,
    ADD COLUMN IF NOT EXISTS baseline_explanation_json TEXT,
    ADD COLUMN IF NOT EXISTS semantic_evidence_explanation_json TEXT,
    ADD COLUMN IF NOT EXISTS freshness_explanation_json TEXT,
    ADD COLUMN IF NOT EXISTS trigger_explanation_json TEXT,
    ADD COLUMN IF NOT EXISTS llm_reasoning_summary VARCHAR(1024),
    ADD COLUMN IF NOT EXISTS llm_reasoning_hash VARCHAR(64),
    ADD COLUMN IF NOT EXISTS llm_parser_failure BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS llm_technical_fallback BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS llm_fallback_category VARCHAR(128),
    ADD COLUMN IF NOT EXISTS llm_fallback_reason VARCHAR(1024);

CREATE INDEX IF NOT EXISTS idx_hcad_eval_mode_created
    ON hcad_detection_evaluation (mode, created_at);

CREATE INDEX IF NOT EXISTS idx_hcad_eval_outcome_created
    ON hcad_detection_evaluation (outcome_class, created_at);

CREATE INDEX IF NOT EXISTS idx_hcad_eval_resource
    ON hcad_detection_evaluation (request_path, http_method);

CREATE INDEX IF NOT EXISTS idx_hcad_eval_normalized_resource
    ON hcad_detection_evaluation (normalized_path, resource_id, http_method);

CREATE INDEX IF NOT EXISTS idx_hcad_eval_request_id
    ON hcad_detection_evaluation (request_id);

CREATE INDEX IF NOT EXISTS idx_hcad_eval_event_id
    ON hcad_detection_evaluation (event_id);

CREATE INDEX IF NOT EXISTS idx_hcad_eval_actor_created
    ON hcad_detection_evaluation (actor_session_key, created_at);

CREATE INDEX IF NOT EXISTS idx_hcad_eval_window
    ON hcad_detection_evaluation (window_id);

CREATE INDEX IF NOT EXISTS idx_hcad_eval_test_run
    ON hcad_detection_evaluation (test_run_id, created_at);

CREATE TABLE IF NOT EXISTS ai_security_decision_observation (
    observation_id VARCHAR(64) PRIMARY KEY,
    event_id VARCHAR(128),
    request_id VARCHAR(160),
    correlation_id VARCHAR(160),
    test_run_id VARCHAR(160),
    user_id VARCHAR(160),
    session_id VARCHAR(160),
    context_binding_hash VARCHAR(128),
    actor_session_key VARCHAR(128),
    window_id VARCHAR(64),
    hcad_evaluation_id VARCHAR(64),
    trigger_source VARCHAR(64) NOT NULL DEFAULT 'UNKNOWN',
    trigger_relation VARCHAR(64) NOT NULL DEFAULT 'UNMATCHED_LLM',
    decision_boundary_mode VARCHAR(32),
    hcad_mode VARCHAR(32),
    hcad_score INTEGER,
    hcad_band VARCHAR(32),
    hcad_eligible BOOLEAN,
    http_method VARCHAR(16),
    request_path VARCHAR(2048),
    resource_id VARCHAR(512),
    model_provider VARCHAR(128),
    model_id VARCHAR(160),
    prompt_template_key VARCHAR(160),
    final_action VARCHAR(64),
    proposed_action VARCHAR(64),
    llm_risk_score DOUBLE PRECISION,
    llm_confidence DOUBLE PRECISION,
    llm_latency_ms BIGINT,
    llm_decision_present BOOLEAN,
    parser_failure BOOLEAN NOT NULL DEFAULT FALSE,
    technical_fallback BOOLEAN NOT NULL DEFAULT FALSE,
    timeout_failure BOOLEAN NOT NULL DEFAULT FALSE,
    model_unavailable BOOLEAN NOT NULL DEFAULT FALSE,
    failure_type VARCHAR(64),
    fallback_category VARCHAR(128),
    fallback_reason VARCHAR(1024),
    outcome_class VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN',
    metadata_json TEXT,
    success BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    decided_at TIMESTAMP(6)
);

ALTER TABLE ai_security_decision_observation
    ADD COLUMN IF NOT EXISTS hcad_evaluation_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS test_run_id VARCHAR(160),
    ADD COLUMN IF NOT EXISTS trigger_relation VARCHAR(64) NOT NULL DEFAULT 'UNMATCHED_LLM',
    ADD COLUMN IF NOT EXISTS decision_boundary_mode VARCHAR(32),
    ADD COLUMN IF NOT EXISTS hcad_mode VARCHAR(32),
    ADD COLUMN IF NOT EXISTS hcad_score INTEGER,
    ADD COLUMN IF NOT EXISTS hcad_band VARCHAR(32),
    ADD COLUMN IF NOT EXISTS hcad_eligible BOOLEAN,
    ADD COLUMN IF NOT EXISTS actor_session_key VARCHAR(128),
    ADD COLUMN IF NOT EXISTS window_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS prompt_template_key VARCHAR(160),
    ADD COLUMN IF NOT EXISTS parser_failure BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS technical_fallback BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS timeout_failure BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS model_unavailable BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS failure_type VARCHAR(64),
    ADD COLUMN IF NOT EXISTS outcome_class VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN',
    ADD COLUMN IF NOT EXISTS metadata_json TEXT;

CREATE INDEX IF NOT EXISTS idx_ai_sec_decision_created
    ON ai_security_decision_observation (created_at);

CREATE INDEX IF NOT EXISTS idx_ai_sec_decision_trigger_created
    ON ai_security_decision_observation (trigger_source, created_at);

CREATE INDEX IF NOT EXISTS idx_ai_sec_decision_relation_created
    ON ai_security_decision_observation (trigger_relation, created_at);

CREATE INDEX IF NOT EXISTS idx_ai_sec_decision_outcome_created
    ON ai_security_decision_observation (outcome_class, created_at);

CREATE INDEX IF NOT EXISTS idx_ai_sec_decision_hcad_eval
    ON ai_security_decision_observation (hcad_evaluation_id);

CREATE INDEX IF NOT EXISTS idx_ai_sec_decision_event
    ON ai_security_decision_observation (event_id);

CREATE INDEX IF NOT EXISTS idx_ai_sec_decision_test_run
    ON ai_security_decision_observation (test_run_id, created_at);

CREATE TABLE IF NOT EXISTS hcad_llm_decision_correlation (
    correlation_id VARCHAR(64) PRIMARY KEY,
    hcad_evaluation_id VARCHAR(64),
    llm_observation_id VARCHAR(64),
    event_id VARCHAR(128),
    request_id VARCHAR(160),
    test_run_id VARCHAR(160),
    user_id VARCHAR(160),
    actor_session_key VARCHAR(128),
    window_id VARCHAR(64),
    trigger_relation VARCHAR(64) NOT NULL DEFAULT 'UNMATCHED_LLM',
    outcome_class VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN',
    hcad_score INTEGER,
    hcad_band VARCHAR(32),
    hcad_eligible BOOLEAN,
    llm_final_action VARCHAR(64),
    llm_proposed_action VARCHAR(64),
    llm_risk_score DOUBLE PRECISION,
    llm_confidence DOUBLE PRECISION,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    decided_at TIMESTAMP(6)
);

ALTER TABLE hcad_llm_decision_correlation
    ADD COLUMN IF NOT EXISTS hcad_evaluation_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS llm_observation_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS test_run_id VARCHAR(160),
    ADD COLUMN IF NOT EXISTS actor_session_key VARCHAR(128),
    ADD COLUMN IF NOT EXISTS window_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS trigger_relation VARCHAR(64) NOT NULL DEFAULT 'UNMATCHED_LLM',
    ADD COLUMN IF NOT EXISTS outcome_class VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN',
    ADD COLUMN IF NOT EXISTS hcad_score INTEGER,
    ADD COLUMN IF NOT EXISTS hcad_band VARCHAR(32),
    ADD COLUMN IF NOT EXISTS hcad_eligible BOOLEAN,
    ADD COLUMN IF NOT EXISTS llm_final_action VARCHAR(64),
    ADD COLUMN IF NOT EXISTS llm_proposed_action VARCHAR(64),
    ADD COLUMN IF NOT EXISTS llm_risk_score DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS llm_confidence DOUBLE PRECISION;

CREATE INDEX IF NOT EXISTS idx_hcad_llm_corr_created
    ON hcad_llm_decision_correlation (created_at);

CREATE INDEX IF NOT EXISTS idx_hcad_llm_corr_relation_created
    ON hcad_llm_decision_correlation (trigger_relation, created_at);

CREATE INDEX IF NOT EXISTS idx_hcad_llm_corr_outcome_created
    ON hcad_llm_decision_correlation (outcome_class, created_at);

CREATE INDEX IF NOT EXISTS idx_hcad_llm_corr_hcad_eval
    ON hcad_llm_decision_correlation (hcad_evaluation_id);

CREATE INDEX IF NOT EXISTS idx_hcad_llm_corr_llm_obs
    ON hcad_llm_decision_correlation (llm_observation_id);

CREATE INDEX IF NOT EXISTS idx_hcad_llm_corr_test_run
    ON hcad_llm_decision_correlation (test_run_id, created_at);

create table shedlock
(
    name       varchar(64)  not null
        primary key,
    lock_until timestamp    not null,
    locked_at  timestamp    not null,
    locked_by  varchar(255) not null
);


-- ----------------------------------------------------------------

-- ============================================================
-- Contexa Core PQA official/evidence schema transcript
--
-- Source: Enterprise PQA original migration files from
-- D:/contexa-enterprise/contexa-core-enterprise/src/main/resources/db/migration
--
-- Purpose: Phase 1 original-storage migration. This file keeps the
-- official inspection/evidence DB contract in Core without moving
-- Enterprise-only resolution/governance/certificate/promotion tables.
-- ============================================================


-- ------------------------------------------------------------
-- Source migration: V20260414_01__verification_benchmark_publication_ledger.sql
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS verification_run_ledger (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    run_id VARCHAR(128) NOT NULL UNIQUE,
    user_id VARCHAR(160) NOT NULL,
    metric_code VARCHAR(32) NOT NULL,
    execution_path VARCHAR(160) NOT NULL,
    state VARCHAR(80),
    state_tone VARCHAR(80),
    requested_by VARCHAR(160),
    request_id VARCHAR(160),
    endpoint_key VARCHAR(80),
    endpoint_label VARCHAR(255),
    round_number INTEGER,
    score DOUBLE PRECISION,
    passed_checks INTEGER,
    total_checks INTEGER,
    processing_time_ms BIGINT,
    message TEXT,
    evidence_references_json TEXT,
    checks_json TEXT,
    request_facts_json TEXT,
    event_facts_json TEXT,
    prompt_facts_json TEXT,
    analysis_facts_json TEXT,
    events_json TEXT,
    raw_evidence_json TEXT,
    requested_at TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_verification_run_ledger_user_requested_at
    ON verification_run_ledger(user_id, requested_at DESC);

CREATE INDEX IF NOT EXISTS idx_verification_run_ledger_user_metric
    ON verification_run_ledger(user_id, metric_code, requested_at DESC);

CREATE INDEX IF NOT EXISTS idx_verification_run_ledger_user_request
    ON verification_run_ledger(user_id, request_id);

CREATE TABLE IF NOT EXISTS verification_execution_request_ledger (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    execution_request_id VARCHAR(160) NOT NULL UNIQUE,
    user_id VARCHAR(160) NOT NULL,
    metric_code VARCHAR(32) NOT NULL,
    execution_mode VARCHAR(32) NOT NULL,
    requested_endpoint_key VARCHAR(80),
    requested_resource_id VARCHAR(255),
    requested_request_path TEXT,
    resolved_endpoint_key VARCHAR(80),
    resolved_resource_id VARCHAR(255),
    resolved_request_path TEXT,
    execution_condition VARCHAR(80),
    execution_condition_multi_account BOOLEAN,
    execution_condition_repeated BOOLEAN,
    subject_account VARCHAR(255),
    comparison_accounts_json TEXT,
    comparison_account_count INTEGER,
    requested_run_count INTEGER,
    rerun_requested BOOLEAN,
    contamination_seed BOOLEAN,
    baseline_seed_requested BOOLEAN,
    runtime_profile_code VARCHAR(120),
    runtime_model_id VARCHAR(255),
    comparison_model_ids_json TEXT,
    runtime_comparison_model_count INTEGER,
    runtime_temperature DOUBLE PRECISION,
    runtime_top_p DOUBLE PRECISION,
    runtime_seed INTEGER,
    runtime_max_tokens INTEGER,
    runtime_disable_retries BOOLEAN,
    runtime_disable_ollama_thinking BOOLEAN,
    llm_runtime_mode VARCHAR(120),
    chat_runtime_provider VARCHAR(120),
    embedding_runtime_provider VARCHAR(120),
    embedding_priority VARCHAR(120),
    embedding_dedicated_runtime_enabled BOOLEAN,
    chat_ollama_base_url TEXT,
    embedding_ollama_base_url TEXT,
    browser_observation_json TEXT,
    raw_request_json TEXT,
    request_attributes_json TEXT,
    linked_run_id VARCHAR(160),
    linked_request_id VARCHAR(160),
    outcome_state VARCHAR(80),
    outcome_message TEXT,
    terminal_outcome BOOLEAN,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ver_exec_req_metric_created
    ON verification_execution_request_ledger(metric_code, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ver_exec_req_user_created
    ON verification_execution_request_ledger(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ver_exec_req_linked_run
    ON verification_execution_request_ledger(linked_run_id);

CREATE TABLE IF NOT EXISTS verification_execution_preflight_ledger (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    execution_request_id VARCHAR(160) NOT NULL UNIQUE,
    metric_code VARCHAR(32) NOT NULL,
    preflight_ready BOOLEAN NOT NULL,
    status_code VARCHAR(80),
    message TEXT,
    selection_json TEXT,
    evaluated_models_json TEXT,
    evaluated_model_count INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ver_exec_pre_metric_created
    ON verification_execution_preflight_ledger(metric_code, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_ver_exec_pre_ready_created
    ON verification_execution_preflight_ledger(preflight_ready, created_at DESC);

CREATE TABLE IF NOT EXISTS verification_case_ledger (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    verification_case_id VARCHAR(160) NOT NULL UNIQUE,
    tenant_id VARCHAR(160),
    source_run_id VARCHAR(128),
    request_id VARCHAR(160),
    metric_code VARCHAR(32) NOT NULL,
    metric_category VARCHAR(120),
    scenario_key VARCHAR(255),
    verified_at TIMESTAMP,
    overall_passed BOOLEAN NOT NULL,
    case_status VARCHAR(80) NOT NULL,
    truth_bundle_json TEXT NOT NULL,
    drillback_reference_json TEXT NOT NULL,
    source_kind VARCHAR(160),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_verification_case_ledger_run
    ON verification_case_ledger(source_run_id);

CREATE INDEX IF NOT EXISTS idx_verification_case_ledger_request
    ON verification_case_ledger(request_id);

CREATE INDEX IF NOT EXISTS idx_verification_case_ledger_metric
    ON verification_case_ledger(metric_code, verified_at DESC);

CREATE TABLE IF NOT EXISTS evaluation_case_ledger (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    evaluation_case_id VARCHAR(160) NOT NULL UNIQUE,
    verification_case_id VARCHAR(160) NOT NULL,
    metric_code VARCHAR(32) NOT NULL,
    metric_category VARCHAR(120),
    suite_keys_json TEXT NOT NULL,
    metric_result_json TEXT NOT NULL,
    publication_ready BOOLEAN NOT NULL,
    gate_results_json TEXT NOT NULL,
    drillback_reference_json TEXT NOT NULL,
    evaluated_at TIMESTAMP,
    source_kind VARCHAR(120),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evaluation_case_ledger_verification
    ON evaluation_case_ledger(verification_case_id);

CREATE INDEX IF NOT EXISTS idx_evaluation_case_ledger_metric
    ON evaluation_case_ledger(metric_code, evaluated_at DESC);

CREATE TABLE IF NOT EXISTS unified_truth_audit_ledger (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    recorded_at TIMESTAMP NOT NULL,
    stage VARCHAR(80) NOT NULL,
    action VARCHAR(120) NOT NULL,
    subject_id VARCHAR(255),
    note TEXT,
    metadata_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_unified_truth_audit_subject
    ON unified_truth_audit_ledger(subject_id, recorded_at DESC);

CREATE INDEX IF NOT EXISTS idx_unified_truth_audit_stage
    ON unified_truth_audit_ledger(stage, recorded_at DESC);

CREATE TABLE IF NOT EXISTS published_benchmark_release (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    slug VARCHAR(200) NOT NULL,
    version_no INTEGER NOT NULL,
    publication_status VARCHAR(40) NOT NULL,
    source_type VARCHAR(120),
    title VARCHAR(400) NOT NULL,
    benchmark_version VARCHAR(120),
    generated_at TIMESTAMP,
    published_at TIMESTAMP,
    manifest_identity VARCHAR(255),
    artifact_sha256 TEXT,
    note TEXT,
    summary_json TEXT NOT NULL,
    chart_data_json TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    html_report_text TEXT NOT NULL,
    pdf_base64_text TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT uq_published_benchmark_release_slug_version UNIQUE (slug, version_no)
);

CREATE INDEX IF NOT EXISTS idx_published_benchmark_release_slug_status
    ON published_benchmark_release(slug, publication_status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_published_benchmark_release_status_generated
    ON published_benchmark_release(publication_status, generated_at DESC);

-- ------------------------------------------------------------
-- Source migration: V20260414_09__verification_run_detail_normalization.sql
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS verification_run_round_ledger (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    run_id VARCHAR(128) NOT NULL,
    round_no INTEGER NOT NULL,
    endpoint_key VARCHAR(80),
    endpoint_label VARCHAR(255),
    score DOUBLE PRECISION,
    passed_checks INTEGER,
    total_checks INTEGER,
    processing_time_ms BIGINT,
    state VARCHAR(80),
    state_tone VARCHAR(80),
    message TEXT,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT fk_verification_run_round_ledger_run
        FOREIGN KEY (run_id) REFERENCES verification_run_ledger(run_id) ON DELETE CASCADE,
    CONSTRAINT uq_verification_run_round_ledger UNIQUE (run_id, round_no)
);

CREATE INDEX IF NOT EXISTS idx_verification_run_round_ledger_run
    ON verification_run_round_ledger(run_id, round_no);

CREATE TABLE IF NOT EXISTS verification_run_check_ledger (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    run_id VARCHAR(128) NOT NULL,
    round_no INTEGER,
    sequence_no INTEGER NOT NULL,
    label VARCHAR(255) NOT NULL,
    expected_value TEXT,
    actual_value TEXT,
    pass BOOLEAN NOT NULL,
    source VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT fk_verification_run_check_ledger_run
        FOREIGN KEY (run_id) REFERENCES verification_run_ledger(run_id) ON DELETE CASCADE,
    CONSTRAINT uq_verification_run_check_ledger UNIQUE (run_id, round_no, sequence_no)
);

CREATE INDEX IF NOT EXISTS idx_verification_run_check_ledger_run
    ON verification_run_check_ledger(run_id, round_no, sequence_no);

CREATE TABLE IF NOT EXISTS verification_run_fact_ledger (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    run_id VARCHAR(128) NOT NULL,
    round_no INTEGER,
    fact_type VARCHAR(32) NOT NULL,
    fact_key VARCHAR(255) NOT NULL,
    fact_value TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT fk_verification_run_fact_ledger_run
        FOREIGN KEY (run_id) REFERENCES verification_run_ledger(run_id) ON DELETE CASCADE,
    CONSTRAINT uq_verification_run_fact_ledger UNIQUE (run_id, round_no, fact_type, fact_key)
);

CREATE INDEX IF NOT EXISTS idx_verification_run_fact_ledger_run
    ON verification_run_fact_ledger(run_id, round_no, fact_type);

CREATE TABLE IF NOT EXISTS verification_run_event_ledger (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    run_id VARCHAR(128) NOT NULL,
    round_no INTEGER,
    sequence_no INTEGER NOT NULL,
    event_type VARCHAR(255),
    layer VARCHAR(120),
    event_status VARCHAR(120),
    request_path TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT fk_verification_run_event_ledger_run
        FOREIGN KEY (run_id) REFERENCES verification_run_ledger(run_id) ON DELETE CASCADE,
    CONSTRAINT uq_verification_run_event_ledger UNIQUE (run_id, round_no, sequence_no)
);

CREATE INDEX IF NOT EXISTS idx_verification_run_event_ledger_run
    ON verification_run_event_ledger(run_id, round_no, sequence_no);

CREATE TABLE IF NOT EXISTS verification_raw_evidence_artifact_ledger (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    run_id VARCHAR(128) NOT NULL,
    artifact_type VARCHAR(64) NOT NULL,
    content_type VARCHAR(120) NOT NULL,
    artifact_body TEXT NOT NULL,
    sha256 VARCHAR(128),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT fk_verification_raw_evidence_artifact_ledger_run
        FOREIGN KEY (run_id) REFERENCES verification_run_ledger(run_id) ON DELETE CASCADE,
    CONSTRAINT uq_verification_raw_evidence_artifact_ledger UNIQUE (run_id, artifact_type)
);

CREATE INDEX IF NOT EXISTS idx_verification_raw_evidence_artifact_ledger_run
    ON verification_raw_evidence_artifact_ledger(run_id, artifact_type);

-- ------------------------------------------------------------
-- Source migration: V20260428_02__verification_run_ledger_package_id.sql
-- ------------------------------------------------------------
ALTER TABLE verification_run_ledger
    ADD COLUMN IF NOT EXISTS package_id VARCHAR(160);

CREATE INDEX IF NOT EXISTS idx_verification_run_ledger_package_metric
    ON verification_run_ledger(package_id, metric_code, requested_at DESC);

-- ------------------------------------------------------------
-- Source migration: V20260430_06__official_verification_operator_snapshot.sql
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS verification_run_check_ledger (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    run_id VARCHAR(128) NOT NULL,
    round_no INTEGER,
    sequence_no INTEGER NOT NULL,
    label VARCHAR(255) NOT NULL,
    expected_value TEXT,
    actual_value TEXT,
    pass BOOLEAN NOT NULL,
    source VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_verification_run_check_ledger_run
    ON verification_run_check_ledger(run_id, round_no, sequence_no);

ALTER TABLE verification_run_check_ledger
    ADD COLUMN IF NOT EXISTS check_code VARCHAR(128);

ALTER TABLE verification_run_check_ledger
    ADD COLUMN IF NOT EXISTS severity VARCHAR(32);

ALTER TABLE verification_run_check_ledger
    ADD COLUMN IF NOT EXISTS failure_type VARCHAR(80);

ALTER TABLE verification_run_check_ledger
    ADD COLUMN IF NOT EXISTS remediation_owner VARCHAR(128);

ALTER TABLE verification_run_check_ledger
    ADD COLUMN IF NOT EXISTS operator_reason TEXT;

ALTER TABLE verification_run_check_ledger
    ADD COLUMN IF NOT EXISTS next_action TEXT;

ALTER TABLE verification_run_check_ledger
    ADD COLUMN IF NOT EXISTS reverify_criterion TEXT;

CREATE INDEX IF NOT EXISTS idx_verification_run_check_ledger_code
    ON verification_run_check_ledger(run_id, check_code);

CREATE TABLE IF NOT EXISTS official_verification_run_batch (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    aggregate_run_id VARCHAR(256) NOT NULL UNIQUE,
    package_id VARCHAR(256) NOT NULL,
    scope_type VARCHAR(64) NOT NULL,
    expected_metric_count INTEGER NOT NULL,
    actual_metric_count INTEGER NOT NULL DEFAULT 0,
    passed_metric_count INTEGER NOT NULL DEFAULT 0,
    failed_metric_count INTEGER NOT NULL DEFAULT 0,
    insufficient_metric_count INTEGER NOT NULL DEFAULT 0,
    not_applicable_metric_count INTEGER NOT NULL DEFAULT 0,
    final_decision VARCHAR(64) NOT NULL,
    blocked BOOLEAN NOT NULL DEFAULT TRUE,
    block_reason_summary TEXT,
    prompt_hash VARCHAR(160),
    context_hash VARCHAR(160),
    context_hash_state VARCHAR(64),
    template_resource_id VARCHAR(256),
    actual_resource_id VARCHAR(256),
    resource_url_template TEXT,
    actual_request_path TEXT,
    http_method VARCHAR(32),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_official_verification_run_batch_package
    ON official_verification_run_batch(package_id, created_at DESC);

CREATE TABLE IF NOT EXISTS official_verification_metric_snapshot (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    aggregate_run_id VARCHAR(256) NOT NULL,
    official_run_id VARCHAR(256) NOT NULL,
    package_id VARCHAR(256) NOT NULL,
    metric_code VARCHAR(32) NOT NULL,
    metric_name VARCHAR(255),
    metric_group VARCHAR(128),
    score DOUBLE PRECISION,
    state VARCHAR(80),
    severity VARCHAR(32),
    passed_checks INTEGER,
    total_checks INTEGER,
    operator_title VARCHAR(255),
    operator_summary TEXT,
    primary_failure_reason TEXT,
    remediation_owner VARCHAR(128),
    next_action TEXT,
    reverify_criterion TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT uq_official_verification_metric_snapshot
        UNIQUE (aggregate_run_id, metric_code)
);

CREATE INDEX IF NOT EXISTS idx_official_verification_metric_snapshot_package
    ON official_verification_metric_snapshot(package_id, aggregate_run_id, metric_code);

CREATE TABLE IF NOT EXISTS official_verification_operator_finding (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    finding_id VARCHAR(256) NOT NULL UNIQUE,
    aggregate_run_id VARCHAR(256) NOT NULL,
    official_run_id VARCHAR(256),
    package_id VARCHAR(256) NOT NULL,
    metric_code VARCHAR(32) NOT NULL,
    check_code VARCHAR(128),
    severity VARCHAR(32) NOT NULL,
    operator_title VARCHAR(255) NOT NULL,
    operator_reason TEXT,
    evidence_summary TEXT,
    evidence_path VARCHAR(512),
    expected_value TEXT,
    actual_value TEXT,
    impact TEXT,
    remediation_owner VARCHAR(128),
    next_action TEXT,
    reverify_criterion TEXT,
    related_process_step VARCHAR(128),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_official_verification_operator_finding_package
    ON official_verification_operator_finding(package_id, aggregate_run_id, metric_code);

-- ------------------------------------------------------------
-- Source migration: V20260430_07__official_verification_operator_snapshot_links.sql
-- ------------------------------------------------------------
ALTER TABLE official_verification_run_batch
    ADD COLUMN IF NOT EXISTS certificate_id VARCHAR(256);

ALTER TABLE official_verification_run_batch
    ADD COLUMN IF NOT EXISTS case_id VARCHAR(256);

ALTER TABLE official_verification_metric_snapshot
    ADD COLUMN IF NOT EXISTS certificate_id VARCHAR(256);

ALTER TABLE official_verification_metric_snapshot
    ADD COLUMN IF NOT EXISTS case_id VARCHAR(256);

ALTER TABLE official_verification_metric_snapshot
    ADD COLUMN IF NOT EXISTS failed_check_count INTEGER DEFAULT 0;

ALTER TABLE official_verification_operator_finding
    ADD COLUMN IF NOT EXISTS certificate_id VARCHAR(256);

ALTER TABLE official_verification_operator_finding
    ADD COLUMN IF NOT EXISTS case_id VARCHAR(256);

ALTER TABLE official_verification_operator_finding
    ADD COLUMN IF NOT EXISTS issue_id VARCHAR(256);

CREATE INDEX IF NOT EXISTS idx_official_verification_run_batch_certificate
    ON official_verification_run_batch(certificate_id);

CREATE INDEX IF NOT EXISTS idx_official_verification_operator_finding_issue
    ON official_verification_operator_finding(issue_id);

-- ------------------------------------------------------------
-- Source migration: V20260501_01__official_verification_metric_contracts.sql
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS official_verification_metric_definition (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    metric_code VARCHAR(32) NOT NULL,
    definition_version VARCHAR(40) NOT NULL,
    metric_name VARCHAR(255) NOT NULL,
    metric_group VARCHAR(128) NOT NULL,
    purpose TEXT NOT NULL,
    evidence_contract TEXT NOT NULL,
    blocking_scope VARCHAR(64) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    effective_from TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT uq_official_verification_metric_definition
        UNIQUE (metric_code, definition_version)
);

CREATE INDEX IF NOT EXISTS idx_official_verification_metric_definition_active
    ON official_verification_metric_definition(metric_code, is_active);

CREATE TABLE IF NOT EXISTS official_verification_metric_check_definition (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    metric_code VARCHAR(32) NOT NULL,
    check_code VARCHAR(128) NOT NULL,
    definition_version VARCHAR(40) NOT NULL,
    check_label VARCHAR(255) NOT NULL,
    expected_value TEXT,
    evidence_source VARCHAR(512),
    severity VARCHAR(32) NOT NULL,
    remediation_owner VARCHAR(128) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT uq_official_verification_metric_check_definition
        UNIQUE (metric_code, check_code, definition_version)
);

CREATE INDEX IF NOT EXISTS idx_official_verification_metric_check_definition_metric
    ON official_verification_metric_check_definition(metric_code, is_active);

CREATE TABLE IF NOT EXISTS official_verification_operator_remediation_group (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    group_id VARCHAR(256) NOT NULL UNIQUE,
    aggregate_run_id VARCHAR(256) NOT NULL,
    package_id VARCHAR(256) NOT NULL,
    certificate_id VARCHAR(256),
    case_id VARCHAR(256),
    root_cause_key VARCHAR(256) NOT NULL,
    remediation_owner VARCHAR(128) NOT NULL,
    operator_title VARCHAR(255) NOT NULL,
    operator_reason TEXT,
    next_action TEXT,
    reverify_criterion TEXT,
    affected_metric_codes VARCHAR(512),
    affected_check_codes TEXT,
    finding_count INTEGER NOT NULL DEFAULT 0,
    related_process_step VARCHAR(128),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_official_verification_operator_remediation_group_run
    ON official_verification_operator_remediation_group(package_id, aggregate_run_id);

CREATE INDEX IF NOT EXISTS idx_official_verification_operator_remediation_group_owner
    ON official_verification_operator_remediation_group(remediation_owner, created_at);

CREATE TABLE IF NOT EXISTS official_verification_metric_regression_package (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    scenario_id VARCHAR(128) NOT NULL UNIQUE,
    scenario_name VARCHAR(255) NOT NULL,
    scenario_type VARCHAR(64) NOT NULL,
    target_metric_codes VARCHAR(512) NOT NULL,
    fixture_source VARCHAR(512) NOT NULL,
    expected_decision VARCHAR(64) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS official_verification_metric_regression_expectation (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    scenario_id VARCHAR(128) NOT NULL,
    metric_code VARCHAR(32) NOT NULL,
    expected_state VARCHAR(80) NOT NULL,
    expected_failed_check_codes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT uq_official_verification_metric_regression_expectation
        UNIQUE (scenario_id, metric_code)
);

CREATE INDEX IF NOT EXISTS idx_official_verification_metric_regression_expectation_scenario
    ON official_verification_metric_regression_expectation(scenario_id);

-- Legacy official_verification_metric_* definition/check/regression seed rows are intentionally not installed.
-- Runtime PQA contracts are loaded from classpath:pqa/final-prompt-metric-contracts.json by
-- OfficialMetricPurposeContractCatalogWriter. Historical pqa12-* regression packages are test fixtures,
-- not runtime seed data.

-- ------------------------------------------------------------
-- Source migration: V20260501_02__official_verification_jsonb_evidence_shadows.sql
-- ------------------------------------------------------------
CREATE OR REPLACE FUNCTION contexa_safe_jsonb(value TEXT)
RETURNS JSONB
LANGUAGE plpgsql
IMMUTABLE
AS $function$
BEGIN
    IF value IS NULL OR btrim(value) = '' THEN
        RETURN NULL;
    END IF;
    RETURN value::JSONB;
EXCEPTION WHEN others THEN
    RETURN NULL;
END;
$function$;

ALTER TABLE sealed_evidence_package
    ADD COLUMN IF NOT EXISTS request_facts_jsonb JSONB;
ALTER TABLE sealed_evidence_package
    ADD COLUMN IF NOT EXISTS auth_state_jsonb JSONB;
ALTER TABLE sealed_evidence_package
    ADD COLUMN IF NOT EXISTS canonical_context_jsonb JSONB;
ALTER TABLE sealed_evidence_package
    ADD COLUMN IF NOT EXISTS baseline_snapshot_jsonb JSONB;
ALTER TABLE sealed_evidence_package
    ADD COLUMN IF NOT EXISTS rag_results_jsonb JSONB;
ALTER TABLE sealed_evidence_package
    ADD COLUMN IF NOT EXISTS prompt_execution_metadata_jsonb JSONB;
ALTER TABLE sealed_evidence_package
    ADD COLUMN IF NOT EXISTS decision_jsonb JSONB;

UPDATE sealed_evidence_package
   SET request_facts_jsonb = COALESCE(request_facts_jsonb, contexa_safe_jsonb(request_facts_json)),
       auth_state_jsonb = COALESCE(auth_state_jsonb, contexa_safe_jsonb(auth_state_json)),
       canonical_context_jsonb = COALESCE(canonical_context_jsonb, contexa_safe_jsonb(canonical_context_json)),
       baseline_snapshot_jsonb = COALESCE(baseline_snapshot_jsonb, contexa_safe_jsonb(baseline_snapshot_json)),
       rag_results_jsonb = COALESCE(rag_results_jsonb, contexa_safe_jsonb(rag_results_json)),
       prompt_execution_metadata_jsonb = COALESCE(prompt_execution_metadata_jsonb, contexa_safe_jsonb(prompt_execution_metadata_json)),
       decision_jsonb = COALESCE(decision_jsonb, contexa_safe_jsonb(decision_json))
 WHERE (request_facts_jsonb IS NULL AND request_facts_json IS NOT NULL)
    OR (auth_state_jsonb IS NULL AND auth_state_json IS NOT NULL)
    OR (canonical_context_jsonb IS NULL AND canonical_context_json IS NOT NULL)
    OR (baseline_snapshot_jsonb IS NULL AND baseline_snapshot_json IS NOT NULL)
    OR (rag_results_jsonb IS NULL AND rag_results_json IS NOT NULL)
    OR (prompt_execution_metadata_jsonb IS NULL AND prompt_execution_metadata_json IS NOT NULL)
    OR (decision_jsonb IS NULL AND decision_json IS NOT NULL);

CREATE INDEX IF NOT EXISTS idx_sep_request_facts_jsonb
    ON sealed_evidence_package USING GIN (request_facts_jsonb);
CREATE INDEX IF NOT EXISTS idx_sep_canonical_context_jsonb
    ON sealed_evidence_package USING GIN (canonical_context_jsonb);
CREATE INDEX IF NOT EXISTS idx_sep_baseline_snapshot_jsonb
    ON sealed_evidence_package USING GIN (baseline_snapshot_jsonb);
CREATE INDEX IF NOT EXISTS idx_sep_rag_results_jsonb
    ON sealed_evidence_package USING GIN (rag_results_jsonb);
CREATE INDEX IF NOT EXISTS idx_sep_prompt_execution_metadata_jsonb
    ON sealed_evidence_package USING GIN (prompt_execution_metadata_jsonb);

CREATE OR REPLACE FUNCTION contexa_sync_sealed_evidence_jsonb()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $function$
BEGIN
    NEW.request_facts_jsonb = contexa_safe_jsonb(NEW.request_facts_json);
    NEW.auth_state_jsonb = contexa_safe_jsonb(NEW.auth_state_json);
    NEW.canonical_context_jsonb = contexa_safe_jsonb(NEW.canonical_context_json);
    NEW.baseline_snapshot_jsonb = contexa_safe_jsonb(NEW.baseline_snapshot_json);
    NEW.rag_results_jsonb = contexa_safe_jsonb(NEW.rag_results_json);
    NEW.prompt_execution_metadata_jsonb = contexa_safe_jsonb(NEW.prompt_execution_metadata_json);
    NEW.decision_jsonb = contexa_safe_jsonb(NEW.decision_json);
    RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS trg_a_sync_sealed_evidence_jsonb ON sealed_evidence_package;

CREATE TRIGGER trg_a_sync_sealed_evidence_jsonb
BEFORE INSERT OR UPDATE ON sealed_evidence_package
FOR EACH ROW
EXECUTE FUNCTION contexa_sync_sealed_evidence_jsonb();

ALTER TABLE verification_run_fact_ledger
    ADD COLUMN IF NOT EXISTS fact_value_jsonb JSONB;

UPDATE verification_run_fact_ledger
   SET fact_value_jsonb = COALESCE(fact_value_jsonb, contexa_safe_jsonb(fact_value))
 WHERE fact_value_jsonb IS NULL AND fact_value IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_verification_run_fact_ledger_jsonb
    ON verification_run_fact_ledger USING GIN (fact_value_jsonb);

CREATE OR REPLACE FUNCTION contexa_sync_verification_fact_jsonb()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $function$
BEGIN
    NEW.fact_value_jsonb = contexa_safe_jsonb(NEW.fact_value);
    RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS trg_a_sync_verification_fact_jsonb ON verification_run_fact_ledger;

CREATE TRIGGER trg_a_sync_verification_fact_jsonb
BEFORE INSERT OR UPDATE ON verification_run_fact_ledger
FOR EACH ROW
EXECUTE FUNCTION contexa_sync_verification_fact_jsonb();

-- ------------------------------------------------------------
-- Source migration: V20260503_01__official_verification_reverify_result.sql
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS official_verification_reverify_result (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    result_id VARCHAR(256) NOT NULL UNIQUE,
    source_package_id VARCHAR(256) NOT NULL,
    source_aggregate_run_id VARCHAR(256),
    fixed_package_id VARCHAR(256) NOT NULL,
    fixed_aggregate_run_id VARCHAR(256),
    source_finding_id VARCHAR(256),
    issue_id VARCHAR(256),
    metric_code VARCHAR(32) NOT NULL,
    check_code VARCHAR(128),
    reverify_criterion TEXT,
    source_operator_reason TEXT,
    source_expected_value TEXT,
    source_actual_value TEXT,
    fixed_actual_value TEXT,
    resolved BOOLEAN NOT NULL DEFAULT FALSE,
    resolution_state VARCHAR(64) NOT NULL,
    operator_summary TEXT,
    created_by VARCHAR(128),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_official_verification_reverify_source
    ON official_verification_reverify_result(source_package_id, source_aggregate_run_id);

CREATE INDEX IF NOT EXISTS idx_official_verification_reverify_fixed
    ON official_verification_reverify_result(fixed_package_id, fixed_aggregate_run_id);

CREATE INDEX IF NOT EXISTS idx_official_verification_reverify_finding
    ON official_verification_reverify_result(source_finding_id, issue_id);

-- ------------------------------------------------------------
-- Source migration: V20260504_01__official_verification_audit_snapshot.sql
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS official_verification_audit_snapshot (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    snapshot_id VARCHAR(256) NOT NULL UNIQUE,
    aggregate_run_id VARCHAR(256) NOT NULL,
    package_id VARCHAR(256) NOT NULL,
    certificate_id VARCHAR(256),
    case_id VARCHAR(256),
    state VARCHAR(80),
    state_label VARCHAR(120),
    total_metric_count INTEGER NOT NULL DEFAULT 0,
    failed_metric_count INTEGER NOT NULL DEFAULT 0,
    certificate_issued BOOLEAN NOT NULL DEFAULT FALSE,
    prompt_hash VARCHAR(160),
    context_hash VARCHAR(160),
    blocking_findings_json TEXT,
    next_actions_json TEXT,
    payload_json TEXT NOT NULL,
    created_by VARCHAR(128),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_official_verification_audit_snapshot_run
    ON official_verification_audit_snapshot(package_id, aggregate_run_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_official_verification_audit_snapshot_certificate
    ON official_verification_audit_snapshot(certificate_id, created_at DESC);

-- ------------------------------------------------------------
-- Source migration: V20260504_02__verification_ledger_jsonb_shadows.sql
-- ------------------------------------------------------------
ALTER TABLE verification_run_ledger
    ADD COLUMN IF NOT EXISTS evidence_references_jsonb JSONB;
ALTER TABLE verification_run_ledger
    ADD COLUMN IF NOT EXISTS checks_jsonb JSONB;
ALTER TABLE verification_run_ledger
    ADD COLUMN IF NOT EXISTS request_facts_jsonb JSONB;
ALTER TABLE verification_run_ledger
    ADD COLUMN IF NOT EXISTS event_facts_jsonb JSONB;
ALTER TABLE verification_run_ledger
    ADD COLUMN IF NOT EXISTS prompt_facts_jsonb JSONB;
ALTER TABLE verification_run_ledger
    ADD COLUMN IF NOT EXISTS analysis_facts_jsonb JSONB;
ALTER TABLE verification_run_ledger
    ADD COLUMN IF NOT EXISTS events_jsonb JSONB;
ALTER TABLE verification_run_ledger
    ADD COLUMN IF NOT EXISTS raw_evidence_jsonb JSONB;

UPDATE verification_run_ledger
   SET evidence_references_jsonb = COALESCE(evidence_references_jsonb, contexa_safe_jsonb(evidence_references_json)),
       checks_jsonb = COALESCE(checks_jsonb, contexa_safe_jsonb(checks_json)),
       request_facts_jsonb = COALESCE(request_facts_jsonb, contexa_safe_jsonb(request_facts_json)),
       event_facts_jsonb = COALESCE(event_facts_jsonb, contexa_safe_jsonb(event_facts_json)),
       prompt_facts_jsonb = COALESCE(prompt_facts_jsonb, contexa_safe_jsonb(prompt_facts_json)),
       analysis_facts_jsonb = COALESCE(analysis_facts_jsonb, contexa_safe_jsonb(analysis_facts_json)),
       events_jsonb = COALESCE(events_jsonb, contexa_safe_jsonb(events_json)),
       raw_evidence_jsonb = COALESCE(raw_evidence_jsonb, contexa_safe_jsonb(raw_evidence_json))
 WHERE (evidence_references_jsonb IS NULL AND evidence_references_json IS NOT NULL)
    OR (checks_jsonb IS NULL AND checks_json IS NOT NULL)
    OR (request_facts_jsonb IS NULL AND request_facts_json IS NOT NULL)
    OR (event_facts_jsonb IS NULL AND event_facts_json IS NOT NULL)
    OR (prompt_facts_jsonb IS NULL AND prompt_facts_json IS NOT NULL)
    OR (analysis_facts_jsonb IS NULL AND analysis_facts_json IS NOT NULL)
    OR (events_jsonb IS NULL AND events_json IS NOT NULL)
    OR (raw_evidence_jsonb IS NULL AND raw_evidence_json IS NOT NULL);

CREATE INDEX IF NOT EXISTS idx_verification_run_ledger_request_facts_jsonb
    ON verification_run_ledger USING GIN (request_facts_jsonb);
CREATE INDEX IF NOT EXISTS idx_verification_run_ledger_prompt_facts_jsonb
    ON verification_run_ledger USING GIN (prompt_facts_jsonb);
CREATE INDEX IF NOT EXISTS idx_verification_run_ledger_analysis_facts_jsonb
    ON verification_run_ledger USING GIN (analysis_facts_jsonb);
CREATE INDEX IF NOT EXISTS idx_verification_run_ledger_raw_evidence_jsonb
    ON verification_run_ledger USING GIN (raw_evidence_jsonb);

CREATE OR REPLACE FUNCTION contexa_sync_verification_run_ledger_jsonb()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $function$
BEGIN
    NEW.evidence_references_jsonb = contexa_safe_jsonb(NEW.evidence_references_json);
    NEW.checks_jsonb = contexa_safe_jsonb(NEW.checks_json);
    NEW.request_facts_jsonb = contexa_safe_jsonb(NEW.request_facts_json);
    NEW.event_facts_jsonb = contexa_safe_jsonb(NEW.event_facts_json);
    NEW.prompt_facts_jsonb = contexa_safe_jsonb(NEW.prompt_facts_json);
    NEW.analysis_facts_jsonb = contexa_safe_jsonb(NEW.analysis_facts_json);
    NEW.events_jsonb = contexa_safe_jsonb(NEW.events_json);
    NEW.raw_evidence_jsonb = contexa_safe_jsonb(NEW.raw_evidence_json);
    RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS trg_a_sync_verification_run_ledger_jsonb ON verification_run_ledger;

CREATE TRIGGER trg_a_sync_verification_run_ledger_jsonb
BEFORE INSERT OR UPDATE ON verification_run_ledger
FOR EACH ROW
EXECUTE FUNCTION contexa_sync_verification_run_ledger_jsonb();

ALTER TABLE verification_raw_evidence_artifact_ledger
    ADD COLUMN IF NOT EXISTS artifact_body_jsonb JSONB;

UPDATE verification_raw_evidence_artifact_ledger
   SET artifact_body_jsonb = COALESCE(artifact_body_jsonb, contexa_safe_jsonb(artifact_body))
 WHERE artifact_body_jsonb IS NULL AND artifact_body IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_verification_raw_evidence_artifact_jsonb
    ON verification_raw_evidence_artifact_ledger USING GIN (artifact_body_jsonb);

CREATE OR REPLACE FUNCTION contexa_sync_verification_raw_artifact_jsonb()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $function$
BEGIN
    NEW.artifact_body_jsonb = contexa_safe_jsonb(NEW.artifact_body);
    RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS trg_a_sync_verification_raw_artifact_jsonb ON verification_raw_evidence_artifact_ledger;

CREATE TRIGGER trg_a_sync_verification_raw_artifact_jsonb
BEFORE INSERT OR UPDATE ON verification_raw_evidence_artifact_ledger
FOR EACH ROW
EXECUTE FUNCTION contexa_sync_verification_raw_artifact_jsonb();

-- ------------------------------------------------------------
-- Source migration: V20260504_04__official_verification_execution_lock.sql
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS official_verification_execution_lock (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    idempotency_key VARCHAR(256) NOT NULL,
    base_idempotency_key VARCHAR(256) NOT NULL,
    package_id VARCHAR(256) NOT NULL,
    aggregate_run_id VARCHAR(256),
    revision_no INTEGER NOT NULL DEFAULT 1,
    state VARCHAR(64) NOT NULL,
    progress_percent INTEGER NOT NULL DEFAULT 0,
    recoverable BOOLEAN,
    retry_instruction TEXT,
    failure_reason TEXT,
    requested_by VARCHAR(128),
    reverification_reason TEXT,
    request_fingerprint_json TEXT,
    result_json TEXT,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    failed_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_official_verification_execution_lock_key UNIQUE (idempotency_key),
    CONSTRAINT ck_official_verification_execution_lock_progress
        CHECK (progress_percent >= 0 AND progress_percent <= 100)
);

CREATE INDEX IF NOT EXISTS idx_official_verification_execution_lock_package
    ON official_verification_execution_lock(package_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_official_verification_execution_lock_state
    ON official_verification_execution_lock(state, updated_at);

CREATE INDEX IF NOT EXISTS idx_official_verification_execution_lock_base
    ON official_verification_execution_lock(base_idempotency_key, revision_no);

-- ------------------------------------------------------------
-- Source migration: V20260504_05__official_verification_failure_recovery_ledger.sql
-- ------------------------------------------------------------
ALTER TABLE official_verification_execution_lock
    ADD COLUMN IF NOT EXISTS attempt_no INTEGER NOT NULL DEFAULT 1;

ALTER TABLE official_verification_execution_lock
    ADD COLUMN IF NOT EXISTS failure_stage VARCHAR(64);

CREATE TABLE IF NOT EXISTS official_verification_execution_state_history (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    execution_lock_id BIGINT NOT NULL,
    package_id VARCHAR(256) NOT NULL,
    aggregate_run_id VARCHAR(256),
    attempt_no INTEGER NOT NULL DEFAULT 1,
    state VARCHAR(64) NOT NULL,
    progress_percent INTEGER NOT NULL DEFAULT 0,
    recoverable BOOLEAN,
    failure_stage VARCHAR(64),
    failure_reason TEXT,
    retry_instruction TEXT,
    message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT ck_official_verification_state_history_progress
        CHECK (progress_percent >= 0 AND progress_percent <= 100)
);

CREATE INDEX IF NOT EXISTS idx_official_verification_state_history_lock
    ON official_verification_execution_state_history(execution_lock_id, attempt_no, created_at);

CREATE INDEX IF NOT EXISTS idx_official_verification_state_history_package
    ON official_verification_execution_state_history(package_id, created_at DESC);

CREATE TABLE IF NOT EXISTS official_verification_metric_execution_ledger (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    execution_lock_id BIGINT NOT NULL,
    package_id VARCHAR(256) NOT NULL,
    aggregate_run_id VARCHAR(256),
    attempt_no INTEGER NOT NULL DEFAULT 1,
    metric_code VARCHAR(32) NOT NULL,
    sequence_no INTEGER NOT NULL,
    state VARCHAR(64) NOT NULL,
    progress_percent INTEGER NOT NULL DEFAULT 0,
    recoverable BOOLEAN,
    failure_reason TEXT,
    retry_instruction TEXT,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT ck_official_verification_metric_progress
        CHECK (progress_percent >= 0 AND progress_percent <= 100),
    CONSTRAINT uq_official_verification_metric_execution_attempt
        UNIQUE (execution_lock_id, attempt_no, metric_code)
);

CREATE INDEX IF NOT EXISTS idx_official_verification_metric_execution_package
    ON official_verification_metric_execution_ledger(package_id, aggregate_run_id, metric_code);

CREATE INDEX IF NOT EXISTS idx_official_verification_metric_execution_lock
    ON official_verification_metric_execution_ledger(execution_lock_id, attempt_no, sequence_no);

-- ------------------------------------------------------------
-- Source migration: V20260504_06__official_verification_metric_regression_samples.sql
-- ------------------------------------------------------------
ALTER TABLE official_verification_metric_regression_package
    ADD COLUMN IF NOT EXISTS sample_kind VARCHAR(16);

ALTER TABLE official_verification_metric_regression_package
    ADD COLUMN IF NOT EXISTS prompt_hash VARCHAR(160);

ALTER TABLE official_verification_metric_regression_package
    ADD COLUMN IF NOT EXISTS context_hash VARCHAR(160);

ALTER TABLE official_verification_metric_regression_package
    ADD COLUMN IF NOT EXISTS resource_template_id VARCHAR(256);

ALTER TABLE official_verification_metric_regression_package
    ADD COLUMN IF NOT EXISTS actual_resource_id VARCHAR(256);

ALTER TABLE official_verification_metric_regression_package
    ADD COLUMN IF NOT EXISTS sample_package_json TEXT;

ALTER TABLE official_verification_metric_regression_package
    ADD COLUMN IF NOT EXISTS expected_finding_snapshot TEXT;

ALTER TABLE official_verification_metric_regression_package
    ADD COLUMN IF NOT EXISTS expected_remediation_group TEXT;

ALTER TABLE official_verification_metric_regression_package
    ADD COLUMN IF NOT EXISTS expected_reverify_criterion TEXT;

ALTER TABLE official_verification_metric_regression_package
    ADD COLUMN IF NOT EXISTS expected_audit_payload_json TEXT;

ALTER TABLE official_verification_metric_regression_package
    ADD COLUMN IF NOT EXISTS customer_sentence_contract_json TEXT;

ALTER TABLE official_verification_metric_regression_expectation
    ADD COLUMN IF NOT EXISTS expected_score NUMERIC(7,2);

ALTER TABLE official_verification_metric_regression_expectation
    ADD COLUMN IF NOT EXISTS expected_passed_check_count INTEGER;

ALTER TABLE official_verification_metric_regression_expectation
    ADD COLUMN IF NOT EXISTS expected_failed_check_count INTEGER;

ALTER TABLE official_verification_metric_regression_expectation
    ADD COLUMN IF NOT EXISTS expected_finding_snapshot TEXT;

ALTER TABLE official_verification_metric_regression_expectation
    ADD COLUMN IF NOT EXISTS expected_remediation_group TEXT;

ALTER TABLE official_verification_metric_regression_expectation
    ADD COLUMN IF NOT EXISTS expected_reverify_criterion TEXT;

ALTER TABLE official_verification_metric_regression_expectation
    ADD COLUMN IF NOT EXISTS expected_audit_payload_json TEXT;

CREATE INDEX IF NOT EXISTS idx_official_metric_regression_package_kind
    ON official_verification_metric_regression_package(sample_kind, target_metric_codes);

CREATE INDEX IF NOT EXISTS idx_official_metric_regression_expectation_metric
    ON official_verification_metric_regression_expectation(metric_code, expected_state);

-- Legacy pqa12-* regression sample payload updates/inserts are intentionally omitted.
-- These fixed samples used synthetic resource ids/templates and must not be installed as runtime defaults.

-- ------------------------------------------------------------
-- Source migration: V20260504_07__official_verification_result_sentence_contract.sql
-- ------------------------------------------------------------
ALTER TABLE verification_run_check_ledger
    ADD COLUMN IF NOT EXISTS operator_title VARCHAR(255);

ALTER TABLE verification_run_check_ledger
    ADD COLUMN IF NOT EXISTS operator_summary TEXT;

ALTER TABLE verification_run_check_ledger
    ADD COLUMN IF NOT EXISTS problem_statement TEXT;

ALTER TABLE verification_run_check_ledger
    ADD COLUMN IF NOT EXISTS root_cause TEXT;

ALTER TABLE verification_run_check_ledger
    ADD COLUMN IF NOT EXISTS affected_target VARCHAR(256);

ALTER TABLE verification_run_check_ledger
    ADD COLUMN IF NOT EXISTS evidence_summary TEXT;

ALTER TABLE verification_run_check_ledger
    ADD COLUMN IF NOT EXISTS expected_result TEXT;

ALTER TABLE verification_run_check_ledger
    ADD COLUMN IF NOT EXISTS actual_result TEXT;

ALTER TABLE verification_run_check_ledger
    ADD COLUMN IF NOT EXISTS impact TEXT;

ALTER TABLE verification_run_check_ledger
    ADD COLUMN IF NOT EXISTS customer_visible_severity VARCHAR(64);

ALTER TABLE verification_run_check_ledger
    ADD COLUMN IF NOT EXISTS related_process_step VARCHAR(128);

ALTER TABLE official_verification_operator_finding
    ADD COLUMN IF NOT EXISTS operator_summary TEXT;

ALTER TABLE official_verification_operator_finding
    ADD COLUMN IF NOT EXISTS problem_statement TEXT;

ALTER TABLE official_verification_operator_finding
    ADD COLUMN IF NOT EXISTS root_cause TEXT;

ALTER TABLE official_verification_operator_finding
    ADD COLUMN IF NOT EXISTS affected_target VARCHAR(256);

ALTER TABLE official_verification_operator_finding
    ADD COLUMN IF NOT EXISTS expected_result TEXT;

ALTER TABLE official_verification_operator_finding
    ADD COLUMN IF NOT EXISTS actual_result TEXT;

ALTER TABLE official_verification_operator_finding
    ADD COLUMN IF NOT EXISTS customer_visible_severity VARCHAR(64);

CREATE INDEX IF NOT EXISTS idx_verification_run_check_ledger_customer_severity
    ON verification_run_check_ledger(run_id, customer_visible_severity);

CREATE INDEX IF NOT EXISTS idx_official_operator_finding_customer_severity
    ON official_verification_operator_finding(package_id, customer_visible_severity, created_at);

-- ------------------------------------------------------------
-- Source migration: V20260504_09__official_verification_diagnostic_catalog_version.sql
-- ------------------------------------------------------------
ALTER TABLE official_verification_run_batch
    ADD COLUMN IF NOT EXISTS diagnostic_catalog_version VARCHAR(128);

ALTER TABLE official_verification_metric_snapshot
    ADD COLUMN IF NOT EXISTS diagnostic_catalog_version VARCHAR(128);

ALTER TABLE official_verification_operator_finding
    ADD COLUMN IF NOT EXISTS diagnostic_catalog_version VARCHAR(128);

ALTER TABLE official_verification_operator_remediation_group
    ADD COLUMN IF NOT EXISTS diagnostic_catalog_version VARCHAR(128);

ALTER TABLE official_verification_audit_snapshot
    ADD COLUMN IF NOT EXISTS diagnostic_catalog_version VARCHAR(128);

ALTER TABLE official_verification_reverify_result
    ADD COLUMN IF NOT EXISTS diagnostic_catalog_version VARCHAR(128);

CREATE INDEX IF NOT EXISTS idx_official_verification_run_batch_catalog_version
    ON official_verification_run_batch(diagnostic_catalog_version, created_at);

CREATE INDEX IF NOT EXISTS idx_official_verification_finding_catalog_version
    ON official_verification_operator_finding(diagnostic_catalog_version, created_at);

-- ------------------------------------------------------------
-- Source migration: V20260504_10__sealed_evidence_package_identifier_width.sql
-- ------------------------------------------------------------
alter table sealed_evidence_package
    alter column package_id set data type varchar(256);

-- ------------------------------------------------------------
-- Source migration: V20260510_01__official_verification_prompt_comparison_linkage.sql
-- ------------------------------------------------------------
ALTER TABLE official_verification_metric_check_definition
    ADD COLUMN IF NOT EXISTS comparison_field_key VARCHAR(128);

ALTER TABLE official_verification_metric_check_definition
    ADD COLUMN IF NOT EXISTS prompt_location VARCHAR(256);

ALTER TABLE official_verification_metric_check_definition
    ADD COLUMN IF NOT EXISTS related_process_step VARCHAR(128);

ALTER TABLE official_verification_operator_finding
    ADD COLUMN IF NOT EXISTS comparison_field_key VARCHAR(128);

ALTER TABLE official_verification_operator_finding
    ADD COLUMN IF NOT EXISTS comparison_state VARCHAR(64);

ALTER TABLE official_verification_operator_finding
    ADD COLUMN IF NOT EXISTS prompt_location VARCHAR(256);

ALTER TABLE official_verification_operator_remediation_group
    ADD COLUMN IF NOT EXISTS comparison_field_keys TEXT;

ALTER TABLE official_verification_operator_remediation_group
    ADD COLUMN IF NOT EXISTS prompt_locations TEXT;

CREATE TABLE IF NOT EXISTS official_verification_prompt_comparison (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    comparison_id VARCHAR(256) NOT NULL UNIQUE,
    aggregate_run_id VARCHAR(256) NOT NULL,
    package_id VARCHAR(256) NOT NULL,
    field_key VARCHAR(128) NOT NULL,
    field_label VARCHAR(255) NOT NULL,
    sealed_evidence_value TEXT,
    prompt_value TEXT,
    official_fact_value TEXT,
    state VARCHAR(64) NOT NULL,
    state_label VARCHAR(128),
    meaning TEXT,
    prompt_location VARCHAR(256),
    evidence_source VARCHAR(512),
    recommended_owner VARCHAR(128),
    related_metric_codes TEXT,
    related_check_codes TEXT,
    related_finding_ids TEXT,
    related_issue_ids TEXT,
    related_remediation_group_ids TEXT,
    canonical_source VARCHAR(64) NOT NULL DEFAULT 'PROMPT_COMPARISON',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_official_verification_prompt_comparison_run
    ON official_verification_prompt_comparison(package_id, aggregate_run_id);

CREATE INDEX IF NOT EXISTS idx_official_verification_prompt_comparison_field
    ON official_verification_prompt_comparison(field_key, state);

CREATE INDEX IF NOT EXISTS idx_official_verification_finding_comparison_field
    ON official_verification_operator_finding(package_id, aggregate_run_id, comparison_field_key);

UPDATE official_verification_metric_check_definition
   SET comparison_field_key = lower(metric_code || '.official_contract'),
       prompt_location = 'officialVerification.contract',
       related_process_step = 'OFFICIAL_VERIFICATION'
 WHERE comparison_field_key IS NULL
   AND check_code = metric_code || '_OFFICIAL_CONTRACT';

UPDATE official_verification_metric_check_definition
   SET comparison_field_key = v.comparison_field_key,
       prompt_location = v.prompt_location,
       related_process_step = v.related_process_step
  FROM (
      VALUES
          ('EIR_MFA_STATE_PROMPT_MATCH', 'mfaVerified', 'userPrompt.requestContext', 'RUNTIME_EVIDENCE'),
          ('CCR_AUTH_CONTEXT_COMPLETE', 'authState', 'userPrompt.requestContext', 'RUNTIME_EVIDENCE'),
          ('CCSR_PROMPT_HASH_LEDGER_MATCH', 'promptHash', 'promptExecutionMetadata', 'OFFICIAL_VERIFICATION'),
          ('PFR_CONTRACT_VIOLATION_ZERO', 'promptExecutionMetadata', 'promptExecutionMetadata', 'PROMPT_GOVERNANCE'),
          ('MTR_EXPIRY_PRESENT', 'sealedEvidenceExpiry', 'officialVerification.evidence', 'RUNTIME_EVIDENCE'),
          ('COR_PURPOSE_MISMATCH_ZERO', 'ragResults', 'userPrompt.rag', 'PROMPT_GOVERNANCE'),
          ('RAP_DOC_AUTH_DECISION_PRESENT_1', 'ragResults.authorizationDecision', 'userPrompt.rag', 'PROMPT_GOVERNANCE'),
          ('RAP_DOC_INCLUDED_IS_AUTHORIZED_1', 'ragResults.finalContextIncluded', 'userPrompt.rag', 'PROMPT_GOVERNANCE'),
          ('RAP_DOC_PERMISSION_SCOPE_PRESENT_1', 'ragResults.permissionScope', 'userPrompt.rag', 'PROMPT_GOVERNANCE'),
          ('RPI_RELATED_DOCUMENTS_NON_REGRESSIVE', 'ragResults.relatedDocuments', 'userPrompt.rag', 'PROMPT_GOVERNANCE'),
          ('BMA_MATURITY_NOT_OVERCLAIMED', 'baselineSnapshot', 'userPrompt.baseline', 'PROMPT_GOVERNANCE'),
          ('USNS_TIME_PROMPT_REFLECTS_SIGNAL', 'baselineSnapshot.noveltySignals.time', 'userPrompt.baseline', 'PROMPT_GOVERNANCE'),
          ('BSR_PROMPT_EXPLAINS_BEHAVIOR', 'canonicalContext.behavior', 'userPrompt.context', 'PROMPT_GOVERNANCE'),
          ('PRE_RESOURCE_ID_BOUND_TO_ACTUAL', 'resourceId', 'userPrompt.requestContext', 'PROTECTABLE_RESOURCES')
  ) AS v(check_code, comparison_field_key, prompt_location, related_process_step)
 WHERE official_verification_metric_check_definition.check_code = v.check_code
   AND official_verification_metric_check_definition.comparison_field_key IS NULL;

UPDATE official_verification_metric_check_definition
   SET comparison_field_key = lower(metric_code || '.' || check_code),
       prompt_location = 'officialVerification.check',
       related_process_step = 'OFFICIAL_VERIFICATION'
 WHERE comparison_field_key IS NULL;

-- ------------------------------------------------------------
-- Source migration: V20260511_02__official_verification_prompt_field_mapping_contract.sql
-- ------------------------------------------------------------
UPDATE official_verification_metric_check_definition
   SET comparison_field_key = v.comparison_field_key,
       prompt_location = v.prompt_location,
       related_process_step = v.related_process_step
  FROM (
      VALUES
          ('CCR_REQUEST_CONTEXT_COMPLETE', 'requestFacts', 'userPrompt.requestContext', 'RUNTIME_EVIDENCE'),
          ('CCR_AUTH_CONTEXT_COMPLETE', 'authState', 'userPrompt.requestContext', 'RUNTIME_EVIDENCE'),
          ('CCR_PROTECTABLE_CONTEXT_COMPLETE', 'resourceId', 'userPrompt.requestContext', 'PROTECTABLE_RESOURCES'),
          ('CCR_BASELINE_CONTEXT_STATE', 'baselineSnapshot', 'userPrompt.baseline', 'LEARNING_CONTEXT'),
          ('CCR_RAG_CONTEXT_STATE', 'ragResults', 'userPrompt.rag', 'RAG_CONTEXT'),
          ('CCR_FINAL_PROMPTS_CAPTURED', 'userPromptText', 'userPrompt', 'PROMPT_CAPTURE'),
          ('CCR_PROMPT_GOVERNANCE_COMPLETE', 'promptGovernance', 'promptExecutionMetadata', 'PROMPT_GOVERNANCE'),
          ('CCR_NO_EXPLICIT_MISSING_KNOWLEDGE', 'userPromptText', 'userPrompt.contextCoverage', 'PROMPT_ASSEMBLER'),
          ('CCR_UNCERTAINTY_MARKER_COUNT_ZERO', 'contextUncertaintyMarkers', 'userPrompt.contextCoverage', 'CONTEXT_ASSEMBLER'),
          ('CCR_PROVISIONAL_MARKER_COUNT_ZERO', 'contextProvisionalMarkers', 'userPrompt.contextCoverage', 'LEARNING_CONTEXT'),
          ('CCR_CONTEXT_PRODUCER_GAP_COUNT_ZERO', 'contextProducerCoverage', 'userPrompt.contextCoverage', 'CONTEXT_ASSEMBLER'),
          ('CCSR_CORRELATION_ID_CONSISTENT', 'correlationId', 'promptExecutionMetadata', 'EVIDENCE_SEALER'),
          ('CCSR_REQUEST_PATH_PROMPT_MATCH', 'requestPath', 'userPrompt.requestContext', 'PROMPT_ASSEMBLER'),
          ('CCSR_HTTP_METHOD_PROMPT_MATCH', 'httpMethod', 'userPrompt.requestContext', 'PROMPT_ASSEMBLER'),
          ('CCSR_ACTUAL_RESOURCE_PROMPT_MATCH', 'resourceId', 'userPrompt.requestContext', 'PROMPT_ASSEMBLER'),
          ('CCSR_TENANT_PROMPT_MATCH', 'tenantId', 'userPrompt.requestContext', 'PROMPT_ASSEMBLER'),
          ('CCSR_USER_PROMPT_MATCH', 'userId', 'userPrompt.requestContext', 'PROMPT_ASSEMBLER'),
          ('BMA_BASELINE_SNAPSHOT_PRESENT', 'baselineSnapshot', 'userPrompt.baseline', 'LEARNING_CONTEXT'),
          ('BMA_BASELINE_COMPLETE', 'baselineSnapshot.evidenceState', 'userPrompt.baseline', 'LEARNING_CONTEXT'),
          ('BMA_CANONICAL_CONTEXT_PRESENT', 'canonicalContext', 'userPrompt.context', 'CONTEXT_ASSEMBLER'),
          ('BMA_OBSERVATION_DAYS_TRACKED', 'baselineSnapshot.observationDays', 'userPrompt.baseline', 'LEARNING_CONTEXT'),
          ('BMA_OBSERVATION_EVENT_COUNT_TRACKED', 'baselineSnapshot.eventCount', 'userPrompt.baseline', 'LEARNING_CONTEXT'),
          ('BMA_COVERAGE_TRACKED', 'baselineSnapshot.coverage', 'userPrompt.baseline', 'LEARNING_CONTEXT'),
          ('BMA_FALLBACK_RATIO_TRACKED', 'baselineSnapshot.fallbackRatio', 'userPrompt.baseline', 'LEARNING_CONTEXT'),
          ('BMA_PROVISIONAL_REASON_RECORDED', 'baselineSnapshot.provisionalReason', 'userPrompt.baseline', 'LEARNING_CONTEXT'),
          ('BMA_MATURITY_NOT_OVERCLAIMED', 'baselineSnapshot.maturityState', 'userPrompt.baseline', 'LEARNING_CONTEXT'),
          ('USNS_USER_PROMPT_PRESENT', 'userPromptText', 'userPrompt', 'PROMPT_ASSEMBLER'),
          ('USNS_BASELINE_PRESENT', 'baselineSnapshot', 'userPrompt.baseline', 'LEARNING_CONTEXT'),
          ('USNS_NEW_USER_FLAG_PRESENT', 'baselineSnapshot.isNewUser', 'userPrompt.baseline', 'LEARNING_CONTEXT'),
          ('USNS_NEW_DEVICE_FLAG_PRESENT', 'baselineSnapshot.isNewDevice', 'userPrompt.baseline', 'LEARNING_CONTEXT'),
          ('USNS_NEW_SESSION_FLAG_PRESENT', 'baselineSnapshot.isNewSession', 'userPrompt.baseline', 'LEARNING_CONTEXT'),
          ('USNS_OBSERVED_SCOPE_PRESENT', 'canonicalContext.observedScope', 'userPrompt.baseline', 'LEARNING_CONTEXT'),
          ('USNS_TIME_SIGNAL_PRESENT', 'baselineSnapshot.noveltySignals.time', 'userPrompt.baseline', 'LEARNING_CONTEXT'),
          ('USNS_TIME_SIGNAL_STATE_PRESENT', 'baselineSnapshot.noveltySignals.time.state', 'userPrompt.baseline', 'LEARNING_CONTEXT'),
          ('USNS_NETWORK_SIGNAL_PRESENT', 'baselineSnapshot.noveltySignals.network', 'userPrompt.baseline', 'LEARNING_CONTEXT'),
          ('USNS_NETWORK_SIGNAL_STATE_PRESENT', 'baselineSnapshot.noveltySignals.network.state', 'userPrompt.baseline', 'LEARNING_CONTEXT'),
          ('USNS_BROWSER_SIGNAL_PRESENT', 'baselineSnapshot.noveltySignals.browser', 'userPrompt.baseline', 'LEARNING_CONTEXT'),
          ('USNS_BROWSER_SIGNAL_STATE_PRESENT', 'baselineSnapshot.noveltySignals.browser.state', 'userPrompt.baseline', 'LEARNING_CONTEXT'),
          ('USNS_DEVICE_SIGNAL_PRESENT', 'baselineSnapshot.noveltySignals.device', 'userPrompt.baseline', 'LEARNING_CONTEXT'),
          ('USNS_DEVICE_SIGNAL_STATE_PRESENT', 'baselineSnapshot.noveltySignals.device.state', 'userPrompt.baseline', 'LEARNING_CONTEXT'),
          ('USNS_REQUEST_COMBINATION_SIGNAL_PRESENT', 'baselineSnapshot.noveltySignals.requestCombination', 'userPrompt.baseline', 'LEARNING_CONTEXT'),
          ('USNS_REQUEST_COMBINATION_SIGNAL_STATE_PRESENT', 'baselineSnapshot.noveltySignals.requestCombination.state', 'userPrompt.baseline', 'LEARNING_CONTEXT'),
          ('USNS_PERSONAL_COMPARABLE_HISTORY_STATE', 'baselineSnapshot.personalComparableScope', 'userPrompt.baseline', 'LEARNING_CONTEXT'),
          ('BSR_USER_PROMPT_PRESENT', 'userPromptText', 'userPrompt', 'PROMPT_ASSEMBLER'),
          ('BSR_CANONICAL_CONTEXT_PRESENT', 'canonicalContext', 'userPrompt.context', 'BEHAVIOR_CONTEXT'),
          ('BSR_SESSION_NARRATIVE_PROFILE', 'canonicalContext.sessionNarrativeProfile', 'userPrompt.context', 'BEHAVIOR_CONTEXT'),
          ('BSR_FRICTION_PROFILE', 'canonicalContext.frictionProfile', 'userPrompt.context', 'BEHAVIOR_CONTEXT'),
          ('BSR_SURPRISE_SIGNAL_SOURCE', 'canonicalContext.behavioralSurpriseSignals', 'userPrompt.context', 'BEHAVIOR_CONTEXT'),
          ('BSR_PROMPT_EXPLAINS_BEHAVIOR', 'userPromptText', 'userPrompt.context', 'PROMPT_ASSEMBLER'),
          ('PFR_CONTRACT_VIOLATION_ZERO', 'promptExecutionMetadata.contract', 'promptExecutionMetadata', 'PROMPT_GOVERNANCE'),
          ('PFR_COMPRESSION_TRACE_RECORDED', 'promptExecutionMetadata.compression', 'promptExecutionMetadata', 'PROMPT_CAPTURE'),
          ('PFR_TOKEN_BUDGET_NOT_EXCEEDED', 'promptExecutionMetadata.tokenBudget', 'promptExecutionMetadata', 'PROMPT_ASSEMBLER'),
          ('RAP_RAG_RESULTS_PRESENT', 'ragResults', 'userPrompt.rag', 'RAG_CONTEXT'),
          ('RAP_DOCUMENT_AUTHORIZATION_LIST_PRESENT', 'ragResults.relatedDocuments', 'userPrompt.rag', 'RAG_AUTHORIZATION'),
          ('RAP_AUTHORIZED_DOCUMENT_COUNT_TRACKED', 'ragResults.authorizedDocumentCount', 'userPrompt.rag', 'RAG_AUTHORIZATION'),
          ('RPI_RELATED_DOCUMENTS_NON_REGRESSIVE', 'ragResults.relatedDocuments', 'userPrompt.rag', 'RAG_CONTEXT')
  ) AS v(check_code, comparison_field_key, prompt_location, related_process_step)
 WHERE official_verification_metric_check_definition.check_code = v.check_code;

UPDATE official_verification_metric_check_definition
   SET comparison_field_key = 'ragResults.relatedDocuments',
       prompt_location = 'userPrompt.rag',
       related_process_step = 'RAG_AUTHORIZATION'
 WHERE check_code LIKE 'RAP_DOC_%';

UPDATE official_verification_metric_check_definition
   SET comparison_field_key = 'ragResults.relatedDocuments',
       prompt_location = 'userPrompt.rag',
       related_process_step = 'RAG_CONTEXT'
 WHERE check_code LIKE 'COR_DOC_%';

UPDATE official_verification_metric_check_definition
   SET prompt_location = 'evidenceSource.unmapped'
 WHERE prompt_location = 'officialVerification.check';

-- ------------------------------------------------------------
-- Source migration: V20260511_03__official_prompt_field_state_ledger.sql
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS official_prompt_field_definition (
    id BIGSERIAL PRIMARY KEY,
    field_key VARCHAR(256) NOT NULL UNIQUE,
    source_model VARCHAR(256) NOT NULL,
    source_field_path VARCHAR(512) NOT NULL,
    prompt_section VARCHAR(128),
    prompt_label VARCHAR(256),
    required_policy VARCHAR(64) NOT NULL DEFAULT 'DISCOVERED_SOURCE_FIELD',
    projection_policy VARCHAR(64) NOT NULL DEFAULT 'UNMAPPED_PROJECTION_POLICY',
    applicability_rule VARCHAR(256),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS official_prompt_field_state_ledger (
    id BIGSERIAL PRIMARY KEY,
    package_id VARCHAR(128) NOT NULL,
    aggregate_run_id VARCHAR(256),
    official_run_id VARCHAR(256),
    field_key VARCHAR(512) NOT NULL,
    source_type VARCHAR(128),
    source_field_path VARCHAR(1024) NOT NULL,
    source_class VARCHAR(512),
    field_state VARCHAR(64) NOT NULL,
    value_type VARCHAR(256),
    value_hash VARCHAR(128),
    value_length INTEGER,
    value_preview TEXT,
    required_policy VARCHAR(128),
    applicability_rule VARCHAR(512),
    applicability_evidence TEXT,
    projection_policy VARCHAR(128),
    prompt_presence_state VARCHAR(128),
    sealed_evidence_presence_state VARCHAR(128),
    producer_status VARCHAR(128),
    absence_reason_code VARCHAR(128),
    absence_reason_text TEXT,
    metric_impact_policy VARCHAR(128),
    blocking_policy VARCHAR(128),
    blocking_candidate BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_official_prompt_field_state_package
    ON official_prompt_field_state_ledger (package_id, created_at);

CREATE INDEX IF NOT EXISTS idx_official_prompt_field_state_run
    ON official_prompt_field_state_ledger (aggregate_run_id, official_run_id);

CREATE INDEX IF NOT EXISTS idx_official_prompt_field_state_key
    ON official_prompt_field_state_ledger (field_key);

CREATE INDEX IF NOT EXISTS idx_official_prompt_field_state_blocking
    ON official_prompt_field_state_ledger (package_id, blocking_candidate, field_state);

CREATE TABLE IF NOT EXISTS official_prompt_projection_ledger (
    id BIGSERIAL PRIMARY KEY,
    package_id VARCHAR(128) NOT NULL,
    aggregate_run_id VARCHAR(256),
    official_run_id VARCHAR(256),
    field_key VARCHAR(512) NOT NULL,
    prompt_section VARCHAR(256),
    prompt_label VARCHAR(256),
    raw_value_hash VARCHAR(128),
    final_value_hash VARCHAR(128),
    raw_line_number INTEGER,
    final_line_number INTEGER,
    projection_state VARCHAR(64) NOT NULL,
    projection_reason TEXT,
    blocking_candidate BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_official_prompt_projection_package
    ON official_prompt_projection_ledger (package_id, created_at);

CREATE INDEX IF NOT EXISTS idx_official_prompt_projection_run
    ON official_prompt_projection_ledger (aggregate_run_id, official_run_id);

CREATE INDEX IF NOT EXISTS idx_official_prompt_projection_blocking
    ON official_prompt_projection_ledger (package_id, blocking_candidate, projection_state);

-- ------------------------------------------------------------
-- Source migration: V20260511_04__official_actual_prompt_problem_ledger.sql
-- ------------------------------------------------------------
ALTER TABLE official_verification_prompt_comparison
    ALTER COLUMN field_key SET DATA TYPE VARCHAR(512);

ALTER TABLE official_verification_operator_finding
    ALTER COLUMN comparison_field_key SET DATA TYPE VARCHAR(512);

ALTER TABLE official_verification_metric_check_definition
    ALTER COLUMN comparison_field_key SET DATA TYPE VARCHAR(512);

CREATE TABLE IF NOT EXISTS official_actual_prompt_problem_ledger (
    id BIGSERIAL PRIMARY KEY,
    problem_id VARCHAR(256) NOT NULL UNIQUE,
    package_id VARCHAR(128) NOT NULL,
    aggregate_run_id VARCHAR(256) NOT NULL,
    field_key VARCHAR(512) NOT NULL,
    problem_type VARCHAR(64) NOT NULL,
    prompt_section VARCHAR(256),
    prompt_label VARCHAR(256),
    prompt_value TEXT,
    source_field_path VARCHAR(1024),
    sealed_evidence_path VARCHAR(1024),
    expected_state TEXT,
    actual_state TEXT,
    severity VARCHAR(32) NOT NULL,
    affected_metric_codes VARCHAR(512),
    remediation_owner VARCHAR(128),
    created_at TIMESTAMP(6) NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_official_actual_prompt_problem_run
    ON official_actual_prompt_problem_ledger (package_id, aggregate_run_id);

CREATE INDEX IF NOT EXISTS idx_official_actual_prompt_problem_field
    ON official_actual_prompt_problem_ledger (field_key, problem_type);

CREATE INDEX IF NOT EXISTS idx_official_actual_prompt_problem_metric
    ON official_actual_prompt_problem_ledger (affected_metric_codes);

-- ------------------------------------------------------------
-- Source migration: V20260511_05__official_prompt_field_contract_scope.sql
-- ------------------------------------------------------------
ALTER TABLE official_prompt_field_definition
    ADD COLUMN IF NOT EXISTS quality_relevance VARCHAR(64) NOT NULL DEFAULT 'AUDIT_ONLY_SEALED_SOURCE';

ALTER TABLE official_prompt_field_definition
    ADD COLUMN IF NOT EXISTS metric_codes VARCHAR(256);

ALTER TABLE official_prompt_field_definition
    ADD COLUMN IF NOT EXISTS remediation_owner VARCHAR(128);

ALTER TABLE official_prompt_field_definition
    ADD COLUMN IF NOT EXISTS not_applicable_rule TEXT;

ALTER TABLE official_prompt_field_state_ledger
    ADD COLUMN IF NOT EXISTS quality_relevance VARCHAR(64) NOT NULL DEFAULT 'AUDIT_ONLY_SEALED_SOURCE';

ALTER TABLE official_prompt_field_state_ledger
    ADD COLUMN IF NOT EXISTS raw_blocking_candidate BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE official_prompt_field_state_ledger
    ADD COLUMN IF NOT EXISTS official_blocking_candidate BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE official_prompt_projection_ledger
    ADD COLUMN IF NOT EXISTS quality_relevance VARCHAR(64) NOT NULL DEFAULT 'AUDIT_ONLY_SEALED_SOURCE';

ALTER TABLE official_prompt_projection_ledger
    ADD COLUMN IF NOT EXISTS raw_blocking_candidate BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE official_prompt_projection_ledger
    ADD COLUMN IF NOT EXISTS official_blocking_candidate BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_official_prompt_field_state_relevance
    ON official_prompt_field_state_ledger (package_id, quality_relevance, official_blocking_candidate);

CREATE INDEX IF NOT EXISTS idx_official_prompt_projection_relevance
    ON official_prompt_projection_ledger (package_id, quality_relevance, official_blocking_candidate);

-- ------------------------------------------------------------
-- Source migration: V20260512_01__official_prompt_value_lineage_diff_ledgers.sql
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS official_prompt_generation_lineage (
    id BIGSERIAL PRIMARY KEY,
    package_id VARCHAR(128) NOT NULL,
    aggregate_run_id VARCHAR(256) NOT NULL,
    prompt_hash VARCHAR(160),
    context_hash VARCHAR(160),
    system_prompt_hash VARCHAR(160),
    user_prompt_hash VARCHAR(160),
    raw_prompt_hash VARCHAR(160),
    raw_system_prompt_hash VARCHAR(160),
    raw_user_prompt_hash VARCHAR(160),
    prompt_budget_profile VARCHAR(128),
    compression_applied BOOLEAN NOT NULL DEFAULT FALSE,
    transformation_mode VARCHAR(128),
    raw_truth_parity BOOLEAN,
    raw_user_field_count INT,
    final_user_field_count INT,
    field_diff_count INT,
    field_loss_count INT,
    field_changed_count INT,
    field_added_count INT,
    compacted_marker_count INT,
    truncated_marker_count INT,
    lineage_summary_json JSONB,
    created_at TIMESTAMP(6) NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_official_prompt_generation_lineage_run
    ON official_prompt_generation_lineage (aggregate_run_id);
CREATE INDEX IF NOT EXISTS idx_official_prompt_generation_lineage_package
    ON official_prompt_generation_lineage (package_id);

CREATE TABLE IF NOT EXISTS official_prompt_field_value_ledger (
    id BIGSERIAL PRIMARY KEY,
    package_id VARCHAR(128) NOT NULL,
    aggregate_run_id VARCHAR(256) NOT NULL,
    prompt_stage VARCHAR(32) NOT NULL,
    field_key VARCHAR(512) NOT NULL,
    section_key VARCHAR(256),
    section_title VARCHAR(256),
    prompt_label VARCHAR(256),
    value_hash VARCHAR(160),
    value_length INT,
    line_number INT,
    value_preview TEXT,
    compacted_marker BOOLEAN NOT NULL DEFAULT FALSE,
    truncated_marker BOOLEAN NOT NULL DEFAULT FALSE,
    quality_relevance VARCHAR(64),
    blocking_candidate BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT now(),
    CONSTRAINT uq_official_prompt_field_value_ledger
        UNIQUE (package_id, aggregate_run_id, prompt_stage, field_key, line_number)
);

CREATE INDEX IF NOT EXISTS idx_official_prompt_field_value_ledger_run
    ON official_prompt_field_value_ledger (aggregate_run_id, prompt_stage);
CREATE INDEX IF NOT EXISTS idx_official_prompt_field_value_ledger_field
    ON official_prompt_field_value_ledger (aggregate_run_id, field_key);

CREATE TABLE IF NOT EXISTS official_prompt_field_diff_ledger (
    id BIGSERIAL PRIMARY KEY,
    package_id VARCHAR(128) NOT NULL,
    aggregate_run_id VARCHAR(256) NOT NULL,
    field_key VARCHAR(512) NOT NULL,
    section_key VARCHAR(256),
    section_title VARCHAR(256),
    prompt_label VARCHAR(256),
    raw_value_hash VARCHAR(160),
    final_value_hash VARCHAR(160),
    raw_line_number INT,
    final_line_number INT,
    diff_type VARCHAR(64) NOT NULL,
    diff_reason TEXT,
    quality_relevance VARCHAR(64),
    raw_blocking_candidate BOOLEAN NOT NULL DEFAULT FALSE,
    official_blocking_candidate BOOLEAN NOT NULL DEFAULT FALSE,
    blocking_candidate BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_official_prompt_field_diff_ledger_run
    ON official_prompt_field_diff_ledger (aggregate_run_id, diff_type);
CREATE INDEX IF NOT EXISTS idx_official_prompt_field_diff_ledger_field
    ON official_prompt_field_diff_ledger (aggregate_run_id, field_key);

-- ------------------------------------------------------------
-- Source migration: V20260512_02__official_prompt_field_definition_width.sql
-- ------------------------------------------------------------
ALTER TABLE official_prompt_field_definition
    ALTER COLUMN field_key TYPE VARCHAR(512);

ALTER TABLE official_prompt_field_definition
    ALTER COLUMN source_field_path TYPE VARCHAR(1024);

-- ------------------------------------------------------------
-- Source migration: V20260512_03__official_prompt_field_definition_source_contract.sql
-- ------------------------------------------------------------
ALTER TABLE official_prompt_field_definition
    ADD COLUMN IF NOT EXISTS source_package VARCHAR(512);

ALTER TABLE official_prompt_field_definition
    ADD COLUMN IF NOT EXISTS source_class VARCHAR(512);

ALTER TABLE official_prompt_field_definition
    ADD COLUMN IF NOT EXISTS value_type VARCHAR(256);

CREATE INDEX IF NOT EXISTS idx_official_prompt_field_definition_source
    ON official_prompt_field_definition (source_model, source_package, source_class);

-- ------------------------------------------------------------
-- Source migration: V20260514_01__official_metric_issue_current_contract.sql
-- ------------------------------------------------------------
ALTER TABLE official_verification_metric_snapshot
    ADD COLUMN IF NOT EXISTS issue_ids_json TEXT;

ALTER TABLE official_verification_metric_snapshot
    ADD COLUMN IF NOT EXISTS problem_ids_json TEXT;

ALTER TABLE official_verification_metric_snapshot
    ADD COLUMN IF NOT EXISTS current_result BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE official_verification_metric_execution_ledger
    ADD COLUMN IF NOT EXISTS issue_ids_json TEXT;

ALTER TABLE official_verification_metric_execution_ledger
    ADD COLUMN IF NOT EXISTS problem_ids_json TEXT;

ALTER TABLE official_verification_run_batch
    ADD COLUMN IF NOT EXISTS current_result BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE official_verification_operator_finding
    ADD COLUMN IF NOT EXISTS current_result BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE official_actual_prompt_problem_ledger
    ADD COLUMN IF NOT EXISTS current_result BOOLEAN NOT NULL DEFAULT TRUE;

CREATE INDEX IF NOT EXISTS idx_official_verification_metric_snapshot_current
    ON official_verification_metric_snapshot(package_id, current_result, aggregate_run_id);

CREATE INDEX IF NOT EXISTS idx_official_verification_run_batch_current
    ON official_verification_run_batch(package_id, current_result, aggregate_run_id);

-- ------------------------------------------------------------
-- Source migration: V20260515_01__official_metric_purpose_contract_ledgers.sql
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS official_metric_contract_version (
    id BIGSERIAL PRIMARY KEY,
    contract_version VARCHAR(128) NOT NULL UNIQUE,
    source_artifact VARCHAR(512) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS official_metric_purpose_contract (
    id BIGSERIAL PRIMARY KEY,
    contract_version VARCHAR(128) NOT NULL,
    metric_code VARCHAR(32) NOT NULL,
    purpose_statement TEXT NOT NULL,
    decision_question TEXT,
    customer_visible BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT now(),
    UNIQUE (contract_version, metric_code)
);

CREATE TABLE IF NOT EXISTS official_metric_signal_contract (
    id BIGSERIAL PRIMARY KEY,
    contract_version VARCHAR(128) NOT NULL,
    metric_code VARCHAR(32) NOT NULL,
    check_code VARCHAR(128) NOT NULL,
    signal_key VARCHAR(256) NOT NULL,
    prompt_location VARCHAR(512),
    required_role VARCHAR(128),
    interpretation_role VARCHAR(128),
    created_at TIMESTAMP(6) NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS official_metric_input_contract (
    id BIGSERIAL PRIMARY KEY,
    contract_version VARCHAR(128) NOT NULL,
    metric_code VARCHAR(32) NOT NULL,
    check_code VARCHAR(128) NOT NULL,
    input_key VARCHAR(256) NOT NULL,
    required_policy VARCHAR(128) NOT NULL,
    absence_policy VARCHAR(128),
    purpose_scope VARCHAR(128),
    created_at TIMESTAMP(6) NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS official_metric_evaluation_contract (
    id BIGSERIAL PRIMARY KEY,
    contract_version VARCHAR(128) NOT NULL,
    metric_code VARCHAR(32) NOT NULL,
    check_code VARCHAR(128) NOT NULL,
    purpose_question TEXT NOT NULL,
    pass_condition TEXT NOT NULL,
    fail_condition TEXT NOT NULL,
    issue_key VARCHAR(512),
    customer_visible BOOLEAN NOT NULL DEFAULT TRUE,
    readiness_scope VARCHAR(128) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS official_prompt_signal_ledger (
    id BIGSERIAL PRIMARY KEY,
    package_id VARCHAR(128) NOT NULL,
    aggregate_run_id VARCHAR(256) NOT NULL,
    metric_code VARCHAR(32),
    check_code VARCHAR(128),
    signal_key VARCHAR(512) NOT NULL,
    prompt_location VARCHAR(512),
    section_name VARCHAR(256),
    label_name VARCHAR(256),
    value_preview TEXT,
    value_hash VARCHAR(128),
    line_number INTEGER,
    signal_role VARCHAR(128),
    created_at TIMESTAMP(6) NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS official_metric_input_readiness_ledger (
    id BIGSERIAL PRIMARY KEY,
    package_id VARCHAR(128) NOT NULL,
    aggregate_run_id VARCHAR(256) NOT NULL,
    metric_code VARCHAR(32) NOT NULL,
    check_code VARCHAR(128) NOT NULL,
    contract_version VARCHAR(128),
    readiness_state VARCHAR(128) NOT NULL,
    detected_inputs_json TEXT NOT NULL DEFAULT '[]',
    missing_inputs_json TEXT NOT NULL DEFAULT '[]',
    readiness_scope VARCHAR(128) NOT NULL,
    customer_visible BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS official_metric_purpose_evaluation_ledger (
    id BIGSERIAL PRIMARY KEY,
    package_id VARCHAR(128) NOT NULL,
    aggregate_run_id VARCHAR(256) NOT NULL,
    metric_code VARCHAR(32) NOT NULL,
    check_code VARCHAR(128) NOT NULL,
    contract_version VARCHAR(128),
    purpose_statement TEXT,
    decision_utility TEXT,
    purpose_result VARCHAR(128) NOT NULL,
    issue_key VARCHAR(512),
    customer_visible BOOLEAN NOT NULL DEFAULT TRUE,
    readiness_scope VARCHAR(128) NOT NULL,
    detected_signals_json TEXT NOT NULL DEFAULT '[]',
    interpretation_links_json TEXT NOT NULL DEFAULT '[]',
    expected_value TEXT,
    actual_value TEXT,
    remediation_owner VARCHAR(128),
    next_action TEXT,
    reverify_criterion TEXT,
    created_at TIMESTAMP(6) NOT NULL DEFAULT now()
);

ALTER TABLE official_actual_prompt_problem_ledger
    ADD COLUMN IF NOT EXISTS purpose_evaluation_id BIGINT;

ALTER TABLE official_actual_prompt_problem_ledger
    ADD COLUMN IF NOT EXISTS quality_question TEXT;

ALTER TABLE official_actual_prompt_problem_ledger
    ADD COLUMN IF NOT EXISTS why_it_matters TEXT;

ALTER TABLE official_actual_prompt_problem_ledger
    ADD COLUMN IF NOT EXISTS fix_action TEXT;

ALTER TABLE official_actual_prompt_problem_ledger
    ADD COLUMN IF NOT EXISTS reverify_criterion_detail TEXT;

ALTER TABLE official_actual_prompt_problem_ledger
    ADD COLUMN IF NOT EXISTS contract_version_id BIGINT;

CREATE INDEX IF NOT EXISTS idx_official_prompt_signal_ledger_run
    ON official_prompt_signal_ledger (package_id, aggregate_run_id, metric_code, check_code);

CREATE INDEX IF NOT EXISTS idx_official_metric_input_readiness_run
    ON official_metric_input_readiness_ledger (package_id, aggregate_run_id, metric_code, check_code);

CREATE INDEX IF NOT EXISTS idx_official_metric_purpose_evaluation_run
    ON official_metric_purpose_evaluation_ledger (package_id, aggregate_run_id, metric_code, check_code);

CREATE INDEX IF NOT EXISTS idx_official_metric_purpose_evaluation_issue
    ON official_metric_purpose_evaluation_ledger (package_id, aggregate_run_id, issue_key);

-- ------------------------------------------------------------
-- Source migration: V20260517_01__official_metric_contract_completion.sql
-- ------------------------------------------------------------
ALTER TABLE official_metric_purpose_contract
    ADD COLUMN IF NOT EXISTS metric_role VARCHAR(128);

ALTER TABLE official_metric_purpose_contract
    ADD COLUMN IF NOT EXISTS blocks_llm_submission BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE official_metric_purpose_contract
    ADD COLUMN IF NOT EXISTS blocks_certificate BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE official_metric_evaluation_contract
    ADD COLUMN IF NOT EXISTS problem_title TEXT;

ALTER TABLE official_metric_evaluation_contract
    ADD COLUMN IF NOT EXISTS short_problem TEXT;

ALTER TABLE official_metric_evaluation_contract
    ADD COLUMN IF NOT EXISTS expected_message TEXT;

ALTER TABLE official_metric_evaluation_contract
    ADD COLUMN IF NOT EXISTS pass_message TEXT;

ALTER TABLE official_metric_evaluation_contract
    ADD COLUMN IF NOT EXISTS failure_message TEXT;

CREATE TABLE IF NOT EXISTS official_prompt_signal_contract (
    id BIGSERIAL PRIMARY KEY,
    contract_version VARCHAR(128) NOT NULL,
    metric_code VARCHAR(32) NOT NULL,
    check_code VARCHAR(128) NOT NULL,
    signal_key VARCHAR(256) NOT NULL,
    prompt_location VARCHAR(512),
    required_role VARCHAR(128),
    interpretation_role VARCHAR(128),
    created_at TIMESTAMP(6) NOT NULL DEFAULT now(),
    UNIQUE (contract_version, metric_code, check_code, signal_key)
);

CREATE TABLE IF NOT EXISTS official_metric_customer_message_contract (
    id BIGSERIAL PRIMARY KEY,
    contract_version VARCHAR(128) NOT NULL,
    metric_code VARCHAR(32) NOT NULL,
    check_code VARCHAR(128) NOT NULL,
    problem_title TEXT NOT NULL,
    short_problem TEXT NOT NULL,
    why_it_matters TEXT NOT NULL,
    fix_action TEXT NOT NULL,
    reverify_criterion TEXT NOT NULL,
    metric_purpose TEXT NOT NULL,
    blocked_reason TEXT NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT now(),
    UNIQUE (contract_version, metric_code, check_code)
);

CREATE INDEX IF NOT EXISTS idx_official_prompt_signal_contract_lookup
    ON official_prompt_signal_contract (contract_version, metric_code, check_code);

CREATE INDEX IF NOT EXISTS idx_official_metric_customer_message_contract_lookup
    ON official_metric_customer_message_contract (contract_version, metric_code, check_code);

CREATE UNIQUE INDEX IF NOT EXISTS ux_official_metric_input_contract_lookup
    ON official_metric_input_contract (contract_version, metric_code, check_code, input_key);

-- ------------------------------------------------------------
-- Source migration: V20260517_02__official_metric_purpose_evidence_ledger.sql
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS official_metric_purpose_evidence_ledger (
    id BIGSERIAL PRIMARY KEY,
    package_id VARCHAR(128) NOT NULL,
    aggregate_run_id VARCHAR(256) NOT NULL,
    purpose_evaluation_id BIGINT,
    metric_code VARCHAR(32) NOT NULL,
    check_code VARCHAR(128) NOT NULL,
    contract_version VARCHAR(128),
    signal_key VARCHAR(512) NOT NULL,
    prompt_location VARCHAR(512),
    evidence_value TEXT,
    evidence_hash VARCHAR(128),
    interpretation TEXT NOT NULL,
    purpose_result VARCHAR(128) NOT NULL,
    customer_visible BOOLEAN NOT NULL DEFAULT TRUE,
    readiness_scope VARCHAR(128) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_official_metric_purpose_evidence_run
    ON official_metric_purpose_evidence_ledger (package_id, aggregate_run_id, metric_code, check_code);

CREATE INDEX IF NOT EXISTS idx_official_metric_purpose_evidence_eval
    ON official_metric_purpose_evidence_ledger (purpose_evaluation_id);

-- ------------------------------------------------------------
-- Source migration: V20260517_03__official_metric_evaluation_contract_lookup.sql
-- ------------------------------------------------------------
CREATE UNIQUE INDEX IF NOT EXISTS ux_official_metric_evaluation_contract_lookup
    ON official_metric_evaluation_contract (contract_version, metric_code, check_code);

-- ------------------------------------------------------------
-- Source migration: V20260521_01__official_metric_customer_display_contract.sql
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS official_metric_customer_display_contract (
    id BIGSERIAL PRIMARY KEY,
    contract_version VARCHAR(128) NOT NULL,
    metric_code VARCHAR(32) NOT NULL,
    check_code VARCHAR(128) NOT NULL,
    display_role VARCHAR(64) NOT NULL,
    display_template TEXT NOT NULL,
    customer_visible BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT now(),
    UNIQUE (contract_version, metric_code, check_code, display_role)
);

CREATE TABLE IF NOT EXISTS official_metric_customer_display_binding (
    id BIGSERIAL PRIMARY KEY,
    contract_version VARCHAR(128) NOT NULL,
    metric_code VARCHAR(32) NOT NULL,
    check_code VARCHAR(128) NOT NULL,
    display_role VARCHAR(64) NOT NULL,
    binding_key VARCHAR(256) NOT NULL,
    source_fact_key VARCHAR(256) NOT NULL,
    required BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT now(),
    UNIQUE (contract_version, metric_code, check_code, display_role, binding_key)
);

CREATE TABLE IF NOT EXISTS official_metric_customer_display_payload (
    id BIGSERIAL PRIMARY KEY,
    package_id VARCHAR(128) NOT NULL,
    aggregate_run_id VARCHAR(256) NOT NULL,
    metric_code VARCHAR(32) NOT NULL,
    check_code VARCHAR(128) NOT NULL,
    contract_version VARCHAR(128) NOT NULL,
    display_role VARCHAR(64) NOT NULL,
    title TEXT,
    summary TEXT,
    evidence_text TEXT,
    why_it_matters TEXT,
    resolution_action TEXT,
    reverify_condition TEXT,
    context_items_json TEXT NOT NULL DEFAULT '[]',
    bound_facts_json TEXT NOT NULL DEFAULT '{}',
    raw_evidence_ref VARCHAR(512),
    created_at TIMESTAMP(6) NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_official_metric_customer_display_contract_lookup
    ON official_metric_customer_display_contract (contract_version, metric_code, check_code, display_role);

CREATE INDEX IF NOT EXISTS idx_official_metric_customer_display_binding_lookup
    ON official_metric_customer_display_binding (contract_version, metric_code, check_code, display_role);

CREATE INDEX IF NOT EXISTS idx_official_metric_customer_display_payload_run
    ON official_metric_customer_display_payload (package_id, aggregate_run_id, metric_code, check_code);

-- ------------------------------------------------------------
-- Source migration: V20260523_02__pqa_prompt_runtime_slot_contract.sql
-- ------------------------------------------------------------
create table if not exists prompt_runtime_slot_contract (
    id bigserial primary key,
    contract_version varchar(128) not null,
    prompt_key varchar(128) not null default 'SECURITY_DECISION',
    slot_key varchar(256) not null,
    prompt_location varchar(512) not null,
    section_key varchar(256) not null,
    label_key varchar(256),
    signal_key varchar(512) not null,
    canonical_context_path varchar(512) not null,
    source_producer varchar(256) not null,
    priority varchar(64) not null,
    truncation_policy varchar(64) not null,
    required_role varchar(128),
    interpretation_role varchar(128),
    active boolean not null default true,
    created_at timestamp not null default current_timestamp,
    updated_at timestamp not null default current_timestamp,
    constraint uq_prompt_runtime_slot_contract
        unique (contract_version, prompt_key, slot_key)
);

create index if not exists idx_prompt_runtime_slot_contract_location
    on prompt_runtime_slot_contract (contract_version, prompt_location, active);

create index if not exists idx_prompt_runtime_slot_contract_label
    on prompt_runtime_slot_contract (contract_version, label_key, active);

create table if not exists prompt_runtime_metric_check_slot_contract (
    id bigserial primary key,
    contract_version varchar(128) not null,
    prompt_key varchar(128) not null default 'SECURITY_DECISION',
    metric_code varchar(32) not null,
    check_code varchar(128) not null,
    slot_key varchar(256) not null,
    prompt_location varchar(512) not null,
    required_role varchar(128),
    interpretation_role varchar(128),
    required boolean not null default true,
    active boolean not null default true,
    created_at timestamp not null default current_timestamp,
    updated_at timestamp not null default current_timestamp,
    constraint uq_prompt_runtime_metric_check_slot_contract
        unique (contract_version, prompt_key, metric_code, check_code, slot_key),
    constraint fk_prompt_runtime_metric_check_slot_contract_slot
        foreign key (contract_version, prompt_key, slot_key)
        references prompt_runtime_slot_contract (contract_version, prompt_key, slot_key)
);

create index if not exists idx_prompt_runtime_metric_check_slot_contract_check
    on prompt_runtime_metric_check_slot_contract (contract_version, metric_code, check_code, active);

with signal_source as (
    select distinct
           s.contract_version,
           s.metric_code,
           s.check_code,
           s.signal_key,
           s.prompt_location,
           s.required_role,
           s.interpretation_role
      from official_prompt_signal_contract s
      join official_metric_evaluation_contract c
        on c.contract_version = s.contract_version
       and c.metric_code = s.metric_code
       and c.check_code = s.check_code
     where s.contract_version is not null
       and s.metric_code is not null
       and s.check_code is not null
       and s.signal_key is not null
       and s.prompt_location is not null
),
slot_source as (
    select
        contract_version,
        'SECURITY_DECISION'::varchar(128) as prompt_key,
        (
            left(
                lower(regexp_replace(
                    regexp_replace(
                        replace(replace(prompt_location, 'finalUserPrompt.', 'user.'), 'finalSystemPrompt.', 'system.')
                        || '.' || replace(signal_key, ':', '.'),
                        '[^A-Za-z0-9]+',
                        '_',
                        'g'
                    ),
                    '(^_|_$)',
                    '',
                    'g'
                )),
                180
            )
            || '_' || substr(md5(prompt_location || '|' || signal_key), 1, 12)
        )::varchar(256) as slot_key,
        prompt_location,
        case
            when signal_key like 'section:%' then substring(signal_key from 9)
            else prompt_location
        end::varchar(256) as section_key,
        case
            when signal_key like 'label:%' then substring(signal_key from 7)
            else null
        end::varchar(256) as label_key,
        signal_key,
        ('canonical.' || lower(regexp_replace(replace(signal_key, ':', '.'), '[^A-Za-z0-9]+', '.', 'g')))::varchar(512)
            as canonical_context_path,
        case
            when signal_key like 'section:%' then 'SecurityDecisionPromptSections'
            when prompt_location like 'finalSystemPrompt.%' then 'SecurityDecisionStandardPromptTemplate'
            else 'PromptContextComposer'
        end::varchar(256) as source_producer,
        case
            when required_role = 'ALL' then 'P0_REQUIRED'
            when required_role like '%DECIDABLE%' then 'P1_HIGH_VALUE'
            else 'P2_SUPPORTING'
        end::varchar(64) as priority,
        case
            when lower(signal_key) like '%truncated%'
              or lower(prompt_location) like '%truncated%'
              or signal_key like '%BaselineContextSummary%' then 'FORBID_TRUNCATION'
            when required_role = 'ALL' then 'PROTECT'
            else 'STANDARD'
        end::varchar(64) as truncation_policy,
        required_role,
        interpretation_role
    from signal_source
)
insert into prompt_runtime_slot_contract (
    contract_version, prompt_key, slot_key, prompt_location, section_key, label_key,
    signal_key, canonical_context_path, source_producer, priority, truncation_policy,
    required_role, interpretation_role, active, created_at, updated_at
)
select distinct
       contract_version, prompt_key, slot_key, prompt_location, section_key, label_key,
       signal_key, canonical_context_path, source_producer, priority, truncation_policy,
       required_role, interpretation_role, true, current_timestamp, current_timestamp
  from slot_source
on conflict (contract_version, prompt_key, slot_key) do update
   set prompt_location = excluded.prompt_location,
       section_key = excluded.section_key,
       label_key = excluded.label_key,
       signal_key = excluded.signal_key,
       canonical_context_path = excluded.canonical_context_path,
       source_producer = excluded.source_producer,
       priority = excluded.priority,
       truncation_policy = excluded.truncation_policy,
       required_role = excluded.required_role,
       interpretation_role = excluded.interpretation_role,
       active = true,
       updated_at = current_timestamp;

with signal_source as (
    select distinct
           s.contract_version,
           s.metric_code,
           s.check_code,
           s.signal_key,
           s.prompt_location,
           s.required_role,
           s.interpretation_role
      from official_prompt_signal_contract s
      join official_metric_evaluation_contract c
        on c.contract_version = s.contract_version
       and c.metric_code = s.metric_code
       and c.check_code = s.check_code
     where s.contract_version is not null
       and s.metric_code is not null
       and s.check_code is not null
       and s.signal_key is not null
       and s.prompt_location is not null
),
slot_source as (
    select
        s.contract_version,
        'SECURITY_DECISION'::varchar(128) as prompt_key,
        s.metric_code,
        s.check_code,
        (
            left(
                lower(regexp_replace(
                    regexp_replace(
                        replace(replace(s.prompt_location, 'finalUserPrompt.', 'user.'), 'finalSystemPrompt.', 'system.')
                        || '.' || replace(s.signal_key, ':', '.'),
                        '[^A-Za-z0-9]+',
                        '_',
                        'g'
                    ),
                    '(^_|_$)',
                    '',
                    'g'
                )),
                180
            )
            || '_' || substr(md5(s.prompt_location || '|' || s.signal_key), 1, 12)
        )::varchar(256) as slot_key,
        s.prompt_location,
        s.required_role,
        s.interpretation_role
    from signal_source s
)
insert into prompt_runtime_metric_check_slot_contract (
    contract_version, prompt_key, metric_code, check_code, slot_key, prompt_location,
    required_role, interpretation_role, required, active, created_at, updated_at
)
select distinct
       contract_version, prompt_key, metric_code, check_code, slot_key, prompt_location,
       required_role, interpretation_role, true, true, current_timestamp, current_timestamp
  from slot_source
on conflict (contract_version, prompt_key, metric_code, check_code, slot_key) do update
   set prompt_location = excluded.prompt_location,
       required_role = excluded.required_role,
       interpretation_role = excluded.interpretation_role,
       required = true,
       active = true,
       updated_at = current_timestamp;

delete from prompt_runtime_metric_check_slot_contract m
 where not exists (
       select 1
         from official_metric_evaluation_contract c
        where c.contract_version = m.contract_version
          and c.metric_code = m.metric_code
          and c.check_code = m.check_code
 );

delete from prompt_runtime_slot_contract s
 where not exists (
       select 1
         from prompt_runtime_metric_check_slot_contract m
        where m.contract_version = s.contract_version
          and m.prompt_key = s.prompt_key
          and m.slot_key = s.slot_key
 );

-- ------------------------------------------------------------
-- Source migration: V20260526_01__pqa_sealed_evidence_resource_status.sql
-- ------------------------------------------------------------
create table if not exists pqa_sealed_evidence_resource_status (
    id bigserial primary key,
    tenant_id varchar(128) not null default 'default',
    resource_id varchar(255) not null,
    resource_url varchar(1000) not null,
    http_method varchar(32) not null,
    evidence_status varchar(64) not null,
    baseline_status varchar(64) not null default 'UNKNOWN',
    rag_status varchar(64) not null default 'UNKNOWN',
    certificate_state varchar(64) not null default 'REVIEW_REQUIRED',
    latest_package_id varchar(256),
    latest_aggregate_run_id varchar(256),
    latest_certificate_id varchar(128),
    first_evidence_issued_at timestamp,
    last_issue_requested_at timestamp,
    last_issue_completed_at timestamp,
    last_failure_reason varchar(2000),
    created_at timestamp not null default current_timestamp,
    updated_at timestamp not null default current_timestamp,
    constraint uq_pqa_sealed_evidence_resource_status
        unique (tenant_id, resource_id, http_method),
    constraint ck_pqa_sealed_evidence_resource_status_state
        check (evidence_status in (
            'NO_EVIDENCE',
            'BASELINE_REQUIRED',
            'RAG_REQUIRED',
            'READY_TO_ISSUE',
            'ISSUING',
            'ISSUED',
            'FAILED'
        ))
);

create index if not exists idx_pqa_sealed_evidence_resource_status_url
    on pqa_sealed_evidence_resource_status (tenant_id, resource_url, http_method);

create index if not exists idx_pqa_sealed_evidence_resource_status_state
    on pqa_sealed_evidence_resource_status (tenant_id, evidence_status, updated_at);

create index if not exists idx_pqa_sealed_evidence_resource_status_package
    on pqa_sealed_evidence_resource_status (latest_package_id);

create table if not exists pqa_sealed_evidence_issuance_audit (
    id bigserial primary key,
    audit_id varchar(128) not null unique,
    tenant_id varchar(128) not null default 'default',
    resource_id varchar(255) not null,
    resource_url varchar(1000) not null,
    http_method varchar(32) not null,
    actor varchar(255) not null,
    action_type varchar(64) not null,
    previous_status varchar(64),
    next_status varchar(64) not null,
    package_id varchar(256),
    aggregate_run_id varchar(256),
    request_id varchar(256),
    detail_json text,
    created_at timestamp not null default current_timestamp
);

create index if not exists idx_pqa_sealed_evidence_issuance_audit_resource
    on pqa_sealed_evidence_issuance_audit (tenant_id, resource_id, http_method, created_at);

create index if not exists idx_pqa_sealed_evidence_issuance_audit_package
    on pqa_sealed_evidence_issuance_audit (package_id, created_at);

-- ------------------------------------------------------------
-- Source migration: V20260526_02__pqa_sealed_evidence_readiness.sql
-- ------------------------------------------------------------
create table if not exists pqa_sealed_evidence_baseline_requirement_contract (
    id bigserial primary key,
    requirement_code varchar(96) not null unique,
    display_label varchar(200) not null,
    source_field_path varchar(240) not null,
    metric_codes varchar(240) not null,
    is_required boolean not null default true,
    sort_order integer not null,
    is_active boolean not null default true,
    created_at timestamp not null default current_timestamp,
    updated_at timestamp not null default current_timestamp
);

insert into pqa_sealed_evidence_baseline_requirement_contract
    (requirement_code, display_label, source_field_path, metric_codes, is_required, sort_order, is_active)
values
    ('OBSERVED_HOURS', 'Observed hours', 'finalUserPrompt.personalWorkProfile.observedHours', 'BMA,USNS,RPI', true, 10, true),
    ('OBSERVED_NETWORKS', 'Observed networks', 'finalUserPrompt.personalWorkProfile.observedNetworks', 'BMA,USNS,CCR', true, 20, true),
    ('OBSERVED_BROWSERS', 'Observed browsers', 'finalUserPrompt.personalWorkProfile.observedBrowsers', 'BMA,USNS,CCR,BSR', true, 30, true),
    ('OBSERVED_OPERATING_SYSTEMS', 'Observed operating systems', 'finalUserPrompt.personalWorkProfile.observedOperatingSystems', 'BMA,USNS,CCR', true, 40, true),
    ('OBSERVED_AUTHENTICATION_TYPES', 'Observed authentication types', 'finalUserPrompt.personalWorkProfile.observedAuthenticationTypes', 'BMA,USNS,EIR', true, 50, true),
    ('OBSERVED_ACTION_FAMILIES', 'Observed action families', 'finalUserPrompt.personalWorkProfile.observedActionFamilies', 'BMA,USNS,CCSR', true, 60, true),
    ('OBSERVED_RESOURCE_FAMILIES', 'Observed resource families', 'finalUserPrompt.personalWorkProfile.observedResourceFamilies', 'BMA,RPI,PRE', true, 70, true),
    ('REQUEST_COMBINATION_EVIDENCE_SCOPE', 'Request combination evidence scope', 'finalUserPrompt.personalWorkProfile.currentRequestCombinationEvidenceScope', 'USNS,RPI,BMA', true, 80, true),
    ('SESSION_NARRATIVE_CONTEXT', 'Session narrative context', 'finalUserPrompt.sessionNarrativeContext', 'BSR,EIR,CCR', true, 90, true),
    ('APPROVAL_FRICTION_DELEGATION_BOUNDARY', 'Approval, friction and delegation boundary', 'finalUserPrompt.behavior.approvalFrictionDelegationBoundary', 'BSR,EIR', true, 100, true)
on conflict (requirement_code) do update
   set display_label = excluded.display_label,
       source_field_path = excluded.source_field_path,
       metric_codes = excluded.metric_codes,
       is_required = excluded.is_required,
       sort_order = excluded.sort_order,
       is_active = excluded.is_active,
       updated_at = current_timestamp;

create table if not exists pqa_sealed_evidence_baseline_seed_ledger (
    id bigserial primary key,
    seed_id varchar(96) not null unique,
    tenant_id varchar(120) not null,
    resource_id varchar(200) not null,
    http_method varchar(16) not null,
    user_id varchar(200),
    action_family varchar(120),
    approval_state varchar(32) not null default 'APPROVED',
    approved_by varchar(200) not null,
    approved_reason text not null,
    seed_summary text not null,
    created_at timestamp not null default current_timestamp,
    updated_at timestamp not null default current_timestamp,
    constraint pqa_sealed_evidence_baseline_seed_state_ck
        check (approval_state in ('APPROVED', 'REVOKED'))
);

create index if not exists idx_pqa_sealed_baseline_seed_scope
    on pqa_sealed_evidence_baseline_seed_ledger (tenant_id, resource_id, http_method, user_id, action_family);

create table if not exists pqa_sealed_evidence_baseline_readiness_ledger (
    id bigserial primary key,
    readiness_id varchar(96) not null unique,
    tenant_id varchar(120) not null,
    resource_id varchar(200) not null,
    http_method varchar(16) not null,
    user_id varchar(200),
    action_family varchar(120),
    requirement_code varchar(96) not null,
    readiness_state varchar(32) not null,
    value_summary text,
    approved_seed_id varchar(96),
    package_id varchar(120),
    created_at timestamp not null default current_timestamp,
    updated_at timestamp not null default current_timestamp,
    constraint pqa_sealed_evidence_baseline_readiness_state_ck
        check (readiness_state in ('READY', 'MISSING', 'NOT_APPLICABLE', 'UNKNOWN')),
    constraint pqa_sealed_evidence_baseline_readiness_req_fk
        foreign key (requirement_code)
        references pqa_sealed_evidence_baseline_requirement_contract (requirement_code)
);

create unique index if not exists uq_pqa_sealed_baseline_readiness_scope
    on pqa_sealed_evidence_baseline_readiness_ledger (
        tenant_id, resource_id, http_method,
        coalesce(user_id, ''), coalesce(action_family, ''), requirement_code
    );

create index if not exists idx_pqa_sealed_baseline_readiness_state
    on pqa_sealed_evidence_baseline_readiness_ledger (tenant_id, resource_id, http_method, readiness_state);

create table if not exists pqa_sealed_evidence_rag_readiness_ledger (
    id bigserial primary key,
    readiness_id varchar(96) not null unique,
    tenant_id varchar(120) not null,
    resource_id varchar(200) not null,
    http_method varchar(16) not null,
    user_id varchar(200),
    action_family varchar(120),
    rag_state varchar(32) not null,
    document_count integer not null default 0,
    scope_summary text,
    package_id varchar(120),
    created_at timestamp not null default current_timestamp,
    updated_at timestamp not null default current_timestamp,
    constraint pqa_sealed_evidence_rag_state_ck
        check (rag_state in ('DOCUMENTS_AVAILABLE', 'NO_DOCUMENTS', 'NOT_APPLICABLE', 'UNKNOWN')),
    constraint pqa_sealed_evidence_rag_document_count_ck
        check (document_count >= 0)
);

create unique index if not exists uq_pqa_sealed_rag_readiness_scope
    on pqa_sealed_evidence_rag_readiness_ledger (
        tenant_id, resource_id, http_method,
        coalesce(user_id, ''), coalesce(action_family, '')
    );

create index if not exists idx_pqa_sealed_rag_readiness_state
    on pqa_sealed_evidence_rag_readiness_ledger (tenant_id, resource_id, http_method, rag_state);

-- ------------------------------------------------------------
-- Source migration: V20260526_04__pqa_sealed_evidence_issuance_batch.sql
-- ------------------------------------------------------------
create table if not exists pqa_sealed_evidence_issuance_batch (
    batch_id varchar(128) primary key,
    tenant_id varchar(128) not null,
    actor varchar(255) not null,
    request_count integer not null,
    success_count integer not null default 0,
    failed_count integer not null default 0,
    batch_state varchar(32) not null,
    created_at timestamp not null,
    updated_at timestamp not null,
    constraint pqa_sealed_evidence_issuance_batch_state_ck
        check (batch_state in ('ISSUING', 'ISSUED', 'PARTIAL_FAILED', 'FAILED'))
);

create table if not exists pqa_sealed_evidence_issuance_batch_item (
    item_id varchar(128) primary key,
    batch_id varchar(128) not null references pqa_sealed_evidence_issuance_batch(batch_id) on delete cascade,
    tenant_id varchar(128) not null,
    resource_id varchar(255) not null,
    resource_url varchar(1000) not null,
    http_method varchar(32) not null,
    request_id varchar(255),
    package_id varchar(256),
    generation_id varchar(128),
    evidence_status varchar(64) not null,
    failure_reason text,
    created_at timestamp not null,
    updated_at timestamp not null,
    constraint pqa_sealed_evidence_issuance_batch_item_status_ck
        check (evidence_status in ('ISSUING', 'ISSUED', 'FAILED'))
);

create index if not exists idx_pqa_sealed_evidence_issuance_batch_tenant
    on pqa_sealed_evidence_issuance_batch (tenant_id, created_at desc);

create index if not exists idx_pqa_sealed_evidence_issuance_batch_item_batch
    on pqa_sealed_evidence_issuance_batch_item (batch_id, created_at);

create index if not exists idx_pqa_sealed_evidence_issuance_batch_item_resource
    on pqa_sealed_evidence_issuance_batch_item (tenant_id, resource_id, http_method, created_at desc);

-- ------------------------------------------------------------
-- Source migration: V20260529_02__official_metric_check_display_evidence_contract.sql
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS official_metric_check_display_evidence_contract (
    id BIGSERIAL PRIMARY KEY,
    contract_version VARCHAR(128) NOT NULL,
    metric_code VARCHAR(32) NOT NULL,
    check_code VARCHAR(128) NOT NULL,
    criterion_template TEXT NOT NULL,
    judgment_template TEXT NOT NULL,
    failure_judgment_template TEXT NOT NULL,
    not_applicable_judgment_template TEXT,
    runtime_fact_bindings_json TEXT NOT NULL DEFAULT '[]',
    context_item_bindings_json TEXT NOT NULL DEFAULT '[]',
    readiness_scope VARCHAR(128) NOT NULL,
    customer_visible BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT now(),
    UNIQUE (contract_version, metric_code, check_code)
);

CREATE INDEX IF NOT EXISTS idx_official_metric_check_display_evidence_contract_lookup
    ON official_metric_check_display_evidence_contract (contract_version, metric_code, check_code);

-- ------------------------------------------------------------
-- Source migration: V20260529_03__official_metric_purpose_evidence_display_payload.sql
-- ------------------------------------------------------------
ALTER TABLE official_metric_purpose_evidence_ledger
    ADD COLUMN IF NOT EXISTS context_items_json TEXT NOT NULL DEFAULT '[]',
    ADD COLUMN IF NOT EXISTS runtime_facts_json TEXT NOT NULL DEFAULT '[]';

-- ------------------------------------------------------------
-- Source migration: V20260529_04__official_metric_purpose_evidence_display_payload_backfill.sql
-- ------------------------------------------------------------
UPDATE official_metric_purpose_evidence_ledger evidence
   SET runtime_facts_json = COALESCE(
           NULLIF(evidence.runtime_facts_json, '[]'),
           (
               SELECT payload.bound_facts_json
                 FROM official_metric_customer_display_payload payload
                WHERE payload.aggregate_run_id = evidence.aggregate_run_id
                  AND UPPER(payload.metric_code) = UPPER(evidence.metric_code)
                  AND payload.check_code = evidence.check_code
                  AND payload.contract_version = evidence.contract_version
                  AND payload.display_role = CASE
                          WHEN evidence.purpose_result = 'PURPOSE_FAILED' THEN 'FAIL_EVIDENCE'
                          ELSE 'PASS_EVIDENCE'
                      END
                  AND COALESCE(payload.bound_facts_json, '[]') <> '[]'
                ORDER BY payload.id DESC
                LIMIT 1
           ),
           '[]'
       ),
       context_items_json = COALESCE(
           NULLIF(evidence.context_items_json, '[]'),
           (
               SELECT payload.context_items_json
                 FROM official_metric_customer_display_payload payload
                WHERE payload.aggregate_run_id = evidence.aggregate_run_id
                  AND UPPER(payload.metric_code) = UPPER(evidence.metric_code)
                  AND payload.check_code = evidence.check_code
                  AND payload.contract_version = evidence.contract_version
                  AND payload.display_role = CASE
                          WHEN evidence.purpose_result = 'PURPOSE_FAILED' THEN 'FAIL_EVIDENCE'
                          ELSE 'PASS_EVIDENCE'
                      END
                  AND COALESCE(payload.context_items_json, '[]') <> '[]'
                ORDER BY payload.id DESC
                LIMIT 1
           ),
           '[]'
       )
 WHERE COALESCE(evidence.runtime_facts_json, '[]') = '[]'
    OR COALESCE(evidence.context_items_json, '[]') = '[]';

-- ------------------------------------------------------------
-- Source migration: V20260529_05__official_metric_purpose_evidence_runtime_facts_normalization.sql
-- ------------------------------------------------------------
WITH structured_runtime AS (
    SELECT e.id,
           jsonb_agg(to_jsonb(trim(value_text)) ORDER BY value_ord)::text AS runtime_facts_json
      FROM official_metric_purpose_evidence_ledger e
      CROSS JOIN LATERAL jsonb_array_elements(e.runtime_facts_json::jsonb) WITH ORDINALITY item(payload, item_ord)
      CROSS JOIN LATERAL regexp_split_to_table(coalesce(item.payload ->> 'runtimeFacts', ''), E'[,\\n]') WITH ORDINALITY split(value_text, split_ord)
      CROSS JOIN LATERAL (SELECT item.item_ord * 1000 + split.split_ord AS value_ord) ords
     WHERE e.customer_visible = true
       AND coalesce(e.runtime_facts_json, '[]') <> '[]'
       AND e.runtime_facts_json LIKE '%"signalKey"%'
       AND trim(value_text) <> ''
     GROUP BY e.id
),
binding_runtime AS (
    SELECT e.id,
           jsonb_agg(to_jsonb(fact_text) ORDER BY fact_ord)::text AS runtime_facts_json
      FROM official_metric_purpose_evidence_ledger e
      JOIN official_metric_check_display_evidence_contract c
        ON c.contract_version = e.contract_version
       AND upper(c.metric_code) = upper(e.metric_code)
       AND c.check_code = e.check_code
      CROSS JOIN LATERAL jsonb_array_elements(c.runtime_fact_bindings_json::jsonb) WITH ORDINALITY binding(payload, binding_ord)
      CROSS JOIN LATERAL (
          SELECT nullif(coalesce(
                     binding.payload ->> 'sourceFactKey',
                     binding.payload ->> 'label',
                     binding.payload ->> 'bindingKey'
                 ), '') AS source_fact_key
      ) source_fact
      JOIN LATERAL (
          SELECT concat(source_fact.source_fact_key, ' value ', v.value_preview) AS fact_text,
                 binding.binding_ord AS fact_ord
            FROM official_prompt_field_value_ledger v
           WHERE v.aggregate_run_id = e.aggregate_run_id
             AND source_fact.source_fact_key IS NOT NULL
             AND coalesce(v.value_preview, '') <> ''
             AND (
                  lower(v.prompt_label) = lower(source_fact.source_fact_key)
                  OR lower(v.field_key) = lower(source_fact.source_fact_key)
                  OR lower(v.field_key) LIKE concat('%.', lower(source_fact.source_fact_key))
             )
           ORDER BY CASE
                        WHEN v.prompt_stage = 'FINAL_USER' THEN 0
                        WHEN v.prompt_stage = 'RAW_USER' THEN 1
                        ELSE 2
                    END,
                    v.id DESC
           LIMIT 1
      ) fact ON true
     WHERE e.customer_visible = true
       AND (
             coalesce(e.runtime_facts_json, '[]') = '[]'
             OR e.runtime_facts_json LIKE '%"signalKey"%'
             OR e.runtime_facts_json LIKE '%"evidenceValue"%'
       )
     GROUP BY e.id
),
fallback_runtime AS (
    SELECT e.id,
           jsonb_build_array(e.evidence_value)::text AS runtime_facts_json
      FROM official_metric_purpose_evidence_ledger e
     WHERE e.customer_visible = true
       AND (
             coalesce(e.runtime_facts_json, '[]') = '[]'
             OR e.runtime_facts_json LIKE '%"signalKey"%'
             OR e.runtime_facts_json LIKE '%"evidenceValue"%'
       )
       AND coalesce(e.evidence_value, '') <> ''
)
UPDATE official_metric_purpose_evidence_ledger e
   SET runtime_facts_json = coalesce(
           structured_runtime.runtime_facts_json,
           binding_runtime.runtime_facts_json,
           fallback_runtime.runtime_facts_json,
           '[]'
       )
  FROM fallback_runtime
  LEFT JOIN structured_runtime ON structured_runtime.id = fallback_runtime.id
  LEFT JOIN binding_runtime ON binding_runtime.id = fallback_runtime.id
 WHERE e.id = fallback_runtime.id;

-- ------------------------------------------------------------
-- Source migration: V20260605_01__pqa_resource_action_family_prompt_field_contract.sql
-- ------------------------------------------------------------
insert into official_prompt_field_definition (
    field_key,
    source_model,
    source_field_path,
    prompt_section,
    prompt_label,
    required_policy,
    projection_policy,
    applicability_rule,
    is_active,
    created_at,
    quality_relevance,
    metric_codes,
    remediation_owner,
    not_applicable_rule,
    source_package,
    source_class,
    value_type
) values
(
    'raw_user_prompt_field:RESOURCE_AND_ACTION_CONTEXT.CURRENT_PATH_FAMILY',
    'RAW_USER_PROMPT_FIELD',
    'rawUserPrompt.RESOURCE_AND_ACTION_CONTEXT.CURRENT_PATH_FAMILY',
    'RESOURCE AND ACTION CONTEXT',
    'CurrentPathFamily',
    'RESOURCE_CONTEXT_REQUIRED',
    'MUST_MATCH_FINAL_USER_PROMPT_OR_DECLARED_POLICY',
    null,
    true,
    current_timestamp,
    'LLM_DECISION_CONTRACT',
    'RAP,COR,CCR,PFR,MTR',
    'RESOURCE_CONTEXT_PRODUCER',
    null,
    'prompt',
    'prompt.line',
    'java.lang.String'
),
(
    'final_user_prompt_field:RESOURCE_AND_ACTION_CONTEXT.CURRENT_PATH_FAMILY',
    'FINAL_USER_PROMPT_FIELD',
    'userPrompt.RESOURCE_AND_ACTION_CONTEXT.CURRENT_PATH_FAMILY',
    'RESOURCE AND ACTION CONTEXT',
    'CurrentPathFamily',
    'RESOURCE_CONTEXT_REQUIRED',
    'MUST_MATCH_FINAL_USER_PROMPT_OR_DECLARED_POLICY',
    null,
    true,
    current_timestamp,
    'LLM_DECISION_CONTRACT',
    'RAP,COR,CCR,PFR,MTR',
    'RESOURCE_CONTEXT_PRODUCER',
    null,
    'prompt',
    'prompt.line',
    'java.lang.String'
),
(
    'raw_user_prompt_field:RESOURCE_AND_ACTION_CONTEXT.CURRENT_RESOURCE_FAMILY',
    'RAW_USER_PROMPT_FIELD',
    'rawUserPrompt.RESOURCE_AND_ACTION_CONTEXT.CURRENT_RESOURCE_FAMILY',
    'RESOURCE AND ACTION CONTEXT',
    'CurrentResourceFamily',
    'RESOURCE_CONTEXT_REQUIRED',
    'MUST_MATCH_FINAL_USER_PROMPT_OR_DECLARED_POLICY',
    null,
    true,
    current_timestamp,
    'LLM_DECISION_CONTRACT',
    'RAP,COR,CCR,PFR,MTR',
    'RESOURCE_CONTEXT_PRODUCER',
    null,
    'prompt',
    'prompt.line',
    'java.lang.String'
),
(
    'final_user_prompt_field:RESOURCE_AND_ACTION_CONTEXT.CURRENT_RESOURCE_FAMILY',
    'FINAL_USER_PROMPT_FIELD',
    'userPrompt.RESOURCE_AND_ACTION_CONTEXT.CURRENT_RESOURCE_FAMILY',
    'RESOURCE AND ACTION CONTEXT',
    'CurrentResourceFamily',
    'RESOURCE_CONTEXT_REQUIRED',
    'MUST_MATCH_FINAL_USER_PROMPT_OR_DECLARED_POLICY',
    null,
    true,
    current_timestamp,
    'LLM_DECISION_CONTRACT',
    'RAP,COR,CCR,PFR,MTR',
    'RESOURCE_CONTEXT_PRODUCER',
    null,
    'prompt',
    'prompt.line',
    'java.lang.String'
)
on conflict (field_key) do update
   set source_model = excluded.source_model,
       source_field_path = excluded.source_field_path,
       prompt_section = excluded.prompt_section,
       prompt_label = excluded.prompt_label,
       required_policy = excluded.required_policy,
       projection_policy = excluded.projection_policy,
       applicability_rule = excluded.applicability_rule,
       is_active = true,
       quality_relevance = excluded.quality_relevance,
       metric_codes = excluded.metric_codes,
       remediation_owner = excluded.remediation_owner,
       not_applicable_rule = excluded.not_applicable_rule,
       source_package = excluded.source_package,
       source_class = excluded.source_class,
       value_type = excluded.value_type;

-- ------------------------------------------------------------
-- Source migration: V20260605_02__pqa_rag_reason_prompt_field_contract.sql
-- ------------------------------------------------------------
insert into official_prompt_field_definition (
    field_key,
    source_model,
    source_field_path,
    prompt_section,
    prompt_label,
    required_policy,
    projection_policy,
    applicability_rule,
    is_active,
    created_at,
    quality_relevance,
    metric_codes,
    remediation_owner,
    not_applicable_rule,
    source_package,
    source_class,
    value_type
) values
(
    'final_user_prompt_field:RAG_EVIDENCE.RAG_SCOPE_REASON',
    'FINAL_USER_PROMPT_FIELD',
    'userPrompt.RAG_EVIDENCE.RAG_SCOPE_REASON',
    'RAG EVIDENCE',
    'RagScopeReason',
    'RAG_SCOPE_REASON_REQUIRED',
    'MUST_MATCH_FINAL_USER_PROMPT_OR_DECLARED_POLICY',
    'RAG_DOCUMENTS_RETRIEVED',
    true,
    current_timestamp,
    'LLM_DECISION_CONTRACT',
    'RAP,COR,CCR,PFR,MTR',
    'RAG_CONTEXT_PRODUCER',
    null,
    'prompt',
    'prompt.line',
    'java.lang.String'
),
(
    'final_user_prompt_field:RAG_EVIDENCE.RAG_AUTHORIZATION_REASON',
    'FINAL_USER_PROMPT_FIELD',
    'userPrompt.RAG_EVIDENCE.RAG_AUTHORIZATION_REASON',
    'RAG EVIDENCE',
    'RagAuthorizationReason',
    'RAG_AUTH_REASON_REQUIRED',
    'MUST_MATCH_FINAL_USER_PROMPT_OR_DECLARED_POLICY',
    'RAG_DOCUMENTS_RETRIEVED',
    true,
    current_timestamp,
    'LLM_DECISION_CONTRACT',
    'RAP,COR,CCR,PFR,MTR',
    'RAG_CONTEXT_PRODUCER',
    null,
    'prompt',
    'prompt.line',
    'java.lang.String'
),
(
    'final_user_prompt_field:RAG_EVIDENCE.RAG_DOCUMENT_SCOPE_REASON',
    'FINAL_USER_PROMPT_FIELD',
    'userPrompt.RAG_EVIDENCE.RAG_DOCUMENT_SCOPE_REASON',
    'RAG EVIDENCE',
    'RagDocumentScopeReason',
    'RAG_DOC_SCOPE_REASON_REQUIRED',
    'MUST_MATCH_FINAL_USER_PROMPT_OR_DECLARED_POLICY',
    'RAG_DOCUMENTS_RETRIEVED',
    true,
    current_timestamp,
    'LLM_DECISION_CONTRACT',
    'RAP,COR,CCR,PFR,MTR',
    'RAG_CONTEXT_PRODUCER',
    null,
    'prompt',
    'prompt.line',
    'java.lang.String'
),
(
    'final_user_prompt_field:RAG_EVIDENCE.RAG_DOCUMENT_AUTHORIZATION_REASON',
    'FINAL_USER_PROMPT_FIELD',
    'userPrompt.RAG_EVIDENCE.RAG_DOCUMENT_AUTHORIZATION_REASON',
    'RAG EVIDENCE',
    'RagDocumentAuthorizationReason',
    'RAG_DOC_AUTH_REASON_REQUIRED',
    'MUST_MATCH_FINAL_USER_PROMPT_OR_DECLARED_POLICY',
    'RAG_DOCUMENTS_RETRIEVED',
    true,
    current_timestamp,
    'LLM_DECISION_CONTRACT',
    'RAP,COR,CCR,PFR,MTR',
    'RAG_CONTEXT_PRODUCER',
    null,
    'prompt',
    'prompt.line',
    'java.lang.String'
)
on conflict (field_key) do update
   set source_model = excluded.source_model,
       source_field_path = excluded.source_field_path,
       prompt_section = excluded.prompt_section,
       prompt_label = excluded.prompt_label,
       required_policy = excluded.required_policy,
       projection_policy = excluded.projection_policy,
       applicability_rule = excluded.applicability_rule,
       is_active = true,
       quality_relevance = excluded.quality_relevance,
       metric_codes = excluded.metric_codes,
       remediation_owner = excluded.remediation_owner,
       not_applicable_rule = excluded.not_applicable_rule,
       source_package = excluded.source_package,
       source_class = excluded.source_class,
       value_type = excluded.value_type;

-- ------------------------------------------------------------
-- Source migration: V20260606_01__pqa_rag_reason_contract_repair.sql
-- ------------------------------------------------------------
update official_prompt_field_definition
   set required_policy = case field_key
           when 'final_user_prompt_field:RAG_EVIDENCE.RAG_SCOPE_REASON' then 'RAG_SCOPE_REASON_REQUIRED'
           when 'final_user_prompt_field:RAG_EVIDENCE.RAG_AUTHORIZATION_REASON' then 'RAG_AUTH_REASON_REQUIRED'
           when 'final_user_prompt_field:RAG_EVIDENCE.RAG_DOCUMENT_SCOPE_REASON' then 'RAG_DOC_SCOPE_REASON_REQUIRED'
           when 'final_user_prompt_field:RAG_EVIDENCE.RAG_DOCUMENT_AUTHORIZATION_REASON' then 'RAG_DOC_AUTH_REASON_REQUIRED'
           else required_policy
       end,
       projection_policy = 'MUST_MATCH_FINAL_USER_PROMPT_OR_DECLARED_POLICY',
       applicability_rule = 'RAG_DOCUMENTS_RETRIEVED',
       quality_relevance = 'LLM_DECISION_CONTRACT',
       metric_codes = 'RAP,COR,CCR,PFR,MTR',
       remediation_owner = 'RAG_CONTEXT_PRODUCER',
       source_model = 'FINAL_USER_PROMPT_FIELD',
       source_package = 'prompt',
       source_class = 'prompt.line',
       value_type = 'java.lang.String',
       is_active = true
 where field_key in (
       'final_user_prompt_field:RAG_EVIDENCE.RAG_SCOPE_REASON',
       'final_user_prompt_field:RAG_EVIDENCE.RAG_AUTHORIZATION_REASON',
       'final_user_prompt_field:RAG_EVIDENCE.RAG_DOCUMENT_SCOPE_REASON',
       'final_user_prompt_field:RAG_EVIDENCE.RAG_DOCUMENT_AUTHORIZATION_REASON'
 );

update official_prompt_field_definition
   set required_policy = case field_key
           when 'raw_user_prompt_field:RAG_EVIDENCE.RAG_SCOPE_REASON' then 'RAG_SCOPE_REASON_REQUIRED'
           when 'raw_user_prompt_field:RAG_EVIDENCE.RAG_AUTHORIZATION_REASON' then 'RAG_AUTH_REASON_REQUIRED'
           when 'raw_user_prompt_field:RAG_EVIDENCE.RAG_DOCUMENT_SCOPE_REASON' then 'RAG_DOC_SCOPE_REASON_REQUIRED'
           when 'raw_user_prompt_field:RAG_EVIDENCE.RAG_DOCUMENT_AUTHORIZATION_REASON' then 'RAG_DOC_AUTH_REASON_REQUIRED'
           else required_policy
       end,
       projection_policy = 'MUST_MATCH_FINAL_USER_PROMPT_OR_DECLARED_POLICY',
       applicability_rule = 'RAG_DOCUMENTS_RETRIEVED',
       quality_relevance = 'LLM_DECISION_CONTRACT',
       metric_codes = 'RAP,COR,CCR,PFR,MTR',
       remediation_owner = 'RAG_CONTEXT_PRODUCER',
       source_model = 'RAW_USER_PROMPT_FIELD',
       source_package = 'prompt',
       source_class = 'prompt.line',
       value_type = 'java.lang.String',
       is_active = true
 where field_key in (
       'raw_user_prompt_field:RAG_EVIDENCE.RAG_SCOPE_REASON',
       'raw_user_prompt_field:RAG_EVIDENCE.RAG_AUTHORIZATION_REASON',
       'raw_user_prompt_field:RAG_EVIDENCE.RAG_DOCUMENT_SCOPE_REASON',
       'raw_user_prompt_field:RAG_EVIDENCE.RAG_DOCUMENT_AUTHORIZATION_REASON'
 );

create index idx_soar_approval_vote_decision
    on soar_approval_votes (decision);

