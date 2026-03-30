create table public.users
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

alter table public.users
    owner to contexa;

create index idx_users_email
    on public.users (email);

create index idx_users_department
    on public.users (department);

create index idx_users_enabled
    on public.users (enabled);

create table public.app_group
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

alter table public.app_group
    owner to contexa;

create table public.role
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

alter table public.role
    owner to contexa;

create table public.managed_resource
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

alter table public.managed_resource
    owner to contexa;

create table public.permission
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
                                                                references public.managed_resource
                                                                    on delete set null,
    created_at           timestamp(6) default CURRENT_TIMESTAMP not null,
    updated_at           timestamp(6)
);

alter table public.permission
    owner to contexa;

create table public.user_groups
(
    user_id     bigint                                 not null
        references public.users
            on delete cascade,
    group_id    bigint                                 not null
        references public.app_group
            on delete cascade,
    assigned_at timestamp(6) default CURRENT_TIMESTAMP not null,
    assigned_by varchar(100),
    primary key (user_id, group_id)
);

alter table public.user_groups
    owner to contexa;

create table public.group_roles
(
    group_id    bigint                                 not null
        references public.app_group
            on delete cascade,
    role_id     bigint                                 not null
        references public.role
            on delete cascade,
    assigned_at timestamp(6) default CURRENT_TIMESTAMP not null,
    assigned_by varchar(100),
    primary key (group_id, role_id)
);

alter table public.group_roles
    owner to contexa;

create table public.role_permissions
(
    role_id       bigint                                 not null
        references public.role
            on delete cascade,
    permission_id bigint                                 not null
        references public.permission
            on delete cascade,
    assigned_at   timestamp(6) default CURRENT_TIMESTAMP not null,
    assigned_by   varchar(100),
    primary key (role_id, permission_id)
);

alter table public.role_permissions
    owner to contexa;

create table public.policy
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
                   ((ARRAY ['PENDING'::character varying, 'APPROVED'::character varying, 'REJECTED'::character varying, 'NOT_REQUIRED'::character varying])::text[])),
    approved_at          timestamp(6),
    approved_by          varchar(255),
    confidence_score     double precision,
    source               varchar(50)
        constraint policy_source_check
            check ((source)::text = ANY
                   ((ARRAY ['MANUAL'::character varying, 'AI_GENERATED'::character varying, 'AI_EVOLVED'::character varying, 'IMPORTED'::character varying])::text[])),
    updated_at           timestamp(6),
    created_at           timestamp(6) default CURRENT_TIMESTAMP not null,
    is_active            boolean      default true              not null,
    reasoning            varchar(4096)
);

alter table public.policy
    owner to contexa;

create table public.policy_target
(
    id                bigserial
        primary key,
    policy_id         bigint                not null
        references public.policy
            on delete cascade,
    target_type       varchar(255)          not null,
    target_identifier varchar(255)          not null,
    http_method       varchar(255),
    target_order      integer     default 0 not null,
    source_type       varchar(20) default 'RESOURCE'::character varying
);

alter table public.policy_target
    owner to contexa;

create table public.policy_rule
(
    id          bigserial
        primary key,
    policy_id   bigint not null
        references public.policy
            on delete cascade,
    description varchar(255)
);

alter table public.policy_rule
    owner to contexa;

create table public.policy_condition
(
    id                   bigserial
        primary key,
    rule_id              bigint                                                  not null
        references public.policy_rule
            on delete cascade,
    condition_expression varchar(2048)                                           not null,
    authorization_phase  varchar(255) default 'PRE_AUTHORIZE'::character varying not null,
    description          varchar(255)
);

alter table public.policy_condition
    owner to contexa;

create table public.role_hierarchy_config
(
    hierarchy_id     bigserial
        primary key,
    description      varchar(255),
    hierarchy_string text                  not null
        unique,
    is_active        boolean default false not null
);

alter table public.role_hierarchy_config
    owner to contexa;

create table public.audit_log
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

alter table public.audit_log
    owner to contexa;

create table public.business_resource
(
    id            bigserial
        primary key,
    name          varchar(255) not null
        unique,
    resource_type varchar(100) not null,
    description   varchar(1024)
);

alter table public.business_resource
    owner to contexa;

create table public.business_action
(
    id          bigserial
        primary key,
    name        varchar(255) not null
        unique,
    action_type varchar(100) not null,
    description varchar(1024)
);

alter table public.business_action
    owner to contexa;

create table public.business_resource_action
(
    business_resource_id   bigint       not null
        references public.business_resource
            on delete cascade,
    business_action_id     bigint       not null
        references public.business_action
            on delete cascade,
    mapped_permission_name varchar(255) not null,
    primary key (business_resource_id, business_action_id)
);

alter table public.business_resource_action
    owner to contexa;

create table public.condition_template
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
                   ((ARRAY ['UNIVERSAL'::character varying, 'CONTEXT_DEPENDENT'::character varying, 'CUSTOM_COMPLEX'::character varying])::text[])),
    complexity_score     integer,
    context_dependent    boolean
);

alter table public.condition_template
    owner to contexa;

create table public.wizard_session
(
    session_id    varchar(36)  not null
        primary key,
    context_data  text         not null,
    owner_user_id varchar(255) not null,
    created_at    timestamp(6) not null,
    expires_at    timestamp(6) not null
);

alter table public.wizard_session
    owner to contexa;

create table public.function_group
(
    id   bigserial
        primary key,
    name varchar(255) not null
        unique
);

alter table public.function_group
    owner to contexa;

create table public.function_catalog
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
        references public.function_group,
    managed_resource_id bigint       not null
        unique
        references public.managed_resource
);

alter table public.function_catalog
    owner to contexa;

create table public.policy_template
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

alter table public.policy_template
    owner to contexa;

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

create table public.user_behavior_profiles
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

alter table public.user_behavior_profiles
    owner to contexa;

create table public.soar_incidents
(
    id          uuid         not null
        primary key,
    created_at  timestamp(6) not null,
    history     text,
    severity    varchar(20),
    status      varchar(255) not null
        constraint soar_incidents_status_check
            check ((status)::text = ANY
                   ((ARRAY ['NEW'::character varying, 'TRIAGE'::character varying, 'INVESTIGATION'::character varying, 'PLANNING'::character varying, 'PENDING_APPROVAL'::character varying, 'EXECUTION'::character varying, 'REPORTING'::character varying, 'COMPLETED'::character varying, 'AUTO_CLOSED'::character varying, 'FAILED'::character varying, 'CLOSED_BY_ADMIN'::character varying])::text[])),
    title       varchar(255) not null,
    updated_at  timestamp(6) not null,
    description text,
    incident_id varchar(100),
    metadata    text,
    type        varchar(50)
);

alter table public.soar_incidents
    owner to contexa;

create table public.soar_approval_policies
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

alter table public.soar_approval_policies
    owner to contexa;

create table public.soar_approval_requests
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

alter table public.soar_approval_requests
    owner to contexa;

create table public.soar_approval_steps
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

alter table public.soar_approval_steps
    owner to contexa;

create index idx_soar_approval_step_request_id
    on public.soar_approval_steps (request_id);

create index idx_soar_approval_step_status
    on public.soar_approval_steps (status);

create table public.soar_approval_assignments
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

alter table public.soar_approval_assignments
    owner to contexa;

create index idx_soar_approval_assignment_request_id
    on public.soar_approval_assignments (request_id);

create index idx_soar_approval_assignment_status
    on public.soar_approval_assignments (status);

create index idx_soar_approval_assignment_step
    on public.soar_approval_assignments (request_id, step_number);

create table public.soar_approval_votes
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

create table public.approval_notifications
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

create table public.threat_indicators
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
                   ((ARRAY ['ACTIVE'::character varying, 'INACTIVE'::character varying, 'EXPIRED'::character varying, 'FALSE_POSITIVE'::character varying, 'UNDER_REVIEW'::character varying])::text[])),
    threat_actor         varchar(255),
    threat_actor_id      varchar(100),
    threat_score         double precision,
    indicator_type       varchar(255)  not null
        constraint threat_indicators_indicator_type_check
            check ((indicator_type)::text = ANY
                   ((ARRAY ['IP_ADDRESS'::character varying, 'DOMAIN'::character varying, 'URL'::character varying, 'FILE_HASH'::character varying, 'FILE_PATH'::character varying, 'REGISTRY_KEY'::character varying, 'PROCESS_NAME'::character varying, 'EMAIL_ADDRESS'::character varying, 'USER_AGENT'::character varying, 'CERTIFICATE'::character varying, 'MUTEX'::character varying, 'YARA_RULE'::character varying, 'BEHAVIORAL'::character varying, 'UNKNOWN'::character varying, 'PATTERN'::character varying, 'USER_ACCOUNT'::character varying, 'COMPLIANCE'::character varying, 'EVENT'::character varying])::text[])),
    updated_at           timestamp(6),
    indicator_value      varchar(1024) not null
);

alter table public.threat_indicators
    owner to contexa;

create table public.indicator_metadata
(
    indicator_id varchar(100) not null
        references public.threat_indicators,
    meta_value   varchar(255),
    meta_key     varchar(255) not null,
    primary key (indicator_id, meta_key)
);

alter table public.indicator_metadata
    owner to contexa;

create table public.indicator_tags
(
    indicator_id varchar(100) not null
        references public.threat_indicators,
    tag          varchar(255)
);

alter table public.indicator_tags
    owner to contexa;

create table public.related_indicators
(
    indicator_id         varchar(100) not null
        references public.threat_indicators,
    related_indicator_id varchar(100) not null
        references public.threat_indicators,
    primary key (indicator_id, related_indicator_id)
);

alter table public.related_indicators
    owner to contexa;

create table public.blocked_user
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

alter table public.blocked_user
    owner to contexa;

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
    client_name            varchar(100)                                     not null
        primary key,
    enabled                boolean     default true not null,
    health_status          varchar(30) default 'UNKNOWN'::character varying not null,
    health_message         varchar(500),
    last_health_checked_at timestamp(6),
    updated_at             timestamp(6)                                     not null
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
    metadata_json  text
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

create table public.baseline_signal_outbox
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

alter table public.baseline_signal_outbox
    owner to contexa;

create index idx_baseline_signal_outbox_dispatch
    on public.baseline_signal_outbox (status, next_attempt_at, period_start);

create table public.decision_feedback_forwarding_outbox
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

alter table public.decision_feedback_forwarding_outbox
    owner to contexa;

create index idx_decision_feedback_forwarding_outbox_dispatch
    on public.decision_feedback_forwarding_outbox (status, next_attempt_at, created_at);

create table public.model_performance_telemetry_outbox
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

alter table public.model_performance_telemetry_outbox
    owner to contexa;

create index idx_model_performance_telemetry_outbox_dispatch
    on public.model_performance_telemetry_outbox (status, next_attempt_at, period);

create table public.prompt_context_audit_forwarding_outbox
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

alter table public.prompt_context_audit_forwarding_outbox
    owner to contexa;

create index idx_prompt_context_audit_forwarding_outbox_dispatch
    on public.prompt_context_audit_forwarding_outbox (status, next_attempt_at, created_at);

create table public.security_decision_forwarding_outbox
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

alter table public.security_decision_forwarding_outbox
    owner to contexa;

create index idx_security_decision_forwarding_outbox_dispatch
    on public.security_decision_forwarding_outbox (status, next_attempt_at, created_at);

create table public.threat_outcome_forwarding_outbox
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

alter table public.threat_outcome_forwarding_outbox
    owner to contexa;

create index idx_threat_outcome_forwarding_outbox_dispatch
    on public.threat_outcome_forwarding_outbox (status, next_attempt_at, created_at);

create table public.user_roles
(
    role_id     bigint       not null
        constraint fkrhfovtciq1l558cw6udg0h0d3
            references public.role,
    user_id     bigint       not null
        constraint fkhfh9dx7w3ubf1co1vdev94g3f
            references public.users,
    assigned_at timestamp(6) not null,
    assigned_by varchar(100),
    primary key (role_id, user_id)
);

alter table public.user_roles
    owner to contexa;

create table public.password_policy
(
    id                       bigint generated by default as identity
        primary key,
    created_at               timestamp(6) not null,
    history_count            integer      not null,
    lockout_duration_minutes integer      not null,
    max_failed_attempts      integer      not null,
    max_length               integer      not null,
    min_length               integer      not null,
    password_expiry_days     integer      not null,
    require_digit            boolean      not null,
    require_lowercase        boolean      not null,
    require_special_char     boolean      not null,
    require_uppercase        boolean      not null,
    updated_at               timestamp(6)
);

alter table public.password_policy
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

create table public.bridge_user_profile
(
    user_id                     bigint       not null
        primary key
        constraint fk6ln576ijwr4i3kdbqmfjyedeo
            references public.users,
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

alter table public.bridge_user_profile
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

create table public.active_sessions
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

alter table public.active_sessions
    owner to contexa;

create index idx_session_user_id
    on public.active_sessions (user_id);

create index idx_session_expired
    on public.active_sessions (expired);

create table public.ip_access_rules
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
            check ((rule_type)::text = ANY ((ARRAY ['ALLOW'::character varying, 'DENY'::character varying])::text[]))
);

alter table public.ip_access_rules
    owner to contexa;

create index idx_ip_rule_type
    on public.ip_access_rules (rule_type);

create index idx_ip_rule_enabled
    on public.ip_access_rules (enabled);

create index idx_ip_address
    on public.ip_access_rules (ip_address);

create table public.security_spel
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

alter table public.security_spel
    owner to contexa;

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

