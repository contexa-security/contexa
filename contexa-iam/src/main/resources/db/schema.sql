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
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    auto_created         boolean      default false             not null,
    created_at           timestamp(6) default CURRENT_TIMESTAMP not null,
    updated_at           timestamp(6)
);

alter table public.permission
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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

alter table public.policy
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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
                   (ARRAY [('UNIVERSAL'::character varying)::text, ('CONTEXT_DEPENDENT'::character varying)::text, ('CUSTOM_COMPLEX'::character varying)::text])),
    complexity_score     integer,
    context_dependent    boolean
);

alter table public.condition_template
    owner to contexa_sim;

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
    owner to contexa_sim;

create table public.function_group
(
    id   bigserial
        primary key,
    name varchar(255) not null
        unique
);

alter table public.function_group
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

create table public.vector_store
(
    id        uuid default gen_random_uuid() not null
        primary key,
    content   text                           not null,
    metadata  jsonb,
    embedding vector(1024)
);

alter table public.vector_store
    owner to contexa_sim;

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
    owner to contexa_sim;

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
                   (ARRAY [('NEW'::character varying)::text, ('TRIAGE'::character varying)::text, ('INVESTIGATION'::character varying)::text, ('PLANNING'::character varying)::text, ('PENDING_APPROVAL'::character varying)::text, ('EXECUTION'::character varying)::text, ('REPORTING'::character varying)::text, ('COMPLETED'::character varying)::text, ('AUTO_CLOSED'::character varying)::text, ('FAILED'::character varying)::text, ('CLOSED_BY_ADMIN'::character varying)::text])),
    title       varchar(255) not null,
    updated_at  timestamp(6) not null,
    description text,
    incident_id varchar(100),
    metadata    text,
    type        varchar(50)
);

alter table public.soar_incidents
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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

alter table public.threat_indicators
    owner to contexa_sim;

create table public.indicator_metadata
(
    indicator_id varchar(100) not null
        references public.threat_indicators,
    meta_value   varchar(255),
    meta_key     varchar(255) not null,
    primary key (indicator_id, meta_key)
);

alter table public.indicator_metadata
    owner to contexa_sim;

create table public.indicator_tags
(
    indicator_id varchar(100) not null
        references public.threat_indicators,
    tag          varchar(255)
);

alter table public.indicator_tags
    owner to contexa_sim;

create table public.related_indicators
(
    indicator_id         varchar(100) not null
        references public.threat_indicators,
    related_indicator_id varchar(100) not null
        references public.threat_indicators,
    primary key (indicator_id, related_indicator_id)
);

alter table public.related_indicators
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

create table public.user_entities
(
    id           varchar(1000) not null
        primary key,
    name         varchar(100)  not null,
    display_name varchar(200)
);

alter table public.user_entities
    owner to contexa_sim;

create table public.one_time_tokens
(
    token_value varchar(36) not null
        primary key,
    username    varchar(50) not null,
    expires_at  timestamp   not null
);

alter table public.one_time_tokens
    owner to contexa_sim;

create table public.oauth2_authorization_consent
(
    registered_client_id varchar(100)  not null
        references public.oauth2_registered_client,
    principal_name       varchar(200)  not null,
    authorities          varchar(1000) not null,
    primary key (registered_client_id, principal_name)
);

alter table public.oauth2_authorization_consent
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

create table public.password_policy
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

alter table public.password_policy
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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
            check ((rule_type)::text = ANY
                   (ARRAY [('ALLOW'::character varying)::text, ('DENY'::character varying)::text]))
);

alter table public.ip_access_rules
    owner to contexa_sim;

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
    owner to contexa_sim;

create table public.admin_menu
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

alter table public.admin_menu
    owner to contexa_sim;

create unique index ux_admin_menu_data_page
    on public.admin_menu (data_page)
    where (data_page IS NOT NULL);

create table public.admin_menu_role
(
    id        bigserial
        primary key,
    menu_id   bigint       not null
        references public.admin_menu,
    role_name varchar(100) not null,
    unique (menu_id, role_name)
);

alter table public.admin_menu_role
    owner to contexa_sim;

create table public.group_role_permissions
(
    group_id      bigint       not null
        references public.app_group,
    role_id       bigint       not null
        references public.role,
    permission_id bigint       not null
        references public.permission,
    assigned_at   timestamp(6) not null,
    assigned_by   varchar(100),
    primary key (group_id, role_id, permission_id)
);

alter table public.group_role_permissions
    owner to contexa_sim;

create table public.user_role_permissions
(
    user_id       bigint       not null
        references public.users,
    role_id       bigint       not null
        references public.role,
    permission_id bigint       not null
        references public.permission,
    assigned_at   timestamp(6) not null,
    assigned_by   varchar(100),
    primary key (user_id, role_id, permission_id)
);

alter table public.user_role_permissions
    owner to contexa_sim;

create table public.password_history
(
    id            bigserial
        primary key,
    user_id       bigint       not null,
    password_hash varchar(512) not null,
    changed_at    timestamp(6) not null
);

alter table public.password_history
    owner to contexa_sim;

create table public.policy_version
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

alter table public.policy_version
    owner to contexa_sim;

create index idx_policy_version_changed_at
    on public.policy_version (changed_at);

create index idx_policy_version_policy_id
    on public.policy_version (policy_id);

create table public.system_settings
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

alter table public.system_settings
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

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
    owner to contexa_sim;

create index idx_learning_governance_snapshot_tenant_updated
    on public.learning_governance_snapshot (tenant_id, updated_at);

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
    owner to contexa_sim;

create index idx_login_attempt_ip_window
    on public.login_attempt_ip (window_start_at);

create table public.shedlock
(
    name       varchar(64)  not null
        primary key,
    lock_until timestamp    not null,
    locked_at  timestamp    not null,
    locked_by  varchar(255) not null
);

alter table public.shedlock
    owner to contexa_sim;

