create table public.users
(
    id                     bigserial
        primary key,
    username               varchar(255)          not null
        unique,
    password               varchar(255)          not null,
    name                   varchar(255)          not null,
    mfa_enabled            boolean default false not null,
    last_mfa_used_at       timestamp,
    enabled                boolean default true  not null,
    last_used_mfa_factor   varchar(255),
    preferred_mfa_factor   varchar(255),
    registered_mfa_factors varchar(255)[],
    created_at             timestamp(6),
    updated_at             timestamp(6),
    roles                  varchar(255)
);

alter table public.users
    owner to admin;

create table public.app_group
(
    group_id    bigserial
        primary key,
    group_name  varchar(255) not null
        unique,
    description varchar(255)
);

alter table public.app_group
    owner to admin;

create table public.role
(
    role_id       bigserial
        primary key,
    role_name     varchar(255) not null
        unique,
    role_desc     varchar(255),
    is_expression varchar(255) default 'N'::character varying
);

alter table public.role
    owner to admin;

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
    parameter_types             varchar(255),
    return_type                 varchar(255),
    api_docs_url                varchar(255),
    source_code_location        varchar(255),
    status                      varchar(255) default 'NEEDS_DEFINITION'::character varying not null,
    created_at                  timestamp    default CURRENT_TIMESTAMP                     not null,
    updated_at                  timestamp    default CURRENT_TIMESTAMP                     not null,
    available_context_variables varchar(1024)
);

alter table public.managed_resource
    owner to admin;

create table public.permission
(
    permission_id        bigserial
        primary key,
    permission_name      varchar(255) not null
        unique,
    friendly_name        varchar(255),
    description          varchar(1024),
    target_type          varchar(255),
    action_type          varchar(255),
    condition_expression varchar(2048),
    managed_resource_id  bigint
        unique
                                      references public.managed_resource
                                          on delete set null
);

alter table public.permission
    owner to admin;

create table public.user_groups
(
    user_id  bigint not null
        references public.users
            on delete cascade,
    group_id bigint not null
        references public.app_group
            on delete cascade,
    primary key (user_id, group_id)
);

alter table public.user_groups
    owner to admin;

create table public.group_roles
(
    group_id bigint not null
        references public.app_group
            on delete cascade,
    role_id  bigint not null
        references public.role
            on delete cascade,
    primary key (group_id, role_id)
);

alter table public.group_roles
    owner to admin;

create table public.role_permissions
(
    role_id       bigint not null
        references public.role
            on delete cascade,
    permission_id bigint not null
        references public.permission
            on delete cascade,
    primary key (role_id, permission_id)
);

alter table public.role_permissions
    owner to admin;

create table public.policy
(
    id                   bigserial
        primary key,
    name                 varchar(255) not null
        unique,
    description          varchar(255),
    effect               varchar(255) not null,
    priority             integer      not null,
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
    created_at           timestamp    not null,
    is_active            boolean
);

alter table public.policy
    owner to admin;

create table public.policy_target
(
    id                bigserial
        primary key,
    policy_id         bigint       not null
        references public.policy
            on delete cascade,
    target_type       varchar(255) not null,
    target_identifier varchar(255) not null,
    http_method       varchar(255)
);

alter table public.policy_target
    owner to admin;

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
    owner to admin;

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
    owner to admin;

create table public.role_hierarchy_config
(
    id               bigserial
        primary key,
    description      varchar(255),
    hierarchy_string text                  not null,
    is_active        boolean default false not null,
    hierarchy_id     bigint generated by default as identity
);

alter table public.role_hierarchy_config
    owner to admin;

create table public.audit_log
(
    id                  bigserial
        primary key,
    timestamp           timestamp default CURRENT_TIMESTAMP not null,
    principal_name      varchar(255)                        not null,
    resource_identifier varchar(512)                        not null,
    action              varchar(255),
    decision            varchar(255)                        not null,
    reason              varchar(1024),
    client_ip           varchar(255),
    details             text,
    outcome             varchar(255),
    resource_uri        varchar(1024),
    parameters          varchar(255),
    session_id          varchar(255),
    status              varchar(255)
);

alter table public.audit_log
    owner to admin;

create table public.business_resource
(
    id            bigserial
        primary key,
    name          varchar(255) not null
        unique,
    resource_type varchar(255) not null,
    description   varchar(1024)
);

alter table public.business_resource
    owner to admin;

create table public.business_action
(
    id          bigserial
        primary key,
    name        varchar(255) not null
        unique,
    action_type varchar(255) not null,
    description varchar(1024)
);

alter table public.business_action
    owner to admin;

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
    owner to admin;

create table public.condition_template
(
    id                         bigserial
        primary key,
    name                       varchar(255)      not null
        unique,
    spel_template              varchar(2048)     not null,
    category                   varchar(255),
    parameter_count            integer default 0 not null,
    description                varchar(1024),
    required_context_variables varchar(1024),
    parameter_metadata         jsonb,
    required_target_type       varchar(1024),
    created_at                 timestamp(6),
    is_auto_generated          boolean,
    is_universal               boolean,
    source_method              varchar(255),
    template_type              varchar(255),
    updated_at                 timestamp(6),
    approval_required          boolean,
    classification             varchar(255)
        constraint condition_template_classification_check
            check ((classification)::text = ANY
                   ((ARRAY ['UNIVERSAL'::character varying, 'CONTEXT_DEPENDENT'::character varying, 'CUSTOM_COMPLEX'::character varying])::text[])),
    complexity_score           integer,
    context_dependent          boolean,
    risk_level                 varchar(255)
        constraint condition_template_risk_level_check
            check ((risk_level)::text = ANY
                   ((ARRAY ['LOW'::character varying, 'MEDIUM'::character varying, 'HIGH'::character varying])::text[]))
);

alter table public.condition_template
    owner to admin;

create table public.wizard_session
(
    session_id    varchar(36)  not null
        primary key,
    context_data  text         not null,
    owner_user_id varchar(255) not null,
    created_at    timestamp    not null,
    expires_at    timestamp    not null
);

alter table public.wizard_session
    owner to admin;

create table public.document
(
    document_id    bigserial
        primary key,
    title          varchar(255)                        not null,
    content        text,
    owner_username varchar(255)                        not null,
    created_at     timestamp default CURRENT_TIMESTAMP not null,
    updated_at     timestamp
);

alter table public.document
    owner to admin;

create table public.function_group
(
    id   bigint generated by default as identity
        primary key,
    name varchar(255) not null
        constraint uk2g3eo8mfkcu5ejl7oa9l0xkgd
            unique
);

alter table public.function_group
    owner to admin;

create table public.function_catalog
(
    id                  bigint generated by default as identity
        primary key,
    description         varchar(1024),
    friendly_name       varchar(255) not null,
    status              varchar(255) not null
        constraint function_catalog_status_check
            check ((status)::text = ANY
                   ((ARRAY ['UNCONFIRMED'::character varying, 'ACTIVE'::character varying, 'INACTIVE'::character varying])::text[])),
    function_group_id   bigint
        constraint fkq7oc3xf6h5751ujccfwra52de
            references public.function_group,
    managed_resource_id bigint       not null
        constraint uk1gc7v1ph0re3caqe1rr6x2bqe
            unique
        constraint fklgnitp52iu5y28w8oslepyb1e
            references public.managed_resource
);

alter table public.function_catalog
    owner to admin;

create table public.policy_template
(
    id                bigint generated by default as identity
        primary key,
    category          varchar(255),
    description       varchar(1024),
    name              varchar(255) not null,
    policy_draft_json jsonb        not null,
    template_id       varchar(255) not null
        constraint ukbudcfqmqypbf160uukp83no3d
            unique
);

alter table public.policy_template
    owner to admin;

create table public.vector_store
(
    id        uuid default gen_random_uuid() not null
        constraint iam_vectors_pkey
            primary key,
    content   text                           not null,
    metadata  jsonb,
    embedding vector(1024)
);

alter table public.vector_store
    owner to admin;

create index iam_vectors_embedding_idx
    on public.vector_store using hnsw (embedding public.vector_cosine_ops);

create index spring_ai_vector_index
    on public.vector_store using hnsw (embedding public.vector_cosine_ops);

create index embedding_hnsw_idx
    on public.vector_store using hnsw (embedding public.vector_cosine_ops);

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
    owner to admin;

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
    owner to admin;

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
    owner to admin;

create table public.user_behavior_profiles
(
    id                      bigint generated by default as identity
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
    vector_cluster_id       varchar(255)
);

alter table public.user_behavior_profiles
    owner to admin;

create table public.soar_execution_plans
(
    plan_id         varchar(255)  not null
        primary key,
    created_at      timestamp(6)  not null,
    reason          varchar(1000) not null,
    status          varchar(255)  not null
        constraint soar_execution_plans_status_check
            check ((status)::text = ANY
                   ((ARRAY ['PENDING_APPROVAL'::character varying, 'APPROVED'::character varying, 'REJECTED'::character varying, 'EXECUTED_SUCCESS'::character varying, 'EXECUTED_PARTIAL_SUCCESS'::character varying, 'EXECUTED_FAILURE'::character varying])::text[])),
    tool_calls_json text          not null,
    updated_at      timestamp(6)
);

alter table public.soar_execution_plans
    owner to admin;

create table public.soar_playbook_context
(
    instance_id        uuid         not null
        primary key,
    current_state_name varchar(255) not null,
    data               text,
    playbook_id        varchar(255) not null,
    playbook_version   varchar(255) not null
);

alter table public.soar_playbook_context
    owner to admin;

create table public.soar_incidents
(
    id                  uuid         not null
        primary key,
    created_at          timestamp(6) not null,
    history             text,
    severity            varchar(255),
    status              varchar(255) not null
        constraint soar_incidents_status_check
            check ((status)::text = ANY
                   ((ARRAY ['NEW'::character varying, 'TRIAGE'::character varying, 'INVESTIGATION'::character varying, 'PLANNING'::character varying, 'PENDING_APPROVAL'::character varying, 'EXECUTION'::character varying, 'REPORTING'::character varying, 'COMPLETED'::character varying, 'AUTO_CLOSED'::character varying, 'FAILED'::character varying, 'CLOSED_BY_ADMIN'::character varying])::text[])),
    title               varchar(255) not null,
    updated_at          timestamp(6) not null,
    playbook_context_id uuid
        constraint ukmsngu83d34nmqokotdvofotmf
            unique
        constraint fk594sfdey19u7lhb0xdqyidq9
            references public.soar_playbook_context,
    description         text,
    incident_id         varchar(255),
    metadata            text,
    type                varchar(255)
);

alter table public.soar_incidents
    owner to admin;

create table public.soar_approval_policies
(
    id                      bigint generated by default as identity
        primary key,
    action_name             varchar(255),
    auto_approve_on_timeout boolean      not null,
    policy_name             varchar(255) not null
        constraint uk9kpc008gu6g8pc1lr76iakhjl
            unique,
    required_approvers      integer      not null,
    required_roles          text,
    severity                varchar(255),
    timeout_minutes         integer      not null
);

alter table public.soar_approval_policies
    owner to admin;

create table public.soar_approval_requests
(
    id                   bigint generated by default as identity
        primary key,
    action_name          varchar(255) not null,
    created_at           timestamp(6) not null,
    description          oid,
    organization_id      varchar(255),
    parameters           text,
    playbook_instance_id varchar(255) not null,
    required_approvers   integer,
    required_roles       text,
    reviewer_comment     oid,
    reviewer_id          varchar(255),
    status               varchar(255) not null,
    updated_at           timestamp(6) not null,
    request_id           varchar(255) not null
        constraint ukpihdj0vlwd3ya4deserflnfm9
            unique,
    action_type          varchar(255),
    approval_comment     oid,
    approval_timeout     integer,
    approval_type        varchar(255),
    approved_at          timestamp(6),
    approved_by          varchar(255),
    incident_id          varchar(255),
    requested_by         varchar(255),
    risk_level           varchar(255),
    session_id           varchar(255),
    tool_name            varchar(255)
);

alter table public.soar_approval_requests
    owner to admin;

create table public.approval_notifications
(
    id                bigint generated by default as identity
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
    owner to admin;

create index idx_notification_request_id
    on public.approval_notifications (request_id);

create index idx_notification_user_id
    on public.approval_notifications (user_id);

create index idx_notification_is_read
    on public.approval_notifications (is_read);

create index idx_notification_created_at
    on public.approval_notifications (created_at);

create table public.tool_execution_contexts
(
    id                   bigint generated by default as identity
        primary key,
    available_tools      text,
    chat_options         text,
    chat_response        text,
    created_at           timestamp(6) not null,
    execution_end_time   timestamp(6),
    execution_error      text,
    execution_result     text,
    execution_start_time timestamp(6),
    expires_at           timestamp(6),
    incident_id          varchar(100),
    max_retries          integer,
    metadata             text,
    pipeline_context     text,
    prompt_content       text         not null,
    request_id           varchar(100) not null
        constraint idx_tool_context_request_id
            unique,
    retry_count          integer,
    risk_level           varchar(20),
    session_id           varchar(100),
    soar_context         text,
    status               varchar(20)  not null,
    tool_arguments       text,
    tool_call_id         varchar(255),
    tool_definitions     text,
    tool_name            varchar(255) not null,
    tool_type            varchar(50),
    updated_at           timestamp(6) not null
);

alter table public.tool_execution_contexts
    owner to admin;

create index idx_tool_context_status
    on public.tool_execution_contexts (status);

create index idx_tool_context_created_at
    on public.tool_execution_contexts (created_at);

create table public.security_incidents
(
    incident_id           varchar(50)  not null
        primary key,
    affected_system       varchar(255),
    affected_user         varchar(255),
    approval_request_id   varchar(255),
    auto_response_enabled boolean,
    created_at            timestamp(6) not null,
    description           text,
    destination_ip        varchar(255),
    detected_at           timestamp(6),
    detected_by           varchar(255),
    detection_source      varchar(255),
    escalated_at          timestamp(6),
    event_count           integer,
    last_event_time       timestamp(6),
    mitre_attack_mapping  varchar(255),
    organization_id       varchar(255),
    requires_approval     boolean,
    resolved_at           timestamp(6),
    risk_score            double precision,
    source                varchar(255),
    source_ip             varchar(255),
    incident_status       varchar(255) not null
        constraint security_incidents_incident_status_check
            check ((incident_status)::text = ANY
                   ((ARRAY ['NEW'::character varying, 'INVESTIGATING'::character varying, 'CONFIRMED'::character varying, 'CONTAINED'::character varying, 'ERADICATED'::character varying, 'RECOVERING'::character varying, 'RESOLVED'::character varying, 'CLOSED'::character varying, 'FALSE_POSITIVE'::character varying])::text[])),
    target_ip             varchar(255),
    threat_level          varchar(255) not null
        constraint security_incidents_threat_level_check
            check ((threat_level)::text = ANY
                   ((ARRAY ['CRITICAL'::character varying, 'HIGH'::character varying, 'MEDIUM'::character varying, 'LOW'::character varying, 'INFO'::character varying])::text[])),
    incident_type         varchar(255) not null
        constraint security_incidents_incident_type_check
            check ((incident_type)::text = ANY
                   ((ARRAY ['INTRUSION_ATTEMPT'::character varying, 'MALWARE_DETECTION'::character varying, 'DATA_EXFILTRATION'::character varying, 'UNAUTHORIZED_ACCESS'::character varying, 'PRIVILEGE_ESCALATION'::character varying, 'PHISHING_ATTEMPT'::character varying, 'DOS_ATTACK'::character varying, 'SUSPICIOUS_ACTIVITY'::character varying, 'POLICY_VIOLATION'::character varying, 'CONFIGURATION_CHANGE'::character varying, 'MALWARE'::character varying, 'INTRUSION'::character varying, 'DATA_BREACH'::character varying, 'PHISHING'::character varying, 'OTHER'::character varying])::text[])),
    updated_at            timestamp(6)
);

alter table public.security_incidents
    owner to admin;

create table public.incident_affected_assets
(
    incident_id varchar(50) not null
        constraint fk10jof249j9uoc6rat6qfi9jde
            references public.security_incidents,
    asset_id    varchar(255)
);

alter table public.incident_affected_assets
    owner to admin;

create table public.incident_related_events
(
    incident_id varchar(50) not null
        constraint fkh16gpnxq6c5nye841dhdfyfxc
            references public.security_incidents,
    event_id    varchar(255)
);

alter table public.incident_related_events
    owner to admin;

create table public.incident_tags
(
    incident_id varchar(50) not null
        constraint fk4v2ne4qjw6h5yx9t3adr7e75d
            references public.security_incidents,
    tag         varchar(255)
);

alter table public.incident_tags
    owner to admin;

create table public.security_actions
(
    action_id                varchar(255) not null
        primary key,
    action_type              varchar(255) not null,
    approval_comment         varchar(255),
    approval_request_id      varchar(255),
    approval_status          varchar(255)
        constraint security_actions_approval_status_check
            check ((approval_status)::text = ANY
                   ((ARRAY ['NOT_REQUIRED'::character varying, 'PENDING'::character varying, 'APPROVED'::character varying, 'DENIED'::character varying, 'TIMEOUT'::character varying, 'AUTO_APPROVED'::character varying, 'AUTO_DENIED'::character varying])::text[])),
    approved_at              timestamp(6),
    approved_by              varchar(255),
    approver_id              varchar(255),
    auto_approved            boolean,
    auto_execute             boolean,
    compensation_action_id   varchar(255),
    compensation_executed    boolean,
    compensation_executed_at timestamp(6),
    completed_at             timestamp(6),
    created_at               timestamp(6) not null,
    description              text,
    error_message            text,
    executed_at              timestamp(6),
    execution_duration       bigint,
    execution_duration_ms    bigint,
    execution_order          integer,
    execution_output         text,
    execution_result         varchar(255),
    expires_at               timestamp(6),
    failed_at                timestamp(6),
    is_compensatable         boolean,
    last_retry_at            timestamp(6),
    max_retries              integer,
    parent_action_id         varchar(255),
    priority                 integer,
    requires_approval        boolean,
    result                   text,
    retry_count              integer,
    risk_level               varchar(255) not null
        constraint security_actions_risk_level_check
            check ((risk_level)::text = ANY
                   ((ARRAY ['LOW'::character varying, 'MEDIUM'::character varying, 'HIGH'::character varying, 'CRITICAL'::character varying])::text[])),
    rollbackable             boolean,
    scheduled_at             timestamp(6),
    started_at               timestamp(6),
    action_status            varchar(255) not null
        constraint security_actions_action_status_check
            check ((action_status)::text = ANY
                   ((ARRAY ['PENDING'::character varying, 'AWAITING_APPROVAL'::character varying, 'APPROVED'::character varying, 'REJECTED'::character varying, 'SCHEDULED'::character varying, 'IN_PROGRESS'::character varying, 'COMPLETED'::character varying, 'FAILED'::character varying, 'CANCELLED'::character varying, 'COMPENSATED'::character varying, 'EXECUTING'::character varying, 'UNDONE'::character varying])::text[])),
    updated_at               timestamp(6),
    incident_id              varchar(50)
        constraint fkd44tltp54cr7gb6km5wt6vgf1
            references public.security_incidents
);

alter table public.security_actions
    owner to admin;

create table public.action_audit_log
(
    action_id varchar(255) not null
        constraint fksxh22v9cljn09qidtl5c9dejj
            references public.security_actions,
    log_entry varchar(255)
);

alter table public.action_audit_log
    owner to admin;

create table public.action_parameters
(
    action_id   varchar(255) not null
        constraint fkqfmghcguog6f6gsox7gitwfm0
            references public.security_actions,
    param_value text,
    param_key   varchar(255) not null,
    primary key (action_id, param_key)
);

alter table public.action_parameters
    owner to admin;

create table public.threat_indicators
(
    indicator_id         varchar(255) not null
        primary key,
    active               boolean,
    campaign             varchar(255),
    campaign_id          varchar(255),
    cis_control          varchar(255),
    confidence           double precision,
    created_at           timestamp(6) not null,
    description          text,
    detected_at          timestamp(6),
    detection_count      integer,
    expires_at           timestamp(6),
    false_positive_count integer,
    first_seen           timestamp(6),
    last_seen            timestamp(6),
    malware_family       varchar(255),
    mitre_attack_id      varchar(255),
    mitre_tactic         varchar(255),
    mitre_technique      varchar(255),
    nist_csf_category    varchar(255),
    severity             varchar(255) not null
        constraint threat_indicators_severity_check
            check ((severity)::text = ANY
                   ((ARRAY ['CRITICAL'::character varying, 'HIGH'::character varying, 'MEDIUM'::character varying, 'LOW'::character varying, 'INFO'::character varying])::text[])),
    source               varchar(255),
    status               varchar(255)
        constraint threat_indicators_status_check
            check ((status)::text = ANY
                   ((ARRAY ['ACTIVE'::character varying, 'INACTIVE'::character varying, 'EXPIRED'::character varying, 'FALSE_POSITIVE'::character varying, 'UNDER_REVIEW'::character varying])::text[])),
    threat_actor         varchar(255),
    threat_actor_id      varchar(255),
    threat_score         double precision,
    indicator_type       varchar(255) not null
        constraint threat_indicators_indicator_type_check
            check ((indicator_type)::text = ANY
                   ((ARRAY ['IP_ADDRESS'::character varying, 'DOMAIN'::character varying, 'URL'::character varying, 'FILE_HASH'::character varying, 'FILE_PATH'::character varying, 'REGISTRY_KEY'::character varying, 'PROCESS_NAME'::character varying, 'EMAIL_ADDRESS'::character varying, 'USER_AGENT'::character varying, 'CERTIFICATE'::character varying, 'MUTEX'::character varying, 'YARA_RULE'::character varying, 'BEHAVIORAL'::character varying, 'UNKNOWN'::character varying, 'PATTERN'::character varying, 'USER_ACCOUNT'::character varying, 'COMPLIANCE'::character varying, 'EVENT'::character varying])::text[])),
    updated_at           timestamp(6),
    indicator_value      varchar(255) not null
);

alter table public.threat_indicators
    owner to admin;

create table public.indicator_incidents
(
    indicator_id varchar(255) not null
        constraint fki28885hvl5vmyod9a9u8p59kt
            references public.threat_indicators,
    incident_id  varchar(50)  not null
        constraint fk7dha3wyl562a8rloqvs7tjo3o
            references public.security_incidents,
    primary key (indicator_id, incident_id)
);

alter table public.indicator_incidents
    owner to admin;

create table public.indicator_metadata
(
    indicator_id varchar(255) not null
        constraint fk8woobi3dw4qnun8tmc9ydeh3a
            references public.threat_indicators,
    meta_value   varchar(255),
    meta_key     varchar(255) not null,
    primary key (indicator_id, meta_key)
);

alter table public.indicator_metadata
    owner to admin;

create table public.indicator_tags
(
    indicator_id varchar(255) not null
        constraint fk798h0bhyufds0oabwfaircn82
            references public.threat_indicators,
    tag          varchar(255)
);

alter table public.indicator_tags
    owner to admin;

create table public.related_indicators
(
    indicator_id         varchar(255) not null
        constraint fke955l2l6jjmnhrqktg2xhhqik
            references public.threat_indicators,
    related_indicator_id varchar(255) not null
        constraint fks2jii22s35fvojsokbmq9elij
            references public.threat_indicators,
    primary key (indicator_id, related_indicator_id)
);

alter table public.related_indicators
    owner to admin;

create table public.policy_evolution_proposals
(
    id                 bigint generated by default as identity
        primary key,
    action_payload     jsonb,
    activated_at       timestamp(6),
    activated_by       varchar(100),
    actual_impact      double precision,
    ai_reasoning       text,
    analysis_lab_id    varchar(100),
    approved_at        timestamp(6),
    approved_by        varchar(100),
    confidence_score   double precision,
    created_at         timestamp(6) not null,
    created_by         varchar(100),
    deactivated_at     timestamp(6),
    description        text,
    evidence_context   jsonb,
    expected_impact    double precision,
    expires_at         timestamp(6),
    learning_type      varchar(50)
        constraint policy_evolution_proposals_learning_type_check
            check ((learning_type)::text = ANY
                   ((ARRAY ['THREAT_RESPONSE'::character varying, 'ACCESS_PATTERN'::character varying, 'POLICY_FEEDBACK'::character varying, 'FALSE_POSITIVE_LEARNING'::character varying, 'PERFORMANCE_OPTIMIZATION'::character varying, 'COMPLIANCE_LEARNING'::character varying])::text[])),
    metadata           jsonb,
    parent_proposal_id bigint,
    policy_content     text,
    policy_id          bigint,
    proposal_type      varchar(50)  not null
        constraint policy_evolution_proposals_proposal_type_check
            check ((proposal_type)::text = ANY
                   ((ARRAY ['CREATE_POLICY'::character varying, 'UPDATE_POLICY'::character varying, 'DELETE_POLICY'::character varying, 'REVOKE_ACCESS'::character varying, 'GRANT_ACCESS'::character varying, 'OPTIMIZE_RULE'::character varying, 'MODIFY_CONFIG'::character varying, 'CREATE_ALERT'::character varying, 'SUGGEST_TRAINING'::character varying, 'ADJUST_THRESHOLD'::character varying, 'ACCESS_CONTROL'::character varying, 'THREAT_RESPONSE'::character varying, 'INCIDENT_RESPONSE'::character varying, 'COMPLIANCE'::character varying, 'OPTIMIZATION'::character varying, 'USER_BEHAVIOR'::character varying, 'ANOMALY_RESPONSE'::character varying, 'DATA_PROTECTION'::character varying])::text[])),
    rationale          text,
    rejected_at        timestamp(6),
    rejected_by        varchar(100),
    rejection_reason   text,
    reviewed_at        timestamp(6),
    reviewed_by        varchar(100),
    risk_level         varchar(20)
        constraint policy_evolution_proposals_risk_level_check
            check ((risk_level)::text = ANY
                   ((ARRAY ['LOW'::character varying, 'MEDIUM'::character varying, 'HIGH'::character varying, 'CRITICAL'::character varying])::text[])),
    source_event_id    varchar(100),
    spel_expression    text,
    status             varchar(50)  not null
        constraint policy_evolution_proposals_status_check
            check ((status)::text = ANY
                   ((ARRAY ['DRAFT'::character varying, 'PENDING_APPROVAL'::character varying, 'PENDING'::character varying, 'UNDER_REVIEW'::character varying, 'APPROVED'::character varying, 'REJECTED'::character varying, 'ACTIVATED'::character varying, 'DEACTIVATED'::character varying, 'ON_HOLD'::character varying, 'EXPIRED'::character varying, 'ROLLED_BACK'::character varying])::text[])),
    title              varchar(255) not null,
    version_id         bigint
);

alter table public.policy_evolution_proposals
    owner to admin;

create table public.customer_data
(
    customer_id            varchar(50)  not null
        primary key,
    account_balance        double precision,
    active                 boolean,
    address                text,
    created_at             timestamp(6) not null,
    created_date           timestamp(6),
    credit_card_number     varchar(20),
    email                  varchar(255) not null,
    is_vip                 boolean,
    last_accessed_at       timestamp(6),
    last_login             timestamp(6),
    membership_tier        varchar(20)
        constraint customer_data_membership_tier_check
            check ((membership_tier)::text = ANY
                   ((ARRAY ['PLATINUM'::character varying, 'GOLD'::character varying, 'SILVER'::character varying, 'BRONZE'::character varying])::text[])),
    name                   varchar(100) not null,
    personal_info          text,
    phone_number           varchar(20),
    sensitivity_level      varchar(20)
        constraint customer_data_sensitivity_level_check
            check ((sensitivity_level)::text = ANY
                   ((ARRAY ['CRITICAL'::character varying, 'HIGH'::character varying, 'MEDIUM'::character varying, 'LOW'::character varying])::text[])),
    social_security_number varchar(15),
    two_factor_enabled     boolean,
    updated_at             timestamp(6)
);

alter table public.customer_data
    owner to admin;

create table public.simulation_results
(
    event_id            varchar(50)  not null
        primary key,
    ai_analysis_time_ms bigint,
    attack_id           varchar(50)  not null,
    attack_type         varchar(50)  not null,
    blocked             boolean      not null,
    campaign_id         varchar(50),
    confidence_score    double precision,
    created_at          timestamp(6) not null,
    detected            boolean      not null,
    error_message       varchar(500),
    metadata            jsonb,
    processed_at        timestamp(6) not null,
    processing_mode     varchar(30),
    processing_success  boolean      not null,
    processing_time_ms  bigint,
    response_actions    jsonb,
    risk_score          double precision,
    session_id          varchar(50),
    simulation_mode     varchar(20)  not null
        constraint simulation_results_simulation_mode_check
            check ((simulation_mode)::text = ANY
                   ((ARRAY ['UNPROTECTED'::character varying, 'PROTECTED'::character varying])::text[])),
    source_ip           varchar(45),
    target_user         varchar(100)
);

alter table public.simulation_results
    owner to admin;

create index idx_simulation_attack_id
    on public.simulation_results (attack_id);

create index idx_simulation_processed_at
    on public.simulation_results (processed_at);

create index idx_simulation_mode
    on public.simulation_results (simulation_mode);

create table public.attack_results
(
    attack_id             varchar(50) not null
        primary key,
    additional_data       jsonb,
    attack_name           varchar(255),
    attack_successful     boolean,
    attack_type           varchar(50)
        constraint attack_results_attack_type_check
            check ((attack_type)::text = ANY
                   ((ARRAY ['BRUTE_FORCE'::character varying, 'CREDENTIAL_STUFFING'::character varying, 'PASSWORD_SPRAY'::character varying, 'SESSION_HIJACKING'::character varying, 'TOKEN_MANIPULATION'::character varying, 'MFA_BYPASS'::character varying, 'TOKEN_REPLAY'::character varying, 'ACCOUNT_ENUMERATION'::character varying, 'PRIVILEGE_ESCALATION'::character varying, 'IDOR'::character varying, 'API_BYPASS'::character varying, 'API_AUTHORIZATION_BYPASS'::character varying, 'HORIZONTAL_PRIVILEGE_ESCALATION'::character varying, 'ROLE_MANIPULATION'::character varying, 'IMPOSSIBLE_TRAVEL'::character varying, 'ABNORMAL_BEHAVIOR'::character varying, 'BEHAVIORAL'::character varying, 'BEHAVIORAL_ANOMALY'::character varying, 'VELOCITY_ATTACK'::character varying, 'SEQUENCE_BREAKING'::character varying, 'DEVICE_TRUST_VIOLATION'::character varying, 'NETWORK_ANOMALY'::character varying, 'TIME_BASED_ANOMALY'::character varying, 'API_ABUSE'::character varying, 'GRAPHQL_INJECTION'::character varying, 'RATE_LIMIT_BYPASS'::character varying, 'API_KEY_EXPOSURE'::character varying, 'MODEL_POISONING'::character varying, 'ADVERSARIAL_EVASION'::character varying, 'PROMPT_INJECTION'::character varying, 'MODEL_EXTRACTION'::character varying, 'ACCOUNT_TAKEOVER'::character varying, 'INSIDER_THREAT'::character varying, 'DORMANT_ACCOUNT_ABUSE'::character varying, 'SERVICE_ACCOUNT_ABUSE'::character varying, 'UNKNOWN'::character varying, 'INJECTION'::character varying, 'DOS'::character varying, 'AUTHORIZATION_BYPASS'::character varying, 'PHISHING'::character varying, 'DATA_EXFILTRATION'::character varying])::text[])),
    blocked               boolean,
    breached_record_count integer,
    campaign_id           varchar(50),
    data_breached         boolean,
    description           varchar(1000),
    detected              boolean,
    detection_time        timestamp(6),
    execution_time        timestamp(6),
    risk_level            varchar(20)
        constraint attack_results_risk_level_check
            check ((risk_level)::text = ANY
                   ((ARRAY ['LOW'::character varying, 'MEDIUM'::character varying, 'HIGH'::character varying, 'CRITICAL'::character varying])::text[])),
    risk_score            double precision,
    successful            boolean,
    target_resource       varchar(255),
    target_user           varchar(100),
    username              varchar(100)
);

alter table public.attack_results
    owner to admin;

create index idx_attack_campaign_id
    on public.attack_results (campaign_id);

create index idx_attack_type
    on public.attack_results (attack_type);

create index idx_attack_execution_time
    on public.attack_results (execution_time);

create index idx_attack_successful
    on public.attack_results (attack_successful);

create table public.privilege_escalation_rules
(
    id                serial
        primary key,
    from_role         varchar(50),
    to_role           varchar(50),
    risk_score        numeric(3, 2),
    detection_pattern varchar(255),
    alert_level       varchar(20)
);

alter table public.privilege_escalation_rules
    owner to admin;

create table public.permission_levels
(
    role_name           varchar(50) not null
        primary key,
    level_value         integer     not null,
    sensitive_resources text,
    description         varchar(255)
);

alter table public.permission_levels
    owner to admin;

create table public.oauth2_authorization
(
    id                            varchar(100) not null
        primary key,
    registered_client_id          varchar(100) not null,
    principal_name                varchar(200) not null,
    authorization_grant_type      varchar(100) not null,
    authorized_scopes             varchar(1000) default NULL::character varying,
    attributes                    text,
    state                         varchar(500)  default NULL::character varying,
    authorization_code_value      text,
    authorization_code_issued_at  timestamp,
    authorization_code_expires_at timestamp,
    authorization_code_metadata   text,
    access_token_value            text,
    access_token_issued_at        timestamp,
    access_token_expires_at       timestamp,
    access_token_metadata         text,
    access_token_type             varchar(100)  default NULL::character varying,
    access_token_scopes           varchar(1000) default NULL::character varying,
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
    owner to admin;

create table public.oauth2_registered_client
(
    id                            varchar(100)                            not null
        primary key,
    client_id                     varchar(100)                            not null,
    client_id_issued_at           timestamp     default CURRENT_TIMESTAMP not null,
    client_secret                 varchar(200)  default NULL::character varying,
    client_secret_expires_at      timestamp,
    client_name                   varchar(200)                            not null,
    client_authentication_methods varchar(1000)                           not null,
    authorization_grant_types     varchar(1000)                           not null,
    redirect_uris                 varchar(1000) default NULL::character varying,
    post_logout_redirect_uris     varchar(1000) default NULL::character varying,
    scopes                        varchar(1000)                           not null,
    client_settings               varchar(2000)                           not null,
    token_settings                varchar(2000)                           not null
);

alter table public.oauth2_registered_client
    owner to admin;

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
    owner to admin;

create table public.user_entities
(
    id           varchar(1000) not null
        primary key,
    name         varchar(100)  not null,
    display_name varchar(200)
);

alter table public.user_entities
    owner to admin;

create table public.one_time_tokens
(
    token_value varchar(36) not null
        primary key,
    username    varchar(50) not null,
    expires_at  timestamp   not null
);

alter table public.one_time_tokens
    owner to admin;

create table public.blocked_user
(
    id              bigint generated by default as identity
        primary key,
    block_count     integer      not null,
    blocked_at      timestamp(6) not null,
    confidence      double precision,
    reasoning       text,
    request_id      varchar(255) not null
        constraint ukj3qud4e063wflknx8qa0h7ym5
            unique,
    resolve_reason  text,
    resolved_action varchar(255),
    resolved_at     timestamp(6),
    resolved_by     varchar(255),
    risk_score      double precision,
    source_ip       varchar(255),
    status          varchar(255) not null
        constraint blocked_user_status_check
            check ((status)::text = ANY
                   ((ARRAY ['BLOCKED'::character varying, 'RESOLVED'::character varying])::text[])),
    user_agent      varchar(255),
    user_id         varchar(255) not null,
    username        varchar(255)
);

alter table public.blocked_user
    owner to admin;

