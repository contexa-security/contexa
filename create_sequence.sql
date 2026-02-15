create sequence public.users_id_seq;

alter sequence public.users_id_seq owner to admin;

alter sequence public.users_id_seq owned by public.users.id;

create sequence public.app_group_group_id_seq;

alter sequence public.app_group_group_id_seq owner to admin;

alter sequence public.app_group_group_id_seq owned by public.app_group.group_id;

create sequence public.role_role_id_seq;

alter sequence public.role_role_id_seq owner to admin;

alter sequence public.role_role_id_seq owned by public.role.role_id;

create sequence public.managed_resource_id_seq;

alter sequence public.managed_resource_id_seq owner to admin;

alter sequence public.managed_resource_id_seq owned by public.managed_resource.id;

create sequence public.permission_permission_id_seq;

alter sequence public.permission_permission_id_seq owner to admin;

alter sequence public.permission_permission_id_seq owned by public.permission.permission_id;

create sequence public.policy_id_seq;

alter sequence public.policy_id_seq owner to admin;

alter sequence public.policy_id_seq owned by public.policy.id;

create sequence public.policy_target_id_seq;

alter sequence public.policy_target_id_seq owner to admin;

alter sequence public.policy_target_id_seq owned by public.policy_target.id;

create sequence public.policy_rule_id_seq;

alter sequence public.policy_rule_id_seq owner to admin;

alter sequence public.policy_rule_id_seq owned by public.policy_rule.id;

create sequence public.policy_condition_id_seq;

alter sequence public.policy_condition_id_seq owner to admin;

alter sequence public.policy_condition_id_seq owned by public.policy_condition.id;

create sequence public.role_hierarchy_config_id_seq;

alter sequence public.role_hierarchy_config_id_seq owner to admin;

alter sequence public.role_hierarchy_config_id_seq owned by public.role_hierarchy_config.id;

create sequence public.audit_log_id_seq;

alter sequence public.audit_log_id_seq owner to admin;

alter sequence public.audit_log_id_seq owned by public.audit_log.id;

create sequence public.business_resource_id_seq;

alter sequence public.business_resource_id_seq owner to admin;

alter sequence public.business_resource_id_seq owned by public.business_resource.id;

create sequence public.business_action_id_seq;

alter sequence public.business_action_id_seq owner to admin;

alter sequence public.business_action_id_seq owned by public.business_action.id;

create sequence public.condition_template_id_seq;

alter sequence public.condition_template_id_seq owner to admin;

alter sequence public.condition_template_id_seq owned by public.condition_template.id;

create sequence public.document_document_id_seq;

alter sequence public.document_document_id_seq owner to admin;

alter sequence public.document_document_id_seq owned by public.document.document_id;

create sequence public.function_catalog_id_seq;

alter sequence public.function_catalog_id_seq owner to admin;

alter sequence public.function_catalog_id_seq owned by public.function_catalog.id;

create sequence public.function_group_id_seq;

alter sequence public.function_group_id_seq owner to admin;

alter sequence public.function_group_id_seq owned by public.function_group.id;

create sequence public.policy_template_id_seq;

alter sequence public.policy_template_id_seq owner to admin;

alter sequence public.policy_template_id_seq owned by public.policy_template.id;

create sequence public.role_hierarchy_config_hierarchy_id_seq;

alter sequence public.role_hierarchy_config_hierarchy_id_seq owner to admin;

alter sequence public.role_hierarchy_config_hierarchy_id_seq owned by public.role_hierarchy_config.hierarchy_id;

create sequence public.policy_condition_seq
    increment by 50;

alter sequence public.policy_condition_seq owner to admin;

create sequence public.policy_rule_seq
    increment by 50;

alter sequence public.policy_rule_seq owner to admin;

create sequence public.policy_target_seq
    increment by 50;

alter sequence public.policy_target_seq owner to admin;

create sequence public.behavior_anomaly_events_id_seq;

alter sequence public.behavior_anomaly_events_id_seq owner to admin;

alter sequence public.behavior_anomaly_events_id_seq owned by public.behavior_anomaly_events.id;

create sequence public.behavior_based_permissions_id_seq;

alter sequence public.behavior_based_permissions_id_seq owner to admin;

alter sequence public.behavior_based_permissions_id_seq owned by public.behavior_based_permissions.id;

create sequence public.user_behavior_profiles_id_seq;

alter sequence public.user_behavior_profiles_id_seq owner to admin;

alter sequence public.user_behavior_profiles_id_seq owned by public.user_behavior_profiles.id;

create sequence public.soar_approval_policies_id_seq;

alter sequence public.soar_approval_policies_id_seq owner to admin;

alter sequence public.soar_approval_policies_id_seq owned by public.soar_approval_policies.id;

create sequence public.soar_approval_requests_id_seq;

alter sequence public.soar_approval_requests_id_seq owner to admin;

alter sequence public.soar_approval_requests_id_seq owned by public.soar_approval_requests.id;

create sequence public.approval_notifications_id_seq;

alter sequence public.approval_notifications_id_seq owner to admin;

alter sequence public.approval_notifications_id_seq owned by public.approval_notifications.id;

create sequence public.tool_execution_contexts_id_seq;

alter sequence public.tool_execution_contexts_id_seq owner to admin;

alter sequence public.tool_execution_contexts_id_seq owned by public.tool_execution_contexts.id;

create sequence public.policy_evolution_proposals_id_seq;

alter sequence public.policy_evolution_proposals_id_seq owner to admin;

alter sequence public.policy_evolution_proposals_id_seq owned by public.policy_evolution_proposals.id;

create sequence public.privilege_escalation_rules_id_seq
    as integer;

alter sequence public.privilege_escalation_rules_id_seq owner to admin;

alter sequence public.privilege_escalation_rules_id_seq owned by public.privilege_escalation_rules.id;

create sequence public.blocked_user_id_seq;

alter sequence public.blocked_user_id_seq owner to admin;

alter sequence public.blocked_user_id_seq owned by public.blocked_user.id;

