package io.contexa.contexaiam.admin.verification.service.quality.runtime;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.context.prompt.PromptRuntimeGovernanceRule;
import io.contexa.contexacore.autonomous.context.prompt.PromptRuntimeGovernanceRuleApplication;
import io.contexa.contexacore.autonomous.context.prompt.PromptRuntimeGovernanceRuleContext;
import io.contexa.contexacore.autonomous.context.prompt.PromptRuntimeGovernanceRuleProvider;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceSupport;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;

public class JdbcPromptRuntimeGovernanceRuleProvider implements PromptRuntimeGovernanceRuleProvider {

    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {
    };

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final Map<RuleSetCacheKey, CachedRuleSet> ruleSetCache = new ConcurrentHashMap<>();
    private final Map<RuleSetCacheKey, Map<String, Object>> ruleSetCacheMetadata = new ConcurrentHashMap<>();

    public JdbcPromptRuntimeGovernanceRuleProvider(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    @Override
    public List<PromptRuntimeGovernanceRule> activeRules(PromptRuntimeGovernanceRuleContext context) {
        if (context == null || !StringUtils.hasText(context.promptKey()) || !StringUtils.hasText(context.promptVersion())) {
            return List.of();
        }
        RuleSetCacheKey cacheKey = RuleSetCacheKey.from(context);
        long invalidationId = latestInvalidationId(cacheKey);
        CachedRuleSet cached = ruleSetCache.get(cacheKey);
        if (cached != null && cached.invalidationId() == invalidationId) {
            recordCacheMetadata(cacheKey, true, invalidationId, cached.rules().size());
            return cached.rules();
        }
        RuntimeScopeValues scope = RuntimeScopeValues.from(context);
        List<RuleRow> ruleRows = jdbcTemplate.query("""
                        select rule.rule_id,
                               rule.source_action_id,
                               rule.prompt_key,
                               rule.slot_key,
                               rule.rule_type,
                               rule.priority,
                               rule.rule_payload_json,
                               rule.scope_type
                          from prompt_runtime_governance_rule rule
                          join prompt_runtime_governance_action action
                            on action.action_id = rule.source_action_id
                           and action.current_result = true
                           and action.action_status = 'APPROVED'
                           and action.action_type = rule.rule_type
                           and action.slot_key = rule.slot_key
                           and action.package_id = rule.package_id
                           and action.aggregate_run_id = rule.aggregate_run_id
                          left join pqa_resolution_work_item wi
                            on wi.work_item_id = coalesce(action.work_item_id, action.issue_id)
                           and wi.package_id = action.package_id
                           and wi.aggregate_run_id = action.aggregate_run_id
                          join prompt_runtime_governance_scope_type_contract scope
                            on scope.scope_type = rule.scope_type
                           and scope.active = true
                          left join lateral (
                              select m.slot_key
                                from prompt_runtime_governance_action_policy p
                                join prompt_runtime_metric_check_slot_contract m
                                  on m.contract_version = p.contract_version
                                 and m.prompt_key = p.prompt_key
                                 and m.metric_code = p.metric_code
                                 and m.check_code = p.check_code
                                 and m.active = true
                                left join prompt_runtime_slot_contract slot
                                  on slot.slot_key = m.slot_key
                                 and slot.active = true
                               where p.active = true
                                 and p.action_type = rule.rule_type
                                 and upper(p.metric_code) = upper(coalesce(wi.metric_code, action.metric_code, rule.metric_code))
                                 and (
                                      p.check_code = coalesce(wi.check_code, action.check_code, rule.check_code)
                                      or p.issue_key = wi.signal_key
                                      or p.issue_key = wi.prompt_location
                                      or m.prompt_location = wi.signal_key
                                      or m.prompt_location = wi.prompt_location
                                 )
                               order by
                                 case when m.prompt_location = wi.prompt_location then 0 else 1 end,
                                 case when p.issue_key = wi.prompt_location then 0 else 1 end,
                                 case when p.issue_key = wi.signal_key then 0 else 1 end,
                                 case when p.action_type = 'SUPPRESS_SLOT'
                                            and slot.signal_key like 'forbiddenTerm:%'
                                      then 0 else 1 end,
                                 case when p.action_type in ('ADD_NARRATIVE', 'ADD_LIMITATION')
                                            and slot.signal_key like 'groupTerm:%'
                                      then 0 else 1 end,
                                 m.id asc
                               limit 1
                          ) current_policy on true
                         where rule.active = true
                           and rule.current_result = true
                           and rule.prompt_key = ?
                           and rule.prompt_version = ?
                           and (
                                current_policy.slot_key is null
                                or current_policy.slot_key = rule.slot_key
                           )
                           and (
                                rule.scope_type = 'GLOBAL'
                                or (rule.scope_type = 'TENANT'
                                    and rule.tenant_id = ?)
                                or (rule.scope_type = 'SENSITIVITY'
                                    and rule.sensitivity = ?)
                                or (rule.scope_type = 'ACTION_FAMILY'
                                    and rule.action_family = ?)
                                or (rule.scope_type = 'RESOURCE_TYPE'
                                    and rule.resource_type = ?)
                                or (rule.scope_type = 'METRIC_CHECK'
                                    and upper(rule.metric_code) = upper(?)
                                    and rule.check_code = ?)
                                or (rule.scope_type = 'RESOURCE_ID'
                                    and rule.resource_id = ?)
                                or (rule.scope_type = 'RESOURCE_URL_METHOD'
                                    and coalesce(rule.resource_url, '') = coalesce(?, '')
                                    and coalesce(rule.http_method, '') = coalesce(?, ''))
                           )
                         order by scope.scope_priority asc,
                                  rule.priority asc,
                                  rule.updated_at desc,
                                  rule.rule_id asc
                        """,
                (rs, rowNum) -> new RuleRow(
                        new PromptRuntimeGovernanceRule(
                                rs.getString("rule_id"),
                                rs.getString("source_action_id"),
                                rs.getString("prompt_key"),
                                rs.getString("slot_key"),
                                rs.getString("rule_type"),
                                rs.getInt("priority"),
                                readPayload(rs)),
                        rs.getString("scope_type")),
                context.promptKey(),
                context.promptVersion(),
                context.tenantId(),
                scope.sensitivity(),
                scope.actionFamily(),
                scope.resourceType(),
                scope.metricCode(),
                scope.checkCode(),
                context.resourceId(),
                context.resourceUrl(),
                context.httpMethod());
        List<PromptRuntimeGovernanceRule> rules = resolveSlotConflicts(ruleRows);
        List<PromptRuntimeGovernanceRule> immutableRules = List.copyOf(rules);
        ruleSetCache.put(cacheKey, new CachedRuleSet(invalidationId, immutableRules));
        recordCacheMetadata(cacheKey, false, invalidationId, immutableRules.size());
        return immutableRules;
    }

    @Override
    public void recordApplications(
            PromptRuntimeGovernanceRuleContext context,
            List<PromptRuntimeGovernanceRuleApplication> applications,
            String systemPromptHash,
            String userPromptHash) {
        if (context == null || applications == null || applications.isEmpty()) {
            return;
        }
        String requestId = textAttribute(context.attributes(), "requestId", "request_id", "eventId", "event_id", "traceId");
        for (PromptRuntimeGovernanceRuleApplication application : applications) {
            if (application == null || !StringUtils.hasText(application.ruleId())) {
                continue;
            }
            if (!isValidApplicationSource(application.ruleId())) {
                continue;
            }
            String applicationId = applicationId(context, application, requestId);
            jdbcTemplate.update("""
                            insert into prompt_runtime_governance_application_ledger (
                                application_id,
                                rule_id,
                                source_action_id,
                                registry_scope,
                                prompt_key,
                                prompt_version,
                                tenant_id,
                                resource_id,
                                resource_url,
                                http_method,
                                request_id,
                                system_prompt_hash,
                                user_prompt_hash,
                                before_prompt_hash,
                                after_prompt_hash,
                                slot_key,
                                rule_type,
                                applied_operation,
                                result_state,
                                changed_prompt,
                                application_context_json,
                                applied_at
                            )
                            values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?::jsonb, current_timestamp)
                            on conflict (application_id) do update set
                                system_prompt_hash = excluded.system_prompt_hash,
                                user_prompt_hash = excluded.user_prompt_hash,
                                before_prompt_hash = excluded.before_prompt_hash,
                                after_prompt_hash = excluded.after_prompt_hash,
                                result_state = excluded.result_state,
                                changed_prompt = excluded.changed_prompt,
                                application_context_json = excluded.application_context_json,
                                applied_at = current_timestamp
                            """,
                    applicationId,
                    application.ruleId(),
                    application.sourceActionId(),
                    context.registryScope(),
                    context.promptKey(),
                    context.promptVersion(),
                    context.tenantId(),
                    context.resourceId(),
                    context.resourceUrl(),
                    context.httpMethod(),
                    requestId,
                    systemPromptHash,
                    userPromptHash,
                    application.beforePromptHash(),
                    application.afterPromptHash(),
                    application.slotKey(),
                    application.ruleType(),
                    application.appliedOperation(),
                    application.resultState(),
                    application.changedPrompt(),
                    writeJson(applicationContext(context, application)));
        }
    }

    private boolean isValidApplicationSource(String ruleId) {
        if (!StringUtils.hasText(ruleId)) {
            return false;
        }
        Integer count = jdbcTemplate.queryForObject("""
                        select count(*)
                          from prompt_runtime_governance_rule rule
                          join prompt_runtime_governance_action action
                            on action.action_id = rule.source_action_id
                           and action.package_id = rule.package_id
                           and action.aggregate_run_id = rule.aggregate_run_id
                           and action.current_result = true
                           and action.action_status = 'APPROVED'
                         where rule.rule_id = ?
                           and rule.current_result = true
                           and rule.active = true
                        """,
                Integer.class,
                ruleId);
        return count != null && count > 0;
    }

    @Override
    public Map<String, Object> runtimeCacheMetadata(PromptRuntimeGovernanceRuleContext context) {
        if (context == null || !StringUtils.hasText(context.promptKey()) || !StringUtils.hasText(context.promptVersion())) {
            return Map.of();
        }
        Map<String, Object> metadata = ruleSetCacheMetadata.get(RuleSetCacheKey.from(context));
        return metadata == null ? Map.of() : Map.copyOf(metadata);
    }

    private Map<String, Object> readPayload(ResultSet rs) throws SQLException {
        String json = rs.getString("rule_payload_json");
        if (!StringUtils.hasText(json)) {
            return Map.of();
        }
        try {
            Map<String, Object> payload = objectMapper.readValue(json, MAP_TYPE);
            return payload != null ? payload : Map.of();
        }
        catch (Exception exception) {
            throw new IllegalStateException("Failed to read prompt runtime governance rule payload.", exception);
        }
    }

    private String writeJson(Map<String, Object> value) {
        try {
            return objectMapper.writeValueAsString(value != null ? value : Map.of());
        }
        catch (Exception exception) {
            throw new IllegalStateException("Failed to write prompt runtime governance application context.", exception);
        }
    }

    private Map<String, Object> applicationContext(
            PromptRuntimeGovernanceRuleContext context,
            PromptRuntimeGovernanceRuleApplication application) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("registryScope", context.registryScope());
        value.put("promptKey", context.promptKey());
        value.put("promptVersion", context.promptVersion());
        value.put("tenantId", context.tenantId());
        value.put("resourceId", context.resourceId());
        value.put("resourceUrl", context.resourceUrl());
        value.put("httpMethod", context.httpMethod());
        RuntimeScopeValues scope = RuntimeScopeValues.from(context);
        value.put("resourceType", scope.resourceType());
        value.put("actionFamily", scope.actionFamily());
        value.put("sensitivity", scope.sensitivity());
        value.put("metricCode", scope.metricCode());
        value.put("checkCode", scope.checkCode());
        value.put("ruleId", application.ruleId());
        value.put("slotKey", application.slotKey());
        value.put("ruleType", application.ruleType());
        value.put("appliedOperation", application.appliedOperation());
        value.put("resultState", application.resultState());
        value.put("changedPrompt", application.changedPrompt());
        value.putAll(runtimeCacheMetadata(context));
        value.put("recordedAt", Instant.now().toString());
        return value;
    }

    private List<PromptRuntimeGovernanceRule> resolveSlotConflicts(List<RuleRow> rows) {
        if (rows == null || rows.isEmpty()) {
            return List.of();
        }
        Map<String, PromptRuntimeGovernanceRule> bySlot = new LinkedHashMap<>();
        for (RuleRow row : rows) {
            if (row == null || row.rule() == null || !StringUtils.hasText(row.rule().slotKey())) {
                continue;
            }
            if (isUnusableRuntimeRule(row.rule())) {
                continue;
            }
            PromptRuntimeGovernanceScopeType.from(row.scopeType());
            bySlot.putIfAbsent(row.rule().slotKey(), row.rule());
        }
        return new ArrayList<>(bySlot.values());
    }

    private boolean isUnusableRuntimeRule(PromptRuntimeGovernanceRule rule) {
        if (rule == null || !"UPDATE_SLOT_VALUE".equals(rule.ruleType())) {
            return false;
        }
        Object renderedValue = rule.payload() == null ? null : rule.payload().get("renderedValue");
        return isUnusablePromptValue(renderedValue == null ? null : String.valueOf(renderedValue));
    }

    private boolean isUnusablePromptValue(String value) {
        if (!StringUtils.hasText(value)) {
            return true;
        }
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        return "N/A".equals(normalized)
                || "NA".equals(normalized)
                || "UNKNOWN".equals(normalized)
                || "MISSING".equals(normalized)
                || "NULL".equals(normalized)
                || normalized.startsWith("UNKNOWN ")
                || normalized.contains(" NOT AVAILABLE")
                || normalized.contains(" NOT SUPPLIED")
                || normalized.contains(" NO RELIABLE")
                || normalized.contains(" DO NOT ASSUME")
                || "?????놁쓬".equals(value.trim());
    }

    private long latestInvalidationId(RuleSetCacheKey key) {
        if (key == null || !StringUtils.hasText(key.promptKey()) || !StringUtils.hasText(key.promptVersion())) {
            return 0L;
        }
        Long value = jdbcTemplate.queryForObject("""
                        select coalesce(max(id), 0)
                          from prompt_governance_runtime_cache_invalidation
                         where registry_scope = ?
                           and prompt_key = ?
                           and prompt_version = ?
                        """,
                Long.class,
                key.registryScope(),
                key.promptKey(),
                key.promptVersion());
        return value == null ? 0L : value;
    }

    private void recordCacheMetadata(
            RuleSetCacheKey key,
            boolean hit,
            long invalidationId,
            int ruleCount) {
        if (key == null) {
            return;
        }
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("promptRuntimeGovernanceRuleCacheHit", hit);
        metadata.put("promptRuntimeGovernanceRuleCacheKey", key.cacheKey());
        metadata.put("promptRuntimeGovernanceRuleCacheInvalidationId", invalidationId);
        metadata.put("promptRuntimeGovernanceRuleCacheRuleCount", ruleCount);
        ruleSetCacheMetadata.put(key, Map.copyOf(metadata));
    }

    private String applicationId(
            PromptRuntimeGovernanceRuleContext context,
            PromptRuntimeGovernanceRuleApplication application,
            String requestId) {
        String material = String.join("|",
                text(context.promptKey()),
                text(context.promptVersion()),
                text(context.registryScope()),
                text(context.tenantId()),
                text(context.resourceId()),
                text(context.resourceUrl()),
                text(context.httpMethod()),
                text(requestId),
                text(application.ruleId()),
                text(application.sourceActionId()),
                text(application.beforePromptHash()),
                text(application.afterPromptHash()),
                text(application.resultState()));
        return "pqa-rtg-application-" + PromptGovernanceSupport.sha256(material).substring(0, 32);
    }

    private String textAttribute(Map<String, Object> attributes, String... keys) {
        if (attributes == null || keys == null) {
            return null;
        }
        for (String key : keys) {
            Object value = attributes.get(key);
            if (value != null && StringUtils.hasText(String.valueOf(value))) {
                return String.valueOf(value).trim();
            }
        }
        return null;
    }

    private String text(String value) {
        return value == null ? "" : value;
    }

    private record CachedRuleSet(
            long invalidationId,
            List<PromptRuntimeGovernanceRule> rules) {
    }

    private record RuleRow(
            PromptRuntimeGovernanceRule rule,
            String scopeType) {
    }

    private record RuleSetCacheKey(
            String registryScope,
            String promptKey,
            String promptVersion,
            String tenantId,
            String resourceType,
            String resourceId,
            String resourceUrl,
            String httpMethod,
            String actionFamily,
            String sensitivity,
            String metricCode,
            String checkCode) {

        static RuleSetCacheKey from(PromptRuntimeGovernanceRuleContext context) {
            RuntimeScopeValues scope = RuntimeScopeValues.from(context);
            return new RuleSetCacheKey(
                    text(context.registryScope()),
                    text(context.promptKey()),
                    text(context.promptVersion()),
                    text(context.tenantId()),
                    text(scope.resourceType()),
                    text(context.resourceId()),
                    text(context.resourceUrl()),
                    text(context.httpMethod()),
                    text(scope.actionFamily()),
                    text(scope.sensitivity()),
                    text(scope.metricCode()),
                    text(scope.checkCode()));
        }

        String cacheKey() {
            return String.join("|",
                    registryScope,
                    promptKey,
                    promptVersion,
                    tenantId,
                    resourceType,
                    resourceId,
                    resourceUrl,
                    httpMethod,
                    actionFamily,
                    sensitivity,
                    metricCode,
                    checkCode);
        }

        private static String text(String value) {
            return value == null ? "" : value;
        }
    }

    private record RuntimeScopeValues(
            String resourceType,
            String actionFamily,
            String sensitivity,
            String metricCode,
            String checkCode) {

        static RuntimeScopeValues from(PromptRuntimeGovernanceRuleContext context) {
            Map<String, Object> attributes = context == null ? Map.of() : context.attributes();
            return new RuntimeScopeValues(
                    textAttribute(attributes, "resourceType", "resource_type", "resourceFamily", "resource_family"),
                    textAttribute(attributes, "actionFamily", "action_family", "operation", "action"),
                    textAttribute(attributes, "sensitivity", "resourceSensitivity", "resource_sensitivity", "sensitivityLevel"),
                    textAttribute(attributes, "metricCode", "metric_code"),
                    textAttribute(attributes, "checkCode", "check_code"));
        }

        private static String textAttribute(Map<String, Object> attributes, String... keys) {
            if (attributes == null || keys == null) {
                return null;
            }
            for (String key : keys) {
                Object value = attributes.get(key);
                if (value != null && StringUtils.hasText(String.valueOf(value))) {
                    return String.valueOf(value).trim();
                }
            }
            return null;
        }
    }
}
