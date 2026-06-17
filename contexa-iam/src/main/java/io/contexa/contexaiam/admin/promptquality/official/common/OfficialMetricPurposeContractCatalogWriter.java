package io.contexa.contexaiam.admin.promptquality.official.common;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricCheckContract;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricContract;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricContractCatalog;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricRule;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.util.StringUtils;

import java.sql.Timestamp;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ArrayList;

public class OfficialMetricPurposeContractCatalogWriter {

    private static final List<String> CUSTOMER_DISPLAY_ROLES = List.of(
            "TITLE",
            "PASS_EVIDENCE",
            "FAIL_EVIDENCE",
            "WHY_IT_MATTERS",
            "RESOLUTION_ACTION",
            "REVERIFY_CONDITION");
    private static final String RESOLUTION_CONTRACT_SEED_RESOURCE = "/pqa-resolution-contract-seed.json";

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private FinalPromptMetricContractCatalog finalPromptMetricContractCatalog;

    public OfficialMetricPurposeContractCatalogWriter(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    public void upsertFullMetricContractCatalog() {
        FinalPromptMetricContractCatalog catalog = finalPromptMetricContractCatalog();
        String currentVersion = currentContractVersion(catalog);
        boolean resolutionContractsAvailable = resolutionContractsAvailable();
        removeFallbackContractRows();
        removeCurrentContractRows(currentVersion);
        if (resolutionContractsAvailable) {
            upsertResolutionContractSeed();
        }
        for (String metricCode : catalog.metricCodesInOrder()) {
            FinalPromptMetricContract metricContract = catalog.metric(metricCode);
            for (FinalPromptMetricCheckContract checkContract : metricContract.checks()) {
                upsertMetricPurposeContract(metricContract.version(), metricCode, metricContract, checkContract);
                upsertMetricCheckDisplayEvidenceContract(metricContract.version(), metricCode, checkContract);
            }
        }
        upsertPromptRuntimeGovernanceActionTypeContracts();
        upsertPromptRuntimeGovernanceCheckActionContracts(currentVersion, catalog);
        upsertPromptSignalRegistryContracts(currentVersion, catalog);
        upsertPromptRuntimeSlotContracts();
        refreshPromptRuntimeGovernanceActionPolicy();
        deactivateNonCurrentContractVersions(currentVersion);
    }

    public void assertFullMetricContractCatalogPersisted() {
        FinalPromptMetricContractCatalog catalog = finalPromptMetricContractCatalog();
        String currentVersion = currentContractVersion(catalog);
        int expectedMetricCount = catalog.metricCodesInOrder().size();
        int expectedCheckCount = 0;
        int expectedCustomerDisplayRows = 0;
        int expectedCustomerDisplayBindingRows = 0;
        LinkedHashSet<String> expectedInputRows = new LinkedHashSet<>();
        LinkedHashSet<String> expectedSignalRows = new LinkedHashSet<>();
        for (String metricCode : catalog.metricCodesInOrder()) {
            FinalPromptMetricContract metricContract = catalog.metric(metricCode);
            expectedCheckCount += metricContract.checks().size();
            for (FinalPromptMetricCheckContract checkContract : metricContract.checks()) {
                addExpectedInputRows(expectedInputRows, metricCode, checkContract, checkContract.rule());
                if (checkContract.inputReadinessRule() != null) {
                    addExpectedInputRows(expectedInputRows, metricCode, checkContract, checkContract.inputReadinessRule());
                }
                if (checkContract.applicabilityRule() != null) {
                    addExpectedInputRows(expectedInputRows, metricCode, checkContract, checkContract.applicabilityRule());
                }
                addExpectedSignalRows(expectedSignalRows, metricCode, checkContract, checkContract.rule());
                if (checkContract.inputReadinessRule() != null) {
                    addExpectedSignalRows(expectedSignalRows, metricCode, checkContract, checkContract.inputReadinessRule());
                }
                if (checkContract.applicabilityRule() != null) {
                    addExpectedSignalRows(expectedSignalRows, metricCode, checkContract, checkContract.applicabilityRule());
                }
                if (customerDisplayEligible(checkContract)) {
                    expectedCustomerDisplayRows += CUSTOMER_DISPLAY_ROLES.size();
                    expectedCustomerDisplayBindingRows += safeEvidenceBindings(checkContract).size() * 2;
                }
            }
        }
        for (FinalPromptMetricContractCatalog.PromptSignalContract signal : catalog.promptSignalContracts()) {
            expectedSignalRows.add("MTR|" + signal.checkCode() + "|" + signal.signalKey());
        }
        assertCurrentContractRows("official_metric_purpose_contract", currentVersion, expectedMetricCount);
        assertCurrentContractRows("official_metric_evaluation_contract", currentVersion, expectedCheckCount);
        assertCurrentContractRows("official_prompt_signal_contract", currentVersion, expectedSignalRows.size());
        assertCurrentContractRows("official_metric_customer_message_contract", currentVersion, expectedCheckCount);
        assertCurrentContractRows("official_metric_check_display_evidence_contract", currentVersion, expectedCheckCount);
        assertCurrentContractRows("official_metric_customer_display_contract", currentVersion, expectedCustomerDisplayRows);
        assertCurrentContractRows("official_metric_customer_display_binding", currentVersion, expectedCustomerDisplayBindingRows);
        assertCurrentContractRows("official_metric_input_contract", currentVersion, expectedInputRows.size());
        if (resolutionContractsAvailable()) {
            assertCurrentActionCatalogRows();
            assertCurrentSignalActionPolicyRows();
            assertCurrentDisplayTextContractRows(expectedCheckCount * 2 + 17);
        }
        assertCurrentPromptRuntimeGovernanceActionPolicyRows(currentVersion, expectedCheckCount);
    }

    private void addExpectedInputRows(
            LinkedHashSet<String> expectedInputRows,
            String metricCode,
            FinalPromptMetricCheckContract checkContract,
            FinalPromptMetricRule rule) {
        for (MetricInputRequirement input : contractInputRequirements(rule)) {
            expectedInputRows.add(metricCode + "|" + checkContract.checkName() + "|" + input.inputKey());
        }
    }

    private void addExpectedSignalRows(
            LinkedHashSet<String> expectedSignalRows,
            String metricCode,
            FinalPromptMetricCheckContract checkContract,
            FinalPromptMetricRule rule) {
        for (String signalKey : contractInputKeys(rule)) {
            expectedSignalRows.add(metricCode + "|" + checkContract.checkName() + "|" + signalKey);
        }
    }

    private void assertCurrentContractRows(String tableName, String contractVersion, int expectedRows) {
        Integer actualRows = jdbcTemplate.queryForObject(
                "select count(*) from " + tableName + " where contract_version = ?",
                Integer.class,
                contractVersion);
        if (actualRows == null || actualRows != expectedRows) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Metric contract catalog was not persisted."
                    + " table=" + tableName + ", contractVersion=" + contractVersion
                    + ", expectedRows=" + expectedRows + ", actualRows=" + actualRows);
        }
    }

    private void removeFallbackContractRows() {
        String fallbackVersion = "runtime-contract-unknown";
        jdbcTemplate.update("delete from official_metric_customer_message_contract where contract_version = ?",
                fallbackVersion);
        jdbcTemplate.update("delete from official_metric_check_display_evidence_contract where contract_version = ?",
                fallbackVersion);
        jdbcTemplate.update("delete from official_metric_customer_display_binding where contract_version = ?",
                fallbackVersion);
        jdbcTemplate.update("delete from official_metric_customer_display_contract where contract_version = ?",
                fallbackVersion);
        jdbcTemplate.update("delete from official_metric_customer_display_payload where contract_version = ?",
                fallbackVersion);
        jdbcTemplate.update("delete from official_prompt_signal_contract where contract_version = ?",
                fallbackVersion);
        jdbcTemplate.update("delete from official_metric_input_contract where contract_version = ?",
                fallbackVersion);
        jdbcTemplate.update("delete from official_metric_evaluation_contract where contract_version = ?",
                fallbackVersion);
        jdbcTemplate.update("delete from official_metric_purpose_contract where contract_version = ?",
                fallbackVersion);
        jdbcTemplate.update("delete from official_metric_contract_version where contract_version = ?",
                fallbackVersion);
        if (tableExists("pqa_resolution_display_text_contract")) {
            jdbcTemplate.update("""
                            update pqa_resolution_display_text_contract
                               set active = false,
                                   updated_at = ?
                             where metric_code is not null
                               and check_code is not null
                               and check_code like metric_code || '\\_%' escape '\\'
                            """,
                    nowTimestamp());
        }
    }

    private void removeCurrentContractRows(String contractVersion) {
        if (!StringUtils.hasText(contractVersion)) {
            throw new IllegalStateException("Final prompt metric contract version is required before pruning current rows.");
        }
        jdbcTemplate.update("delete from official_metric_customer_message_contract where contract_version = ?",
                contractVersion);
        jdbcTemplate.update("delete from official_metric_check_display_evidence_contract where contract_version = ?",
                contractVersion);
        jdbcTemplate.update("delete from official_metric_customer_display_binding where contract_version = ?",
                contractVersion);
        jdbcTemplate.update("delete from official_metric_customer_display_contract where contract_version = ?",
                contractVersion);
        jdbcTemplate.update("delete from official_prompt_signal_contract where contract_version = ?",
                contractVersion);
        jdbcTemplate.update("delete from official_metric_input_contract where contract_version = ?",
                contractVersion);
        jdbcTemplate.update("delete from official_metric_evaluation_contract where contract_version = ?",
                contractVersion);
        jdbcTemplate.update("delete from official_metric_purpose_contract where contract_version = ?",
                contractVersion);
        jdbcTemplate.update("delete from official_metric_contract_version where contract_version = ?",
                contractVersion);
    }

    private void assertCurrentActionCatalogRows() {
        Integer actualRows = jdbcTemplate.queryForObject(
                "select count(*) from pqa_resolution_action_catalog where active = true",
                Integer.class);
        if (actualRows == null || actualRows < 10) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: PQA resolution action catalog was not persisted."
                    + " expectedRows>=10, actualRows=" + actualRows);
        }
    }

    private void assertCurrentSignalActionPolicyRows() {
        Integer actualRows = jdbcTemplate.queryForObject(
                "select count(*) from pqa_resolution_signal_action_policy where active = true",
                Integer.class);
        if (actualRows == null || actualRows < 6) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: PQA resolution signal action policy was not persisted."
                    + " expectedRows>=6, actualRows=" + actualRows);
        }
    }

    private void assertCurrentPromptRuntimeGovernanceActionPolicyRows(String contractVersion, int expectedRows) {
        if (!postgresqlDatabase()
                || !tableExists("prompt_runtime_governance_action_policy")
                || !tableExists("prompt_runtime_governance_check_action_contract")) {
            return;
        }
        Integer contractRows = jdbcTemplate.queryForObject("""
                        select count(*)
                          from prompt_runtime_governance_check_action_contract
                         where contract_version = ?
                           and active = true
                        """,
                Integer.class,
                contractVersion);
        Integer policyRows = jdbcTemplate.queryForObject("""
                        select count(*)
                          from prompt_runtime_governance_action_policy
                         where contract_version = ?
                           and active = true
                        """,
                Integer.class,
                contractVersion);
        Integer missingPolicyRows = jdbcTemplate.queryForObject("""
                        select count(*)
                          from official_metric_evaluation_contract c
                         where c.contract_version = ?
                           and not exists (
                               select 1
                                 from prompt_runtime_governance_action_policy p
                                where p.contract_version = c.contract_version
                                  and p.metric_code = c.metric_code
                                  and p.check_code = c.check_code
                                  and p.active = true
                           )
                        """,
                Integer.class,
                contractVersion);
        Integer missingActionDisplayRows = jdbcTemplate.queryForObject("""
                        select count(*)
                          from prompt_runtime_governance_action_type_contract
                         where active = true
                           and (
                                display_label is null or btrim(display_label) = ''
                                or button_label is null or btrim(button_label) = ''
                                or customer_description is null or btrim(customer_description) = ''
                           )
                        """,
                Integer.class);
        if (contractRows == null || contractRows != expectedRows
                || policyRows == null || policyRows != expectedRows
                || missingPolicyRows == null || missingPolicyRows != 0
                || missingActionDisplayRows == null || missingActionDisplayRows != 0) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Prompt runtime governance action policy was not persisted."
                    + " contractVersion=" + contractVersion
                    + ", expectedRows=" + expectedRows
                    + ", contractRows=" + contractRows
                    + ", policyRows=" + policyRows
                    + ", missingPolicyRows=" + missingPolicyRows
                    + ", missingActionDisplayRows=" + missingActionDisplayRows);
        }
    }

    private void assertCurrentDisplayTextContractRows(int expectedRows) {
        Integer actualRows = jdbcTemplate.queryForObject(
                "select count(*) from pqa_resolution_display_text_contract where active = true",
                Integer.class);
        if (actualRows == null || actualRows < expectedRows) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: PQA resolution display text contract was not persisted."
                    + " expectedRows>=" + expectedRows + ", actualRows=" + actualRows);
        }
        Integer prefixedRows = jdbcTemplate.queryForObject("""
                        select count(*)
                          from pqa_resolution_display_text_contract
                         where active = true
                           and metric_code is not null
                           and check_code is not null
                           and check_code like metric_code || '\\_%' escape '\\'
                        """,
                Integer.class);
        if (prefixedRows != null && prefixedRows > 0) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: PQA resolution display text contract contains prefixed check_code rows."
                    + " prefixedRows=" + prefixedRows);
        }
    }

    private boolean resolutionContractTablesAvailable() {
        return tableExists("pqa_resolution_action_catalog")
                && tableExists("pqa_resolution_signal_action_policy")
                && tableExists("pqa_resolution_display_text_contract");
    }

    private boolean resolutionContractsAvailable() {
        return resolutionContractTablesAvailable() && resolutionContractSeedResourceAvailable();
    }

    private boolean resolutionContractSeedResourceAvailable() {
        try (InputStream input = OfficialMetricPurposeContractCatalogWriter.class
                .getResourceAsStream(RESOLUTION_CONTRACT_SEED_RESOURCE)) {
            return input != null;
        } catch (Exception exception) {
            return false;
        }
    }

    private void upsertResolutionContractSeed() {
        JsonNode seed = resolutionContractSeed();
        for (JsonNode action : requiredArray(seed, "actions")) {
            upsertResolutionAction(
                    requiredText(action, "action_type"),
                    requiredText(action, "resolution_type"),
                    requiredText(action, "label"),
                    requiredText(action, "description"),
                    optionalText(action, "target_page"),
                    optionalText(action, "route_template"),
                    requiredText(action, "execution_mode"),
                    requiredText(action, "primary_button_label"),
                    requiredText(action, "success_message_template"),
                    requiredText(action, "failure_message_template"),
                    requiredInt(action, "expected_duration_seconds"),
                    requiredText(action, "allowed_state_from"),
                    requiredText(action, "allowed_state_to"),
                    requiredText(action, "completion_event_type"),
                    optionalText(action, "completion_query_key"),
                    requiredBoolean(action, "requires_confirmation"),
                    requiredText(action, "idempotency_policy"));
        }
        for (JsonNode policy : requiredArray(seed, "signalActionPolicies")) {
            upsertSignalActionPolicy(
                    requiredText(policy, "policy_id"),
                    requiredText(policy, "resolution_type"),
                    requiredText(policy, "signal_key_pattern"),
                    optionalText(policy, "input_kind"),
                    optionalText(policy, "producer_key_pattern"),
                    optionalText(policy, "producer_key"),
                    requiredText(policy, "primary_action_type"),
                    requiredText(policy, "action_readiness_state"),
                    requiredText(policy, "requirement_state"),
                    requiredInt(policy, "priority"));
        }
        for (JsonNode displayText : requiredArray(seed, "displayTexts")) {
            upsertResolutionDisplayTextRow(
                    requiredText(displayText, "text_id"),
                    requiredText(displayText, "text_key"),
                    requiredText(displayText, "locale"),
                    requiredText(displayText, "resolution_type"),
                    optionalText(displayText, "metric_code"),
                    optionalText(displayText, "check_code"),
                    optionalText(displayText, "signal_key_pattern"),
                    optionalText(displayText, "input_kind"),
                    requiredText(displayText, "title_template"),
                    requiredText(displayText, "summary_template"),
                    requiredText(displayText, "why_it_matters_template"),
                    requiredText(displayText, "action_title_template"),
                    requiredText(displayText, "action_detail_template"),
                    requiredText(displayText, "completion_criterion_template"),
                    requiredText(displayText, "badge_label"),
                    requiredText(displayText, "severity_label"),
                    optionalText(displayText, "empty_state_title"),
                    optionalText(displayText, "empty_state_description"));
        }
    }

    private JsonNode resolutionContractSeed() {
        try (InputStream input = OfficialMetricPurposeContractCatalogWriter.class
                .getResourceAsStream(RESOLUTION_CONTRACT_SEED_RESOURCE)) {
            if (input == null) {
                throw new IllegalStateException("ENGINE_CONTRACT_ERROR: PQA resolution contract seed resource is missing."
                        + " resource=" + RESOLUTION_CONTRACT_SEED_RESOURCE);
            }
            return objectMapper.readTree(input);
        } catch (Exception exception) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: PQA resolution contract seed resource is unreadable."
                    + " resource=" + RESOLUTION_CONTRACT_SEED_RESOURCE, exception);
        }
    }

    private Iterable<JsonNode> requiredArray(JsonNode node, String fieldName) {
        JsonNode value = node == null ? null : node.get(fieldName);
        if (value == null || !value.isArray()) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: PQA resolution contract seed array is missing."
                    + " resource=" + RESOLUTION_CONTRACT_SEED_RESOURCE
                    + ", field=" + fieldName);
        }
        return value;
    }

    private String requiredText(JsonNode node, String fieldName) {
        String value = optionalText(node, fieldName);
        if (!StringUtils.hasText(value)) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: PQA resolution contract seed text is missing."
                    + " resource=" + RESOLUTION_CONTRACT_SEED_RESOURCE
                    + ", field=" + fieldName);
        }
        return value;
    }

    private String optionalText(JsonNode node, String fieldName) {
        JsonNode value = node == null ? null : node.get(fieldName);
        return value == null || value.isNull() ? null : value.asText();
    }

    private int requiredInt(JsonNode node, String fieldName) {
        JsonNode value = node == null ? null : node.get(fieldName);
        if (value == null || !value.canConvertToInt()) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: PQA resolution contract seed number is missing."
                    + " resource=" + RESOLUTION_CONTRACT_SEED_RESOURCE
                    + ", field=" + fieldName);
        }
        return value.asInt();
    }

    private boolean requiredBoolean(JsonNode node, String fieldName) {
        JsonNode value = node == null ? null : node.get(fieldName);
        if (value == null || !value.isBoolean()) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: PQA resolution contract seed boolean is missing."
                    + " resource=" + RESOLUTION_CONTRACT_SEED_RESOURCE
                    + ", field=" + fieldName);
        }
        return value.asBoolean();
    }

    private void refreshPromptRuntimeGovernanceActionPolicy() {
        if (!postgresqlDatabase()
                || !tableExists("prompt_runtime_governance_action_policy")
                || !functionExists("refresh_prompt_runtime_governance_action_policy")) {
            return;
        }
        jdbcTemplate.queryForObject("select refresh_prompt_runtime_governance_action_policy()", Integer.class);
    }

    private void upsertPromptRuntimeSlotContracts() {
        if (!postgresqlDatabase()
                || !tableExists("prompt_runtime_slot_contract")
                || !tableExists("prompt_runtime_metric_check_slot_contract")
                || !tableExists("official_prompt_signal_contract")
                || !tableExists("official_metric_evaluation_contract")) {
            return;
        }
        jdbcTemplate.update("""
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
                               updated_at = current_timestamp
                        """);
        jdbcTemplate.update("""
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
                               updated_at = current_timestamp
                        """);
        jdbcTemplate.update("""
                        delete from prompt_runtime_metric_check_slot_contract m
                         where not exists (
                               select 1
                                 from official_metric_evaluation_contract c
                                where c.contract_version = m.contract_version
                                  and c.metric_code = m.metric_code
                                  and c.check_code = m.check_code
                         )
                        """);
        jdbcTemplate.update("""
                        delete from prompt_runtime_slot_contract s
                         where not exists (
                               select 1
                                 from prompt_runtime_metric_check_slot_contract m
                                where m.contract_version = s.contract_version
                                  and m.prompt_key = s.prompt_key
                                  and m.slot_key = s.slot_key
                         )
                        """);
    }

    private void upsertPromptRuntimeGovernanceCheckActionContracts(
            String contractVersion,
            FinalPromptMetricContractCatalog catalog) {
        if (!postgresqlDatabase()
                || !tableExists("prompt_runtime_governance_check_action_contract")
                || !tableExists("prompt_runtime_governance_action_type_contract")) {
            return;
        }
        for (String metricCode : catalog.metricCodesInOrder()) {
            FinalPromptMetricContract metricContract = catalog.metric(metricCode);
            for (FinalPromptMetricCheckContract checkContract : metricContract.checks()) {
                jdbcTemplate.update("""
                                insert into prompt_runtime_governance_check_action_contract (
                                    contract_version, prompt_key, metric_code, check_code,
                                    action_type, action_reason, active, created_at, updated_at
                                ) values (?, 'SECURITY_DECISION', ?, ?, ?, ?, true, ?, ?)
                                on conflict (contract_version, prompt_key, metric_code, check_code) do update
                                   set action_type = excluded.action_type,
                                       action_reason = excluded.action_reason,
                                       active = true,
                                       updated_at = excluded.updated_at
                                """,
                        contractVersion,
                        metricCode,
                        checkContract.checkName(),
                        promptRuntimeGovernanceActionType(metricCode, checkContract),
                        promptRuntimeGovernanceActionReason(metricCode, checkContract),
                        nowTimestamp(),
                        nowTimestamp());
            }
        }
    }

    private void upsertPromptRuntimeGovernanceActionTypeContracts() {
        if (!postgresqlDatabase() || !tableExists("prompt_runtime_governance_action_type_contract")) {
            return;
        }
        List<PromptRuntimeGovernanceActionTypeSeed> seeds = List.of(
                new PromptRuntimeGovernanceActionTypeSeed(
                        "ADD_SLOT",
                        "SLOT_STRUCTURE",
                        "Add a required prompt slot before runtime rendering.",
                        "입력 항목 추가",
                        "다음 요청에 입력 추가",
                        "다음 LLM 입력을 만들기 전에 필요한 입력 항목을 추가합니다."),
                new PromptRuntimeGovernanceActionTypeSeed(
                        "UPDATE_SLOT_VALUE",
                        "SLOT_VALUE",
                        "Replace or enrich an existing prompt slot value.",
                        "입력값 정리",
                        "다음 요청에 값 정리",
                        "다음 LLM 입력을 만들기 전에 잘못되었거나 부족한 값을 정리합니다."),
                new PromptRuntimeGovernanceActionTypeSeed(
                        "ADD_NARRATIVE",
                        "SLOT_MEANING",
                        "Add decision meaning so the LLM can interpret the slot.",
                        "판단 설명 추가",
                        "다음 요청에 설명 반영",
                        "LLM이 입력값의 의미를 이해할 수 있도록 설명을 추가합니다."),
                new PromptRuntimeGovernanceActionTypeSeed(
                        "ADD_LIMITATION",
                        "SLOT_BOUNDARY",
                        "Add a limitation so unknown or thin evidence is not overclaimed.",
                        "판단 한계 추가",
                        "다음 요청에 한계 반영",
                        "알 수 없음, 부족한 근거, 임시 근거가 확정 근거처럼 보이지 않도록 한계를 추가합니다."),
                new PromptRuntimeGovernanceActionTypeSeed(
                        "SUPPRESS_SLOT",
                        "SLOT_STRUCTURE",
                        "Exclude a prompt slot that must not influence the LLM decision.",
                        "판단 근거 제외",
                        "다음 요청에서 제외",
                        "LLM 판단에 영향을 주면 안 되는 항목을 다음 입력에서 제외합니다."),
                new PromptRuntimeGovernanceActionTypeSeed(
                        "REORDER_SLOT",
                        "SLOT_ORDER",
                        "Change prompt slot order for decision priority.",
                        "표시 순서 조정",
                        "다음 요청 순서 조정",
                        "중요한 판단 항목이 다음 입력에서 먼저 보이도록 순서를 조정합니다."),
                new PromptRuntimeGovernanceActionTypeSeed(
                        "RAISE_PRIORITY",
                        "SLOT_PRIORITY",
                        "Raise a slot priority so it is protected from omission.",
                        "우선순위 높이기",
                        "다음 요청에서 우선 표시",
                        "필수 판단 항목이 누락되지 않도록 우선순위를 높입니다."),
                new PromptRuntimeGovernanceActionTypeSeed(
                        "FORBID_TRUNCATION",
                        "SLOT_TRUNCATION",
                        "Prevent required decision material from being truncated or replaced by placeholders.",
                        "잘림 방지",
                        "다음 요청에서 잘림 방지",
                        "필수 판단 항목이 줄임표나 자리표시자로 잘리지 않도록 보호합니다."),
                new PromptRuntimeGovernanceActionTypeSeed(
                        "REPLACE_SECTION_POLICY",
                        "SECTION_POLICY",
                        "Replace the section composition policy.",
                        "섹션 정책 변경",
                        "다음 요청 섹션 변경",
                        "다음 LLM 입력에서 해당 섹션을 조립하는 방식을 변경합니다."),
                new PromptRuntimeGovernanceActionTypeSeed(
                        "RECOLLECT_INPUT",
                        "INPUT_COLLECTION",
                        "Collect missing input again before prompt rendering.",
                        "입력 다시 수집",
                        "입력 다시 수집",
                        "프롬프트를 직접 바꾸지 않고 필요한 입력이나 증거를 다시 수집합니다.")
        );
        for (PromptRuntimeGovernanceActionTypeSeed seed : seeds) {
            jdbcTemplate.update("""
                            insert into prompt_runtime_governance_action_type_contract (
                                action_type, action_family, action_intent, active, created_at, updated_at,
                                display_label, button_label, customer_description
                            ) values (?, ?, ?, true, ?, ?, ?, ?, ?)
                            on conflict (action_type) do update
                               set action_family = excluded.action_family,
                                   action_intent = excluded.action_intent,
                                   display_label = excluded.display_label,
                                   button_label = excluded.button_label,
                                   customer_description = excluded.customer_description,
                                   active = true,
                                   updated_at = excluded.updated_at
                            """,
                    seed.actionType(),
                    seed.actionFamily(),
                    seed.actionIntent(),
                    nowTimestamp(),
                    nowTimestamp(),
                    seed.displayLabel(),
                    seed.buttonLabel(),
                    seed.customerDescription());
        }
    }

    private record PromptRuntimeGovernanceActionTypeSeed(
            String actionType,
            String actionFamily,
            String actionIntent,
            String displayLabel,
            String buttonLabel,
            String customerDescription) {
    }

    private String promptRuntimeGovernanceActionType(String metricCode, FinalPromptMetricCheckContract checkContract) {
        String checkName = normalizedUpper(checkContract.checkName());
        String failureType = normalizedUpper(checkContract.failureType());
        String source = normalizedUpper(checkContract.source());
        String combined = metricCode.toUpperCase(Locale.ROOT) + " " + checkName + " " + failureType + " " + source;
        if (combined.contains("TRUNCATED") || combined.contains("COMPACT") || combined.contains("PLACEHOLDER")) {
            return "FORBID_TRUNCATION";
        }
        if (combined.contains("REORDER") || combined.contains("STRONGEST_DELTA") || combined.contains("SUMMARY")) {
            return "REORDER_SLOT";
        }
        if (combined.contains("PRIORITY")) {
            return "RAISE_PRIORITY";
        }
        if ("COR".equalsIgnoreCase(metricCode)
                || combined.contains("INJECTION")
                || combined.contains("CONTAMINATION")
                || combined.contains("SUPPRESS")) {
            return "SUPPRESS_SLOT";
        }
        if ("MTR".equalsIgnoreCase(metricCode)
                || "PRE".equalsIgnoreCase(metricCode)
                || combined.contains("TRACE")
                || combined.contains("ELIGIBILITY")) {
            return "RECOLLECT_INPUT";
        }
        if ("CCSR".equalsIgnoreCase(metricCode)
                || combined.contains("CONSISTENT")
                || combined.contains("CONFLICT")) {
            return "UPDATE_SLOT_VALUE";
        }
        if (combined.contains("UNKNOWN")
                || combined.contains("NO_COMPARABLE")
                || combined.contains("NOT_OVERCLAIMED")
                || combined.contains("LIMITATION")) {
            return "ADD_LIMITATION";
        }
        if (combined.contains("SECTION_POLICY") || combined.contains("SESSION_FLOW")) {
            return "REPLACE_SECTION_POLICY";
        }
        return "ADD_NARRATIVE";
    }

    private String promptRuntimeGovernanceActionReason(String metricCode, FinalPromptMetricCheckContract checkContract) {
        if (StringUtils.hasText(checkContract.nextAction())) {
            return checkContract.nextAction();
        }
        if (StringUtils.hasText(checkContract.expectedMessage())) {
            return checkContract.expectedMessage();
        }
        if (StringUtils.hasText(checkContract.problemTitle())) {
            return checkContract.problemTitle();
        }
        return "Apply the prompt runtime governance action for "
                + metricCode + "." + checkContract.checkName() + ".";
    }

    private String normalizedUpper(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        return value.toUpperCase(Locale.ROOT);
    }

    private boolean tableExists(String tableName) {
        Integer count = jdbcTemplate.queryForObject("""
                        select count(*)
                          from information_schema.tables
                         where table_schema = 'public'
                           and table_name = ?
                        """,
                Integer.class,
                tableName);
        return count != null && count > 0;
    }

    private boolean functionExists(String functionName) {
        Integer count = jdbcTemplate.queryForObject("""
                        select count(*)
                          from pg_proc p
                          join pg_namespace n on n.oid = p.pronamespace
                         where n.nspname = 'public'
                           and p.proname = ?
                        """,
                Integer.class,
                functionName);
        return count != null && count > 0;
    }

    private void upsertSignalActionPolicy(
            String policyId,
            String resolutionType,
            String signalKeyPattern,
            String inputKind,
            String producerKeyPattern,
            String producerKey,
            String primaryActionType,
            String actionReadinessState,
            String requirementState,
            int priority) {
        String sql = postgresqlDatabase() ? """
                        insert into pqa_resolution_signal_action_policy (
                            policy_id, resolution_type, signal_key_pattern, input_kind, producer_key_pattern,
                            producer_key, primary_action_type, action_readiness_state, requirement_state,
                            priority, active, updated_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, true, ?)
                        on conflict (policy_id) do update
                           set resolution_type = excluded.resolution_type,
                               signal_key_pattern = excluded.signal_key_pattern,
                               input_kind = excluded.input_kind,
                               producer_key_pattern = excluded.producer_key_pattern,
                               producer_key = excluded.producer_key,
                               primary_action_type = excluded.primary_action_type,
                               action_readiness_state = excluded.action_readiness_state,
                               requirement_state = excluded.requirement_state,
                               priority = excluded.priority,
                               active = true,
                                updated_at = excluded.updated_at
                        """
                : """
                        merge into pqa_resolution_signal_action_policy (
                            policy_id, resolution_type, signal_key_pattern, input_kind, producer_key_pattern,
                            producer_key, primary_action_type, action_readiness_state, requirement_state,
                            priority, active, updated_at
                        ) key (policy_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, true, ?)
                        """;
        jdbcTemplate.update(sql,
                fit(policyId, 256),
                fit(resolutionType, 32),
                fit(signalKeyPattern, 512),
                fit(inputKind, 64),
                fit(producerKeyPattern, 256),
                fit(producerKey, 128),
                fit(primaryActionType, 128),
                fit(actionReadinessState, 64),
                fit(requirementState, 64),
                priority,
                nowTimestamp());
    }

    private void upsertResolutionAction(
            String actionType,
            String resolutionType,
            String label,
            String description,
            String targetPage,
            String routeTemplate,
            String executionMode,
            String primaryButtonLabel,
            String successMessage,
            String failureMessage,
            int expectedDurationSeconds,
            String allowedStateFrom,
            String allowedStateTo,
            String completionEventType,
            String completionQueryKey,
            boolean requiresConfirmation,
            String idempotencyPolicy) {
        String sql = postgresqlDatabase() ? """
                        insert into pqa_resolution_action_catalog (
                            action_type, resolution_type, label, description, target_page, route_template,
                            required_params_json, execution_mode, primary_button_label,
                            success_message_template, failure_message_template, expected_duration_seconds,
                            allowed_state_from, allowed_state_to, completion_event_type, completion_query_key,
                            requires_confirmation, idempotency_policy, active, updated_at
                        ) values (?, ?, ?, ?, ?, ?, ?::jsonb, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, true, ?)
                        on conflict (action_type) do update
                           set resolution_type = excluded.resolution_type,
                               label = excluded.label,
                               description = excluded.description,
                               target_page = excluded.target_page,
                               route_template = excluded.route_template,
                               required_params_json = excluded.required_params_json,
                               execution_mode = excluded.execution_mode,
                               primary_button_label = excluded.primary_button_label,
                               success_message_template = excluded.success_message_template,
                               failure_message_template = excluded.failure_message_template,
                               expected_duration_seconds = excluded.expected_duration_seconds,
                               allowed_state_from = excluded.allowed_state_from,
                               allowed_state_to = excluded.allowed_state_to,
                               completion_event_type = excluded.completion_event_type,
                               completion_query_key = excluded.completion_query_key,
                               requires_confirmation = excluded.requires_confirmation,
                               idempotency_policy = excluded.idempotency_policy,
                               active = true,
                               updated_at = excluded.updated_at
                        """
                : """
                        merge into pqa_resolution_action_catalog (
                            action_type, resolution_type, label, description, target_page, route_template,
                            required_params_json, execution_mode, primary_button_label,
                            success_message_template, failure_message_template, expected_duration_seconds,
                            allowed_state_from, allowed_state_to, completion_event_type, completion_query_key,
                            requires_confirmation, idempotency_policy, active, updated_at
                        ) key (action_type) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, true, ?)
                        """;
        jdbcTemplate.update(sql,
                fit(actionType, 128),
                fit(resolutionType, 32),
                fit(label, 256),
                description,
                fit(targetPage, 512),
                fit(routeTemplate, 1024),
                "[]",
                fit(executionMode, 64),
                fit(primaryButtonLabel, 256),
                successMessage,
                failureMessage,
                expectedDurationSeconds,
                fit(allowedStateFrom, 128),
                fit(allowedStateTo, 128),
                fit(completionEventType, 128),
                fit(completionQueryKey, 256),
                requiresConfirmation,
                fit(idempotencyPolicy, 128),
                nowTimestamp());
    }

    private void deactivateNonCurrentContractVersions(String currentVersion) {
        jdbcTemplate.update("""
                        update official_metric_contract_version
                           set active = false
                         where contract_version <> ?
                        """,
                currentVersion);
    }

    private void upsertMetricPurposeContract(
            String purposeVersion,
            String metricCode,
            FinalPromptMetricContract metricContract,
            FinalPromptMetricCheckContract checkContract) {
        if (postgresqlDatabase()) {
            jdbcTemplate.update("""
                            insert into official_metric_contract_version (
                                contract_version, source_artifact, active, created_at
                            ) values (?, ?, ?, ?)
                            on conflict (contract_version) do update
                               set source_artifact = excluded.source_artifact,
                                   active = excluded.active
                            """,
                    fit(purposeVersion, 128),
                    "classpath:pqa/final-prompt-metric-contracts.json",
                    true,
                    nowTimestamp());
            jdbcTemplate.update("""
                            insert into official_metric_purpose_contract (
                                contract_version, metric_code, purpose_statement, decision_question,
                                customer_visible, metric_role, blocks_llm_submission, blocks_certificate, created_at
                            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            on conflict (contract_version, metric_code) do update
                               set purpose_statement = excluded.purpose_statement,
                                   decision_question = excluded.decision_question,
                                   customer_visible = excluded.customer_visible,
                                   metric_role = excluded.metric_role,
                                   blocks_llm_submission = excluded.blocks_llm_submission,
                                   blocks_certificate = excluded.blocks_certificate
                            """,
                    fit(purposeVersion, 128),
                    fit(metricCode, 32),
                    metricContract.purpose(),
                    metricContract.qualityQuestion(),
                    metricContract.checks().stream().anyMatch(FinalPromptMetricCheckContract::customerVisible),
                    fit(metricContract.metricRole(), 128),
                    metricContract.blocksLlmSubmission(),
                    metricContract.blocksCertificate(),
                    nowTimestamp());
            jdbcTemplate.update("""
                            insert into official_metric_evaluation_contract (
                                contract_version, metric_code, check_code, purpose_question,
                                pass_condition, fail_condition, issue_key, customer_visible,
                                readiness_scope, problem_title, short_problem, expected_message,
                                pass_message, failure_message, created_at
                            )
                            select ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                             on conflict (contract_version, metric_code, check_code) do update
                                set purpose_question = excluded.purpose_question,
                                    pass_condition = excluded.pass_condition,
                                    fail_condition = excluded.fail_condition,
                                    issue_key = excluded.issue_key,
                                    customer_visible = excluded.customer_visible,
                                    readiness_scope = excluded.readiness_scope,
                                    problem_title = excluded.problem_title,
                                    short_problem = excluded.short_problem,
                                    expected_message = excluded.expected_message,
                                    pass_message = excluded.pass_message,
                                    failure_message = excluded.failure_message
                             """,
                    fit(purposeVersion, 128),
                    fit(metricCode, 32),
                    fit(checkContract.checkName(), 128),
                    checkContract.qualityQuestion(),
                    checkContract.passMessage(),
                    checkContract.failureMessage(),
                    fit(checkContract.issueKey(), 512),
                    checkContract.customerVisible(),
                    fit(checkContract.readinessScope(), 128),
                    checkContract.problemTitle(),
                    checkContract.shortProblem(),
                    checkContract.expectedMessage(),
                    checkContract.passMessage(),
                    checkContract.failureMessage(),
                    nowTimestamp());
        } else {
            jdbcTemplate.update("""
                            merge into official_metric_contract_version (
                                contract_version, source_artifact, active, created_at
                            ) key (contract_version) values (?, ?, ?, ?)
                            """,
                    fit(purposeVersion, 128),
                    "classpath:pqa/final-prompt-metric-contracts.json",
                    true,
                    nowTimestamp());
            jdbcTemplate.update("""
                            merge into official_metric_purpose_contract (
                                contract_version, metric_code, purpose_statement, decision_question,
                                customer_visible, metric_role, blocks_llm_submission, blocks_certificate, created_at
                            ) key (contract_version, metric_code) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                    fit(purposeVersion, 128),
                    fit(metricCode, 32),
                    metricContract.purpose(),
                    metricContract.qualityQuestion(),
                    metricContract.checks().stream().anyMatch(FinalPromptMetricCheckContract::customerVisible),
                    fit(metricContract.metricRole(), 128),
                    metricContract.blocksLlmSubmission(),
                    metricContract.blocksCertificate(),
                    nowTimestamp());
            jdbcTemplate.update("""
                            merge into official_metric_evaluation_contract (
                                contract_version, metric_code, check_code, purpose_question,
                                pass_condition, fail_condition, issue_key, customer_visible,
                                readiness_scope, problem_title, short_problem, expected_message,
                                pass_message, failure_message, created_at
                            ) key (contract_version, metric_code, check_code) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                    fit(purposeVersion, 128),
                    fit(metricCode, 32),
                    fit(checkContract.checkName(), 128),
                    checkContract.qualityQuestion(),
                    checkContract.passMessage(),
                    checkContract.failureMessage(),
                    fit(checkContract.issueKey(), 512),
                    checkContract.customerVisible(),
                    fit(checkContract.readinessScope(), 128),
                    checkContract.problemTitle(),
                    checkContract.shortProblem(),
                    checkContract.expectedMessage(),
                    checkContract.passMessage(),
                    checkContract.failureMessage(),
                    nowTimestamp());
        }
        upsertMetricInputContract(purposeVersion, metricCode, checkContract);
        upsertMetricSignalContract(purposeVersion, metricCode, checkContract);
        upsertMetricCustomerMessageContract(purposeVersion, metricCode, metricContract, checkContract);
        upsertMetricCustomerDisplayContracts(purposeVersion, metricCode, checkContract);
    }

    private void upsertMetricInputContract(
            String purposeVersion,
            String metricCode,
            FinalPromptMetricCheckContract checkContract) {
        for (MetricInputRequirement input : contractInputRequirements(checkContract.rule())) {
            upsertMetricInputContractRow(purposeVersion, metricCode, checkContract, input, checkContract.failureType());
        }
        if (checkContract.inputReadinessRule() != null) {
            for (MetricInputRequirement input : contractInputRequirements(checkContract.inputReadinessRule())) {
                upsertMetricInputContractRow(purposeVersion, metricCode, checkContract, input, "INPUT_READINESS");
            }
        }
        if (checkContract.applicabilityRule() != null) {
            for (MetricInputRequirement input : contractInputRequirements(checkContract.applicabilityRule())) {
                upsertMetricInputContractRow(purposeVersion, metricCode, checkContract, input, "APPLICABILITY");
            }
        }
    }

    private void upsertMetricInputContractRow(
            String purposeVersion,
            String metricCode,
            FinalPromptMetricCheckContract checkContract,
            MetricInputRequirement input,
            String purposeScope) {
            if (postgresqlDatabase()) {
                jdbcTemplate.update("""
                            insert into official_metric_input_contract (
                                contract_version, metric_code, check_code, input_key,
                                required_policy, absence_policy, purpose_scope, created_at
                            ) values (?, ?, ?, ?, ?, ?, ?, ?)
                            on conflict (contract_version, metric_code, check_code, input_key) do update
                               set required_policy = excluded.required_policy,
                                   absence_policy = excluded.absence_policy,
                                   purpose_scope = excluded.purpose_scope
                            """,
                    fit(purposeVersion, 128),
                    fit(metricCode, 32),
                    fit(checkContract.checkName(), 128),
                    fit(input.inputKey(), 256),
                    fit(input.requiredPolicy(), 128),
                    fit(input.absencePolicy(), 128),
                    fit(purposeScope, 128),
                    nowTimestamp());
            } else {
                jdbcTemplate.update("""
                                merge into official_metric_input_contract (
                                    contract_version, metric_code, check_code, input_key,
                                    required_policy, absence_policy, purpose_scope, created_at
                                ) key (contract_version, metric_code, check_code, input_key) values (?, ?, ?, ?, ?, ?, ?, ?)
                                """,
                        fit(purposeVersion, 128),
                        fit(metricCode, 32),
                        fit(checkContract.checkName(), 128),
                        fit(input.inputKey(), 256),
                        fit(input.requiredPolicy(), 128),
                        fit(input.absencePolicy(), 128),
                        fit(purposeScope, 128),
                        nowTimestamp());
            }
    }

    private void upsertMetricSignalContract(
            String purposeVersion,
            String metricCode,
            FinalPromptMetricCheckContract checkContract) {
        for (String signalKey : contractInputKeys(checkContract.rule())) {
            upsertMetricSignalContractRow(
                    purposeVersion,
                    metricCode,
                    checkContract,
                    signalKey,
                    ruleOperator(checkContract.rule()),
                    checkContract.failureType());
        }
        if (checkContract.inputReadinessRule() != null) {
            for (String signalKey : contractInputKeys(checkContract.inputReadinessRule())) {
                upsertMetricSignalContractRow(
                        purposeVersion,
                        metricCode,
                        checkContract,
                        signalKey,
                        ruleOperator(checkContract.inputReadinessRule()),
                        "INPUT_READINESS");
            }
        }
        if (checkContract.applicabilityRule() != null) {
            for (String signalKey : contractInputKeys(checkContract.applicabilityRule())) {
                upsertMetricSignalContractRow(
                        purposeVersion,
                        metricCode,
                        checkContract,
                        signalKey,
                        ruleOperator(checkContract.applicabilityRule()),
                        "APPLICABILITY");
            }
        }
    }

    private void upsertMetricSignalContractRow(
            String purposeVersion,
            String metricCode,
            FinalPromptMetricCheckContract checkContract,
            String signalKey,
            String requiredRole,
            String interpretationRole) {
            if (postgresqlDatabase()) {
                jdbcTemplate.update("""
                            insert into official_prompt_signal_contract (
                                contract_version, metric_code, check_code, signal_key,
                                prompt_location, required_role, interpretation_role, created_at
                            ) values (?, ?, ?, ?, ?, ?, ?, ?)
                            on conflict (contract_version, metric_code, check_code, signal_key) do update
                               set prompt_location = excluded.prompt_location,
                                   required_role = excluded.required_role,
                                   interpretation_role = excluded.interpretation_role
                            """,
                    fit(purposeVersion, 128),
                    fit(metricCode, 32),
                    fit(checkContract.checkName(), 128),
                    fit(signalKey, 256),
                    fit(checkContract.source(), 512),
                    fit(requiredRole, 128),
                    fit(interpretationRole, 128),
                    nowTimestamp());
            } else {
                jdbcTemplate.update("""
                                merge into official_prompt_signal_contract (
                                    contract_version, metric_code, check_code, signal_key,
                                    prompt_location, required_role, interpretation_role, created_at
                                ) key (contract_version, metric_code, check_code, signal_key) values (?, ?, ?, ?, ?, ?, ?, ?)
                                """,
                        fit(purposeVersion, 128),
                        fit(metricCode, 32),
                        fit(checkContract.checkName(), 128),
                        fit(signalKey, 256),
                        fit(checkContract.source(), 512),
                        fit(requiredRole, 128),
                        fit(interpretationRole, 128),
                        nowTimestamp());
            }
    }

    private void upsertPromptSignalRegistryContracts(
            String purposeVersion,
            FinalPromptMetricContractCatalog catalog) {
        for (FinalPromptMetricContractCatalog.PromptSignalContract signal : catalog.promptSignalContracts()) {
            if (postgresqlDatabase()) {
                jdbcTemplate.update("""
                            insert into official_prompt_signal_contract (
                                contract_version, metric_code, check_code, signal_key,
                                prompt_location, required_role, interpretation_role, created_at
                            ) values (?, ?, ?, ?, ?, ?, ?, ?)
                            on conflict (contract_version, metric_code, check_code, signal_key) do update
                               set prompt_location = excluded.prompt_location,
                                   required_role = excluded.required_role,
                                   interpretation_role = excluded.interpretation_role
                            """,
                    fit(purposeVersion, 128),
                    "MTR",
                    fit(signal.checkCode(), 128),
                    fit(signal.signalKey(), 256),
                    fit(signal.promptLocation(), 512),
                    fit(signal.requiredRole(), 128),
                    fit(signal.interpretationRole(), 128),
                    nowTimestamp());
            } else {
                jdbcTemplate.update("""
                                merge into official_prompt_signal_contract (
                                    contract_version, metric_code, check_code, signal_key,
                                    prompt_location, required_role, interpretation_role, created_at
                                ) key (contract_version, metric_code, check_code, signal_key) values (?, ?, ?, ?, ?, ?, ?, ?)
                                """,
                        fit(purposeVersion, 128),
                        "MTR",
                        fit(signal.checkCode(), 128),
                        fit(signal.signalKey(), 256),
                        fit(signal.promptLocation(), 512),
                        fit(signal.requiredRole(), 128),
                        fit(signal.interpretationRole(), 128),
                        nowTimestamp());
            }
        }
    }

    private void upsertMetricCustomerMessageContract(
            String purposeVersion,
            String metricCode,
            FinalPromptMetricContract metricContract,
            FinalPromptMetricCheckContract checkContract) {
        if (postgresqlDatabase()) {
            jdbcTemplate.update("""
                        insert into official_metric_customer_message_contract (
                            contract_version, metric_code, check_code,
                            problem_title, short_problem, why_it_matters,
                            fix_action, reverify_criterion, metric_purpose,
                            blocked_reason, created_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        on conflict (contract_version, metric_code, check_code) do update
                           set problem_title = excluded.problem_title,
                               short_problem = excluded.short_problem,
                               why_it_matters = excluded.why_it_matters,
                               fix_action = excluded.fix_action,
                               reverify_criterion = excluded.reverify_criterion,
                               metric_purpose = excluded.metric_purpose,
                               blocked_reason = excluded.blocked_reason
                        """,
                fit(purposeVersion, 128),
                fit(metricCode, 32),
                fit(checkContract.checkName(), 128),
                checkContract.problemTitle(),
                checkContract.shortProblem(),
                checkContract.whyItMatters(),
                checkContract.nextAction(),
                checkContract.reverifyCriterion(),
                metricContract.purpose(),
                checkContract.failureMessage(),
                nowTimestamp());
        } else {
            jdbcTemplate.update("""
                            merge into official_metric_customer_message_contract (
                                contract_version, metric_code, check_code,
                                problem_title, short_problem, why_it_matters,
                                fix_action, reverify_criterion, metric_purpose,
                                blocked_reason, created_at
                            ) key (contract_version, metric_code, check_code) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                    fit(purposeVersion, 128),
                    fit(metricCode, 32),
                    fit(checkContract.checkName(), 128),
                    checkContract.problemTitle(),
                    checkContract.shortProblem(),
                    checkContract.whyItMatters(),
                    checkContract.nextAction(),
                    checkContract.reverifyCriterion(),
                    metricContract.purpose(),
                    checkContract.failureMessage(),
                    nowTimestamp());
        }
    }

    private void upsertMetricCustomerDisplayContracts(
            String purposeVersion,
            String metricCode,
            FinalPromptMetricCheckContract checkContract) {
        if (!customerDisplayEligible(checkContract)) {
            return;
        }
        upsertMetricCustomerDisplayContractRow(
                purposeVersion,
                metricCode,
                checkContract.checkName(),
                "TITLE",
                checkContract.problemTitle(),
                checkContract.customerVisible());
        upsertMetricCustomerDisplayContractRow(
                purposeVersion,
                metricCode,
                checkContract.checkName(),
                "PASS_EVIDENCE",
                checkContract.passEvidenceTemplate(),
                checkContract.customerVisible());
        upsertMetricCustomerDisplayContractRow(
                purposeVersion,
                metricCode,
                checkContract.checkName(),
                "FAIL_EVIDENCE",
                checkContract.failureEvidenceTemplate(),
                checkContract.customerVisible());
        upsertMetricCustomerDisplayContractRow(
                purposeVersion,
                metricCode,
                checkContract.checkName(),
                "WHY_IT_MATTERS",
                checkContract.whyItMatters(),
                checkContract.customerVisible());
        upsertMetricCustomerDisplayContractRow(
                purposeVersion,
                metricCode,
                checkContract.checkName(),
                "RESOLUTION_ACTION",
                checkContract.nextAction(),
                checkContract.customerVisible());
        upsertMetricCustomerDisplayContractRow(
                purposeVersion,
                metricCode,
                checkContract.checkName(),
                "REVERIFY_CONDITION",
                checkContract.reverifyCriterion(),
                checkContract.customerVisible());
        for (Map<String, String> binding : safeEvidenceBindings(checkContract)) {
            upsertMetricCustomerDisplayBindingRow(
                    purposeVersion,
                    metricCode,
                    checkContract.checkName(),
                    "PASS_EVIDENCE",
                    binding);
            upsertMetricCustomerDisplayBindingRow(
                    purposeVersion,
                    metricCode,
                    checkContract.checkName(),
                    "FAIL_EVIDENCE",
                    binding);
        }
    }

    private void upsertMetricCheckDisplayEvidenceContract(
            String purposeVersion,
            String metricCode,
            FinalPromptMetricCheckContract checkContract) {
        if (checkContract == null) {
            throw new IllegalStateException("Metric check display evidence contract requires a check contract.");
        }
        String criterionTemplate = firstNonBlank(
                checkContract.expectedMessage(),
                checkContract.qualityQuestion(),
                checkContract.passMessage());
        String judgmentTemplate = firstNonBlank(
                checkContract.passEvidenceTemplate(),
                checkContract.passMessage());
        String failureJudgmentTemplate = firstNonBlank(
                checkContract.failureEvidenceTemplate(),
                checkContract.failureMessage());
        if (!StringUtils.hasText(criterionTemplate)
                || !StringUtils.hasText(judgmentTemplate)
                || !StringUtils.hasText(failureJudgmentTemplate)) {
            throw new IllegalStateException("Metric check display evidence contract is incomplete."
                    + " metric=" + metricCode + ", check=" + checkContract.checkName());
        }
        String runtimeBindingsJson = writeJson(runtimeFactBindings(checkContract));
        String contextBindingsJson = writeJson(contextItemBindings(checkContract));
        String sql = postgresqlDatabase() ? """
                        insert into official_metric_check_display_evidence_contract (
                            contract_version, metric_code, check_code,
                            criterion_template, judgment_template, failure_judgment_template,
                            not_applicable_judgment_template, runtime_fact_bindings_json,
                            context_item_bindings_json, readiness_scope, customer_visible, created_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        on conflict (contract_version, metric_code, check_code) do update
                           set criterion_template = excluded.criterion_template,
                               judgment_template = excluded.judgment_template,
                               failure_judgment_template = excluded.failure_judgment_template,
                               not_applicable_judgment_template = excluded.not_applicable_judgment_template,
                               runtime_fact_bindings_json = excluded.runtime_fact_bindings_json,
                               context_item_bindings_json = excluded.context_item_bindings_json,
                               readiness_scope = excluded.readiness_scope,
                               customer_visible = excluded.customer_visible
                        """
                : """
                        merge into official_metric_check_display_evidence_contract (
                            contract_version, metric_code, check_code,
                            criterion_template, judgment_template, failure_judgment_template,
                            not_applicable_judgment_template, runtime_fact_bindings_json,
                            context_item_bindings_json, readiness_scope, customer_visible, created_at
                        ) key (contract_version, metric_code, check_code) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """;
        jdbcTemplate.update(sql,
                fit(purposeVersion, 128),
                fit(metricCode, 32),
                fit(checkContract.checkName(), 128),
                criterionTemplate,
                judgmentTemplate,
                failureJudgmentTemplate,
                firstNonBlank(checkContract.notApplicableMessage(), ""),
                runtimeBindingsJson,
                contextBindingsJson,
                fit(firstNonBlank(checkContract.readinessScope(), "CUSTOMER_PROMPT_QUALITY"), 128),
                checkContract.customerVisible(),
                nowTimestamp());
    }

    private boolean customerDisplayEligible(FinalPromptMetricCheckContract checkContract) {
        return checkContract != null
                && (checkContract.customerVisible()
                || "INTERNAL_EXECUTION_GATE".equalsIgnoreCase(checkContract.readinessScope()));
    }

    private void upsertMetricCustomerDisplayContractRow(
            String purposeVersion,
            String metricCode,
            String checkCode,
            String displayRole,
            String displayTemplate,
            boolean customerVisible) {
        if (!StringUtils.hasText(displayTemplate)) {
            throw new IllegalStateException("Customer display contract template is required."
                    + " metric=" + metricCode + ", check=" + checkCode + ", role=" + displayRole);
        }
        if (postgresqlDatabase()) {
            jdbcTemplate.update("""
                            insert into official_metric_customer_display_contract (
                                contract_version, metric_code, check_code, display_role,
                                display_template, customer_visible, created_at
                            ) values (?, ?, ?, ?, ?, ?, ?)
                            on conflict (contract_version, metric_code, check_code, display_role) do update
                               set display_template = excluded.display_template,
                                   customer_visible = excluded.customer_visible
                            """,
                    fit(purposeVersion, 128),
                    fit(metricCode, 32),
                    fit(checkCode, 128),
                    fit(displayRole, 64),
                    displayTemplate,
                    customerVisible,
                    nowTimestamp());
        } else {
            jdbcTemplate.update("""
                            merge into official_metric_customer_display_contract (
                                contract_version, metric_code, check_code, display_role,
                                display_template, customer_visible, created_at
                            ) key (contract_version, metric_code, check_code, display_role) values (?, ?, ?, ?, ?, ?, ?)
                            """,
                    fit(purposeVersion, 128),
                    fit(metricCode, 32),
                    fit(checkCode, 128),
                    fit(displayRole, 64),
                    displayTemplate,
                    customerVisible,
                    nowTimestamp());
        }
    }

    private void upsertMetricCustomerDisplayBindingRow(
            String purposeVersion,
            String metricCode,
            String checkCode,
            String displayRole,
            Map<String, String> binding) {
        String bindingKey = firstNonBlank(binding.get("id"), binding.get("name"));
        String sourceFactKey = firstNonBlank(binding.get("labels"), binding.get("label"), binding.get("source"));
        if (!StringUtils.hasText(bindingKey) || !StringUtils.hasText(sourceFactKey)) {
            throw new IllegalStateException("Customer display binding must declare id and source fact."
                    + " metric=" + metricCode + ", check=" + checkCode + ", role=" + displayRole);
        }
        if (postgresqlDatabase()) {
            jdbcTemplate.update("""
                            insert into official_metric_customer_display_binding (
                                contract_version, metric_code, check_code, display_role,
                                binding_key, source_fact_key, required, created_at
                            ) values (?, ?, ?, ?, ?, ?, ?, ?)
                            on conflict (contract_version, metric_code, check_code, display_role, binding_key) do update
                               set source_fact_key = excluded.source_fact_key,
                                   required = excluded.required
                            """,
                    fit(purposeVersion, 128),
                    fit(metricCode, 32),
                    fit(checkCode, 128),
                    fit(displayRole, 64),
                    fit(bindingKey, 256),
                    fit(sourceFactKey, 256),
                    true,
                    nowTimestamp());
        } else {
            jdbcTemplate.update("""
                            merge into official_metric_customer_display_binding (
                                contract_version, metric_code, check_code, display_role,
                                binding_key, source_fact_key, required, created_at
                            ) key (contract_version, metric_code, check_code, display_role, binding_key) values (?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                    fit(purposeVersion, 128),
                    fit(metricCode, 32),
                    fit(checkCode, 128),
                    fit(displayRole, 64),
                    fit(bindingKey, 256),
                    fit(sourceFactKey, 256),
                    true,
                    nowTimestamp());
        }
    }

    private static List<Map<String, String>> safeEvidenceBindings(FinalPromptMetricCheckContract checkContract) {
        return checkContract.evidenceBindings() == null ? List.of() : checkContract.evidenceBindings();
    }

    private List<Map<String, String>> runtimeFactBindings(FinalPromptMetricCheckContract checkContract) {
        List<Map<String, String>> rows = new ArrayList<>();
        for (Map<String, String> binding : safeEvidenceBindings(checkContract)) {
            if (binding == null) {
                continue;
            }
            String bindingKey = firstNonBlank(binding.get("id"), binding.get("name"));
            String sourceFactKey = firstNonBlank(
                    binding.get("runtimeFactItems"),
                    binding.get("customerVisibleRuntimeItems"),
                    binding.get("sourceFactKey"),
                    binding.get("labels"),
                    binding.get("label"),
                    binding.get("sections"),
                    binding.get("tokens"),
                    binding.get("source"));
            if (!StringUtils.hasText(bindingKey) || !StringUtils.hasText(sourceFactKey)) {
                throw new IllegalStateException("Metric check display evidence runtime binding is incomplete."
                        + " metric=" + checkContract.metricCode() + ", check=" + checkContract.checkName());
            }
            Map<String, String> row = new LinkedHashMap<>();
            row.put("bindingKey", bindingKey);
            row.put("source", firstNonBlank(binding.get("source"), "CONTRACT_BINDING"));
            row.put("sourceFactKey", sourceFactKey);
            if (StringUtils.hasText(binding.get("runtimeFactItems"))) {
                row.put("runtimeFactItems", binding.get("runtimeFactItems"));
            }
            if (StringUtils.hasText(binding.get("customerVisibleRuntimeItems"))) {
                row.put("customerVisibleRuntimeItems", binding.get("customerVisibleRuntimeItems"));
            }
            row.put("valueRole", firstNonBlank(binding.get("valueRole"), "runtimeFact"));
            rows.add(row);
        }
        if (rows.isEmpty()) {
            throw new IllegalStateException("Metric check display evidence runtime bindings are required."
                    + " metric=" + checkContract.metricCode() + ", check=" + checkContract.checkName());
        }
        return List.copyOf(rows);
    }

    private List<String> contextItemBindings(FinalPromptMetricCheckContract checkContract) {
        LinkedHashSet<String> items = new LinkedHashSet<>();
        for (Map<String, String> binding : safeEvidenceBindings(checkContract)) {
            if (binding == null) {
                continue;
            }
            appendContextBindingItems(items, binding.get("customerVisibleContextItems"));
            appendContextBindingItems(items, binding.get("contextItems"));
            appendContextBindingItems(items, binding.get("customerVisiblePromptItems"));
            appendContextBindingItems(items, binding.get("promptItems"));
        }
        if (items.isEmpty()) {
            throw new IllegalStateException("Metric check display evidence context item bindings are required."
                    + " metric=" + checkContract.metricCode() + ", check=" + checkContract.checkName());
        }
        return List.copyOf(items);
    }

    private void appendContextBindingItems(LinkedHashSet<String> items, String value) {
        if (items == null || !StringUtils.hasText(value)) {
            return;
        }
        for (String token : value.split("[,|]")) {
            String item = token == null ? "" : token.trim();
            if (StringUtils.hasText(item)) {
                items.add(item);
            }
        }
    }

    private String writeJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value == null ? List.of() : value);
        } catch (Exception e) {
            throw new IllegalStateException("Metric check display evidence contract JSON serialization failed.", e);
        }
    }

    private void upsertResolutionDisplayTextRow(
            String textId,
            String textKey,
            String locale,
            String resolutionType,
            String metricCode,
            String checkCode,
            String signalKeyPattern,
            String inputKind,
            String titleTemplate,
            String summaryTemplate,
            String whyItMattersTemplate,
            String actionTitleTemplate,
            String actionDetailTemplate,
            String completionCriterionTemplate,
            String badgeLabel,
            String severityLabel,
            String emptyStateTitle,
            String emptyStateDescription) {
        Timestamp now = nowTimestamp();
        int updated = jdbcTemplate.update("""
                        update pqa_resolution_display_text_contract
                           set text_key = ?,
                               title_template = ?,
                               summary_template = ?,
                               why_it_matters_template = ?,
                               action_title_template = ?,
                               action_detail_template = ?,
                               completion_criterion_template = ?,
                               badge_label = ?,
                               severity_label = ?,
                               empty_state_title = ?,
                               empty_state_description = ?,
                               active = true,
                               updated_at = ?
                         where locale = ?
                           and resolution_type = ?
                           and coalesce(metric_code, '') = coalesce(?, '')
                           and coalesce(check_code, '') = coalesce(?, '')
                           and coalesce(signal_key_pattern, '') = coalesce(?, '')
                           and coalesce(input_kind, '') = coalesce(?, '')
                        """,
                fit(textKey, 256),
                titleTemplate,
                summaryTemplate,
                whyItMattersTemplate,
                actionTitleTemplate,
                actionDetailTemplate,
                completionCriterionTemplate,
                fit(badgeLabel, 128),
                fit(severityLabel, 128),
                emptyStateTitle,
                emptyStateDescription,
                now,
                fit(locale, 32),
                fit(resolutionType, 32),
                fit(metricCode, 32),
                fit(checkCode, 128),
                fit(signalKeyPattern, 512),
                fit(inputKind, 64));
        if (updated > 0) {
            return;
        }

        updated = jdbcTemplate.update("""
                        update pqa_resolution_display_text_contract
                           set text_key = ?,
                               locale = ?,
                               resolution_type = ?,
                               metric_code = ?,
                               check_code = ?,
                               signal_key_pattern = ?,
                               input_kind = ?,
                               title_template = ?,
                               summary_template = ?,
                               why_it_matters_template = ?,
                               action_title_template = ?,
                               action_detail_template = ?,
                               completion_criterion_template = ?,
                               badge_label = ?,
                               severity_label = ?,
                               empty_state_title = ?,
                               empty_state_description = ?,
                               active = true,
                               updated_at = ?
                         where text_id = ?
                        """,
                fit(textKey, 256),
                fit(locale, 32),
                fit(resolutionType, 32),
                fit(metricCode, 32),
                fit(checkCode, 128),
                fit(signalKeyPattern, 512),
                fit(inputKind, 64),
                titleTemplate,
                summaryTemplate,
                whyItMattersTemplate,
                actionTitleTemplate,
                actionDetailTemplate,
                completionCriterionTemplate,
                fit(badgeLabel, 128),
                fit(severityLabel, 128),
                emptyStateTitle,
                emptyStateDescription,
                now,
                fit(textId, 256));
        if (updated > 0) {
            return;
        }

        jdbcTemplate.update("""
                        insert into pqa_resolution_display_text_contract (
                            text_id, text_key, locale, resolution_type, metric_code, check_code,
                            signal_key_pattern, input_kind, title_template, summary_template,
                            why_it_matters_template, action_title_template, action_detail_template,
                            completion_criterion_template, badge_label, severity_label,
                            empty_state_title, empty_state_description, active, updated_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, true, ?)
                        """,
                fit(textId, 256),
                fit(textKey, 256),
                fit(locale, 32),
                fit(resolutionType, 32),
                fit(metricCode, 32),
                fit(checkCode, 128),
                fit(signalKeyPattern, 512),
                fit(inputKind, 64),
                titleTemplate,
                summaryTemplate,
                whyItMattersTemplate,
                actionTitleTemplate,
                actionDetailTemplate,
                completionCriterionTemplate,
                fit(badgeLabel, 128),
                fit(severityLabel, 128),
                emptyStateTitle,
                emptyStateDescription,
                now);
    }

    private FinalPromptMetricContractCatalog finalPromptMetricContractCatalog() {
        if (finalPromptMetricContractCatalog == null) {
            finalPromptMetricContractCatalog = FinalPromptMetricContractCatalog.load(objectMapper);
        }
        return finalPromptMetricContractCatalog;
    }

    private String currentContractVersion(FinalPromptMetricContractCatalog catalog) {
        String version = null;
        for (String metricCode : catalog.metricCodesInOrder()) {
            String next = catalog.metric(metricCode).version();
            if (!StringUtils.hasText(next)) {
                throw new IllegalStateException("Final prompt metric contract version is required. metricCode="
                        + metricCode);
            }
            if (version == null) {
                version = next.trim();
            } else if (!version.equals(next.trim())) {
                throw new IllegalStateException("Final prompt metric contracts must use one active version."
                        + " expected=" + version + ", actual=" + next + ", metricCode=" + metricCode);
            }
        }
        if (!StringUtils.hasText(version)) {
            throw new IllegalStateException("Final prompt metric contract catalog is empty.");
        }
        return version;
    }

    private List<MetricInputRequirement> contractInputRequirements(FinalPromptMetricRule rule) {
        LinkedHashMap<String, MetricInputRequirement> values = new LinkedHashMap<>();
        collectContractInputRequirements(rule, values);
        if (values.isEmpty()) {
            throw new IllegalStateException("Final prompt metric check contract has no input requirements. operator="
                    + ruleOperator(rule));
        }
        return List.copyOf(values.values());
    }

    private void collectContractInputRequirements(
            FinalPromptMetricRule rule,
            LinkedHashMap<String, MetricInputRequirement> values) {
        if (rule == null || values == null) {
            return;
        }
        String operator = ruleOperator(rule).toUpperCase(Locale.ROOT);
        String requiredPolicy = requiredPolicyForOperator(operator);
        String absencePolicy = absencePolicyForOperator(operator);
        for (String section : rule.sections()) {
            addInputRequirement(values, "section:" + section, requiredPolicy, absencePolicy);
        }
        for (String label : rule.labels()) {
            addInputRequirement(values, "label:" + label, requiredPolicy, absencePolicy);
        }
        if (StringUtils.hasText(rule.field())) {
            addInputRequirement(values, "field:" + rule.field(), requiredPolicy, absencePolicy);
        }
        for (String term : rule.terms()) {
            addInputRequirement(values, "term:" + term, triggerPolicyForOperator(operator), absencePolicy);
        }
        for (String term : rule.thenTerms()) {
            addInputRequirement(values, "thenTerm:" + term, "CONDITIONAL_REQUIRED", "MISSING_CONDITIONAL_INPUT");
        }
        for (String term : rule.forbiddenTerms()) {
            addInputRequirement(values, "forbiddenTerm:" + term, "FORBIDDEN_IF_PRESENT", "NOT_APPLICABLE_WHEN_ABSENT");
        }
        for (String label : rule.thenLabels()) {
            addInputRequirement(values, "thenLabel:" + label, "CONDITIONAL_REQUIRED", "MISSING_CONDITIONAL_INPUT");
        }
        for (List<String> group : rule.labelGroups()) {
            for (String item : group) {
                addInputRequirement(values, "groupTerm:" + item, "ALTERNATIVE_REQUIRED", "MISSING_ALTERNATIVE_INPUT");
            }
        }
        for (FinalPromptMetricRule child : rule.all()) {
            collectContractInputRequirements(child, values);
        }
        for (FinalPromptMetricRule child : rule.any()) {
            collectContractInputRequirements(child, values);
        }
        if (values.isEmpty() && StringUtils.hasText(rule.operator())) {
            addInputRequirement(values, "operator:" + rule.operator().trim(), "OPTIONAL", "NO_PROMPT_INPUT_REQUIRED");
        }
    }

    private void addInputRequirement(
            LinkedHashMap<String, MetricInputRequirement> values,
            String inputKey,
            String requiredPolicy,
            String absencePolicy) {
        if (!StringUtils.hasText(inputKey)) {
            return;
        }
        MetricInputRequirement next = new MetricInputRequirement(
                inputKey.trim(),
                requiredPolicy,
                absencePolicy);
        values.merge(next.inputKey(), next, this::stricterRequirement);
    }

    private MetricInputRequirement stricterRequirement(
            MetricInputRequirement existing,
            MetricInputRequirement next) {
        return policyRank(next.requiredPolicy()) > policyRank(existing.requiredPolicy()) ? next : existing;
    }

    private int policyRank(String policy) {
        return switch (normalize(policy)) {
            case "REQUIRED" -> 5;
            case "MINIMUM_REQUIRED" -> 4;
            case "ALTERNATIVE_REQUIRED", "CONDITIONAL_REQUIRED" -> 3;
            case "FORBIDDEN_IF_PRESENT" -> 2;
            default -> 1;
        };
    }

    private String requiredPolicyForOperator(String operator) {
        return switch (operator == null ? "" : operator) {
            case "SECTIONS_DECIDABLE", "FIELDS_DECIDABLE",
                    "FIELD_VALUES_CONSISTENT", "BOOLEAN_FIELDS_CONSISTENT" -> "REQUIRED";
            case "ANY_FIELD_DECIDABLE", "ANY" -> "ALTERNATIVE_REQUIRED";
            case "MIN_FIELDS_DECIDABLE" -> "MINIMUM_REQUIRED";
            case "IF_FIELD_EQUALS_THEN_FORBIDDEN_TERMS_ABSENT",
                    "IF_ANY_TERM_PRESENT_THEN_ANY_FIELD_OR_TERM_PRESENT" -> "CONDITIONAL_REQUIRED";
            default -> "OPTIONAL";
        };
    }

    private String triggerPolicyForOperator(String operator) {
        if ("IF_ANY_TERM_PRESENT_THEN_ANY_FIELD_OR_TERM_PRESENT".equals(operator)
                || "IF_FIELD_EQUALS_THEN_FORBIDDEN_TERMS_ABSENT".equals(operator)) {
            return "OPTIONAL_TRIGGER";
        }
        return requiredPolicyForOperator(operator);
    }

    private String absencePolicyForOperator(String operator) {
        return switch (operator == null ? "" : operator) {
            case "SECTIONS_DECIDABLE", "FIELDS_DECIDABLE",
                    "FIELD_VALUES_CONSISTENT", "BOOLEAN_FIELDS_CONSISTENT",
                    "MIN_FIELDS_DECIDABLE" -> "MISSING_INPUT_PRODUCER_GAP";
            case "ANY_FIELD_DECIDABLE", "ANY" -> "MISSING_ALTERNATIVE_INPUT";
            case "IF_FIELD_EQUALS_THEN_FORBIDDEN_TERMS_ABSENT",
                    "IF_ANY_TERM_PRESENT_THEN_ANY_FIELD_OR_TERM_PRESENT" -> "MISSING_CONDITIONAL_INPUT";
            default -> "NO_PROMPT_INPUT_REQUIRED";
        };
    }

    private List<String> contractInputKeys(FinalPromptMetricRule rule) {
        LinkedHashSet<String> values = new LinkedHashSet<>();
        collectContractInputKeys(rule, values);
        if (values.isEmpty()) {
            throw new IllegalStateException("Final prompt metric check contract has no input keys. operator="
                    + ruleOperator(rule));
        }
        return List.copyOf(values);
    }

    private void collectContractInputKeys(FinalPromptMetricRule rule, LinkedHashSet<String> values) {
        if (rule == null || values == null) {
            return;
        }
        for (String section : rule.sections()) {
            if (StringUtils.hasText(section)) {
                values.add("section:" + section.trim());
            }
        }
        for (String label : rule.labels()) {
            if (StringUtils.hasText(label)) {
                values.add("label:" + label.trim());
            }
        }
        if (StringUtils.hasText(rule.field())) {
            values.add("field:" + rule.field().trim());
        }
        for (String term : rule.terms()) {
            if (StringUtils.hasText(term)) {
                values.add("term:" + term.trim());
            }
        }
        for (String term : rule.thenTerms()) {
            if (StringUtils.hasText(term)) {
                values.add("thenTerm:" + term.trim());
            }
        }
        for (String term : rule.forbiddenTerms()) {
            if (StringUtils.hasText(term)) {
                values.add("forbiddenTerm:" + term.trim());
            }
        }
        for (String label : rule.thenLabels()) {
            if (StringUtils.hasText(label)) {
                values.add("thenLabel:" + label.trim());
            }
        }
        for (List<String> group : rule.labelGroups()) {
            for (String item : group) {
                if (StringUtils.hasText(item)) {
                    values.add("groupTerm:" + item.trim());
                }
            }
        }
        for (FinalPromptMetricRule child : rule.all()) {
            collectContractInputKeys(child, values);
        }
        for (FinalPromptMetricRule child : rule.any()) {
            collectContractInputKeys(child, values);
        }
        if (values.isEmpty() && StringUtils.hasText(rule.operator())) {
            values.add("operator:" + rule.operator().trim());
        }
    }

    private String ruleOperator(FinalPromptMetricRule rule) {
        if (rule == null || !StringUtils.hasText(rule.operator())) {
            throw new IllegalStateException("Final prompt metric check contract rule operator is required.");
        }
        return rule.operator().trim();
    }

    private String fit(String value, int maxLength) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.length() <= maxLength ? trimmed : trimmed.substring(0, maxLength);
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private String firstNonBlank(String... values) {
        if (values == null) {
            return "";
        }
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return "";
    }

    private boolean postgresqlDatabase() {
        Boolean result = jdbcTemplate.execute((ConnectionCallback<Boolean>) connection ->
                connection.getMetaData().getDatabaseProductName().toLowerCase(Locale.ROOT).contains("postgresql"));
        return Boolean.TRUE.equals(result);
    }

    private Timestamp nowTimestamp() {
        return Timestamp.from(Instant.now());
    }

    private String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest((value == null ? "" : value).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required for PQA resolution contract identifiers.", e);
        }
    }

    private record MetricInputRequirement(
            String inputKey,
            String requiredPolicy,
            String absencePolicy) {
    }
}
