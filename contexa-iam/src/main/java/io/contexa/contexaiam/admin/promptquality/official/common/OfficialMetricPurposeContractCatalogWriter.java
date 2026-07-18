package io.contexa.contexaiam.admin.promptquality.official.common;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricCheckContract;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricContract;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricContractCatalog;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricRule;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceCheckResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceMetricResult;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.util.StringUtils;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ArrayList;

public class OfficialMetricPurposeContractCatalogWriter implements OfficialMetricPurposeContractWriter {

    private static final List<String> CUSTOMER_DISPLAY_ROLES = List.of(
            "TITLE",
            "PASS_EVIDENCE",
            "FAIL_EVIDENCE",
            "WHY_IT_MATTERS",
            "RESOLUTION_ACTION",
            "REVERIFY_CONDITION");
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
        removeFallbackContractRows();
        removeCurrentContractRows(currentVersion);
        for (String metricCode : catalog.metricCodesInOrder()) {
            FinalPromptMetricContract metricContract = catalog.metric(metricCode);
            for (FinalPromptMetricCheckContract checkContract : metricContract.checks()) {
                upsertMetricPurposeContract(metricContract.version(), metricCode, metricContract, checkContract);
                upsertMetricCheckDisplayEvidenceContract(metricContract.version(), metricCode, checkContract);
            }
        }
        upsertPromptSignalRegistryContracts(currentVersion, catalog);
        upsertPromptRuntimeSlotContracts();
        deactivateNonCurrentContractVersions(currentVersion);
    }

    @Override
    public void upsertRuntimeMetricContractCatalog(List<RuntimeEvidenceMetricResult> metrics) {
        if (metrics == null) {
            return;
        }
        for (RuntimeEvidenceMetricResult metric : metrics) {
            if (metric == null || metric.checks() == null) {
                continue;
            }
            String metricCode = normalize(metric.metricCode());
            for (RuntimeEvidenceCheckResult check : metric.checks()) {
                if (check == null) {
                    continue;
                }
                String purposeVersion = firstNonBlank(check.purposeVersion(), "runtime-official-v1");
                FinalPromptMetricCheckContract checkContract = finalPromptMetricCheckContractOrNull(metricCode, check);
                if (checkContract != null) {
                    upsertMetricPurposeContract(
                            purposeVersion,
                            metricCode,
                            finalPromptMetricContractCatalog().metric(metricCode),
                            checkContract);
                } else {
                    upsertRuntimeMetricPurposeContract(purposeVersion, metricCode, metric, check);
                }
            }
        }
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
    }

    private FinalPromptMetricCheckContract finalPromptMetricCheckContractOrNull(
            String metricCode,
            RuntimeEvidenceCheckResult check) {
        if (check == null || !StringUtils.hasText(check.checkCode())) {
            return null;
        }
        try {
            return finalPromptMetricContractCatalog().check(metricCode, check.checkCode());
        } catch (IllegalStateException exception) {
            return null;
        }
    }

    private String canonicalMetricCheckCode(String metricCode, RuntimeEvidenceCheckResult check) {
        String normalizedMetric = normalize(metricCode);
        String normalizedCheck = normalize(check == null ? null : check.checkCode());
        if (!StringUtils.hasText(normalizedCheck)) {
            return "";
        }
        try {
            return finalPromptMetricContractCatalog().check(normalizedMetric, normalizedCheck).checkName();
        } catch (IllegalStateException exception) {
            String prefix = normalizedMetric + "_";
            return normalizedCheck.startsWith(prefix) && normalizedCheck.length() > prefix.length()
                    ? normalizedCheck.substring(prefix.length())
                    : normalizedCheck;
        }
    }

    private void upsertRuntimeMetricPurposeContract(
            String purposeVersion,
            String metricCode,
            RuntimeEvidenceMetricResult metric,
            RuntimeEvidenceCheckResult check) {
        String checkCode = firstNonBlank(
                canonicalMetricCheckCode(metricCode, check), check.checkCode(), check.label(), "CHECK");
        String issueKey = firstNonBlank(check.issueKey(), check.source(), checkCode);
        String readinessScope = firstNonBlank(check.readinessScope(), "OFFICIAL_VERIFICATION");
        String purpose = firstNonBlank(metric.metricName(), metricCode + " official metric");
        String question = firstNonBlank(
                check.whyItMatters(), check.label(), metric.metricName(), metricCode + " official check");
        String passMessage = firstNonBlank(
                check.operatorReason(), check.expectedValue(), "Official runtime check passed.");
        String failureMessage = firstNonBlank(
                check.operatorReason(), check.actualValue(), "Official runtime check failed.");
        jdbcTemplate.update("""
                        insert into official_metric_contract_version (
                            contract_version, source_artifact, active, created_at
                        ) values (?, ?, ?, ?)
                        on conflict (contract_version) do update
                           set source_artifact = excluded.source_artifact,
                               active = excluded.active
                        """,
                fit(purposeVersion, 128),
                "runtime:official-verification-metric-results",
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
                purpose,
                question,
                metric.checks().stream().anyMatch(RuntimeEvidenceCheckResult::customerVisible),
                fit(readinessScope, 128),
                false,
                false,
                nowTimestamp());
        jdbcTemplate.update("""
                        insert into official_metric_evaluation_contract (
                            contract_version, metric_code, check_code, purpose_question,
                            pass_condition, fail_condition, issue_key, customer_visible,
                            readiness_scope, problem_title, short_problem, expected_message,
                            pass_message, failure_message, created_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                fit(checkCode, 128),
                question,
                firstNonBlank(check.expectedValue(), passMessage),
                firstNonBlank(check.actualValue(), failureMessage),
                fit(issueKey, 512),
                check.customerVisible(),
                fit(readinessScope, 128),
                firstNonBlank(check.label(), checkCode),
                firstNonBlank(check.operatorReason(), check.label(), checkCode),
                firstNonBlank(check.expectedValue(), question),
                passMessage,
                failureMessage,
                nowTimestamp());
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
                fit(checkCode, 128),
                firstNonBlank(check.label(), checkCode),
                firstNonBlank(check.operatorReason(), check.label(), checkCode),
                firstNonBlank(check.whyItMatters(), question),
                firstNonBlank(check.nextAction(), "Review the official runtime metric evidence and rerun verification."),
                firstNonBlank(check.reverifyCriterion(), "Rerun official verification with the same sealed evidence."),
                purpose,
                failureMessage,
                nowTimestamp());
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

    private void upsertPromptRuntimeSlotContracts() {
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
            
    }

    private void upsertPromptSignalRegistryContracts(
            String purposeVersion,
            FinalPromptMetricContractCatalog catalog) {
        for (FinalPromptMetricContractCatalog.PromptSignalContract signal : catalog.promptSignalContracts()) {
            
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
            
        }
    }

    private void upsertMetricCustomerMessageContract(
            String purposeVersion,
            String metricCode,
            FinalPromptMetricContract metricContract,
            FinalPromptMetricCheckContract checkContract) {
        
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
        String sql = """
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

    private FinalPromptMetricContractCatalog finalPromptMetricContractCatalog() {
        if (finalPromptMetricContractCatalog == null) {
            finalPromptMetricContractCatalog = FinalPromptMetricContractCatalog.load(objectMapper);
        }
        return finalPromptMetricContractCatalog;
    }

    private String currentContractVersion(FinalPromptMetricContractCatalog catalog) {
        return catalog.contractVersion();
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

    private Timestamp nowTimestamp() {
        return Timestamp.from(Instant.now());
    }

    private record MetricInputRequirement(
            String inputKey,
            String requiredPolicy,
            String absencePolicy) {
    }
}
