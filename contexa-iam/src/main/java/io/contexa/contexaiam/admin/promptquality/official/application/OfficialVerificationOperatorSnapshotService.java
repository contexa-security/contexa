package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.metric.OfficialContextHashStateResolver;
import io.contexa.contexacore.verification.metric.OfficialPromptQualityNarrativeCatalog;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricCheckContract;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricContract;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricContractCatalog;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricRule;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptParser;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.common.OfficialMetricPurposeContractCatalogWriter;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityCustomerSentencePolicy;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityIssue;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceReverifyFindingResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceCheckResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceMetricResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRun;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialActualPromptProblem;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationPromptComparison;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class OfficialVerificationOperatorSnapshotService {

    public static final String DIAGNOSTIC_CATALOG_VERSION = OfficialPromptQualityNarrativeCatalog.CATALOG_VERSION;
    public static final String ACTUAL_PROMPT_PROBLEM_LEDGER_CONTRACT_VERSION =
            DIAGNOSTIC_CATALOG_VERSION + "-ACTUAL-PROMPT-PROBLEM-LEDGER-2026.05.13.2";
    private static final int CUSTOMER_OPERATOR_TEXT_MAX = 1200;
    private static final int CUSTOMER_OPERATOR_TITLE_MAX = 120;

    private static final Set<String> PASS_STATES = Set.of("SUCCESS", "PASS", "PASSED", "VERIFIED", "COMPLETED");
    private static final Set<String> CONTRACT_METADATA_SIGNAL_KEYS = Set.of(
            "purposeSignal",
            "meaning",
            "securityRelevance",
            "interpretationLink",
            "purposeResult");
    private static final List<String> CUSTOMER_DISPLAY_ROLES = List.of(
            "TITLE",
            "PASS_EVIDENCE",
            "FAIL_EVIDENCE",
            "WHY_IT_MATTERS",
            "RESOLUTION_ACTION",
            "REVERIFY_CONDITION");
    private static final String CUSTOMER_PURPOSE_EVIDENCE_SEPARATOR = " || ";
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};
    private static final Pattern CUSTOMER_EVIDENCE_KEY_VALUE =
            Pattern.compile("([A-Za-z][A-Za-z0-9_.-]{1,80})\\s*=\\s*(.*?)(?=\\s*(?:[,;]\\s*[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=|[;\\r\\n]|$))");
    private static final Pattern CUSTOMER_TECHNICAL_CONTRACT_CODE =
            Pattern.compile("\\b[A-Z]{2,}(?:_[A-Z0-9]+)+\\b");

    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;
    private final OfficialMetricPurposeContractCatalogWriter contractCatalogWriter;
    private final OfficialPromptQualityNarrativeCatalog narrativeCatalog = new OfficialPromptQualityNarrativeCatalog();
    private final CustomerDisplayPayloadFactory customerDisplayPayloadFactory = new CustomerDisplayPayloadFactory();
    private FinalPromptMetricContractCatalog finalPromptMetricContractCatalog;

    public OfficialVerificationOperatorSnapshotService(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this(jdbcTemplate, objectMapper, null);
    }

    public OfficialVerificationOperatorSnapshotService(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper,
            OfficialMetricPurposeContractCatalogWriter contractCatalogWriter) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
        this.contractCatalogWriter = contractCatalogWriter != null
                ? contractCatalogWriter
                : defaultContractCatalogWriter(jdbcTemplate, objectMapper);
    }

    private static OfficialMetricPurposeContractCatalogWriter defaultContractCatalogWriter(
            JdbcTemplate jdbcTemplate,
            ObjectMapper objectMapper) {
        if (jdbcTemplate == null || objectMapper == null || jdbcTemplate.getDataSource() == null) {
            return null;
        }
        return new OfficialMetricPurposeContractCatalogWriter(jdbcTemplate, objectMapper);
    }

    @Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.REQUIRES_NEW)
    public List<String> replaceDiagnosticsForQualityTarget(
            String currentPackageId,
            String actualResourceId,
            String actualRequestPath,
            String httpMethod) {
        if (!StringUtils.hasText(currentPackageId)) {
            return List.of();
        }
        deleteDiagnosticPackage(currentPackageId.trim());
        return List.of();
    }

    private void deleteDiagnosticPackage(String packageId) {
        if (!StringUtils.hasText(packageId)) {
            return;
        }
        String normalizedPackageId = packageId.trim();
        List<String> officialRunIds = new ArrayList<>(safeList(jdbcTemplate.queryForList("""
                        select distinct official_run_id
                          from official_verification_metric_snapshot
                         where package_id = ?
                           and official_run_id is not null
                           and trim(official_run_id) <> ''
                          """,
                String.class,
                normalizedPackageId)));
        List<String> packageRunIds = jdbcTemplate.queryForList("""
                        select distinct run_id
                          from verification_run_ledger
                         where package_id = ?
                           and run_id is not null
                           and trim(run_id) <> ''
                        """,
                String.class,
                normalizedPackageId);
        if (packageRunIds != null) {
            officialRunIds.addAll(packageRunIds);
        }
        for (String runId : officialRunIds) {
            if (StringUtils.hasText(runId)) {
                deleteVerificationRunLedger(runId.trim());
            }
        }
        jdbcTemplate.update("""
                        delete from official_verification_metric_execution_ledger
                         where package_id = ?
                        """,
                normalizedPackageId);
        jdbcTemplate.update("""
                        delete from official_verification_execution_state_history
                         where package_id = ?
                        """,
                normalizedPackageId);
        if (tableExists("prompt_quality_issue")) {
            if (tableExists("prompt_quality_remediation_action")) {
                jdbcTemplate.update("""
                                delete from prompt_quality_remediation_action
                                 where issue_id in (
                                       select issue_id
                                         from prompt_quality_issue
                                        where package_id = ?
                                    )
                                """,
                        normalizedPackageId);
            }
            jdbcTemplate.update("delete from prompt_quality_issue where package_id = ?", normalizedPackageId);
        }
        jdbcTemplate.update("""
                        delete from official_verification_reverify_result
                         where source_package_id = ?
                            or fixed_package_id = ?
                        """,
                normalizedPackageId,
                normalizedPackageId);
        jdbcTemplate.update("delete from official_verification_audit_snapshot where package_id = ?", normalizedPackageId);
        jdbcTemplate.update("delete from official_verification_operator_remediation_group where package_id = ?", normalizedPackageId);
        jdbcTemplate.update("delete from official_metric_purpose_evidence_ledger where package_id = ?", normalizedPackageId);
        jdbcTemplate.update("delete from official_metric_purpose_evaluation_ledger where package_id = ?", normalizedPackageId);
        jdbcTemplate.update("delete from official_metric_input_readiness_ledger where package_id = ?", normalizedPackageId);
        jdbcTemplate.update("delete from official_prompt_signal_ledger where package_id = ?", normalizedPackageId);
        jdbcTemplate.update("delete from official_actual_prompt_problem_ledger where package_id = ?", normalizedPackageId);
        jdbcTemplate.update("delete from official_verification_prompt_comparison where package_id = ?", normalizedPackageId);
        jdbcTemplate.update("delete from official_prompt_field_diff_ledger where package_id = ?", normalizedPackageId);
        jdbcTemplate.update("delete from official_prompt_field_value_ledger where package_id = ?", normalizedPackageId);
        jdbcTemplate.update("delete from official_prompt_generation_lineage where package_id = ?", normalizedPackageId);
        jdbcTemplate.update("delete from official_prompt_projection_ledger where package_id = ?", normalizedPackageId);
        jdbcTemplate.update("delete from official_prompt_field_state_ledger where package_id = ?", normalizedPackageId);
        jdbcTemplate.update("delete from official_verification_operator_finding where package_id = ?", normalizedPackageId);
        jdbcTemplate.update("delete from official_verification_metric_snapshot where package_id = ?", normalizedPackageId);
        jdbcTemplate.update("delete from official_verification_run_batch where package_id = ?", normalizedPackageId);
    }

    private void deleteVerificationRunLedger(String runId) {
        jdbcTemplate.update("delete from verification_run_round_ledger where run_id = ?", runId);
        jdbcTemplate.update("delete from verification_run_check_ledger where run_id = ?", runId);
        jdbcTemplate.update("delete from verification_run_fact_ledger where run_id = ?", runId);
        jdbcTemplate.update("delete from verification_run_event_ledger where run_id = ?", runId);
        jdbcTemplate.update("delete from verification_raw_evidence_artifact_ledger where run_id = ?", runId);
        jdbcTemplate.update("delete from verification_run_ledger where run_id = ?", runId);
    }

    private <T> List<T> safeList(List<T> values) {
        return values == null ? List.of() : values;
    }

    public void record(
            String aggregateRunId,
            SealedEvidencePackage evidencePackage,
            String requestPath,
            String resourceId,
            String httpMethod,
            String promptHash,
            String contextHash,
            String certificateId,
            String caseId,
            List<PromptQualityIssue> issues,
            List<RuntimeEvidenceMetricResult> metrics,
            List<OfficialVerificationPromptComparison> promptComparisons) {
        if (!StringUtils.hasText(aggregateRunId) || evidencePackage == null || metrics == null || metrics.isEmpty()) {
            return;
        }
        if (metrics.size() != 12) {
            throw new IllegalStateException("Official prompt quality inspection must store exactly 12 metric results (12\uAC1C \uC9C0\uD45C). actual=" + metrics.size());
        }
        requirePersistedSealedEvidencePackage(evidencePackage.getPackageId());
        try {
            if (completeSnapshotExists(aggregateRunId)) {
                return;
            }
            assertMetricDefinitionsRegistered(metrics);
            Map<String, String> issueIdsByMetric = issueIdsByMetric(issues);
            jdbcTemplate.update("delete from official_verification_operator_remediation_group where aggregate_run_id = ?", aggregateRunId);
            jdbcTemplate.update("delete from official_metric_customer_display_payload where aggregate_run_id = ?", aggregateRunId);
            jdbcTemplate.update("delete from official_metric_purpose_evidence_ledger where aggregate_run_id = ?", aggregateRunId);
            jdbcTemplate.update("delete from official_metric_purpose_evaluation_ledger where aggregate_run_id = ?", aggregateRunId);
            jdbcTemplate.update("delete from official_metric_input_readiness_ledger where aggregate_run_id = ?", aggregateRunId);
            jdbcTemplate.update("delete from official_prompt_signal_ledger where aggregate_run_id = ?", aggregateRunId);
            jdbcTemplate.update("delete from official_actual_prompt_problem_ledger where aggregate_run_id = ?", aggregateRunId);
            jdbcTemplate.update("delete from official_verification_prompt_comparison where aggregate_run_id = ?", aggregateRunId);
            jdbcTemplate.update("delete from official_prompt_field_diff_ledger where aggregate_run_id = ?", aggregateRunId);
            jdbcTemplate.update("delete from official_prompt_field_value_ledger where aggregate_run_id = ?", aggregateRunId);
            jdbcTemplate.update("delete from official_prompt_generation_lineage where aggregate_run_id = ?", aggregateRunId);
            jdbcTemplate.update("delete from official_prompt_projection_ledger where aggregate_run_id = ?", aggregateRunId);
            jdbcTemplate.update("delete from official_prompt_field_state_ledger where aggregate_run_id = ?", aggregateRunId);
            jdbcTemplate.update("delete from official_verification_operator_finding where aggregate_run_id = ?", aggregateRunId);
            jdbcTemplate.update("delete from official_verification_metric_snapshot where aggregate_run_id = ?", aggregateRunId);
            jdbcTemplate.update("delete from official_verification_run_batch where aggregate_run_id = ?", aggregateRunId);
            upsertPromptFieldDefinitions(evidencePackage);
            List<ActualPromptProblem> actualPromptProblems = actualPromptProblems(
                    aggregateRunId,
                    evidencePackage.getPackageId(),
                    evidencePackage,
                    metrics,
                    promptComparisons);
            Map<String, List<ActualPromptProblem>> problemsByMetric = actualPromptProblemsByMetric(actualPromptProblems);
            assertCustomerMetricFailuresHaveActualPromptProblems(aggregateRunId, metrics, problemsByMetric);
            insertParsedFinalPromptSignalLedgers(aggregateRunId, evidencePackage.getPackageId(), evidencePackage);
            insertMetricPurposeLedgers(aggregateRunId, evidencePackage.getPackageId(), metrics);
            assertCustomerDisplayPayloadComplete(aggregateRunId);
            insertActualPromptProblemLedger(aggregateRunId, evidencePackage.getPackageId(), actualPromptProblems);
            linkActualPromptProblemsToPurposeLedgers(aggregateRunId);
            insertBatch(
                    aggregateRunId,
                    evidencePackage,
                    requestPath,
                    resourceId,
                    httpMethod,
                    promptHash,
                    contextHash,
                    certificateId,
                    caseId,
                    metrics,
                    problemsByMetric);
            for (RuntimeEvidenceMetricResult metric : metrics) {
                if (metric == null) {
                    continue;
                }
                List<ActualPromptProblem> metricProblems = problemsByMetric.getOrDefault(normalize(metric.metricCode()), List.of());
                insertMetricSnapshot(
                        aggregateRunId,
                        evidencePackage.getPackageId(),
                        certificateId,
                        caseId,
                        metric,
                        issueIdsByMetric,
                        metricProblems);
                insertFindings(
                        aggregateRunId,
                        evidencePackage.getPackageId(),
                        certificateId,
                        caseId,
                        issueIdsByMetric,
                        metric,
                        metricProblems);
            }
            updateMetricExecutionIssueReferences(aggregateRunId, metrics, issueIdsByMetric, problemsByMetric);
            insertRemediationGroups(aggregateRunId, evidencePackage.getPackageId(), certificateId, caseId, actualPromptProblems);
            insertPromptComparisons(aggregateRunId, evidencePackage.getPackageId(), promptComparisons, actualPromptProblems);
            insertPromptGenerationLineage(aggregateRunId, evidencePackage.getPackageId(), evidencePackage, promptHash, contextHash);
            insertPromptFieldValueLedgers(aggregateRunId, evidencePackage.getPackageId(), evidencePackage);
            insertPromptFieldDiffLedgers(aggregateRunId, evidencePackage.getPackageId(), evidencePackage);
            insertPromptFieldStateLedgers(aggregateRunId, evidencePackage.getPackageId(), evidencePackage);
            linkActualPromptProblemsToPurposeLedgers(aggregateRunId);
            synchronizePromptQualityIssuesWithActualPromptProblems(evidencePackage.getPackageId(), aggregateRunId);
            assertPromptFieldDefinitionsCoverStateLedger(aggregateRunId);
            assertCustomerVisiblePurposeLedgersClean(aggregateRunId);
            assertPromptComparisonLinksComplete(aggregateRunId);
            assertActualPromptProblemLedgerAligned(aggregateRunId);
            assertMetricSnapshotComplete(aggregateRunId);
        } catch (DataAccessException ex) {
            throw new IllegalStateException("공식검사 결과 저장 중 DB 오류가 발생했습니다: " + databaseMessage(ex), ex);
        }
    }

    private void requirePersistedSealedEvidencePackage(String packageId) {
        if (!StringUtils.hasText(packageId)) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: official verification requires a sealed evidence package id.");
        }
        Integer count = jdbcTemplate.queryForObject(
                "select count(*) from sealed_evidence_package where package_id = ?",
                Integer.class,
                packageId.trim());
        if (count == null || count <= 0) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: official verification package is not linked to sealed evidence. packageId="
                    + packageId.trim());
        }
    }

    private boolean completeSnapshotExists(String aggregateRunId) {
        Integer batchCount = jdbcTemplate.queryForObject("""
                        select count(*)
                          from official_verification_run_batch b
                          join sealed_evidence_package sealed
                            on sealed.package_id = b.package_id
                         where b.aggregate_run_id = ?
                        """,
                Integer.class,
                aggregateRunId);
        if (batchCount == null || batchCount <= 0) {
            return false;
        }
        Integer metricCount = jdbcTemplate.queryForObject(
                "select count(*) from official_verification_metric_snapshot where aggregate_run_id = ?",
                Integer.class,
                aggregateRunId);
        if (metricCount == null || metricCount != 12) {
            return false;
        }
        Integer expectedCustomerDisplayPayloadRows = jdbcTemplate.queryForObject("""
                        select coalesce(sum(
                            case
                                when purpose_result = 'PURPOSE_FAILED' then 5
                                else 3
                            end
                        ), 0)
                          from official_metric_purpose_evaluation_ledger
                         where aggregate_run_id = ?
                           and customer_visible = true
                        """,
                Integer.class,
                aggregateRunId);
        Integer actualCustomerDisplayPayloadRows = jdbcTemplate.queryForObject("""
                        select count(*)
                          from official_metric_customer_display_payload
                         where aggregate_run_id = ?
                        """,
                Integer.class,
                aggregateRunId);
        if ((expectedCustomerDisplayPayloadRows == null ? 0 : expectedCustomerDisplayPayloadRows)
                != (actualCustomerDisplayPayloadRows == null ? 0 : actualCustomerDisplayPayloadRows)) {
            return false;
        }
        Integer findingWithoutProblem = jdbcTemplate.queryForObject("""
                        select count(*)
                          from (
                                select check_code
                                  from official_verification_operator_finding
                                 where aggregate_run_id = ?
                                   and check_code is not null
                                   and trim(check_code) <> ''
                                except
                                select problem_id
                                  from official_actual_prompt_problem_ledger
                                 where aggregate_run_id = ?
                               ) missing_actual_prompt_problem
                        """,
                Integer.class,
                aggregateRunId,
                aggregateRunId);
        if (findingWithoutProblem != null && findingWithoutProblem > 0) {
            return false;
        }
        Integer inputReadinessProblems = jdbcTemplate.queryForObject("""
                        select count(*)
                          from official_actual_prompt_problem_ledger
                         where aggregate_run_id = ?
                           and upper(coalesce(problem_type, '')) = 'INPUT_NOT_READY'
                        """,
                Integer.class,
                aggregateRunId);
        if (inputReadinessProblems != null && inputReadinessProblems > 0) {
            return false;
        }
        Integer staleInputReadinessPurposeRows = jdbcTemplate.queryForObject("""
                        select count(*)
                          from official_metric_purpose_evaluation_ledger
                         where aggregate_run_id = ?
                           and upper(coalesce(purpose_result, '')) in ('NOT_EVALUATED_INPUT_NOT_READY', 'INPUT_NOT_READY')
                           and customer_visible = true
                        """,
                Integer.class,
                aggregateRunId);
        if (staleInputReadinessPurposeRows != null && staleInputReadinessPurposeRows > 0) {
            return false;
        }
        Integer missingPromptComparison = jdbcTemplate.queryForObject("""
                        select count(*)
                          from (
                                select distinct comparison_field_key
                                  from official_verification_operator_finding
                                 where aggregate_run_id = ?
                                   and comparison_field_key is not null
                                   and trim(comparison_field_key) <> ''
                                except
                                select distinct field_key
                                  from official_verification_prompt_comparison
                                 where aggregate_run_id = ?
                                   and field_key is not null
                                   and trim(field_key) <> ''
                               ) missing_prompt_comparison
                        """,
                Integer.class,
                aggregateRunId,
                aggregateRunId);
        if (missingPromptComparison != null && missingPromptComparison > 0) {
            return false;
        }
        Integer actualProblemCount = jdbcTemplate.queryForObject("""
                        select count(*)
                          from official_actual_prompt_problem_ledger
                         where aggregate_run_id = ?
                           and severity = 'BLOCKING'
                        """,
                Integer.class,
                aggregateRunId);
        Integer findingProblemReferenceCount = jdbcTemplate.queryForObject("""
                        select count(distinct check_code)
                           from official_verification_operator_finding
                          where aggregate_run_id = ?
                            and check_code is not null
                            and trim(check_code) <> ''
                         """,
                Integer.class,
                aggregateRunId);
        if ((actualProblemCount == null ? 0 : actualProblemCount)
                != (findingProblemReferenceCount == null ? 0 : findingProblemReferenceCount)) {
            return false;
        }
        Integer blockedMetricWithoutProblem = jdbcTemplate.queryForObject("""
                        /* blocked_metric_without_problem */
                        select count(*)
                          from official_verification_metric_snapshot m
                         where m.aggregate_run_id = ?
                           and m.state = 'BLOCKED'
                           and upper(m.metric_code) not in ('MTR', 'RPI', 'PRE')
                           and not exists (
                                select 1
                                  from official_verification_operator_finding f
                                 where f.aggregate_run_id = m.aggregate_run_id
                                   and f.metric_code = m.metric_code
                           )
                        """,
                Integer.class,
                aggregateRunId);
        return blockedMetricWithoutProblem == null || blockedMetricWithoutProblem == 0;
    }

    public OperatorSnapshot findLatest(String packageId, String aggregateRunId) {
        if (!StringUtils.hasText(packageId)) {
            return OperatorSnapshot.empty();
        }
        try {
            List<OperatorRunBatch> batches = StringUtils.hasText(aggregateRunId)
                    ? jdbcTemplate.query("""
                            select b.aggregate_run_id, b.package_id, b.certificate_id, b.case_id, b.scope_type,
                                   b.expected_metric_count, b.actual_metric_count, b.passed_metric_count,
                                   b.failed_metric_count, b.insufficient_metric_count, b.not_applicable_metric_count,
                                   b.final_decision, b.blocked, b.block_reason_summary, b.prompt_hash, b.context_hash,
                                   b.context_hash_state, b.template_resource_id, b.actual_resource_id,
                                   b.resource_url_template, b.actual_request_path, b.http_method,
                                   b.diagnostic_catalog_version, b.created_at
                              from official_verification_run_batch b
                              join sealed_evidence_package sealed
                                on sealed.package_id = b.package_id
                             where b.package_id = ?
                               and b.aggregate_run_id = ?
                               and b.diagnostic_catalog_version = ?
                               and b.current_result = true
                              order by b.created_at desc
                              limit 1
                             """, this::batch, packageId.trim(), aggregateRunId.trim(), diagnosticCatalogVersion())
                    : jdbcTemplate.query("""
                            select b.aggregate_run_id, b.package_id, b.certificate_id, b.case_id, b.scope_type,
                                   b.expected_metric_count, b.actual_metric_count, b.passed_metric_count,
                                   b.failed_metric_count, b.insufficient_metric_count, b.not_applicable_metric_count,
                                   b.final_decision, b.blocked, b.block_reason_summary, b.prompt_hash, b.context_hash,
                                   b.context_hash_state, b.template_resource_id, b.actual_resource_id,
                                   b.resource_url_template, b.actual_request_path, b.http_method,
                                   b.diagnostic_catalog_version, b.created_at
                              from official_verification_run_batch b
                              join sealed_evidence_package sealed
                                on sealed.package_id = b.package_id
                             where b.package_id = ?
                               and b.diagnostic_catalog_version = ?
                               and b.current_result = true
                              order by b.created_at desc
                              limit 1
                             """, this::batch, packageId.trim(), diagnosticCatalogVersion());
            if (batches.isEmpty()) {
                return OperatorSnapshot.empty();
            }
            OperatorRunBatch batch = batches.get(0);
            return new OperatorSnapshot(
                    batch,
                    List.copyOf(metricSnapshots(batch.aggregateRunId())),
                    List.copyOf(findings(batch.aggregateRunId())),
                    List.copyOf(remediationGroups(batch.aggregateRunId())),
                    List.copyOf(storedActualPromptProblems(batch.aggregateRunId())),
                    List.copyOf(purposeEvidence(batch.aggregateRunId())),
                    List.copyOf(auditSnapshots(batch.aggregateRunId())));
        } catch (DataAccessException ignored) {
            return OperatorSnapshot.empty();
        }
    }

    public List<OfficialVerificationPromptComparison> promptComparisons(String packageId, String aggregateRunId) {
        if (!StringUtils.hasText(packageId)) {
            return List.of();
        }
        try {
            String resolvedAggregateRunId = aggregateRunId;
            if (!StringUtils.hasText(resolvedAggregateRunId)) {
                OperatorSnapshot snapshot = findLatest(packageId, null);
                resolvedAggregateRunId = snapshot.batch() == null ? null : snapshot.batch().aggregateRunId();
            }
            if (!StringUtils.hasText(resolvedAggregateRunId)) {
                return List.of();
            }
            if (!isCurrentDiagnosticCatalogVersion(packageId.trim(), resolvedAggregateRunId.trim())) {
                return List.of();
            }
            synchronizePromptComparisonLinks(packageId.trim(), resolvedAggregateRunId.trim());
            return jdbcTemplate.query("""
                            select field_key, field_label, sealed_evidence_value, prompt_value,
                                   official_fact_value, state, state_label, meaning,
                                   related_metric_codes, related_check_codes, related_finding_ids,
                                   related_issue_ids, related_remediation_group_ids, prompt_location,
                                   evidence_source, recommended_owner, canonical_source
                              from official_verification_prompt_comparison
                             where package_id = ?
                               and aggregate_run_id = ?
                               and canonical_source <> 'OFFICIAL_FINDING'
                              order by case when state in (
                                           'PROMPT_MISSING',
                                           'FACT_MISSING',
                                           'VALUE_MISMATCH',
                                           'CONTRACT_MISMATCH',
                                           'REQUIRED_MISSING',
                                           'CONDITIONAL_REQUIRED_MISSING',
                                           'UNKNOWN_WITHOUT_REASON',
                                           'PROMPT_COMPACTED_SIGNAL',
                                           'PRODUCER_NOT_AVAILABLE',
                                           'PROVISIONAL_EVIDENCE',
                                           'NO_DIRECT_COMPARABLE',
                                           'BASELINE_MISMATCH_SIGNAL'
                                       ) then 0 else 1 end,
                                       field_label asc, field_key asc
                             """,
                    this::promptComparison,
                    packageId.trim(),
                    resolvedAggregateRunId.trim());
        } catch (DataAccessException ignored) {
            return List.of();
        }
    }

    public List<OfficialActualPromptProblem> actualPromptProblems(String packageId, String aggregateRunId) {
        if (!StringUtils.hasText(packageId)) {
            return List.of();
        }
        try {
            String resolvedAggregateRunId = aggregateRunId;
            if (!StringUtils.hasText(resolvedAggregateRunId)) {
                OperatorSnapshot snapshot = findLatest(packageId, null);
                resolvedAggregateRunId = snapshot.batch() == null ? null : snapshot.batch().aggregateRunId();
            }
            if (!StringUtils.hasText(resolvedAggregateRunId)) {
                return List.of();
            }
            if (!isCurrentDiagnosticCatalogVersion(packageId.trim(), resolvedAggregateRunId.trim())) {
                return List.of();
            }
            return storedActualPromptProblems(resolvedAggregateRunId.trim()).stream()
                    .filter(problem -> packageId.trim().equals(problem.packageId()))
                    .toList();
        } catch (DataAccessException ignored) {
            return List.of();
        }
    }

    public List<OperatorSnapshot> recentSnapshots(int limit) {
        int rowLimit = Math.max(1, Math.min(limit <= 0 ? 10 : limit, 50));
        try {
            List<OperatorRunBatch> batches = jdbcTemplate.query("""
                            select b.aggregate_run_id, b.package_id, b.certificate_id, b.case_id, b.scope_type,
                                   b.expected_metric_count, b.actual_metric_count, b.passed_metric_count,
                                   b.failed_metric_count, b.insufficient_metric_count, b.not_applicable_metric_count,
                                   b.final_decision, b.blocked, b.block_reason_summary, b.prompt_hash, b.context_hash,
                                   b.context_hash_state, b.template_resource_id, b.actual_resource_id,
                                   b.resource_url_template, b.actual_request_path, b.http_method,
                                   b.diagnostic_catalog_version, b.created_at
                              from official_verification_run_batch b
                              join sealed_evidence_package sealed
                                on sealed.package_id = b.package_id
                             where b.diagnostic_catalog_version = ?
                               and b.current_result = true
                             order by b.created_at desc
                             limit ?
                            """,
                    this::batch,
                    diagnosticCatalogVersion(),
                    rowLimit);
            if (batches.isEmpty()) {
                return List.of();
            }
            List<String> aggregateRunIds = batches.stream()
                    .map(OperatorRunBatch::aggregateRunId)
                    .filter(StringUtils::hasText)
                    .distinct()
                    .toList();
            Map<String, List<OperatorMetricSnapshot>> metricRows = metricSnapshots(aggregateRunIds).stream()
                    .collect(Collectors.groupingBy(OperatorMetricSnapshot::aggregateRunId, LinkedHashMap::new, Collectors.toList()));
            Map<String, List<OperatorFinding>> findingRows = findings(aggregateRunIds).stream()
                    .collect(Collectors.groupingBy(OperatorFinding::aggregateRunId, LinkedHashMap::new, Collectors.toList()));
            Map<String, List<OperatorRemediationGroup>> groupRows = remediationGroups(aggregateRunIds).stream()
                    .collect(Collectors.groupingBy(OperatorRemediationGroup::aggregateRunId, LinkedHashMap::new, Collectors.toList()));
            Map<String, List<OfficialActualPromptProblem>> problemRows = storedActualPromptProblems(aggregateRunIds).stream()
                    .collect(Collectors.groupingBy(OfficialActualPromptProblem::aggregateRunId, LinkedHashMap::new, Collectors.toList()));
            Map<String, List<OperatorPurposeEvidence>> purposeEvidenceRows = purposeEvidence(aggregateRunIds).stream()
                    .collect(Collectors.groupingBy(OperatorPurposeEvidence::aggregateRunId, LinkedHashMap::new, Collectors.toList()));
            Map<String, List<OperatorAuditSnapshot>> auditRows = auditSnapshots(aggregateRunIds).stream()
                    .collect(Collectors.groupingBy(OperatorAuditSnapshot::aggregateRunId, LinkedHashMap::new, Collectors.toList()));
            return batches.stream()
                    .map(batch -> new OperatorSnapshot(
                            batch,
                            List.copyOf(metricRows.getOrDefault(batch.aggregateRunId(), List.of())),
                            List.copyOf(findingRows.getOrDefault(batch.aggregateRunId(), List.of())),
                            List.copyOf(groupRows.getOrDefault(batch.aggregateRunId(), List.of())),
                            List.copyOf(problemRows.getOrDefault(batch.aggregateRunId(), List.of())),
                            List.copyOf(purposeEvidenceRows.getOrDefault(batch.aggregateRunId(), List.of())),
                            List.copyOf(auditRows.getOrDefault(batch.aggregateRunId(), List.of()))))
                    .toList();
        } catch (DataAccessException ignored) {
            return List.of();
        }
    }

    private boolean isCurrentDiagnosticCatalogVersion(String packageId, String aggregateRunId) {
        if (!StringUtils.hasText(packageId) || !StringUtils.hasText(aggregateRunId)) {
            return false;
        }
        Integer count = jdbcTemplate.queryForObject("""
                select count(*)
                  from official_verification_run_batch b
                  join sealed_evidence_package sealed
                    on sealed.package_id = b.package_id
                 where b.package_id = ?
                   and b.aggregate_run_id = ?
                   and b.diagnostic_catalog_version = ?
                   and b.current_result = true
                """,
                Integer.class,
                packageId,
                aggregateRunId,
                diagnosticCatalogVersion());
        return count != null && count > 0;
    }

    public List<OperatorReverificationResult> reverificationResults(String sourcePackageId, String sourceAggregateRunId) {
        if (!StringUtils.hasText(sourcePackageId)) {
            return List.of();
        }
        try {
            if (StringUtils.hasText(sourceAggregateRunId)) {
                return jdbcTemplate.query("""
                                select result_id, source_package_id, source_aggregate_run_id,
                                       fixed_package_id, fixed_aggregate_run_id, source_finding_id,
                                       issue_id, metric_code, check_code, reverify_criterion,
                                       source_operator_reason, source_expected_value, source_actual_value,
                                       fixed_actual_value, resolved, resolution_state, operator_summary,
                                       created_by, diagnostic_catalog_version, created_at
                                  from official_verification_reverify_result
                                 where source_package_id = ?
                                   and source_aggregate_run_id = ?
                                 order by created_at desc
                                 limit 50
                                """,
                        this::reverificationResult,
                        sourcePackageId.trim(),
                        sourceAggregateRunId.trim());
            }
            return jdbcTemplate.query("""
                            select result_id, source_package_id, source_aggregate_run_id,
                                   fixed_package_id, fixed_aggregate_run_id, source_finding_id,
                                   issue_id, metric_code, check_code, reverify_criterion,
                                   source_operator_reason, source_expected_value, source_actual_value,
                                   fixed_actual_value, resolved, resolution_state, operator_summary,
                                   created_by, diagnostic_catalog_version, created_at
                              from official_verification_reverify_result
                             where source_package_id = ?
                             order by created_at desc
                             limit 50
                            """,
                    this::reverificationResult,
                    sourcePackageId.trim());
        } catch (DataAccessException ignored) {
            return List.of();
        }
    }

    public void recordAuditSnapshot(
            String aggregateRunId,
            String packageId,
            String certificateId,
            String caseId,
            String state,
            String stateLabel,
            int totalMetricCount,
            int failedMetricCount,
            boolean certificateIssued,
            String promptHash,
            String contextHash,
            List<String> blockingFindings,
            List<String> nextActions,
            Map<String, Object> payload,
            String operatorId) {
        if (!StringUtils.hasText(aggregateRunId) || !StringUtils.hasText(packageId)) {
            return;
        }
        String snapshotId = "pqa-audit-" + packageId.trim() + "-" + aggregateRunId.trim();
        List<String> safeBlockingFindings = auditCustomerSentences(
                "audit.blockingFindings",
                blockingFindings == null ? List.of() : blockingFindings,
                true);
        List<String> safeNextActions = auditCustomerSentences(
                "audit.nextActions",
                nextActions == null ? List.of() : nextActions,
                false);
        Map<String, Object> safePayload = new LinkedHashMap<>(payload == null ? Map.of() : payload);
        safePayload.put("blockingFindings", safeBlockingFindings);
        safePayload.put("nextActions", safeNextActions);
        try {
            jdbcTemplate.update(
                    "delete from official_verification_audit_snapshot where aggregate_run_id = ? and package_id = ?",
                    aggregateRunId.trim(),
                    packageId.trim());
            jdbcTemplate.update("""
                            insert into official_verification_audit_snapshot (
                                snapshot_id, aggregate_run_id, package_id, certificate_id, case_id,
                                state, state_label, total_metric_count, failed_metric_count,
                                certificate_issued, prompt_hash, context_hash, blocking_findings_json,
                                next_actions_json, payload_json, created_by, diagnostic_catalog_version, created_at
                            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                    fit(snapshotId, 256),
                    fit(aggregateRunId, 256),
                    fit(packageId, 256),
                    fit(certificateId, 256),
                    fit(caseId, 256),
                    fit(state, 80),
                    fit(stateLabel, 120),
                    totalMetricCount,
                    failedMetricCount,
                    certificateIssued,
                    fit(promptHash, 160),
                    fit(contextHash, 160),
                    writeJson(safeBlockingFindings),
                    writeJson(safeNextActions),
                    writeJson(safePayload),
                    fit(safe(operatorId, "runtime-pqa"), 128),
                    diagnosticCatalogVersion(),
                    nowTimestamp());
        } catch (DataAccessException ex) {
            throw new IllegalStateException("공식검사 감사 스냅샷 저장 중 DB 오류가 발생했습니다: " + databaseMessage(ex), ex);
        }
    }

    public List<RuntimeEvidenceReverifyFindingResult> recordReverificationResults(
            String sourcePackageId,
            String sourceAggregateRunId,
            List<String> findingIds,
            List<String> issueIds,
            RuntimeEvidenceVerificationRun fixedRun,
            String operatorId) {
        if (!StringUtils.hasText(sourcePackageId) || fixedRun == null || !StringUtils.hasText(fixedRun.packageId())) {
            return List.of();
        }
        OperatorSnapshot sourceSnapshot = findLatest(sourcePackageId, sourceAggregateRunId);
        if (!sourceSnapshot.available() || sourceSnapshot.findings().isEmpty()) {
            return List.of();
        }
        Set<String> findingFilter = normalizedSet(findingIds);
        Set<String> issueFilter = normalizedSet(issueIds);
        List<OperatorFinding> sourceFindings = sourceSnapshot.findings().stream()
                .filter(finding -> finding != null)
                .filter(finding -> findingFilter.isEmpty() || findingFilter.contains(normalize(finding.findingId())))
                .filter(finding -> issueFilter.isEmpty() || issueFilter.contains(normalize(finding.issueId())))
                .toList();
        if (sourceFindings.isEmpty()) {
            return List.of();
        }
        String fixedAggregateRunId = safe(fixedRun.runId());
        jdbcTemplate.update("""
                        delete from official_verification_reverify_result
                         where source_package_id = ?
                           and fixed_package_id = ?
                           and coalesce(fixed_aggregate_run_id, '') = coalesce(?, '')
                        """,
                sourcePackageId.trim(),
                fixedRun.packageId().trim(),
                fixedAggregateRunId);
        Map<String, RuntimeEvidenceMetricResult> fixedMetricsByCode = fixedRun.metrics() == null
                ? Map.of()
                : fixedRun.metrics().stream()
                .filter(metric -> metric != null && StringUtils.hasText(metric.metricCode()))
                .collect(Collectors.toMap(
                        metric -> normalize(metric.metricCode()),
                        metric -> metric,
                        (left, right) -> left,
                        LinkedHashMap::new));
        List<RuntimeEvidenceReverifyFindingResult> results = new ArrayList<>();
        for (OperatorFinding finding : sourceFindings) {
            RuntimeEvidenceMetricResult fixedMetric = fixedMetricsByCode.get(normalize(finding.metricCode()));
            RuntimeEvidenceCheckResult fixedCheck = matchingCheck(fixedMetric, finding.checkCode());
            boolean fixedCriterionPassed = fixedCheck != null ? fixedCheck.pass() : fixedMetric != null && passed(fixedMetric);
            boolean sourceIssueGone = sourceIssueGoneFromFixedRun(finding.issueId(), fixedRun);
            boolean resolved = fixedCriterionPassed && sourceIssueGone;
            String state = fixedMetric == null
                    ? "NOT_VERIFIED"
                    : resolved ? "RESOLVED" : "UNRESOLVED";
            String fixedActualValue = fixedCheck == null
                    ? fixedMetric == null ? "\uC7AC\uAC80\uC99D \uB300\uC0C1 \uC9C0\uD45C\uAC00 \uCD5C\uC2E0 \uAC80\uC0AC\uC5D0\uC11C \uD655\uC778\uB418\uC9C0 \uC54A\uC558\uC2B5\uB2C8\uB2E4." : "\uCD5C\uC2E0 \uC9C0\uD45C \uC0C1\uD0DC " + safe(fixedMetric.state())
                    : safe(fixedCheck.actualValue());
            if (fixedCriterionPassed && !sourceIssueGone) {
                fixedActualValue = "\uD310\uC815 \uAE30\uC900\uC740 \uD1B5\uACFC\uD588\uC9C0\uB9CC \uC6D0\uBCF8 \uBB38\uC81C \uC5F0\uACB0\uC774 \uD574\uC18C\uB418\uC9C0 \uC54A\uC558\uC2B5\uB2C8\uB2E4.";
            }
            String problemTitle = safe(finding.operatorTitle(), "\uD574\uACB0 \uD655\uC778 \uB300\uC0C1 \uBB38\uC81C");
            String summary = resolved
                    ? "\uD574\uACB0 \uD655\uC778: '" + problemTitle + "' \uBB38\uC81C\uAC00 \uD574\uC18C\uB418\uC5C8\uACE0 \uC7AC\uAC80\uC99D \uAE30\uC900\uC744 \uD1B5\uACFC\uD588\uC2B5\uB2C8\uB2E4."
                    : "\uD574\uACB0 \uD655\uC778: '" + problemTitle + "' \uBB38\uC81C\uAC00 \uC544\uC9C1 \uD574\uC18C\uB418\uC9C0 \uC54A\uC544 \uC7AC\uAC80\uC99D \uAE30\uC900\uC744 \uD1B5\uACFC\uD558\uC9C0 \uBABB\uD588\uC2B5\uB2C8\uB2E4.";
            String sourceReason = customerText(
                    "reverify.sourceOperatorReason",
                    firstNonBlank(finding.problemStatement(), finding.operatorReason(), finding.operatorSummary()));
            String operatorSummary = customerText("reverify.operatorSummary", summary);
            RuntimeEvidenceReverifyFindingResult result = new RuntimeEvidenceReverifyFindingResult(
                    safe(finding.packageId()),
                    safe(finding.aggregateRunId()),
                    safe(fixedRun.packageId()),
                    fixedAggregateRunId,
                    safe(finding.findingId()),
                    safe(finding.issueId()),
                    safe(finding.metricCode()),
                    safe(finding.checkCode()),
                    resolved,
                    state,
                    safe(finding.reverifyCriterion()),
                    sourceReason,
                    safe(finding.actualValue()),
                    fixedActualValue,
                    operatorSummary);
            jdbcTemplate.update("""
                            insert into official_verification_reverify_result (
                                result_id, source_package_id, source_aggregate_run_id,
                                fixed_package_id, fixed_aggregate_run_id, source_finding_id,
                                issue_id, metric_code, check_code, reverify_criterion,
                                source_operator_reason, source_expected_value, source_actual_value,
                                fixed_actual_value, resolved, resolution_state, operator_summary,
                                created_by, diagnostic_catalog_version, created_at
                            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                    fit("ovr-" + UUID.randomUUID(), 256),
                    fit(result.sourcePackageId(), 256),
                    fit(result.sourceAggregateRunId(), 256),
                    fit(result.fixedPackageId(), 256),
                    fit(result.fixedAggregateRunId(), 256),
                    fit(result.findingId(), 256),
                    fit(result.issueId(), 256),
                    fit(result.metricCode(), 32),
                    fit(result.checkCode(), 128),
                    result.reverifyCriterion(),
                    result.sourceOperatorReason(),
                    finding.expectedValue(),
                    result.sourceActualValue(),
                    result.fixedActualValue(),
                    result.resolved(),
                    fit(result.resolutionState(), 64),
                    result.operatorSummary(),
                    fit(safe(operatorId, "runtime-pqa"), 128),
                    diagnosticCatalogVersion(),
                    nowTimestamp());
            results.add(result);
        }
        return List.copyOf(results);
    }

    private boolean sourceIssueGoneFromFixedRun(String issueId, RuntimeEvidenceVerificationRun fixedRun) {
        if (!StringUtils.hasText(issueId)
                || fixedRun == null
                || !StringUtils.hasText(fixedRun.packageId())
                || !StringUtils.hasText(fixedRun.runId())) {
            return false;
        }
        try {
            Integer count = jdbcTemplate.queryForObject("""
                            select count(*)
                              from official_actual_prompt_problem_ledger
                             where package_id = ?
                               and aggregate_run_id = ?
                               and problem_id = ?
                            """,
                    Integer.class,
                    fixedRun.packageId().trim(),
                    fixedRun.runId().trim(),
                    issueId.trim());
            return count == null || count == 0;
        } catch (DataAccessException ex) {
            return false;
        }
    }

    private List<OperatorMetricSnapshot> metricSnapshots(String aggregateRunId) {
        return jdbcTemplate.query("""
                        select aggregate_run_id, official_run_id, package_id, certificate_id, case_id,
                               metric_code, metric_name, metric_group, score, state, severity,
                               passed_checks, total_checks, failed_check_count, operator_title,
                               operator_summary, primary_failure_reason, remediation_owner,
                               next_action, reverify_criterion, diagnostic_catalog_version, created_at
                          from official_verification_metric_snapshot
                         where aggregate_run_id = ?
                         order by metric_code asc
                        """,
                this::metricSnapshot,
                aggregateRunId);
    }

    private List<OperatorMetricSnapshot> metricSnapshots(List<String> aggregateRunIds) {
        if (aggregateRunIds == null || aggregateRunIds.isEmpty()) {
            return List.of();
        }
        return jdbcTemplate.query("""
                        select aggregate_run_id, official_run_id, package_id, certificate_id, case_id,
                               metric_code, metric_name, metric_group, score, state, severity,
                               passed_checks, total_checks, failed_check_count, operator_title,
                               operator_summary, primary_failure_reason, remediation_owner,
                               next_action, reverify_criterion, diagnostic_catalog_version, created_at
                          from official_verification_metric_snapshot
                         where aggregate_run_id in (%s)
                         order by aggregate_run_id asc, metric_code asc
                        """.formatted(placeholders(aggregateRunIds)),
                this::metricSnapshot,
                aggregateRunIds.toArray());
    }

    private Set<String> normalizedSet(List<String> values) {
        if (values == null || values.isEmpty()) {
            return Set.of();
        }
        Set<String> result = new LinkedHashSet<>();
        for (String value : values) {
            String normalized = normalize(value);
            if (StringUtils.hasText(normalized)) {
                result.add(normalized);
            }
        }
        return Set.copyOf(result);
    }

    private RuntimeEvidenceCheckResult matchingCheck(RuntimeEvidenceMetricResult metric, String checkCode) {
        if (metric == null || metric.checks() == null || !StringUtils.hasText(checkCode)) {
            return null;
        }
        String metricCode = normalize(metric.metricCode());
        String normalizedCheckCode = normalize(canonicalMetricCheckCode(metricCode, checkCode));
        return metric.checks().stream()
                .filter(check -> check != null
                        && normalizedCheckCode.equals(normalize(canonicalMetricCheckCode(metricCode, check))))
                .findFirst()
                .orElse(null);
    }

    private List<OperatorFinding> findings(String aggregateRunId) {
        return jdbcTemplate.query("""
                        select finding_id, aggregate_run_id, official_run_id, package_id, certificate_id,
                               case_id, issue_id, metric_code, check_code, severity, operator_title,
                               operator_summary, problem_statement, root_cause, affected_target,
                               operator_reason, evidence_summary, evidence_path, expected_value,
                               actual_value, expected_result, actual_result, impact, remediation_owner,
                               next_action, reverify_criterion, customer_visible_severity,
                               related_process_step, comparison_field_key, comparison_state,
                               prompt_location, diagnostic_catalog_version, created_at
                          from official_verification_operator_finding
                         where aggregate_run_id = ?
                         order by metric_code asc, id asc
                        """,
                this::finding,
                aggregateRunId);
    }

    private List<OperatorFinding> findings(List<String> aggregateRunIds) {
        if (aggregateRunIds == null || aggregateRunIds.isEmpty()) {
            return List.of();
        }
        return jdbcTemplate.query("""
                        select finding_id, aggregate_run_id, official_run_id, package_id, certificate_id,
                               case_id, issue_id, metric_code, check_code, severity, operator_title,
                               operator_summary, problem_statement, root_cause, affected_target,
                               operator_reason, evidence_summary, evidence_path, expected_value,
                               actual_value, expected_result, actual_result, impact, remediation_owner,
                               next_action, reverify_criterion, customer_visible_severity,
                               related_process_step, comparison_field_key, comparison_state,
                               prompt_location, diagnostic_catalog_version, created_at
                          from official_verification_operator_finding
                         where aggregate_run_id in (%s)
                         order by aggregate_run_id asc, metric_code asc, id asc
                        """.formatted(placeholders(aggregateRunIds)),
                this::finding,
                aggregateRunIds.toArray());
    }

    private List<OperatorRemediationGroup> remediationGroups(String aggregateRunId) {
        return jdbcTemplate.query("""
                        select group_id, aggregate_run_id, package_id, certificate_id, case_id,
                               root_cause_key, remediation_owner, operator_title, operator_reason,
                               next_action, reverify_criterion, affected_metric_codes,
                               affected_check_codes, finding_count, related_process_step,
                               comparison_field_keys, prompt_locations, diagnostic_catalog_version, created_at
                          from official_verification_operator_remediation_group
                         where aggregate_run_id = ?
                         order by finding_count desc, remediation_owner asc, id asc
                        """,
                this::remediationGroup,
                aggregateRunId);
    }

    private List<OperatorRemediationGroup> remediationGroups(List<String> aggregateRunIds) {
        if (aggregateRunIds == null || aggregateRunIds.isEmpty()) {
            return List.of();
        }
        return jdbcTemplate.query("""
                        select group_id, aggregate_run_id, package_id, certificate_id, case_id,
                               root_cause_key, remediation_owner, operator_title, operator_reason,
                               next_action, reverify_criterion, affected_metric_codes,
                               affected_check_codes, finding_count, related_process_step,
                               comparison_field_keys, prompt_locations, diagnostic_catalog_version, created_at
                          from official_verification_operator_remediation_group
                         where aggregate_run_id in (%s)
                         order by aggregate_run_id asc, finding_count desc, remediation_owner asc, id asc
                        """.formatted(placeholders(aggregateRunIds)),
                this::remediationGroup,
                aggregateRunIds.toArray());
    }

    private List<OfficialActualPromptProblem> storedActualPromptProblems(String aggregateRunId) {
        if (!StringUtils.hasText(aggregateRunId)) {
            return List.of();
        }
        return jdbcTemplate.query("""
                        select problem_id, package_id, aggregate_run_id, field_key, problem_type,
                               prompt_section, prompt_label, prompt_value, source_field_path,
                               sealed_evidence_path, expected_state, actual_state, severity,
                               affected_metric_codes, remediation_owner, quality_question,
                               why_it_matters, fix_action, reverify_criterion_detail,
                               coalesce((
                                   select evidence.runtime_facts_json
                                     from official_metric_purpose_evidence_ledger evidence
                                    where evidence.aggregate_run_id = p.aggregate_run_id
                                      and evidence.purpose_evaluation_id = p.purpose_evaluation_id
                                      and evidence.customer_visible = true
                                    order by evidence.id desc
                                    limit 1
                               ), '[]') as runtime_facts_json,
                               coalesce((
                                   select evidence.context_items_json
                                     from official_metric_purpose_evidence_ledger evidence
                                    where evidence.aggregate_run_id = p.aggregate_run_id
                                      and evidence.purpose_evaluation_id = p.purpose_evaluation_id
                                      and evidence.customer_visible = true
                                    order by evidence.id desc
                                    limit 1
                               ), '[]') as context_items_json
                          from official_actual_prompt_problem_ledger p
                         where aggregate_run_id = ?
                           and upper(coalesce(problem_type, '')) <> 'INPUT_NOT_READY'
                          order by case when severity = 'BLOCKING' then 0 else 1 end,
                                   prompt_label asc, field_key asc, problem_id asc
                        """,
                this::storedActualPromptProblem,
                aggregateRunId);
    }

    private List<OfficialActualPromptProblem> storedActualPromptProblems(List<String> aggregateRunIds) {
        if (aggregateRunIds == null || aggregateRunIds.isEmpty()) {
            return List.of();
        }
        return jdbcTemplate.query("""
                        select problem_id, package_id, aggregate_run_id, field_key, problem_type,
                               prompt_section, prompt_label, prompt_value, source_field_path,
                               sealed_evidence_path, expected_state, actual_state, severity,
                               affected_metric_codes, remediation_owner, quality_question,
                               why_it_matters, fix_action, reverify_criterion_detail,
                               coalesce((
                                   select evidence.runtime_facts_json
                                     from official_metric_purpose_evidence_ledger evidence
                                    where evidence.aggregate_run_id = p.aggregate_run_id
                                      and evidence.purpose_evaluation_id = p.purpose_evaluation_id
                                      and evidence.customer_visible = true
                                    order by evidence.id desc
                                    limit 1
                               ), '[]') as runtime_facts_json,
                               coalesce((
                                   select evidence.context_items_json
                                     from official_metric_purpose_evidence_ledger evidence
                                    where evidence.aggregate_run_id = p.aggregate_run_id
                                      and evidence.purpose_evaluation_id = p.purpose_evaluation_id
                                      and evidence.customer_visible = true
                                    order by evidence.id desc
                                    limit 1
                               ), '[]') as context_items_json
                          from official_actual_prompt_problem_ledger p
                         where aggregate_run_id in (%s)
                           and upper(coalesce(problem_type, '')) <> 'INPUT_NOT_READY'
                          order by aggregate_run_id asc,
                                   case when severity = 'BLOCKING' then 0 else 1 end,
                                  prompt_label asc, field_key asc, problem_id asc
                        """.formatted(placeholders(aggregateRunIds)),
                this::storedActualPromptProblem,
                aggregateRunIds.toArray());
    }

    private List<OperatorPurposeEvidence> purposeEvidence(String aggregateRunId) {
        if (!StringUtils.hasText(aggregateRunId)) {
            return List.of();
        }
        List<OperatorPurposeEvidence> rows = jdbcTemplate.query("""
                        select aggregate_run_id, package_id, metric_code, check_code,
                               contract_version, signal_key, prompt_location, evidence_value,
                               evidence_hash, interpretation, purpose_result, customer_visible,
                               readiness_scope, created_at,
                               coalesce(evidence.runtime_facts_json, '[]') as runtime_facts_json,
                               coalesce(nullif(evidence.context_items_json, '[]'), (
                                   select payload.context_items_json
                                     from official_metric_customer_display_payload payload
                                    where payload.aggregate_run_id = evidence.aggregate_run_id
                                      and upper(payload.metric_code) = upper(evidence.metric_code)
                                      and payload.check_code = evidence.check_code
                                      and payload.contract_version = evidence.contract_version
                                      and payload.display_role = case
                                              when evidence.purpose_result = 'PURPOSE_FAILED' then 'FAIL_EVIDENCE'
                                              else 'PASS_EVIDENCE'
                                          end
                                      and coalesce(payload.context_items_json, '[]') <> '[]'
                                    order by payload.id desc
                                    limit 1
                               ), '[]') as context_items_json
                          from official_metric_purpose_evidence_ledger evidence
                         where aggregate_run_id = ?
                         order by metric_code asc, check_code asc, evidence.id asc
                        """,
                this::purposeEvidenceRow,
                aggregateRunId);
        return rows == null ? List.of() : rows;
    }

    private List<OperatorPurposeEvidence> purposeEvidence(List<String> aggregateRunIds) {
        if (aggregateRunIds == null || aggregateRunIds.isEmpty()) {
            return List.of();
        }
        return jdbcTemplate.query("""
                        select aggregate_run_id, package_id, metric_code, check_code,
                               contract_version, signal_key, prompt_location, evidence_value,
                               evidence_hash, interpretation, purpose_result, customer_visible,
                               readiness_scope, created_at,
                               coalesce(evidence.runtime_facts_json, '[]') as runtime_facts_json,
                               coalesce(nullif(evidence.context_items_json, '[]'), (
                                   select payload.context_items_json
                                     from official_metric_customer_display_payload payload
                                    where payload.aggregate_run_id = evidence.aggregate_run_id
                                      and upper(payload.metric_code) = upper(evidence.metric_code)
                                      and payload.check_code = evidence.check_code
                                      and payload.contract_version = evidence.contract_version
                                      and payload.display_role = case
                                              when evidence.purpose_result = 'PURPOSE_FAILED' then 'FAIL_EVIDENCE'
                                              else 'PASS_EVIDENCE'
                                          end
                                      and coalesce(payload.context_items_json, '[]') <> '[]'
                                    order by payload.id desc
                                    limit 1
                               ), '[]') as context_items_json
                          from official_metric_purpose_evidence_ledger evidence
                         where aggregate_run_id in (%s)
                         order by aggregate_run_id asc, metric_code asc, check_code asc, evidence.id asc
                        """.formatted(placeholders(aggregateRunIds)),
                this::purposeEvidenceRow,
                aggregateRunIds.toArray());
    }

    private List<OperatorAuditSnapshot> auditSnapshots(String aggregateRunId) {
        List<OperatorAuditSnapshot> rows = jdbcTemplate.query("""
                        select snapshot_id, aggregate_run_id, package_id, certificate_id, case_id,
                               state, state_label, total_metric_count, failed_metric_count,
                               certificate_issued, prompt_hash, context_hash, blocking_findings_json,
                               next_actions_json, payload_json, created_by,
                               diagnostic_catalog_version, created_at
                          from official_verification_audit_snapshot
                         where aggregate_run_id = ?
                         order by created_at desc, id desc
                        """,
                this::auditSnapshot,
                aggregateRunId);
        return rows == null ? List.of() : rows;
    }

    private List<OperatorAuditSnapshot> auditSnapshots(List<String> aggregateRunIds) {
        if (aggregateRunIds == null || aggregateRunIds.isEmpty()) {
            return List.of();
        }
        return jdbcTemplate.query("""
                        select snapshot_id, aggregate_run_id, package_id, certificate_id, case_id,
                               state, state_label, total_metric_count, failed_metric_count,
                               certificate_issued, prompt_hash, context_hash, blocking_findings_json,
                               next_actions_json, payload_json, created_by,
                               diagnostic_catalog_version, created_at
                          from official_verification_audit_snapshot
                         where aggregate_run_id in (%s)
                         order by aggregate_run_id asc, created_at desc, id desc
                        """.formatted(placeholders(aggregateRunIds)),
                this::auditSnapshot,
                aggregateRunIds.toArray());
    }

    private void insertBatch(
            String aggregateRunId,
            SealedEvidencePackage evidencePackage,
            String requestPath,
            String resourceId,
            String httpMethod,
            String promptHash,
            String contextHash,
            String certificateId,
            String caseId,
            List<RuntimeEvidenceMetricResult> metrics,
            Map<String, List<ActualPromptProblem>> problemsByMetric) {
        int total = metrics.size();
        int failed = (int) metrics.stream()
                .filter(metric -> actualPromptMetricBlocked(metric, problemsByMetric))
                .count();
        int notApplicable = (int) metrics.stream().filter(metric -> state(metric).equals("NOT_APPLICABLE")).count();
        int insufficient = (int) metrics.stream()
                .filter(metric -> !actualPromptMetricBlocked(metric, problemsByMetric))
                .filter(metric -> metricInputReadinessNotReady(metric)
                        || internalGateMetric(metric == null ? null : metric.metricCode()) && metricFailed(metric))
                .count();
        int passed = Math.max(total - failed - insufficient - notApplicable, 0);
        boolean blocked = failed > 0 || insufficient > 0 || total < 12;
        String finalDecision = blocked ? "BLOCKED" : "CERTIFIABLE";
        Map<String, Object> requestFacts = jsonMap(evidencePackage.getRequestFactsJson());
        Map<String, Object> promptMetadata = jsonMap(evidencePackage.getPromptExecutionMetadataJson());
        OfficialContextHashStateResolver.Resolution contextHashResolution =
                OfficialContextHashStateResolver.resolve(requestFacts, promptMetadata, evidencePackage.getCanonicalContextJson());
        String resolvedContextHash = firstNonBlank(contextHash, contextHashResolution.contextHash());
        String blockSummary = metrics.stream()
                .filter(metric -> actualPromptMetricBlocked(metric, problemsByMetric))
                .map(metric -> narrativeCatalog.metricName(metric.metricCode()) + ": "
                        + metricBlockReason(metric, problemsByMetric))
                .filter(StringUtils::hasText)
                .limit(5)
                .reduce((left, right) -> left + " / " + right)
                .orElse("");
        String safeBlockSummary = customerTextOrBlank("runBatch.blockReasonSummary", blockSummary);
        jdbcTemplate.update("""
                        insert into official_verification_run_batch (
                            aggregate_run_id, package_id, certificate_id, case_id, scope_type,
                            expected_metric_count, actual_metric_count, passed_metric_count,
                            failed_metric_count, insufficient_metric_count, not_applicable_metric_count,
                            final_decision, blocked, block_reason_summary, prompt_hash, context_hash,
                            context_hash_state, template_resource_id, actual_resource_id,
                            resource_url_template, actual_request_path, http_method,
                            started_at, completed_at, diagnostic_catalog_version, created_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                fit(aggregateRunId, 256),
                fit(evidencePackage.getPackageId(), 256),
                fit(certificateId, 256),
                fit(caseId, 256),
                "PROMPT_QUALITY",
                12,
                total,
                passed,
                failed,
                insufficient,
                notApplicable,
                finalDecision,
                blocked,
                safeBlockSummary,
                fit(promptHash, 160),
                fit(resolvedContextHash, 160),
                fit(contextHashResolution.state(), 64),
                fit(requestFact(evidencePackage, "protectableResourceId"), 256),
                fit(resourceId, 256),
                requestFact(evidencePackage, "protectableResourceUrl"),
                requestPath,
                fit(httpMethod, 32),
                nowTimestamp(),
                nowTimestamp(),
                diagnosticCatalogVersion(),
                nowTimestamp());
        deactivatePriorCurrentRowsForResource(aggregateRunId, requestPath, resourceId, httpMethod);
    }

    private void deactivatePriorCurrentRowsForResource(
            String aggregateRunId,
            String requestPath,
            String resourceId,
            String httpMethod
    ) {
        String resourceRef = firstNonBlank(requestPath, resourceId);
        if (!StringUtils.hasText(aggregateRunId)
                || !StringUtils.hasText(resourceRef)
                || !StringUtils.hasText(httpMethod)) {
            return;
        }
        jdbcTemplate.update("""
                        update official_verification_run_batch run
                           set current_result = false
                         where run.current_result = true
                           and run.aggregate_run_id <> ?
                           and upper(coalesce(run.http_method, '')) = upper(?)
                           and lower(coalesce(nullif(run.actual_request_path, ''),
                                              nullif(run.resource_url_template, ''),
                                              nullif(run.actual_resource_id, ''),
                                              '')) = lower(?)
                        """,
                fit(aggregateRunId, 256),
                fit(httpMethod, 32),
                resourceRef);
        jdbcTemplate.update("""
                        update official_actual_prompt_problem_ledger problem
                           set current_result = false
                         where problem.current_result = true
                           and exists (
                               select 1
                                 from official_verification_run_batch run
                                where run.package_id = problem.package_id
                                  and run.aggregate_run_id = problem.aggregate_run_id
                                  and run.current_result = false
                           )
                        """);
    }

    private void insertMetricSnapshot(
            String aggregateRunId,
            String packageId,
            String certificateId,
            String caseId,
            RuntimeEvidenceMetricResult metric,
            Map<String, String> issueIdsByMetric,
            List<ActualPromptProblem> metricProblems) {
        List<ActualPromptProblem> problems = metricProblems == null ? List.of() : metricProblems;
        String metricCode = safe(metric.metricCode());
        boolean blockedByActualPrompt = !problems.isEmpty();
        ActualPromptProblem firstProblem = problems.isEmpty() ? null : problems.get(0);
        boolean metricFailure = metricFailed(metric);
        RuntimeEvidenceCheckResult firstFailure = metricFailure ? firstFailedCheck(metric) : null;
        boolean notApplicable = state(metric).equals("NOT_APPLICABLE");
        boolean inputReviewCandidate = metricInputReadinessNotReady(metric);
        boolean gateReview = metricFailure
                && (internalGateMetric(metricCode)
                || (!blockedByActualPrompt && !inputReviewCandidate && !notApplicable));
        boolean inputReview = !gateReview && inputReviewCandidate;
        RuntimeEvidenceCheckResult firstNotApplicable = notApplicable ? firstNotApplicableCheck(metric) : null;
        boolean blocked = blockedByActualPrompt;
        String metricName = narrativeCatalog.metricName(metricCode);
        String primaryFailureReason = blockedByActualPrompt
                ? actualPromptProblemSummary(firstProblem)
                : notApplicable && firstNotApplicable != null
                ? notApplicableCheckMessage(firstNotApplicable)
                : metricSnapshotFailureReason(metric, firstFailure, inputReview, gateReview);
        int failedCheckCount = failedCheckCount(metric);
        int totalChecks = totalCheckCount(metric);
        int passedChecks = passedCheckCount(metric);
        double storedScore = metric.score();
        FinalPromptMetricContract metricContract = finalPromptMetricContract(metricCode);
        String metricPurpose = firstNonBlank(
                metricContract.qualityQuestion(),
                metricContract.purpose(),
                narrativeCatalog.metricPurpose(metricCode));
        String contractOperatorTitle = blockedByActualPrompt ? actualPromptProblemTitle(firstProblem) : metricName;
        String contractOperatorSummary = !blocked
                ? notApplicable && firstNotApplicable != null
                ? notApplicableCheckMessage(firstNotApplicable)
                : metricPurpose
                : primaryFailureReason;
        String remediationOwner = firstProblem != null
                ? ownerDisplayName(firstProblem.remediationOwner())
                : firstFailure == null
                ? "\uACF5\uC2DD\uAC80\uC0AC \uD1B5\uD569 \uACF5\uC815"
                : ownerDisplayName(firstFailure.remediationOwner());
        String nextAction = firstProblem != null
                ? actualPromptProblemAction(firstProblem)
                : notApplicable && firstNotApplicable != null
                ? notApplicableCheckMessage(firstNotApplicable)
                : firstFailure == null
                ? metricPurpose
                : metricSnapshotNextAction(metricCode, firstFailure, inputReview, gateReview);
        String reverifyCriterion = firstProblem != null
                ? actualPromptProblemReverify(firstProblem)
                : notApplicable && firstNotApplicable != null
                ? notApplicableCheckReverifyCriterion(firstNotApplicable)
                : firstFailure == null
                ? metricPurpose
                : metricSnapshotReverifyCriterion(metricCode, firstFailure, inputReview, gateReview);
        String storedState = blocked
                ? "BLOCKED"
                : gateReview ? "GATE_REVIEW" : inputReview ? "INPUT_NOT_READY" : notApplicable ? "NOT_APPLICABLE" : "SUCCESS";
        String storedSeverity = blocked ? "BLOCKING" : gateReview ? "GATE" : inputReview ? "INPUT" : "INFO";
        List<String> problemIds = problems.stream()
                .map(ActualPromptProblem::problemId)
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
        List<String> issueIds = problemIds;
        jdbcTemplate.update("""
                        insert into official_verification_metric_snapshot (
                            aggregate_run_id, official_run_id, package_id, certificate_id, case_id,
                            metric_code, metric_name, metric_group, score, state, severity,
                            passed_checks, total_checks, failed_check_count, operator_title,
                            operator_summary, primary_failure_reason, remediation_owner,
                            next_action, reverify_criterion, issue_ids_json, problem_ids_json,
                            diagnostic_catalog_version, current_result, created_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                fit(aggregateRunId, 256),
                fit(safe(metric.officialRunId()), 256),
                fit(packageId, 256),
                fit(certificateId, 256),
                fit(caseId, 256),
                fit(metricCode, 32),
                fit(metricName, 255),
                fit(safe(metric.groupName()), 128),
                storedScore,
                fit(storedState, 80),
                fit(storedSeverity, 32),
                passedChecks,
                totalChecks,
                failedCheckCount,
                fit(customerText("metricSnapshot.operatorTitle", contractOperatorTitle), 255),
                customerText("metricSnapshot.operatorSummary", contractOperatorSummary),
                customerTextOrBlank("metricSnapshot.primaryFailureReason", primaryFailureReason),
                fit(customerText("metricSnapshot.remediationOwner", remediationOwner), 128),
                customerText("metricSnapshot.nextAction", nextAction),
                customerText("metricSnapshot.reverifyCriterion", reverifyCriterion),
                writeJson(issueIds),
                writeJson(problemIds),
                diagnosticCatalogVersion(),
                true,
                nowTimestamp());
    }

    private void updateMetricExecutionIssueReferences(
            String aggregateRunId,
            List<RuntimeEvidenceMetricResult> metrics,
            Map<String, String> issueIdsByMetric,
            Map<String, List<ActualPromptProblem>> problemsByMetric) {
        if (!StringUtils.hasText(aggregateRunId) || metrics == null || metrics.isEmpty()) {
            return;
        }
        for (RuntimeEvidenceMetricResult metric : metrics) {
            if (metric == null || !StringUtils.hasText(metric.metricCode())) {
                continue;
            }
            String metricCode = normalize(metric.metricCode());
            List<String> problemIds = problemsByMetric == null ? List.of() : problemsByMetric
                    .getOrDefault(metricCode, List.of())
                    .stream()
                    .map(ActualPromptProblem::problemId)
                    .filter(StringUtils::hasText)
                    .distinct()
                    .toList();
            List<String> issueIds = problemIds;
            jdbcTemplate.update("""
                            update official_verification_metric_execution_ledger
                               set issue_ids_json = ?,
                                   problem_ids_json = ?,
                                   updated_at = ?
                             where aggregate_run_id = ?
                               and upper(metric_code) = ?
                            """,
                    writeJson(issueIds),
                    writeJson(problemIds),
                    nowTimestamp(),
                    aggregateRunId,
                    metricCode);
        }
    }

    private void insertFindings(
            String aggregateRunId,
            String packageId,
            String certificateId,
            String caseId,
            Map<String, String> issueIdsByMetric,
            RuntimeEvidenceMetricResult metric,
            List<ActualPromptProblem> metricProblems) {
        if (metric == null || metricProblems == null || metricProblems.isEmpty()) {
            return;
        }
        String metricCode = safe(metric.metricCode());
        for (ActualPromptProblem problem : metricProblems) {
            if (problem == null || !StringUtils.hasText(problem.problemId())) {
                continue;
            }
            String issueId = problem.problemId();
            String operatorTitle = customerText("finding.operatorTitle", actualPromptProblemTitle(problem));
            String operatorSummary = customerText("finding.operatorSummary", actualPromptProblemSummary(problem));
            String problemStatement = customerText("finding.problemStatement", actualPromptProblemStatement(problem));
            String rootCause = customerText("finding.rootCause", actualPromptProblemRootCause(problem));
            String affectedTarget = customerText("finding.affectedTarget", ownerDisplayName(problem.remediationOwner()));
            String operatorReason = customerText("finding.operatorReason", rootCause);
            String evidenceSummary = customerText("finding.evidenceSummary", actualPromptProblemEvidence(problem));
            String expectedResult = customerText("finding.expectedResult", actualPromptProblemExpectedResult(problem));
            String actualResult = customerText("finding.actualResult", actualPromptProblemActualResult(problem));
            String impact = customerText("finding.impact", actualPromptProblemRootCause(problem));
            String remediationOwner = customerText("finding.remediationOwner", affectedTarget);
            String nextAction = customerText("finding.nextAction", actualPromptProblemAction(problem));
            String reverifyCriterion = customerText("finding.reverifyCriterion", actualPromptProblemReverify(problem));
            String customerVisibleSeverity = customerText("finding.customerVisibleSeverity", severityLabel(problem.severity()));
            jdbcTemplate.update("""
                            insert into official_verification_operator_finding (
                                finding_id, aggregate_run_id, official_run_id, package_id,
                                certificate_id, case_id, issue_id, metric_code,
                                check_code, severity, operator_title, operator_summary,
                                problem_statement, root_cause, affected_target, operator_reason,
                                evidence_summary, evidence_path, expected_value, actual_value,
                                expected_result, actual_result, impact, remediation_owner,
                                next_action, reverify_criterion, customer_visible_severity,
                                related_process_step, comparison_field_key, comparison_state,
                                prompt_location, diagnostic_catalog_version, created_at
                            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                    fit("of-" + UUID.randomUUID(), 256),
                    fit(aggregateRunId, 256),
                    fit(safe(metric.officialRunId()), 256),
                    fit(packageId, 256),
                    fit(certificateId, 256),
                    fit(caseId, 256),
                    fit(issueId, 256),
                    fit(metricCode, 32),
                    fit(problem.problemId(), 128),
                    fit(safe(problem.severity(), "BLOCKING"), 32),
                    fit(operatorTitle, 255),
                    operatorSummary,
                    problemStatement,
                    rootCause,
                    fit(affectedTarget, 256),
                    operatorReason,
                    evidenceSummary,
                    fit(problem.sealedEvidencePath(), 512),
                    safe(problem.expectedState()),
                    safe(problem.actualState()),
                    expectedResult,
                    actualResult,
                    impact,
                    fit(remediationOwner, 128),
                    nextAction,
                    reverifyCriterion,
                    fit(customerVisibleSeverity, 64),
                    fit(firstNonBlank(processStepForProblem(problem), "OFFICIAL_VERIFICATION"), 128),
                    fit(problem.fieldKey(), 512),
                    fit(problem.problemType(), 64),
                    fit(problem.promptSection(), 256),
                    diagnosticCatalogVersion(),
                    nowTimestamp());
        }
    }

    private void assertCustomerMetricFailuresHaveActualPromptProblems(
            String aggregateRunId,
            List<RuntimeEvidenceMetricResult> metrics,
            Map<String, List<ActualPromptProblem>> problemsByMetric) {
        for (RuntimeEvidenceMetricResult metric : metrics == null ? List.<RuntimeEvidenceMetricResult>of() : metrics) {
            if (metric == null || !metricFailed(metric) || internalGateMetric(metric.metricCode())
                    || !hasCustomerPromptQualityFailure(metric)) {
                continue;
            }
            if (problemsByMetric.getOrDefault(normalize(metric.metricCode()), List.of()).isEmpty()) {
                throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-facing metric failed without an actual final userPrompt issue. "
                        + "aggregateRunId=" + aggregateRunId
                        + ", metricCode=" + safe(metric.metricCode())
                        + ", state=" + safe(metric.state()));
            }
        }
    }

    private boolean metricBlocked(
            RuntimeEvidenceMetricResult metric,
            Map<String, List<ActualPromptProblem>> problemsByMetric) {
        if (metric == null) {
            return false;
        }
        if (actualPromptMetricBlocked(metric, problemsByMetric)) {
            return true;
        }
        return metricInputReadinessNotReady(metric) || internalGateMetric(metric.metricCode()) && metricFailed(metric);
    }

    private boolean actualPromptMetricBlocked(
            RuntimeEvidenceMetricResult metric,
            Map<String, List<ActualPromptProblem>> problemsByMetric) {
        if (metric == null) {
            return false;
        }
        if (!problemsByMetric.getOrDefault(normalize(metric.metricCode()), List.of()).isEmpty()) {
            return true;
        }
        return false;
    }

    private String metricBlockReason(
            RuntimeEvidenceMetricResult metric,
            Map<String, List<ActualPromptProblem>> problemsByMetric) {
        List<ActualPromptProblem> problems = problemsByMetric.getOrDefault(normalize(metric.metricCode()), List.of());
        if (!problems.isEmpty()) {
            return firstProblemReason(problems);
        }
        RuntimeEvidenceCheckResult failedCheck = firstFailedCheck(metric);
        if (failedCheck != null && StringUtils.hasText(failedCheck.operatorReason())) {
            return failedCheck.operatorReason().trim();
        }
        return "차단된 지표에 연결된 문제 또는 실패 사유가 없습니다.";
    }

    private void insertRemediationGroups(
            String aggregateRunId,
            String packageId,
            String certificateId,
            String caseId,
            List<ActualPromptProblem> actualPromptProblems) {
        Map<String, RemediationGroupAccumulator> groups = new LinkedHashMap<>();
        for (ActualPromptProblem problem : actualPromptProblems == null ? List.<ActualPromptProblem>of() : actualPromptProblems) {
            if (problem == null) {
                continue;
            }
            if (!"BLOCKING".equals(normalize(problem.severity()))) {
                continue;
            }
            String owner = firstNonBlank(problem.remediationOwner(), "\uACF5\uC2DD\uAC80\uC0AC \uD1B5\uD569 \uACF5\uC815");
            String failureType = firstNonBlank(problem.problemType(), problem.fieldKey(), "PROMPT_FIELD_CONTRACT");
            String nextAction = actualPromptProblemAction(problem);
            String key = normalize(owner) + "|" + normalize(failureType) + "|" + normalize(nextAction);
            RemediationGroupAccumulator group = groups.computeIfAbsent(key, ignored ->
                    new RemediationGroupAccumulator(owner, failureType, nextAction, problem));
            group.add(problem);
        }
        for (RemediationGroupAccumulator group : groups.values()) {
            jdbcTemplate.update("""
                            insert into official_verification_operator_remediation_group (
                                group_id, aggregate_run_id, package_id, certificate_id, case_id,
                                root_cause_key, remediation_owner, operator_title, operator_reason,
                                next_action, reverify_criterion, affected_metric_codes,
                                affected_check_codes, finding_count, related_process_step,
                                comparison_field_keys, prompt_locations,
                                diagnostic_catalog_version, created_at
                            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                    fit("org-" + UUID.randomUUID(), 256),
                    fit(aggregateRunId, 256),
                    fit(packageId, 256),
                    fit(certificateId, 256),
                    fit(caseId, 256),
                    fit(group.failureType, 256),
                    fit(customerText("remediationGroup.remediationOwner", ownerDisplayName(group.owner)), 128),
                    fit(customerText("remediationGroup.operatorTitle", group.title()), 255),
                    customerText("remediationGroup.operatorReason", group.reason()),
                    customerText("remediationGroup.nextAction", group.nextAction),
                    customerText("remediationGroup.reverifyCriterion", group.reverifyCriterion()),
                    fit(group.metricCodes(), 512),
                    fit(group.checkCodes(), 2048),
                    group.findingCount,
                    "OFFICIAL_VERIFICATION",
                    fit(group.comparisonFieldKeys(), 2048),
                    fit(group.promptLocations(), 2048),
                    diagnosticCatalogVersion(),
                    nowTimestamp());
        }
    }

    private void insertPromptComparisons(
            String aggregateRunId,
            String packageId,
            List<OfficialVerificationPromptComparison> promptComparisons,
            List<ActualPromptProblem> actualPromptProblems) {
        Map<String, PromptComparisonLinkAccumulator> linksByField = promptComparisonLinks(aggregateRunId);
        Map<String, ActualPromptProblem> problemsByField = new LinkedHashMap<>();
        for (ActualPromptProblem problem : actualPromptProblems == null
                ? List.<ActualPromptProblem>of()
                : actualPromptProblems) {
            if (problem != null && StringUtils.hasText(problem.fieldKey())) {
                problemsByField.putIfAbsent(problem.fieldKey().trim(), problem);
            }
        }
        Set<String> insertedComparisonKeys = new LinkedHashSet<>();

        for (OfficialVerificationPromptComparison comparison : promptComparisons == null
                ? List.<OfficialVerificationPromptComparison>of()
                : promptComparisons) {
            if (comparison == null || !StringUtils.hasText(comparison.fieldKey())) {
                continue;
            }
            String fieldKey = comparison.fieldKey().trim();
            insertedComparisonKeys.add(promptComparisonDedupeKey(fieldKey, comparison.state()));
            PromptComparisonLinkAccumulator links = linksByField.get(fieldKey);
            ActualPromptProblem problem = problemsByField.get(fieldKey);
            insertPromptComparisonRow(
                    aggregateRunId,
                    packageId,
                    new OfficialVerificationPromptComparison(
                            fieldKey,
                            firstNonBlank(problem == null ? null : problem.promptLabel(), comparison.fieldLabel()),
                            comparison.sealedEvidenceValue(),
                            firstNonBlank(problem == null ? null : problem.promptValue(), comparison.promptValue()),
                            firstNonBlank(problem == null ? null : problem.expectedState(), comparison.officialFactValue()),
                            comparison.state(),
                            comparison.stateLabel(),
                            firstNonBlank(problem == null ? null : problem.whyItMatters(), comparison.meaning()),
                            merged(comparison.metricCodes(), links == null ? List.of() : links.metricCodes),
                            merged(comparison.checkCodes(), links == null ? List.of() : links.checkCodes),
                            merged(comparison.findingIds(), links == null ? List.of() : links.findingIds),
                            merged(comparison.issueIds(), links == null ? List.of() : links.issueIds),
                            merged(comparison.remediationGroupIds(), links == null ? List.of() : links.groupIds),
                            comparison.promptLocation(),
                            comparison.evidenceSource(),
                            firstNonBlank(comparison.recommendedOwner(), links == null ? "" : links.firstOwner()),
                            firstNonBlank(comparison.canonicalSource(), "PROMPT_COMPARISON")));
        }
    }

    private String promptComparisonDedupeKey(String fieldKey, String state) {
        return safe(fieldKey).trim() + "|" + normalize(state);
    }

    private void synchronizePromptComparisonLinks(String packageId, String aggregateRunId) {
        // Deliberately do not synthesize prompt comparison rows from metric findings here.
        // The official inspection result must be backed by the actual prompt problem ledger.
        // Missing links are detected by assertPromptComparisonLinksComplete during record().
    }

    private Map<String, PromptComparisonLinkAccumulator> promptComparisonLinks(String aggregateRunId) {
        List<OperatorFinding> findings = findings(aggregateRunId);
        List<OperatorRemediationGroup> groups = remediationGroups(aggregateRunId);
        Map<String, PromptComparisonLinkAccumulator> linksByField = new LinkedHashMap<>();
        for (OperatorFinding finding : findings) {
            String fieldKey = safe(finding.comparisonFieldKey());
            if (!StringUtils.hasText(fieldKey)) {
                throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Official finding is missing actual prompt problem field key."
                        + " aggregateRunId=" + safe(aggregateRunId)
                        + ", metricCode=" + safe(finding.metricCode())
                        + ", checkCode=" + safe(finding.checkCode()));
            }
            linksByField.computeIfAbsent(fieldKey, PromptComparisonLinkAccumulator::new)
                    .addFinding(finding);
        }
        for (OperatorRemediationGroup group : groups) {
            for (String fieldKey : group.comparisonFieldKeys()) {
                if (StringUtils.hasText(fieldKey)) {
                    linksByField.computeIfAbsent(fieldKey, PromptComparisonLinkAccumulator::new)
                            .addGroup(group);
                }
            }
        }
        return linksByField;
    }

    private void insertPromptComparisonRow(
            String aggregateRunId,
            String packageId,
            OfficialVerificationPromptComparison comparison) {
        jdbcTemplate.update("""
                        insert into official_verification_prompt_comparison (
                            comparison_id, aggregate_run_id, package_id, field_key, field_label,
                            sealed_evidence_value, prompt_value, official_fact_value, state,
                            state_label, meaning, prompt_location, evidence_source,
                            recommended_owner, related_metric_codes, related_check_codes,
                            related_finding_ids, related_issue_ids, related_remediation_group_ids,
                            canonical_source, created_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                new Object[] {
                        fit("opc-" + UUID.randomUUID(), 256),
                        fit(aggregateRunId, 256),
                        fit(packageId, 256),
                        fit(comparison.fieldKey(), 512),
                        fit(comparison.fieldLabel(), 255),
                        customerDisplayValue(comparison.sealedEvidenceValue()),
                        customerDisplayValue(comparison.promptValue()),
                        customerDisplayValue(comparison.officialFactValue()),
                        fit(safe(comparison.state(), "UNKNOWN"), 64),
                        fit(safe(comparison.stateLabel()), 120),
                        safe(comparison.meaning()),
                        fit(safe(comparison.promptLocation()), 256),
                        fit(safe(comparison.evidenceSource()), 512),
                        fit(safe(comparison.recommendedOwner()), 128),
                        fit(String.join(",", comparison.metricCodes()), 512),
                        fit(String.join(",", comparison.checkCodes()), 2048),
                        fit(String.join(",", comparison.findingIds()), 2048),
                        fit(String.join(",", comparison.issueIds()), 2048),
                        fit(String.join(",", comparison.remediationGroupIds()), 4096),
                        fit(safe(comparison.canonicalSource(), "PROMPT_COMPARISON"), 64),
                        nowTimestamp()
                });
    }

    private void upsertPromptFieldDefinitions(SealedEvidencePackage evidencePackage) {
        if (evidencePackage == null) {
            return;
        }
        Map<String, Object> manifest = parseJson(evidencePackage.getPromptEvidenceManifestJson());
        Object fields = manifest.get("fields");
        if (fields instanceof List<?> rows) {
            for (Object row : rows) {
                if (row instanceof Map<?, ?> map) {
                    upsertPromptFieldDefinitionFromManifestField(map);
                }
            }
        }
        Object fieldStateLedger = manifest.get("fieldStateLedger");
        if (fieldStateLedger instanceof List<?> rows) {
            for (Object row : rows) {
                if (row instanceof Map<?, ?> map) {
                    upsertPromptFieldDefinitionFromStateLedger(map);
                }
            }
        }
    }

    private void upsertPromptFieldDefinitionFromManifestField(Map<?, ?> row) {
        String fieldKey = stringValue(row.get("fieldKey"));
        if (!StringUtils.hasText(fieldKey)) {
            return;
        }
        Object promptLabels = row.get("promptLabels");
        String promptLabel = promptLabels instanceof List<?> labels && !labels.isEmpty()
                ? stringValue(labels.get(0))
                : stringValue(row.get("displayName"));
        upsertPromptFieldDefinition(
                fieldKey,
                defaultText(row.get("evidenceSection"), "SEALED_EVIDENCE"),
                null,
                null,
                defaultText(row.get("evidencePath"), fieldKey),
                "userPrompt",
                promptLabel,
                null,
                defaultText(row.get("requiredLevel"), "P1_REQUIRED_WITH_DECLARED_ABSENCE"),
                defaultText(row.get("projectionPolicy"), "MUST_MATCH_FINAL_USER_PROMPT_OR_DECLARED_POLICY"),
                defaultText(row.get("applicabilityRule"), "APPLIES_TO_POST_AUTH_ZERO_TRUST_LLM_DECISION"),
                defaultText(row.get("qualityRelevance"), "LLM_DECISION_CONTRACT"),
                String.join(",", objectStringList(row.get("metricCodes"))),
                defaultText(row.get("producerCode"), stringValue(row.get("producer"))),
                stringValue(row.get("notApplicableRule")));
    }

    private void upsertPromptFieldDefinitionFromStateLedger(Map<?, ?> row) {
        String fieldKey = stringValue(row.get("fieldKey"));
        if (!StringUtils.hasText(fieldKey)) {
            return;
        }
        upsertPromptFieldDefinition(
                fieldKey,
                defaultText(row.get("sourceType"), "SOURCE_CONTEXT"),
                sourcePackage(stringValue(row.get("sourceClass"))),
                stringValue(row.get("sourceClass")),
                defaultText(row.get("sourceFieldPath"), fieldKey),
                defaultText(row.get("promptSection"), stringValue(row.get("promptPresenceState"))),
                defaultText(row.get("promptLabel"), fieldKey),
                stringValue(row.get("valueType")),
                defaultText(row.get("requiredPolicy"), "SOURCE_STATE_CAPTURED"),
                defaultText(row.get("projectionPolicy"), "SEALED_SOURCE_ONLY"),
                defaultText(row.get("applicabilityRule"), "ALWAYS_CAPTURE_SOURCE_STATE"),
                defaultText(row.get("qualityRelevance"), "AUDIT_ONLY_SEALED_SOURCE"),
                String.join(",", objectStringList(row.get("metricCodes"))),
                defaultText(row.get("remediationOwner"), stringValue(row.get("producerStatus"))),
                stringValue(row.get("notApplicableRule")));
    }

    private void upsertPromptFieldDefinition(
            String fieldKey,
            String sourceModel,
            String sourcePackage,
            String sourceClass,
            String sourceFieldPath,
            String promptSection,
            String promptLabel,
            String valueType,
            String requiredPolicy,
            String projectionPolicy,
            String applicabilityRule,
            String qualityRelevance,
            String metricCodes,
            String remediationOwner,
            String notApplicableRule) {
        jdbcTemplate.update("""
                        insert into official_prompt_field_definition (
                            field_key, source_model, source_package, source_class, source_field_path,
                            prompt_section, prompt_label, value_type,
                            required_policy, projection_policy, applicability_rule, quality_relevance,
                            metric_codes, remediation_owner, not_applicable_rule, is_active, created_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, true, ?)
                        on conflict (field_key) do update set
                            source_model = excluded.source_model,
                            source_package = excluded.source_package,
                            source_class = excluded.source_class,
                            source_field_path = excluded.source_field_path,
                            prompt_section = excluded.prompt_section,
                            prompt_label = excluded.prompt_label,
                            value_type = excluded.value_type,
                            required_policy = case
                                when official_prompt_field_definition.quality_relevance <> 'AUDIT_ONLY_SEALED_SOURCE'
                                     and excluded.quality_relevance = 'AUDIT_ONLY_SEALED_SOURCE'
                                then official_prompt_field_definition.required_policy
                                else excluded.required_policy
                            end,
                            projection_policy = case
                                when official_prompt_field_definition.quality_relevance <> 'AUDIT_ONLY_SEALED_SOURCE'
                                     and excluded.quality_relevance = 'AUDIT_ONLY_SEALED_SOURCE'
                                then official_prompt_field_definition.projection_policy
                                else excluded.projection_policy
                            end,
                            applicability_rule = excluded.applicability_rule,
                            quality_relevance = case
                                when official_prompt_field_definition.quality_relevance <> 'AUDIT_ONLY_SEALED_SOURCE'
                                     and excluded.quality_relevance = 'AUDIT_ONLY_SEALED_SOURCE'
                                then official_prompt_field_definition.quality_relevance
                                else excluded.quality_relevance
                            end,
                            metric_codes = case
                                when official_prompt_field_definition.quality_relevance <> 'AUDIT_ONLY_SEALED_SOURCE'
                                     and excluded.quality_relevance = 'AUDIT_ONLY_SEALED_SOURCE'
                                then official_prompt_field_definition.metric_codes
                                else excluded.metric_codes
                            end,
                            remediation_owner = case
                                when official_prompt_field_definition.quality_relevance <> 'AUDIT_ONLY_SEALED_SOURCE'
                                     and excluded.quality_relevance = 'AUDIT_ONLY_SEALED_SOURCE'
                                then official_prompt_field_definition.remediation_owner
                                else excluded.remediation_owner
                            end,
                            not_applicable_rule = excluded.not_applicable_rule,
                            is_active = true
                        """,
                fit(fieldKey, 512),
                fit(firstNonBlank(sourceModel, "SOURCE_CONTEXT"), 256),
                fit(sourcePackage, 512),
                fit(sourceClass, 512),
                fit(firstNonBlank(sourceFieldPath, fieldKey), 1024),
                fit(promptSection, 128),
                fit(promptLabel, 256),
                fit(valueType, 256),
                fit(firstNonBlank(requiredPolicy, "SOURCE_STATE_CAPTURED"), 64),
                fit(firstNonBlank(projectionPolicy, "SEALED_SOURCE_ONLY"), 64),
                fit(applicabilityRule, 256),
                fit(firstNonBlank(qualityRelevance, "AUDIT_ONLY_SEALED_SOURCE"), 64),
                fit(metricCodes, 256),
                fit(remediationOwner, 128),
                safe(notApplicableRule),
                nowTimestamp());
    }

    private List<ActualPromptProblem> actualPromptProblems(
            String aggregateRunId,
            String packageId,
            SealedEvidencePackage evidencePackage,
            List<RuntimeEvidenceMetricResult> metrics,
            List<OfficialVerificationPromptComparison> promptComparisons) {
        if (!StringUtils.hasText(aggregateRunId) || !StringUtils.hasText(packageId)) {
            return List.of();
        }
        Map<String, ActualPromptProblem> problems = new LinkedHashMap<>();
        addActualPromptProblemsFromMetricChecks(problems, aggregateRunId, packageId, metrics);
        addActualPromptProblemsFromPromptComparisons(problems, aggregateRunId, packageId, promptComparisons);
        return List.copyOf(problems.values());
    }

    private void addActualPromptProblemsFromMetricChecks(
            Map<String, ActualPromptProblem> problems,
            String aggregateRunId,
            String packageId,
            List<RuntimeEvidenceMetricResult> metrics) {
        if (metrics == null || metrics.isEmpty()) {
            return;
        }
        for (RuntimeEvidenceMetricResult metric : metrics) {
            if (metric == null || !metricFailed(metric) || internalGateMetric(metric.metricCode()) || metric.checks() == null) {
                continue;
            }
            String metricCode = normalize(metric.metricCode());
            for (RuntimeEvidenceCheckResult check : metric.checks()) {
                if (check == null || check.pass() || inputReadinessNotReady(check) || !customerPromptQualityCheck(check)
                        || !"BLOCKING".equalsIgnoreCase(safe(check.severity(), ""))) {
                    continue;
                }
                String fieldKey = firstNonBlank(check.issueKey(), check.source());
                if (!officialPromptIssueField(fieldKey)) {
                    continue;
                }
                FinalPromptMetricCheckContract contract = customerPromptProblemContract(metricCode, check);
                String problemType = contract.failureType();
                addActualPromptProblem(
                        problems,
                        aggregateRunId,
                        packageId,
                        contract.issueKey(),
                        problemType,
                        contract.source(),
                        contract.problemTitle(),
                        contract.shortProblem(),
                        concreteSourceFieldPath(check, contract),
                        sealedEvidencePromptPath(contract.issueKey()),
                        contract.expectedMessage(),
                        concreteActualPromptProblemState(check, contract),
                        contract.severity(),
                        List.of(metricCode),
                        contract.remediationOwner(),
                        "FINAL_PROMPT_METRIC_PURPOSE",
                        contract.qualityQuestion(),
                        contract.whyItMatters(),
                        contract.nextAction(),
                        contract.reverifyCriterion());
            }
        }
    }

    private void addActualPromptProblemsFromPromptComparisons(
            Map<String, ActualPromptProblem> problems,
            String aggregateRunId,
            String packageId,
            List<OfficialVerificationPromptComparison> promptComparisons) {
        if (promptComparisons == null || promptComparisons.isEmpty()) {
            return;
        }
        for (OfficialVerificationPromptComparison comparison : promptComparisons) {
            if (!blockingPromptComparison(comparison) || "OFFICIAL_FINDING".equalsIgnoreCase(safe(comparison.canonicalSource()))) {
                continue;
            }
            if (!officialPromptIssueField(comparison.fieldKey())) {
                continue;
            }
            List<String> metricCodes = promptComparisonMetricCodes(comparison);
            if (metricCodes.isEmpty()) {
                throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Prompt comparison problem is not bound to any official metric. "
                        + "fieldKey=" + safe(comparison.fieldKey())
                        + ", state=" + safe(comparison.state()));
            }
            String problemType = normalize(firstNonBlank(comparison.state(), "CONTRACT_MISMATCH"));
            String label = firstNonBlank(comparison.fieldLabel(), comparison.fieldKey(), "Prompt field");
            String promptLocation = firstNonBlank(comparison.promptLocation(), comparison.fieldKey(), "finalUserPrompt");
            addActualPromptProblem(
                    problems,
                    aggregateRunId,
                    packageId,
                    comparison.fieldKey(),
                    problemType,
                    promptLocation,
                    label,
                    firstNonBlank(comparison.promptValue(), comparison.meaning(), label),
                    promptLocation,
                    firstNonBlank(comparison.evidenceSource(), sealedEvidencePromptPath(comparison.fieldKey()), promptLocation),
                    promptComparisonExpectedState(comparison),
                    promptComparisonActualState(comparison),
                    "BLOCKING",
                    metricCodes,
                    firstNonBlank(comparison.recommendedOwner(), "PROMPT_ASSEMBLER"),
                    "PROMPT_COMPARISON",
                    "Does the final prompt preserve the sealed evidence contract for this field?",
                    firstNonBlank(comparison.meaning(), "A final prompt field is not synchronized with its sealed evidence contract."),
                    "Fix the source that creates this prompt field, collect new sealed evidence, and rerun official inspection.",
                    "The same prompt field must be recorded as matched or non-blocking in the next official inspection.");
        }
    }

    private boolean blockingPromptComparison(OfficialVerificationPromptComparison comparison) {
        if (comparison == null) {
            return false;
        }
        String state = safe(comparison.state()).toUpperCase(Locale.ROOT);
        if (state.startsWith("FINAL_PROMPT_")) {
            return true;
        }
        return switch (state) {
            case "PROMPT_MISSING",
                    "FACT_MISSING",
                    "VALUE_MISMATCH",
                    "CONTRACT_MISMATCH",
                    "REQUIRED_MISSING",
                    "CONDITIONAL_REQUIRED_MISSING",
                    "UNKNOWN_WITHOUT_REASON",
                    "PROMPT_COMPACTED_SIGNAL",
                    "PRODUCER_NOT_AVAILABLE",
                    "PROVISIONAL_EVIDENCE",
                    "NO_DIRECT_COMPARABLE",
                    "BASELINE_MISMATCH_SIGNAL" -> true;
            default -> false;
        };
    }

    private List<String> promptComparisonMetricCodes(OfficialVerificationPromptComparison comparison) {
        List<String> result = new ArrayList<>();
        if (comparison != null && comparison.metricCodes() != null) {
            for (String metricCode : comparison.metricCodes()) {
                if (StringUtils.hasText(metricCode)) {
                    appendUnique(result, normalize(metricCode));
                }
            }
        }
        return List.copyOf(result);
    }

    private String promptComparisonExpectedState(OfficialVerificationPromptComparison comparison) {
        if (comparison == null) {
            return "The actual prompt field must satisfy the sealed evidence contract.";
        }
        String state = safe(comparison.state()).toUpperCase(Locale.ROOT);
        return switch (state) {
            case "PROMPT_MISSING" -> "The sealed evidence value must be visible in the final LLM user prompt.";
            case "FACT_MISSING" -> "The final LLM user prompt field must also be stored in the sealed evidence package.";
            case "VALUE_MISMATCH", "CONTRACT_MISMATCH" -> "The final LLM user prompt value and the sealed evidence value must match.";
            case "REQUIRED_MISSING", "CONDITIONAL_REQUIRED_MISSING" -> "The required prompt evidence field must be present or have an allowed absence policy.";
            case "UNKNOWN_WITHOUT_REASON" -> "Unknown prompt evidence must include a recorded reason and remediation owner.";
            case "PROMPT_COMPACTED_SIGNAL" -> "Prompt compaction must preserve full source lineage and field-level diff evidence.";
            case "PRODUCER_NOT_AVAILABLE" -> "The required context producer must record its unavailable state and reason.";
            case "PROVISIONAL_EVIDENCE" -> "Provisional evidence must be explicitly labeled and not represented as confirmed evidence.";
            case "NO_DIRECT_COMPARABLE" -> "Comparable-history absence must be recorded as a bounded evidence limitation.";
            case "BASELINE_MISMATCH_SIGNAL" -> "Baseline mismatch signals must be visible and linked to the final prompt evidence.";
            default -> firstNonBlank(comparison.officialFactValue(), comparison.sealedEvidenceValue(), comparison.meaning(),
                    "The actual prompt field must satisfy the sealed evidence contract.");
        };
    }

    private String promptComparisonActualState(OfficialVerificationPromptComparison comparison) {
        if (comparison == null) {
            return "An actual prompt problem was recorded.";
        }
        String state = safe(comparison.state()).toUpperCase(Locale.ROOT);
        return switch (state) {
            case "PROMPT_MISSING" -> "The final user prompt does not contain the sealed evidence value for this field.";
            case "FACT_MISSING" -> "The sealed evidence package does not contain the final prompt value for this field.";
            case "VALUE_MISMATCH", "CONTRACT_MISMATCH" -> "The final prompt value and the sealed evidence value do not match for this field.";
            case "REQUIRED_MISSING", "CONDITIONAL_REQUIRED_MISSING" -> "A required prompt evidence field was recorded as missing.";
            case "UNKNOWN_WITHOUT_REASON" -> "The field is unknown and no reason was recorded.";
            case "PROMPT_COMPACTED_SIGNAL" -> "The prompt was compacted or changed without complete field-level lineage.";
            case "PRODUCER_NOT_AVAILABLE" -> "The context producer did not provide the required field.";
            case "PROVISIONAL_EVIDENCE" -> "The field is provisional and must remain explicitly bounded.";
            case "NO_DIRECT_COMPARABLE" -> "No direct comparable history was recorded for the field.";
            case "BASELINE_MISMATCH_SIGNAL" -> "The field carries a baseline mismatch signal that requires explanation.";
            default -> firstNonBlank(comparison.promptValue(), comparison.meaning(), "The actual prompt problem must be reviewed.");
        };
    }

    private String concreteSourceFieldPath(
            RuntimeEvidenceCheckResult check,
            FinalPromptMetricCheckContract contract) {
        for (String signal : jsonStringList(check == null ? null : check.detectedSignalsJson())) {
            String parsed = concreteSourceFromSignal(signal);
            if (StringUtils.hasText(parsed)) {
                return parsed;
            }
        }
        return contract == null ? "" : contract.source();
    }

    private String concreteSourceFromSignal(String signal) {
        if (!StringUtils.hasText(signal)) {
            return "";
        }
        String trimmed = signal.trim();
        String[] prefixes = {
                "truncatedField=",
                "truncatedBullet=",
                "truncatedNarrative=",
                "unmappedPromptFact="
        };
        for (String prefix : prefixes) {
            if (!trimmed.startsWith(prefix)) {
                continue;
            }
            String value = trimmed.substring(prefix.length()).trim();
            int valueIndex = value.indexOf(" value=");
            return valueIndex < 0 ? value : value.substring(0, valueIndex).trim();
        }
        return "";
    }

    private String concreteActualPromptProblemState(
            RuntimeEvidenceCheckResult check,
            FinalPromptMetricCheckContract contract) {
        if (check != null && StringUtils.hasText(check.purposeVersion())) {
            return customerDisplayPayload(check, contract).evidenceText();
        }
        String concrete = concreteDetectedSignalSummary(check);
        if (StringUtils.hasText(concrete)) {
            return requireCustomerLedgerText(customerDisplayValue(concrete), check, "purpose.actual_value");
        }
        String actual = check == null ? "" : check.actualValue();
        if (StringUtils.hasText(actual)) {
            return requireCustomerLedgerText(actual.trim(), check, "purpose.actual_value");
        }
        return contract == null ? "" : contract.failureMessage();
    }

    private String purposeLedgerActualValue(
            RuntimeEvidenceCheckResult check,
            boolean customerVisible,
            FinalPromptMetricCheckContract checkContract) {
        if (!customerVisible) {
            return concreteMetricActualValue(check);
        }
        if (check == null || !StringUtils.hasText(check.purposeVersion())) {
            return legacyCustomerPurposeActualValue(check);
        }
        CustomerDisplayPayloadFactory.Payload payload = customerDisplayPayload(check, checkContract);
        String structuredEvidence = payload.evidenceText();
        return structuredEvidence;
    }

    private String purposeLedgerExpectedValue(
            RuntimeEvidenceCheckResult check,
            boolean customerVisible,
            FinalPromptMetricCheckContract checkContract) {
        String expectedValue = check == null ? "" : check.expectedValue();
        if (!customerVisible) {
            return expectedValue;
        }
        if (checkContract != null && StringUtils.hasText(checkContract.expectedMessage())) {
            return requireCustomerLedgerText(checkContract.expectedMessage(), check, "purpose.expected_value");
        }
        if (check == null || !StringUtils.hasText(check.purposeVersion())) {
            return legacyCustomerExpectedValue(check);
        }
        throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose check has no contract expected message. "
                + "metric=" + safe(check.metricCode())
                + ", check=" + safe(check.checkCode())
                + ", purposeVersion=" + safe(check.purposeVersion()));
    }

    private String purposeLedgerDecisionUtility(
            RuntimeEvidenceCheckResult check,
            boolean customerVisible,
            FinalPromptMetricCheckContract checkContract) {
        String decisionUtility = check == null ? "" : check.decisionUtility();
        if (!customerVisible) {
            return decisionUtility;
        }
        if (checkContract != null && StringUtils.hasText(checkContract.whyItMatters())) {
            return requireCustomerLedgerText(checkContract.whyItMatters(), check, "purpose.decision_utility");
        }
        if (check == null || !StringUtils.hasText(check.purposeVersion())) {
            String legacy = firstNonBlank(
                    decisionUtility,
                    check == null ? null : check.whyItMatters(),
                    check == null ? null : check.operatorReason(),
                    check == null ? null : check.expectedValue(),
                    check == null ? null : check.label());
            return requireCustomerLedgerText(customerDisplayValue(legacy), check, "purpose.decision_utility");
        }
        throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose check has no contract decision utility. "
                + "metric=" + safe(check.metricCode())
                + ", check=" + safe(check.checkCode())
                + ", purposeVersion=" + safe(check.purposeVersion()));
    }

    private String legacyCustomerExpectedValue(RuntimeEvidenceCheckResult check) {
        String text = firstNonBlank(
                check == null ? null : check.expectedValue(),
                check == null ? null : check.decisionUtility(),
                check == null ? null : check.whyItMatters(),
                check == null ? null : check.label());
        text = stripCustomerLedgerPrefix(text);
        if (!StringUtils.hasText(text)) {
            return "";
        }
        return requireCustomerLedgerText(customerDisplayValue(text), check, "purpose.expected_value");
    }

    private String stripCustomerLedgerPrefix(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        String text = value.trim();
        String[] prefixes = {"문제:", "확인된 값:", "해결 방안:", "재검사 기준:"};
        for (String prefix : prefixes) {
            if (text.startsWith(prefix)) {
                return text.substring(prefix.length()).trim();
            }
        }
        return text;
    }

    private String legacyCustomerPurposeActualValue(RuntimeEvidenceCheckResult check) {
        String structuredEvidence = customerPurposeEvidenceActualValue(check);
        if (StringUtils.hasText(structuredEvidence)) {
            return requireCustomerLedgerText(structuredEvidence, check, "purpose.actual_value");
        }
        String concrete = concreteDetectedSignalSummary(customerVisiblePurposeSignals(
                effectiveDetectedSignals(check),
                check,
                true));
        if (StringUtils.hasText(concrete)) {
            return requireCustomerLedgerText(customerDisplayValue(concrete), check, "purpose.actual_value");
        }
        List<String> fragments = customerEvidenceFragments(check == null ? "" : check.actualValue());
        if (!fragments.isEmpty()) {
            return requireCustomerLedgerText(
                    "확인된 근거는 " + joinCustomerFragments(fragments) + "입니다.",
                    check,
                    "purpose.actual_value");
        }
        String actual = check == null ? "" : check.actualValue();
        if (StringUtils.hasText(actual) && !customerVisibleTechnicalText(actual)) {
            return requireCustomerLedgerText(actual.trim(), check, "purpose.actual_value");
        }
        String contractText = check == null
                ? ""
                : firstNonBlank(check.operatorReason(), check.expectedValue(), check.decisionUtility(), check.whyItMatters());
        if (StringUtils.hasText(contractText) && !customerVisibleTechnicalText(contractText)) {
            return requireCustomerLedgerText(contractText.trim(), check, "purpose.actual_value");
        }
        throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose actual value is not contract-backed. "
                + "metric=" + safe(check == null ? null : check.metricCode())
                + ", check=" + safe(check == null ? null : check.checkCode()));
    }

    private String customerPurposeEvidenceActualValue(RuntimeEvidenceCheckResult check) {
        List<CustomerPurposeEvidenceDisplay> displays = customerPurposeEvidenceDisplays(check);
        if (displays.isEmpty()) {
            return "";
        }
        return customerDisplayJoinedText(
                displays.stream()
                        .map(CustomerPurposeEvidenceDisplay::evidenceValue)
                        .toList(),
                check,
                "purpose.actual_value");
    }

    private CustomerDisplayPayloadFactory.Payload customerDisplayPayload(
            RuntimeEvidenceCheckResult check,
            FinalPromptMetricCheckContract checkContract) {
        if (check == null) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer display payload requires a metric check.");
        }
        List<CustomerPurposeEvidenceDisplay> displays = customerPurposeEvidenceDisplays(check, checkContract);
        String title = displays.stream()
                .map(CustomerPurposeEvidenceDisplay::signalKey)
                .filter(StringUtils::hasText)
                .findFirst()
                .orElseGet(() -> requireCustomerLedgerText(firstNonBlank(
                                checkContract == null ? null : checkContract.problemTitle(),
                                checkContract == null ? null : checkContract.passMessage(),
                                check.label(),
                                check.expectedValue()),
                        check,
                        "customer_display.title"));
        String evidenceText = customerDisplayJoinedText(
                displays.stream()
                        .map(CustomerPurposeEvidenceDisplay::evidenceValue)
                        .toList(),
                check,
                "purpose.actual_value");
        String purposeResult = effectivePurposeResult(check);
        String resolutionAction = "";
        String reverifyCondition = "";
        if (!"PURPOSE_PASSED".equals(purposeResult) && !"NOT_APPLICABLE".equals(purposeResult)) {
            resolutionAction = requireCustomerLedgerText(
                    firstNonBlank(checkContract == null ? null : checkContract.nextAction(), check.nextAction()),
                    check,
                    "purpose.next_action");
            reverifyCondition = requireCustomerLedgerText(
                    firstNonBlank(checkContract == null ? null : checkContract.reverifyCriterion(), check.reverifyCriterion()),
                    check,
                    "purpose.reverify_criterion");
        }
        return customerDisplayPayloadFactory.create(new CustomerDisplayPayloadFactory.Request(
                title,
                displays.stream()
                        .map(display -> new CustomerDisplayPayloadFactory.EvidenceDisplay(
                                display.signalKey(),
                                display.evidenceValue()))
                        .toList(),
                requireCustomerLedgerText(firstNonBlank(checkContract == null ? null : checkContract.whyItMatters(), check.whyItMatters(), title),
                        check,
                        "customer_display.why_it_matters"),
                resolutionAction,
                reverifyCondition,
                effectivePurposeResult(check)));
    }

    private List<CustomerPurposeEvidenceDisplay> customerPurposeEvidenceDisplays(RuntimeEvidenceCheckResult check) {
        return customerPurposeEvidenceDisplays(check, null);
    }

    private List<CustomerPurposeEvidenceDisplay> customerPurposeEvidenceDisplays(
            RuntimeEvidenceCheckResult check,
            FinalPromptMetricCheckContract checkContract) {
        if (check == null) {
            return List.of();
        }
        List<String> signals = customerVisiblePurposeSignals(effectiveDetectedSignals(check), check, true);
        if (signals.isEmpty() && StringUtils.hasText(check.purposeVersion())) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible metric purpose evidence is missing. "
                    + "metric=" + safe(check.metricCode())
                    + ", check=" + safe(check.checkCode()));
        }
        List<CustomerPurposeEvidenceDisplay> displays = new ArrayList<>();
        for (String signal : signals) {
            CustomerPurposeEvidenceDisplay display = customerPurposeEvidenceDisplay(signal, check, checkContract);
            if (display == null) {
                continue;
            }
            assertCustomerPurposeEvidenceDisplay(display, check, checkContract);
            displays.add(display);
        }
        if (displays.isEmpty() && StringUtils.hasText(check.purposeVersion())) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible metric purpose evidence did not produce display payload. "
                    + "metric=" + safe(check.metricCode())
                    + ", check=" + safe(check.checkCode()));
        }
        return List.copyOf(displays);
    }

    private String customerDisplayJoinedText(
            List<String> values,
            RuntimeEvidenceCheckResult check,
            String ledgerField) {
        List<String> cleaned = new ArrayList<>();
        for (String value : values == null ? List.<String>of() : values) {
            if (!StringUtils.hasText(value)) {
                continue;
            }
            appendUnique(cleaned, requireCustomerLedgerText(value, check, ledgerField));
        }
        if (cleaned.isEmpty()) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer display payload has no customer evidence text. "
                    + "field=" + ledgerField
                    + ", metric=" + safe(check == null ? null : check.metricCode())
                    + ", check=" + safe(check == null ? null : check.checkCode()));
        }
        return requireCustomerLedgerText(String.join(" ", cleaned), check, ledgerField);
    }

    private String purposeLedgerNextAction(
            RuntimeEvidenceCheckResult check,
            boolean customerVisible,
            FinalPromptMetricCheckContract checkContract) {
        String nextAction = check == null ? "" : check.nextAction();
        if (!customerVisible) {
            return nextAction;
        }
        String purposeResult = effectivePurposeResult(check);
        if ("PURPOSE_PASSED".equals(purposeResult) || "NOT_APPLICABLE".equals(purposeResult)) {
            return "";
        }
        if (check == null || !StringUtils.hasText(check.purposeVersion())) {
            if (checkContract != null && StringUtils.hasText(checkContract.nextAction())) {
                return requireCustomerLedgerText(checkContract.nextAction(), check, "purpose.next_action");
            }
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose check has no contract next action. "
                    + "metric=" + safe(check == null ? null : check.metricCode())
                    + ", check=" + safe(check == null ? null : check.checkCode())
                    + ", purposeVersion=" + safe(check == null ? null : check.purposeVersion()));
        }
        return customerDisplayPayload(check, checkContract).resolutionAction();
    }

    private String purposeLedgerReverifyCriterion(
            RuntimeEvidenceCheckResult check,
            boolean customerVisible,
            FinalPromptMetricCheckContract checkContract) {
        String reverifyCriterion = check == null ? "" : check.reverifyCriterion();
        if (!customerVisible) {
            return reverifyCriterion;
        }
        String purposeResult = effectivePurposeResult(check);
        if ("PURPOSE_PASSED".equals(purposeResult) || "NOT_APPLICABLE".equals(purposeResult)) {
            return "";
        }
        if (check == null || !StringUtils.hasText(check.purposeVersion())) {
            if (checkContract != null && StringUtils.hasText(checkContract.reverifyCriterion())) {
                return requireCustomerLedgerText(checkContract.reverifyCriterion(), check, "purpose.reverify_criterion");
            }
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose check has no contract reverify criterion. "
                    + "metric=" + safe(check == null ? null : check.metricCode())
                    + ", check=" + safe(check == null ? null : check.checkCode())
                    + ", purposeVersion=" + safe(check == null ? null : check.purposeVersion()));
        }
        return customerDisplayPayload(check, checkContract).reverifyCondition();
    }

    private boolean customerVisibleTechnicalText(String value) {
        if (!StringUtils.hasText(value)) {
            return false;
        }
        String text = value.trim();
        if (text.contains("Evidence:") || text.contains("evidence:")) {
            return true;
        }
        if (CUSTOMER_TECHNICAL_CONTRACT_CODE.matcher(text).find()) {
            return true;
        }
        if (customerVisiblePromptLocationToken(text)) {
            return true;
        }
        if (text.startsWith("field:")
                || text.startsWith("section:")
                || text.startsWith("label:")
                || text.startsWith("term:")
                || text.startsWith("thenLabel:")
                || text.startsWith("thenTerm:")
                || text.startsWith("source:")) {
            return true;
        }
        if (text.contains("missingLabels=")
                || text.contains("compactMarker=")
                || text.contains("unmappedPromptFact=")
                || text.contains("truncatedField=")
                || text.contains("truncatedBullet=")
                || text.contains("truncatedNarrative=")) {
            return true;
        }
        return CUSTOMER_EVIDENCE_KEY_VALUE.matcher(text).find();
    }

    private boolean customerVisiblePromptLocationToken(String value) {
        if (!StringUtils.hasText(value)) {
            return false;
        }
        String text = value.trim();
        return text.startsWith("finalUserPrompt.")
                || text.startsWith("finalSystemPrompt.")
                || text.startsWith("sealedEvidence.")
                || text.startsWith("internalGate.")
                || text.startsWith("section ");
    }

    private String concreteMetricActualValue(RuntimeEvidenceCheckResult check) {
        String concrete = concreteDetectedSignalSummary(check);
        String actual = check == null ? "" : check.actualValue();
        if (StringUtils.hasText(concrete)) {
            return StringUtils.hasText(actual) && !actual.contains(concrete)
                    ? actual.trim() + ". 확인 근거: " + concrete
                    : concrete;
        }
        return actual;
    }

    private String concreteDetectedSignalSummary(RuntimeEvidenceCheckResult check) {
        if (check == null) {
            return "";
        }
        return concreteDetectedSignalSummary(jsonStringList(check.detectedSignalsJson()));
    }

    private String concreteDetectedSignalSummary(List<String> signals) {
        if (signals == null || signals.isEmpty()) {
            return "";
        }
        List<String> concreteFacts = new ArrayList<>();
        for (String signal : signals) {
            String fact = concreteSignalFact(signal);
            if (StringUtils.hasText(fact) && !concreteFacts.contains(fact)) {
                concreteFacts.add(fact);
            }
            if (concreteFacts.size() >= 6) {
                break;
            }
        }
        if (concreteFacts.isEmpty()) {
            return "";
        }
        return String.join(" / ", concreteFacts);
    }

    private String concreteSignalFact(String signal) {
        if (!StringUtils.hasText(signal)) {
            return "";
        }
        String trimmed = signal.trim();
        if (contractMetadataSignal(trimmed)) {
            return "";
        }
        String readablePromptFact = readablePromptFactSignal(trimmed);
        if (StringUtils.hasText(readablePromptFact)) {
            return readablePromptFact;
        }
        String concretePromptFact = concretePromptFactSignal(trimmed);
        if (StringUtils.hasText(concretePromptFact)) {
            return concretePromptFact;
        }
        if (trimmed.startsWith("compactMarker=")) {
            String value = trimmed.substring("compactMarker=".length()).trim();
            if (!StringUtils.hasText(value) || "absent".equalsIgnoreCase(value)) {
                return "";
            }
            return "축약 표식이 발견되었습니다: " + value;
        }
        if (trimmed.startsWith("section ") && trimmed.endsWith("=missing")) {
            return "누락된 섹션: " + trimmed.substring("section ".length(), trimmed.length() - "=missing".length()).trim();
        }
        if (trimmed.startsWith("missing:")) {
            return "누락된 항목: " + trimmed.substring("missing:".length()).trim();
        }
        if (trimmed.endsWith("=missing")) {
            return "누락된 항목: " + trimmed.substring(0, trimmed.length() - "=missing".length()).trim();
        }
        if (trimmed.endsWith("=absent")) {
            return "확인되지 않은 항목: " + trimmed.substring(0, trimmed.length() - "=absent".length()).trim();
        }
        String consistency = consistencySignalFact(trimmed);
        if (StringUtils.hasText(consistency)) {
            return consistency;
        }
        String valueFact = valueSignalFact(trimmed);
        if (StringUtils.hasText(valueFact)) {
            return valueFact;
        }
        return "";
    }

    private String concretePromptFactSignal(String signal) {
        String[] prefixes = { "truncatedField=", "truncatedBullet=", "truncatedNarrative=", "unmappedPromptFact=" };
        for (String prefix : prefixes) {
            if (!signal.startsWith(prefix)) {
                continue;
            }
            String value = signal.substring(prefix.length()).trim();
            int valueIndex = value.indexOf(" value=");
            String location = valueIndex < 0 ? value : value.substring(0, valueIndex).trim();
            String factValue = valueIndex < 0 ? "" : value.substring(valueIndex + " value=".length()).trim();
            String label = prefix.startsWith("truncated") ? "\uC798\uB9B0 \uD310\uB2E8 \uC7AC\uB8CC" : "\uACC4\uC57D\uC5D0 \uB4F1\uB85D\uB418\uC9C0 \uC54A\uC740 \uD504\uB86C\uD504\uD2B8 \uD56D\uBAA9";
            return StringUtils.hasText(factValue)
                    ? label + ": " + customerEvidenceName(location) + " \uAC12 " + customerEvidenceValue(factValue)
                    : label + ": " + customerEvidenceName(location);
        }
        return "";
    }

    private String readablePromptFactSignal(String signal) {
        return concretePromptFactSignal(signal);
    }

    private boolean contractMetadataSignal(String signal) {
        if (!StringUtils.hasText(signal)) {
            return false;
        }
        String trimmed = signal.trim();
        int equalsIndex = trimmed.indexOf('=');
        String key = equalsIndex < 0 ? trimmed : trimmed.substring(0, equalsIndex).trim();
        return CONTRACT_METADATA_SIGNAL_KEYS.contains(key);
    }

    private String consistencySignalFact(String signal) {
        if (!signal.startsWith("consistencyOutcome=") && !signal.startsWith("stageNoteRelation=")) {
            return "";
        }
        if (signal.startsWith("stageNoteRelation=")) {
            String relation = valueAfter(signal, "stageNoteRelation=");
            if ("BOUND_TO_FINAL_AUTHORIZATION_EFFECT".equalsIgnoreCase(relation)) {
                return "\uAD8C\uD55C \uB2E8\uACC4 \uC124\uBA85\uC774 \uCD5C\uC885 \uAD8C\uD55C \uD6A8\uACFC\uC640 \uC5F0\uACB0\uB418\uC5B4 \uC788\uC2B5\uB2C8\uB2E4.";
            }
            if ("UNBOUND_PARALLEL_FACT_RISK".equalsIgnoreCase(relation)) {
                return "\uAD8C\uD55C \uB2E8\uACC4 \uC124\uBA85\uC774 \uBCC4\uB3C4 \uC0AC\uC2E4\uCC98\uB7FC \uC77D\uD790 \uC218 \uC788\uC2B5\uB2C8\uB2E4.";
            }
            return "\uAD8C\uD55C \uB2E8\uACC4 \uC124\uBA85 \uAD00\uACC4: " + customerEvidenceValue(relation);
        }
        String outcome = valueAfter(signal, "consistencyOutcome=");
        String labels = namedPart(signal, "comparedLabels=");
        String values = namedPart(signal, "distinctValues=");
        if (outcome.startsWith("CONFLICT")) {
            return "\uCDA9\uB3CC \uD56D\uBAA9: " + customerEvidenceName(firstNonBlank(labels, "\uBE44\uAD50 \uD56D\uBAA9"))
                    + " \uAC12 " + customerEvidenceValue(firstNonBlank(values, outcome));
        }
        return "\uC77C\uCE58 \uD655\uC778 \uD56D\uBAA9: " + customerEvidenceName(firstNonBlank(labels, "\uBE44\uAD50 \uD56D\uBAA9"))
                + " \uAC12 " + customerEvidenceValue(firstNonBlank(values, outcome));
    }

    private String valueSignalFact(String signal) {
        List<String> fragments = customerEvidenceKeyValueFragments(signal);
        if (fragments.size() > 1) {
            return joinCustomerFragments(fragments);
        }
        int equalsIndex = signal.indexOf('=');
        if (equalsIndex <= 0) {
            return "";
        }
        String key = signal.substring(0, equalsIndex).trim();
        String value = customerEvidenceValue(signal.substring(equalsIndex + 1));
        if (!StringUtils.hasText(key) || !StringUtils.hasText(value)
                || "present".equalsIgnoreCase(value) || "absent".equalsIgnoreCase(value)) {
            return "";
        }
        return "확인된 값: " + key + " 값은 " + value;
    }

    private String valueAfter(String signal, String prefix) {
        String value = signal.substring(prefix.length()).trim();
        int commaIndex = value.indexOf(',');
        return commaIndex < 0 ? value : value.substring(0, commaIndex).trim();
    }

    private String namedPart(String signal, String name) {
        int index = signal.indexOf(name);
        if (index < 0) {
            return "";
        }
        String value = signal.substring(index + name.length()).trim();
        int commaIndex = value.indexOf(',');
        return commaIndex < 0 ? value : value.substring(0, commaIndex).trim();
    }

    private FinalPromptMetricCheckContract customerPromptProblemContract(
            String metricCode,
            RuntimeEvidenceCheckResult check) {
        if (check == null || !StringUtils.hasText(check.purposeVersion()) || !StringUtils.hasText(check.checkCode())) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer prompt problem check is not contract backed. "
                    + "metricCode=" + safe(metricCode)
                    + ", checkCode=" + safe(check == null ? null : check.checkCode())
                    + ", purposeVersion=" + safe(check == null ? null : check.purposeVersion()));
        }
        FinalPromptMetricContract metricContract = finalPromptMetricContract(metricCode);
        if (!check.purposeVersion().trim().equals(metricContract.version())) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer prompt problem check uses an unknown contract version. "
                    + "metricCode=" + safe(metricCode)
                    + ", checkCode=" + safe(check.checkCode())
                    + ", purposeVersion=" + safe(check.purposeVersion()));
        }
        FinalPromptMetricCheckContract contract = finalPromptMetricCheckContract(metricCode, check);
        if (!contract.customerVisible() || !"CUSTOMER_PROMPT_QUALITY".equalsIgnoreCase(contract.readinessScope())) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer prompt problem check is not customer prompt quality scoped. "
                    + "metricCode=" + safe(metricCode)
                    + ", checkCode=" + safe(check.checkCode()));
        }
        return contract;
    }

    private String sealedEvidencePromptPath(String fieldKey) {
        String normalized = safe(fieldKey);
        if (normalized.startsWith("finalSystemPrompt.")) {
            return "sealedEvidence.systemPromptText";
        }
        return "sealedEvidence.userPromptText";
    }

    private boolean officialPromptIssueField(String fieldKey) {
        String normalized = safe(fieldKey);
        return normalized.startsWith("finalUserPrompt.")
                || normalized.startsWith("finalSystemPrompt.");
    }

    private String actualPromptProblemType(RuntimeEvidenceCheckResult check) {
        if (inputReadinessNotReady(check)) {
            return "INPUT_NOT_READY";
        }
        String failureType = normalize(check == null ? null : check.failureType());
        if ("INPUT_NOT_READY".equals(failureType)) {
            return "PROMPT_PURPOSE_NOT_SATISFIED";
        }
        String purposeResult = normalize(check == null ? null : check.purposeResult());
        if ("NOT_EVALUATED_INPUT_NOT_READY".equals(purposeResult) || "INPUT_NOT_READY".equals(purposeResult)) {
            return "INPUT_NOT_READY";
        }
        return firstNonBlank(
                failureType,
                purposeResult,
                "PROMPT_PURPOSE_NOT_SATISFIED");
    }

    private String effectiveInputReadinessState(RuntimeEvidenceCheckResult check) {
        if (inputReadinessNotReady(check)) {
            return "INPUT_NOT_READY";
        }
        return firstNonBlank(check == null ? null : check.inputReadinessState(), "READY");
    }

    private String effectivePurposeResult(RuntimeEvidenceCheckResult check) {
        if (inputReadinessNotReady(check)) {
            return "INPUT_NOT_READY";
        }
        String purpose = normalize(check == null ? null : check.purposeResult());
        return switch (purpose) {
            case "PURPOSE_PASSED", "PURPOSE_FAILED", "NOT_APPLICABLE" -> purpose;
            case "PASSED", "PASS", "SUCCESS" -> "PURPOSE_PASSED";
            case "FAILED", "FAIL", "BLOCKED", "THRESHOLD_FAILED" -> "PURPOSE_FAILED";
            case "NOT_EVALUATED_INPUT_NOT_READY", "INPUT_NOT_READY" -> "INPUT_NOT_READY";
            default -> check != null && check.pass() ? "PURPOSE_PASSED" : "PURPOSE_FAILED";
        };
    }

    private boolean inputReadinessNotReady(RuntimeEvidenceCheckResult check) {
        if (check == null) {
            return false;
        }
        String readiness = normalize(check.inputReadinessState());
        String purpose = normalize(check.purposeResult());
        String failure = normalize(check.failureType());
        if ("NOT_READY".equals(readiness) || "INPUT_NOT_READY".equals(readiness)
                || "NOT_EVALUATED_INPUT_NOT_READY".equals(purpose) || "INPUT_NOT_READY".equals(purpose)) {
            return true;
        }
        return "INPUT_NOT_READY".equals(failure) && readinessEvidencePresent(check);
    }

    private boolean readinessEvidencePresent(RuntimeEvidenceCheckResult check) {
        if (check == null) {
            return false;
        }
        if (!jsonStringList(check.detectedSignalsJson()).isEmpty()) {
            return true;
        }
        String text = safe(check.actualValue()) + " " + safe(check.operatorReason());
        String normalized = text.toLowerCase(Locale.ROOT);
        return normalized.contains("missing:")
                || normalized.contains("missing inputs")
                || normalized.contains("누락된 항목");
    }

    private List<String> effectiveDetectedSignals(RuntimeEvidenceCheckResult check) {
        List<String> detectedSignals = jsonStringList(check == null ? null : check.detectedSignalsJson());
        if (!detectedSignals.isEmpty() || !inputReadinessNotReady(check)) {
            return detectedSignals;
        }
        List<String> extracted = new ArrayList<>();
        extracted.addAll(extractReadinessSignals(check.actualValue(), "누락된 항목", "missing:"));
        extracted.addAll(extractReadinessSignals(check.actualValue(), "확인된 항목", "present:"));
        extracted.addAll(extractReadinessSignals(check.actualValue(), "Missing:", "missing:"));
        extracted.addAll(extractReadinessSignals(check.actualValue(), "Present:", "present:"));
        return extracted.stream()
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
    }

    private List<String> extractReadinessSignals(String value, String marker, String prefix) {
        if (!StringUtils.hasText(value) || !StringUtils.hasText(marker)) {
            return List.of();
        }
        int start = value.indexOf(marker);
        if (start < 0) {
            return List.of();
        }
        int contentStart = start + marker.length();
        int end = value.indexOf('.', contentStart);
        if (end < 0) {
            end = value.length();
        }
        String segment = value.substring(contentStart, end);
        List<String> result = new ArrayList<>();
        for (String part : segment.split(",")) {
            String trimmed = part.trim();
            if (StringUtils.hasText(trimmed) && !"\uC5C6\uC74C".equals(trimmed)) {
                result.add(prefix + trimmed);
            }
        }
        return result;
    }

    private void addActualPromptProblem(
            Map<String, ActualPromptProblem> problems,
            String aggregateRunId,
            String packageId,
            String fieldKey,
            String problemType,
            String promptSection,
            String promptLabel,
            String promptValue,
            String sourceFieldPath,
            String sealedEvidencePath,
            String expectedState,
            String actualState,
            String severity,
            List<String> metricCodes,
            String remediationOwner,
            String sourceType) {
        addActualPromptProblem(
                problems,
                aggregateRunId,
                packageId,
                fieldKey,
                problemType,
                promptSection,
                promptLabel,
                promptValue,
                sourceFieldPath,
                sealedEvidencePath,
                expectedState,
                actualState,
                severity,
                metricCodes,
                remediationOwner,
                sourceType,
                "",
                "",
                "",
                "");
    }

    private void addActualPromptProblem(
            Map<String, ActualPromptProblem> problems,
            String aggregateRunId,
            String packageId,
            String fieldKey,
            String problemType,
            String promptSection,
            String promptLabel,
            String promptValue,
            String sourceFieldPath,
            String sealedEvidencePath,
            String expectedState,
            String actualState,
            String severity,
            List<String> metricCodes,
            String remediationOwner,
            String sourceType,
            String qualityQuestion,
            String whyItMatters,
            String fixAction,
            String reverifyCriterion) {
        String normalizedFieldKey = safe(fieldKey);
        String normalizedProblemType = normalize(problemType);
        if (!StringUtils.hasText(normalizedFieldKey) || !StringUtils.hasText(normalizedProblemType)) {
            return;
        }
        List<String> normalizedMetrics = normalizeMetricCodes(
                metricCodes,
                normalizedFieldKey,
                normalizedProblemType,
                sourceType,
                sourceFieldPath,
                promptLabel);
        String normalizedSeverity = "BLOCKING".equals(normalize(severity)) ? "BLOCKING" : "REVIEW";
        if ("BLOCKING".equals(normalizedSeverity) && normalizedMetrics.isEmpty()) {
            throw new IllegalStateException("Actual prompt problem is not bound to any official metric. fieldKey="
                    + normalizedFieldKey + ", problemType=" + normalizedProblemType);
        }
        if ("BLOCKING".equals(normalizedSeverity) && !StringUtils.hasText(remediationOwner)) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Actual final userPrompt problem is missing contract owner. "
                    + "fieldKey=" + normalizedFieldKey + ", problemType=" + normalizedProblemType);
        }
        String dedupeKey = normalizedFieldKey + "|" + normalizedProblemType;
        ActualPromptProblem incoming = new ActualPromptProblem(
                actualPromptProblemId(aggregateRunId, packageId, normalizedFieldKey, normalizedProblemType),
                normalizedFieldKey,
                normalizedProblemType,
                safe(promptSection, "userPrompt"),
                safe(promptLabel, normalizedFieldKey),
                safe(promptValue),
                safe(sourceFieldPath, normalizedFieldKey),
                safe(sealedEvidencePath, sourceFieldPath),
                safe(expectedState),
                safe(actualState),
                normalizedSeverity,
                normalizedMetrics,
                safe(remediationOwner),
                safe(qualityQuestion),
                safe(whyItMatters),
                safe(fixAction),
                safe(reverifyCriterion));
        ActualPromptProblem existing = problems.get(dedupeKey);
        if (existing == null) {
            problems.put(dedupeKey, incoming);
            return;
        }
        ActualPromptProblem merged = mergeActualPromptProblem(existing, incoming);
        if (!"BLOCKING".equals(normalize(existing.severity())) && "BLOCKING".equals(normalize(incoming.severity()))) {
            problems.put(dedupeKey, merged);
            return;
        }
        problems.put(dedupeKey, merged);
    }

    private ActualPromptProblem mergeActualPromptProblem(ActualPromptProblem existing, ActualPromptProblem incoming) {
        if (existing == null) {
            return incoming;
        }
        if (incoming == null) {
            return existing;
        }
        List<String> metricCodes = new ArrayList<>();
        for (String metricCode : existing.metricCodes()) {
            appendUnique(metricCodes, metricCode);
        }
        for (String metricCode : incoming.metricCodes()) {
            appendUnique(metricCodes, metricCode);
        }
        boolean incomingBlocking = "BLOCKING".equals(normalize(incoming.severity()));
        boolean existingBlocking = "BLOCKING".equals(normalize(existing.severity()));
        ActualPromptProblem primary = incomingBlocking && !existingBlocking ? incoming : existing;
        return new ActualPromptProblem(
                primary.problemId(),
                primary.fieldKey(),
                primary.problemType(),
                primary.promptSection(),
                primary.promptLabel(),
                primary.promptValue(),
                primary.sourceFieldPath(),
                primary.sealedEvidencePath(),
                primary.expectedState(),
                primary.actualState(),
                incomingBlocking || existingBlocking ? "BLOCKING" : primary.severity(),
                List.copyOf(metricCodes),
                primary.remediationOwner(),
                firstNonBlank(primary.qualityQuestion(), incoming.qualityQuestion(), existing.qualityQuestion()),
                firstNonBlank(primary.whyItMatters(), incoming.whyItMatters(), existing.whyItMatters()),
                firstNonBlank(primary.fixAction(), incoming.fixAction(), existing.fixAction()),
                firstNonBlank(primary.reverifyCriterion(), incoming.reverifyCriterion(), existing.reverifyCriterion()));
    }

    private Map<String, List<ActualPromptProblem>> actualPromptProblemsByMetric(List<ActualPromptProblem> problems) {
        Map<String, List<ActualPromptProblem>> result = new LinkedHashMap<>();
        for (ActualPromptProblem problem : problems == null ? List.<ActualPromptProblem>of() : problems) {
            if (!"BLOCKING".equals(normalize(problem.severity()))) {
                continue;
            }
            for (String metricCode : problem.metricCodes()) {
                String normalized = normalize(metricCode);
                if (StringUtils.hasText(normalized)) {
                    result.computeIfAbsent(normalized, ignored -> new ArrayList<>()).add(problem);
                }
            }
        }
        return result;
    }

    private void insertActualPromptProblemLedger(
            String aggregateRunId,
            String packageId,
            List<ActualPromptProblem> actualPromptProblems) {
        if (!StringUtils.hasText(aggregateRunId) || !StringUtils.hasText(packageId)) {
            return;
        }
        for (ActualPromptProblem problem : actualPromptProblems == null ? List.<ActualPromptProblem>of() : actualPromptProblems) {
            String primaryMetricCode = problem.metricCodes() == null || problem.metricCodes().isEmpty()
                    ? ""
                    : normalize(problem.metricCodes().get(0));
            jdbcTemplate.update("""
                             insert into official_actual_prompt_problem_ledger (
                                 problem_id, package_id, aggregate_run_id, field_key, problem_type,
                                  prompt_section, prompt_label, prompt_value, source_field_path,
                                  sealed_evidence_path, expected_state, actual_state, severity,
                                   affected_metric_codes, remediation_owner, quality_question,
                                   why_it_matters, fix_action, reverify_criterion_detail,
                                   purpose_evaluation_id, contract_version_id, created_at
                               ) values (
                                   ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                                   (
                                       select e.id
                                         from official_metric_purpose_evaluation_ledger e
                                        where e.aggregate_run_id = ?
                                          and upper(e.metric_code) = ?
                                          and e.customer_visible = true
                                          and (
                                               e.issue_key = ?
                                               or e.check_code = ?
                                               or e.issue_key = ?
                                          )
                                        order by e.id desc
                                        limit 1
                                   ),
                                   (
                                       select c.id
                                         from official_metric_evaluation_contract c
                                         join official_metric_purpose_evaluation_ledger e
                                           on e.contract_version = c.contract_version
                                          and upper(e.metric_code) = upper(c.metric_code)
                                          and (
                                               e.check_code = c.check_code
                                               or e.issue_key = c.issue_key
                                               or c.issue_key = ?
                                          )
                                        where e.aggregate_run_id = ?
                                          and upper(e.metric_code) = ?
                                          and e.customer_visible = true
                                          and (
                                               e.issue_key = ?
                                               or e.check_code = ?
                                               or c.issue_key = ?
                                          )
                                        order by c.id desc
                                        limit 1
                                   ),
                                   ?
                               )
                             """,
                    fit(problem.problemId(), 256),
                    fit(packageId, 128),
                    fit(aggregateRunId, 256),
                    fit(problem.fieldKey(), 512),
                    fit(problem.problemType(), 64),
                    fit(problem.promptSection(), 256),
                    fit(problem.promptLabel(), 256),
                    safe(problem.promptValue()),
                    fit(problem.sourceFieldPath(), 1024),
                    fit(problem.sealedEvidencePath(), 1024),
                    problem.expectedState(),
                    problem.actualState(),
                     fit(problem.severity(), 32),
                     fit(String.join(",", problem.metricCodes()), 512),
                     fit(safe(problem.remediationOwner()), 128),
                     safe(problem.qualityQuestion()),
                     safe(problem.whyItMatters()),
                     safe(problem.fixAction()),
                     safe(problem.reverifyCriterion()),
                     aggregateRunId,
                     primaryMetricCode,
                     fit(problem.fieldKey(), 512),
                     fit(problem.problemType(), 128),
                     fit(problem.sourceFieldPath(), 512),
                     fit(problem.fieldKey(), 512),
                     aggregateRunId,
                     primaryMetricCode,
                     fit(problem.fieldKey(), 512),
                     fit(problem.problemType(), 128),
                     fit(problem.fieldKey(), 512),
                      nowTimestamp());
        }
    }

    private void synchronizePromptQualityIssuesWithActualPromptProblems(String packageId, String aggregateRunId) {
        if (!StringUtils.hasText(packageId) || !StringUtils.hasText(aggregateRunId)) {
            return;
        }
        if (!tableExists("prompt_quality_issue")) {
            return;
        }
        if (!postgresqlDatabase()) {
            synchronizePromptQualityIssuesWithActualPromptProblemsPortable(packageId, aggregateRunId);
            return;
        }
        jdbcTemplate.update("""
                        update prompt_quality_issue i
                           set severity = p.severity,
                               issue_title = p.prompt_label,
                               plain_problem = p.prompt_value,
                               llm_judgement_risk = p.why_it_matters,
                               remediation_target = p.remediation_owner,
                               next_action = p.fix_action,
                               metric_code = split_part(p.affected_metric_codes, ',', 1),
                               package_id = p.package_id,
                               aggregate_run_id = p.aggregate_run_id,
                               failed_package_id = p.package_id,
                               failed_check = p.prompt_label,
                               expected_value = p.expected_state,
                                actual_value = p.actual_state,
                               evidence_source = p.sealed_evidence_path,
                                prompt_location = p.source_field_path,
                                root_cause_type = p.problem_type,
                                production_target_type = i.production_target_type,
                                production_target_ref = p.remediation_owner,
                                http_method = i.http_method,
                                reverify_criterion = p.reverify_criterion_detail,
                                expected_prompt_delta_json = jsonb_build_object(
                                    'problem', p.prompt_label,
                                    'currentState', p.actual_state,
                                    'targetState', p.expected_state,
                                    'impact', p.why_it_matters,
                                    'resolutionAction', p.fix_action,
                                    'reverifyCondition', p.reverify_criterion_detail,
                                    'owner', p.remediation_owner,
                                    'metric', p.affected_metric_codes
                                )::text
                           from official_actual_prompt_problem_ledger p
                          where p.package_id = ?
                            and p.aggregate_run_id = ?
                           and i.issue_id = p.problem_id
                        """,
                packageId,
                aggregateRunId);
    }

    private void synchronizePromptQualityIssuesWithActualPromptProblemsPortable(String packageId, String aggregateRunId) {
        List<Map<String, Object>> rows = jdbcTemplate.queryForList("""
                        select p.problem_id, p.severity, p.prompt_label, p.prompt_value, p.why_it_matters,
                               p.remediation_owner, p.fix_action, p.affected_metric_codes, p.package_id,
                               p.aggregate_run_id, p.expected_state, p.actual_state, p.sealed_evidence_path,
                               p.source_field_path, p.problem_type, p.reverify_criterion_detail
                          from official_actual_prompt_problem_ledger p
                         where p.package_id = ?
                           and p.aggregate_run_id = ?
                        """,
                packageId,
                aggregateRunId);
        for (Map<String, Object> row : rows) {
            jdbcTemplate.update("""
                            update prompt_quality_issue
                               set severity = ?,
                                   issue_title = ?,
                                   plain_problem = ?,
                                   llm_judgement_risk = ?,
                                   remediation_target = ?,
                                   next_action = ?,
                                   metric_code = ?,
                                   package_id = ?,
                                   aggregate_run_id = ?,
                                   failed_package_id = ?,
                                   failed_check = ?,
                                   expected_value = ?,
                                   actual_value = ?,
                                   evidence_source = ?,
                                    prompt_location = ?,
                                    root_cause_type = ?,
                                    production_target_type = ?,
                                    production_target_ref = ?,
                                    http_method = ?,
                                    reverify_criterion = ?,
                                    expected_prompt_delta_json = ?
                             where issue_id = ?
                            """,
                    row.get("severity"),
                    row.get("prompt_label"),
                    row.get("actual_state"),
                    row.get("why_it_matters"),
                    row.get("remediation_owner"),
                    row.get("fix_action"),
                    firstCsvValue(row.get("affected_metric_codes")),
                    row.get("package_id"),
                    row.get("aggregate_run_id"),
                    row.get("package_id"),
                    row.get("prompt_label"),
                    row.get("expected_state"),
                    row.get("actual_state"),
                    row.get("sealed_evidence_path"),
                    row.get("source_field_path"),
                    row.get("problem_type"),
                    stringValue(row.get("remediation_owner")),
                    stringValue(row.get("remediation_owner")),
                    "",
                    row.get("reverify_criterion_detail"),
                    promptIssueDeltaJson(row),
                    row.get("problem_id"));
        }
    }

    private String promptIssueDeltaJson(Map<String, Object> row) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("problem", stringValue(row.get("prompt_label")));
        payload.put("currentState", stringValue(row.get("actual_state")));
        payload.put("targetState", stringValue(row.get("expected_state")));
        payload.put("impact", stringValue(row.get("why_it_matters")));
        payload.put("resolutionAction", stringValue(row.get("fix_action")));
        payload.put("reverifyCondition", stringValue(row.get("reverify_criterion_detail")));
        payload.put("owner", stringValue(row.get("remediation_owner")));
        payload.put("metric", firstCsvValue(row.get("affected_metric_codes")));
        return writeJson(payload);
    }

    private String firstCsvValue(Object value) {
        String text = stringValue(value);
        if (!StringUtils.hasText(text)) {
            return "";
        }
        int comma = text.indexOf(',');
        return comma < 0 ? text.trim() : text.substring(0, comma).trim();
    }

    private void insertMetricPurposeLedgers(
            String aggregateRunId,
            String packageId,
            List<RuntimeEvidenceMetricResult> metrics) {
        if (!StringUtils.hasText(aggregateRunId) || !StringUtils.hasText(packageId) || metrics == null) {
            return;
        }
        upsertFullMetricContractCatalog();
        assertFullMetricContractCatalogPersisted();
        for (RuntimeEvidenceMetricResult metric : metrics) {
            if (metric == null || metric.checks() == null) {
                continue;
            }
            String metricCode = normalize(metric.metricCode());
            for (RuntimeEvidenceCheckResult check : metric.checks()) {
                if (check == null) {
                    continue;
                }
                String runtimeCheckCode = firstNonBlank(check.checkCode(), check.label(), "CHECK");
                String purposeVersion = check.purposeVersion();
                boolean inputNotReady = inputReadinessNotReady(check);
                boolean contradictoryPassedMetricFailure = passed(metric) && !check.pass();
                FinalPromptMetricCheckContract checkContract = StringUtils.hasText(purposeVersion)
                        ? finalPromptMetricCheckContract(metricCode, check)
                        : null;
                boolean customerVisible = customerDisplayEligible(checkContract)
                        && !inputNotReady
                        && !contradictoryPassedMetricFailure;
                String readinessScope = inputNotReady
                        ? "INPUT_READINESS"
                        : firstNonBlank(check.readinessScope(), "CUSTOMER_PROMPT_QUALITY");
                CustomerDisplayPayloadFactory.Payload customerDisplayPayload = customerVisible && StringUtils.hasText(purposeVersion)
                        ? customerDisplayPayload(check, checkContract)
                        : null;
                String checkCode = firstNonBlank(
                        checkContract == null ? null : checkContract.checkName(),
                        runtimeCheckCode);
                String purposeIssueKey = firstNonBlank(
                        check.issueKey(),
                        checkContract == null ? null : checkContract.issueKey(),
                        check.source(),
                        checkCode);
                upsertMetricPurposeContract(purposeVersion, metricCode, metric, check);
                List<String> detectedSignals = effectiveDetectedSignals(check);
                List<String> presentInputs = detectedSignals.stream()
                        .filter(value -> value.startsWith("present:"))
                        .map(value -> value.substring("present:".length()))
                        .toList();
                List<String> missingInputs = detectedSignals.stream()
                        .filter(value -> value.startsWith("missing:"))
                        .map(value -> value.substring("missing:".length()))
                        .toList();
                jdbcTemplate.update("""
                                insert into official_metric_input_readiness_ledger (
                                    package_id, aggregate_run_id, metric_code, check_code,
                                    contract_version, readiness_state, detected_inputs_json,
                                    missing_inputs_json, readiness_scope, customer_visible, created_at
                                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """,
                        fit(packageId, 128),
                        fit(aggregateRunId, 256),
                        fit(metricCode, 32),
                        fit(checkCode, 128),
                        fit(purposeVersion, 128),
                        fit(effectiveInputReadinessState(check), 128),
                        writeJson(presentInputs.isEmpty() ? detectedSignals : presentInputs),
                        writeJson(missingInputs),
                        fit(readinessScope, 128),
                        customerVisible,
                        nowTimestamp());
                jdbcTemplate.update("""
                                insert into official_metric_purpose_evaluation_ledger (
                                    package_id, aggregate_run_id, metric_code, check_code,
                                    contract_version, purpose_statement, decision_utility,
                                    purpose_result, issue_key, customer_visible, readiness_scope,
                                    detected_signals_json, interpretation_links_json, expected_value,
                                    actual_value, remediation_owner, next_action, reverify_criterion,
                                    created_at
                                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                """,
                        fit(packageId, 128),
                        fit(aggregateRunId, 256),
                        fit(metricCode, 32),
                        fit(checkCode, 128),
                        fit(purposeVersion, 128),
                        narrativeCatalog.metricPurpose(metricCode),
                        purposeLedgerDecisionUtility(check, customerVisible, checkContract),
                        fit(effectivePurposeResult(check), 128),
                        fit(purposeIssueKey, 512),
                        customerVisible,
                        fit(readinessScope, 128),
                        validJsonArrayOrEmpty(check.detectedSignalsJson()),
                        validJsonArrayOrEmpty(check.interpretationLinksJson()),
                        purposeLedgerExpectedValue(check, customerVisible, checkContract),
                        purposeLedgerActualValue(check, customerVisible, checkContract),
                        fit(check.remediationOwner(), 128),
                        purposeLedgerNextAction(check, customerVisible, checkContract),
                        purposeLedgerReverifyCriterion(check, customerVisible, checkContract),
                        nowTimestamp());
                insertCustomerDisplayPayload(
                        aggregateRunId,
                        packageId,
                        metricCode,
                        checkCode,
                        purposeVersion,
                        check,
                        checkContract,
                        customerDisplayPayload);
                insertMetricPurposeEvidenceLedgers(
                        aggregateRunId,
                        packageId,
                        metricCode,
                        checkCode,
                        purposeVersion,
                        check,
                        detectedSignals,
                        customerVisible,
                        readinessScope);
                insertPromptSignalLedgers(aggregateRunId, packageId, metricCode, checkCode, check, detectedSignals);
            }
        }
    }

    private void insertCustomerDisplayPayload(
            String aggregateRunId,
            String packageId,
            String metricCode,
            String checkCode,
            String purposeVersion,
            RuntimeEvidenceCheckResult check,
            FinalPromptMetricCheckContract checkContract,
            CustomerDisplayPayloadFactory.Payload payload) {
        if (payload == null || check == null || !StringUtils.hasText(purposeVersion)) {
            return;
        }
        for (CustomerDisplayPayloadFactory.RolePayload rolePayload : payload.rolePayloads()) {
            assertCustomerDisplayContractRole(purposeVersion, metricCode, checkCode, rolePayload.displayRole());
            jdbcTemplate.update("""
                            insert into official_metric_customer_display_payload (
                                package_id, aggregate_run_id, metric_code, check_code, contract_version,
                                display_role, title, summary, evidence_text, why_it_matters,
                                resolution_action, reverify_condition, context_items_json,
                                bound_facts_json, raw_evidence_ref, created_at
                            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                    fit(packageId, 128),
                    fit(aggregateRunId, 256),
                    fit(metricCode, 32),
                    fit(checkCode, 128),
                    fit(purposeVersion, 128),
                    fit(rolePayload.displayRole(), 64),
                    fit(rolePayload.title(), 512),
                    fit(rolePayload.summary(), 1200),
                    rolePayload.evidenceText(),
                    rolePayload.whyItMatters(),
                    rolePayload.resolutionAction(),
                    rolePayload.reverifyCondition(),
                    writeJson(customerDisplayContextItems(checkContract)),
                    validJsonArrayOrEmpty(check.detectedSignalsJson()),
                    fit(firstNonBlank(check.source(), check.issueKey(), checkCode), 512),
                    nowTimestamp());
        }
    }

    private void assertCustomerDisplayPayloadComplete(String aggregateRunId) {
        if (!StringUtils.hasText(aggregateRunId)) {
            return;
        }
        Integer expectedRows = jdbcTemplate.queryForObject("""
                        select coalesce(sum(
                            case
                                when purpose_result = 'PURPOSE_FAILED' then 5
                                else 3
                            end
                        ), 0)
                          from official_metric_purpose_evaluation_ledger
                         where aggregate_run_id = ?
                           and customer_visible = true
                        """,
                Integer.class,
                aggregateRunId);
        Integer actualRows = jdbcTemplate.queryForObject("""
                        select count(*)
                          from official_metric_customer_display_payload
                         where aggregate_run_id = ?
                        """,
                Integer.class,
                aggregateRunId);
        int expected = expectedRows == null ? 0 : expectedRows;
        int actual = actualRows == null ? 0 : actualRows;
        if (expected != actual) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer display payload row count mismatch."
                    + " aggregateRunId=" + aggregateRunId
                    + ", expectedRows=" + expected
                    + ", actualRows=" + actual);
        }
        Integer emptyContextItemRows = jdbcTemplate.queryForObject("""
                        /* customer_display_payload_empty_context_items */
                        select count(*)
                          from official_metric_customer_display_payload
                         where aggregate_run_id = ?
                           and coalesce(context_items_json::text, '[]') = '[]'
                        """,
                Integer.class,
                aggregateRunId);
        if (emptyContextItemRows != null && emptyContextItemRows > 0) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer display payload is missing contract context items."
                    + " aggregateRunId=" + aggregateRunId
                    + ", emptyContextItemRows=" + emptyContextItemRows);
        }
    }

    private void assertCustomerDisplayContractRole(
            String purposeVersion,
            String metricCode,
            String checkCode,
            String displayRole) {
        if (!CUSTOMER_DISPLAY_ROLES.contains(displayRole)) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer display payload role is not supported."
                    + " metric=" + safe(metricCode)
                    + ", check=" + safe(checkCode)
                    + ", displayRole=" + safe(displayRole));
        }
        Integer count = jdbcTemplate.queryForObject("""
                        select count(*)
                          from official_metric_customer_display_contract
                         where contract_version = ?
                           and upper(metric_code) = ?
                           and check_code = ?
                           and display_role = ?
                        """,
                Integer.class,
                purposeVersion,
                normalize(metricCode),
                checkCode,
                displayRole);
        if (count == null || count < 1) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer display payload role is not contract-backed."
                    + " metric=" + safe(metricCode)
                    + ", check=" + safe(checkCode)
                    + ", displayRole=" + safe(displayRole)
                    + ", contractVersion=" + safe(purposeVersion));
        }
    }

    private List<String> customerDisplayContextItems(FinalPromptMetricCheckContract checkContract) {
        if (checkContract == null) {
            return List.of();
        }
        List<String> items = new ArrayList<>();
        for (Map<String, String> binding : safeEvidenceBindings(checkContract)) {
            if (binding == null) {
                continue;
            }
            appendCustomerDisplayContextItems(items, binding.get("customerVisibleContextItems"));
            appendCustomerDisplayContextItems(items, binding.get("customerVisiblePromptItems"));
        }
        return List.copyOf(items);
    }

    private void appendCustomerDisplayContextItems(List<String> items, String value) {
        if (items == null || !StringUtils.hasText(value)) {
            return;
        }
        for (String token : value.split("[,|]")) {
            String item = token == null ? "" : token.trim();
            if (StringUtils.hasText(item)) {
                appendUnique(items, item);
            }
        }
    }

    private void insertMetricPurposeEvidenceLedgers(
            String aggregateRunId,
            String packageId,
            String metricCode,
            String checkCode,
            String purposeVersion,
            RuntimeEvidenceCheckResult check,
            List<String> detectedSignals,
            boolean customerVisible,
            String readinessScope) {
        List<String> signals = detectedSignals == null ? List.of() : detectedSignals.stream()
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
        if (customerVisible) {
            signals = customerVisiblePurposeSignals(signals, check, true);
        }
        boolean contractBackedCustomerVisible = customerVisible
                && check != null
                && StringUtils.hasText(check.purposeVersion());
        FinalPromptMetricCheckContract checkContract = contractBackedCustomerVisible
                ? finalPromptMetricCheckContract(metricCode, check)
                : null;
        if (signals.isEmpty() && contractBackedCustomerVisible) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible metric purpose evidence is missing. "
                    + "metricCode=" + metricCode + ", checkCode=" + checkCode);
        }
        if (signals.isEmpty()) {
            String issueKey = customerVisible
                    ? firstNonBlank(
                            check.label(),
                            check.expectedValue(),
                            check.decisionUtility(),
                            check.whyItMatters(),
                            checkCode)
                    : firstNonBlank(check.issueKey(), check.source(), checkCode);
            if (!StringUtils.hasText(issueKey)) {
                throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Metric purpose evidence requires a signal key."
                        + " metricCode=" + metricCode + ", checkCode=" + checkCode);
            }
            signals = List.of(issueKey);
        }
        String interpretation = contractBackedCustomerVisible
                ? customerDisplayPayload(check, checkContract).whyItMatters()
                : firstNonBlank(
                        check.decisionUtility(),
                        check.whyItMatters(),
                        check.expectedValue(),
                        check.actualValue());
        if (!StringUtils.hasText(interpretation)) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Metric purpose evidence requires contract interpretation."
                    + " metricCode=" + metricCode + ", checkCode=" + checkCode);
        }
        String purposeResult = effectivePurposeResult(check);
        String normalizedReadinessScope = firstNonBlank(readinessScope, "CUSTOMER_PROMPT_QUALITY");
        String promptLocation = firstNonBlank(check.source(), check.issueKey());
        for (String signal : signals) {
            CustomerPurposeEvidenceDisplay display = (customerVisible || structuredCustomerPurposeEvidenceSignal(signal))
                    ? customerPurposeEvidenceDisplay(signal, check, checkContract)
                    : null;
            if (display == null) {
                display = new CustomerPurposeEvidenceDisplay(
                        firstNonBlank(signal, checkCode),
                        firstNonBlank(signal, check.actualValue(), check.expectedValue()));
            }
            if (customerVisible) {
                assertCustomerPurposeEvidenceDisplay(display, check, checkContract);
            }
            List<String> runtimeFactsForLedger = customerVisible
                    ? customerScopedRuntimeFacts(display)
                    : display.runtimeFacts();
            jdbcTemplate.update("""
                            insert into official_metric_purpose_evidence_ledger (
                                package_id, aggregate_run_id, purpose_evaluation_id,
                                metric_code, check_code, contract_version, signal_key,
                                prompt_location, evidence_value, evidence_hash, interpretation,
                                purpose_result, customer_visible, readiness_scope,
                                runtime_facts_json, context_items_json, created_at
                            ) values (
                                ?, ?,
                                (
                                    select e.id
                                      from official_metric_purpose_evaluation_ledger e
                                     where e.aggregate_run_id = ?
                                       and upper(e.metric_code) = ?
                                       and e.check_code = ?
                                     order by e.id desc
                                     limit 1
                                ),
                                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                            )
                            """,
                    fit(packageId, 128),
                    fit(aggregateRunId, 256),
                    aggregateRunId,
                    normalize(metricCode),
                    fit(checkCode, 128),
                    fit(metricCode, 32),
                    fit(checkCode, 128),
                    fit(purposeVersion, 128),
                    fit(display.signalKey(), 512),
                    fit(promptLocation, 512),
                    display.evidenceValue(),
                    sha256Prefixed(display.evidenceValue()),
                    interpretation,
                    fit(purposeResult, 128),
                    customerVisible,
                    fit(normalizedReadinessScope, 128),
                    writeJson(runtimeFactsForLedger),
                    writeJson(display.contextItems()),
                    nowTimestamp());
        }
    }

    private List<String> customerScopedRuntimeFacts(CustomerPurposeEvidenceDisplay display) {
        if (display == null || display.runtimeFacts().isEmpty()) {
            return List.of();
        }
        List<String> scoped = new ArrayList<>();
        String title = display.signalKey();
        for (String runtimeFact : display.runtimeFacts()) {
            if (!StringUtils.hasText(runtimeFact)) {
                continue;
            }
            String fact = runtimeFact.trim();
            String value = StringUtils.hasText(title) && !sameCustomerEvidenceText(title, fact)
                    ? title.trim() + " 확인값: " + fact
                    : fact;
            appendCustomerDisplayUnique(scoped, value);
        }
        return List.copyOf(scoped);
    }

    private List<String> customerVisiblePurposeSignals(
            List<String> signals,
            RuntimeEvidenceCheckResult check,
            boolean customerVisible) {
        if (!customerVisible || signals == null || signals.isEmpty()) {
            return signals == null ? List.of() : signals;
        }
        if (check != null && StringUtils.hasText(check.purposeVersion())) {
            List<String> structuredSignals = signals.stream()
                    .filter(StringUtils::hasText)
                    .map(String::trim)
                    .filter(this::structuredCustomerPurposeEvidenceSignal)
                    .distinct()
                    .toList();
            if (structuredSignals.isEmpty()) {
                throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose evidence must be generated as structured payload. "
                        + "metric=" + safe(check.metricCode())
                        + ", check=" + safe(check.checkCode()));
            }
            return structuredSignals;
        }
        boolean purposePassed = "PURPOSE_PASSED".equals(effectivePurposeResult(check));
        return signals.stream()
                .filter(StringUtils::hasText)
                .map(signal -> customerVisiblePurposeSignal(signal, purposePassed, check))
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
    }

    private boolean structuredCustomerPurposeEvidenceSignal(String signal) {
        if (!StringUtils.hasText(signal)) {
            return false;
        }
        String trimmed = signal.trim();
        return trimmed.startsWith("{")
                && trimmed.endsWith("}")
                && trimmed.contains("\"signalKey\"")
                && trimmed.contains("\"evidenceValue\"");
    }

    private String customerVisiblePurposeSignal(
            String signal,
            boolean purposePassed,
            RuntimeEvidenceCheckResult check) {
        if (!StringUtils.hasText(signal) || contractMetadataSignal(signal)) {
            return "";
        }
        if (customerVisibleInternalPurposeSignal(signal)) {
            return "";
        }
        if (customerVisiblePromptLocationToken(signal)) {
            return "";
        }
        if (customerVisiblePresenceOnlySignal(signal)) {
            return "";
        }
        if (purposePassed && customerVisibleAbsenceSignal(signal)) {
            return "";
        }
        return signal;
    }

    private boolean customerVisiblePresenceOnlySignal(String signal) {
        if (!StringUtils.hasText(signal)) {
            return false;
        }
        String trimmed = signal.trim();
        if (!trimmed.endsWith("=present")) {
            return false;
        }
        return !trimmed.startsWith("compactMarker=")
                || "compactMarker=present".equalsIgnoreCase(trimmed);
    }

    private boolean customerVisibleInternalPurposeSignal(String signal) {
        if (!StringUtils.hasText(signal)) {
            return false;
        }
        String trimmed = signal.trim();
        return trimmed.startsWith("consistencyOutcome=")
                || trimmed.startsWith("stageNoteRelation=");
    }

    private boolean customerVisibleAbsenceSignal(String signal) {
        if (!StringUtils.hasText(signal)) {
            return false;
        }
        String trimmed = signal.trim();
        return trimmed.endsWith("=missing")
                || trimmed.endsWith("=absent")
                || trimmed.endsWith("=present")
                || trimmed.contains("missingLabels=");
    }

    private CustomerPurposeEvidenceDisplay customerPurposeEvidenceDisplay(
            String signal,
            RuntimeEvidenceCheckResult check) {
        return customerPurposeEvidenceDisplay(signal, check, null);
    }

    private CustomerPurposeEvidenceDisplay customerPurposeEvidenceDisplay(
            String signal,
            RuntimeEvidenceCheckResult check,
            FinalPromptMetricCheckContract checkContract) {
        CustomerPurposeEvidenceDisplay structured = splitCustomerPurposeEvidence(signal, check, checkContract);
        if (structured != null) {
            return structured;
        }
        if (check != null && StringUtils.hasText(check.purposeVersion())) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose evidence is not a structured payload. "
                    + "metric=" + safe(check.metricCode())
                    + ", check=" + safe(check.checkCode()));
        }
        if (StringUtils.hasText(signal) && customerVisibleTechnicalText(signal)) {
            List<String> fragments = customerEvidenceFragments(signal);
            if (!fragments.isEmpty()) {
                String signalKey = firstNonBlank(
                        check == null ? null : check.label(),
                        check == null ? null : check.expectedValue(),
                        check == null ? null : check.decisionUtility(),
                        check == null ? null : check.whyItMatters());
                return new CustomerPurposeEvidenceDisplay(
                        requireCustomerLedgerText(signalKey, check, "purpose.signal_key"),
                        requireCustomerLedgerText(joinCustomerFragments(fragments), check, "purpose.evidence_value"));
            }
        }
        String signalKey = customerVisiblePurposeSignalKey(signal, check);
        String evidenceValue = customerVisiblePurposeEvidenceValue(
                firstNonBlank(signal, check == null ? null : check.actualValue(), check == null ? null : check.expectedValue()),
                check,
                signalKey);
        return new CustomerPurposeEvidenceDisplay(signalKey, evidenceValue);
    }

    private CustomerPurposeEvidenceDisplay splitCustomerPurposeEvidence(
            String signal,
            RuntimeEvidenceCheckResult check,
            FinalPromptMetricCheckContract checkContract) {
        if (!StringUtils.hasText(signal)) {
            return null;
        }
        String trimmed = signal.trim();
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            Map<String, Object> structured = jsonMap(trimmed);
            String signalKey = objectText(structured.get("signalKey"));
            String evidenceValue = objectText(structured.get("evidenceValue"));
            if (StringUtils.hasText(signalKey) || StringUtils.hasText(evidenceValue)) {
                String customerSignalKey = customerPurposeDisplaySignalKey(signalKey, check, checkContract);
                return new CustomerPurposeEvidenceDisplay(
                        customerSignalKey,
                        customerPurposeDisplayEvidenceValue(evidenceValue, check, checkContract, customerSignalKey),
                        customerPurposeRuntimeFacts(structured),
                        customerPurposeContextItems(structured),
                        true);
            }
        }
        if (trimmed.contains(CUSTOMER_PURPOSE_EVIDENCE_SEPARATOR)
                && check != null
                && StringUtils.hasText(check.purposeVersion())) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose evidence uses deprecated separator. "
                    + "metric=" + safe(check == null ? null : check.metricCode())
                    + ", check=" + safe(check == null ? null : check.checkCode()));
        }
        if (!trimmed.contains(CUSTOMER_PURPOSE_EVIDENCE_SEPARATOR)) {
            return null;
        }
        String[] parts = trimmed.split(Pattern.quote(CUSTOMER_PURPOSE_EVIDENCE_SEPARATOR), 2);
        if (parts.length != 2) {
            return null;
        }
        String signalKey = requireCustomerLedgerText(parts[0], check, "purpose.signal_key");
        String evidenceValue = requireCustomerLedgerText(parts[1], check, "purpose.evidence_value");
        return new CustomerPurposeEvidenceDisplay(signalKey, evidenceValue);
    }

    private String customerPurposeDisplaySignalKey(
            String rawSignalKey,
            RuntimeEvidenceCheckResult check,
            FinalPromptMetricCheckContract checkContract) {
        if (StringUtils.hasText(rawSignalKey)
                && !customerVisibleTechnicalText(rawSignalKey)
                && !customerEvidenceContainsRawSymbol(rawSignalKey)) {
            return requireCustomerLedgerText(rawSignalKey, check, "purpose.signal_key");
        }
        String contractText = contractBackedPurposeDisplayTitle(check, checkContract);
        if (StringUtils.hasText(contractText)) {
            return requireCustomerLedgerText(contractText, check, "purpose.signal_key");
        }
        return requireCustomerLedgerText(rawSignalKey, check, "purpose.signal_key");
    }

    private String customerPurposeDisplayEvidenceValue(
            String rawEvidenceValue,
            RuntimeEvidenceCheckResult check,
            FinalPromptMetricCheckContract checkContract,
            String excludedText) {
        if (StringUtils.hasText(rawEvidenceValue)
                && !sameCustomerEvidenceText(rawEvidenceValue, excludedText)
                && !customerVisibleTechnicalText(rawEvidenceValue)
                && !customerEvidenceContainsRawSymbol(rawEvidenceValue)) {
            return requireCustomerLedgerText(rawEvidenceValue, check, "purpose.evidence_value");
        }
        if (checkContract == null
                && StringUtils.hasText(rawEvidenceValue)
                && sameCustomerEvidenceText(rawEvidenceValue, excludedText)
                && !customerVisibleTechnicalText(rawEvidenceValue)
                && !customerEvidenceContainsRawSymbol(rawEvidenceValue)) {
            return requireCustomerLedgerText(rawEvidenceValue, check, "purpose.evidence_value");
        }
        String contractText = contractBackedPurposeEvidenceText(check, checkContract, excludedText);
        if (StringUtils.hasText(contractText)) {
            return requireCustomerLedgerText(contractText, check, "purpose.evidence_value");
        }
        return customerVisiblePurposeEvidenceValue(rawEvidenceValue, check, excludedText);
    }

    private String contractBackedPurposeDisplayTitle(
            RuntimeEvidenceCheckResult check,
            FinalPromptMetricCheckContract checkContract) {
        if (checkContract == null) {
            return "";
        }
        String result = effectivePurposeResult(check);
        if ("PURPOSE_FAILED".equals(result) || "FAILED".equals(result)) {
            return firstNonBlank(
                    checkContract.problemTitle(),
                    checkContract.failureMessage(),
                    checkContract.expectedMessage(),
                    checkContract.qualityQuestion());
        }
        if ("NOT_APPLICABLE".equals(result)) {
            return firstNonBlank(
                    checkContract.notApplicableMessage(),
                    checkContract.passMessage(),
                    checkContract.expectedMessage(),
                    checkContract.qualityQuestion());
        }
        return firstNonBlank(
                checkContract.passMessage(),
                checkContract.expectedMessage(),
                checkContract.qualityQuestion(),
                checkContract.problemTitle());
    }

    private String contractBackedPurposeEvidenceText(
            RuntimeEvidenceCheckResult check,
            FinalPromptMetricCheckContract checkContract,
            String excludedText) {
        if (checkContract == null) {
            return "";
        }
        List<String> candidates = new ArrayList<>();
        String result = effectivePurposeResult(check);
        if ("PURPOSE_FAILED".equals(result) || "FAILED".equals(result)) {
            appendUnique(candidates, checkContract.failureMessage());
            appendUnique(candidates, checkContract.shortProblem());
            appendUnique(candidates, checkContract.expectedMessage());
        } else if ("NOT_APPLICABLE".equals(result)) {
            appendUnique(candidates, checkContract.notApplicableMessage());
            appendUnique(candidates, checkContract.expectedMessage());
        } else {
            appendUnique(candidates, checkContract.expectedMessage());
            appendUnique(candidates, checkContract.qualityQuestion());
        }
        for (String candidate : candidates) {
            if (StringUtils.hasText(candidate)
                    && !sameCustomerEvidenceText(candidate, excludedText)
                    && !customerVisibleTechnicalText(candidate)
                    && !customerEvidenceContainsRawSymbol(candidate)) {
                return candidate.trim();
            }
        }
        return "";
    }

    private String objectText(Object value) {
        return value == null ? "" : String.valueOf(value).trim();
    }

    private List<String> customerPurposeRuntimeFacts(Map<String, Object> structured) {
        return customerPurposeDisplayItems(
                structured == null ? null : structured.get("runtimeFacts"),
                true);
    }

    private List<String> customerPurposeContextItems(Map<String, Object> structured) {
        return customerPurposeDisplayItems(
                structured == null ? null : structured.get("contextItems"),
                false);
    }

    private List<String> customerPurposeDisplayItems(Object value) {
        return customerPurposeDisplayItems(value, false);
    }

    private List<String> customerPurposeDisplayItems(Object value, boolean runtimeFacts) {
        if (value == null) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        if (value instanceof Iterable<?> iterable) {
            for (Object item : iterable) {
                if (item instanceof Map<?, ?> map) {
                    Object runtimeFactItems = map.get("runtimeFacts");
                    Object contextItems = map.get("contextItems");
                    Object nested = runtimeFacts ? runtimeFactItems : contextItems;
                    if (nested != null) {
                        result.addAll(customerPurposeDisplayItems(nested, runtimeFacts));
                    }
                    continue;
                }
                appendCustomerDisplayItems(result, objectText(item), runtimeFacts);
            }
            return List.copyOf(result);
        }
        appendCustomerDisplayItems(result, objectText(value), runtimeFacts);
        return List.copyOf(result);
    }

    private void appendCustomerDisplayItems(List<String> items, String value, boolean runtimeFacts) {
        if (runtimeFacts) {
            appendRuntimeFactDisplayItems(items, value);
            return;
        }
        appendDelimitedDisplayItems(items, value);
    }

    private void appendRuntimeFactDisplayItems(List<String> items, String value) {
        if (items == null || !StringUtils.hasText(value)) {
            return;
        }
        String normalized = value
                .replace("\r\n", "\n")
                .replace('\r', '\n')
                .trim();
        for (String line : normalized.split("\\n+")) {
            String trimmedLine = line == null ? "" : line.trim();
            if (!StringUtils.hasText(trimmedLine)) {
                continue;
            }
            for (String token : trimmedLine.split("(?<=\\.)\\s+")) {
                String item = token == null ? "" : token.trim();
                if (StringUtils.hasText(item)) {
                    appendCustomerDisplayUnique(items, item);
                }
            }
        }
    }

    private void appendDelimitedDisplayItems(List<String> items, String value) {
        if (items == null || !StringUtils.hasText(value)) {
            return;
        }
        for (String token : value.split("[,\\n]")) {
            String item = token == null ? "" : token.trim();
            if (StringUtils.hasText(item)) {
                appendCustomerDisplayUnique(items, item);
            }
        }
    }

    private void assertCustomerPurposeEvidenceDisplay(
            CustomerPurposeEvidenceDisplay display,
            RuntimeEvidenceCheckResult check,
            FinalPromptMetricCheckContract checkContract) {
        if (display == null
                || !StringUtils.hasText(display.signalKey())
                || !StringUtils.hasText(display.evidenceValue())) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose evidence is incomplete. "
                    + "metric=" + safe(check == null ? null : check.metricCode())
                    + ", check=" + safe(check == null ? null : check.checkCode()));
        }
        if (display.signalKey().contains(CUSTOMER_PURPOSE_EVIDENCE_SEPARATOR)
                || display.evidenceValue().contains(CUSTOMER_PURPOSE_EVIDENCE_SEPARATOR)) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose evidence separator leaked into DB fields. "
                    + "metric=" + safe(check == null ? null : check.metricCode())
                    + ", check=" + safe(check == null ? null : check.checkCode()));
        }
        if (customerEvidenceContainsRawSymbol(display.signalKey())
                || customerEvidenceContainsRawSymbol(display.evidenceValue())) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose evidence contains raw technical symbols. "
                    + "metric=" + safe(check == null ? null : check.metricCode())
                    + ", check=" + safe(check == null ? null : check.checkCode())
                    + ", signalKey=" + safe(display.signalKey())
                    + ", evidenceValue=" + safe(display.evidenceValue()));
        }
        if (sameCustomerEvidenceText(display.signalKey(), display.evidenceValue())) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose evidence repeats the same text. "
                    + "metric=" + safe(check == null ? null : check.metricCode())
                    + ", check=" + safe(check == null ? null : check.checkCode())
                    + ", text=" + safe(display.signalKey()));
        }
        if (check != null && StringUtils.hasText(check.purposeVersion())) {
            if (display.runtimeFacts().isEmpty()) {
                throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose evidence is missing runtime facts. "
                        + "metric=" + safe(check.metricCode())
                        + ", check=" + safe(check.checkCode()));
            }
            for (String runtimeFact : display.runtimeFacts()) {
                if (customerRuntimeFactHasGenericWrapper(runtimeFact)
                        || (display.structured()
                        && (sameCustomerEvidenceText(runtimeFact, display.signalKey())
                        || sameCustomerEvidenceText(runtimeFact, display.evidenceValue())))
                        || customerRuntimeFactRepeatsContractDisplayText(runtimeFact, checkContract)) {
                    throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible runtime fact repeats display text. "
                            + "metric=" + safe(check.metricCode())
                            + ", check=" + safe(check.checkCode())
                            + ", runtimeFact=" + safe(runtimeFact));
                }
            }
            if (display.contextItems().isEmpty()) {
                throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose evidence is missing context items. "
                        + "metric=" + safe(check.metricCode())
                        + ", check=" + safe(check.checkCode()));
            }
            if (customerDisplayItemsContainDuplicates(display.runtimeFacts())) {
                throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible runtime facts contain duplicate display text. "
                        + "metric=" + safe(check.metricCode())
                        + ", check=" + safe(check.checkCode()));
            }
            if (customerDisplayItemsContainDuplicates(display.contextItems())) {
                throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible context items contain duplicate display text. "
                        + "metric=" + safe(check.metricCode())
                        + ", check=" + safe(check.checkCode()));
            }
            for (String contextItem : display.contextItems()) {
                assertCustomerVisibleContextItem(check, contextItem);
            }
        }
    }

    private void assertCustomerPurposeEvidenceDisplay(
            CustomerPurposeEvidenceDisplay display,
            RuntimeEvidenceCheckResult check) {
        assertCustomerPurposeEvidenceDisplay(display, check, null);
    }

    private void assertCustomerVisibleContextItem(
            RuntimeEvidenceCheckResult check,
            String item) {
        if (check == null || !StringUtils.hasText(item)) {
            return;
        }
        if (!isContractedPromptSignal(item)) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible context item is not a prompt field. metric="
                    + safe(check.metricCode())
                    + ", check=" + safe(check.checkCode())
                    + ", contextItem=" + safe(item));
        }
    }

    private boolean isContractedPromptSignal(String item) {
        if (!StringUtils.hasText(item) || jdbcTemplate == null) {
            return false;
        }
        try {
            Integer count = jdbcTemplate.queryForObject("""
                            select count(*)
                              from official_prompt_signal_contract
                             where lower(signal_key) in (
                                   lower(?),
                                   lower(concat('label:', ?)),
                                   lower(concat('section:', ?))
                             )
                               and coalesce(prompt_location, '') <> ''
                            """,
                    Integer.class,
                    item.trim(),
                    item.trim(),
                    item.trim());
            return count != null && count > 0;
        } catch (DataAccessException ignored) {
            return false;
        }
    }

    private boolean customerRuntimeFactRepeatsContractDisplayText(
            String runtimeFact,
            FinalPromptMetricCheckContract checkContract) {
        if (!StringUtils.hasText(runtimeFact) || checkContract == null) {
            return false;
        }
        return sameCustomerEvidenceText(runtimeFact, checkContract.expectedMessage())
                || sameCustomerEvidenceText(runtimeFact, checkContract.passMessage())
                || sameCustomerEvidenceText(runtimeFact, checkContract.failureMessage())
                || sameCustomerEvidenceText(runtimeFact, checkContract.problemTitle())
                || sameCustomerEvidenceText(runtimeFact, checkContract.shortProblem())
                || sameCustomerEvidenceText(runtimeFact, checkContract.qualityQuestion())
                || sameCustomerEvidenceText(runtimeFact, checkContract.whyItMatters())
                || sameCustomerEvidenceText(runtimeFact, checkContract.meaning())
                || sameCustomerEvidenceText(runtimeFact, checkContract.securityRelevance())
                || sameCustomerEvidenceText(runtimeFact, checkContract.interpretationLink());
    }

    private boolean customerEvidenceContainsRawSymbol(String value) {
        if (!StringUtils.hasText(value)) {
            return false;
        }
        String text = value.trim();
        return text.contains("=")
                || text.contains("|")
                || text.contains("...")
                || text.contains(CUSTOMER_PURPOSE_EVIDENCE_SEPARATOR)
                || CUSTOMER_TECHNICAL_CONTRACT_CODE.matcher(text).find()
                || customerVisiblePromptLocationToken(text)
                || text.startsWith("field:")
                || text.startsWith("section:")
                || text.startsWith("label:")
                || text.startsWith("term:")
                || text.startsWith("thenLabel:")
                || text.startsWith("thenTerm:")
                || text.startsWith("source:");
    }

    private boolean sameCustomerEvidenceText(String left, String right) {
        if (!StringUtils.hasText(left) || !StringUtils.hasText(right)) {
            return false;
        }
        return normalizeCustomerEvidenceText(left).equals(normalizeCustomerEvidenceText(right));
    }

    private void appendCustomerDisplayUnique(List<String> values, String value) {
        if (values == null || !StringUtils.hasText(value)) {
            return;
        }
        String trimmed = value.trim();
        String candidateKey = normalizeCustomerDisplayItemKey(trimmed);
        boolean exists = values.stream()
                .filter(StringUtils::hasText)
                .map(this::normalizeCustomerDisplayItemKey)
                .anyMatch(candidateKey::equals);
        if (!exists) {
            values.add(trimmed);
        }
    }

    private boolean customerDisplayItemsContainDuplicates(List<String> values) {
        if (values == null || values.isEmpty()) {
            return false;
        }
        Set<String> seen = new LinkedHashSet<>();
        for (String value : values) {
            if (!StringUtils.hasText(value)) {
                continue;
            }
            String key = normalizeCustomerDisplayItemKey(value);
            if (!seen.add(key)) {
                return true;
            }
        }
        return false;
    }

    private String normalizeCustomerDisplayItemKey(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        return value.trim()
                .replaceAll("[\\s\\u00A0]+", " ")
                .replaceAll("[.。]+$", "")
                .toLowerCase(Locale.ROOT);
    }

    private boolean customerRuntimeFactHasGenericWrapper(String value) {
        return StringUtils.hasText(value)
                && (value.contains("실제 프롬프트에서 확인된 값은")
                || value.contains("\uac80\uc0ac \ub300\uc0c1 \ud56d\ubaa9\uc740")
                || value.contains("\uac80\uc0ac \ub300\uc0c1 \ucee8\ud14d\uc2a4\ud2b8 \ud56d\ubaa9\uc740"));
    }

    private String normalizeCustomerEvidenceText(String value) {
        return value == null
                ? ""
                : value.trim()
                        .replaceAll("\\s+", " ")
                        .replaceAll("[.!?]+$", "")
                        .toLowerCase(Locale.ROOT);
    }

    private String customerVisiblePurposeSignalKey(String signal, RuntimeEvidenceCheckResult check) {
        if (StringUtils.hasText(signal)) {
            String text = signal.trim();
            if (!customerVisibleTechnicalText(text)) {
                return requireCustomerLedgerText(text, check, "purpose.signal_key");
            }
            List<String> fragments = customerEvidenceFragments(text);
            if (!fragments.isEmpty()) {
                return requireCustomerLedgerText(joinCustomerFragments(fragments), check, "purpose.signal_key");
            }
        }
        String contractText = check == null
                ? ""
                : firstNonBlank(check.label(), check.expectedValue(), check.decisionUtility(), check.whyItMatters());
        if (StringUtils.hasText(contractText)) {
            return requireCustomerLedgerText(contractText, check, "purpose.signal_key");
        }
        throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose signal is not contract-backed. "
                + "metric=" + safe(check == null ? null : check.metricCode())
                + ", check=" + safe(check == null ? null : check.checkCode()));
    }

    private String customerVisiblePurposeEvidenceValue(String rawEvidenceValue, RuntimeEvidenceCheckResult check) {
        return customerVisiblePurposeEvidenceValue(rawEvidenceValue, check, "");
    }

    private String customerVisiblePurposeEvidenceValue(
            String rawEvidenceValue,
            RuntimeEvidenceCheckResult check,
            String excludedText) {
        List<String> fragments = customerEvidenceFragments(rawEvidenceValue);
        List<String> candidates = new ArrayList<>();
        if (!fragments.isEmpty()) {
            appendUnique(candidates, joinCustomerFragments(fragments));
        }
        if (StringUtils.hasText(rawEvidenceValue) && !customerVisibleTechnicalText(rawEvidenceValue)) {
            appendUnique(candidates, rawEvidenceValue.trim());
        }
        if (check != null) {
            appendUnique(candidates, check.decisionUtility());
            appendUnique(candidates, check.operatorReason());
            appendUnique(candidates, check.whyItMatters());
            appendUnique(candidates, check.expectedValue());
            appendUnique(candidates, check.actualValue());
            appendUnique(candidates, check.label());
        }
        for (String candidate : candidates) {
            if (!StringUtils.hasText(candidate)
                    || sameCustomerEvidenceText(candidate, excludedText)
                    || customerVisibleTechnicalText(candidate)) {
                continue;
            }
            return requireCustomerLedgerText(candidate.trim(), check, "purpose.evidence_value");
        }
        throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose evidence is not contract-backed. "
                + "metric=" + safe(check == null ? null : check.metricCode())
                + ", check=" + safe(check == null ? null : check.checkCode()));
    }

    private String requireCustomerLedgerText(
            String candidate,
            RuntimeEvidenceCheckResult check,
            String ledgerField) {
        if (!StringUtils.hasText(candidate)) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose ledger text is blank. "
                    + "field=" + ledgerField
                    + ", metric=" + safe(check == null ? null : check.metricCode())
                    + ", check=" + safe(check == null ? null : check.checkCode()));
        }
        String text = normalizeCustomerLedgerVocabulary(candidate.trim());
        if (!customerVisibleTechnicalText(text) && !customerEvidenceContainsRawSymbol(text)) {
            return text;
        }
        List<String> fragments = customerEvidenceFragments(text);
        if (!fragments.isEmpty()) {
            String converted = joinCustomerFragments(fragments);
            if (StringUtils.hasText(converted)
                    && !customerVisibleTechnicalText(converted)
                    && !customerEvidenceContainsRawSymbol(converted)) {
                return converted;
            }
        }
        throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose ledger text still contains raw technical evidence. "
                + "field=" + ledgerField
                + ", metric=" + safe(check == null ? null : check.metricCode())
                + ", check=" + safe(check == null ? null : check.checkCode()));
    }

    private String normalizeCustomerLedgerVocabulary(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        return value.trim()
                .replace("NO_DIRECT_PERSONAL_COMPARABLE", "no direct personal comparable history")
                .replace("NO_COMPARABLE", "no comparable history")
                .replace("ZERO_RESULTS_NO_DOCUMENTS", "no retrieved documents")
                .replace("NO_RAG_CONTEXT", "no RAG context")
                .replace("SEARCH_NOT_EXECUTED", "search not executed")
                .replace("ObjectiveAlignmentEvidence: UNKNOWN", "ObjectiveAlignmentEvidence state is unknown")
                .replace("Delegated: UNKNOWN", "Delegated state is unknown")
                .replace("confirmed context items:", "context items:");
    }

    private void upsertMetricPurposeContract(
            String purposeVersion,
            String metricCode,
            RuntimeEvidenceMetricResult metric,
            RuntimeEvidenceCheckResult check) {
        if (!StringUtils.hasText(purposeVersion)) {
            return;
        }
        FinalPromptMetricContract metricContract = finalPromptMetricContract(metricCode);
        FinalPromptMetricCheckContract checkContract = finalPromptMetricCheckContract(metricCode, check);
        upsertMetricPurposeContract(purposeVersion, metricCode, metricContract, checkContract);
    }

    private void upsertFullMetricContractCatalog() {
        if (contractCatalogWriter != null) {
            contractCatalogWriter.upsertFullMetricContractCatalog();
            return;
        }
        FinalPromptMetricContractCatalog catalog = finalPromptMetricContractCatalog();
        for (String metricCode : catalog.metricCodesInOrder()) {
            FinalPromptMetricContract metricContract = catalog.metric(metricCode);
            for (FinalPromptMetricCheckContract checkContract : metricContract.checks()) {
                upsertMetricPurposeContract(metricContract.version(), metricCode, metricContract, checkContract);
            }
        }
        upsertPromptSignalRegistryContracts(diagnosticCatalogVersion(), catalog);
    }

    private void assertFullMetricContractCatalogPersisted() {
        if (contractCatalogWriter != null) {
            contractCatalogWriter.assertFullMetricContractCatalogPersisted();
            return;
        }
        FinalPromptMetricContractCatalog catalog = finalPromptMetricContractCatalog();
        int expectedMetricCount = catalog.metricCodesInOrder().size();
        int expectedCheckCount = 0;
        LinkedHashSet<String> expectedInputRows = new LinkedHashSet<>();
        LinkedHashSet<String> expectedSignalRows = new LinkedHashSet<>();
        int expectedCustomerDisplayRows = 0;
        int expectedCustomerDisplayBindingRows = 0;
        for (String metricCode : catalog.metricCodesInOrder()) {
            FinalPromptMetricContract metricContract = catalog.metric(metricCode);
            expectedCheckCount += metricContract.checks().size();
            for (FinalPromptMetricCheckContract checkContract : metricContract.checks()) {
                if (customerDisplayEligible(checkContract)) {
                    expectedCustomerDisplayRows += CUSTOMER_DISPLAY_ROLES.size();
                    expectedCustomerDisplayBindingRows += safeEvidenceBindings(checkContract).size() * 2;
                }
                addExpectedInputRows(expectedInputRows, metricCode, checkContract, checkContract.rule());
                if (checkContract.inputReadinessRule() != null) {
                    addExpectedInputRows(
                            expectedInputRows,
                            metricCode,
                            checkContract,
                            checkContract.inputReadinessRule());
                }
                if (checkContract.applicabilityRule() != null) {
                    addExpectedInputRows(
                            expectedInputRows,
                            metricCode,
                            checkContract,
                            checkContract.applicabilityRule());
                }
                addExpectedSignalRows(expectedSignalRows, metricCode, checkContract, checkContract.rule());
                if (checkContract.inputReadinessRule() != null) {
                    addExpectedSignalRows(
                            expectedSignalRows,
                            metricCode,
                            checkContract,
                            checkContract.inputReadinessRule());
                }
                if (checkContract.applicabilityRule() != null) {
                    addExpectedSignalRows(
                            expectedSignalRows,
                            metricCode,
                            checkContract,
                            checkContract.applicabilityRule());
                }
            }
        }
        for (FinalPromptMetricContractCatalog.PromptSignalContract signal : catalog.promptSignalContracts()) {
            expectedSignalRows.add("MTR|" + signal.checkCode() + "|" + signal.signalKey());
        }
        assertMinimumContractRows("official_metric_purpose_contract", expectedMetricCount);
        assertMinimumContractRows("official_metric_evaluation_contract", expectedCheckCount);
        assertMinimumContractRows("official_metric_customer_message_contract", expectedCheckCount);
        assertMinimumContractRows("official_metric_check_display_evidence_contract", expectedCheckCount);
        assertMinimumContractRows("official_metric_input_contract", expectedInputRows.size());
        assertMinimumContractRows("official_prompt_signal_contract", expectedSignalRows.size());
        assertMinimumContractRows("official_metric_customer_display_contract", expectedCustomerDisplayRows);
        assertMinimumContractRows("official_metric_customer_display_binding", expectedCustomerDisplayBindingRows);
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

    private boolean customerDisplayEligible(FinalPromptMetricCheckContract checkContract) {
        return checkContract != null
                && (checkContract.customerVisible()
                || "INTERNAL_EXECUTION_GATE".equalsIgnoreCase(checkContract.readinessScope()));
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

    private void assertMinimumContractRows(String tableName, int expectedRows) {
        Integer actualRows = contractRowCount(tableName);
        if (actualRows == null || actualRows < expectedRows) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Metric contract catalog was not persisted."
                    + " table=" + tableName + ", expectedRows=" + expectedRows + ", actualRows=" + actualRows);
        }
    }

    private Integer contractRowCount(String tableName) {
        return switch (safe(tableName)) {
            case "official_metric_purpose_contract" ->
                    jdbcTemplate.queryForObject("select count(*) from official_metric_purpose_contract", Integer.class);
            case "official_metric_evaluation_contract" ->
                    jdbcTemplate.queryForObject("select count(*) from official_metric_evaluation_contract", Integer.class);
            case "official_metric_customer_message_contract" ->
                    jdbcTemplate.queryForObject("select count(*) from official_metric_customer_message_contract", Integer.class);
            case "official_metric_check_display_evidence_contract" ->
                    jdbcTemplate.queryForObject("select count(*) from official_metric_check_display_evidence_contract", Integer.class);
            case "official_metric_input_contract" ->
                    jdbcTemplate.queryForObject("select count(*) from official_metric_input_contract", Integer.class);
            case "official_prompt_signal_contract" ->
                    jdbcTemplate.queryForObject("select count(*) from official_prompt_signal_contract", Integer.class);
            case "official_metric_customer_display_contract" ->
                    jdbcTemplate.queryForObject("select count(*) from official_metric_customer_display_contract", Integer.class);
            case "official_metric_customer_display_binding" ->
                    jdbcTemplate.queryForObject("select count(*) from official_metric_customer_display_binding", Integer.class);
            default -> throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Unsupported metric contract table. table="
                    + safe(tableName));
        };
    }

    private static List<Map<String, String>> safeEvidenceBindings(FinalPromptMetricCheckContract checkContract) {
        if (checkContract == null || checkContract.evidenceBindings() == null) {
            return List.of();
        }
        return checkContract.evidenceBindings();
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

    private FinalPromptMetricContract finalPromptMetricContract(String metricCode) {
        return finalPromptMetricContractCatalog().metric(metricCode);
    }

    private FinalPromptMetricCheckContract finalPromptMetricCheckContract(
            String metricCode,
            RuntimeEvidenceCheckResult check) {
        if (check == null || !StringUtils.hasText(check.checkCode())) {
            throw new IllegalStateException("Metric check code is required for contract lookup. metricCode="
                    + normalize(metricCode));
        }
        return finalPromptMetricContractCatalog().check(metricCode, check.checkCode());
    }

    private String canonicalMetricCheckCode(String metricCode, RuntimeEvidenceCheckResult check) {
        return check == null ? "" : canonicalMetricCheckCode(metricCode, check.checkCode());
    }

    private String canonicalMetricCheckCode(String metricCode, String checkCode) {
        String normalizedMetric = normalize(metricCode);
        String normalizedCheck = normalize(checkCode);
        if (!StringUtils.hasText(normalizedCheck)) {
            return "";
        }
        if (StringUtils.hasText(normalizedMetric)) {
            try {
                return finalPromptMetricContractCatalog().check(normalizedMetric, normalizedCheck).checkName();
            }
            catch (IllegalStateException ignored) {
                String prefix = normalizedMetric + "_";
                if (normalizedCheck.startsWith(prefix) && normalizedCheck.length() > prefix.length()) {
                    return normalizedCheck.substring(prefix.length());
                }
            }
        }
        return normalizedCheck;
    }

    private FinalPromptMetricContractCatalog finalPromptMetricContractCatalog() {
        if (finalPromptMetricContractCatalog == null) {
            finalPromptMetricContractCatalog = FinalPromptMetricContractCatalog.load(objectMapper);
        }
        return finalPromptMetricContractCatalog;
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

    private void insertParsedFinalPromptSignalLedgers(
            String aggregateRunId,
            String packageId,
            SealedEvidencePackage evidencePackage) {
        if (!StringUtils.hasText(aggregateRunId) || !StringUtils.hasText(packageId) || evidencePackage == null) {
            return;
        }
        if (!StringUtils.hasText(evidencePackage.getUserPromptText())) {
            return;
        }
        FinalPromptSnapshot snapshot = new FinalPromptParser(finalPromptMetricContractCatalog())
                .parse(evidencePackage.getUserPromptText());
        for (var section : snapshot.sections()) {
            insertPromptSignalLedgerRow(
                    aggregateRunId,
                    packageId,
                    "PROMPT",
                    "SECTION",
                    "section:" + section.name(),
                    "finalUserPrompt.section",
                    section.name(),
                    "",
                    section.name(),
                    section.lineNumber(),
                    "PROMPT_SECTION");
        }
        for (var field : snapshot.fields()) {
            if (!field.mappedToContract()) {
                continue;
            }
            insertPromptSignalLedgerRow(
                    aggregateRunId,
                    packageId,
                    "PROMPT",
                    "FIELD",
                    field.semanticKey(),
                    field.promptLocation(),
                    field.section(),
                    field.label(),
                    field.value(),
                    field.lineNumber(),
                    firstNonBlank(field.attackSignalRole(), field.securityRelevance(), "PROMPT_FIELD"));
        }
        for (var bullet : snapshot.bullets()) {
            insertPromptSignalLedgerRow(
                    aggregateRunId,
                    packageId,
                    "PROMPT",
                    "BULLET",
                    bullet.semanticKey(),
                    bullet.promptLocation(),
                    bullet.section(),
                    firstNonBlank(bullet.parentGroup(), "bullet"),
                    bullet.text(),
                    bullet.lineNumber(),
                    firstNonBlank(bullet.attackSignalRole(), "PROMPT_BULLET"));
        }
        for (var narrative : snapshot.narrativeLines()) {
            insertPromptSignalLedgerRow(
                    aggregateRunId,
                    packageId,
                    "PROMPT",
                    "NARRATIVE",
                    narrative.semanticKey(),
                    narrative.promptLocation(),
                    narrative.section(),
                    "narrative",
                    narrative.text(),
                    narrative.lineNumber(),
                    firstNonBlank(narrative.attackSignalRole(), "PROMPT_NARRATIVE"));
        }
        for (var group : snapshot.semanticGroups()) {
            insertPromptSignalLedgerRow(
                    aggregateRunId,
                    packageId,
                    "PROMPT",
                    "SEMANTIC_GROUP",
                    group.groupKey(),
                    group.groupKey(),
                    group.section(),
                    group.groupLabel(),
                    "fields=" + group.fieldLabels().size()
                            + "; bullets=" + group.bulletTexts().size()
                            + "; narratives=" + group.narrativeTexts().size(),
                    group.startLineNumber(),
                    firstNonBlank(group.attackSignalRole(), group.securityRelevance(), "PROMPT_SEMANTIC_GROUP"));
        }
        for (var unmapped : snapshot.unmappedFacts()) {
            insertPromptSignalLedgerRow(
                    aggregateRunId,
                    packageId,
                    "INTERNAL",
                    "UNMAPPED_PROMPT_FACT",
                    unmapped.errorCode() + ":" + unmapped.section() + ":" + unmapped.label(),
                    "internalGate.unmappedPromptFact",
                    unmapped.section(),
                    unmapped.label(),
                    unmapped.value(),
                    unmapped.lineNumber(),
                    "INTERNAL_GATE");
        }
    }

    private void insertPromptSignalLedgers(
            String aggregateRunId,
            String packageId,
            String metricCode,
            String checkCode,
            RuntimeEvidenceCheckResult check,
            List<String> detectedSignals) {
        if (detectedSignals == null || detectedSignals.isEmpty()) {
            return;
        }
        int index = 0;
        for (String signal : detectedSignals) {
            if (!StringUtils.hasText(signal)) {
                continue;
            }
            String normalizedSignal = signal.trim();
            jdbcTemplate.update("""
                            insert into official_prompt_signal_ledger (
                                package_id, aggregate_run_id, metric_code, check_code,
                                signal_key, prompt_location, section_name, label_name,
                                value_preview, value_hash, line_number, signal_role, created_at
                            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                    fit(packageId, 128),
                    fit(aggregateRunId, 256),
                    fit(metricCode, 32),
                    fit(checkCode, 128),
                    fit(normalizedSignal, 512),
                    fit(firstNonBlank(check.source(), check.issueKey()), 512),
                    "",
                    fit(check.label(), 256),
                    preview(normalizedSignal, 400),
                    null,
                    ++index,
                    fit(firstNonBlank(check.readinessScope(), "CUSTOMER_PROMPT_QUALITY"), 128),
                    nowTimestamp());
        }
    }

    private void insertPromptSignalLedgerRow(
            String aggregateRunId,
            String packageId,
            String metricCode,
            String checkCode,
            String signalKey,
            String promptLocation,
            String sectionName,
            String labelName,
            String value,
            Integer lineNumber,
            String signalRole) {
        if (!StringUtils.hasText(signalKey)) {
            throw new IllegalStateException("Prompt signal ledger row requires a contract signal key.");
        }
        jdbcTemplate.update("""
                        insert into official_prompt_signal_ledger (
                            package_id, aggregate_run_id, metric_code, check_code,
                            signal_key, prompt_location, section_name, label_name,
                            value_preview, value_hash, line_number, signal_role, created_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                fit(packageId, 128),
                fit(aggregateRunId, 256),
                fit(metricCode, 32),
                fit(checkCode, 128),
                fit(signalKey, 512),
                fit(promptLocation, 512),
                fit(sectionName, 256),
                fit(labelName, 256),
                preview(value, 400),
                sha256Prefixed(value),
                lineNumber,
                fit(signalRole, 128),
                nowTimestamp());
    }

    private void linkActualPromptProblemsToPurposeLedgers(String aggregateRunId) {
        if (!StringUtils.hasText(aggregateRunId)) {
            return;
        }
        if (!postgresqlDatabase()) {
            linkActualPromptProblemsToPurposeLedgersPortable(aggregateRunId);
            return;
        }
        jdbcTemplate.update("""
                        update official_actual_prompt_problem_ledger p
                        set purpose_evaluation_id = e.id,
                                contract_version_id = coalesce(
                                        p.contract_version_id,
                                        c.id,
                                        (
                                            select c2.id
                                              from official_metric_evaluation_contract c2
                                             where c2.contract_version = e.contract_version
                                               and upper(c2.metric_code) = upper(e.metric_code)
                                               and (
                                                    c2.check_code = e.check_code
                                                    or c2.issue_key = e.issue_key
                                                    or c2.issue_key = p.field_key
                                               )
                                             order by c2.id desc
                                             limit 1
                                        )
                                ),
                                quality_question = coalesce(nullif(trim(p.quality_question), ''), e.decision_utility),
                                why_it_matters = coalesce(nullif(trim(p.why_it_matters), ''), e.purpose_statement),
                                fix_action = coalesce(nullif(trim(p.fix_action), ''), e.next_action),
                               reverify_criterion_detail = coalesce(nullif(trim(p.reverify_criterion_detail), ''), e.reverify_criterion)
                         from official_metric_purpose_evaluation_ledger e
                         left join official_metric_evaluation_contract c
                           on c.contract_version = e.contract_version
                          and upper(c.metric_code) = upper(e.metric_code)
                          and (
                               c.check_code = e.check_code
                               or c.issue_key = e.issue_key
                          )
                         where p.aggregate_run_id = ?
                           and e.aggregate_run_id = p.aggregate_run_id
                           and e.customer_visible = true
                           and (
                                coalesce(nullif(trim(e.issue_key), ''), e.check_code) = p.field_key
                                or c.issue_key = p.field_key
                           )
                           and (
                                p.purpose_evaluation_id is null
                                or p.contract_version_id is null
                           )
                         """,
                aggregateRunId);
        jdbcTemplate.update("""
                        update official_prompt_field_value_ledger v
                           set blocking_candidate = true
                          from official_actual_prompt_problem_ledger p
                         where p.aggregate_run_id = ?
                           and v.aggregate_run_id = p.aggregate_run_id
                           and upper(v.prompt_stage) = 'FINAL_USER'
                           and p.current_result = true
                           and p.severity = 'BLOCKING'
                           and (
                                v.field_key = p.field_key
                                or (
                                    nullif(trim(coalesce(v.prompt_label, '')), '') is not null
                                    and v.prompt_label = p.prompt_label
                                )
                                or (
                                    nullif(trim(coalesce(v.prompt_label, '')), '') is not null
                                    and position(v.prompt_label in coalesce(p.actual_state, '')) > 0
                                )
                           )
                          """,
                aggregateRunId);
    }

    private void linkActualPromptProblemsToPurposeLedgersPortable(String aggregateRunId) {
        List<Map<String, Object>> rows = jdbcTemplate.queryForList("""
                        select p.id as problem_row_id,
                               e.id as purpose_evaluation_id,
                               coalesce(
                                   p.contract_version_id,
                                   c.id,
                                   (
                                       select c2.id
                                         from official_metric_evaluation_contract c2
                                        where c2.contract_version = e.contract_version
                                          and upper(c2.metric_code) = upper(e.metric_code)
                                          and (
                                               c2.check_code = e.check_code
                                               or c2.issue_key = e.issue_key
                                               or c2.issue_key = p.field_key
                                          )
                                        order by c2.id desc
                                        limit 1
                                   )
                               ) as contract_version_id,
                               coalesce(nullif(trim(p.quality_question), ''), e.decision_utility) as quality_question,
                               coalesce(nullif(trim(p.why_it_matters), ''), e.purpose_statement) as why_it_matters,
                               coalesce(nullif(trim(p.fix_action), ''), e.next_action) as fix_action,
                               coalesce(nullif(trim(p.reverify_criterion_detail), ''), e.reverify_criterion) as reverify_criterion_detail
                          from official_actual_prompt_problem_ledger p
                          join official_metric_purpose_evaluation_ledger e
                            on e.aggregate_run_id = p.aggregate_run_id
                           and e.customer_visible = true
                           and coalesce(nullif(trim(e.issue_key), ''), e.check_code) = p.field_key
                          left join official_metric_evaluation_contract c
                            on c.contract_version = e.contract_version
                           and upper(c.metric_code) = upper(e.metric_code)
                           and (
                                c.check_code = e.check_code
                                or c.issue_key = e.issue_key
                           )
                         where p.aggregate_run_id = ?
                           and (
                                p.purpose_evaluation_id is null
                                or p.contract_version_id is null
                           )
                        """,
                aggregateRunId);
        for (Map<String, Object> row : rows) {
            jdbcTemplate.update("""
                            update official_actual_prompt_problem_ledger
                               set purpose_evaluation_id = ?,
                                   contract_version_id = ?,
                                   quality_question = ?,
                                   why_it_matters = ?,
                                   fix_action = ?,
                                   reverify_criterion_detail = ?
                             where id = ?
                            """,
                    row.get("purpose_evaluation_id"),
                    row.get("contract_version_id"),
                    row.get("quality_question"),
                    row.get("why_it_matters"),
                    row.get("fix_action"),
                    row.get("reverify_criterion_detail"),
                    row.get("problem_row_id"));
        }
        jdbcTemplate.update("""
                        update official_prompt_field_value_ledger v
                           set blocking_candidate = true
                         where v.aggregate_run_id = ?
                           and upper(v.prompt_stage) = 'FINAL_USER'
                           and exists (
                               select 1
                                 from official_actual_prompt_problem_ledger p
                                where p.aggregate_run_id = v.aggregate_run_id
                                  and p.current_result = true
                                  and p.severity = 'BLOCKING'
                                  and (
                                       v.field_key = p.field_key
                                       or (
                                           nullif(trim(coalesce(v.prompt_label, '')), '') is not null
                                           and v.prompt_label = p.prompt_label
                                       )
                                       or (
                                           nullif(trim(coalesce(v.prompt_label, '')), '') is not null
                                           and locate(v.prompt_label, coalesce(p.actual_state, '')) > 0
                                       )
                                  )
                           )
                        """,
                aggregateRunId);
    }

    private String actualPromptProblemId(String aggregateRunId, String packageId, String fieldKey, String state) {
        String seed = safe(packageId) + "|" + safe(fieldKey) + "|" + safe(state);
        return "app-" + UUID.nameUUIDFromBytes(seed.getBytes(StandardCharsets.UTF_8));
    }

    private List<String> normalizeMetricCodes(
            List<String> metricCodes,
            String fieldKey,
            String problemType,
            String sourceType,
            String sourceFieldPath,
            String promptLabel) {
        List<String> result = new ArrayList<>();
        for (String metricCode : metricCodes == null ? List.<String>of() : metricCodes) {
            if (StringUtils.hasText(metricCode)) {
                appendUnique(result, normalize(metricCode));
            }
        }
        if (!result.isEmpty()) {
            return List.copyOf(result);
        }
        return List.copyOf(result);
    }

    private String actualPromptProblemTitle(ActualPromptProblem problem) {
        return requiredActualPromptProblemText(problem, "prompt_label", problem == null ? null : problem.promptLabel());
    }

    private String actualPromptProblemSummary(ActualPromptProblem problem) {
        return actualPromptProblemCustomerText(problem, "prompt_value", problem == null ? null : problem.promptValue());
    }

    private String firstProblemReason(List<ActualPromptProblem> problems) {
        return problems == null || problems.isEmpty()
                ? ""
                : actualPromptProblemSummary(problems.get(0));
    }

    private String actualPromptProblemStatement(ActualPromptProblem problem) {
        return actualPromptProblemSummary(problem);
    }

    private String actualPromptProblemRootCause(ActualPromptProblem problem) {
        return requiredActualPromptProblemText(problem, "why_it_matters", problem == null ? null : problem.whyItMatters());
    }

    private String actualPromptProblemEvidence(ActualPromptProblem problem) {
        return actualPromptProblemCustomerText(problem, "actual_state", problem == null ? null : problem.actualState());
    }

    private String actualPromptProblemExpectedResult(ActualPromptProblem problem) {
        return actualPromptProblemCustomerText(problem, "expected_state", problem == null ? null : problem.expectedState());
    }

    private String actualPromptProblemActualResult(ActualPromptProblem problem) {
        return actualPromptProblemSummary(problem);
    }

    private String actualPromptProblemAction(ActualPromptProblem problem) {
        return requiredActualPromptProblemText(problem, "fix_action", problem == null ? null : problem.fixAction());
    }

    private String actualPromptProblemReverify(ActualPromptProblem problem) {
        return requiredActualPromptProblemText(problem, "reverify_criterion_detail",
                problem == null ? null : problem.reverifyCriterion());
    }
    private String requiredActualPromptProblemText(ActualPromptProblem problem, String fieldName, String value) {
        if (problem == null || !StringUtils.hasText(value)) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Actual final userPrompt problem is missing contract text. "
                    + "field=" + fieldName
                    + ", problemId=" + safe(problem == null ? null : problem.problemId())
                    + ", fieldKey=" + safe(problem == null ? null : problem.fieldKey()));
        }
        return value.trim();
    }

    private String actualPromptProblemCustomerText(ActualPromptProblem problem, String fieldName, String value) {
        String raw = requiredActualPromptProblemText(problem, fieldName, value);
        if (PromptQualityCustomerSentencePolicy.isCustomerSentence(raw)) {
            return raw;
        }
        String converted = customerEvidenceSentence(problem, raw);
        if (PromptQualityCustomerSentencePolicy.isCustomerSentence(converted)) {
            return converted;
        }
        String subject = firstNonBlank(problem.promptLabel(), problem.fieldKey(), "\uD504\uB86C\uD504\uD2B8 \uD56D\uBAA9");
        return subject + " \uD56D\uBAA9\uC758 \uC2E4\uC81C \uAC12\uACFC \uD310\uB2E8 \uADFC\uAC70\uB97C \uACE0\uAC1D\uC774 \uC77D\uC744 \uC218 \uC788\uB294 \uBB38\uC7A5\uC73C\uB85C \uC81C\uACF5\uD574\uC57C \uD569\uB2C8\uB2E4.";
    }

    private String customerEvidenceSentence(ActualPromptProblem problem, String rawEvidence) {
        List<String> fragments = customerEvidenceFragments(rawEvidence);
        String subject = firstNonBlank(problem.promptLabel(), problem.fieldKey(), "\uD504\uB86C\uD504\uD2B8 \uD56D\uBAA9");
        if (fragments.isEmpty()) {
            return subject + " \uD56D\uBAA9\uC758 \uC2E4\uC81C \uAC12\uACFC \uD310\uB2E8 \uADFC\uAC70\uB97C \uACE0\uAC1D\uC774 \uC77D\uC744 \uC218 \uC788\uB294 \uBB38\uC7A5\uC73C\uB85C \uC81C\uACF5\uD574\uC57C \uD569\uB2C8\uB2E4.";
        }
        return subject + " \uD56D\uBAA9\uC5D0\uC11C \uD655\uC778\uB41C \uADFC\uAC70\uB294 " + joinCustomerFragments(fragments) + "\uC785\uB2C8\uB2E4.";
    }

    private List<String> customerEvidenceFragments(String rawEvidence) {
        if (!StringUtils.hasText(rawEvidence)) {
            return List.of();
        }
        String normalized = rawEvidence.trim()
                .replace('[', ' ')
                .replace(']', ' ')
                .replace('{', ' ')
                .replace('}', ' ')
                .replace('"', ' ')
                .replace('\'', ' ');
        List<String> fragments = new ArrayList<>();
        for (String part : normalized.split("\\r?\\n|;|,\\s*(?=[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=)")) {
            String promptFactFragment = customerPromptFactFragment(part.trim());
            if (StringUtils.hasText(promptFactFragment)) {
                if (!fragments.contains(promptFactFragment)) {
                    fragments.add(promptFactFragment);
                }
                if (fragments.size() >= 4) {
                    break;
                }
                continue;
            }
            List<String> keyValueFragments = customerEvidenceKeyValueFragments(part);
            if (!keyValueFragments.isEmpty()) {
                for (String fragment : keyValueFragments) {
                    if (StringUtils.hasText(fragment) && !fragments.contains(fragment)) {
                        fragments.add(fragment);
                    }
                    if (fragments.size() >= 4) {
                        break;
                    }
                }
            } else {
                String fragment = customerEvidenceFragment(part);
                if (StringUtils.hasText(fragment) && !fragments.contains(fragment)) {
                    fragments.add(fragment);
                }
            }
            if (fragments.size() >= 4) {
                break;
            }
        }
        return List.copyOf(fragments);
    }

    private List<String> customerEvidenceKeyValueFragments(String rawPart) {
        if (!StringUtils.hasText(rawPart)) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        Matcher matcher = CUSTOMER_EVIDENCE_KEY_VALUE.matcher(rawPart.trim());
        while (matcher.find()) {
            String key = customerEvidenceName(matcher.group(1));
            String value = customerEvidenceValue(matcher.group(2));
            if (!StringUtils.hasText(key)) {
                continue;
            }
            if (!StringUtils.hasText(value) || missingEvidenceValue(value)) {
                result.add(key + " \uAC12\uC774 \uC81C\uACF5\uB418\uC9C0 \uC54A\uC558\uC2B5\uB2C8\uB2E4");
            } else if ("compactMarker".equals(key)) {
                result.add("\uCD95\uC57D \uD45C\uC2DD " + value);
            } else {
                result.add(key + " \uAC12 " + value);
            }
            if (result.size() >= 4) {
                break;
            }
        }
        return List.copyOf(result);
    }

    private String customerEvidenceFragment(String rawPart) {
        if (!StringUtils.hasText(rawPart)) { return ""; }
        String part = rawPart.trim();
        String promptFact = customerPromptFactFragment(part);
        if (StringUtils.hasText(promptFact)) { return promptFact; }
        if (part.startsWith("field:")) { return "\uD544\uB4DC " + customerEvidenceName(part.substring("field:".length())) + " \uD655\uC778 \uD544\uC694"; }
        if (part.startsWith("section:")) { return "\uC139\uC158 " + customerEvidenceName(part.substring("section:".length())) + " \uD655\uC778 \uD544\uC694"; }
        if (part.startsWith("section ") && part.endsWith("=missing")) { return "\uC139\uC158 " + customerEvidenceName(part.substring("section ".length(), part.length() - "=missing".length())) + " \uB204\uB77D"; }
        int equalsIndex = part.indexOf('=');
        if (equalsIndex <= 0) { return customerEvidencePlainFragment(part); }
        String key = customerEvidenceName(part.substring(0, equalsIndex));
        String value = customerEvidenceValue(part.substring(equalsIndex + 1));
        if (!StringUtils.hasText(key)) { return ""; }
        if (!StringUtils.hasText(value) || missingEvidenceValue(value)) { return key + " \uAC12\uC774 \uC81C\uACF5\uB418\uC9C0 \uC54A\uC558\uC2B5\uB2C8\uB2E4"; }
        if ("compactMarker".equals(key)) { return "\uCD95\uC57D \uD45C\uC2DD " + value; }
        return key + " \uAC12 " + value;
    }

    private String customerPromptFactFragment(String part) {
        return concretePromptFactSignal(part);
    }

    private String customerEvidencePlainFragment(String part) {
        String value = customerEvidenceValue(part);
        if (!StringUtils.hasText(value)) { return ""; }
        if (value.startsWith("\uB204\uB77D") || value.startsWith("\uBD80\uC7AC") || value.startsWith("\uCD95\uC57D \uD45C\uC2DD") || value.startsWith("\uC798\uB9B0 \uD310\uB2E8 \uC7AC\uB8CC")) {
            return value.replace(":", " ");
        }
        return "";
    }

    private boolean missingEvidenceValue(String value) {
        String normalized = normalize(value);
        return normalized.equals("MISSING")
                || normalized.equals("ABSENT")
                || normalized.equals("NULL")
                || normalized.equals("EMPTY")
                || normalized.equals("UNKNOWN");
    }

    private String customerEvidenceName(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        return value.trim()
                .replace("=", " ")
                .replace(":", " ")
                .replace("|", " ")
                .replace("...", " 생략됨")
                .replaceAll("\\s+", " ");
    }

    private String customerEvidenceValue(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        String cleaned = value.trim()
                .replace("Evidence:", "")
                .replace("evidence:", "")
                .replace("=", " ")
                .replace("|", ", ")
                .replace("...", " \uC0DD\uB7B5\uB428")
                .replaceAll("\\s+", " ");
        if (cleaned.length() > 120) {
            return cleaned.substring(0, 120).trim() + " \uC0DD\uB7B5\uB428";
        }
        return cleaned;
    }

    private String customerDisplayValue(String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        String text = value.trim();
        if (!customerVisibleTechnicalText(text)) {
            return text;
        }
        List<String> fragments = customerEvidenceFragments(text);
        if (!fragments.isEmpty()) {
            return joinCustomerFragments(fragments);
        }
        return customerEvidenceValue(text);
    }

    private String joinCustomerFragments(List<String> fragments) {
        List<String> limited = fragments == null ? List.of() : fragments.stream().filter(StringUtils::hasText).limit(3).toList();
        if (limited.isEmpty()) { return "\uD655\uC778 \uAC00\uB2A5\uD55C \uAD6C\uCCB4 \uADFC\uAC70\uAC00 \uC5C6\uC2B5\uB2C8\uB2E4"; }
        if (limited.size() == 1) { return limited.get(0); }
        if (limited.size() == 2) { return limited.get(0) + " \uBC0F " + limited.get(1); }
        return limited.get(0) + ", " + limited.get(1) + " \uBC0F " + limited.get(2);
    }

    private String severityLabel(String severity) {
        return normalize(severity).equals("BLOCKING") ? "\uCC28\uB2E8" : "\uAC80\uD1A0 \uD544\uC694";
    }

    private String processStepForProblem(ActualPromptProblem problem) {
        String owner = normalize(problem == null ? "" : problem.remediationOwner());
        if (owner.contains("PROMPT")) {
            return "PROMPT_GOVERNANCE";
        }
        if (owner.contains("BASELINE") || owner.contains("LEARNING")) {
            return "ISSUE_REMEDIATION";
        }
        return "OFFICIAL_VERIFICATION";
    }

    private void insertPromptGenerationLineage(
            String aggregateRunId,
            String packageId,
            SealedEvidencePackage evidencePackage,
            String promptHash,
            String contextHash) {
        if (!StringUtils.hasText(aggregateRunId) || evidencePackage == null) {
            return;
        }
        Map<String, Object> promptMetadata = parseJson(evidencePackage.getPromptExecutionMetadataJson());
        Object summary = promptMetadata.get("promptUserFieldLineageSummary");
        Boolean compressionApplied = booleanValue(promptMetadata.get("compressionApplied"));
        Boolean rawTruthParity = effectiveRawTruthParity(evidencePackage, promptMetadata);
        String transformationMode = firstNonBlank(
                stringValue(promptMetadata.get("promptViewTransformationMode")),
                stringValue(promptMetadata.get("transformationMode")));
        if (Boolean.TRUE.equals(rawTruthParity) && !Boolean.TRUE.equals(compressionApplied)
                && !StringUtils.hasText(transformationMode)) {
            transformationMode = "NONE";
        }
        String lineageSql = """
                        insert into official_prompt_generation_lineage (
                            package_id, aggregate_run_id, prompt_hash, context_hash,
                            system_prompt_hash, user_prompt_hash, raw_prompt_hash,
                            raw_system_prompt_hash, raw_user_prompt_hash,
                            prompt_budget_profile, compression_applied, transformation_mode,
                            raw_truth_parity, raw_user_field_count, final_user_field_count,
                            field_diff_count, field_loss_count, field_changed_count,
                            field_added_count, compacted_marker_count, truncated_marker_count,
                            lineage_summary_json, created_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, %s, ?)
                        """.formatted(jsonbParameterPlaceholder());
        jdbcTemplate.update(lineageSql,
                fit(packageId, 128),
                fit(aggregateRunId, 256),
                fit(firstNonBlank(promptHash, evidencePackage.getPromptHash(), stringValue(promptMetadata.get("promptHash"))), 160),
                fit(contextHash, 160),
                fit(firstNonBlank(evidencePackage.getSystemPromptHash(), stringValue(promptMetadata.get("systemPromptHash"))), 160),
                fit(firstNonBlank(evidencePackage.getUserPromptHash(), stringValue(promptMetadata.get("userPromptHash"))), 160),
                fit(stringValue(promptMetadata.get("rawPromptHash")), 160),
                fit(firstNonBlank(evidencePackage.getRawSystemPromptHash(), stringValue(promptMetadata.get("rawSystemPromptHash"))), 160),
                fit(firstNonBlank(evidencePackage.getRawUserPromptHash(), stringValue(promptMetadata.get("rawUserPromptHash"))), 160),
                fit(firstNonBlank(
                        stringValue(promptMetadata.get("defaultBudgetProfile")),
                        stringValue(promptMetadata.get("promptBudgetProfile")),
                        stringValue(promptMetadata.get("budgetProfile"))), 128),
                compressionApplied,
                fit(transformationMode, 128),
                rawTruthParity,
                intValue(promptMetadata.get("promptRawUserFieldCount")),
                intValue(promptMetadata.get("promptFinalUserFieldCount")),
                intValue(promptMetadata.get("promptUserFieldDiffCount")),
                intValue(promptMetadata.get("promptUserFieldLossCount")),
                intValue(promptMetadata.get("promptUserFieldChangedCount")),
                intValue(promptMetadata.get("promptUserFieldAddedCount")),
                intValue(promptMetadata.get("promptUserFieldCompactedMarkerCount")),
                intValue(promptMetadata.get("promptUserFieldTruncatedMarkerCount")),
                writeJson(summary),
                nowTimestamp());
    }

    private Boolean effectiveRawTruthParity(
            SealedEvidencePackage evidencePackage,
            Map<String, Object> promptMetadata) {
        Boolean declared = nullableBoolean(promptMetadata.get("promptRawTruthParity"));
        if (evidencePackage == null) {
            return declared;
        }
        boolean sameSystem = samePromptIgnoringLineEndingsAndTrailingWhitespace(
                evidencePackage.getRawSystemPrompt(),
                evidencePackage.getSystemPromptText());
        boolean sameUser = samePromptIgnoringLineEndingsAndTrailingWhitespace(
                evidencePackage.getRawUserPrompt(),
                evidencePackage.getUserPromptText());
        if (sameSystem && sameUser) {
            return true;
        }
        return declared;
    }

    private boolean samePromptIgnoringLineEndingsAndTrailingWhitespace(String left, String right) {
        return normalizePromptForLineageParity(left).equals(normalizePromptForLineageParity(right));
    }

    private String normalizePromptForLineageParity(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\r\n", "\n")
                .replace('\r', '\n')
                .stripTrailing();
    }

    private String jsonbParameterPlaceholder() {
        return postgresqlDatabase() ? "?::jsonb" : "?";
    }

    private boolean postgresqlDatabase() {
        try {
            Boolean postgresql = jdbcTemplate.execute((ConnectionCallback<Boolean>) connection ->
                    connection.getMetaData().getDatabaseProductName().toLowerCase(Locale.ROOT).contains("postgresql"));
            return postgresql == null || Boolean.TRUE.equals(postgresql);
        } catch (DataAccessException exception) {
            return true;
        }
    }

    private boolean tableExists(String tableName) {
        if (!StringUtils.hasText(tableName)) {
            return false;
        }
        try {
            Integer count = jdbcTemplate.queryForObject("""
                            select count(*)
                              from information_schema.tables
                             where lower(table_name) = lower(?)
                               and lower(table_schema) in ('public', 'PUBLIC')
                            """,
                    Integer.class,
                    tableName.trim());
            return count != null && count > 0;
        } catch (DataAccessException exception) {
            return false;
        }
    }

    private void insertPromptFieldValueLedgers(
            String aggregateRunId,
            String packageId,
            SealedEvidencePackage evidencePackage) {
        if (!StringUtils.hasText(aggregateRunId) || evidencePackage == null) {
            return;
        }
        Map<String, Object> promptMetadata = parseJson(evidencePackage.getPromptExecutionMetadataJson());
        insertPromptFieldValueLedgerRows(aggregateRunId, packageId, "RAW_USER",
                promptMetadata.get("promptRawUserFieldLedger"));
        insertPromptFieldValueLedgerRows(aggregateRunId, packageId, "FINAL_USER",
                promptMetadata.get("promptFinalUserFieldLedger"));
    }

    private void insertPromptFieldValueLedgerRows(
            String aggregateRunId,
            String packageId,
            String promptStage,
            Object ledger) {
        if (!(ledger instanceof List<?> rows)) {
            return;
        }
        for (Object row : rows) {
            if (row instanceof Map<?, ?> map) {
                insertPromptFieldValueLedgerRow(aggregateRunId, packageId, promptStage, map);
            }
        }
    }

    private void insertPromptFieldValueLedgerRow(
            String aggregateRunId,
            String packageId,
            String promptStage,
            Map<?, ?> row) {
        jdbcTemplate.update("""
                        insert into official_prompt_field_value_ledger (
                            package_id, aggregate_run_id, prompt_stage, field_key,
                            section_key, section_title, prompt_label, value_hash,
                            value_length, line_number, value_preview,
                            compacted_marker, truncated_marker, quality_relevance,
                            blocking_candidate, created_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        on conflict (package_id, aggregate_run_id, prompt_stage, field_key, line_number)
                        do update set
                            section_key = excluded.section_key,
                            section_title = excluded.section_title,
                            prompt_label = excluded.prompt_label,
                            value_hash = excluded.value_hash,
                            value_length = excluded.value_length,
                            value_preview = excluded.value_preview,
                            compacted_marker = excluded.compacted_marker,
                            truncated_marker = excluded.truncated_marker,
                            quality_relevance = excluded.quality_relevance,
                            blocking_candidate = excluded.blocking_candidate
                        """,
                fit(packageId, 128),
                fit(aggregateRunId, 256),
                fit(promptStage, 32),
                fit(stringValue(row.get("fieldKey")), 512),
                fit(stringValue(row.get("sectionKey")), 256),
                fit(stringValue(row.get("sectionTitle")), 256),
                fit(stringValue(row.get("label")), 256),
                fit(stringValue(row.get("valueHash")), 160),
                intValue(row.get("valueLength")),
                intValue(row.get("lineNumber")),
                safe(stringValue(row.get("valuePreview"))),
                booleanValue(row.get("compactedMarker")),
                booleanValue(row.get("truncatedMarker")),
                fit(defaultText(row.get("qualityRelevance"), "LLM_DECISION_CONTRACT"), 64),
                booleanValue(row.get("blockingCandidate")),
                nowTimestamp());
    }

    private void insertPromptFieldDiffLedgers(
            String aggregateRunId,
            String packageId,
            SealedEvidencePackage evidencePackage) {
        if (!StringUtils.hasText(aggregateRunId) || evidencePackage == null) {
            return;
        }
        Map<String, Object> promptMetadata = parseJson(evidencePackage.getPromptExecutionMetadataJson());
        Object diffLedger = promptMetadata.get("promptUserFieldDiffLedger");
        if (!(diffLedger instanceof List<?> rows)) {
            return;
        }
        for (Object row : rows) {
            if (row instanceof Map<?, ?> map) {
                insertPromptFieldDiffLedgerRow(aggregateRunId, packageId, map);
            }
        }
    }

    private void insertPromptFieldDiffLedgerRow(
            String aggregateRunId,
            String packageId,
            Map<?, ?> row) {
        jdbcTemplate.update("""
                        insert into official_prompt_field_diff_ledger (
                            package_id, aggregate_run_id, field_key, section_key,
                            section_title, prompt_label, raw_value_hash, final_value_hash,
                            raw_line_number, final_line_number, diff_type, diff_reason,
                            quality_relevance, raw_blocking_candidate, official_blocking_candidate,
                            blocking_candidate, created_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                fit(packageId, 128),
                fit(aggregateRunId, 256),
                fit(stringValue(row.get("fieldKey")), 512),
                fit(stringValue(row.get("sectionKey")), 256),
                fit(stringValue(row.get("sectionTitle")), 256),
                fit(stringValue(row.get("label")), 256),
                fit(stringValue(row.get("rawValueHash")), 160),
                fit(stringValue(row.get("finalValueHash")), 160),
                intValue(row.get("rawLineNumber")),
                intValue(row.get("finalLineNumber")),
                fit(stringValue(row.get("diffType")), 64),
                safe(stringValue(row.get("reason"))),
                fit(defaultText(row.get("qualityRelevance"), "LLM_DECISION_CONTRACT"), 64),
                booleanValue(row.get("rawBlockingCandidate")),
                booleanValue(row.get("officialBlockingCandidate")),
                booleanValue(row.get("blockingCandidate")),
                nowTimestamp());
    }

    private void insertPromptFieldStateLedgers(
            String aggregateRunId,
            String packageId,
            SealedEvidencePackage evidencePackage) {
        if (!StringUtils.hasText(aggregateRunId) || evidencePackage == null) {
            return;
        }
        Map<String, Object> manifest = parseJson(evidencePackage.getPromptEvidenceManifestJson());
        Object ledger = manifest.get("fieldStateLedger");
        if (ledger instanceof List<?> rows) {
            for (Object row : rows) {
                if (row instanceof Map<?, ?> map) {
                    insertPromptFieldStateLedgerRow(aggregateRunId, packageId, map);
                }
            }
        }
        Map<String, Object> promptMetadata = parseJson(evidencePackage.getPromptExecutionMetadataJson());
        Object diffLedger = promptMetadata.get("promptUserFieldDiffLedger");
        if (diffLedger instanceof List<?> rows) {
            for (Object row : rows) {
                if (row instanceof Map<?, ?> map) {
                    insertPromptProjectionLedgerRow(aggregateRunId, packageId, map);
                }
            }
        }
        insertMissingPromptFieldStateLedgerRows(aggregateRunId, packageId);
    }

    private void insertMissingPromptFieldStateLedgerRows(String aggregateRunId, String packageId) {
        jdbcTemplate.update("""
                        insert into official_prompt_field_state_ledger (
                            package_id, aggregate_run_id, official_run_id, field_key,
                            source_type, source_field_path, source_class, field_state,
                            value_type, value_hash, value_length, value_preview,
                            required_policy, applicability_rule, applicability_evidence,
                            projection_policy, prompt_presence_state, sealed_evidence_presence_state,
                            producer_status, absence_reason_code, absence_reason_text,
                            metric_impact_policy, blocking_policy, blocking_candidate,
                            quality_relevance, raw_blocking_candidate, official_blocking_candidate,
                            created_at
                        )
                        select ?, ?, null, d.field_key,
                               left(coalesce(nullif(d.source_model, ''), 'OFFICIAL_FIELD_DEFINITION'), 128),
                               d.source_field_path,
                               d.source_class,
                               'PRODUCER_NOT_AVAILABLE',
                               d.value_type,
                               null,
                               null,
                               null,
                               d.required_policy,
                               d.applicability_rule,
                               coalesce(nullif(d.not_applicable_rule, ''), 'Runtime manifest did not emit this active field.'),
                               d.projection_policy,
                               'NOT_RECORDED_IN_RUNTIME_MANIFEST',
                               'NOT_RECORDED_IN_RUNTIME_MANIFEST',
                               'NOT_RECORDED_IN_RUNTIME_MANIFEST',
                               'FIELD_STATE_NOT_EMITTED',
                               'Active field definition existed but the sealed runtime manifest did not emit a state row.',
                               left(coalesce(nullif(d.metric_codes, ''), 'AUDIT_ONLY'), 128),
                               'NON_BLOCKING_FIELD_COVERAGE_GAP',
                               false,
                               d.quality_relevance,
                               false,
                               false,
                               ?
                          from official_prompt_field_definition d
                         where d.is_active = true
                           and not exists (
                                select 1
                                  from official_prompt_field_state_ledger s
                                 where s.aggregate_run_id = ?
                                   and s.field_key = d.field_key
                           )
                        """,
                fit(packageId, 128),
                fit(aggregateRunId, 256),
                nowTimestamp(),
                aggregateRunId);
    }

    private void insertPromptFieldStateLedgerRow(
            String aggregateRunId,
            String packageId,
            Map<?, ?> row) {
        jdbcTemplate.update("""
                        insert into official_prompt_field_state_ledger (
                            package_id, aggregate_run_id, official_run_id, field_key,
                            source_type, source_field_path, source_class, field_state,
                            value_type, value_hash, value_length, value_preview,
                            required_policy, applicability_rule, applicability_evidence,
                            projection_policy, prompt_presence_state, sealed_evidence_presence_state,
                            producer_status, absence_reason_code, absence_reason_text,
                            metric_impact_policy, blocking_policy, blocking_candidate,
                            quality_relevance, raw_blocking_candidate, official_blocking_candidate,
                            created_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                fit(packageId, 128),
                fit(aggregateRunId, 256),
                null,
                fit(stringValue(row.get("fieldKey")), 512),
                fit(stringValue(row.get("sourceType")), 128),
                fit(stringValue(row.get("sourceFieldPath")), 1024),
                fit(stringValue(row.get("sourceClass")), 512),
                fit(stringValue(row.get("fieldState")), 64),
                fit(stringValue(row.get("valueType")), 256),
                fit(stringValue(row.get("valueHash")), 128),
                intValue(row.get("valueLength")),
                safe(stringValue(row.get("valuePreview"))),
                fit(stringValue(row.get("requiredPolicy")), 128),
                fit(stringValue(row.get("applicabilityRule")), 512),
                safe(stringValue(row.get("applicabilityEvidence"))),
                fit(stringValue(row.get("projectionPolicy")), 128),
                fit(stringValue(row.get("promptPresenceState")), 128),
                fit(stringValue(row.get("sealedEvidencePresenceState")), 128),
                fit(stringValue(row.get("producerStatus")), 128),
                fit(stringValue(row.get("absenceReasonCode")), 128),
                safe(stringValue(row.get("absenceReasonText"))),
                fit(stringValue(row.get("metricImpactPolicy")), 128),
                fit(stringValue(row.get("blockingPolicy")), 128),
                booleanValue(row.get("blockingCandidate")),
                fit(defaultText(row.get("qualityRelevance"), "AUDIT_ONLY_SEALED_SOURCE"), 64),
                booleanValue(row.get("rawBlockingCandidate")),
                booleanValue(row.get("officialBlockingCandidate")),
                nowTimestamp());
    }

    private void insertPromptProjectionLedgerRow(
            String aggregateRunId,
            String packageId,
            Map<?, ?> row) {
        jdbcTemplate.update("""
                        insert into official_prompt_projection_ledger (
                            package_id, aggregate_run_id, official_run_id, field_key,
                            prompt_section, prompt_label, raw_value_hash, final_value_hash,
                            raw_line_number, final_line_number, projection_state,
                            projection_reason, blocking_candidate,
                            quality_relevance, raw_blocking_candidate, official_blocking_candidate,
                            created_at
                        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                fit(packageId, 128),
                fit(aggregateRunId, 256),
                null,
                fit(stringValue(row.get("fieldKey")), 512),
                fit(stringValue(row.get("sectionTitle")), 256),
                fit(stringValue(row.get("label")), 256),
                fit(stringValue(row.get("rawValueHash")), 128),
                fit(stringValue(row.get("finalValueHash")), 128),
                intValue(row.get("rawLineNumber")),
                intValue(row.get("finalLineNumber")),
                fit(stringValue(row.get("diffType")), 64),
                safe(stringValue(row.get("reason"))),
                booleanValue(row.get("blockingCandidate")),
                fit(defaultText(row.get("qualityRelevance"), "LLM_DECISION_CONTRACT"), 64),
                booleanValue(row.get("rawBlockingCandidate")),
                booleanValue(row.get("officialBlockingCandidate")),
                nowTimestamp());
    }

    private void assertMetricSnapshotComplete(String aggregateRunId) {
        Integer count = jdbcTemplate.queryForObject(
                "select count(*) from official_verification_metric_snapshot where aggregate_run_id = ?",
                Integer.class,
                aggregateRunId);
        if (count == null || count != 12) {
            throw new IllegalStateException("공식검사 지표 스냅샷은 12개 지표를 모두 저장해야 합니다. aggregateRunId="
                    + aggregateRunId + ", actual=" + count);
        }
    }

    private void assertPromptComparisonLinksComplete(String aggregateRunId) {
        Integer missing = jdbcTemplate.queryForObject("""
                        select count(*)
                          from (
                                select distinct comparison_field_key
                                  from official_verification_operator_finding
                                 where aggregate_run_id = ?
                                   and comparison_field_key is not null
                                   and trim(comparison_field_key) <> ''
                                except
                                select distinct field_key
                                  from official_verification_prompt_comparison
                                 where aggregate_run_id = ?
                                   and field_key is not null
                                   and trim(field_key) <> ''
                               ) missing_prompt_comparison
                        """,
                Integer.class,
                aggregateRunId,
                aggregateRunId);
        if (missing != null && missing > 0) {
            throw new IllegalStateException("공식검사 문제 원장과 프롬프트 비교 원장의 필드 연결이 누락되었습니다. aggregateRunId="
                    + aggregateRunId + ", missingFieldCount=" + missing);
        }
    }

    private void assertActualPromptProblemLedgerAligned(String aggregateRunId) {
        Integer actualProblemCount = jdbcTemplate.queryForObject("""
                        select count(*)
                          from official_actual_prompt_problem_ledger
                         where aggregate_run_id = ?
                           and severity = 'BLOCKING'
                        """,
                Integer.class,
                aggregateRunId);
        Integer findingCount = jdbcTemplate.queryForObject("""
                        select count(distinct check_code)
                           from official_verification_operator_finding
                          where aggregate_run_id = ?
                            and check_code is not null
                            and trim(check_code) <> ''
                         """,
                Integer.class,
                aggregateRunId);
        if ((findingCount == null ? 0 : findingCount) != (actualProblemCount == null ? 0 : actualProblemCount)) {
            throw new IllegalStateException("Actual prompt problem ledger is not aligned with operator findings. aggregateRunId="
                    + aggregateRunId + ", distinctMetricProblemIds=" + findingCount
                    + ", actualPromptProblems=" + actualProblemCount);
        }
        assertActualPromptProblemLedgerReferences(aggregateRunId);
        Integer blockedMetricWithoutProblem = jdbcTemplate.queryForObject("""
                        /* blocked_metric_without_problem */
                        select count(*)
                          from official_verification_metric_snapshot m
                         where m.aggregate_run_id = ?
                           and m.state = 'BLOCKED'
                           and upper(m.metric_code) not in ('MTR', 'RPI', 'PRE')
                           and not exists (
                                select 1
                                  from official_verification_operator_finding f
                                 where f.aggregate_run_id = m.aggregate_run_id
                                   and f.metric_code = m.metric_code
                           )
                        """,
                Integer.class,
                aggregateRunId);
        if (blockedMetricWithoutProblem != null && blockedMetricWithoutProblem > 0) {
            throw new IllegalStateException("Blocked metric snapshot is missing actual prompt problem linkage. aggregateRunId="
                    + aggregateRunId + ", blockedMetricWithoutProblem=" + blockedMetricWithoutProblem);
        }
    }

    private void assertPromptFieldDefinitionsCoverStateLedger(String aggregateRunId) {
        Integer undefinedStateRows = jdbcTemplate.queryForObject("""
                        select count(*)
                          from (
                                select distinct field_key
                                  from official_prompt_field_state_ledger
                                 where aggregate_run_id = ?
                                   and field_key is not null
                                   and trim(field_key) <> ''
                                except
                                select distinct field_key
                                  from official_prompt_field_definition
                                 where is_active = true
                                ) missing_field_definitions
                        """,
                Integer.class,
                aggregateRunId);
        if (undefinedStateRows != null && undefinedStateRows > 0) {
            throw new IllegalStateException("Prompt field state ledger contains fields that are not registered in official_prompt_field_definition. aggregateRunId="
                    + aggregateRunId + ", missingDefinitionCount=" + undefinedStateRows);
        }
        Integer missingStateRows = jdbcTemplate.queryForObject("""
                        select count(*)
                          from official_prompt_field_definition d
                         where d.is_active = true
                           and not exists (
                                select 1
                                  from official_prompt_field_state_ledger s
                                 where s.aggregate_run_id = ?
                                   and s.field_key = d.field_key
                           )
                        """,
                Integer.class,
                aggregateRunId);
        if (missingStateRows != null && missingStateRows > 0) {
            throw new IllegalStateException("Prompt field definition is missing runtime state ledger rows. aggregateRunId="
                    + aggregateRunId + ", missingStateCount=" + missingStateRows);
        }
    }

    private void assertCustomerVisiblePurposeLedgersClean(String aggregateRunId) {
        Integer invalidCustomerVisiblePurposeState = jdbcTemplate.queryForObject("""
                        /* customer_visible_purpose_state_contract */
                        select count(*)
                          from (
                                select purpose_result
                                  from official_metric_purpose_evaluation_ledger
                                 where aggregate_run_id = ?
                                   and customer_visible = true
                                union all
                                select purpose_result
                                  from official_metric_purpose_evidence_ledger
                                 where aggregate_run_id = ?
                                   and customer_visible = true
                               ) purpose_rows
                         where upper(coalesce(purpose_result, '')) not in (
                               'INPUT_NOT_READY',
                               'NOT_APPLICABLE',
                               'PURPOSE_PASSED',
                               'PURPOSE_FAILED'
                         )
                        """,
                Integer.class,
                aggregateRunId,
                aggregateRunId);
        if (invalidCustomerVisiblePurposeState != null && invalidCustomerVisiblePurposeState > 0) {
            throw new IllegalStateException("Customer-visible purpose ledgers contain non-contract purpose_result. aggregateRunId="
                    + aggregateRunId + ", invalidStateCount=" + invalidCustomerVisiblePurposeState
                    + ", firstOffender=" + firstCustomerVisiblePurposeStateOffender(aggregateRunId));
        }
        Integer purposeActualTechnicalText = jdbcTemplate.queryForObject("""
                        /* customer_visible_purpose_actual_technical_text */
                        select count(*)
                          from official_metric_purpose_evaluation_ledger
                          where aggregate_run_id = ?
                            and customer_visible = true
                            and (
                                  actual_value ilike '%Evidence:%'
                                  or actual_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                  or actual_value like '확인된 값:%'
                                  or actual_value like '%실제 프롬프트에서 확인된 값%'
                                  or actual_value like '%확인된 근거:%'
                                  or actual_value like '%검사 대상 항목%'
                                  or actual_value like '% 생략됨%'
                            )
                        """,
                Integer.class,
                aggregateRunId);
        Integer purposeNextActionTechnicalText = jdbcTemplate.queryForObject("""
                        /* customer_visible_purpose_next_action_technical_text */
                        select count(*)
                          from official_metric_purpose_evaluation_ledger
                         where aggregate_run_id = ?
                           and customer_visible = true
                           and (
                                 next_action ilike '%Evidence:%'
                                 or next_action ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                 or next_action like '조치:%'
                                 or next_action like '%누락된 항목%'
                           )
                        """,
                Integer.class,
                aggregateRunId);
        Integer purposeReverifyTechnicalText = jdbcTemplate.queryForObject("""
                        /* customer_visible_purpose_reverify_technical_text */
                        select count(*)
                          from official_metric_purpose_evaluation_ledger
                         where aggregate_run_id = ?
                           and customer_visible = true
                           and (
                                 reverify_criterion ilike '%Evidence:%'
                                 or reverify_criterion ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                 or reverify_criterion like '재검사 기준:%'
                                 or reverify_criterion like '%누락된 항목%'
                           )
                        """,
                Integer.class,
                aggregateRunId);
        Integer purposeEvidenceTechnicalText = jdbcTemplate.queryForObject("""
                        /* customer_visible_purpose_evidence_technical_text */
                        select count(*)
                          from official_metric_purpose_evidence_ledger
                         where aggregate_run_id = ?
                           and customer_visible = true
                           and (
                                 evidence_value ilike '%Evidence:%'
                                 or evidence_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                           )
                        """,
                Integer.class,
                aggregateRunId);
        Integer actualPromptProblemTechnicalText = jdbcTemplate.queryForObject("""
                        /* actual_prompt_problem_customer_technical_text */
                        select count(*)
                          from official_actual_prompt_problem_ledger
                         where aggregate_run_id = ?
                           and (
                                prompt_value ilike '%Evidence:%'
                                or prompt_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                or expected_state ilike '%Evidence:%'
                                or expected_state ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                or expected_state like '문제:%'
                                or actual_state ilike '%Evidence:%'
                                or actual_state ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                or actual_state like '확인된 값:%'
                                or fix_action ilike '%Evidence:%'
                                or fix_action ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                or reverify_criterion_detail ilike '%Evidence:%'
                                or reverify_criterion_detail ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                           )
                        """,
                Integer.class,
                aggregateRunId);
        Integer promptQualityIssueTechnicalText = tableExists("prompt_quality_issue")
                ? jdbcTemplate.queryForObject("""
                                /* prompt_quality_issue_customer_technical_text */
                                select count(*)
                                  from prompt_quality_issue
                                 where aggregate_run_id = ?
                                   and (
                                        actual_value ilike '%Evidence:%'
                                        or actual_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                        or next_action ilike '%Evidence:%'
                                        or next_action ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                        or reverify_criterion ilike '%Evidence:%'
                                        or reverify_criterion ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                   )
                                """,
                        Integer.class,
                        aggregateRunId)
                : 0;
        Integer promptComparisonTechnicalText = jdbcTemplate.queryForObject("""
                        /* prompt_comparison_customer_technical_text */
                        select count(*)
                          from official_verification_prompt_comparison
                         where aggregate_run_id = ?
                            and (
                                 prompt_value ilike '%Evidence:%'
                                 or prompt_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                or prompt_value like '확인된 값:%'
                                 or official_fact_value ilike '%Evidence:%'
                                 or official_fact_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                or official_fact_value like '문제:%'
                                 or sealed_evidence_value ilike '%Evidence:%'
                                 or sealed_evidence_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                            )
                        """,
                Integer.class,
                aggregateRunId);
        int actualCount = purposeActualTechnicalText == null ? 0 : purposeActualTechnicalText;
        int nextActionCount = purposeNextActionTechnicalText == null ? 0 : purposeNextActionTechnicalText;
        int reverifyCount = purposeReverifyTechnicalText == null ? 0 : purposeReverifyTechnicalText;
        int evidenceCount = purposeEvidenceTechnicalText == null ? 0 : purposeEvidenceTechnicalText;
        int actualProblemCount = actualPromptProblemTechnicalText == null ? 0 : actualPromptProblemTechnicalText;
        int issueCount = promptQualityIssueTechnicalText == null ? 0 : promptQualityIssueTechnicalText;
        int comparisonCount = promptComparisonTechnicalText == null ? 0 : promptComparisonTechnicalText;
        if (actualCount > 0 || nextActionCount > 0 || reverifyCount > 0
                || evidenceCount > 0 || actualProblemCount > 0 || issueCount > 0 || comparisonCount > 0) {
            String firstOffender = firstCustomerVisiblePurposeLedgerTechnicalLocation(aggregateRunId);
            throw new IllegalStateException("Customer-visible purpose ledgers contain raw technical evidence. aggregateRunId="
                    + aggregateRunId + ", actualValueCount=" + actualCount + ", nextActionCount=" + nextActionCount
                    + ", reverifyCriterionCount=" + reverifyCount + ", evidenceValueCount=" + evidenceCount
                    + ", actualPromptProblemCount=" + actualProblemCount
                    + ", promptQualityIssueCount=" + issueCount + ", promptComparisonCount=" + comparisonCount
                    + ", firstOffender=" + firstOffender);
        }
        Integer duplicatedPurposeEvidenceText = jdbcTemplate.queryForObject("""
                        /* customer_visible_purpose_evidence_duplicate_text */
                        select count(*)
                          from (
                                select metric_code,
                                       lower(regexp_replace(trim(evidence_value), '[.。]+$', '')) as evidence_key,
                                       count(*) as duplicate_count
                                  from official_metric_purpose_evidence_ledger
                                 where aggregate_run_id = ?
                                   and customer_visible = true
                                   and coalesce(trim(evidence_value), '') <> ''
                                 group by metric_code, lower(regexp_replace(trim(evidence_value), '[.。]+$', ''))
                                having count(*) > 1
                               ) duplicated
                        """,
                Integer.class,
                aggregateRunId);
        if (duplicatedPurposeEvidenceText != null && duplicatedPurposeEvidenceText > 0) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible purpose evidence repeats across checks. aggregateRunId="
                    + aggregateRunId + ", duplicateGroupCount=" + duplicatedPurposeEvidenceText
                    + ", firstOffender=" + firstCustomerVisiblePurposeEvidenceDuplicate(aggregateRunId));
        }
        Integer duplicatedRuntimeFacts = jdbcTemplate.queryForObject("""
                        /* customer_visible_runtime_fact_duplicate_text */
                        select count(*)
                          from (
                                select metric_code,
                                       lower(trim(fact)) as fact_key,
                                       count(distinct check_code) as duplicate_count
                                  from official_metric_purpose_evidence_ledger,
                                       jsonb_array_elements_text(runtime_facts_json::jsonb) as fact
                                 where aggregate_run_id = ?
                                   and customer_visible = true
                                   and coalesce(trim(fact), '') <> ''
                                 group by metric_code, lower(trim(fact))
                                having count(distinct check_code) > 1
                               ) duplicated
                        """,
                Integer.class,
                aggregateRunId);
        if (duplicatedRuntimeFacts != null && duplicatedRuntimeFacts > 0) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible runtime facts repeat across checks. aggregateRunId="
                    + aggregateRunId + ", duplicateGroupCount=" + duplicatedRuntimeFacts
                    + ", firstOffender=" + firstCustomerVisibleRuntimeFactDuplicate(aggregateRunId));
        }
    }

    private String firstCustomerVisiblePurposeEvidenceDuplicate(String aggregateRunId) {
        List<String> rows = jdbcTemplate.queryForList("""
                        select metric_code || ':' || string_agg(check_code, ', ' order by check_code) as offender
                          from (
                                select metric_code,
                                       check_code,
                                       lower(regexp_replace(trim(evidence_value), '[.。]+$', '')) as evidence_key
                                  from official_metric_purpose_evidence_ledger
                                 where aggregate_run_id = ?
                                   and customer_visible = true
                                   and coalesce(trim(evidence_value), '') <> ''
                               ) evidence
                         where (metric_code, evidence_key) in (
                               select metric_code,
                                      lower(regexp_replace(trim(evidence_value), '[.。]+$', '')) as evidence_key
                                 from official_metric_purpose_evidence_ledger
                                where aggregate_run_id = ?
                                  and customer_visible = true
                                  and coalesce(trim(evidence_value), '') <> ''
                                group by metric_code, lower(regexp_replace(trim(evidence_value), '[.。]+$', ''))
                               having count(*) > 1
                         )
                         group by metric_code, evidence_key
                         order by metric_code, evidence_key
                         limit 1
                        """,
                String.class,
                aggregateRunId,
                aggregateRunId);
        return rows.isEmpty() ? "UNKNOWN" : rows.get(0);
    }

    private String firstCustomerVisibleRuntimeFactDuplicate(String aggregateRunId) {
        List<String> rows = jdbcTemplate.queryForList("""
                        select metric_code || ':' || string_agg(check_code, ', ' order by check_code) || ':' || fact_key as offender
                          from (
                                select metric_code,
                                       check_code,
                                       lower(trim(fact)) as fact_key
                                  from official_metric_purpose_evidence_ledger,
                                       jsonb_array_elements_text(runtime_facts_json::jsonb) as fact
                                 where aggregate_run_id = ?
                                   and customer_visible = true
                                   and coalesce(trim(fact), '') <> ''
                               ) evidence
                         where (metric_code, fact_key) in (
                               select metric_code,
                                      lower(trim(fact)) as fact_key
                                 from official_metric_purpose_evidence_ledger,
                                      jsonb_array_elements_text(runtime_facts_json::jsonb) as fact
                                where aggregate_run_id = ?
                                  and customer_visible = true
                                  and coalesce(trim(fact), '') <> ''
                                group by metric_code, lower(trim(fact))
                               having count(distinct check_code) > 1
                         )
                         group by metric_code, fact_key
                         order by metric_code, fact_key
                         limit 1
                        """,
                String.class,
                aggregateRunId,
                aggregateRunId);
        return rows.isEmpty() ? "UNKNOWN" : rows.get(0);
    }

    private String firstCustomerVisiblePurposeStateOffender(String aggregateRunId) {
        List<String> rows = jdbcTemplate.queryForList("""
                        select location
                          from (
                                select 'purpose:' || metric_code || '.' || check_code || '=' || coalesce(purpose_result, '') as location, created_at
                                  from official_metric_purpose_evaluation_ledger
                                 where aggregate_run_id = ?
                                   and customer_visible = true
                                   and upper(coalesce(purpose_result, '')) not in (
                                       'INPUT_NOT_READY',
                                       'NOT_APPLICABLE',
                                       'PURPOSE_PASSED',
                                       'PURPOSE_FAILED'
                                   )
                                union all
                                select 'purpose_evidence:' || metric_code || '.' || check_code || '=' || coalesce(purpose_result, '') as location, created_at
                                  from official_metric_purpose_evidence_ledger
                                 where aggregate_run_id = ?
                                   and customer_visible = true
                                   and upper(coalesce(purpose_result, '')) not in (
                                       'INPUT_NOT_READY',
                                       'NOT_APPLICABLE',
                                       'PURPOSE_PASSED',
                                       'PURPOSE_FAILED'
                                   )
                               ) offenders
                         order by created_at desc
                         limit 1
                        """,
                String.class,
                aggregateRunId,
                aggregateRunId);
        return rows == null || rows.isEmpty() ? "UNKNOWN" : rows.get(0);
    }

    private String firstCustomerVisiblePurposeLedgerTechnicalLocation(String aggregateRunId) {
        if (!tableExists("prompt_quality_issue")) {
            return "UNKNOWN";
        }
        List<String> rows = jdbcTemplate.queryForList("""
                        select location
                          from (
                                select 'purpose.actual_value:' || metric_code || '.' || check_code as location, created_at
                                  from official_metric_purpose_evaluation_ledger
                                 where aggregate_run_id = ?
                                   and customer_visible = true
                                    and (
                                         actual_value ilike '%Evidence:%'
                                         or actual_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                         or actual_value like '확인된 값:%'
                                          or actual_value like '%실제 프롬프트에서 확인된 값%'
                                          or actual_value like '%확인된 근거:%'
                                          or actual_value like '%검사 대상 항목%'
                                          or actual_value like '% 생략됨%'
                                     )
                                  union all
                                 select 'purpose.next_action:' || metric_code || '.' || check_code as location, created_at
                                   from official_metric_purpose_evaluation_ledger
                                  where aggregate_run_id = ?
                                    and customer_visible = true
                                    and (
                                          next_action ilike '%Evidence:%'
                                          or next_action ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                          or next_action like '조치:%'
                                          or next_action like '%누락된 항목%'
                                     )
                                  union all
                                 select 'purpose.reverify_criterion:' || metric_code || '.' || check_code as location, created_at
                                   from official_metric_purpose_evaluation_ledger
                                  where aggregate_run_id = ?
                                    and customer_visible = true
                                    and (
                                          reverify_criterion ilike '%Evidence:%'
                                          or reverify_criterion ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                          or reverify_criterion like '재검사 기준:%'
                                          or reverify_criterion like '%누락된 항목%'
                                     )
                                  union all
                                 select 'purpose_evidence.evidence_value:' || metric_code || '.' || check_code as location, created_at
                                  from official_metric_purpose_evidence_ledger
                                 where aggregate_run_id = ?
                                   and customer_visible = true
                                   and (
                                        evidence_value ilike '%Evidence:%'
                                        or evidence_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                   )
                                 union all
                                 select 'prompt_quality_issue:' || metric_code || '.' || failed_check as location, detected_at as created_at
                                   from prompt_quality_issue
                                  where aggregate_run_id = ?
                                    and (
                                         actual_value ilike '%Evidence:%'
                                        or actual_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                        or next_action ilike '%Evidence:%'
                                        or next_action ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                        or reverify_criterion ilike '%Evidence:%'
                                         or reverify_criterion ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                    )
                                 union all
                                 select 'actual_prompt_problem:' || field_key as location, created_at
                                   from official_actual_prompt_problem_ledger
                                  where aggregate_run_id = ?
                                    and (
                                         prompt_value ilike '%Evidence:%'
                                         or prompt_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                         or expected_state ilike '%Evidence:%'
                                         or expected_state ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                         or expected_state like '문제:%'
                                         or actual_state ilike '%Evidence:%'
                                         or actual_state ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                         or actual_state like '확인된 값:%'
                                         or fix_action ilike '%Evidence:%'
                                         or fix_action ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                         or reverify_criterion_detail ilike '%Evidence:%'
                                         or reverify_criterion_detail ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                    )
                                 union all
                                 select 'prompt_comparison:' || field_key as location, created_at
                                   from official_verification_prompt_comparison
                                  where aggregate_run_id = ?
                                    and (
                                         prompt_value ilike '%Evidence:%'
                                         or prompt_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                         or prompt_value like '확인된 값:%'
                                         or official_fact_value ilike '%Evidence:%'
                                         or official_fact_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                         or official_fact_value like '문제:%'
                                         or sealed_evidence_value ilike '%Evidence:%'
                                         or sealed_evidence_value ~ '[A-Za-z][A-Za-z0-9_.-]{1,80}\\s*=\\s*'
                                    )
                               ) offenders
                         order by created_at desc
                         limit 1
                        """,
                String.class,
                aggregateRunId,
                aggregateRunId,
                aggregateRunId,
                aggregateRunId,
                aggregateRunId,
                aggregateRunId,
                aggregateRunId);
        return rows == null || rows.isEmpty() ? "UNKNOWN" : rows.get(0);
    }

    private void assertActualPromptProblemLedgerReferences(String aggregateRunId) {
        Integer problemWithoutPurposeContract = jdbcTemplate.queryForObject("""
                        /* problem_without_purpose_contract */
                        select count(*)
                          from official_actual_prompt_problem_ledger
                         where aggregate_run_id = ?
                           and severity = 'BLOCKING'
                           and (
                                purpose_evaluation_id is null
                                 or contract_version_id is null
                           )
                        """,
                Integer.class,
                aggregateRunId);
        if (problemWithoutPurposeContract != null && problemWithoutPurposeContract > 0) {
            throw new IllegalStateException("Actual prompt problem ledger is missing purpose contract linkage. aggregateRunId="
                    + aggregateRunId
                    + ", missingContractCount=" + problemWithoutPurposeContract
                    + ", firstOffender=" + firstActualPromptProblemWithoutPurposeContract(aggregateRunId));
        }
        Integer comparisonWithoutProblem = jdbcTemplate.queryForObject("""
                        select count(*)
                          from (
                                select distinct field_key
                                  from official_verification_prompt_comparison
                                 where aggregate_run_id = ?
                                   and nullif(trim(field_key), '') is not null
                                   and (
                                       field_key like 'finalUserPrompt.%'
                                       or field_key like 'finalSystemPrompt.%'
                                   )
                                   and (
                                       state like 'FINAL_PROMPT_%'
                                       or state in (
                                           'PROMPT_MISSING',
                                           'FACT_MISSING',
                                           'VALUE_MISMATCH',
                                           'CONTRACT_MISMATCH',
                                           'REQUIRED_MISSING',
                                           'CONDITIONAL_REQUIRED_MISSING',
                                           'UNKNOWN_WITHOUT_REASON',
                                           'PROMPT_COMPACTED_SIGNAL',
                                           'PRODUCER_NOT_AVAILABLE',
                                           'PROVISIONAL_EVIDENCE',
                                           'NO_DIRECT_COMPARABLE',
                                           'BASELINE_MISMATCH_SIGNAL'
                                       )
                                   )
                                   and canonical_source <> 'OFFICIAL_FINDING'
                                except
                                 select distinct field_key
                                   from official_actual_prompt_problem_ledger
                                  where aggregate_run_id = ?
                                    and severity = 'BLOCKING'
                                    and nullif(trim(field_key), '') is not null
                                ) missing_actual_prompt_problem
                        """,
                Integer.class,
                aggregateRunId,
                aggregateRunId);
        if (comparisonWithoutProblem != null && comparisonWithoutProblem > 0) {
            throw new IllegalStateException("Prompt comparison blocking rows are not fully represented in the actual prompt problem ledger. aggregateRunId="
                    + aggregateRunId + ", missingProblemCount=" + comparisonWithoutProblem);
        }
        Integer findingWithoutProblem = jdbcTemplate.queryForObject("""
                        select count(*)
                          from (
                                select check_code
                                  from official_verification_operator_finding
                                 where aggregate_run_id = ?
                                   and check_code is not null
                                   and trim(check_code) <> ''
                                except
                                 select problem_id
                                   from official_actual_prompt_problem_ledger
                                  where aggregate_run_id = ?
                                    and severity = 'BLOCKING'
                                ) missing_actual_prompt_problem
                        """,
                Integer.class,
                aggregateRunId,
                aggregateRunId);
        if (findingWithoutProblem != null && findingWithoutProblem > 0) {
            throw new IllegalStateException("12 official metric findings must reference actual prompt problem ledger problem_id values. aggregateRunId="
                    + aggregateRunId + ", missingProblemReferenceCount=" + findingWithoutProblem);
        }
    }

    private void assertMetricDefinitionsRegistered(List<RuntimeEvidenceMetricResult> metrics) {
        Set<String> metricCodes = new LinkedHashSet<>();
        Set<String> metricCheckCodes = new LinkedHashSet<>();
        for (RuntimeEvidenceMetricResult metric : metrics) {
            if (metric != null && StringUtils.hasText(metric.metricCode())) {
                String metricCode = normalize(metric.metricCode());
                metricCodes.add(metricCode);
                if (metric.checks() != null) {
                    for (RuntimeEvidenceCheckResult check : metric.checks()) {
                        if (check == null || !StringUtils.hasText(check.purposeVersion())) {
                            continue;
                        }
                        String checkCode = canonicalMetricCheckCode(metricCode, check);
                        if (StringUtils.hasText(checkCode)) {
                            metricCheckCodes.add(metricCode + "|" + normalize(checkCode));
                        }
                    }
                }
            }
        }
        upsertFullMetricContractCatalog();
        assertFullMetricContractCatalogPersisted();
        List<String> registeredRows = jdbcTemplate.queryForList("""
                        select p.metric_code
                          from official_metric_purpose_contract p
                          join official_metric_contract_version v
                            on v.contract_version = p.contract_version
                           and v.active = true
                        """,
                String.class);
        Set<String> registeredCodes = new LinkedHashSet<>();
        if (registeredRows != null) {
            for (String row : registeredRows) {
                if (StringUtils.hasText(row)) {
                    registeredCodes.add(normalize(row));
                }
            }
        }
        List<String> missingDefinitions = metricCodes.stream()
                .filter(code -> !registeredCodes.contains(code))
                .toList();
        if (!missingDefinitions.isEmpty()) {
            throw new IllegalStateException("공식검사 지표 정의가 DB 계약에 등록되지 않았습니다: "
                    + String.join(", ", missingDefinitions));
        }

        List<String> checkRows = jdbcTemplate.queryForList("""
                        select e.metric_code || '|' || e.check_code
                          from official_metric_evaluation_contract e
                          join official_metric_contract_version v
                            on v.contract_version = e.contract_version
                           and v.active = true
                        """,
                String.class);
        Set<String> checkDefinitionCodes = new LinkedHashSet<>();
        if (checkRows != null) {
            for (String row : checkRows) {
                if (StringUtils.hasText(row)) {
                    String[] parts = row.split("\\|", 2);
                    if (parts.length == 2) {
                        checkDefinitionCodes.add(normalize(parts[0]) + "|" + normalize(parts[1]));
                    }
                }
            }
        }
        List<String> missingCheckDefinitions = metricCheckCodes.stream()
                .filter(code -> !checkDefinitionCodes.contains(code))
                .toList();
        if (!missingCheckDefinitions.isEmpty()) {
            throw new IllegalStateException("공식검사 지표 검사항목 정의가 DB 계약에 등록되지 않았습니다: "
                    + String.join(", ", missingCheckDefinitions));
        }
    }

    private CheckDefinitionLink checkDefinitionLink(String aggregateRunId, String metricCode, RuntimeEvidenceCheckResult check) {
        CheckDefinitionLink actualPromptProblemLink = actualPromptProblemLink(aggregateRunId, check);
        if (actualPromptProblemLink != null) {
            return actualPromptProblemLink;
        }
        String safeMetricCode = safe(metricCode);
        String safeCheckCode = safe(canonicalMetricCheckCode(safeMetricCode, check));
        if (StringUtils.hasText(safeMetricCode) && StringUtils.hasText(safeCheckCode)) {
            try {
                List<CheckDefinitionLink> rows = jdbcTemplate.query("""
                                select e.issue_key, e.issue_key as prompt_location, e.readiness_scope
                                  from official_metric_evaluation_contract e
                                  join official_metric_contract_version v
                                    on v.contract_version = e.contract_version
                                   and v.active = true
                                 where e.metric_code = ?
                                   and e.check_code = ?
                                 order by e.created_at desc, e.id desc
                                 limit 1
                                 """,
                        (rs, rowNum) -> new CheckDefinitionLink(
                                rs.getString("issue_key"),
                                rs.getString("prompt_location"),
                                rs.getString("readiness_scope")),
                        safeMetricCode,
                        safeCheckCode);
                if (!rows.isEmpty()) {
                    CheckDefinitionLink row = rows.get(0);
                    if (!StringUtils.hasText(row.fieldKey()) || !StringUtils.hasText(row.promptLocation())) {
                        throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Metric check definition is missing prompt linkage."
                                + " aggregateRunId=" + safe(aggregateRunId)
                                + ", metricCode=" + safeMetricCode
                                + ", checkCode=" + safeCheckCode);
                    }
                    return new CheckDefinitionLink(
                            row.fieldKey(),
                            row.promptLocation(),
                            firstNonBlank(row.relatedProcessStep(), "OFFICIAL_VERIFICATION"));
                }
            } catch (DataAccessException ignored) {
                // The final consistency assertion rejects official findings that are not linked to
                // the actual prompt problem ledger or an explicit metric check definition.
            }
        }
        throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Metric check is not linked to actual prompt problem or check definition."
                + " aggregateRunId=" + safe(aggregateRunId)
                + ", metricCode=" + safeMetricCode
                + ", checkCode=" + safeCheckCode);
    }

    private CheckDefinitionLink actualPromptProblemLink(String aggregateRunId, RuntimeEvidenceCheckResult check) {
        String problemId = safe(check == null ? null : check.checkCode());
        String source = safe(check == null ? null : check.source());
        String issueKey = safe(check == null ? null : check.issueKey());
        String contractIssueKey = "";
        if (check != null && StringUtils.hasText(check.purposeVersion()) && StringUtils.hasText(check.checkCode())) {
            try {
                contractIssueKey = safe(finalPromptMetricCheckContract(check.metricCode(), check).issueKey());
            }
            catch (IllegalStateException ignored) {
                contractIssueKey = "";
            }
        }
        if (!StringUtils.hasText(aggregateRunId)
                || (!StringUtils.hasText(problemId)
                && !StringUtils.hasText(issueKey)
                && !StringUtils.hasText(contractIssueKey)
                && !StringUtils.hasText(source))) {
            return null;
        }
        try {
            List<CheckDefinitionLink> rows = jdbcTemplate.query("""
                            select field_key, prompt_section, source_field_path
                              from official_actual_prompt_problem_ledger
                             where aggregate_run_id = ?
                               and (
                                    problem_id = ?
                                    or field_key = ?
                                    or field_key = ?
                                    or field_key = ?
                               )
                             order by case when severity = 'BLOCKING' then 0 else 1 end, created_at desc
                             limit 1
                             """,
                    (rs, rowNum) -> new CheckDefinitionLink(
                            rs.getString("field_key"),
                            firstNonBlank(rs.getString("source_field_path"), rs.getString("prompt_section"), "userPrompt"),
                            "OFFICIAL_VERIFICATION"),
                    aggregateRunId,
                    problemId,
                    issueKey,
                    contractIssueKey,
                    source);
            if (rows != null && !rows.isEmpty()) {
                CheckDefinitionLink row = rows.get(0);
                if (StringUtils.hasText(row.fieldKey())) {
                    return row;
                }
            }
        }
        catch (DataAccessException ignored) {
            // Existing installations may not yet have the problem ledger while migration validation is running.
            // The final consistency assertion still rejects official findings that are not linked to this ledger.
        }
        return null;
    }

    private RuntimeEvidenceCheckResult firstFailedCheck(RuntimeEvidenceMetricResult metric) {
        if (metric == null || metric.checks() == null) {
            return null;
        }
        return metric.checks().stream()
                .filter(check -> check != null && !check.pass())
                .findFirst()
                .orElse(null);
    }

    private RuntimeEvidenceCheckResult firstNotApplicableCheck(RuntimeEvidenceMetricResult metric) {
        if (metric == null || metric.checks() == null) {
            return null;
        }
        return metric.checks().stream()
                .filter(this::notApplicableCheck)
                .findFirst()
                .orElse(null);
    }

    private String notApplicableCheckMessage(RuntimeEvidenceCheckResult check) {
        if (check == null) {
            return "";
        }
        String contractMessage = "";
        if (StringUtils.hasText(check.purposeVersion()) && StringUtils.hasText(check.checkCode())) {
            contractMessage = finalPromptMetricCheckContract(check.metricCode(), check).notApplicableMessage();
        }
        String message = firstNonBlank(contractMessage, check.operatorReason(), check.actualValue());
        if (StringUtils.hasText(message)) {
            return conciseCustomerText(message, CUSTOMER_OPERATOR_TEXT_MAX);
        }
        throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Not applicable metric check is missing contract message. "
                + "metricCode=" + safe(check.metricCode())
                + ", checkCode=" + safe(check.checkCode()));
    }

    private String notApplicableCheckReverifyCriterion(RuntimeEvidenceCheckResult check) {
        if (check == null) {
            return "";
        }
        String contractCriterion = "";
        if (StringUtils.hasText(check.purposeVersion()) && StringUtils.hasText(check.checkCode())) {
            contractCriterion = finalPromptMetricCheckContract(check.metricCode(), check).reverifyCriterion();
        }
        String criterion = firstNonBlank(contractCriterion, check.reverifyCriterion(), notApplicableCheckMessage(check));
        if (StringUtils.hasText(criterion)) {
            return conciseCustomerText(criterion, CUSTOMER_OPERATOR_TEXT_MAX);
        }
        throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Not applicable metric check is missing contract reverify criterion. "
                + "metricCode=" + safe(check.metricCode())
                + ", checkCode=" + safe(check.checkCode()));
    }

    private String firstFailureReason(RuntimeEvidenceMetricResult metric) {
        RuntimeEvidenceCheckResult check = firstFailedCheck(metric);
        if (check == null) {
            return "";
        }
        if (StringUtils.hasText(check.operatorReason())) {
            return conciseCustomerText(check.operatorReason(), CUSTOMER_OPERATOR_TEXT_MAX);
        }
        throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Metric failure is missing DB-backed operator reason. "
                + "metricCode=" + safe(metric == null ? null : metric.metricCode())
                + ", checkCode=" + safe(check.checkCode()));
    }

    private String firstActualPromptProblemWithoutPurposeContract(String aggregateRunId) {
        List<String> rows = jdbcTemplate.queryForList("""
                        select field_key || '|' || problem_type || '|metrics=' || affected_metric_codes
                          from official_actual_prompt_problem_ledger
                         where aggregate_run_id = ?
                           and severity = 'BLOCKING'
                           and (
                                purpose_evaluation_id is null
                                 or contract_version_id is null
                           )
                         order by created_at desc, field_key asc
                         limit 1
                        """,
                String.class,
                aggregateRunId);
        return rows == null || rows.isEmpty() ? "UNKNOWN" : rows.get(0);
    }

    private String metricSnapshotFailureReason(
            RuntimeEvidenceMetricResult metric,
            RuntimeEvidenceCheckResult check,
            boolean inputReview,
            boolean gateReview) {
        if (check == null) {
            return "";
        }
        if (inputReview) {
            String missing = joinedSignals(check, "missing:");
            if (StringUtils.hasText(missing)) {
                return conciseCustomerText("입력 준비에 필요한 항목이 누락되었습니다: " + missing, CUSTOMER_OPERATOR_TEXT_MAX);
            }
        }
        if (gateReview) {
            String missing = joinedSignals(check, "missing:");
            if (StringUtils.hasText(missing)) {
                return conciseCustomerText("발급 전 확인에 필요한 항목이 누락되었습니다: " + missing, CUSTOMER_OPERATOR_TEXT_MAX);
            }
            String present = joinedSignals(check, "present:");
            if (StringUtils.hasText(present)) {
                return conciseCustomerText("발급 전 확인에서 확인된 항목입니다: " + present, CUSTOMER_OPERATOR_TEXT_MAX);
            }
        }
        return firstFailureReason(metric);
    }

    private String metricSnapshotNextAction(
            String metricCode,
            RuntimeEvidenceCheckResult check,
            boolean inputReview,
            boolean gateReview) {
        String base = nextAction(metricCode, check);
        if (inputReview) {
            String missing = joinedSignals(check, "missing:");
            if (StringUtils.hasText(missing)) {
                return conciseCustomerText(base + " 누락된 항목: " + missing, CUSTOMER_OPERATOR_TEXT_MAX);
            }
        }
        if (gateReview) {
            String missing = joinedSignals(check, "missing:");
            if (StringUtils.hasText(missing)) {
                return conciseCustomerText(base + " 확인할 항목: " + missing, CUSTOMER_OPERATOR_TEXT_MAX);
            }
        }
        return base;
    }

    private String metricSnapshotReverifyCriterion(
            String metricCode,
            RuntimeEvidenceCheckResult check,
            boolean inputReview,
            boolean gateReview) {
        String base = reverifyCriterion(metricCode, check);
        if (inputReview || gateReview) {
            String missing = joinedSignals(check, "missing:");
            if (StringUtils.hasText(missing)) {
                return conciseCustomerText(base + " 재검사할 항목: " + missing, CUSTOMER_OPERATOR_TEXT_MAX);
            }
        }
        return base;
    }

    private String joinedSignals(RuntimeEvidenceCheckResult check, String prefix) {
        if (check == null || !StringUtils.hasText(prefix)) {
            return "";
        }
        return effectiveDetectedSignals(check).stream()
                .filter(value -> value != null && value.startsWith(prefix))
                .map(value -> displaySignal(value.substring(prefix.length())))
                .filter(StringUtils::hasText)
                .distinct()
                .limit(6)
                .collect(Collectors.joining(", "));
    }

    private String displaySignal(String value) {
        String normalized = safe(value).trim();
        if (!StringUtils.hasText(normalized)) {
            return "";
        }
        if (normalized.startsWith("field:")) {
            return normalized.substring("field:".length());
        }
        if (normalized.startsWith("label:")) {
            return normalized.substring("label:".length());
        }
        if (normalized.startsWith("section:")) {
            return "section:" + normalized.substring("section:".length());
        }
        return normalized;
    }

    private String evidenceSummary(RuntimeEvidenceCheckResult check) {
        throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Metric check is missing DB-backed evidence summary.");
    }

    private String operatorSummary(String metricCode, RuntimeEvidenceCheckResult check, String metricImpact) {
        throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Metric check is missing DB-backed operator summary. metricCode="
                + safe(metricCode)
                + ", checkCode=" + safe(check == null ? null : check.checkCode()));
    }

    private String problemStatement(String metricCode, RuntimeEvidenceCheckResult check) {
        throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Metric check is missing DB-backed problem statement. metricCode="
                + safe(metricCode)
                + ", checkCode=" + safe(check == null ? null : check.checkCode()));
    }

    private String rootCause(String metricCode, RuntimeEvidenceCheckResult check) {
        if (check == null) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Metric check is missing contract reason. metricCode="
                    + safe(metricCode));
        }
        if (StringUtils.hasText(check.operatorReason())) {
            return conciseCustomerText(check.operatorReason(), CUSTOMER_OPERATOR_TEXT_MAX);
        }
        throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Metric check is missing contract reason. metricCode="
                + safe(metricCode)
                + ", checkCode=" + safe(check.checkCode()));
    }

    private String affectedTarget(String metricCode, RuntimeEvidenceCheckResult check) {
        throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Metric check is missing DB-backed affected target. metricCode="
                + safe(metricCode)
                + ", checkCode=" + safe(check == null ? null : check.checkCode()));
    }

    private String expectedResult(RuntimeEvidenceCheckResult check) {
        throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Metric check is missing DB-backed expected result. checkCode="
                + safe(check == null ? null : check.checkCode()));
    }

    private String actualResult(RuntimeEvidenceCheckResult check) {
        throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Metric check is missing DB-backed actual result. checkCode="
                + safe(check == null ? null : check.checkCode()));
    }

    private String checkLabel(String metricCode, RuntimeEvidenceCheckResult check) {
        String label = check == null ? null : check.label();
        if (StringUtils.hasText(label)) {
            return label.trim();
        }
        throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Metric check is missing contract label. metricCode="
                + safe(metricCode)
                + ", checkCode=" + safe(check == null ? null : check.checkCode()));
    }

    private String nextAction(String metricCode, RuntimeEvidenceCheckResult check) {
        if (check != null && StringUtils.hasText(check.purposeVersion()) && StringUtils.hasText(check.checkCode())) {
            String contractAction = finalPromptMetricCheckContract(metricCode, check).nextAction();
            if (StringUtils.hasText(contractAction)) {
                return conciseCustomerText(contractAction, CUSTOMER_OPERATOR_TEXT_MAX);
            }
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Metric check contract is missing next action. metricCode="
                    + safe(metricCode)
                    + ", checkCode=" + safe(check.checkCode()));
        }
        String action = check == null ? null : check.nextAction();
        if (StringUtils.hasText(action)) {
            return conciseCustomerText(action, CUSTOMER_OPERATOR_TEXT_MAX);
        }
        throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Metric check is missing contract next action. metricCode="
                + safe(metricCode)
                + ", checkCode=" + safe(check == null ? null : check.checkCode()));
    }

    private String reverifyCriterion(String metricCode, RuntimeEvidenceCheckResult check) {
        if (check != null && StringUtils.hasText(check.purposeVersion()) && StringUtils.hasText(check.checkCode())) {
            String contractCriterion = finalPromptMetricCheckContract(metricCode, check).reverifyCriterion();
            if (StringUtils.hasText(contractCriterion)) {
                return conciseCustomerText(contractCriterion, CUSTOMER_OPERATOR_TEXT_MAX);
            }
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Metric check contract is missing reverify criterion. metricCode="
                    + safe(metricCode)
                    + ", checkCode=" + safe(check.checkCode()));
        }
        String criterion = check == null ? null : check.reverifyCriterion();
        if (StringUtils.hasText(criterion)) {
            return conciseCustomerText(criterion, CUSTOMER_OPERATOR_TEXT_MAX);
        }
        throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Metric check is missing contract reverify criterion. metricCode="
                + safe(metricCode)
                + ", checkCode=" + safe(check == null ? null : check.checkCode()));
    }

    private boolean actualPromptProblemCheck(RuntimeEvidenceCheckResult check) {
        return customerPromptQualityCheck(check)
                && officialPromptIssueField(firstNonBlank(check.issueKey(), check.source()));
    }

    private boolean hasCustomerPromptQualityFailure(RuntimeEvidenceMetricResult metric) {
        if (metric == null || metric.checks() == null) {
            return false;
        }
        return metric.checks().stream()
                .anyMatch(check -> customerPromptQualityCheck(check)
                        && !check.pass()
                        && !inputReadinessNotReady(check)
                        && "BLOCKING".equalsIgnoreCase(safe(check.severity(), "")));
    }

    private boolean customerPromptQualityCheck(RuntimeEvidenceCheckResult check) {
        if (check == null || !check.customerVisible()) {
            return false;
        }
        return "CUSTOMER_PROMPT_QUALITY".equalsIgnoreCase(firstNonBlank(
                check.readinessScope(),
                "CUSTOMER_PROMPT_QUALITY"));
    }

    private String evidenceLocationDisplay(String source) {
        String normalized = normalize(source);
        if (normalized.contains("AUTH")) return "\uC778\uC99D\u00B7\uAD8C\uD55C \uCEE8\uD14D\uC2A4\uD2B8";
        if (normalized.contains("REQUEST")) return "\uC694\uCCAD \uCEE8\uD14D\uC2A4\uD2B8";
        if (normalized.contains("PROMPT")) return "\uD504\uB86C\uD504\uD2B8 \uC0B0\uCD9C\uBB3C";
        if (normalized.contains("GOVERNANCE")) return "\uD504\uB86C\uD504\uD2B8 \uAC70\uBC84\uB10C\uC2A4";
        if (normalized.contains("BASELINE")) return "\uAE30\uC900\uC120 \uCEE8\uD14D\uC2A4\uD2B8";
        if (normalized.contains("RAG") || normalized.contains("DOCUMENT")) return "RAG \uAC80\uC0C9 \uADFC\uAC70";
        if (normalized.contains("RESOURCE")) return "\uB9AC\uC18C\uC2A4 \uBA54\uD0C0\uB370\uC774\uD130";
        if (StringUtils.hasText(source)) return "\uCEE8\uD14D\uC2A4\uD2B8 \uCD9C\uCC98 " + source.trim();
        return "\uCEE8\uD14D\uC2A4\uD2B8 \uCD9C\uCC98";
    }

    private String customerVisibleSeverity(RuntimeEvidenceCheckResult check) {
        String severity = check == null ? "" : safe(check.severity(), "");
        if ("BLOCKING".equalsIgnoreCase(severity)) {
            return "\uCC28\uB2E8";
        }
        if ("INSUFFICIENT".equalsIgnoreCase(severity)) {
            return "\uC785\uB825 \uC900\uBE44 \uBD80\uC871";
        }
        return "\uAC80\uD1A0 \uD544\uC694";
    }

    private String ownerDisplayName(String owner) {
        String normalized = normalize(owner);
        if (!StringUtils.hasText(normalized)) return "\uACF5\uC2DD\uAC80\uC0AC \uD1B5\uD569 \uACF5\uC815";
        if (normalized.contains("PQA_RUNTIME") || normalized.contains("OFFICIAL_VERIFICATION")) return "\uACF5\uC2DD\uAC80\uC0AC \uD1B5\uD569 \uACF5\uC815";
        if (normalized.contains("PROMPT_ASSEMBLER")) return "\uD504\uB86C\uD504\uD2B8 \uC870\uB9BD\uAE30";
        if (normalized.contains("REQUEST_CONTEXT")) return "\uC694\uCCAD \uCEE8\uD14D\uC2A4\uD2B8 \uC0DD\uC0B0\uC790";
        if (normalized.contains("AUTH_CONTEXT")) return "\uC778\uC99D\u00B7\uAD8C\uD55C \uCEE8\uD14D\uC2A4\uD2B8 \uC0DD\uC0B0\uC790";
        if (normalized.contains("AUTHORIZATION")) return "\uAD8C\uD55C \uCEE8\uD14D\uC2A4\uD2B8 \uC0DD\uC0B0\uC790";
        if (normalized.contains("CONTEXT_PRODUCER")) return "\uCEE8\uD14D\uC2A4\uD2B8 \uC0DD\uC0B0\uC790";
        if (normalized.contains("CONTEXT_ASSEMBLER")) return "\uCEE8\uD14D\uC2A4\uD2B8 \uC870\uB9BD\uAE30";
        if (normalized.contains("PROMPT_CAPTURE")) return "\uD504\uB86C\uD504\uD2B8 \uCEA1\uCC98";
        if (normalized.contains("PROMPT_HASH") || normalized.contains("TRACEABILITY")) return "\uD504\uB86C\uD504\uD2B8 \uCD94\uC801\uC131 \uC800\uC7A5\uC18C";
        if (normalized.contains("PROMPT_TEMPLATE")) return "\uD504\uB86C\uD504\uD2B8 \uD15C\uD50C\uB9BF";
        if (normalized.contains("PROMPT_GOVERNANCE")) return "\uD504\uB86C\uD504\uD2B8 \uAC70\uBC84\uB10C\uC2A4 \uC800\uC7A5\uC18C";
        if (normalized.contains("EVIDENCE")) return "\uBD09\uC778 \uC99D\uAC70 \uC800\uC7A5\uC18C";
        if (normalized.contains("RAG")) return "RAG \uAD8C\uD55C \uD544\uD130";
        if (normalized.contains("LEARNING") || normalized.contains("BASELINE")) return "\uD559\uC2B5 \uAE30\uC900\uC120 \uC0DD\uC0B0\uC790";
        if (normalized.contains("BEHAVIOR")) return "\uD589\uB3D9 \uCEE8\uD14D\uC2A4\uD2B8 \uC0DD\uC0B0\uC790";
        if (normalized.contains("PROTECTABLE")) return "\uBCF4\uD638 \uB9AC\uC18C\uC2A4 \uBA54\uD0C0\uB370\uC774\uD130";
        if (normalized.contains("OFFICIAL_LEDGER")) return "\uACF5\uC2DD\uAC80\uC0AC \uC6D0\uC7A5 \uC800\uC7A5\uC18C";
        if (hasHangul(owner) && !OfficialPromptQualityNarrativeCatalog.containsBrokenText(owner)) return owner.trim();
        return "\uACF5\uC2DD\uAC80\uC0AC \uD1B5\uD569 \uACF5\uC815";
    }

    private boolean passed(RuntimeEvidenceMetricResult metric) {
        return PASS_STATES.contains(state(metric));
    }

    private boolean metricFailed(RuntimeEvidenceMetricResult metric) {
        return metric != null && !passed(metric);
    }

    private boolean metricInputReadinessNotReady(RuntimeEvidenceMetricResult metric) {
        if (metric == null) {
            return false;
        }
        if ("INPUT_NOT_READY".equals(state(metric)) || "INPUT_NOT_READY".equalsIgnoreCase(safe(metric.state()))) {
            return true;
        }
        if (metric.checks() == null) {
            return false;
        }
        return metric.checks().stream().anyMatch(this::inputReadinessNotReady);
    }

    private int failedCheckCount(RuntimeEvidenceMetricResult metric) {
        if (state(metric).equals("NOT_APPLICABLE")) {
            return 0;
        }
        if (passed(metric)) {
            return 0;
        }
        if (metric == null || metric.checks() == null) {
            return Math.max(metric == null ? 0 : metric.totalChecks() - metric.passedChecks(), 0);
        }
        return (int) metric.checks().stream()
                .filter(check -> check != null && evaluatedCustomerCheck(check) && !check.pass())
                .count();
    }

    private int totalCheckCount(RuntimeEvidenceMetricResult metric) {
        if (metric == null) {
            return 0;
        }
        if (state(metric).equals("NOT_APPLICABLE")) {
            return 0;
        }
        if (metric.checks() != null && !metric.checks().isEmpty()) {
            return (int) metric.checks().stream()
                    .filter(this::evaluatedCustomerCheck)
                    .count();
        }
        return Math.max(metric.totalChecks(), 0);
    }

    private int passedCheckCount(RuntimeEvidenceMetricResult metric) {
        if (metric == null) {
            return 0;
        }
        if (state(metric).equals("NOT_APPLICABLE")) {
            return 0;
        }
        if (passed(metric)) {
            return totalCheckCount(metric);
        }
        if (metric.checks() != null && !metric.checks().isEmpty()) {
            return (int) metric.checks().stream()
                    .filter(check -> check != null && evaluatedCustomerCheck(check) && check.pass())
                    .count();
        }
        return Math.max(metric.passedChecks(), 0);
    }

    private boolean notApplicableCheck(RuntimeEvidenceCheckResult check) {
        return check != null && "NOT_APPLICABLE".equalsIgnoreCase(safe(check.purposeResult()));
    }

    private boolean evaluatedCustomerCheck(RuntimeEvidenceCheckResult check) {
        return check != null
                && !notApplicableCheck(check)
                && !"INTERNAL_REFERENCE".equalsIgnoreCase(safe(check.readinessScope()));
    }

    private boolean internalGateMetric(String metricCode) {
        return switch (normalize(metricCode)) {
            case "MTR", "RPI", "PRE" -> true;
            default -> false;
        };
    }

    private String state(RuntimeEvidenceMetricResult metric) {
        return metric == null || metric.state() == null ? "" : metric.state().trim().toUpperCase(Locale.ROOT);
    }

    private Map<String, String> issueIdsByMetric(List<PromptQualityIssue> issues) {
        if (issues == null || issues.isEmpty()) {
            return Map.of();
        }
        Map<String, String> result = new LinkedHashMap<>();
        for (PromptQualityIssue issue : issues) {
            if (issue == null || !StringUtils.hasText(issue.issueId())) {
                continue;
            }
            String metricCode = normalize(issue.relatedMetricCode());
            if (StringUtils.hasText(metricCode)) {
                result.putIfAbsent(metricCode, issue.issueId());
            }
        }
        return Map.copyOf(result);
    }

    private String requestFact(SealedEvidencePackage evidencePackage, String key) {
        if (evidencePackage == null || !StringUtils.hasText(evidencePackage.getRequestFactsJson())) {
            return "";
        }
        try {
            Map<String, Object> facts = objectMapper.readValue(evidencePackage.getRequestFactsJson(), MAP_TYPE);
            Object value = facts.get(key);
            return value == null ? "" : String.valueOf(value);
        } catch (Exception ignored) {
            return "";
        }
    }

    private Map<String, Object> jsonMap(String json) {
        if (!StringUtils.hasText(json)) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, MAP_TYPE);
        } catch (Exception ignored) {
            return Map.of();
        }
    }

    private String writeJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value == null ? Map.of() : value);
        } catch (Exception ignored) {
            return "{}";
        }
    }

    private List<String> jsonStringList(String value) {
        if (!StringUtils.hasText(value)) {
            return List.of();
        }
        try {
            List<?> raw = objectMapper.readValue(value, List.class);
            List<String> result = new ArrayList<>();
            for (Object item : raw) {
                if (item == null) {
                    continue;
                }
                String text = item instanceof String string
                        ? string
                        : objectMapper.writeValueAsString(item);
                if (StringUtils.hasText(text)) {
                    result.add(text.trim());
                }
            }
            return List.copyOf(result);
        } catch (Exception ignored) {
            return List.of(value.trim());
        }
    }

    private String validJsonArrayOrEmpty(String value) {
        if (!StringUtils.hasText(value)) {
            return "[]";
        }
        try {
            Object parsed = objectMapper.readValue(value, Object.class);
            if (parsed instanceof List<?>) {
                return objectMapper.writeValueAsString(parsed);
            }
            return "[]";
        } catch (Exception ignored) {
            return "[]";
        }
    }

    private String preview(String value, int maxLength) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        int limit = Math.max(16, maxLength);
        String normalized = value.trim().replaceAll("\\s+", " ");
        return normalized.length() <= limit ? normalized : normalized.substring(0, limit - 3) + "...";
    }

    private String sha256Prefixed(String value) {
        if (value == null) {
            return null;
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return "sha256:" + HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 digest is not available.", exception);
        }
    }

    private OperatorRunBatch batch(ResultSet rs, int rowNum) throws SQLException {
        return new OperatorRunBatch(
                rs.getString("aggregate_run_id"),
                rs.getString("package_id"),
                rs.getString("certificate_id"),
                rs.getString("case_id"),
                rs.getString("scope_type"),
                rs.getInt("expected_metric_count"),
                rs.getInt("actual_metric_count"),
                rs.getInt("passed_metric_count"),
                rs.getInt("failed_metric_count"),
                rs.getInt("insufficient_metric_count"),
                rs.getInt("not_applicable_metric_count"),
                rs.getString("final_decision"),
                rs.getBoolean("blocked"),
                rs.getString("block_reason_summary"),
                rs.getString("prompt_hash"),
                rs.getString("context_hash"),
                rs.getString("context_hash_state"),
                rs.getString("template_resource_id"),
                rs.getString("actual_resource_id"),
                rs.getString("resource_url_template"),
                rs.getString("actual_request_path"),
                rs.getString("http_method"),
                rs.getString("diagnostic_catalog_version"),
                instant(rs.getTimestamp("created_at")));
    }

    private OperatorMetricSnapshot metricSnapshot(ResultSet rs, int rowNum) throws SQLException {
        return new OperatorMetricSnapshot(
                rs.getString("aggregate_run_id"),
                rs.getString("official_run_id"),
                rs.getString("package_id"),
                rs.getString("certificate_id"),
                rs.getString("case_id"),
                rs.getString("metric_code"),
                rs.getString("metric_name"),
                rs.getString("metric_group"),
                rs.getDouble("score"),
                rs.getString("state"),
                rs.getString("severity"),
                rs.getInt("passed_checks"),
                rs.getInt("total_checks"),
                rs.getInt("failed_check_count"),
                rs.getString("operator_title"),
                rs.getString("operator_summary"),
                rs.getString("primary_failure_reason"),
                rs.getString("remediation_owner"),
                rs.getString("next_action"),
                rs.getString("reverify_criterion"),
                rs.getString("diagnostic_catalog_version"),
                instant(rs.getTimestamp("created_at")));
    }

    private OperatorFinding finding(ResultSet rs, int rowNum) throws SQLException {
        return new OperatorFinding(
                rs.getString("finding_id"),
                rs.getString("aggregate_run_id"),
                rs.getString("official_run_id"),
                rs.getString("package_id"),
                rs.getString("certificate_id"),
                rs.getString("case_id"),
                rs.getString("issue_id"),
                rs.getString("metric_code"),
                rs.getString("check_code"),
                rs.getString("severity"),
                rs.getString("operator_title"),
                rs.getString("operator_summary"),
                rs.getString("problem_statement"),
                rs.getString("root_cause"),
                rs.getString("affected_target"),
                rs.getString("operator_reason"),
                rs.getString("evidence_summary"),
                rs.getString("evidence_path"),
                rs.getString("expected_value"),
                rs.getString("actual_value"),
                rs.getString("expected_result"),
                rs.getString("actual_result"),
                rs.getString("impact"),
                rs.getString("remediation_owner"),
                rs.getString("next_action"),
                rs.getString("reverify_criterion"),
                rs.getString("customer_visible_severity"),
                rs.getString("related_process_step"),
                rs.getString("comparison_field_key"),
                rs.getString("comparison_state"),
                rs.getString("prompt_location"),
                rs.getString("diagnostic_catalog_version"),
                instant(rs.getTimestamp("created_at")));
    }

    private OperatorRemediationGroup remediationGroup(ResultSet rs, int rowNum) throws SQLException {
        return new OperatorRemediationGroup(
                rs.getString("group_id"),
                rs.getString("aggregate_run_id"),
                rs.getString("package_id"),
                rs.getString("certificate_id"),
                rs.getString("case_id"),
                rs.getString("root_cause_key"),
                rs.getString("remediation_owner"),
                rs.getString("operator_title"),
                rs.getString("operator_reason"),
                rs.getString("next_action"),
                rs.getString("reverify_criterion"),
                splitCsv(rs.getString("affected_metric_codes")),
                splitCsv(rs.getString("affected_check_codes")),
                rs.getInt("finding_count"),
                rs.getString("related_process_step"),
                splitCsv(rs.getString("comparison_field_keys")),
                splitCsv(rs.getString("prompt_locations")),
                rs.getString("diagnostic_catalog_version"),
                instant(rs.getTimestamp("created_at")));
    }

    private OfficialVerificationPromptComparison promptComparison(ResultSet rs, int rowNum) throws SQLException {
        return new OfficialVerificationPromptComparison(
                rs.getString("field_key"),
                rs.getString("field_label"),
                rs.getString("sealed_evidence_value"),
                rs.getString("prompt_value"),
                rs.getString("official_fact_value"),
                rs.getString("state"),
                rs.getString("state_label"),
                rs.getString("meaning"),
                splitCsv(rs.getString("related_metric_codes")),
                splitCsv(rs.getString("related_check_codes")),
                splitCsv(rs.getString("related_finding_ids")),
                splitCsv(rs.getString("related_issue_ids")),
                splitCsv(rs.getString("related_remediation_group_ids")),
                rs.getString("prompt_location"),
                rs.getString("evidence_source"),
                rs.getString("recommended_owner"),
                rs.getString("canonical_source"));
    }

    private OfficialActualPromptProblem storedActualPromptProblem(ResultSet rs, int rowNum) throws SQLException {
        return new OfficialActualPromptProblem(
                rs.getString("problem_id"),
                rs.getString("package_id"),
                rs.getString("aggregate_run_id"),
                rs.getString("field_key"),
                rs.getString("problem_type"),
                rs.getString("prompt_section"),
                rs.getString("prompt_label"),
                rs.getString("prompt_value"),
                rs.getString("source_field_path"),
                rs.getString("sealed_evidence_path"),
                rs.getString("expected_state"),
                rs.getString("actual_state"),
                rs.getString("severity"),
                splitCsv(rs.getString("affected_metric_codes")),
                rs.getString("remediation_owner"),
                rs.getString("quality_question"),
                rs.getString("why_it_matters"),
                rs.getString("fix_action"),
                rs.getString("reverify_criterion_detail"),
                splitCustomerDisplayJsonArray(rs.getString("runtime_facts_json"), "runtimeFacts"),
                splitCustomerDisplayJsonArray(rs.getString("context_items_json"), "contextItems"));
    }

    private OperatorPurposeEvidence purposeEvidenceRow(ResultSet rs, int rowNum) throws SQLException {
        return new OperatorPurposeEvidence(
                rs.getString("aggregate_run_id"),
                rs.getString("package_id"),
                rs.getString("metric_code"),
                rs.getString("check_code"),
                rs.getString("contract_version"),
                rs.getString("signal_key"),
                rs.getString("prompt_location"),
                rs.getString("evidence_value"),
                rs.getString("evidence_hash"),
                rs.getString("interpretation"),
                rs.getString("purpose_result"),
                rs.getBoolean("customer_visible"),
                rs.getString("readiness_scope"),
                splitCustomerDisplayJsonArray(rs.getString("runtime_facts_json"), "runtimeFacts"),
                splitCustomerDisplayJsonArray(rs.getString("context_items_json"), "contextItems"),
                instant(rs.getTimestamp("created_at")));
    }

    private OperatorAuditSnapshot auditSnapshot(ResultSet rs, int rowNum) throws SQLException {
        return new OperatorAuditSnapshot(
                rs.getString("snapshot_id"),
                rs.getString("aggregate_run_id"),
                rs.getString("package_id"),
                rs.getString("certificate_id"),
                rs.getString("case_id"),
                rs.getString("state"),
                rs.getString("state_label"),
                rs.getInt("total_metric_count"),
                rs.getInt("failed_metric_count"),
                rs.getBoolean("certificate_issued"),
                rs.getString("prompt_hash"),
                rs.getString("context_hash"),
                splitJsonArray(rs.getString("blocking_findings_json")),
                splitJsonArray(rs.getString("next_actions_json")),
                rs.getString("payload_json"),
                rs.getString("created_by"),
                rs.getString("diagnostic_catalog_version"),
                instant(rs.getTimestamp("created_at")));
    }

    private OperatorReverificationResult reverificationResult(ResultSet rs, int rowNum) throws SQLException {
        return new OperatorReverificationResult(
                rs.getString("result_id"),
                rs.getString("source_package_id"),
                rs.getString("source_aggregate_run_id"),
                rs.getString("fixed_package_id"),
                rs.getString("fixed_aggregate_run_id"),
                rs.getString("source_finding_id"),
                rs.getString("issue_id"),
                rs.getString("metric_code"),
                rs.getString("check_code"),
                rs.getString("reverify_criterion"),
                rs.getString("source_operator_reason"),
                rs.getString("source_expected_value"),
                rs.getString("source_actual_value"),
                rs.getString("fixed_actual_value"),
                rs.getBoolean("resolved"),
                rs.getString("resolution_state"),
                rs.getString("operator_summary"),
                rs.getString("created_by"),
                rs.getString("diagnostic_catalog_version"),
                instant(rs.getTimestamp("created_at")));
    }

    private String safe(String value) {
        return safe(value, "");
    }

    private String safe(String value, String fallback) {
        return StringUtils.hasText(value) ? value.trim() : fallback;
    }

    private Map<String, Object> parseJson(String json) {
        if (!StringUtils.hasText(json)) {
            return Map.of();
        }
        try {
            Map<String, Object> parsed = objectMapper.readValue(json, MAP_TYPE);
            return parsed == null ? Map.of() : parsed;
        }
        catch (Exception ignored) {
            return Map.of();
        }
    }

    private String stringValue(Object value) {
        return value == null ? "" : String.valueOf(value).trim();
    }

    private String defaultText(Object value, String fallback) {
        String text = stringValue(value);
        return StringUtils.hasText(text) ? text : fallback;
    }

    private String sourcePackage(String sourceClass) {
        if (!StringUtils.hasText(sourceClass)) {
            return null;
        }
        int lastDot = sourceClass.lastIndexOf('.');
        return lastDot > 0 ? sourceClass.substring(0, lastDot) : null;
    }

    private List<String> objectStringList(Object value) {
        if (value instanceof List<?> list) {
            return list.stream()
                    .map(this::stringValue)
                    .filter(StringUtils::hasText)
                    .distinct()
                    .toList();
        }
        if (value instanceof String text && StringUtils.hasText(text)) {
            return splitCsv(text);
        }
        return List.of();
    }

    private Integer intValue(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String text && StringUtils.hasText(text)) {
            try {
                return Integer.parseInt(text.trim());
            }
            catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private boolean booleanValue(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        return value instanceof String text && Boolean.parseBoolean(text.trim());
    }

    private Boolean nullableBoolean(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        if (value instanceof String text && StringUtils.hasText(text)) {
            return Boolean.parseBoolean(text.trim());
        }
        return null;
    }

    private String customerText(String fieldName, String value) {
        String text = conciseCustomerText(value, customerTextMaxLength(fieldName));
        if (normalize(fieldName).contains("OWNER")
                && OfficialPromptQualityNarrativeCatalog.containsBrokenText(text)) {
            text = "Official verification process";
        }
        if (OfficialPromptQualityNarrativeCatalog.containsBrokenText(text)) {
            return "";
        }
        return PromptQualityCustomerSentencePolicy.requireCustomerSentence(
                fieldName,
                text);
    }

    private String customerTextOrBlank(String fieldName, String value) {
        if (!StringUtils.hasText(value)) {
            return "";
        }
        String text = conciseCustomerText(value, customerTextMaxLength(fieldName));
        if (normalize(fieldName).contains("OWNER")
                && OfficialPromptQualityNarrativeCatalog.containsBrokenText(text)) {
            text = "Official verification process";
        }
        if (OfficialPromptQualityNarrativeCatalog.containsBrokenText(text)) {
            return "";
        }
        return PromptQualityCustomerSentencePolicy.requireCustomerSentence(
                fieldName,
                text);
    }

    private int customerTextMaxLength(String fieldName) {
        String normalized = normalize(fieldName);
        if (normalized.contains("TITLE") || normalized.contains("OWNER") || normalized.contains("SEVERITY")) {
            return CUSTOMER_OPERATOR_TITLE_MAX;
        }
        return CUSTOMER_OPERATOR_TEXT_MAX;
    }

    private String conciseCustomerText(String value, int maxLength) {
        if (!StringUtils.hasText(value)) {
            return value;
        }
        String cleaned = value.trim().replaceAll("\\s+", " ").trim();
        if (cleaned.length() <= maxLength) {
            return cleaned;
        }
        int sentenceEnd = cleaned.lastIndexOf('.', maxLength - 1);
        if (sentenceEnd >= Math.max(80, maxLength / 2)) {
            return cleaned.substring(0, sentenceEnd + 1).trim();
        }
        return cleaned.substring(0, Math.max(1, maxLength)).trim();
    }

    private List<String> auditCustomerSentences(String fieldName, List<String> values, boolean blockingFinding) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        int index = 0;
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                result.add(PromptQualityCustomerSentencePolicy.requireCustomerSentence(
                        fieldName + "[" + index + "]",
                        auditCustomerSentence(value, blockingFinding)));
            }
            index++;
        }
        return List.copyOf(result);
    }

    private String auditCustomerSentence(String value, boolean blockingFinding) {
        String candidate = value == null ? "" : value.trim();
        if (PromptQualityCustomerSentencePolicy.isCustomerSentence(candidate)) {
            return conciseCustomerText(candidate, CUSTOMER_OPERATOR_TEXT_MAX);
        }
        throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Audit snapshot sentence is not DB-contract backed. "
                + "fieldValue=" + safe(candidate));
    }

    private String auditMetricName(String value) {
        String normalized = normalize(value);
        for (String code : List.of("EIR", "CCR", "CCSR", "PFR", "MTR", "COR", "RAP", "RPI", "BMA", "USNS", "BSR", "PRE")) {
            if (normalized.matches("(?s).*\\b" + code + "\\b.*")) {
                return narrativeCatalog.metricName(code) + " metric";
            }
        }
        if (normalized.contains("PROMPT")) {
            return "Evidence and prompt alignment";
        }
        if (normalized.contains("PROTECTABLE") || value.contains("@Protectable")) {
            return "Protectable resource eligibility";
        }
        return "Official verification metric";
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

    private String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private boolean hasHangul(String value) {
        if (value == null) {
            return false;
        }
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch >= 0xAC00 && ch <= 0xD7A3) {
                return true;
            }
        }
        return false;
    }

    private String fit(String value, int maxLength) {
        if (!StringUtils.hasText(value) || maxLength <= 0) {
            return value;
        }
        String trimmed = value.trim();
        return trimmed.length() <= maxLength ? trimmed : trimmed.substring(0, maxLength);
    }

    private List<String> splitCsv(String value) {
        if (!StringUtils.hasText(value)) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        for (String part : value.split(",")) {
            if (StringUtils.hasText(part)) {
                result.add(part.trim());
            }
        }
        return List.copyOf(result);
    }

    private List<String> splitJsonArray(String value) {
        if (!StringUtils.hasText(value)) {
            return List.of();
        }
        try {
            List<?> raw = objectMapper.readValue(value, List.class);
            List<String> result = new ArrayList<>();
            for (Object item : raw) {
                if (item != null && StringUtils.hasText(String.valueOf(item))) {
                    result.add(String.valueOf(item).trim());
                }
            }
            return List.copyOf(result);
        } catch (Exception ignored) {
            return List.of(value);
        }
    }

    private List<String> splitCustomerDisplayJsonArray(String value, String nestedKey) {
        if (!StringUtils.hasText(value)) {
            return List.of();
        }
        try {
            List<?> raw = objectMapper.readValue(value, List.class);
            List<String> result = new ArrayList<>();
            boolean runtimeFacts = "runtimeFacts".equals(nestedKey);
            for (Object item : raw) {
                if (item instanceof String text) {
                    appendCustomerDisplayItems(result, text, runtimeFacts);
                } else if (item instanceof Map<?, ?> map) {
                    Object nested = map.get(nestedKey);
                    if (nested != null) {
                        result.addAll(customerPurposeDisplayItems(nested, runtimeFacts));
                    }
                }
            }
            return List.copyOf(result);
        } catch (Exception ignored) {
            return List.of();
        }
    }

    private void appendUnique(List<String> values, String value) {
        if (StringUtils.hasText(value) && !values.contains(value.trim())) {
            values.add(value.trim());
        }
    }

    private List<String> merged(List<String> left, List<String> right) {
        List<String> result = new ArrayList<>();
        if (left != null) {
            for (String value : left) {
                appendUnique(result, value);
            }
        }
        if (right != null) {
            for (String value : right) {
                appendUnique(result, value);
            }
        }
        return List.copyOf(result);
    }

    private String placeholders(List<String> values) {
        return values.stream().map(ignored -> "?").collect(Collectors.joining(", "));
    }

    private String databaseMessage(DataAccessException ex) {
        Throwable cause = ex.getMostSpecificCause();
        return cause == null || !StringUtils.hasText(cause.getMessage()) ? ex.getMessage() : cause.getMessage();
    }

    private String diagnosticCatalogVersion() {
        return DIAGNOSTIC_CATALOG_VERSION;
    }

    private Instant instant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }

    private Timestamp nowTimestamp() {
        return Timestamp.from(Instant.now());
    }

    private record MetricInputRequirement(
            String inputKey,
            String requiredPolicy,
            String absencePolicy) {
    }

    private record CustomerPurposeEvidenceDisplay(
            String signalKey,
            String evidenceValue,
            List<String> runtimeFacts,
            List<String> contextItems,
            boolean structured) {
        CustomerPurposeEvidenceDisplay(String signalKey, String evidenceValue) {
            this(signalKey, evidenceValue, List.of(), List.of(), false);
        }

        CustomerPurposeEvidenceDisplay {
            runtimeFacts = runtimeFacts == null ? List.of() : List.copyOf(runtimeFacts);
            contextItems = contextItems == null ? List.of() : List.copyOf(contextItems);
        }
    }

    public record OperatorSnapshot(
            OperatorRunBatch batch,
            List<OperatorMetricSnapshot> metrics,
            List<OperatorFinding> findings,
            List<OperatorRemediationGroup> remediationGroups,
            List<OfficialActualPromptProblem> actualPromptProblems,
            List<OperatorPurposeEvidence> purposeEvidence,
            List<OperatorAuditSnapshot> auditSnapshots) {
        public OperatorSnapshot(
                OperatorRunBatch batch,
                List<OperatorMetricSnapshot> metrics,
                List<OperatorFinding> findings,
                List<OperatorRemediationGroup> remediationGroups,
                List<OperatorAuditSnapshot> auditSnapshots) {
            this(batch, metrics, findings, remediationGroups, List.of(), List.of(), auditSnapshots);
        }

        public static OperatorSnapshot empty() {
            return new OperatorSnapshot(null, List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
        }

        public boolean available() {
            return batch != null;
        }
    }

    public record OperatorRunBatch(
            String aggregateRunId,
            String packageId,
            String certificateId,
            String caseId,
            String scopeType,
            int expectedMetricCount,
            int actualMetricCount,
            int passedMetricCount,
            int failedMetricCount,
            int insufficientMetricCount,
            int notApplicableMetricCount,
            String finalDecision,
            boolean blocked,
            String blockReasonSummary,
            String promptHash,
            String contextHash,
            String contextHashState,
            String templateResourceId,
            String actualResourceId,
            String resourceUrlTemplate,
            String actualRequestPath,
            String httpMethod,
            String diagnosticCatalogVersion,
            Instant createdAt) {
        public OperatorRunBatch(
                String aggregateRunId,
                String packageId,
                String certificateId,
                String caseId,
                String scopeType,
                int expectedMetricCount,
                int actualMetricCount,
                int passedMetricCount,
                int failedMetricCount,
                int insufficientMetricCount,
                int notApplicableMetricCount,
                String finalDecision,
                boolean blocked,
                String blockReasonSummary,
                String promptHash,
                String contextHash,
                String contextHashState,
                String templateResourceId,
                String actualResourceId,
                String resourceUrlTemplate,
                String actualRequestPath,
                String httpMethod,
                Instant createdAt) {
            this(
                    aggregateRunId,
                    packageId,
                    certificateId,
                    caseId,
                    scopeType,
                    expectedMetricCount,
                    actualMetricCount,
                    passedMetricCount,
                    failedMetricCount,
                    insufficientMetricCount,
                    notApplicableMetricCount,
                    finalDecision,
                    blocked,
                    blockReasonSummary,
                    promptHash,
                    contextHash,
                    contextHashState,
                    templateResourceId,
                    actualResourceId,
                    resourceUrlTemplate,
                    actualRequestPath,
                    httpMethod,
                    OfficialPromptQualityNarrativeCatalog.CATALOG_VERSION,
                    createdAt);
        }
    }

    public record OperatorMetricSnapshot(
            String aggregateRunId,
            String officialRunId,
            String packageId,
            String certificateId,
            String caseId,
            String metricCode,
            String metricName,
            String metricGroup,
            double score,
            String state,
            String severity,
            int passedChecks,
            int totalChecks,
            int failedCheckCount,
            String operatorTitle,
            String operatorSummary,
            String primaryFailureReason,
            String remediationOwner,
            String nextAction,
            String reverifyCriterion,
            String diagnosticCatalogVersion,
            Instant createdAt) {
        public OperatorMetricSnapshot(
                String aggregateRunId,
                String officialRunId,
                String packageId,
                String certificateId,
                String caseId,
                String metricCode,
                String metricName,
                String metricGroup,
                double score,
                String state,
                String severity,
                int passedChecks,
                int totalChecks,
                int failedCheckCount,
                String operatorTitle,
                String operatorSummary,
                String primaryFailureReason,
                String remediationOwner,
                String nextAction,
                String reverifyCriterion,
                Instant createdAt) {
            this(
                    aggregateRunId,
                    officialRunId,
                    packageId,
                    certificateId,
                    caseId,
                    metricCode,
                    metricName,
                    metricGroup,
                    score,
                    state,
                    severity,
                    passedChecks,
                    totalChecks,
                    failedCheckCount,
                    operatorTitle,
                    operatorSummary,
                    primaryFailureReason,
                    remediationOwner,
                    nextAction,
                    reverifyCriterion,
                    OfficialPromptQualityNarrativeCatalog.CATALOG_VERSION,
                    createdAt);
        }
    }

    public record OperatorPurposeEvidence(
            String aggregateRunId,
            String packageId,
            String metricCode,
            String checkCode,
            String contractVersion,
            String signalKey,
            String promptLocation,
            String evidenceValue,
            String evidenceHash,
            String interpretation,
            String purposeResult,
            boolean customerVisible,
            String readinessScope,
            List<String> runtimeFacts,
            List<String> contextItems,
            Instant createdAt) {
        public OperatorPurposeEvidence {
            runtimeFacts = runtimeFacts == null ? List.of() : List.copyOf(runtimeFacts);
            contextItems = contextItems == null ? List.of() : List.copyOf(contextItems);
        }
    }

    public record OperatorFinding(
            String findingId,
            String aggregateRunId,
            String officialRunId,
            String packageId,
            String certificateId,
            String caseId,
            String issueId,
            String metricCode,
            String checkCode,
            String severity,
            String operatorTitle,
            String operatorSummary,
            String problemStatement,
            String rootCause,
            String affectedTarget,
            String operatorReason,
            String evidenceSummary,
            String evidencePath,
            String expectedValue,
            String actualValue,
            String expectedResult,
            String actualResult,
            String impact,
            String remediationOwner,
            String nextAction,
            String reverifyCriterion,
            String customerVisibleSeverity,
            String relatedProcessStep,
            String comparisonFieldKey,
            String comparisonState,
            String promptLocation,
            String diagnosticCatalogVersion,
            Instant createdAt) {
        public OperatorFinding(
                String findingId,
                String aggregateRunId,
                String officialRunId,
                String packageId,
                String certificateId,
                String caseId,
                String issueId,
                String metricCode,
                String checkCode,
                String severity,
                String operatorTitle,
                String operatorSummary,
                String problemStatement,
                String rootCause,
                String affectedTarget,
                String operatorReason,
                String evidenceSummary,
                String evidencePath,
                String expectedValue,
                String actualValue,
                String expectedResult,
                String actualResult,
                String impact,
                String remediationOwner,
                String nextAction,
                String reverifyCriterion,
                String customerVisibleSeverity,
                String relatedProcessStep,
                Instant createdAt) {
            this(
                    findingId,
                    aggregateRunId,
                    officialRunId,
                    packageId,
                    certificateId,
                    caseId,
                    issueId,
                    metricCode,
                    checkCode,
                    severity,
                    operatorTitle,
                    operatorSummary,
                    problemStatement,
                    rootCause,
                    affectedTarget,
                    operatorReason,
                    evidenceSummary,
                    evidencePath,
                    expectedValue,
                    actualValue,
                    expectedResult,
                    actualResult,
                    impact,
                    remediationOwner,
                    nextAction,
                    reverifyCriterion,
                    customerVisibleSeverity,
                    relatedProcessStep,
                    "",
                    "",
                    "",
                    OfficialPromptQualityNarrativeCatalog.CATALOG_VERSION,
                    createdAt);
        }

        public OperatorFinding(
                String findingId,
                String aggregateRunId,
                String officialRunId,
                String packageId,
                String certificateId,
                String caseId,
                String issueId,
                String metricCode,
                String checkCode,
                String severity,
                String operatorTitle,
                String operatorReason,
                String evidenceSummary,
                String evidencePath,
                String expectedValue,
                String actualValue,
                String impact,
                String remediationOwner,
                String nextAction,
                String reverifyCriterion,
                String relatedProcessStep,
                Instant createdAt) {
            this(
                    findingId,
                    aggregateRunId,
                    officialRunId,
                    packageId,
                    certificateId,
                    caseId,
                    issueId,
                    metricCode,
                    checkCode,
                    severity,
                    operatorTitle,
                    operatorReason,
                    operatorReason,
                    operatorReason,
                    remediationOwner,
                    operatorReason,
                    evidenceSummary,
                    evidencePath,
                    expectedValue,
                    actualValue,
                    expectedValue,
                    actualValue,
                    impact,
                    remediationOwner,
                    nextAction,
                    reverifyCriterion,
                    severity,
                    relatedProcessStep,
                    "",
                    "",
                    "",
                    OfficialPromptQualityNarrativeCatalog.CATALOG_VERSION,
                    createdAt);
        }
    }

    public record OperatorRemediationGroup(
            String groupId,
            String aggregateRunId,
            String packageId,
            String certificateId,
            String caseId,
            String rootCauseKey,
            String remediationOwner,
            String operatorTitle,
            String operatorReason,
            String nextAction,
            String reverifyCriterion,
            List<String> affectedMetricCodes,
            List<String> affectedCheckCodes,
            int findingCount,
            String relatedProcessStep,
            List<String> comparisonFieldKeys,
            List<String> promptLocations,
            String diagnosticCatalogVersion,
            Instant createdAt) {
        public OperatorRemediationGroup {
            affectedMetricCodes = affectedMetricCodes == null ? List.of() : List.copyOf(affectedMetricCodes);
            affectedCheckCodes = affectedCheckCodes == null ? List.of() : List.copyOf(affectedCheckCodes);
            comparisonFieldKeys = comparisonFieldKeys == null ? List.of() : List.copyOf(comparisonFieldKeys);
            promptLocations = promptLocations == null ? List.of() : List.copyOf(promptLocations);
        }

        public OperatorRemediationGroup(
                String groupId,
                String aggregateRunId,
                String packageId,
                String certificateId,
                String caseId,
                String rootCauseKey,
                String remediationOwner,
                String operatorTitle,
                String operatorReason,
                String nextAction,
                String reverifyCriterion,
                List<String> affectedMetricCodes,
                List<String> affectedCheckCodes,
                int findingCount,
                String relatedProcessStep,
                Instant createdAt) {
            this(
                    groupId,
                    aggregateRunId,
                    packageId,
                    certificateId,
                    caseId,
                    rootCauseKey,
                    remediationOwner,
                    operatorTitle,
                    operatorReason,
                    nextAction,
                    reverifyCriterion,
                    affectedMetricCodes,
                    affectedCheckCodes,
                    findingCount,
                    relatedProcessStep,
                    List.of(),
                    List.of(),
                    OfficialPromptQualityNarrativeCatalog.CATALOG_VERSION,
                    createdAt);
        }
    }

    public record OperatorAuditSnapshot(
            String snapshotId,
            String aggregateRunId,
            String packageId,
            String certificateId,
            String caseId,
            String state,
            String stateLabel,
            int totalMetricCount,
            int failedMetricCount,
            boolean certificateIssued,
            String promptHash,
            String contextHash,
            List<String> blockingFindings,
            List<String> nextActions,
            String payloadJson,
            String createdBy,
            String diagnosticCatalogVersion,
            Instant createdAt) {
        public OperatorAuditSnapshot {
            blockingFindings = blockingFindings == null ? List.of() : List.copyOf(blockingFindings);
            nextActions = nextActions == null ? List.of() : List.copyOf(nextActions);
        }

        public OperatorAuditSnapshot(
                String snapshotId,
                String aggregateRunId,
                String packageId,
                String certificateId,
                String caseId,
                String state,
                String stateLabel,
                int totalMetricCount,
                int failedMetricCount,
                boolean certificateIssued,
                String promptHash,
                String contextHash,
                List<String> blockingFindings,
                List<String> nextActions,
                String payloadJson,
                String createdBy,
                Instant createdAt) {
            this(
                    snapshotId,
                    aggregateRunId,
                    packageId,
                    certificateId,
                    caseId,
                    state,
                    stateLabel,
                    totalMetricCount,
                    failedMetricCount,
                    certificateIssued,
                    promptHash,
                    contextHash,
                    blockingFindings,
                    nextActions,
                    payloadJson,
                    createdBy,
                    OfficialPromptQualityNarrativeCatalog.CATALOG_VERSION,
                    createdAt);
        }
    }

    public record OperatorReverificationResult(
            String resultId,
            String sourcePackageId,
            String sourceAggregateRunId,
            String fixedPackageId,
            String fixedAggregateRunId,
            String sourceFindingId,
            String issueId,
            String metricCode,
            String checkCode,
            String reverifyCriterion,
            String sourceOperatorReason,
            String sourceExpectedValue,
            String sourceActualValue,
            String fixedActualValue,
            boolean resolved,
            String resolutionState,
            String operatorSummary,
            String createdBy,
            String diagnosticCatalogVersion,
            Instant createdAt) {
        public OperatorReverificationResult(
                String resultId,
                String sourcePackageId,
                String sourceAggregateRunId,
                String fixedPackageId,
                String fixedAggregateRunId,
                String sourceFindingId,
                String issueId,
                String metricCode,
                String checkCode,
                String reverifyCriterion,
                String sourceOperatorReason,
                String sourceExpectedValue,
                String sourceActualValue,
                String fixedActualValue,
                boolean resolved,
                String resolutionState,
                String operatorSummary,
                String createdBy,
                Instant createdAt) {
            this(
                    resultId,
                    sourcePackageId,
                    sourceAggregateRunId,
                    fixedPackageId,
                    fixedAggregateRunId,
                    sourceFindingId,
                    issueId,
                    metricCode,
                    checkCode,
                    reverifyCriterion,
                    sourceOperatorReason,
                    sourceExpectedValue,
                    sourceActualValue,
                    fixedActualValue,
                    resolved,
                    resolutionState,
                    operatorSummary,
                    createdBy,
                    OfficialPromptQualityNarrativeCatalog.CATALOG_VERSION,
                    createdAt);
        }
    }

    private record CheckDefinitionLink(
            String fieldKey,
            String promptLocation,
            String relatedProcessStep) {
    }

    private record ActualPromptProblem(
            String problemId,
            String fieldKey,
            String problemType,
            String promptSection,
            String promptLabel,
            String promptValue,
            String sourceFieldPath,
            String sealedEvidencePath,
            String expectedState,
            String actualState,
            String severity,
            List<String> metricCodes,
            String remediationOwner,
            String qualityQuestion,
            String whyItMatters,
            String fixAction,
            String reverifyCriterion) {
    }

    private final class PromptComparisonLinkAccumulator {
        private final String fieldKey;
        private final List<String> metricCodes = new ArrayList<>();
        private final List<String> checkCodes = new ArrayList<>();
        private final List<String> findingIds = new ArrayList<>();
        private final List<String> issueIds = new ArrayList<>();
        private final List<String> groupIds = new ArrayList<>();
        private OperatorFinding firstFinding;

        private PromptComparisonLinkAccumulator(String fieldKey) {
            this.fieldKey = fieldKey;
        }

        private void addFinding(OperatorFinding finding) {
            if (finding == null) {
                return;
            }
            if (firstFinding == null) {
                firstFinding = finding;
            }
            appendUnique(metricCodes, finding.metricCode());
            appendUnique(checkCodes, finding.checkCode());
            appendUnique(findingIds, finding.findingId());
            appendUnique(issueIds, finding.issueId());
        }

        private void addGroup(OperatorRemediationGroup group) {
            if (group == null) {
                return;
            }
            appendUnique(groupIds, group.groupId());
            for (String metricCode : group.affectedMetricCodes()) {
                appendUnique(metricCodes, metricCode);
            }
            for (String checkCode : group.affectedCheckCodes()) {
                appendUnique(checkCodes, checkCode);
            }
        }

        private String firstOwner() {
            return firstFinding == null ? "" : firstFinding.remediationOwner();
        }
    }

    private final class RemediationGroupAccumulator {
        private final String owner;
        private final String failureType;
        private final String nextAction;
        private final String firstReason;
        private final String firstLabel;
        private final String firstMetricCode;
        private final List<String> metricCodes = new ArrayList<>();
        private final List<String> checkCodes = new ArrayList<>();
        private final List<String> comparisonFieldKeys = new ArrayList<>();
        private final List<String> promptLocations = new ArrayList<>();
        private String reverifyCriterion = "";
        private int findingCount;

        private RemediationGroupAccumulator(String owner, String failureType, String nextAction, ActualPromptProblem firstProblem) {
            this.owner = owner;
            this.failureType = failureType;
            this.nextAction = nextAction;
            this.firstMetricCode = firstProblem == null || firstProblem.metricCodes().isEmpty()
                    ? ""
                    : firstProblem.metricCodes().get(0);
            this.firstReason = firstProblem == null
                    ? ""
                    : actualPromptProblemRootCause(firstProblem);
            this.firstLabel = firstProblem == null
                    ? failureType
                    : actualPromptProblemTitle(firstProblem);
            this.reverifyCriterion = firstProblem == null
                    ? ""
                    : actualPromptProblemReverify(firstProblem);
        }

        private RemediationGroupAccumulator(String owner, String failureType, String nextAction, RuntimeEvidenceCheckResult firstCheck) {
            this.owner = owner;
            this.failureType = failureType;
            this.nextAction = nextAction;
            this.firstMetricCode = safe(firstCheck == null ? "" : firstCheck.metricCode());
            this.firstReason = rootCause(firstMetricCode, firstCheck);
            this.firstLabel = checkLabel(firstMetricCode, firstCheck);
            this.reverifyCriterion = OfficialVerificationOperatorSnapshotService.this.reverifyCriterion(firstMetricCode, firstCheck);
        }

        private void add(String metricCode, String checkCode, RuntimeEvidenceCheckResult check, CheckDefinitionLink definitionLink) {
            appendUnique(metricCodes, safe(metricCode));
            appendUnique(checkCodes, safe(checkCode));
            if (definitionLink != null) {
                appendUnique(comparisonFieldKeys, definitionLink.fieldKey());
                appendUnique(promptLocations, definitionLink.promptLocation());
            }
            if (!StringUtils.hasText(reverifyCriterion) && check != null) {
                reverifyCriterion = safe(check.reverifyCriterion());
            }
            findingCount++;
        }

        private void add(ActualPromptProblem problem) {
            if (problem == null) {
                return;
            }
            for (String metricCode : problem.metricCodes()) {
                appendUnique(metricCodes, metricCode);
            }
            appendUnique(checkCodes, problem.problemId());
            appendUnique(comparisonFieldKeys, problem.fieldKey());
            appendUnique(promptLocations, problem.promptSection());
            findingCount++;
        }

        private String title() {
            if (!StringUtils.hasText(firstLabel)) {
                throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Remediation group is missing contract title. failureType="
                        + safe(failureType));
            }
            return firstLabel.trim();
        }

        private String reason() {
            if (!StringUtils.hasText(firstReason)) {
                throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Remediation group is missing contract reason. failureType="
                        + safe(failureType));
            }
            return firstReason.trim();
        }

        private String metricCodes() {
            return String.join(",", metricCodes);
        }

        private String checkCodes() {
            return String.join(",", checkCodes);
        }

        private String comparisonFieldKeys() {
            return String.join(",", comparisonFieldKeys);
        }

        private String promptLocations() {
            return String.join(",", promptLocations);
        }

        private String reverifyCriterion() {
            return reverifyCriterion;
        }
    }
}
