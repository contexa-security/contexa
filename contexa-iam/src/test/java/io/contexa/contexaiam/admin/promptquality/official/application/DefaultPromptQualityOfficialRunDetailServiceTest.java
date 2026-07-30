package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.common.OfficialMetricPurposeContractWriter;
import io.contexa.contexaiam.testsupport.PromptQualityTestResolvers;
import org.springframework.jdbc.core.JdbcOperations;

import io.contexa.contexacore.verification.metric.OfficialVerificationMetricDefinition;
import io.contexa.contexacore.verification.persistence.VerificationLedgerService;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunRecord;
import io.contexa.contexacore.verification.runtime.OfficialVerificationCheckState;
import io.contexa.contexacore.verification.runtime.sealed.OfficialSealedEvidenceVerificationResult;
import io.contexa.contexacore.verification.runtime.sealed.OfficialSealedEvidenceVerificationRuntime;
import io.contexa.contexacore.verification.runtime.sealed.SealedEvidenceOfficialRunView;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricContractCatalog;
import io.contexa.contexaiam.admin.promptquality.official.application.DefaultPromptQualityOfficialRunDetailService;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunLedgerConsistency;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialMetricPurposeEvidence;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunCheckDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageListItem;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageSummary;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationMetricTrace;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationPromptComparison;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePackageDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePackageSummary;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePromptConsistencyResult;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessCodes;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessEventSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessHistorySnapshot;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessRunService;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessStepSnapshot;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class DefaultPromptQualityOfficialRunDetailServiceTest {

    @Test
    void internalExecutionGateContractDoesNotBecomeCustomerVisible() {
        OfficialFinalPromptMetricContractRegistry registry = new OfficialFinalPromptMetricContractRegistry(
                new ObjectMapper(),
                mock(OfficialMetricPurposeContractWriter.class),
                mock(OfficialVerificationSnapshotQueryService.class));

        assertThat(registry.metric("MTR").checks())
                .isNotEmpty()
                .allSatisfy(check -> {
                    assertThat(check.customerVisible()).isFalse();
                    assertThat(check.readinessScope()).isEqualTo("INTERNAL_EXECUTION_GATE");
                    assertThat(registry.customerDisplayEligible(check)).isFalse();
                });
    }

    @Test
    void notApplicablePurposeEvidenceUsesTheContractNotApplicableMessage() {
        ObjectMapper objectMapper = new ObjectMapper();
        FinalPromptMetricContractCatalog contracts = FinalPromptMetricContractCatalog.load(objectMapper);
        OfficialRunMetricContractView contractView = new OfficialRunMetricContractView(
                mock(PromptQualityOfficialMetricCatalog.class), contracts);
        OfficialVerificationOperatorSnapshotService.OperatorSnapshot base = operatorSnapshot();
        OfficialVerificationOperatorSnapshotService.OperatorPurposeEvidence storedEvidence =
                new OfficialVerificationOperatorSnapshotService.OperatorPurposeEvidence(
                        "agg-001", "pkg-001", "COR",
                        "COR_NO_RAG_CONTEXT_NO_CONTAMINATION_SURFACE",
                        "final-user-prompt.v1", "no_rag_context_no_contamination_surface",
                        "internalGate.ragEvidence.absence", "persisted failure text",
                        "evidence-hash", "RAG branch applicability", "NOT_APPLICABLE",
                        false, "INTERNAL_REFERENCE", List.of(), List.of(),
                        Instant.parse("2026-07-30T00:00:00Z"));
        OfficialVerificationOperatorSnapshotService.OperatorSnapshot snapshot =
                new OfficialVerificationOperatorSnapshotService.OperatorSnapshot(
                        base.batch(), base.metrics(), base.findings(), base.remediationGroups(),
                        base.actualPromptProblems(), List.of(storedEvidence), base.auditSnapshots());

        List<OfficialMetricPurposeEvidence> evidence = contractView.purposeEvidenceForMetric(snapshot, "COR");
        String expected = contracts.check(
                "COR", "COR_NO_RAG_CONTEXT_NO_CONTAMINATION_SURFACE").notApplicableMessage();

        assertThat(evidence).singleElement()
                .extracting(OfficialMetricPurposeEvidence::evidenceValue)
                .isEqualTo(expected);

        OfficialRunMetricEvidenceMapper mapper = new OfficialRunMetricEvidenceMapper(
                contractView, new OfficialRunDetailPresentation(PromptQualityTestResolvers.koreanBundle()));
        assertThat(mapper.mergePurposeEvidenceChecks("COR", List.of(), evidence))
                .singleElement()
                .satisfies(check -> {
                    assertThat(check.evaluationState()).isEqualTo(OfficialVerificationCheckState.NOT_APPLICABLE);
                    assertThat(check.pass()).isFalse();
                    assertThat(check.actualValue()).isEqualTo(expected);
                });
    }

    @Test
    void llmDecisionQualityCheckRemainsVisibleForPreviouslyPersistedPurposeEvidence() {
        PromptQualityMessageResolver messages = PromptQualityTestResolvers.koreanBundle();
        OfficialRunMetricEvidenceMapper mapper = new OfficialRunMetricEvidenceMapper(
                mock(OfficialRunMetricContractView.class),
                new OfficialRunDetailPresentation(messages));
        OfficialRunCheckDetail check = new OfficialRunCheckDetail(
                1, "llm-mutation-case", "Safe mutation boundary",
                "CHALLENGE", "CHALLENGE", false,
                "decision.mutation", "BLOCKING", "GATE_REVIEW", "PQA_RUNTIME",
                "Mutation evidence requires review.", "Review the mutation evidence.",
                "Persisted decision evidence", "Review the mutation evidence.",
                "The same scenario must pass.", "decisionUtility", "Prevents unsafe action changes.");
        OfficialMetricPurposeEvidence legacyEvidence = new OfficialMetricPurposeEvidence(
                "D03", "llm-mutation-case", null, "SAFE_MUTATION_BOUNDARY",
                "decision.mutation", "CHALLENGE->CHALLENGE", null,
                "Mutation evidence requires review.", "PURPOSE_FAILED", false,
                "LLM_DECISION_QUALITY", List.of(), List.of());

        assertThat(mapper.customerVisibleChecks("D03", List.of(check), List.of(legacyEvidence)))
                .containsExactly(check);
    }

    @Test
    void officialCertificateStateUsesItsOwnPresentationContract() {
        OfficialRunDetailPresentation presentation =
                new OfficialRunDetailPresentation(PromptQualityTestResolvers.koreanBundle());

        assertThat(presentation.officialStateLabel("CERTIFIABLE")).isEqualTo("공식검사 통과");
        assertThat(presentation.officialStateLabel("BLOCKED")).isEqualTo("공식검사 차단");
        assertThat(presentation.officialStateLabel("INELIGIBLE")).isEqualTo("검토 필요");
    }

    private DefaultPromptQualityOfficialRunDetailService service(
            OfficialSealedEvidenceVerificationRuntime officialRuntime,
            VerificationLedgerService ledgerService,
            PromptQualityRuntimeEvidenceService evidenceService,
            PromptQualityOfficialMetricCatalog metricCatalog) {
        return service(officialRuntime, ledgerService, evidenceService, metricCatalog,
                processRunService(), operatorSnapshotService());
    }

    private DefaultPromptQualityOfficialRunDetailService service(
            OfficialSealedEvidenceVerificationRuntime officialRuntime,
            VerificationLedgerService ledgerService,
            PromptQualityRuntimeEvidenceService evidenceService,
            PromptQualityOfficialMetricCatalog metricCatalog,
            PromptQualityProcessRunService processRunService) {
        return service(officialRuntime, ledgerService, evidenceService, metricCatalog,
                processRunService, operatorSnapshotService());
    }

    private DefaultPromptQualityOfficialRunDetailService service(
            OfficialSealedEvidenceVerificationRuntime officialRuntime,
            VerificationLedgerService ledgerService,
            PromptQualityRuntimeEvidenceService evidenceService,
            PromptQualityOfficialMetricCatalog metricCatalog,
            OfficialVerificationOperatorSnapshotService operatorSnapshotService) {
        return service(officialRuntime, ledgerService, evidenceService, metricCatalog,
                processRunService(), operatorSnapshotService);
    }

    private DefaultPromptQualityOfficialRunDetailService service(
            OfficialSealedEvidenceVerificationRuntime officialRuntime,
            VerificationLedgerService ledgerService,
            PromptQualityRuntimeEvidenceService evidenceService,
            PromptQualityOfficialMetricCatalog metricCatalog,
            PromptQualityProcessRunService processRunService,
            OfficialVerificationOperatorSnapshotService operatorSnapshotService) {
        PromptQualityMessageResolver messageResolver = PromptQualityTestResolvers.koreanBundle();
        ObjectMapper objectMapper = new ObjectMapper();
        OfficialRunLightweightEvidenceReader evidenceReader = new OfficialRunLightweightEvidenceReader(
                mock(JdbcOperations.class),
                objectMapper,
                mock(RuntimeEvidencePromptConsistencyGate.class),
                evidenceService,
                messageResolver);
        OfficialRunMetricContractView metricContractView = new OfficialRunMetricContractView(
                metricCatalog,
                FinalPromptMetricContractCatalog.load(objectMapper));
        return new DefaultPromptQualityOfficialRunDetailService(
                officialRuntime,
                ledgerService,
                evidenceReader,
                metricContractView,
                messageResolver,
                mock(PromptQualityAssuranceCaseService.class),
                processRunService,
                operatorSnapshotService);
    }

    private PromptQualityProcessRunService processRunService() {
        PromptQualityProcessRunService service = mock(PromptQualityProcessRunService.class);
        when(service.steps(any())).thenReturn(List.of());
        when(service.history(any())).thenReturn(List.of());
        when(service.events(any())).thenReturn(List.of());
        return service;
    }

    private OfficialVerificationOperatorSnapshotService operatorSnapshotService() {
        OfficialVerificationOperatorSnapshotService service = mock(OfficialVerificationOperatorSnapshotService.class);
        when(service.findLatest(any(), any()))
                .thenReturn(OfficialVerificationOperatorSnapshotService.OperatorSnapshot.empty());
        return service;
    }

    @Test
    void p2PromptComparisonModelUsesBacklogContractFieldsInOrder() {
        assertThat(OfficialVerificationPromptComparison.class.getRecordComponents())
                .extracting("name")
                .containsExactly(
                        "fieldKey",
                        "fieldLabel",
                        "sealedEvidenceValue",
                        "promptValue",
                        "officialFactValue",
                        "state",
                        "stateLabel",
                        "meaning",
                        "metricCodes",
                        "checkCodes",
                        "findingIds",
                        "issueIds",
                        "remediationGroupIds",
                        "promptLocation",
                        "evidenceSource",
                        "recommendedOwner",
                        "canonicalSource");
    }

    @Test
    void p3MetricTraceModelUsesBacklogContractFieldsInOrder() {
        assertThat(OfficialVerificationMetricTrace.class.getRecordComponents())
                .extracting("name")
                .containsExactly(
                        "metricCode",
                        "metricName",
                        "groupName",
                        "metricPurpose",
                        "metricQualityQuestion",
                        "officialRunId",
                        "requestId",
                        "requestPath",
                        "state",
                        "stateLabel",
                        "score",
                        "passedChecks",
                        "totalChecks",
                        "processingTimeMs",
                        "startedAt",
                        "completedAt",
                        "checks",
                        "requestFacts",
                        "eventFacts",
                        "promptFacts",
                        "analysisFacts",
                        "events",
                        "rawEvidence",
                        "comparisons",
                        "actualPromptProblems",
                        "failureCauses",
                        "purposeEvidence",
                        "operatorTitle",
                        "operatorSummary",
                        "primaryFailureReason",
                        "remediationOwner",
                        "nextAction",
                        "reverifyCriterion");
    }

    @Test
    void p4LedgerConsistencyModelUsesCoreDbTrustFieldsInOrder() {
        assertThat(OfficialRunLedgerConsistency.class.getRecordComponents())
                .extracting("name")
                .containsExactly(
                        "expectedMetricCount",
                        "actualRunCount",
                        "metricCountMatched",
                        "totalCheckCount",
                        "declaredCheckCount",
                        "storedCheckRowCount",
                        "checkCountMatched",
                        "missingSourceCheckCount",
                        "abstractSourceCheckCount",
                        "rawArtifactRunCount",
                        "factBackedRunCount",
                        "aggregateRunIdPresent",
                        "readyForIssueResolution",
                        "warnings");
    }

    @Test
    void packageDetailModelCarriesPersistedCertificateAndCaseContext() {
        assertThat(OfficialRunPackageDetail.class.getRecordComponents())
                .extracting("name")
                .contains(
                        "caseId",
                        "certificateId",
                        "certificateState",
                        "certificateStateLabel",
                        "certificateIssued",
                        "certificateSummary",
                        "blockingFindings",
                        "attempts",
                        "processSteps",
                        "processHistory",
                        "processEvents",
                        "auditSnapshots");
    }

    @Test
    void p1_04SummaryAndListUseOperatorSnapshotWithoutLoadingRawFactLedger() {
        OfficialSealedEvidenceVerificationRuntime officialRuntime = mock(OfficialSealedEvidenceVerificationRuntime.class);
        VerificationLedgerService ledgerService = mock(VerificationLedgerService.class);
        PromptQualityRuntimeEvidenceService evidenceService = mock(PromptQualityRuntimeEvidenceService.class);
        OfficialVerificationOperatorSnapshotService.OperatorSnapshot snapshot = operatorSnapshot();
        OfficialVerificationOperatorSnapshotService snapshotService = mock(OfficialVerificationOperatorSnapshotService.class);
        when(snapshotService.findLatest(any(), any())).thenReturn(snapshot);
        when(snapshotService.recentSnapshots(anyInt())).thenReturn(List.of(snapshot));
        when(snapshotService.promptComparisons(any(), any())).thenReturn(List.of());
        DefaultPromptQualityOfficialRunDetailService service = service(
                officialRuntime,
                ledgerService,
                evidenceService,
                () -> List.of(),
                snapshotService);

        List<OfficialRunPackageListItem> rows = service.listRecentRunSummaries(10);
        OfficialRunPackageSummary summary = service.findPackageSummary("pkg-001", "agg-001");

        assertThat(rows).singleElement().satisfies(row -> {
            assertThat(row.packageId()).isEqualTo("pkg-001");
            assertThat(row.aggregateRunId()).isEqualTo("agg-001");
            assertThat(row.failedMetricCount()).isEqualTo(1);
            assertThat(row.actualRequestPath()).isEqualTo("/contexa/admin/api/orders/resource-001");
        });
        assertThat(summary.packageId()).isEqualTo("pkg-001");
        assertThat(summary.metrics()).singleElement().satisfies(metric -> {
            assertThat(metric.metricCode()).isEqualTo("EIR");
            assertThat(metric.operatorTitle()).isEqualTo("요청 증거 연결이 부족합니다");
            assertThat(metric.primaryFailureReason()).isEqualTo("봉인 증거와 공식 지표 원장의 연결 근거가 부족합니다.");
        });
        assertThat(summary.failureCauses()).singleElement().satisfies(failure -> {
            assertThat(failure.findingId()).isEqualTo("finding-001");
            assertThat(failure.problemStatement()).isEqualTo("요청 증거가 공식 검사 원장과 완전히 연결되지 않았습니다.");
            assertThat(failure.remediationHint()).isEqualTo("봉인 증거 저장과 공식 지표 실행 원장 연결을 같은 packageId와 aggregateRunId로 고정하십시오.");
        });
        assertThat(summary.remediationGroups()).singleElement()
                .extracting("groupId")
                .isEqualTo("group-001");
        assertThat(service.findFailureDetails("pkg-001", "agg-001")).hasSize(1);
        assertThat(service.findAuditPayloads("pkg-001", "agg-001")).singleElement()
                .satisfies(audit -> assertThat(audit.payloadJson()).contains("\"packageId\":\"pkg-001\""));
        verifyNoInteractions(officialRuntime, ledgerService, evidenceService);
    }

    @Test
    void packageDetailSelectsAggregateAttemptAndExposesProcessAndAuditContext() {
        OfficialSealedEvidenceVerificationRuntime officialRuntime = mock(OfficialSealedEvidenceVerificationRuntime.class);
        VerificationLedgerService ledgerService = mock(VerificationLedgerService.class);
        PromptQualityRuntimeEvidenceService evidenceService = mock(PromptQualityRuntimeEvidenceService.class);
        PromptQualityProcessRunService processRunService = mock(PromptQualityProcessRunService.class);
        PromptQualityOfficialMetricCatalog metricCatalog = () -> List.of(new OfficialVerificationMetricDefinition(
                "EIR",
                "Required Evidence",
                "IMPLEMENTATION_ALIGNMENT",
                "required evidence",
                true,
                1.0d,
                true));
        DefaultPromptQualityOfficialRunDetailService service = service(
                officialRuntime,
                ledgerService,
                evidenceService,
                metricCatalog,
                processRunService);

        SealedEvidenceOfficialRunView oldAttempt = officialRun(
                "run-old-eir",
                "EIR",
                "agg-old",
                "FAILED",
                0,
                1,
                "2026-04-27 17:20:00",
                "2026-04-27 17:20:01");
        SealedEvidenceOfficialRunView latestAttempt = officialRun(
                "run-new-eir",
                "EIR",
                "agg-new",
                "SUCCESS",
                1,
                1,
                "2026-04-27 17:30:00",
                "2026-04-27 17:30:01");
        when(evidenceService.findDetail("pkg-001")).thenReturn(sealedEvidence());
        when(officialRuntime.findByPackageId("pkg-001")).thenReturn(new OfficialSealedEvidenceVerificationResult(
                "agg-new",
                "pkg-001",
                "operator-a",
                "2026-04-27 17:30:01",
                true,
                List.of(latestAttempt)));
        when(ledgerService.findMetricRunsByPackageId("pkg-001")).thenReturn(List.of(oldAttempt, latestAttempt));
        when(processRunService.steps(any())).thenReturn(List.of(new PromptQualityProcessStepSnapshot(
                PromptQualityProcessCodes.OFFICIAL_VERIFICATION,
                3,
                PromptQualityProcessCodes.COMPLETED,
                "CERTIFICATE",
                "BLOCKED",
                "pkg-001",
                "/contexa/admin/enterprise/prompt-quality/verification/readiness?packageId=pkg-001",
                "Official verification blocked certificate issuance.",
                "Fix failed official metric and re-request evidence.",
                Instant.parse("2026-04-27T08:20:00Z"),
                Instant.parse("2026-04-27T08:20:01Z"))));
        when(processRunService.history(any())).thenReturn(List.of(new PromptQualityProcessHistorySnapshot(
                PromptQualityProcessCodes.MAIN,
                PromptQualityProcessCodes.OFFICIAL_VERIFICATION,
                PromptQualityProcessCodes.RUNNING,
                PromptQualityProcessCodes.COMPLETED,
                "CERTIFICATE",
                "PENDING",
                "CERTIFICATE",
                "BLOCKED",
                "pkg-001",
                "operator-a",
                "Official verification completed.",
                Instant.parse("2026-04-27T08:20:01Z"))));
        when(processRunService.events(any())).thenReturn(List.of(new PromptQualityProcessEventSnapshot(
                PromptQualityProcessCodes.OFFICIAL_VERIFICATION,
                "OFFICIAL_VERIFICATION_AUDIT_SNAPSHOT",
                "{\"packageId\":\"pkg-001\",\"aggregateRunId\":\"agg-old\"}",
                Instant.parse("2026-04-27T08:20:01Z"))));

        OfficialRunPackageDetail detail = service.findPackageDetail("pkg-001", "agg-old");

        assertThat(detail.aggregateRunId()).isEqualTo("agg-old");
        assertThat(detail.runs()).extracting("officialRunId").containsExactly("run-old-eir");
        assertThat(detail.attempts()).extracting("aggregateRunId").containsExactly("agg-old", "agg-new");
        assertThat(detail.attempts())
                .anySatisfy(attempt -> {
                    assertThat(attempt.aggregateRunId()).isEqualTo("agg-old");
                    assertThat(attempt.latest()).isTrue();
                    assertThat(attempt.failedRunCount()).isEqualTo(1);
                })
                .anySatisfy(attempt -> {
                    assertThat(attempt.aggregateRunId()).isEqualTo("agg-new");
                    assertThat(attempt.latest()).isFalse();
                    assertThat(attempt.passedRunCount()).isEqualTo(1);
                });
        assertThat(detail.processSteps()).singleElement().satisfies(step -> {
            assertThat(step.stepCode()).isEqualTo(PromptQualityProcessCodes.OFFICIAL_VERIFICATION);
            assertThat(step.executionState()).isEqualTo(PromptQualityProcessCodes.COMPLETED);
            assertThat(step.domainStateCode()).isEqualTo("BLOCKED");
        });
        assertThat(detail.processHistory()).singleElement()
                .extracting("toState")
                .isEqualTo(PromptQualityProcessCodes.COMPLETED);
        assertThat(detail.processEvents()).singleElement().satisfies(event -> {
            assertThat(event.type()).isEqualTo("OFFICIAL_VERIFICATION_AUDIT_SNAPSHOT");
            assertThat(event.payloadJson()).contains("agg-old");
        });
        assertThatThrownBy(() -> service.findPackageDetail("pkg-001", "does-not-exist"))
                .isInstanceOf(NoSuchElementException.class)
                .hasMessageContaining("does-not-exist")
                .hasMessageContaining("pkg-001");
        assertThat(detail.auditSnapshots()).singleElement().satisfies(snapshot -> {
            assertThat(snapshot.packageId()).isEqualTo("pkg-001");
            assertThat(snapshot.aggregateRunId()).isEqualTo("agg-old");
            assertThat(snapshot.persisted()).isTrue();
            assertThat(snapshot.failedMetricCount()).isEqualTo(1);
            assertThat(snapshot.payloadJson()).contains("\"aggregateRunId\":\"agg-old\"");
        });
    }

    @Test
    void packageDetailUsesCoreOfficialRunAndDoesNotSynthesizePromptComparisonRows() {
        OfficialSealedEvidenceVerificationRuntime officialRuntime = mock(OfficialSealedEvidenceVerificationRuntime.class);
        VerificationLedgerService ledgerService = mock(VerificationLedgerService.class);
        PromptQualityRuntimeEvidenceService evidenceService = mock(PromptQualityRuntimeEvidenceService.class);
        PromptQualityOfficialMetricCatalog metricCatalog = () -> List.of(new OfficialVerificationMetricDefinition(
                "EIR",
                "Required Evidence",
                "IMPLEMENTATION_ALIGNMENT",
                "required evidence",
                true,
                1.0d,
                true));
        DefaultPromptQualityOfficialRunDetailService service = service(
                officialRuntime,
                ledgerService,
                evidenceService,
                metricCatalog);

        when(evidenceService.findDetail("pkg-001")).thenReturn(sealedEvidence());
        when(officialRuntime.findByPackageId("pkg-001")).thenReturn(new OfficialSealedEvidenceVerificationResult(
                "agg-001",
                "pkg-001",
                "operator-a",
                "2026-04-27 17:30:00",
                true,
                List.of(failedRun())));

        OfficialRunPackageDetail detail = service.findPackageDetail("pkg-001");

        assertThat(detail.packageId()).isEqualTo("pkg-001");
        assertThat(detail.aggregateRunId()).isEqualTo("agg-001");
        assertThat(detail.totalRunCount()).isEqualTo(1);
        assertThat(detail.failedRunCount()).isEqualTo(1);
        assertThat(detail.ledgerConsistency()).satisfies(consistency -> {
            assertThat(consistency.expectedMetricCount()).isEqualTo(1);
            assertThat(consistency.actualRunCount()).isEqualTo(1);
            assertThat(consistency.metricCountMatched()).isTrue();
            assertThat(consistency.totalCheckCount()).isEqualTo(2);
            assertThat(consistency.declaredCheckCount()).isEqualTo(2);
            assertThat(consistency.storedCheckRowCount()).isEqualTo(2);
            assertThat(consistency.checkCountMatched()).isTrue();
            assertThat(consistency.rawArtifactRunCount()).isEqualTo(1);
            assertThat(consistency.factBackedRunCount()).isEqualTo(1);
            assertThat(consistency.readyForIssueResolution()).isFalse();
            assertThat(consistency.warnings()).isNotEmpty();
        });
        assertThat(detail.runs()).singleElement().satisfies(run -> {
            assertThat(run.officialRunId()).isEqualTo("run-eir-001");
            assertThat(run.checks()).extracting("label").contains("mfaVerified true");
            assertThat(run.failureCauses()).singleElement()
                    .extracting("checkLabel")
                    .isEqualTo("mfaVerified true");
        });
        assertThat(detail.promptComparisons()).isEmpty();
        assertThat(detail.failureCauses()).extracting("officialRunId").containsExactly("run-eir-001");
        verify(officialRuntime).findByPackageId("pkg-001");
        verify(evidenceService).findDetail("pkg-001");
    }

    @Test
    void packageDetailPreservesNotApplicableChecksForAuthorizedOperatorRows() {
        OfficialSealedEvidenceVerificationRuntime officialRuntime = mock(OfficialSealedEvidenceVerificationRuntime.class);
        VerificationLedgerService ledgerService = mock(VerificationLedgerService.class);
        PromptQualityRuntimeEvidenceService evidenceService = mock(PromptQualityRuntimeEvidenceService.class);
        PromptQualityOfficialMetricCatalog metricCatalog = () -> List.of(new OfficialVerificationMetricDefinition(
                "RAP",
                "RAG Authorization Precision",
                "RAG_AND_BASELINE",
                "authorized RAG evidence",
                true,
                1.0d,
                true));
        DefaultPromptQualityOfficialRunDetailService service = service(
                officialRuntime,
                ledgerService,
                evidenceService,
                metricCatalog);

        when(evidenceService.findDetail("pkg-001")).thenReturn(sealedEvidence());
        when(officialRuntime.findByPackageId("pkg-001")).thenReturn(new OfficialSealedEvidenceVerificationResult(
                "agg-001",
                "pkg-001",
                "operator-a",
                "2026-04-27 17:30:00",
                true,
                List.of(rapRunWithNotApplicableDocumentCheck())));

        OfficialRunPackageDetail detail = service.findPackageDetail("pkg-001");

        assertThat(detail.ledgerConsistency()).satisfies(consistency -> {
            assertThat(consistency.declaredCheckCount()).isEqualTo(2);
            assertThat(consistency.storedCheckRowCount()).isEqualTo(2);
            assertThat(consistency.totalCheckCount()).isEqualTo(2);
            assertThat(consistency.checkCountMatched()).isTrue();
        });
        assertThat(detail.runs()).singleElement().satisfies(run -> {
            assertThat(run.totalChecks()).isEqualTo(2);
            assertThat(run.passedChecks()).isEqualTo(1);
            assertThat(run.notApplicableChecks()).isEqualTo(1);
            assertThat(run.checks()).hasSize(2);
            assertThat(run.checks()).extracting("checkCode")
                    .containsExactly("RAG_SEARCH_STATE_EXPLAINED", "RAG_AUTHORIZATION_REASON_PRESENT");
            assertThat(run.checks()).filteredOn(check -> !check.customerVisible())
                    .singleElement().satisfies(check -> {
                        assertThat(check.operatorVisible()).isTrue();
                        assertThat(check.evaluationState().name()).isEqualTo("NOT_APPLICABLE");
                    });
        });
    }

    @Test
    void packageDetailSeparatesInternalReferenceCustomerVisibilityFromOperatorVisibility() {
        OfficialSealedEvidenceVerificationRuntime officialRuntime = mock(OfficialSealedEvidenceVerificationRuntime.class);
        VerificationLedgerService ledgerService = mock(VerificationLedgerService.class);
        PromptQualityRuntimeEvidenceService evidenceService = mock(PromptQualityRuntimeEvidenceService.class);
        PromptQualityOfficialMetricCatalog metricCatalog = () -> List.of(new OfficialVerificationMetricDefinition(
                "COR",
                "Context Contamination Rate",
                "IMPLEMENTATION_ALIGNMENT",
                "RAG contamination",
                true,
                1.0d,
                true));
        DefaultPromptQualityOfficialRunDetailService service = service(
                officialRuntime,
                ledgerService,
                evidenceService,
                metricCatalog);

        when(evidenceService.findDetail("pkg-001")).thenReturn(sealedEvidence());
        when(officialRuntime.findByPackageId("pkg-001")).thenReturn(new OfficialSealedEvidenceVerificationResult(
                "agg-001",
                "pkg-001",
                "operator-a",
                "2026-04-27 17:30:00",
                true,
                List.of(corRunWithVisibleAndInternalReferenceChecks())));

        OfficialRunPackageDetail detail = service.findPackageDetail("pkg-001");

        assertThat(detail.ledgerConsistency()).satisfies(consistency -> {
            assertThat(consistency.declaredCheckCount()).isEqualTo(2);
            assertThat(consistency.storedCheckRowCount()).isEqualTo(2);
            assertThat(consistency.totalCheckCount()).isEqualTo(2);
            assertThat(consistency.checkCountMatched()).isTrue();
        });
        assertThat(detail.runs()).singleElement().satisfies(run -> {
            assertThat(run.totalChecks()).isEqualTo(1);
            assertThat(run.passedChecks()).isEqualTo(1);
            assertThat(run.checks()).extracting("checkCode")
                    .containsExactly("RAG_APPLICABILITY_DECLARED", "NO_RAG_CONTEXT_NO_CONTAMINATION_SURFACE");
            assertThat(run.checks()).filteredOn(check -> !check.customerVisible())
                    .singleElement().extracting("operatorVisible").isEqualTo(true);
        });
    }

    @Test
    void packageDetailLabelsMetricAsNotApplicableWhenAllChecksAreNotApplicable() {
        OfficialSealedEvidenceVerificationRuntime officialRuntime = mock(OfficialSealedEvidenceVerificationRuntime.class);
        VerificationLedgerService ledgerService = mock(VerificationLedgerService.class);
        PromptQualityRuntimeEvidenceService evidenceService = mock(PromptQualityRuntimeEvidenceService.class);
        PromptQualityOfficialMetricCatalog metricCatalog = () -> List.of(new OfficialVerificationMetricDefinition(
                "RAP",
                "RAG Authorization Precision",
                "RAG_AND_BASELINE",
                "authorized RAG evidence",
                true,
                1.0d,
                true));
        DefaultPromptQualityOfficialRunDetailService service = service(
                officialRuntime,
                ledgerService,
                evidenceService,
                metricCatalog);

        when(evidenceService.findDetail("pkg-001")).thenReturn(sealedEvidence());
        when(officialRuntime.findByPackageId("pkg-001")).thenReturn(new OfficialSealedEvidenceVerificationResult(
                "agg-001",
                "pkg-001",
                "operator-a",
                "2026-04-27 17:30:00",
                true,
                List.of(rapRunWithOnlyNotApplicableChecks())));

        OfficialRunPackageDetail detail = service.findPackageDetail("pkg-001");

        assertThat(detail.totalRunCount()).isEqualTo(1);
        assertThat(detail.passedRunCount()).isZero();
        assertThat(detail.failedRunCount()).isZero();
        assertThat(detail.runs()).singleElement().satisfies(run -> {
            assertThat(run.state()).isEqualTo("NOT_APPLICABLE");
            assertThat(run.stateLabel()).isEqualTo("해당 없음");
            assertThat(run.totalChecks()).isEqualTo(1);
            assertThat(run.passedChecks()).isZero();
            assertThat(run.notApplicableChecks()).isEqualTo(1);
            assertThat(run.checks()).singleElement()
                    .extracting("evaluationState").isEqualTo(
                            OfficialVerificationCheckState.NOT_APPLICABLE);
        });
    }

    @Test
    void packageDetailLabelsCorAsNotApplicableWhenNoRagDocumentsExist() {
        OfficialSealedEvidenceVerificationRuntime officialRuntime = mock(OfficialSealedEvidenceVerificationRuntime.class);
        VerificationLedgerService ledgerService = mock(VerificationLedgerService.class);
        PromptQualityRuntimeEvidenceService evidenceService = mock(PromptQualityRuntimeEvidenceService.class);
        PromptQualityOfficialMetricCatalog metricCatalog = () -> List.of(new OfficialVerificationMetricDefinition(
                "COR",
                "Context Contamination Rate",
                "IMPLEMENTATION_ALIGNMENT",
                "RAG contamination",
                true,
                1.0d,
                true));
        DefaultPromptQualityOfficialRunDetailService service = service(
                officialRuntime,
                ledgerService,
                evidenceService,
                metricCatalog);

        when(evidenceService.findDetail("pkg-001")).thenReturn(sealedEvidence());
        when(officialRuntime.findByPackageId("pkg-001")).thenReturn(new OfficialSealedEvidenceVerificationResult(
                "agg-001",
                "pkg-001",
                "operator-a",
                "2026-04-27 17:30:00",
                true,
                List.of(corRunWithOnlyNotApplicableChecks())));

        OfficialRunPackageDetail detail = service.findPackageDetail("pkg-001");

        assertThat(detail.totalRunCount()).isEqualTo(1);
        assertThat(detail.passedRunCount()).isZero();
        assertThat(detail.failedRunCount()).isZero();
        assertThat(detail.runs()).singleElement().satisfies(run -> {
            assertThat(run.metricCode()).isEqualTo("COR");
            assertThat(run.state()).isEqualTo("NOT_APPLICABLE");
            assertThat(run.stateLabel()).isEqualTo("해당 없음");
            assertThat(run.totalChecks()).isEqualTo(1);
            assertThat(run.passedChecks()).isZero();
            assertThat(run.notApplicableChecks()).isEqualTo(1);
            assertThat(run.checks()).singleElement()
                    .extracting("operatorVisible").isEqualTo(true);
            assertThat(run.purposeEvidence()).allSatisfy(evidence -> {
                assertThat(evidence.customerVisible()).isFalse();
                assertThat(evidence.purposeResult()).isEqualTo("NOT_APPLICABLE");
                assertThat(evidence.readinessScope()).isEqualTo("INTERNAL_REFERENCE");
            });
        });
    }

    @Test
    void packageDetailFallsBackToPersistedOperatorSnapshotWhenCoreRunLedgerRowsAreMissing() {
        OfficialSealedEvidenceVerificationRuntime officialRuntime = mock(OfficialSealedEvidenceVerificationRuntime.class);
        VerificationLedgerService ledgerService = mock(VerificationLedgerService.class);
        PromptQualityRuntimeEvidenceService evidenceService = mock(PromptQualityRuntimeEvidenceService.class);
        PromptQualityOfficialMetricCatalog metricCatalog = () -> List.of(new OfficialVerificationMetricDefinition(
                "EIR",
                "Required Evidence",
                "IMPLEMENTATION_ALIGNMENT",
                "required evidence",
                true,
                1.0d,
                true));
        OfficialVerificationOperatorSnapshotService.OperatorSnapshot snapshot = operatorSnapshot();
        OfficialVerificationOperatorSnapshotService snapshotService = mock(OfficialVerificationOperatorSnapshotService.class);
        when(snapshotService.findLatest(any(), any())).thenReturn(snapshot);
        when(snapshotService.promptComparisons(any(), any())).thenReturn(List.of());
        DefaultPromptQualityOfficialRunDetailService service = service(
                officialRuntime,
                ledgerService,
                evidenceService,
                metricCatalog,
                snapshotService);

        when(evidenceService.findDetail("pkg-001")).thenReturn(sealedEvidence());
        when(officialRuntime.findByPackageId("pkg-001")).thenReturn(new OfficialSealedEvidenceVerificationResult(
                "agg-001",
                "pkg-001",
                "operator-a",
                "2026-05-04T08:00:00Z",
                true,
                List.of()));
        when(ledgerService.findMetricRunsByPackageId("pkg-001")).thenReturn(List.of());

        OfficialRunPackageDetail detail = service.findPackageDetail("pkg-001", "agg-001");

        assertThat(detail.packageId()).isEqualTo("pkg-001");
        assertThat(detail.aggregateRunId()).isEqualTo("agg-001");
        assertThat(detail.totalRunCount()).isEqualTo(1);
        assertThat(detail.failedRunCount()).isEqualTo(1);
        assertThat(detail.runs()).singleElement().satisfies(run -> {
            assertThat(run.metricCode()).isEqualTo("EIR");
            assertThat(run.officialRunId()).isEqualTo("run-eir-001");
            assertThat(run.requestPath()).isEqualTo("/contexa/admin/api/orders/resource-001");
            assertThat(run.analysisFacts()).containsEntry("sourceMode", "OFFICIAL_OPERATOR_SNAPSHOT");
            assertThat(run.rawEvidence()).containsEntry("aggregateRunId", "agg-001");
            assertThat(run.promptFacts()).containsEntry("promptHash", "prompt-hash-001");
        });
        assertThat(detail.promptComparisons()).isEmpty();
        assertThat(detail.failureCauses()).extracting("officialRunId").contains("run-eir-001");
        verify(officialRuntime).findByPackageId("pkg-001");
        verify(ledgerService).findMetricRunsByPackageId("pkg-001");
        verify(evidenceService).findDetail("pkg-001");
    }

    @Test
    void packageDetailUsesPersistedOperatorSnapshotWhenCoreRunLedgerRowsAreIncomplete() {
        OfficialSealedEvidenceVerificationRuntime officialRuntime = mock(OfficialSealedEvidenceVerificationRuntime.class);
        VerificationLedgerService ledgerService = mock(VerificationLedgerService.class);
        PromptQualityRuntimeEvidenceService evidenceService = mock(PromptQualityRuntimeEvidenceService.class);
        PromptQualityOfficialMetricCatalog metricCatalog = () -> List.of(
                new OfficialVerificationMetricDefinition(
                        "EIR",
                        "Required Evidence",
                        "IMPLEMENTATION_ALIGNMENT",
                        "required evidence",
                        true,
                        1.0d,
                        true),
                new OfficialVerificationMetricDefinition(
                        "PFR",
                        "Prompt Fidelity Rate",
                        "IMPLEMENTATION_ALIGNMENT",
                        "prompt fidelity",
                        true,
                        1.0d,
                        true));
        OfficialVerificationOperatorSnapshotService.OperatorSnapshot snapshot = operatorSnapshot(List.of(
                operatorMetricSnapshot("EIR", "run-eir-001", "PASSED", 5, 5, 0),
                operatorMetricSnapshot("PFR", "run-pfr-001", "PASSED", 5, 5, 0)));
        OfficialVerificationOperatorSnapshotService snapshotService = mock(OfficialVerificationOperatorSnapshotService.class);
        when(snapshotService.findLatest(any(), any())).thenReturn(snapshot);
        when(snapshotService.promptComparisons(any(), any())).thenReturn(List.of());
        DefaultPromptQualityOfficialRunDetailService service = service(
                officialRuntime,
                ledgerService,
                evidenceService,
                metricCatalog,
                snapshotService);

        when(evidenceService.findDetail("pkg-001")).thenReturn(sealedEvidence());
        when(officialRuntime.findByPackageId("pkg-001")).thenReturn(new OfficialSealedEvidenceVerificationResult(
                "agg-001",
                "pkg-001",
                "operator-a",
                "2026-05-04T08:00:00Z",
                true,
                List.of(failedRun())));
        when(ledgerService.findMetricRunsByPackageId("pkg-001")).thenReturn(List.of(failedRun()));

        OfficialRunPackageDetail detail = service.findPackageDetail("pkg-001", "agg-001");

        assertThat(detail.aggregateRunId()).isEqualTo("agg-001");
        assertThat(detail.totalRunCount()).isEqualTo(2);
        assertThat(detail.failedRunCount()).isZero();
        assertThat(detail.ledgerConsistency().declaredCheckCount()).isEqualTo(10);
        assertThat(detail.ledgerConsistency().storedCheckRowCount()).isEqualTo(10);
        assertThat(detail.ledgerConsistency().checkCountMatched()).isTrue();
        assertThat(detail.runs()).extracting(OfficialVerificationMetricTrace::metricCode)
                .containsExactly("EIR", "PFR");
        assertThat(detail.runs()).allSatisfy(run ->
                assertThat(run.analysisFacts()).containsEntry("sourceMode", "OFFICIAL_OPERATOR_SNAPSHOT"));
    }

    @Test
    void packageDetailExposesAllSnapshotOnlyMetricChecksInDetailModalPayload() {
        OfficialSealedEvidenceVerificationRuntime officialRuntime = mock(OfficialSealedEvidenceVerificationRuntime.class);
        VerificationLedgerService ledgerService = mock(VerificationLedgerService.class);
        PromptQualityRuntimeEvidenceService evidenceService = mock(PromptQualityRuntimeEvidenceService.class);
        PromptQualityOfficialMetricCatalog metricCatalog = () -> List.of(
                new OfficialVerificationMetricDefinition(
                        "RPI",
                        "Round Progression Integrity",
                        "LEARNING_BASELINE",
                        "round progression",
                        true,
                        1.0d,
                        true),
                new OfficialVerificationMetricDefinition(
                        "MTR",
                        "Metadata Traceability Rate",
                        "IMPLEMENTATION_ALIGNMENT",
                        "metadata traceability",
                        true,
                        1.0d,
                        true),
                new OfficialVerificationMetricDefinition(
                        "PRE",
                        "Protectable Resource Eligibility",
                        "PROMOTION_ELIGIBILITY",
                        "protectable resource eligibility",
                        true,
                        1.0d,
                        true));
        OfficialVerificationOperatorSnapshotService.OperatorSnapshot snapshot = operatorSnapshot(List.of(
                operatorMetricSnapshot("RPI", "run-rpi-001", "PASSED", 4, 4, 0),
                operatorMetricSnapshot("MTR", "run-mtr-001", "PASSED", 5, 5, 0),
                operatorMetricSnapshot("PRE", "run-pre-001", "PASSED", 4, 4, 0)));
        OfficialVerificationOperatorSnapshotService snapshotService = mock(OfficialVerificationOperatorSnapshotService.class);
        when(snapshotService.findLatest(any(), any())).thenReturn(snapshot);
        when(snapshotService.promptComparisons(any(), any())).thenReturn(List.of());
        DefaultPromptQualityOfficialRunDetailService service = service(
                officialRuntime,
                ledgerService,
                evidenceService,
                metricCatalog,
                snapshotService);

        when(evidenceService.findDetail("pkg-001")).thenReturn(sealedEvidence());
        when(officialRuntime.findByPackageId("pkg-001")).thenReturn(new OfficialSealedEvidenceVerificationResult(
                "agg-001",
                "pkg-001",
                "operator-a",
                "2026-05-04T08:00:00Z",
                true,
                List.of()));
        when(ledgerService.findMetricRunsByPackageId("pkg-001")).thenReturn(List.of());

        OfficialRunPackageDetail detail = service.findPackageDetail("pkg-001", "agg-001");

        assertThat(detail.runs()).extracting(OfficialVerificationMetricTrace::metricCode)
                .containsExactlyInAnyOrder("RPI", "MTR", "PRE");
        assertThat(detail.runs()).allSatisfy(run -> {
            assertThat(run.checks())
                    .as(run.metricCode() + " detail modal checks")
                    .hasSize(run.totalChecks());
            assertThat(run.purposeEvidence())
                    .as(run.metricCode() + " purpose evidence rows")
                    .hasSize(run.totalChecks());
            assertThat(run.checks()).allSatisfy(check -> {
                assertThat(check.checkCode()).isNotBlank();
                assertThat(check.label()).isNotBlank();
                assertThat(check.actualValue()).isNotBlank();
                assertThat(check.pass()).isTrue();
            });
        });
    }

    @Test
    void staleAggregateRunIdDoesNotFallBackToDifferentOperatorSnapshot() {
        OfficialSealedEvidenceVerificationRuntime officialRuntime = mock(OfficialSealedEvidenceVerificationRuntime.class);
        VerificationLedgerService ledgerService = mock(VerificationLedgerService.class);
        PromptQualityRuntimeEvidenceService evidenceService = mock(PromptQualityRuntimeEvidenceService.class);
        PromptQualityOfficialMetricCatalog metricCatalog = () -> List.of(new OfficialVerificationMetricDefinition(
                "EIR",
                "Required Evidence",
                "IMPLEMENTATION_ALIGNMENT",
                "required evidence",
                true,
                1.0d,
                true));
        OfficialVerificationOperatorSnapshotService.OperatorSnapshot latestSnapshot = operatorSnapshot();
        OfficialVerificationOperatorSnapshotService snapshotService = mock(OfficialVerificationOperatorSnapshotService.class);
        when(snapshotService.findLatest(any(), any())).thenAnswer(invocation ->
                "agg-stale".equals(invocation.getArgument(1, String.class))
                        ? OfficialVerificationOperatorSnapshotService.OperatorSnapshot.empty()
                        : latestSnapshot);
        when(snapshotService.promptComparisons(any(), any())).thenReturn(List.of());
        DefaultPromptQualityOfficialRunDetailService service = service(
                officialRuntime,
                ledgerService,
                evidenceService,
                metricCatalog,
                snapshotService);

        when(evidenceService.findDetail("pkg-001")).thenReturn(sealedEvidence());
        when(officialRuntime.findByPackageId("pkg-001")).thenReturn(new OfficialSealedEvidenceVerificationResult(
                "agg-stale",
                "pkg-001",
                "operator-a",
                "2026-05-04T08:00:00Z",
                true,
                List.of()));
        when(ledgerService.findMetricRunsByPackageId("pkg-001")).thenReturn(List.of());

        OfficialRunPackageDetail detail = service.findPackageDetail("pkg-001", "agg-stale");

        assertThat(detail.aggregateRunId()).isEqualTo("agg-stale");
        assertThat(detail.runs()).isEmpty();
        assertThat(detail.actualPromptProblems()).isEmpty();
    }

    @Test
    void failedTrackedAggregateDoesNotFallBackToCoreLedgerResult() {
        OfficialSealedEvidenceVerificationRuntime officialRuntime = mock(OfficialSealedEvidenceVerificationRuntime.class);
        VerificationLedgerService ledgerService = mock(VerificationLedgerService.class);
        PromptQualityRuntimeEvidenceService evidenceService = mock(PromptQualityRuntimeEvidenceService.class);
        PromptQualityOfficialMetricCatalog metricCatalog = () -> List.of(new OfficialVerificationMetricDefinition(
                "EIR",
                "Required Evidence",
                "IMPLEMENTATION_ALIGNMENT",
                "required evidence",
                true,
                1.0d,
                true));
        OfficialVerificationOperatorSnapshotService snapshotService = mock(OfficialVerificationOperatorSnapshotService.class);
        DefaultPromptQualityOfficialRunDetailService service = service(
                officialRuntime,
                ledgerService,
                evidenceService,
                metricCatalog,
                snapshotService);
        SealedEvidenceOfficialRunView failed = officialRun(
                "run-failed-001",
                "EIR",
                "agg-failed",
                "FAILED",
                4,
                5,
                "2026-05-04T08:00:00Z",
                "2026-05-04T08:00:01Z");
        when(evidenceService.findDetail("pkg-001")).thenReturn(sealedEvidence());
        when(ledgerService.findMetricRunsByPackageId("pkg-001")).thenReturn(List.of(failed));
        when(officialRuntime.findByPackageId("pkg-001")).thenReturn(new OfficialSealedEvidenceVerificationResult(
                "agg-failed",
                "pkg-001",
                "operator-a",
                "2026-05-04T08:00:01Z",
                true,
                List.of(failed)));
        when(snapshotService.findLatest("pkg-001", "agg-failed"))
                .thenReturn(OfficialVerificationOperatorSnapshotService.OperatorSnapshot.empty());
        when(snapshotService.executionRecordExists("agg-failed")).thenReturn(true);

        assertThatThrownBy(() -> service.findPackageDetail("pkg-001", "agg-failed"))
                .isInstanceOf(NoSuchElementException.class)
                .hasMessageContaining("agg-failed")
                .hasMessageContaining("pkg-001");
    }

    @Test
    void runDetailReadsCoreLedgerRunAndBuildsEvidenceBackedMetricTrace() {
        OfficialSealedEvidenceVerificationRuntime officialRuntime = mock(OfficialSealedEvidenceVerificationRuntime.class);
        VerificationLedgerService ledgerService = mock(VerificationLedgerService.class);
        PromptQualityRuntimeEvidenceService evidenceService = mock(PromptQualityRuntimeEvidenceService.class);
        PromptQualityOfficialMetricCatalog metricCatalog = () -> List.of(new OfficialVerificationMetricDefinition(
                "EIR",
                "Required Evidence",
                "IMPLEMENTATION_ALIGNMENT",
                "required evidence",
                true,
                1.0d,
                true));
        DefaultPromptQualityOfficialRunDetailService service = service(
                officialRuntime,
                ledgerService,
                evidenceService,
                metricCatalog);

        when(ledgerService.findRunRecord(null, "run-eir-001")).thenReturn(new OfficialVerificationRunRecord(
                "run-eir-001",
                "EIR",
                "SEALED_EVIDENCE_PACKAGE",
                "FAILED",
                "operator-a",
                Instant.parse("2026-04-27T08:30:00Z"),
                Instant.parse("2026-04-27T08:30:00Z"),
                Instant.parse("2026-04-27T08:30:01Z"),
                "failed",
                Map.of("packageId", "pkg-001")));
        when(ledgerService.findMetricRun(null, "EIR", "run-eir-001")).thenReturn(failedRun());
        when(evidenceService.findDetail("pkg-001")).thenReturn(sealedEvidence());

        OfficialVerificationMetricTrace trace = service.findRunDetail("run-eir-001");

        assertThat(trace.metricCode()).isEqualTo("EIR");
        assertThat(trace.officialRunId()).isEqualTo("run-eir-001");
        assertThat(trace.requestId()).isEqualTo("req-001");
        assertThat(trace.passedChecks()).isEqualTo(1);
        assertThat(trace.totalChecks()).isEqualTo(2);
        assertThat(trace.checks()).allSatisfy(check -> {
            assertThat(check.source()).isNotBlank();
            assertThat(check.sourceMeaning()).isNotBlank();
        });
        assertThat(trace.failureCauses()).singleElement().satisfies(failure -> {
            assertThat(failure.source()).isEqualTo("coreEvidenceReplay");
            assertThat(failure.rootCause()).contains("mfaVerified true");
            assertThat(failure.reverifyCriterion()).contains("mfaVerified true");
        });
        assertThat(trace.requestFacts()).containsEntry("requestId", "req-001");
        assertThat(trace.promptFacts()).containsEntry("promptHash", "prompt-hash-001");
        assertThat(trace.analysisFacts()).containsEntry("sourceMode", "CORE_OFFICIAL_SEALED_EVIDENCE");
        assertThat(trace.events()).singleElement().satisfies(event -> assertThat(event.type()).isEqualTo("SEALED_EVIDENCE_REPLAY"));
        assertThat(trace.rawEvidence()).containsEntry("packageId", "pkg-001");
        assertThat(trace.comparisons())
                .as("metric detail must not synthesize customer prompt comparisons when the stored actual prompt problem ledger is absent")
                .isEmpty();
        verify(ledgerService).findRunRecord(null, "run-eir-001");
        verify(ledgerService).findMetricRun(null, "EIR", "run-eir-001");
        verify(evidenceService).findDetail("pkg-001");
    }

    private OfficialVerificationOperatorSnapshotService.OperatorSnapshot operatorSnapshot() {
        return operatorSnapshot(List.of(operatorMetricSnapshot("EIR", "run-eir-001", "FAILED", 10, 11, 1)));
    }

    private OfficialVerificationOperatorSnapshotService.OperatorSnapshot operatorSnapshot(
            List<OfficialVerificationOperatorSnapshotService.OperatorMetricSnapshot> metrics) {
        Instant createdAt = Instant.parse("2026-05-04T08:00:00Z");
        return new OfficialVerificationOperatorSnapshotService.OperatorSnapshot(
                new OfficialVerificationOperatorSnapshotService.OperatorRunBatch(
                        "agg-001",
                        "pkg-001",
                        "cert-001",
                        "case-001",
                        "SEALED_EVIDENCE_PACKAGE",
                        12,
                        12,
                        11,
                        1,
                        0,
                        0,
                        "BLOCKED",
                        true,
                        "공식 검사 원장 연결 문제로 보증서 발급이 차단되었습니다.",
                        "prompt-hash-001",
                        "context-hash-001",
                        "PRESENT",
                        "contexa.official-verification.normal.{resourceId}",
                        "resource-001",
                        "/contexa/admin/api/orders/{resourceId}",
                        "/contexa/admin/api/orders/resource-001",
                        "GET",
                        createdAt),
                metrics,
                List.of(new OfficialVerificationOperatorSnapshotService.OperatorFinding(
                        "finding-001",
                        "agg-001",
                        "run-eir-001",
                        "pkg-001",
                        "cert-001",
                        "case-001",
                        "issue-001",
                        "EIR",
                        "EIR.REQUEST_LINK",
                        "HIGH",
                        "요청 증거 연결이 부족합니다",
                        "공식 검사 원장과 봉인 증거 연결을 확인해야 합니다.",
                        "요청 증거가 공식 검사 원장과 완전히 연결되지 않았습니다.",
                        "packageId와 aggregateRunId 연결 근거가 부족합니다.",
                        "RUNTIME_EVIDENCE",
                        "공식 검사 원장에 packageId와 aggregateRunId 연결 근거가 누락되었습니다.",
                        "packageId와 aggregateRunId 연결 근거를 공식 운영자 스냅샷에서 확인했습니다.",
                        "official_verification_operator_finding.evidence_path",
                        "packageId와 aggregateRunId가 함께 저장되어야 합니다.",
                        "aggregateRunId가 비어 있습니다.",
                        "연결 완료",
                        "연결 부족",
                        "문제 해결과 감사 보고서가 같은 증거를 추적할 수 없습니다.",
                        "RUNTIME_EVIDENCE",
                        "봉인 증거 저장과 공식 지표 실행 원장 연결을 같은 packageId와 aggregateRunId로 고정하십시오.",
                        "같은 리소스를 다시 요청해 packageId와 aggregateRunId가 함께 조회되어야 합니다.",
                        "높음",
                        PromptQualityProcessCodes.RUNTIME_EVIDENCE,
                        createdAt)),
                List.of(new OfficialVerificationOperatorSnapshotService.OperatorRemediationGroup(
                        "group-001",
                        "agg-001",
                        "pkg-001",
                        "cert-001",
                        "case-001",
                        "runtime-evidence-link",
                        "RUNTIME_EVIDENCE",
                        "요청 증거 연결 보강",
                        "packageId와 aggregateRunId 연결을 고정해야 합니다.",
                        "봉인 증거 저장과 공식 지표 실행 원장 연결을 보강하십시오.",
                        "재요청 후 같은 packageId 기준으로 공식 원장 요약이 조회되어야 합니다.",
                        List.of("EIR"),
                        List.of("EIR.REQUEST_LINK"),
                        1,
                        PromptQualityProcessCodes.RUNTIME_EVIDENCE,
                        createdAt)),
                List.of(),
                operatorPurposeEvidence(metrics),
                List.of(new OfficialVerificationOperatorSnapshotService.OperatorAuditSnapshot(
                        "audit-001",
                        "agg-001",
                        "pkg-001",
                        "cert-001",
                        "case-001",
                        "BLOCKED",
                        "차단",
                        12,
                        1,
                        false,
                        "prompt-hash-001",
                        "context-hash-001",
                        List.of("요청 증거 연결이 부족합니다"),
                        List.of("봉인 증거와 공식 지표 원장 연결을 보강하십시오."),
                        "{\"packageId\":\"pkg-001\",\"aggregateRunId\":\"agg-001\"}",
                        "operator-a",
                        createdAt)));
    }

    private List<OfficialVerificationOperatorSnapshotService.OperatorPurposeEvidence> operatorPurposeEvidence(
            List<OfficialVerificationOperatorSnapshotService.OperatorMetricSnapshot> metrics) {
        Instant createdAt = Instant.parse("2026-05-04T08:00:00Z");
        ArrayList<OfficialVerificationOperatorSnapshotService.OperatorPurposeEvidence> rows =
                new ArrayList<>();
        for (OfficialVerificationOperatorSnapshotService.OperatorMetricSnapshot metric : metrics) {
            for (int index = 1; index <= metric.totalChecks(); index++) {
                rows.add(new OfficialVerificationOperatorSnapshotService.OperatorPurposeEvidence(
                        "agg-001",
                        "pkg-001",
                        metric.metricCode(),
                        metric.metricCode() + ".CHECK_" + index,
                        "contract-v1",
                        "purpose signal " + index,
                        "finalUserPrompt.test",
                        "purpose evidence " + index,
                        "hash-" + metric.metricCode() + "-" + index,
                        "purpose interpretation " + index,
                        "PURPOSE_PASSED",
                        true,
                        "CUSTOMER_PROMPT_QUALITY",
                        List.of("RuntimeFact" + index),
                        List.of("ContextItem" + index),
                        createdAt));
            }
        }
        return rows;
    }

    private OfficialVerificationOperatorSnapshotService.OperatorMetricSnapshot operatorMetricSnapshot(
            String metricCode,
            String runId,
            String state,
            int passedChecks,
            int totalChecks,
            int failedChecks) {
        Instant createdAt = Instant.parse("2026-05-04T08:00:00Z");
        return new OfficialVerificationOperatorSnapshotService.OperatorMetricSnapshot(
                "agg-001",
                runId,
                "pkg-001",
                "cert-001",
                "case-001",
                metricCode,
                metricCode + " 지표",
                "프롬프트 품질",
                failedChecks == 0 ? 100.0d : 90.0d,
                state,
                failedChecks == 0 ? "NONE" : "HIGH",
                passedChecks,
                totalChecks,
                failedChecks,
                failedChecks == 0 ? "" : "요청 증거 연결이 부족합니다",
                failedChecks == 0 ? "공식 지표 스냅샷이 최신 결과를 제공합니다." : "공식 검사는 실행됐지만 증거 연결을 보강해야 합니다.",
                failedChecks == 0 ? "" : "봉인 증거와 공식 지표 원장의 연결 근거가 부족합니다.",
                "RUNTIME_EVIDENCE",
                failedChecks == 0 ? "" : "봉인 증거와 공식 지표 원장 연결을 보강하십시오.",
                failedChecks == 0 ? "" : "같은 리소스를 다시 요청했을 때 지표가 통과해야 합니다.",
                createdAt);
    }

    private RuntimeEvidencePackageDetail sealedEvidence() {
        return new RuntimeEvidencePackageDetail(
                new RuntimeEvidencePackageSummary(
                        "pkg-001",
                        "corr-001",
                        "tenant-a",
                        "user-a",
                        Instant.parse("2026-04-27T08:30:00Z"),
                        "/contexa/admin/api/orders",
                        "orders.list",
                        "GET",
                        "ALLOW",
                        0.91d,
                        true,
                        true,
                        "prompt-hash-001",
                        1200,
                        "봉인 완료",
                        "공식검사를 실행하십시오."),
                true,
                true,
                true,
                true,
                true,
                true,
                "system prompt systemPromptHash sha256:system-001",
                """
                        user prompt requestId req-001 correlationId corr-001 tenantId tenant-a userId user-a
                        clientIp 10.0.0.7 requestPath /admin/api/orders httpMethod GET resourceId orders.list
                        mfaVerified true authMethod MFA authorizationEffect ALLOW effectiveRoles ROLE_ADMIN effectivePermissions orders:read
                        baseline observed profile rag retrieval decisionAction ALLOW
                        """,
                Map.of(
                        "requestId", "req-001",
                        "clientIp", "10.0.0.7"),
                Map.of(
                        "mfaVerified", "true",
                        "authMethod", "MFA",
                        "authorizationEffect", "ALLOW",
                        "effectiveRoles", "ROLE_ADMIN",
                        "effectivePermissions", "orders:read"),
                Map.of(
                        "promptHash", "prompt-hash-001",
                        "systemPromptHash", "sha256:system-001",
                        "userPromptHash", "sha256:user-001",
                        "promptVersion", "v1",
                        "modelProfile", "zt-mini",
                        "contextHash", "context-hash-001"),
                Map.of("action", "ALLOW"),
                List.of(),
                List.of(),
                RuntimeEvidencePromptConsistencyResult.empty());
    }

    private SealedEvidenceOfficialRunView rapRunWithNotApplicableDocumentCheck() {
        return new SealedEvidenceOfficialRunView(
                "run-rap-001",
                1,
                "RAP",
                "/contexa/admin/api/orders",
                "req-001",
                100.0d,
                1,
                1,
                12L,
                "success",
                "success",
                "success",
                "2026-04-27 17:30:00",
                "2026-04-27 17:30:01",
                List.of(
                        new SealedEvidenceOfficialRunView.SealedEvidenceCheckView(
                                "RAG_SEARCH_STATE_EXPLAINED",
                                "RAG search state explained",
                                "RAG search state must be clear.",
                                "RAG search state is clear.",
                                true,
                                "finalUserPrompt.rag.searchState",
                                "INFO",
                                "",
                                "RAG_AUTHORIZATION_FILTER",
                                "RAG search produced no documents and the zero-result state is explicit.",
                                "",
                                "",
                                "finalUserPrompt.rag.searchState",
                                true,
                                "CUSTOMER_PROMPT_QUALITY",
                                "final-user-prompt.v1",
                                "READY",
                                "PASSED",
                                "[\"ragSearchExecuted=true\",\"ragRetrievalState=ZERO_RESULTS\"]",
                                "[]",
                                "RAG search state must be visible.",
                                "The LLM must not treat zero-result RAG as authorized document evidence."),
                        new SealedEvidenceOfficialRunView.SealedEvidenceCheckView(
                                "RAG_AUTHORIZATION_REASON_PRESENT",
                                "RAG document authorization not applicable",
                                "RAG documents require authorization reason when documents exist.",
                                "RAG document checks are not applicable because this request retrieved no documents.",
                                true,
                                "internalGate.metricApplicability.RAP.RAG_AUTHORIZATION_REASON_PRESENT",
                                "INFO",
                                "",
                                "RAG_AUTHORIZATION_FILTER",
                                "No retrieved RAG document surface exists.",
                                "",
                                "",
                                "internalGate.metricApplicability.RAP.RAG_AUTHORIZATION_REASON_PRESENT",
                                false,
                                "INTERNAL_REFERENCE",
                                "final-user-prompt.v1",
                                "NOT_APPLICABLE",
                                "NOT_APPLICABLE",
                                "[\"ragText=empty\",\"ragRetrievalState=ZERO_RESULTS\",\"relatedDocumentCount=0\"]",
                                "[]",
                                "RAG document authorization applies only to retrieved documents.",
                                "Zero-result RAG must not be displayed as document authorization success.")),
                Map.ofEntries(
                        Map.entry("requestId", "req-001"),
                        Map.entry("tenantId", "tenant-a"),
                        Map.entry("userId", "user-a"),
                        Map.entry("requestPath", "/contexa/admin/api/orders")),
                Map.of("requestId", "req-001"),
                Map.ofEntries(
                        Map.entry("promptHash", "prompt-hash-001"),
                        Map.entry("userPromptHash", "sha256:user-001")),
                Map.of("ragRetrievalState", "ZERO_RESULTS"),
                List.of(),
                Map.of("packageId", "pkg-001"));
    }

    private SealedEvidenceOfficialRunView rapRunWithOnlyNotApplicableChecks() {
        return new SealedEvidenceOfficialRunView(
                "run-rap-na-001",
                1,
                "RAP",
                "/contexa/admin/api/orders",
                "req-001",
                0.0d,
                0,
                0,
                12L,
                "NOT_APPLICABLE",
                "neutral",
                "RAG document checks are not applicable because this request retrieved no documents.",
                "2026-04-27 17:30:00",
                "2026-04-27 17:30:01",
                List.of(new SealedEvidenceOfficialRunView.SealedEvidenceCheckView(
                        "RAG_AUTHORIZATION_REASON_PRESENT",
                        "RAG document authorization not applicable",
                        "RAG documents require authorization reason when documents exist.",
                        "RAG document checks are not applicable because this request retrieved no documents.",
                        true,
                        "internalGate.metricApplicability.RAP.RAG_AUTHORIZATION_REASON_PRESENT",
                        "INFO",
                        "",
                        "RAG_AUTHORIZATION_FILTER",
                        "No retrieved RAG document surface exists.",
                        "",
                        "",
                        "internalGate.metricApplicability.RAP.RAG_AUTHORIZATION_REASON_PRESENT",
                        false,
                        "INTERNAL_REFERENCE",
                        "final-user-prompt.v1",
                        "NOT_APPLICABLE",
                        "NOT_APPLICABLE",
                        "[\"purposeSignal=rag_document_authorization_reason\",\"meaning=RAG document authorization applies only when documents exist.\",\"securityRelevance=RAG document authorization must not be claimed when no document exists.\",\"ragRetrievalState=ZERO_RESULTS\",\"relatedDocumentCount=0\"]",
                        "[]",
                        "RAG document authorization applies only to retrieved documents.",
                        "Zero-result RAG must not be displayed as document authorization success.")),
                Map.ofEntries(
                        Map.entry("requestId", "req-001"),
                        Map.entry("tenantId", "tenant-a"),
                        Map.entry("userId", "user-a"),
                        Map.entry("requestPath", "/contexa/admin/api/orders")),
                Map.of("requestId", "req-001"),
                Map.ofEntries(
                        Map.entry("promptHash", "prompt-hash-001"),
                        Map.entry("userPromptHash", "sha256:user-001")),
                Map.of("ragRetrievalState", "ZERO_RESULTS"),
                List.of(),
                Map.of("packageId", "pkg-001"));
    }

    private SealedEvidenceOfficialRunView corRunWithOnlyNotApplicableChecks() {
        return new SealedEvidenceOfficialRunView(
                "run-cor-na-001",
                1,
                "COR",
                "/contexa/admin/api/orders",
                "req-001",
                0.0d,
                0,
                0,
                12L,
                "NOT_APPLICABLE",
                "neutral",
                "RAG contamination checks are not applicable because this request retrieved no documents.",
                "2026-04-27 17:30:00",
                "2026-04-27 17:30:01",
                List.of(new SealedEvidenceOfficialRunView.SealedEvidenceCheckView(
                        "NO_PROMPT_INJECTION_TEXT",
                        "RAG contamination not applicable",
                        "RAG prompt-injection checks apply only when retrieved text exists.",
                        "No retrieved RAG document surface exists for this request.",
                        true,
                        "internalGate.metricApplicability.COR.NO_PROMPT_INJECTION_TEXT",
                        "INFO",
                        "",
                        "RAG_CONTAMINATION_FILTER",
                        "No retrieved RAG document surface exists.",
                        "",
                        "",
                        "internalGate.metricApplicability.COR.NO_PROMPT_INJECTION_TEXT",
                        false,
                        "INTERNAL_REFERENCE",
                        "final-user-prompt.v1",
                        "NOT_APPLICABLE",
                        "NOT_APPLICABLE",
                        "[\"purposeSignal=rag_contamination_surface\",\"meaning=RAG contamination checks apply only when retrieved documents exist.\",\"securityRelevance=RAG contamination must not be claimed when no document exists.\",\"ragRetrievalState=ZERO_RESULTS\",\"relatedDocumentCount=0\"]",
                        "[]",
                        "RAG contamination checks apply only when retrieved documents exist.",
                        "Zero-result RAG must not be displayed as contamination success.")),
                Map.ofEntries(
                        Map.entry("requestId", "req-001"),
                        Map.entry("tenantId", "tenant-a"),
                        Map.entry("userId", "user-a"),
                        Map.entry("requestPath", "/contexa/admin/api/orders")),
                Map.of("requestId", "req-001"),
                Map.ofEntries(
                        Map.entry("promptHash", "prompt-hash-001"),
                        Map.entry("userPromptHash", "sha256:user-001")),
                Map.of("ragRetrievalState", "ZERO_RESULTS"),
                List.of(),
                Map.of("packageId", "pkg-001"));
    }

    private SealedEvidenceOfficialRunView corRunWithVisibleAndInternalReferenceChecks() {
        return new SealedEvidenceOfficialRunView(
                "run-cor-001",
                1,
                "COR",
                "/contexa/admin/api/orders",
                "req-001",
                100.0d,
                1,
                1,
                12L,
                "SUCCESS",
                "ready",
                "RAG contamination checks passed.",
                "2026-04-27 17:30:00",
                "2026-04-27 17:30:01",
                List.of(
                        new SealedEvidenceOfficialRunView.SealedEvidenceCheckView(
                                "RAG_APPLICABILITY_DECLARED",
                                "RAG search state explained",
                                "RAG applicability must be declared.",
                                "RAG applicability is declared.",
                                true,
                                "finalUserPrompt.rag.applicability",
                                "INFO",
                                "",
                                "RAG_CONTEXT_PRODUCER",
                                "RAG runtime state is visible.",
                                "",
                                "",
                                "finalUserPrompt.rag.applicability",
                                true,
                                "CUSTOMER_PROMPT_QUALITY",
                                "final-user-prompt.v1",
                                "READY",
                                "PURPOSE_PASSED",
                                "[\"purposeSignal=rag_applicability_declared\",\"meaning=RAG state is visible.\",\"securityRelevance=RAG state must be visible.\"]",
                                "[]",
                                "RAG state must be visible.",
                                "RAG state must stay visible."),
                        new SealedEvidenceOfficialRunView.SealedEvidenceCheckView(
                                "NO_RAG_CONTEXT_NO_CONTAMINATION_SURFACE",
                                "Internal contamination surface reference",
                                "Internal reference must not be displayed.",
                                "Internal reference passed.",
                                true,
                                "internalGate.metricApplicability.COR.NO_RAG_CONTEXT_NO_CONTAMINATION_SURFACE",
                                "INFO",
                                "",
                                "RAG_CONTAMINATION_FILTER",
                                "Internal reference only.",
                                "",
                                "",
                                "internalGate.metricApplicability.COR.NO_RAG_CONTEXT_NO_CONTAMINATION_SURFACE",
                                false,
                                "INTERNAL_REFERENCE",
                                "final-user-prompt.v1",
                                "READY",
                                "PURPOSE_PASSED",
                                "[\"purposeSignal=rag_contamination_surface\",\"meaning=Internal reference only.\"]",
                                "[]",
                                "Internal reference only.",
                                "Internal reference only.")),
                Map.ofEntries(
                        Map.entry("requestId", "req-001"),
                        Map.entry("tenantId", "tenant-a"),
                        Map.entry("userId", "user-a"),
                        Map.entry("requestPath", "/contexa/admin/api/orders")),
                Map.of("requestId", "req-001"),
                Map.ofEntries(
                        Map.entry("promptHash", "prompt-hash-001"),
                        Map.entry("userPromptHash", "sha256:user-001")),
                Map.of("ragRetrievalState", "AVAILABLE"),
                List.of(),
                Map.of("packageId", "pkg-001"));
    }

    private SealedEvidenceOfficialRunView failedRun() {
        return new SealedEvidenceOfficialRunView(
                "run-eir-001",
                1,
                "EIR",
                "/contexa/admin/api/orders",
                "req-001",
                0.5d,
                1,
                2,
                12L,
                "failed",
                "danger",
                "failed",
                "2026-04-27 17:30:00",
                "2026-04-27 17:30:01",
                List.of(
                        new SealedEvidenceOfficialRunView.SealedEvidenceCheckView(
                                "correlationId present",
                                "pass",
                                "pass",
                                true,
                                "coreEvidenceReplay"),
                        new SealedEvidenceOfficialRunView.SealedEvidenceCheckView(
                                "mfaVerified true",
                                "pass",
                                "fail",
                                false,
                                "coreEvidenceReplay")),
                Map.ofEntries(
                        Map.entry("requestId", "req-001"),
                        Map.entry("tenantId", "tenant-a"),
                        Map.entry("clientIp", "10.0.0.7"),
                        Map.entry("userId", "user-a"),
                        Map.entry("requestPath", "/contexa/admin/api/orders"),
                        Map.entry("httpMethod", "GET"),
                        Map.entry("resourceId", "orders.list"),
                        Map.entry("mfaVerified", "true"),
                        Map.entry("authMethod", "MFA"),
                        Map.entry("authorizationEffect", "ALLOW"),
                        Map.entry("effectiveRoles", "ROLE_ADMIN"),
                        Map.entry("effectivePermissions", "orders:read"),
                        Map.entry("decisionAction", "ALLOW")),
                Map.of(
                        "requestId", "req-001",
                        "correlationId", "corr-001"),
                Map.ofEntries(
                        Map.entry("promptHash", "prompt-hash-001"),
                        Map.entry("systemPromptHash", "sha256:system-001"),
                        Map.entry("userPromptHash", "sha256:user-001"),
                        Map.entry("promptVersion", "v1"),
                        Map.entry("modelProfile", "zt-mini"),
                        Map.entry("contextHash", "context-hash-001"),
                        Map.entry("baselineSnapshotCaptured", "true"),
                        Map.entry("ragResultsCaptured", "true"),
                        Map.entry("rawSystemPromptCaptured", "true"),
                        Map.entry("rawUserPromptCaptured", "true"),
                        Map.entry("llmSystemPromptCaptured", "true"),
                        Map.entry("llmUserPromptCaptured", "true")),
                Map.of(
                        "sourceMode", "CORE_OFFICIAL_SEALED_EVIDENCE",
                        "sealedEvidencePackageId", "pkg-001"),
                List.of(new SealedEvidenceOfficialRunView.SealedEvidenceEventView(
                        "SEALED_EVIDENCE_REPLAY",
                        "CORE_OFFICIAL_RUNTIME",
                        "BLOCKED",
                        "/contexa/admin/api/orders")),
                Map.of(
                        "packageId", "pkg-001",
                        "requestId", "req-001",
                        "promptHash", "prompt-hash-001",
                        "contextHash", "context-hash-001"));
    }

    private SealedEvidenceOfficialRunView officialRun(
            String runId,
            String metricCode,
            String aggregateRunId,
            String state,
            int passedChecks,
            int totalChecks,
            String startedAt,
            String completedAt) {
        boolean passed = "SUCCESS".equalsIgnoreCase(state) || "PASS".equalsIgnoreCase(state);
        return new SealedEvidenceOfficialRunView(
                runId,
                1,
                metricCode,
                "/contexa/admin/api/orders",
                "req-001",
                passed ? 1.0d : 0.5d,
                passedChecks,
                totalChecks,
                12L,
                state,
                passed ? "ready" : "danger",
                passed ? "passed" : "failed",
                startedAt,
                completedAt,
                List.of(new SealedEvidenceOfficialRunView.SealedEvidenceCheckView(
                        "mfaVerified true",
                        "pass",
                        passed ? "pass" : "fail",
                        passed,
                        "coreEvidenceReplay")),
                Map.ofEntries(
                        Map.entry("requestId", "req-001"),
                        Map.entry("tenantId", "tenant-a"),
                        Map.entry("clientIp", "10.0.0.7"),
                        Map.entry("userId", "user-a"),
                        Map.entry("requestPath", "/contexa/admin/api/orders"),
                        Map.entry("httpMethod", "GET"),
                        Map.entry("resourceId", "orders.list"),
                        Map.entry("mfaVerified", "true"),
                        Map.entry("authMethod", "MFA"),
                        Map.entry("authorizationEffect", "ALLOW"),
                        Map.entry("effectiveRoles", "ROLE_ADMIN"),
                        Map.entry("effectivePermissions", "orders:read"),
                        Map.entry("decisionAction", "ALLOW")),
                Map.of(
                        "requestId", "req-001",
                        "correlationId", "corr-001"),
                Map.ofEntries(
                        Map.entry("promptHash", "prompt-hash-001"),
                        Map.entry("systemPromptHash", "sha256:system-001"),
                        Map.entry("userPromptHash", "sha256:user-001"),
                        Map.entry("promptVersion", "v1"),
                        Map.entry("modelProfile", "zt-mini"),
                        Map.entry("contextHash", "context-hash-001"),
                        Map.entry("baselineSnapshotCaptured", "true"),
                        Map.entry("ragResultsCaptured", "true"),
                        Map.entry("rawSystemPromptCaptured", "true"),
                        Map.entry("rawUserPromptCaptured", "true"),
                        Map.entry("llmSystemPromptCaptured", "true"),
                        Map.entry("llmUserPromptCaptured", "true")),
                Map.of(
                        "sourceMode", "CORE_OFFICIAL_SEALED_EVIDENCE",
                        "sealedEvidencePackageId", "pkg-001"),
                List.of(new SealedEvidenceOfficialRunView.SealedEvidenceEventView(
                        "SEALED_EVIDENCE_REPLAY",
                        "CORE_OFFICIAL_RUNTIME",
                        passed ? "PASSED" : "BLOCKED",
                        "/contexa/admin/api/orders")),
                Map.of(
                        "packageId", "pkg-001",
                        "aggregateRunId", aggregateRunId,
                        "requestId", "req-001",
                        "promptHash", "prompt-hash-001",
                        "contextHash", "context-hash-001"));
    }
}
