package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.testsupport.PromptQualityTestResolvers;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationVerdict;
import io.contexa.contexacore.verification.adjudication.ScorecardResult;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.metric.OfficialVerificationMetricDefinition;
import io.contexa.contexacore.verification.replay.DeterministicReplayResult;
import io.contexa.contexacore.verification.runtime.OfficialVerificationCheckState;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexacore.verification.runtime.sealed.OfficialSealedEvidenceVerificationResult;
import io.contexa.contexacore.verification.runtime.sealed.OfficialSealedEvidenceVerificationRuntime;
import io.contexa.contexacore.verification.runtime.sealed.SealedEvidenceOfficialRunView;
import io.contexa.contexaiam.admin.promptquality.official.application.DefaultPromptQualityRuntimeVerificationService;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationExecutionLockService;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationPromptComparison;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationGateCode;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceCheckResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceGateResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceMetricResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePromptConsistencyResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRequest;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceVerificationRun;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityAssuranceCase;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityAssuranceScope;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessCodes;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessRunService;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessStepSnapshot;


import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class DefaultPromptQualityRuntimeVerificationServiceTest {
    private DefaultPromptQualityRuntimeVerificationService service(
            SealedEvidencePackageQueryService lookupService,
            RuntimeEvidenceReplayService replayService,
            RuntimeEvidencePromptScorecardService promptScorecardService,
            OfficialSealedEvidenceVerificationRuntime officialRuntime,
            PromptQualityRuntimeCertificationPolicy certificationPolicy,
            PromptQualityProtectableResourceLookup resourceLookup,
            PromptQualityOfficialMetricCatalog metricCatalog,
            PromptQualityAssuranceCaseService assuranceCaseService,
            RuntimeIssueDiagnosticService diagnosticService,
            PromptQualityMessageResolver messageResolver,
            ObjectMapper objectMapper,
            RuntimeEvidencePromptConsistencyGate consistencyGate,
            PromptQualityProcessRunService processRunService) {
        OfficialVerificationOperatorSnapshotService snapshotService =
                mock(OfficialVerificationOperatorSnapshotService.class);
        when(snapshotService.replaceDiagnosticsForQualityTarget(any(), any(), any(), any(), any()))
                .thenReturn(List.of());
        when(snapshotService.promptComparisons(any(), any())).thenReturn(List.of());
        when(snapshotService.actualPromptProblems(any(), any())).thenReturn(List.of());

        OfficialVerificationExecutionLockService lockService = mock(OfficialVerificationExecutionLockService.class);
        when(lockService.start(any())).thenAnswer(invocation -> {
            OfficialVerificationExecutionLockService.ExecutionRequest request = invocation.getArgument(0);
            return new OfficialVerificationExecutionLockService.ExecutionRecord(
                    1L,
                    request.idempotencyKey(),
                    request.baseIdempotencyKey(),
                    request.packageId(),
                    request.tenantId(),
                    null,
                    1,
                    1,
                    OfficialVerificationExecutionLockService.STATE_LOCK_ACQUIRED,
                    0,
                    null,
                    null,
                    null,
                    null,
                    request.requestedBy(),
                    request.reverificationReason(),
                    request.requestFingerprintJson(),
                    null,
                    Instant.EPOCH,
                    null,
                    null,
                    Instant.EPOCH,
                    Instant.EPOCH,
                    true);
        });
        when(lockService.completedResult(any())).thenReturn(Optional.empty());

        return service(
                lookupService,
                replayService,
                promptScorecardService,
                officialRuntime,
                certificationPolicy,
                resourceLookup,
                metricCatalog,
                assuranceCaseService,
                diagnosticService,
                messageResolver != null ? messageResolver : PromptQualityTestResolvers.englishBundle(),
                objectMapper,
                consistencyGate,
                snapshotService,
                processRunService,
                lockService);
    }

    private DefaultPromptQualityRuntimeVerificationService service(
            SealedEvidencePackageQueryService lookupService,
            RuntimeEvidenceReplayService replayService,
            RuntimeEvidencePromptScorecardService promptScorecardService,
            OfficialSealedEvidenceVerificationRuntime officialRuntime,
            PromptQualityRuntimeCertificationPolicy certificationPolicy,
            PromptQualityProtectableResourceLookup resourceLookup,
            PromptQualityOfficialMetricCatalog metricCatalog,
            PromptQualityAssuranceCaseService assuranceCaseService,
            RuntimeIssueDiagnosticService diagnosticService,
            PromptQualityMessageResolver messageResolver,
            ObjectMapper objectMapper,
            RuntimeEvidencePromptConsistencyGate consistencyGate,
            OfficialVerificationOperatorSnapshotService snapshotService,
            PromptQualityProcessRunService processRunService,
            OfficialVerificationExecutionLockService lockService) {
        PromptQualityMessageResolver resolver = messageResolver != null
                ? messageResolver
                : PromptQualityTestResolvers.englishBundle();
        OfficialVerificationResourceResolver resourceResolver =
                new OfficialVerificationResourceResolver(resourceLookup);
        OfficialVerificationEvidencePreflight evidencePreflight = new OfficialVerificationEvidencePreflight(
                lookupService, replayService, promptScorecardService, consistencyGate,
                resourceResolver, objectMapper, resolver);
        OfficialVerificationMetricContract metricContract =
                new OfficialVerificationMetricContract(metricCatalog, officialRuntime);
        OfficialVerificationProgressRecorder progressRecorder = new OfficialVerificationProgressRecorder(
                processRunService, snapshotService, lockService, resolver);
        OfficialVerificationExecutionLedger executionLedger = new OfficialVerificationExecutionLedger(
                lockService, snapshotService, metricContract, evidencePreflight, objectMapper, resolver);
        PromptComparisonValueInterpreter values = new PromptComparisonValueInterpreter(resolver);
        OfficialVerificationResultAssembler resultAssembler = new OfficialVerificationResultAssembler(
                new OfficialVerificationFailureAssembler(resolver),
                new OfficialVerificationPromptComparisonAssembler(
                        new SealedPromptEvidenceComparisonAssembler(objectMapper, resolver, values),
                        values,
                        resolver),
                new OfficialVerificationMetricResultAssembler(metricCatalog, resolver),
                new OfficialVerificationCustomerNarrativeAssembler(metricCatalog, resolver));
        OfficialVerificationResultCoordinator resultCoordinator = new OfficialVerificationResultCoordinator(
                assuranceCaseService, diagnosticService, progressRecorder, resultAssembler,
                snapshotService, executionLedger, resolver);
        OfficialVerificationReverificationCoordinator reverificationCoordinator =
                new OfficialVerificationReverificationCoordinator(snapshotService, progressRecorder, resolver);
        return new DefaultPromptQualityRuntimeVerificationService(
                officialRuntime,
                evidencePreflight,
                certificationPolicy,
                metricContract,
                progressRecorder,
                executionLedger,
                resultCoordinator,
                reverificationCoordinator);
    }

    @Test
    void promptEvidenceManifestComparisonsDeduplicateActualPromptProblemsAndKeepFinalPromptFields() throws Exception {
        DefaultPromptQualityRuntimeVerificationService service = runtimeService();
        SealedEvidencePackage pkg = SealedEvidencePackage.builder()
                .packageId("sep-sync-001")
                .promptEvidenceManifestJson("""
                        {
                          "fields": [
                            {
                              "fieldKey": "baseline.eventCount",
                              "displayName": "Baseline observation count",
                              "promptValue": null,
                              "evidenceValue": "19",
                              "projectionState": "MISSING_IN_PROMPT",
                              "requiredLevel": "P0_REQUIRED",
                              "metricCodes": ["BMA"],
                              "evidenceSection": "baselineSnapshot",
                              "evidencePath": "eventCount",
                              "producer": "LEARNING_CONTEXT"
                            },
                            {
                              "fieldKey": "baseline.eventCount",
                              "displayName": "Baseline observation count",
                              "promptValue": null,
                              "evidenceValue": "19",
                              "projectionState": "MISSING_IN_PROMPT",
                              "requiredLevel": "P0_REQUIRED",
                              "metricCodes": ["BMA"],
                              "evidenceSection": "baselineSnapshot",
                              "evidencePath": "eventCount",
                              "producer": "LEARNING_CONTEXT"
                            },
                            {
                              "fieldKey": "tenantId",
                              "displayName": "Tenant ID",
                              "promptValue": "demo",
                              "evidenceValue": "demo",
                              "projectionState": "PRESENT",
                              "requiredLevel": "P0_REQUIRED",
                              "metricCodes": ["CCR"],
                              "evidenceSection": "requestFacts",
                              "evidencePath": "tenantId",
                              "producer": "REQUEST_CONTEXT"
                            }
                          ],
                          "fieldStateLedger": [
                            {
                              "sourceType": "FINAL_USER_PROMPT_FIELD",
                              "fieldKey": "final.RESOURCE_AND_ACTION_CONTEXT.ResourceId",
                              "promptLabel": "ResourceId",
                              "valuePreview": "resource-001",
                              "fieldState": "VALUE_PRESENT",
                              "blockingCandidate": false,
                              "metricCodes": ["PRE"],
                              "promptSection": "RESOURCE AND ACTION CONTEXT",
                              "sourceFieldPath": "userPrompt.ResourceId",
                              "remediationOwner": "REQUEST_CONTEXT"
                            },
                            {
                              "sourceType": "PROMPT_PROJECTION_DIFF",
                              "fieldKey": "baseline.eventCount",
                              "promptLabel": "BaselineObservations",
                              "valuePreview": "19",
                              "fieldState": "REQUIRED_MISSING",
                              "blockingCandidate": true,
                              "metricCodes": ["BMA"],
                              "promptSection": "PERSONAL WORK PROFILE",
                              "sourceFieldPath": "baselineSnapshot.eventCount",
                              "remediationOwner": "LEARNING_CONTEXT"
                            }
                          ]
                        }
                        """)
                .build();

        List<OfficialVerificationPromptComparison> comparisons = promptComparisons(pkg, List.of());

        assertThat(comparisons)
                .extracting(OfficialVerificationPromptComparison::fieldKey)
                .containsExactly(
                        "baseline.eventCount",
                        "tenantId",
                        "final.RESOURCE_AND_ACTION_CONTEXT.ResourceId",
                        "baseline.eventCount");
        assertThat(comparisons.stream().filter(this::blockingPromptComparison).count()).isEqualTo(2);
    }

    @Test
    void promptEvidenceManifestComparisonsKeepDistinctProblemsForSameField() throws Exception {
        DefaultPromptQualityRuntimeVerificationService service = runtimeService();
        SealedEvidencePackage pkg = SealedEvidencePackage.builder()
                .packageId("sep-sync-002")
                .promptEvidenceManifestJson("""
                        {
                          "fields": [
                            {
                              "fieldKey": "baseline.eventCount",
                              "displayName": "Baseline observation count",
                              "promptValue": null,
                              "evidenceValue": "19",
                              "projectionState": "MISSING_IN_PROMPT",
                              "requiredLevel": "P0_REQUIRED",
                              "metricCodes": ["BMA"],
                              "evidenceSection": "baselineSnapshot",
                              "evidencePath": "eventCount",
                              "producer": "LEARNING_CONTEXT"
                            }
                          ],
                          "fieldStateLedger": [
                            {
                              "sourceType": "PROMPT_PROJECTION_DIFF",
                              "fieldKey": "baseline.eventCount",
                              "promptLabel": "BaselineObservations",
                              "valuePreview": "event count differs",
                              "fieldState": "CONTRACT_MISMATCH",
                              "blockingCandidate": true,
                              "metricCodes": ["BMA"],
                              "promptSection": "PERSONAL WORK PROFILE",
                              "sourceFieldPath": "baselineSnapshot.eventCount",
                              "remediationOwner": "LEARNING_CONTEXT"
                            }
                          ]
                        }
                        """)
                .build();

        List<OfficialVerificationPromptComparison> comparisons = promptComparisons(pkg, List.of());

        assertThat(comparisons)
                .extracting(OfficialVerificationPromptComparison::state)
                .containsExactlyInAnyOrder("PROMPT_MISSING", "CONTRACT_MISMATCH");
        assertThat(comparisons)
                .extracting(OfficialVerificationPromptComparison::fieldKey)
                .containsExactly("baseline.eventCount", "baseline.eventCount");
    }

    @Test
    void promptExecutionMetadataProblemLedgersAreIncludedInOfficialMetricInput() throws Exception {
        DefaultPromptQualityRuntimeVerificationService service = runtimeService();
        SealedEvidencePackage pkg = SealedEvidencePackage.builder()
                .packageId("sep-sync-003")
                .promptEvidenceManifestJson("""
                        {
                          "fields": [],
                          "fieldStateLedger": []
                        }
                        """)
                .promptExecutionMetadataJson("""
                        {
                          "promptFinalUserFieldLedger": [
                            {
                              "fieldKey": "baseline.eventCount",
                              "label": "Baseline observation count",
                              "valuePreview": "",
                              "fieldState": "REQUIRED_MISSING",
                              "blockingCandidate": true,
                              "metricCodes": ["BMA"],
                              "sectionTitle": "PERSONAL WORK PROFILE",
                              "remediationOwner": "LEARNING_CONTEXT"
                            }
                          ],
                          "promptUserFieldDiffLedger": [
                            {
                              "fieldKey": "prompt.rawTruthParity",
                              "label": "Raw and final prompt parity",
                              "diffType": "VALUE_CHANGED",
                              "reason": "raw and final prompt field values differ",
                              "officialBlockingCandidate": true,
                              "metricCodes": ["PFR"],
                              "sectionTitle": "PROMPT METADATA",
                              "remediationOwner": "PROMPT_ASSEMBLER"
                            }
                          ]
                        }
                        """)
                .build();

        List<OfficialVerificationPromptComparison> comparisons = promptComparisons(pkg, List.of());

        assertThat(comparisons)
                .extracting(OfficialVerificationPromptComparison::state)
                .containsExactlyInAnyOrder("REQUIRED_MISSING", "CONTRACT_MISMATCH");
        assertThat(comparisons)
                .allSatisfy(comparison -> assertThat(comparison.metricCodes()).isNotEmpty());
    }

    @Test
    void promptExecutionMetadataRowsWithoutProblemStateDoNotCrashSnapshotWriting() throws Exception {
        DefaultPromptQualityRuntimeVerificationService service = runtimeService();
        SealedEvidencePackage pkg = SealedEvidencePackage.builder()
                .packageId("sep-sync-null-state")
                .promptEvidenceManifestJson("""
                        {
                          "fields": [],
                          "fieldStateLedger": []
                        }
                        """)
                .promptExecutionMetadataJson("""
                        {
                          "promptFinalUserFieldLedger": [
                            {
                              "fieldKey": "request.requestId",
                              "label": "Request ID",
                              "valuePreview": "request-001",
                              "blockingCandidate": true,
                              "metricCodes": ["CCR"],
                              "sectionTitle": "CURRENT REQUEST AND EVENT",
                              "remediationOwner": "REQUEST_CONTEXT"
                            },
                            {
                              "fieldKey": "baseline.eventCount",
                              "label": "Baseline observation count",
                              "valuePreview": "",
                              "fieldState": "REQUIRED_MISSING",
                              "blockingCandidate": true,
                              "metricCodes": ["BMA"],
                              "sectionTitle": "PERSONAL WORK PROFILE",
                              "remediationOwner": "LEARNING_CONTEXT"
                            }
                          ]
                        }
                        """)
                .build();

        List<OfficialVerificationPromptComparison> comparisons = promptComparisons(pkg, List.of());

        assertThat(comparisons)
                .extracting(OfficialVerificationPromptComparison::fieldKey)
                .containsExactly("baseline.eventCount");
        assertThat(comparisons)
                .extracting(OfficialVerificationPromptComparison::state)
                .containsExactly("REQUIRED_MISSING");
    }

    @Test
    void officialMetricRuntimeMustReturnEveryConfiguredPromptQualityMetric() throws Exception {
        PromptQualityOfficialMetricCatalog metricCatalog = mock(PromptQualityOfficialMetricCatalog.class);
        when(metricCatalog.promptQualityMetrics()).thenReturn(List.of(
                new OfficialVerificationMetricDefinition("EIR", "Evidence Integrity", "IMPLEMENTATION_ALIGNMENT", "", true, 1.0d, true),
                new OfficialVerificationMetricDefinition("BMA", "Baseline Maturity", "LEARNING_BASELINE", "", true, 1.0d, true)));
        OfficialVerificationMetricContract contract = new OfficialVerificationMetricContract(
                metricCatalog,
                mock(OfficialSealedEvidenceVerificationRuntime.class));

        assertThatThrownBy(() -> contract.assertComplete(List.of(officialMetricRun())))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void promptEvidenceManifestKeepsDeclaredAbsenceAndRagNotApplicableNonBlocking() throws Exception {
        DefaultPromptQualityRuntimeVerificationService service = runtimeService();
        SealedEvidencePackage pkg = SealedEvidencePackage.builder()
                .packageId("sep-rag-na-001")
                .promptEvidenceManifestJson("""
                        {
                          "fields": [
                            {
                              "fieldKey": "rag.relatedDocuments",
                              "displayName": "RAG document authorization evidence",
                              "promptValue": null,
                              "evidenceValue": null,
                              "projectionState": "MISSING_IN_BOTH",
                              "requiredLevel": "OPTIONAL",
                              "metricCodes": ["RAP"],
                              "evidenceSection": "ragResults",
                              "evidencePath": "relatedDocuments",
                              "producer": "RAG_CONTEXT"
                            },
                            {
                              "fieldKey": "roleScope.recentPermissionChanges",
                              "displayName": "Recent permission changes",
                              "promptValue": null,
                              "evidenceValue": null,
                              "projectionState": "DECLARED_ABSENCE",
                              "requiredLevel": "CONDITIONAL",
                              "metricCodes": ["CCR"],
                              "evidenceSection": "canonicalContext",
                              "evidencePath": "roleScope.recentPermissionChanges",
                              "producer": "AUTH_CONTEXT"
                            },
                            {
                              "fieldKey": "authState.mfaVerified",
                              "displayName": "MFA verified",
                              "promptValue": null,
                              "evidenceValue": "false",
                              "projectionState": "MISSING_IN_PROMPT",
                              "requiredLevel": "P0_REQUIRED",
                              "metricCodes": ["CCR"],
                              "evidenceSection": "authState",
                              "evidencePath": "mfaVerified",
                              "producer": "AUTH_CONTEXT"
                            }
                          ],
                          "fieldStateLedger": []
                        }
                        """)
                .build();

        List<OfficialVerificationPromptComparison> comparisons = promptComparisons(pkg, List.of());

        assertThat(comparisons)
                .filteredOn(comparison -> "rag.relatedDocuments".equals(comparison.fieldKey()))
                .singleElement()
                .extracting(OfficialVerificationPromptComparison::state)
                .isEqualTo("NOT_APPLICABLE");
        assertThat(comparisons)
                .filteredOn(comparison -> "roleScope.recentPermissionChanges".equals(comparison.fieldKey()))
                .singleElement()
                .extracting(OfficialVerificationPromptComparison::state)
                .isEqualTo("NOT_APPLICABLE");
        assertThat(comparisons.stream().filter(this::blockingPromptComparison).count()).isEqualTo(1);
    }

    @Test
    void executionComparisonsDoesNotUseLegacyFallbackWhenPromptEvidenceManifestIsMissing() throws Exception {
        DefaultPromptQualityRuntimeVerificationService service = runtimeService();
        SealedEvidencePackage pkg = SealedEvidencePackage.builder()
                .packageId("sep-without-manifest")
                .build();
        List<OfficialVerificationPromptComparison> result = promptComparisons(pkg, List.of());

        assertThat(result).isEqualTo(List.of());
    }

    @Test
    void metricResultsStoreOnlyBlockingActualPromptProblemsAsMetricChecks() throws Exception {
        PromptQualityOfficialMetricCatalog metricCatalog = mock(PromptQualityOfficialMetricCatalog.class);
        when(metricCatalog.promptQualityMetrics()).thenReturn(List.of(new OfficialVerificationMetricDefinition(
                "BMA",
                "Baseline Maturity Accuracy",
                "RAG_AND_BASELINE",
                "Baseline fields must be present in the final prompt.",
                true,
                1.0d,
                true)));
        DefaultPromptQualityRuntimeVerificationService service = runtimeService(metricCatalog);
        List<OfficialVerificationPromptComparison> promptComparisons = List.of(
                new OfficialVerificationPromptComparison(
                        "baseline.eventCount",
                        "Baseline observation count",
                        "19",
                        "",
                        "19",
                        "PROMPT_MISSING",
                        "Prompt missing",
                        "Baseline observation count is present in sealed evidence but not in the final prompt.",
                        List.of("BMA"),
                        "PERSONAL WORK PROFILE",
                        "sealedEvidence.baselineSnapshot.eventCount",
                        "LEARNING_CONTEXT"),
                new OfficialVerificationPromptComparison(
                        "tenantId",
                        "Tenant ID",
                        "demo",
                        "demo",
                        "demo",
                        "MATCH",
                        "Matched",
                        "Tenant ID is synchronized.",
                        List.of("BMA"),
                        "CURRENT REQUEST AND EVENT",
                        "sealedEvidence.requestFacts.tenantId",
                        "REQUEST_CONTEXT"));
        List<RuntimeEvidenceMetricResult> results = metricResults(
                metricCatalog,
                List.of(),
                promptComparisons,
                "sep-sync-001");

        assertThat(results).hasSize(1);
        RuntimeEvidenceMetricResult result = results.get(0);
        assertThat(result.metricCode()).isEqualTo("BMA");
        assertThat(result.checks()).hasSize(1);
        assertThat(result.checks()).allSatisfy(check -> {
            assertThat(check.pass()).isFalse();
            assertThat(check.checkCode()).startsWith("app-");
        });
        assertThat(result.totalChecks()).isEqualTo(1);
        assertThat(result.passedChecks()).isZero();
    }

    @Test
    void metricResultsBindOneActualPromptProblemToEveryAffectedMetric() throws Exception {
        PromptQualityOfficialMetricCatalog metricCatalog = mock(PromptQualityOfficialMetricCatalog.class);
        when(metricCatalog.promptQualityMetrics()).thenReturn(List.of(
                new OfficialVerificationMetricDefinition(
                        "BMA",
                        "Baseline Maturity Accuracy",
                        "RAG_AND_BASELINE",
                        "Baseline fields must be present in the final prompt.",
                        true,
                        1.0d,
                        true),
                new OfficialVerificationMetricDefinition(
                        "USNS",
                        "User-Specific Novelty Sensitivity",
                        "BEHAVIOR_CONTEXT",
                        "Novelty signals must be represented in the final prompt.",
                        true,
                        1.0d,
                        true)));
        DefaultPromptQualityRuntimeVerificationService service = runtimeService(metricCatalog);
        List<OfficialVerificationPromptComparison> promptComparisons = List.of(new OfficialVerificationPromptComparison(
                "baseline.noveltySignals.time",
                "Access hour novelty signal",
                "OUTSIDE_OBSERVED",
                "",
                "OUTSIDE_OBSERVED",
                "PROMPT_MISSING",
                "Prompt missing",
                "Access hour novelty signal is present in sealed evidence but not in the final prompt.",
                List.of("BMA", "USNS"),
                "PERSONAL WORK PROFILE",
                "sealedEvidence.baselineSnapshot.noveltySignals.time",
                "LEARNING_CONTEXT"));
        List<RuntimeEvidenceMetricResult> results = metricResults(
                metricCatalog,
                List.of(),
                promptComparisons,
                "sep-sync-001");

        assertThat(results).hasSize(2);
        assertThat(results).extracting(RuntimeEvidenceMetricResult::metricCode).containsExactly("BMA", "USNS");
        String problemId = results.get(0).checks().get(0).checkCode();
        assertThat(problemId).startsWith("app-");
        assertThat(results)
                .allSatisfy(result -> {
                    assertThat(result.checks()).hasSize(1);
                    assertThat(result.checks().get(0).pass()).isFalse();
                    assertThat(result.checks().get(0).checkCode()).isEqualTo(problemId);
                });
    }

    @Test
    void metricResultsDoNotCarryLegacyFailedStateWhenActualPromptProblemLedgerPasses() throws Exception {
        PromptQualityOfficialMetricCatalog metricCatalog = mock(PromptQualityOfficialMetricCatalog.class);
        when(metricCatalog.promptQualityMetrics()).thenReturn(List.of(new OfficialVerificationMetricDefinition(
                "BMA",
                "Baseline Maturity Accuracy",
                "RAG_AND_BASELINE",
                "Baseline fields must be present in the final prompt.",
                true,
                1.0d,
                true)));
        DefaultPromptQualityRuntimeVerificationService service = runtimeService(metricCatalog);
        SealedEvidenceOfficialRunView legacyFailedRun = new SealedEvidenceOfficialRunView(
                "legacy-bma-run",
                1,
                "BMA",
                "Baseline Maturity Accuracy",
                "request-001",
                100.0d,
                1,
                1,
                10L,
                "threshold_failed",
                "danger",
                "Legacy core state failed before actual prompt ledger reconciliation.",
                null,
                null,
                List.of(new SealedEvidenceOfficialRunView.SealedEvidenceCheckView(
                        "Legacy check",
                        "legacy expected",
                        "legacy actual",
                        true,
                        "legacy")),
                Map.of(),
                Map.of(),
                Map.of(),
                Map.of(),
                List.of(),
                Map.of());
        List<RuntimeEvidenceMetricResult> results = metricResults(
                metricCatalog,
                List.of(legacyFailedRun),
                List.of(),
                "sep-sync-001");

        assertThat(results).hasSize(1);
        RuntimeEvidenceMetricResult result = results.get(0);
        assertThat(result.metricCode()).isEqualTo("BMA");
        assertThat(result.state()).isEqualTo("SUCCESS");
        assertThat(result.checks()).isEmpty();
        assertThat(result.score()).isEqualTo(100.0d);
        assertThat(result.passedChecks()).isEqualTo(result.totalChecks());
    }

    @Test
    void metricResultsPreserveNotApplicableStateWhenAllChecksAreNotApplicable() throws Exception {
        PromptQualityOfficialMetricCatalog metricCatalog = mock(PromptQualityOfficialMetricCatalog.class);
        when(metricCatalog.promptQualityMetrics()).thenReturn(List.of(new OfficialVerificationMetricDefinition(
                "RAP",
                "RAG Authorization Precision",
                "RAG_AND_BASELINE",
                "RAG evidence must be authorized when documents exist.",
                true,
                1.0d,
                true)));
        DefaultPromptQualityRuntimeVerificationService service = runtimeService(metricCatalog);
        SealedEvidenceOfficialRunView rapRun = new SealedEvidenceOfficialRunView(
                "official-run-rap-001",
                1,
                "RAP",
                "RAG Authorization Precision",
                "request-001",
                100.0d,
                0,
                0,
                10L,
                "not_applicable",
                "warning",
                "No RAG documents were retrieved for this request.",
                "2026-04-28 09:00:00",
                "2026-04-28 09:00:01",
                List.of(new SealedEvidenceOfficialRunView.SealedEvidenceCheckView(
                        "RAP_RAG_AUTHORIZATION_REASON_PRESENT",
                        "RAG authorization reason is not applicable",
                        "RAG documents require authorization reason when documents exist.",
                        "No RAG document was retrieved for this request.",
                        true,
                        "internalGate.metricApplicability.RAP.RAG_AUTHORIZATION_REASON_PRESENT",
                        "INFO",
                        "",
                        "RAG_AUTHORIZATION_FILTER",
                        "The request has no retrieved RAG document surface to authorize.",
                        "",
                        "When documents are retrieved, authorization reason must be evaluated.",
                        "internalGate.metricApplicability.RAP.RAG_AUTHORIZATION_REASON_PRESENT",
                        false,
                        "INTERNAL_REFERENCE",
                        "final-user-prompt.v1",
                        "NOT_APPLICABLE",
                        "NOT_APPLICABLE",
                        "[\"ragText=empty\",\"ragRetrievalState=ZERO_RESULTS\",\"relatedDocumentCount=0\"]",
                        "[{\"signal\":\"No RAG document surface\",\"meaning\":\"Document authorization checks do not apply.\"}]",
                        "RAG document authorization is only meaningful when retrieved documents exist.",
                        "This prevents zero-result RAG from being reported as document authorization success.")),
                Map.of(),
                Map.of(),
                Map.of(),
                Map.of(),
                List.of(),
                Map.of());
        List<RuntimeEvidenceMetricResult> results = metricResults(
                metricCatalog,
                List.of(rapRun),
                List.of(),
                "sep-sync-001");

        assertThat(results).hasSize(1);
        RuntimeEvidenceMetricResult result = results.get(0);
        assertThat(result.metricCode()).isEqualTo("RAP");
        assertThat(result.state()).isEqualTo("NOT_APPLICABLE");
        assertThat(result.totalChecks()).isEqualTo(1);
        assertThat(result.passedChecks()).isZero();
        assertThat(result.checks()).hasSize(1);
        assertThat(result.checks().get(0).purposeResult()).isEqualTo("NOT_APPLICABLE");
        assertThat(result.checks().get(0).evaluationState())
                .isEqualTo(OfficialVerificationCheckState.NOT_APPLICABLE);
    }

    @Test
    void metricResultsPreserveNotEvaluatedStateWhenRequiredInputIsMissing() throws Exception {
        PromptQualityOfficialMetricCatalog metricCatalog = mock(PromptQualityOfficialMetricCatalog.class);
        when(metricCatalog.promptQualityMetrics()).thenReturn(List.of(new OfficialVerificationMetricDefinition(
                "RAP",
                "RAG Authorization Precision",
                "RAG_AND_BASELINE",
                "RAG evidence must be authorized when documents exist.",
                true,
                1.0d,
                true)));
        SealedEvidenceOfficialRunView rapRun = new SealedEvidenceOfficialRunView(
                "official-run-rap-002",
                1,
                "RAP",
                "RAG Authorization Precision",
                "request-002",
                0.0d,
                0,
                0,
                10L,
                "not_evaluated",
                "warning",
                "Required RAG authorization evidence is missing.",
                "2026-04-28 09:00:00",
                "2026-04-28 09:00:01",
                List.of(new SealedEvidenceOfficialRunView.SealedEvidenceCheckView(
                        "RAP_RAG_AUTHORIZATION_REASON_PRESENT",
                        "RAG authorization reason could not be evaluated",
                        "RAG documents require an authorization reason.",
                        "Required authorization evidence is missing.",
                        false,
                        "finalUserPrompt.ragAuthorization",
                        "BLOCKING",
                        "MISSING_REQUIRED_INPUT",
                        "RAG_AUTHORIZATION_FILTER",
                        "The required authorization evidence was not captured.",
                        "Capture the authorization evidence and re-run verification.",
                        "The authorization evidence is present.",
                        "ragAuthorization",
                        true,
                        "CUSTOMER_PROMPT_QUALITY",
                        "final-user-prompt.v1",
                        "INPUT_NOT_READY",
                        "NOT_EVALUATED",
                        "[]",
                        "[]",
                        "Authorization quality cannot be decided without its required input.",
                        "This prevents missing evidence from being reported as a pass.")),
                Map.of(),
                Map.of(),
                Map.of(),
                Map.of(),
                List.of(),
                Map.of());

        RuntimeEvidenceMetricResult result = metricResults(
                metricCatalog,
                List.of(rapRun),
                List.of(),
                "sep-sync-002").get(0);

        assertThat(result.state()).isEqualTo("NOT_EVALUATED");
        assertThat(result.totalChecks()).isEqualTo(1);
        assertThat(result.passedChecks()).isZero();
        assertThat(result.checks()).hasSize(1);
        assertThat(result.checks().get(0).evaluationState())
                .isEqualTo(OfficialVerificationCheckState.NOT_EVALUATED);
    }

    @Test
    void metricResultsKeepInternalGateFailureSeparateFromActualPromptProblems() throws Exception {
        PromptQualityOfficialMetricCatalog metricCatalog = mock(PromptQualityOfficialMetricCatalog.class);
        when(metricCatalog.promptQualityMetrics()).thenReturn(List.of(new OfficialVerificationMetricDefinition(
                "PRE",
                "Protectable Resource Eligibility",
                "OPERATIONS_PROMOTION",
                "Protectable resource gate must be satisfied.",
                true,
                1.0d,
                true)));
        DefaultPromptQualityRuntimeVerificationService service = runtimeService(metricCatalog);
        SealedEvidenceOfficialRunView preRun = new SealedEvidenceOfficialRunView(
                "official-run-pre-001",
                1,
                "PRE",
                "/api/protected/orders",
                "req-001",
                0.0d,
                0,
                1,
                10L,
                "threshold_failed",
                "blocked",
                "resource template token is still visible",
                "2026-04-28 09:00:00",
                "2026-04-28 09:00:01",
                List.of(new SealedEvidenceOfficialRunView.SealedEvidenceCheckView(
                        "resource template token must not be used as actual resource",
                        "actual resource id",
                        "{resourceId}",
                        false,
                        "finalUserPrompt.resourceIdentity")),
                Map.of("requestId", "req-001"),
                Map.of(),
                Map.of("promptHash", "prompt-hash"),
                Map.of("sourceMode", "FINAL_PROMPT_SUITE"),
                List.of(),
                Map.of("packageId", "sep-sync-001", "aggregateRunId", "agg-sync-001"));
        List<OfficialVerificationPromptComparison> promptProblems = promptComparisons(null, List.of(preRun));

        assertThat(promptProblems).isEmpty();
        List<RuntimeEvidenceMetricResult> results = metricResults(
                metricCatalog,
                List.of(preRun),
                List.of(),
                "sep-sync-001");

        assertThat(results).hasSize(1);
        RuntimeEvidenceMetricResult result = results.get(0);
        assertThat(result.metricCode()).isEqualTo("PRE");
        assertThat(result.state()).isEqualTo("threshold_failed");
        assertThat(result.checks()).hasSize(1);
        assertThat(result.checks().get(0).metricCode()).isEqualTo("PRE");
        assertThat(result.checks().get(0).pass()).isFalse();
    }

    @Test
    void internalReferenceCheckDoesNotBecomeCustomerBlockingMetricOrPromptProblem() throws Exception {
        DefaultPromptQualityRuntimeVerificationService service = runtimeService();
        RuntimeEvidenceCheckResult internalReferenceFailure = new RuntimeEvidenceCheckResult(
                "COR",
                "COR_NO_RAG_CONTEXT_NO_CONTAMINATION_SURFACE",
                "RAG not used",
                "RAG absence is recorded",
                "RAG was not used for this request",
                false,
                "internalGate.ragEvidence.absence",
                "BLOCKING",
                "FINAL_PROMPT_RAG_NOT_APPLICABLE",
                "RAG_CONTEXT_PRODUCER",
                "RAG was not used by this request.",
                "",
                "",
                false,
                "INTERNAL_REFERENCE");
        RuntimeEvidenceMetricResult metric = new RuntimeEvidenceMetricResult(
                "COR",
                "run-cor",
                "Context Contamination Rate",
                "IMPLEMENTATION_ALIGNMENT",
                0.0d,
                "threshold_failed",
                "failed",
                0,
                1,
                List.of(internalReferenceFailure));
        assertThat(OfficialVerificationMetricClassifier.customerBlocking(metric)).isFalse();

        SealedEvidenceOfficialRunView corRun = new SealedEvidenceOfficialRunView(
                "run-cor",
                1,
                "COR",
                "/api/protected/orders",
                "req-001",
                0.0d,
                0,
                1,
                10L,
                "threshold_failed",
                "warning",
                "RAG was not used",
                null,
                null,
                List.of(new SealedEvidenceOfficialRunView.SealedEvidenceCheckView(
                        internalReferenceFailure.checkCode(),
                        internalReferenceFailure.label(),
                        internalReferenceFailure.expectedValue(),
                        internalReferenceFailure.actualValue(),
                        internalReferenceFailure.pass(),
                        internalReferenceFailure.source(),
                        internalReferenceFailure.severity(),
                        internalReferenceFailure.failureType(),
                        internalReferenceFailure.remediationOwner(),
                        internalReferenceFailure.operatorReason(),
                        internalReferenceFailure.nextAction(),
                        internalReferenceFailure.reverifyCriterion(),
                        internalReferenceFailure.customerVisible(),
                        internalReferenceFailure.readinessScope())),
                Map.of(),
                Map.of(),
                Map.of(),
                Map.of(),
                List.of(),
                Map.of());
        List<OfficialVerificationPromptComparison> comparisons = promptComparisons(null, List.of(corRun));

        assertThat(comparisons).isEmpty();
    }

    @Test
    void metricResultsRejectActualPromptProblemWithoutMetricBinding() throws Exception {
        PromptQualityOfficialMetricCatalog metricCatalog = mock(PromptQualityOfficialMetricCatalog.class);
        when(metricCatalog.promptQualityMetrics()).thenReturn(List.of(new OfficialVerificationMetricDefinition(
                "BMA",
                "Baseline Maturity Accuracy",
                "RAG_AND_BASELINE",
                "Baseline fields must be present in the final prompt.",
                true,
                1.0d,
                true)));
        DefaultPromptQualityRuntimeVerificationService service = runtimeService(metricCatalog);
        List<OfficialVerificationPromptComparison> promptComparisons = List.of(new OfficialVerificationPromptComparison(
                "baseline.eventCount",
                "Baseline observation count",
                "19",
                "",
                "19",
                "PROMPT_MISSING",
                "Prompt missing",
                "Baseline observation count is present in sealed evidence but not in the final prompt.",
                List.of(),
                "PERSONAL WORK PROFILE",
                "sealedEvidence.baselineSnapshot.eventCount",
                "LEARNING_CONTEXT"));
        assertThatThrownBy(() -> metricResults(
                metricCatalog,
                List.of(),
                promptComparisons,
                "sep-sync-001"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void metricResultsRejectActualPromptProblemWithoutRemediationOwner() throws Exception {
        PromptQualityOfficialMetricCatalog metricCatalog = mock(PromptQualityOfficialMetricCatalog.class);
        when(metricCatalog.promptQualityMetrics()).thenReturn(List.of(new OfficialVerificationMetricDefinition(
                "BMA",
                "Baseline Maturity Accuracy",
                "RAG_AND_BASELINE",
                "Baseline fields must be present in the final prompt.",
                true,
                1.0d,
                true)));
        DefaultPromptQualityRuntimeVerificationService service = runtimeService(metricCatalog);
        List<OfficialVerificationPromptComparison> promptComparisons = List.of(new OfficialVerificationPromptComparison(
                "baseline.eventCount",
                "Baseline observation count",
                "19",
                "",
                "19",
                "PROMPT_MISSING",
                "Prompt missing",
                "Baseline observation count is present in sealed evidence but not in the final prompt.",
                List.of("BMA"),
                "PERSONAL WORK PROFILE",
                "sealedEvidence.baselineSnapshot.eventCount",
                ""));
        assertThatThrownBy(() -> metricResults(
                metricCatalog,
                List.of(),
                promptComparisons,
                "sep-sync-001"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void dynamicPromptComparisonFieldUsesManifestFallbackWhenBundleKeyIsAbsent() {
        PromptComparisonValueInterpreter interpreter = new PromptComparisonValueInterpreter(
                PromptQualityTestResolvers.englishBundle());

        assertThat(interpreter.fieldLabel("organizationId", "Organization ID"))
                .isEqualTo("Organization ID");
    }

    @Test
    void runtimeCustomerNarrativeFixedKeysExistInEnglishAndKoreanBundles() {
        List<String> keys = List.of(
                "enterprise.pqa.common.value.notRecorded",
                "enterprise.pqa.runtimeVerification.customerSentence.metricFallback",
                "enterprise.pqa.runtimeVerification.customerSentence.blockingTpl",
                "enterprise.pqa.runtimeVerification.customerSentence.followUpTpl");
        List<PromptQualityMessageResolver> resolvers = List.of(
                PromptQualityTestResolvers.englishBundle(),
                PromptQualityTestResolvers.koreanBundle());

        resolvers.forEach(resolver -> keys.forEach(key ->
                assertThat(resolver.resolveRequired(key, "metric", "reason", "action"))
                        .isNotBlank()
                        .isNotEqualTo(key)));
    }
    @Test
    void verifyDoesNotRunCoreOfficialMetricsWhenPromptConsistencyGateBlocks() {
        SealedEvidencePackageQueryService lookupService = mock(SealedEvidencePackageQueryService.class);
        RuntimeEvidenceReplayService replayService = mock(RuntimeEvidenceReplayService.class);
        RuntimeEvidencePromptScorecardService scorecardService = mock(RuntimeEvidencePromptScorecardService.class);
        OfficialSealedEvidenceVerificationRuntime officialRuntime = mock(OfficialSealedEvidenceVerificationRuntime.class);
        PromptQualityRuntimeCertificationPolicy certificationPolicy = mock(PromptQualityRuntimeCertificationPolicy.class);
        PromptQualityProtectableResourceLookup resourceLookup = mock(PromptQualityProtectableResourceLookup.class);
        PromptQualityOfficialMetricCatalog metricCatalog = mock(PromptQualityOfficialMetricCatalog.class);
        PromptQualityAssuranceCaseService assuranceCaseService = mock(PromptQualityAssuranceCaseService.class);
        RuntimeIssueDiagnosticService issueDiagnosticService = mock(RuntimeIssueDiagnosticService.class);
        PromptQualityProcessRunService processRunService = mock(PromptQualityProcessRunService.class);
        SealedEvidencePackage evidencePackage = evidencePackage();
        when(lookupService.findByPackageId("sep-blocked-001")).thenReturn(Optional.of(evidencePackage));
        when(lookupService.verifyIntegrity(any(SealedEvidencePackage.class))).thenReturn(true);
        when(processRunService.steps(any())).thenReturn(List.of());
        RuntimeEvidencePromptConsistencyGate promptConsistencyGate = ignored -> new RuntimeEvidencePromptConsistencyResult(
                "BLOCKED",
                "Blocked",
                false,
                true,
                List.of(new RuntimeEvidenceCheckResult(
                        "EVIDENCE_PROMPT_MISMATCH",
                        "tenantId exists in sealed evidence",
                        "tenantId value",
                        "missing",
                        false,
                        "requestFacts")),
                List.of("tenantId exists in sealed evidence: missing"),
                List.of("Fix evidence capture and re-request the protected resource."));
        when(scorecardService.evaluate(evidencePackage)).thenReturn(
                new ScorecardResult("scorecard", 1, 1, 100.0d, List.of()));
        when(replayService.replay("sep-blocked-001")).thenReturn(new DeterministicReplayResult(
                "sep-blocked-001",
                true,
                "prompt-hash",
                "prompt-hash",
                1,
                1,
                List.of(),
                List.of(),
                List.of(),
                Instant.parse("2026-04-28T00:00:01Z")));
        when(certificationPolicy.evaluate(any(), eq(true), any(), any(), any()))
                .thenReturn(new RuntimeEvidenceGateResult(false, List.of(), List.of(), List.of()));
        when(issueDiagnosticService.recordIssues(any(), any(), any(), any(), any())).thenReturn(List.of());
        DefaultPromptQualityRuntimeVerificationService service = service(
                lookupService,
                replayService,
                scorecardService,
                officialRuntime,
                certificationPolicy,
                resourceLookup,
                metricCatalog,
                assuranceCaseService,
                issueDiagnosticService,
                null,
                new ObjectMapper(),
                promptConsistencyGate,
                processRunService);

        RuntimeEvidenceVerificationRun run = service.verify(
                new RuntimeEvidenceVerificationRequest("sep-blocked-001", "operator-admin"));

        assertThat(run.officialFinalDecision()).isEqualTo("INELIGIBLE");
        assertThat(run.verdict()).isNotNull();
        assertThat(run.verdict().failures())
                .extracting(failure -> failure.gateCode())
                .contains(OfficialVerificationGateCode.PROMPT_CONSISTENCY);
        assertThat(run.metrics()).isEmpty();
        verify(processRunService).startStep(
                any(),
                eq(PromptQualityProcessCodes.OFFICIAL_VERIFICATION),
                eq("PROCESS_STAGE"),
                eq(PromptQualityProcessCodes.OFFICIAL_VERIFICATION),
                eq("sep-blocked-001"),
                eq("/contexa/admin/prompt-quality/verification/readiness?packageId=sep-blocked-001&resourceUrl=%2Fapi%2Fprotected%2Forders&resourceId=orders.read&httpMethod=GET"),
                eq("operator-admin"),
                eq("Official verification started from sealed runtime evidence."));
        verify(processRunService).completeStep(
                any(),
                eq(PromptQualityProcessCodes.OFFICIAL_VERIFICATION),
                eq("PROCESS_STAGE"),
                eq("INELIGIBLE"),
                any(),
                any(),
                any(),
                any(),
                any(),
                eq("operator-admin"),
                eq("Official verification completed with an ineligible verdict before metric execution."));
        verifyNoInteractions(officialRuntime);
    }

    @Test
    void verifyBootstrapsProcessPrerequisitesFromSelectedSealedEvidenceBeforeOfficialRun() {
        SealedEvidencePackageQueryService lookupService = mock(SealedEvidencePackageQueryService.class);
        RuntimeEvidenceReplayService replayService = mock(RuntimeEvidenceReplayService.class);
        RuntimeEvidencePromptScorecardService scorecardService = mock(RuntimeEvidencePromptScorecardService.class);
        OfficialSealedEvidenceVerificationRuntime officialRuntime = mock(OfficialSealedEvidenceVerificationRuntime.class);
        PromptQualityRuntimeCertificationPolicy certificationPolicy = mock(PromptQualityRuntimeCertificationPolicy.class);
        PromptQualityProtectableResourceLookup resourceLookup = mock(PromptQualityProtectableResourceLookup.class);
        PromptQualityOfficialMetricCatalog metricCatalog = mock(PromptQualityOfficialMetricCatalog.class);
        PromptQualityAssuranceCaseService assuranceCaseService = mock(PromptQualityAssuranceCaseService.class);
        RuntimeIssueDiagnosticService issueDiagnosticService = mock(RuntimeIssueDiagnosticService.class);
        PromptQualityProcessRunService processRunService = mock(PromptQualityProcessRunService.class);
        SealedEvidencePackage evidencePackage = evidencePackage();
        when(lookupService.findByPackageId("sep-blocked-001")).thenReturn(Optional.of(evidencePackage));
        when(lookupService.verifyIntegrity(any(SealedEvidencePackage.class))).thenReturn(true);
        when(processRunService.steps(any())).thenReturn(
                List.of(
                        new PromptQualityProcessStepSnapshot(
                                PromptQualityProcessCodes.PROTECTABLE_RESOURCES,
                                1,
                                PromptQualityProcessCodes.FAILED,
                                "RESOURCE_OPERATIONAL",
                                "PENDING_VERIFICATION",
                                null,
                                null,
                                null,
                                null,
                                null,
                                null),
                        new PromptQualityProcessStepSnapshot(
                                PromptQualityProcessCodes.RUNTIME_EVIDENCE,
                                2,
                                PromptQualityProcessCodes.PENDING,
                                "RUNTIME_EVIDENCE",
                                "READY_FOR_INSPECTION",
                                null,
                                null,
                                null,
                                null,
                                null,
                                null),
                        new PromptQualityProcessStepSnapshot(
                                PromptQualityProcessCodes.OFFICIAL_VERIFICATION,
                                3,
                                PromptQualityProcessCodes.PENDING,
                                "PROCESS_STAGE",
                                PromptQualityProcessCodes.OFFICIAL_VERIFICATION,
                                null,
                                null,
                                null,
                                null,
                                null,
                                null)),
                List.of(
                        new PromptQualityProcessStepSnapshot(
                                PromptQualityProcessCodes.PROTECTABLE_RESOURCES,
                                1,
                                PromptQualityProcessCodes.COMPLETED,
                                "RESOURCE_OPERATIONAL",
                                "PENDING_VERIFICATION",
                                "orders.read",
                                "/contexa/admin/prompt-quality/resources/detail",
                                null,
                                null,
                                null,
                                null),
                        new PromptQualityProcessStepSnapshot(
                                PromptQualityProcessCodes.RUNTIME_EVIDENCE,
                                2,
                                PromptQualityProcessCodes.COMPLETED,
                                "RUNTIME_EVIDENCE",
                                "READY_FOR_INSPECTION",
                                "sep-blocked-001",
                                "/contexa/admin/prompt-quality/runtime-evidence?packageId=sep-blocked-001&resourceUrl=%2Fapi%2Fprotected%2Forders&resourceId=orders.read&httpMethod=GET",
                                null,
                                null,
                                null,
                                null),
                        new PromptQualityProcessStepSnapshot(
                                PromptQualityProcessCodes.OFFICIAL_VERIFICATION,
                                3,
                                PromptQualityProcessCodes.RUNNING,
                                "PROCESS_STAGE",
                                PromptQualityProcessCodes.OFFICIAL_VERIFICATION,
                                "sep-blocked-001",
                                "/contexa/admin/prompt-quality/verification/readiness?packageId=sep-blocked-001&resourceUrl=%2Fapi%2Fprotected%2Forders&resourceId=orders.read&httpMethod=GET",
                                null,
                                null,
                                null,
                                null)));
        RuntimeEvidencePromptConsistencyGate promptConsistencyGate = ignored -> new RuntimeEvidencePromptConsistencyResult(
                "BLOCKED",
                "Blocked",
                false,
                true,
                List.of(new RuntimeEvidenceCheckResult(
                        "EVIDENCE_PROMPT_MISMATCH",
                        "final prompt captured",
                        "final prompt",
                        "missing",
                        false,
                        "promptCapture")),
                List.of("final prompt captured: missing"),
                List.of("Re-capture sealed runtime evidence."));
        when(scorecardService.evaluate(evidencePackage)).thenReturn(
                new ScorecardResult("scorecard", 1, 1, 100.0d, List.of()));
        when(replayService.replay("sep-blocked-001")).thenReturn(new DeterministicReplayResult(
                "sep-blocked-001",
                true,
                "prompt-hash",
                "prompt-hash",
                1,
                1,
                List.of(),
                List.of(),
                List.of(),
                Instant.parse("2026-04-28T00:00:01Z")));
        when(certificationPolicy.evaluate(any(), eq(true), any(), any(), any()))
                .thenReturn(new RuntimeEvidenceGateResult(false, List.of(), List.of(), List.of()));
        when(issueDiagnosticService.recordIssues(any(), any(), any(), any(), any())).thenReturn(List.of());
        DefaultPromptQualityRuntimeVerificationService service = service(
                lookupService,
                replayService,
                scorecardService,
                officialRuntime,
                certificationPolicy,
                resourceLookup,
                metricCatalog,
                assuranceCaseService,
                issueDiagnosticService,
                null,
                new ObjectMapper(),
                promptConsistencyGate,
                processRunService);

        RuntimeEvidenceVerificationRun run = service.verify(
                new RuntimeEvidenceVerificationRequest("sep-blocked-001", "operator-admin"));

        assertThat(run.officialFinalDecision()).isEqualTo("INELIGIBLE");
        assertThat(run.verdict()).isNotNull();
        assertThat(run.verdict().failures())
                .extracting(failure -> failure.gateCode())
                .contains(OfficialVerificationGateCode.PROMPT_CONSISTENCY);
        assertThat(run.metrics()).isEmpty();
        InOrder ordered = inOrder(processRunService);
        ordered.verify(processRunService).completeStep(
                any(),
                eq(PromptQualityProcessCodes.PROTECTABLE_RESOURCES),
                eq("RESOURCE_OPERATIONAL"),
                eq("PENDING_VERIFICATION"),
                eq("orders.read"),
                any(),
                any(),
                any(),
                any(),
                eq("operator-admin"),
                eq("Protected resource prerequisite completed from selected sealed evidence."));
        ordered.verify(processRunService).completeStep(
                any(),
                eq(PromptQualityProcessCodes.RUNTIME_EVIDENCE),
                eq("RUNTIME_EVIDENCE"),
                eq("WARNING_SIGNALS"),
                eq("sep-blocked-001"),
                eq("/contexa/admin/prompt-quality/runtime-evidence?packageId=sep-blocked-001&resourceUrl=%2Fapi%2Fprotected%2Forders&resourceId=orders.read&httpMethod=GET"),
                any(),
                any(),
                any(),
                eq("operator-admin"),
                eq("Runtime evidence prerequisite completed from selected sealed evidence."));
        ordered.verify(processRunService).startStep(
                any(),
                eq(PromptQualityProcessCodes.OFFICIAL_VERIFICATION),
                eq("PROCESS_STAGE"),
                eq(PromptQualityProcessCodes.OFFICIAL_VERIFICATION),
                eq("sep-blocked-001"),
                eq("/contexa/admin/prompt-quality/verification/readiness?packageId=sep-blocked-001&resourceUrl=%2Fapi%2Fprotected%2Forders&resourceId=orders.read&httpMethod=GET"),
                eq("operator-admin"),
                eq("Official verification started from sealed runtime evidence."));
        ordered.verify(processRunService).completeStep(
                any(),
                eq(PromptQualityProcessCodes.OFFICIAL_VERIFICATION),
                eq("PROCESS_STAGE"),
                eq("INELIGIBLE"),
                any(),
                any(),
                any(),
                any(),
                any(),
                eq("operator-admin"),
                eq("Official verification completed with an ineligible verdict before metric execution."));
        verifyNoInteractions(officialRuntime);
    }

    @Test
    void verifyRunsMetricsWhenPreMetricPolicyIsIneligibleAndConsistencyDoesNotBlock() {
        SealedEvidencePackageQueryService lookupService = mock(SealedEvidencePackageQueryService.class);
        RuntimeEvidenceReplayService replayService = mock(RuntimeEvidenceReplayService.class);
        RuntimeEvidencePromptScorecardService scorecardService = mock(RuntimeEvidencePromptScorecardService.class);
        OfficialSealedEvidenceVerificationRuntime officialRuntime = mock(OfficialSealedEvidenceVerificationRuntime.class);
        PromptQualityRuntimeCertificationPolicy certificationPolicy = mock(PromptQualityRuntimeCertificationPolicy.class);
        PromptQualityProtectableResourceLookup resourceLookup = mock(PromptQualityProtectableResourceLookup.class);
        PromptQualityOfficialMetricCatalog metricCatalog = mock(PromptQualityOfficialMetricCatalog.class);
        PromptQualityAssuranceCaseService assuranceCaseService = mock(PromptQualityAssuranceCaseService.class);
        RuntimeIssueDiagnosticService issueDiagnosticService = mock(RuntimeIssueDiagnosticService.class);
        PromptQualityProcessRunService processRunService = mock(PromptQualityProcessRunService.class);
        SealedEvidencePackage evidencePackage = evidencePackage();
        SealedEvidenceOfficialRunView metricRun = officialMetricRun();
        when(lookupService.findByPackageId("sep-blocked-001")).thenReturn(Optional.of(evidencePackage));
        when(lookupService.verifyIntegrity(any(SealedEvidencePackage.class))).thenReturn(true);
        when(processRunService.steps(any())).thenReturn(List.of());
        OfficialVerificationMetricDefinition eirMetric = new OfficialVerificationMetricDefinition(
                "EIR",
                "Evidence Integrity",
                "IMPLEMENTATION_ALIGNMENT",
                "evidence integrity",
                true,
                1.0d,
                true);
        when(metricCatalog.allMetrics()).thenReturn(List.of(eirMetric));
        when(metricCatalog.promptQualityMetrics()).thenReturn(List.of(eirMetric));
        when(scorecardService.evaluate(evidencePackage)).thenReturn(new ScorecardResult("scorecard", 1, 1, 100.0d, List.of()));
        when(replayService.replay("sep-blocked-001")).thenReturn(new DeterministicReplayResult(
                "sep-blocked-001",
                true,
                "prompt-hash",
                "prompt-hash",
                1,
                1,
                List.of(),
                List.of(),
                List.of(),
                Instant.parse("2026-04-28T00:00:01Z")));
        when(officialRuntime.executeAll(any())).thenReturn(new OfficialSealedEvidenceVerificationResult(
                "agg-run-001",
                "sep-blocked-001",
                "operator-admin",
                "2026-04-28 09:00:01",
                true,
                List.of(metricRun)));
        when(certificationPolicy.evaluate(any(SealedEvidencePackage.class), eq(true), any(), any(), any()))
                .thenReturn(new RuntimeEvidenceGateResult(
                        false,
                        List.of(new RuntimeEvidenceCheckResult(null, "governance descriptor exists", "present", "missing", false, "promptGovernance")),
                        List.of(),
                        List.of()));
        when(resourceLookup.findBestMatch(any(), any(), any())).thenReturn(Optional.empty());
        PromptQualityAssuranceCase assuranceCase = assuranceCase();
        when(assuranceCaseService.recordVerification(any(), eq("agg-run-001"), eq(0), any()))
                .thenReturn(assuranceCase);
        when(issueDiagnosticService.recordIssues(eq("agg-run-001"), eq("sep-blocked-001"), eq("GET"), any(), any()))
                .thenReturn(List.of());
        RuntimeEvidencePromptConsistencyGate promptConsistencyGate = ignored -> new RuntimeEvidencePromptConsistencyResult(
                "PASS",
                "Pass",
                true,
                false,
                List.of(),
                List.of(),
                List.of());
        DefaultPromptQualityRuntimeVerificationService service = service(
                lookupService,
                replayService,
                scorecardService,
                officialRuntime,
                certificationPolicy,
                resourceLookup,
                metricCatalog,
                assuranceCaseService,
                issueDiagnosticService,
                null,
                new ObjectMapper(),
                promptConsistencyGate,
                processRunService);

        RuntimeEvidenceVerificationRun run = service.verify(new RuntimeEvidenceVerificationRequest("sep-blocked-001", "operator-admin"));

        assertThat(run.promptComparisons())
                .extracting(OfficialVerificationPromptComparison::fieldKey)
                .contains("requestPath");
        verify(officialRuntime).executeAll(any());


        verify(processRunService).recordEvent(
                any(),
                eq(PromptQualityProcessCodes.OFFICIAL_VERIFICATION),
                eq("OFFICIAL_VERIFICATION_AUDIT_SNAPSHOT"),
                argThat(payload -> "sep-blocked-001".equals(payload.get("packageId"))
                        && "agg-run-001".equals(payload.get("aggregateRunId"))
                        && payload.get("officialVerdict") instanceof OfficialVerificationVerdict verdict
                        && !verdict.eligible()
                        && "sep-blocked-001".equals(verdict.packageId())
                        && "agg-run-001".equals(verdict.aggregateRunId())
                        && Integer.valueOf(3).equals(payload.get("totalMetricCount"))
                        && Integer.valueOf(0).equals(payload.get("failedMetricCount"))
                        && "prompt-hash".equals(payload.get("promptHash"))),
                eq("operator-admin"),
                eq("Official verification audit snapshot persisted."));
    }

    @Test
    void metricEvaluatorFailureMarksOfficialExecutionFailedAndPreservesOriginalException() {
        SealedEvidencePackageQueryService lookupService = mock(SealedEvidencePackageQueryService.class);
        RuntimeEvidenceReplayService replayService = mock(RuntimeEvidenceReplayService.class);
        RuntimeEvidencePromptScorecardService scorecardService = mock(RuntimeEvidencePromptScorecardService.class);
        OfficialSealedEvidenceVerificationRuntime officialRuntime = mock(OfficialSealedEvidenceVerificationRuntime.class);
        PromptQualityRuntimeCertificationPolicy certificationPolicy = mock(PromptQualityRuntimeCertificationPolicy.class);
        PromptQualityProtectableResourceLookup resourceLookup = mock(PromptQualityProtectableResourceLookup.class);
        PromptQualityOfficialMetricCatalog metricCatalog = mock(PromptQualityOfficialMetricCatalog.class);
        PromptQualityAssuranceCaseService assuranceCaseService = mock(PromptQualityAssuranceCaseService.class);
        RuntimeIssueDiagnosticService issueDiagnosticService = mock(RuntimeIssueDiagnosticService.class);
        PromptQualityProcessRunService processRunService = mock(PromptQualityProcessRunService.class);
        OfficialVerificationOperatorSnapshotService snapshotService = mock(OfficialVerificationOperatorSnapshotService.class);
        OfficialVerificationExecutionLockService executionLockService = mock(OfficialVerificationExecutionLockService.class);
        SealedEvidencePackage evidencePackage = evidencePackage();
        OfficialVerificationMetricDefinition eirMetric = new OfficialVerificationMetricDefinition(
                "EIR",
                "Evidence Integrity",
                "IMPLEMENTATION_ALIGNMENT",
                "evidence integrity",
                true,
                1.0d,
                true);
        OfficialVerificationExecutionLockService.ExecutionRecord executionRecord =
                new OfficialVerificationExecutionLockService.ExecutionRecord(
                        1L,
                        "failure-key-001",
                        "failure-key-001",
                        evidencePackage.getPackageId(),
                        evidencePackage.getTenantId(),
                        null,
                        1,
                        1,
                        OfficialVerificationExecutionLockService.STATE_LOCK_ACQUIRED,
                        0,
                        null,
                        null,
                        null,
                        null,
                        "operator-admin",
                        null,
                        "{}",
                        null,
                        Instant.EPOCH,
                        null,
                        null,
                        Instant.EPOCH,
                        Instant.EPOCH,
                        true);
        IllegalStateException evaluatorFailure = new IllegalStateException("fixture metric evaluator failure");

        when(lookupService.findByPackageId("sep-blocked-001")).thenReturn(Optional.of(evidencePackage));
        when(lookupService.verifyIntegrity(any(SealedEvidencePackage.class))).thenReturn(true);
        when(processRunService.steps(any())).thenReturn(List.of());
        when(metricCatalog.allMetrics()).thenReturn(List.of(eirMetric));
        when(metricCatalog.promptQualityMetrics()).thenReturn(List.of(eirMetric));
        when(scorecardService.evaluate(evidencePackage)).thenReturn(
                new ScorecardResult("scorecard", 1, 1, 100.0d, List.of()));
        when(replayService.replay("sep-blocked-001")).thenReturn(new DeterministicReplayResult(
                "sep-blocked-001",
                true,
                "prompt-hash",
                "prompt-hash",
                1,
                1,
                List.of(),
                List.of(),
                List.of(),
                Instant.parse("2026-04-28T00:00:01Z")));
        when(certificationPolicy.evaluate(any(SealedEvidencePackage.class), eq(true), any(), any(), any()))
                .thenReturn(new RuntimeEvidenceGateResult(true, List.of(), List.of(), List.of()));
        when(resourceLookup.findBestMatch(any(), any(), any())).thenReturn(Optional.empty());
        when(snapshotService.replaceDiagnosticsForQualityTarget(any(), any(), any(), any(), any()))
                .thenReturn(List.of());
        when(snapshotService.promptComparisons(any(), any())).thenReturn(List.of());
        when(snapshotService.actualPromptProblems(any(), any())).thenReturn(List.of());
        when(executionLockService.start(any())).thenReturn(executionRecord);
        when(executionLockService.completedResult(any())).thenReturn(Optional.empty());
        when(officialRuntime.executeAll(any())).thenThrow(evaluatorFailure);
        RuntimeEvidencePromptConsistencyGate promptConsistencyGate = ignored ->
                new RuntimeEvidencePromptConsistencyResult(
                        "PASS",
                        "Pass",
                        true,
                        false,
                        List.of(),
                        List.of(),
                        List.of());
        DefaultPromptQualityRuntimeVerificationService service = service(
                lookupService,
                replayService,
                scorecardService,
                officialRuntime,
                certificationPolicy,
                resourceLookup,
                metricCatalog,
                assuranceCaseService,
                issueDiagnosticService,
                null,
                new ObjectMapper(),
                promptConsistencyGate,
                snapshotService,
                processRunService,
                executionLockService);

        assertThatThrownBy(() -> service.verify(
                new RuntimeEvidenceVerificationRequest("sep-blocked-001", "operator-admin")))
                .isSameAs(evaluatorFailure);
        verify(executionLockService).markMetricsRunning(
                eq(executionRecord),
                eq("osev-failed-sep-blocked-001-lock-1-attempt-1"),
                eq(List.of("EIR")));
        verify(executionLockService).markFailed(
                eq(executionRecord),
                eq(evaluatorFailure),
                eq(true),
                any());
    }

    @Test
    void verifyReturnsStoredCompletedResultWhenIdempotencyKeyAlreadyCompleted() {
        SealedEvidencePackageQueryService lookupService = mock(SealedEvidencePackageQueryService.class);
        RuntimeEvidenceReplayService replayService = mock(RuntimeEvidenceReplayService.class);
        RuntimeEvidencePromptScorecardService scorecardService = mock(RuntimeEvidencePromptScorecardService.class);
        OfficialSealedEvidenceVerificationRuntime officialRuntime = mock(OfficialSealedEvidenceVerificationRuntime.class);
        PromptQualityRuntimeCertificationPolicy certificationPolicy = mock(PromptQualityRuntimeCertificationPolicy.class);
        PromptQualityProtectableResourceLookup resourceLookup = mock(PromptQualityProtectableResourceLookup.class);
        PromptQualityOfficialMetricCatalog metricCatalog = mock(PromptQualityOfficialMetricCatalog.class);
        PromptQualityAssuranceCaseService assuranceCaseService = mock(PromptQualityAssuranceCaseService.class);
        RuntimeIssueDiagnosticService issueDiagnosticService = mock(RuntimeIssueDiagnosticService.class);
        PromptQualityProcessRunService processRunService = mock(PromptQualityProcessRunService.class);
        OfficialVerificationExecutionLockService executionLockService = mock(OfficialVerificationExecutionLockService.class);
        SealedEvidencePackage evidencePackage = evidencePackage();
        OfficialVerificationMetricDefinition eirMetric = new OfficialVerificationMetricDefinition(
                "EIR",
                "Evidence Integrity",
                "IMPLEMENTATION_ALIGNMENT",
                "evidence integrity",
                true,
                1.0d,
                true);
        RuntimeEvidenceVerificationRun storedRun = storedRun();
        OfficialVerificationExecutionLockService.ExecutionRecord completedRecord =
                new OfficialVerificationExecutionLockService.ExecutionRecord(
                        1L,
                        "idem-key-001",
                        "idem-key-001",
                        "sep-blocked-001",
                        evidencePackage.getTenantId(),
                        "agg-run-stored",
                        1,
                        1,
                        OfficialVerificationExecutionLockService.STATE_COMPLETED,
                        100,
                        false,
                        null,
                        null,
                        null,
                        "operator-admin",
                        null,
                        "{}",
                        "{}",
                        Instant.parse("2026-04-28T00:00:00Z"),
                        Instant.parse("2026-04-28T00:00:01Z"),
                        null,
                        Instant.parse("2026-04-28T00:00:00Z"),
                        Instant.parse("2026-04-28T00:00:01Z"),
                        false);
        when(lookupService.findByPackageId("sep-blocked-001")).thenReturn(Optional.of(evidencePackage));
        when(lookupService.verifyIntegrity(any(SealedEvidencePackage.class))).thenReturn(true);
        when(processRunService.steps(any())).thenReturn(List.of());
        when(metricCatalog.promptQualityMetrics()).thenReturn(List.of(eirMetric));
        when(resourceLookup.findBestMatch(any(), any(), any())).thenReturn(Optional.empty());
        when(executionLockService.start(any())).thenReturn(completedRecord);
        when(executionLockService.completedResult(completedRecord)).thenReturn(Optional.of(storedRun));
        RuntimeEvidencePromptConsistencyGate promptConsistencyGate = ignored -> new RuntimeEvidencePromptConsistencyResult(
                "PASS",
                "Pass",
                true,
                false,
                List.of(),
                List.of(),
                List.of());
        DefaultPromptQualityRuntimeVerificationService service = service(
                lookupService,
                replayService,
                scorecardService,
                officialRuntime,
                certificationPolicy,
                resourceLookup,
                metricCatalog,
                assuranceCaseService,
                issueDiagnosticService,
                null,
                new ObjectMapper(),
                promptConsistencyGate,
                mock(OfficialVerificationOperatorSnapshotService.class),
                processRunService,
                executionLockService);

        RuntimeEvidenceVerificationRun actual = service.verify(new RuntimeEvidenceVerificationRequest("sep-blocked-001", "operator-admin"));

        assertThat(actual.aggregateRunId()).isEqualTo("agg-run-stored");
        verifyNoInteractions(officialRuntime, replayService, scorecardService, certificationPolicy,
                assuranceCaseService, issueDiagnosticService);
        verify(processRunService).completeStep(
                any(),
                eq(PromptQualityProcessCodes.PROTECTABLE_RESOURCES),
                eq("RESOURCE_OPERATIONAL"),
                eq("PENDING_VERIFICATION"),
                eq("orders.read"),
                any(),
                any(),
                any(),
                any(),
                eq("operator-admin"),
                eq("Protected resource prerequisite completed from selected sealed evidence."));
    }

    private RuntimeEvidenceVerificationRun storedRun() {
        return new RuntimeEvidenceVerificationRun(
                "agg-run-stored",
                "sep-blocked-001",
                "2026-04-28 09:00:01",
                "case-001",
                "Stored official result",
                1,
                1,
                0,
                "tenant-a",
                "user-a",
                "/api/protected/orders",
                "orders.read",
                "GET",
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                "req-001",
                "prompt-hash",
                "context-hash",
                List.of(),
                List.of(),
                RuntimeEvidencePromptConsistencyResult.empty(),
                OfficialVerificationExecutionLockService.STATE_COMPLETED,
                100);
    }

    private SealedEvidencePackage evidencePackage() {
        String systemPrompt = "system prompt";
        String userPrompt = """
                RequestPath: /api/protected/orders
                ResourceId: orders.read
                ClientIp: 127.0.0.1
                AuthorizationEffect: ALLOW
                EffectiveRoles: [USER]
                AuthenticationType: password
                """;
        String rawSystemPrompt = "raw system prompt";
        String rawUserPrompt = "raw user prompt";
        String systemPromptHash = sha256Prefixed(systemPrompt);
        String userPromptHash = sha256Prefixed(userPrompt);
        String rawSystemPromptHash = sha256Prefixed(rawSystemPrompt);
        String rawUserPromptHash = sha256Prefixed(rawUserPrompt);
        return SealedEvidencePackage.builder()
                .packageId("sep-blocked-001")
                .correlationId("corr-blocked-001")
                .tenantId("tenant-a")
                .userId("user-a")
                .capturedAt(Instant.parse("2026-04-28T00:00:00Z"))
                .requestFactsJson("{\"requestId\":\"req-001\",\"correlationId\":\"corr-blocked-001\",\"requestPath\":\"/api/protected/orders\",\"httpMethod\":\"GET\",\"resourceId\":\"orders.read\",\"clientIp\":\"127.0.0.1\"}")
                .authStateJson("{\"authorizationEffect\":\"ALLOW\",\"effectiveRoles\":[\"USER\"],\"effectivePermissions\":[\"READ\"],\"authMethod\":\"password\"}")
                .promptExecutionMetadataJson("""
                        {
                          "promptHash":"prompt-hash",
                          "systemPromptHash":"%s",
                          "userPromptHash":"%s",
                          "promptSourceContextFieldCount":1,
                          "promptSourceContextExhaustive":true,
                          "promptSourceContextFailureCount":0,
                          "promptFieldStateCount":1,
                          "promptBlockingFieldStateCount":0,
                          "promptFieldStateLedger":[
                            {
                              "fieldKey":"source:securityEvent.metadata.requestPath",
                              "sourceType":"SECURITY_EVENT_METADATA",
                              "sourceFieldPath":"securityEvent.metadata.requestPath",
                              "fieldState":"VALUE_PRESENT",
                              "valueType":"java.lang.String",
                              "valueHash":"sha256:test",
                              "valueLength":21,
                              "valuePreview":"/api/protected/orders",
                              "blockingCandidate":false
                            }
                          ]
                        }
                        """.formatted(systemPromptHash, userPromptHash))
                .decisionJson("{}")
                .systemPromptText(systemPrompt)
                .userPromptText(userPrompt)
                .rawSystemPrompt(rawSystemPrompt)
                .rawUserPrompt(rawUserPrompt)
                .systemPromptHash(systemPromptHash)
                .userPromptHash(userPromptHash)
                .rawSystemPromptHash(rawSystemPromptHash)
                .rawUserPromptHash(rawUserPromptHash)
                .promptEvidenceManifestJson("""
                        {
                          "contractVersion": "USER_PROMPT_EVIDENCE_CONTRACT_V1",
                          "sealable": true,
                          "fieldStateLedgerAvailable": true,
                          "fieldStateTotalCount": 1,
                          "fieldStateBlockingCount": 0,
                          "sourceContextFieldCount": 1,
                          "sourceContextExhaustive": true,
                          "sourceContextFailureCount": 0,
                          "fieldStateLedger": [
                            {
                              "fieldKey": "source:securityEvent.metadata.requestPath",
                              "sourceType": "SECURITY_EVENT_METADATA",
                              "sourceFieldPath": "securityEvent.metadata.requestPath",
                              "fieldState": "VALUE_PRESENT",
                              "valueType": "java.lang.String",
                              "valueHash": "sha256:test",
                              "valueLength": 21,
                              "valuePreview": "/api/protected/orders",
                              "blockingCandidate": false
                            }
                          ],
                          "fields": [
                            {
                              "fieldKey": "requestPath",
                              "displayName": "Request path",
                              "requiredLevel": "P0_REQUIRED",
                              "promptValue": "/api/protected/orders",
                              "evidenceSection": "REQUEST_FACTS",
                              "evidencePath": "requestPath",
                              "evidenceValue": "/api/protected/orders",
                              "projectionState": "PRESENT",
                              "blocking": false,
                              "producer": "REQUEST_CONTEXT",
                              "metricCodes": ["CCR", "PFR"]
                            }
                          ],
                          "violations": []
                        }
                        """)
                .sealState("SEALED")
                .promptHash("prompt-hash")
                .packageHash("package-hash")
                .sealed(true)
                .build();
    }

    private String sha256Prefixed(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return "sha256:" + HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private SealedEvidenceOfficialRunView officialMetricRun() {
        return new SealedEvidenceOfficialRunView(
                "official-run-eir-001",
                1,
                "EIR",
                "/api/protected/orders",
                "req-001",
                1.0d,
                1,
                1,
                10L,
                "SUCCESS",
                "ready",
                "passed",
                "2026-04-28 09:00:00",
                "2026-04-28 09:00:01",
                List.of(new SealedEvidenceOfficialRunView.SealedEvidenceCheckView(
                        "mfaVerified true",
                        "pass",
                        "pass",
                        true,
                        "coreEvidenceReplay")),
                Map.of(
                        "requestId", "req-001",
                        "requestPath", "/api/protected/orders",
                        "httpMethod", "GET",
                        "resourceId", "orders.read"),
                Map.of("correlationId", "corr-blocked-001"),
                Map.of("promptHash", "prompt-hash", "contextHash", "context-hash"),
                Map.of("sourceMode", "CORE_OFFICIAL_SEALED_EVIDENCE"),
                List.of(),
                Map.of(
                        "packageId", "sep-blocked-001",
                        "aggregateRunId", "agg-run-001",
                        "requestId", "req-001",
                        "promptHash", "prompt-hash",
                        "contextHash", "context-hash"));
    }

    private PromptQualityAssuranceCase assuranceCase() {
        return new PromptQualityAssuranceCase(
                "case-001",
                "case-key",
                "tenant-a",
                "/api/protected/orders",
                "orders.read",
                "GET",
                PromptQualityAssuranceScope.DEFAULT_PROMPT_CONTRACT_VERSION,
                PromptQualityAssuranceScope.DEFAULT_MODEL_PROFILE,
                PromptQualityAssuranceScope.DEFAULT_VERIFIER_VERSION,
                "OFFICIAL_VERIFICATION",
                "CLEAN",
                "sep-blocked-001",
                "agg-run-001",
                "cert-001",
                0,
                "summary",
                "2026-04-28 09:00:00",
                "2026-04-28 09:00:01");
    }

    private List<RuntimeEvidenceMetricResult> metricResults(
            PromptQualityOfficialMetricCatalog metricCatalog,
            List<? extends OfficialVerificationRunView> runs,
            List<OfficialVerificationPromptComparison> comparisons,
            String packageId) {
        return new OfficialVerificationMetricResultAssembler(
                metricCatalog,
                PromptQualityTestResolvers.englishBundle()).assemble(runs, comparisons, packageId);
    }

    private List<OfficialVerificationPromptComparison> promptComparisons(
            SealedEvidencePackage evidencePackage,
            List<? extends OfficialVerificationRunView> runs) {
        PromptQualityMessageResolver resolver = PromptQualityTestResolvers.englishBundle();
        PromptComparisonValueInterpreter values = new PromptComparisonValueInterpreter(resolver);
        SealedPromptEvidenceComparisonAssembler sealedEvidenceAssembler =
                new SealedPromptEvidenceComparisonAssembler(new ObjectMapper(), resolver, values);
        return new OfficialVerificationPromptComparisonAssembler(
                sealedEvidenceAssembler,
                values,
                resolver).assemble(evidencePackage, runs);
    }

    private DefaultPromptQualityRuntimeVerificationService runtimeService() {
        return runtimeService(mock(PromptQualityOfficialMetricCatalog.class));
    }

    private DefaultPromptQualityRuntimeVerificationService runtimeService(PromptQualityOfficialMetricCatalog metricCatalog) {
        return service(
                mock(SealedEvidencePackageQueryService.class),
                mock(RuntimeEvidenceReplayService.class),
                mock(RuntimeEvidencePromptScorecardService.class),
                mock(OfficialSealedEvidenceVerificationRuntime.class),
                mock(PromptQualityRuntimeCertificationPolicy.class),
                mock(PromptQualityProtectableResourceLookup.class),
                metricCatalog,
                mock(PromptQualityAssuranceCaseService.class),
                mock(RuntimeIssueDiagnosticService.class),
                null,
                new ObjectMapper(),
                ignored -> new RuntimeEvidencePromptConsistencyResult(
                        "READY",
                        "Ready",
                        true,
                        false,
                        List.of(),
                        List.of(),
                        List.of()),
                mock(PromptQualityProcessRunService.class));
    }

    private boolean blockingPromptComparison(OfficialVerificationPromptComparison comparison) {
        return comparison != null
                && List.of(
                        "PROMPT_MISSING",
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
                        "BASELINE_MISMATCH_SIGNAL")
                .contains(String.valueOf(comparison.state()));
    }
}
