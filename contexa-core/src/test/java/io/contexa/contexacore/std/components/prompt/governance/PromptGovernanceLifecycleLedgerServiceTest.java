package io.contexa.contexacore.std.components.prompt.governance;

import io.contexa.contexacore.repository.prompt.PromptGovernanceChangeRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceEvaluationRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseApprovalRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRollbackRecordRepository;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceChangeRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceEvaluationRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceReleaseApprovalRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceRollbackRecord;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PromptGovernanceLifecycleLedgerServiceTest {

    @Mock
    private PromptGovernanceRegistryService promptGovernanceRegistryService;
    @Mock
    private PromptGovernanceChangeRecordRepository changeRepository;
    @Mock
    private PromptGovernanceEvaluationRecordRepository evaluationRepository;
    @Mock
    private PromptGovernanceReleaseApprovalRepository releaseApprovalRepository;
    @Mock
    private PromptGovernanceRollbackRecordRepository rollbackRepository;

    private PromptGovernanceLifecycleLedgerService service;

    @BeforeEach
    void setUp() {
        service = new PromptGovernanceLifecycleLedgerService(
                promptGovernanceRegistryService,
                changeRepository,
                evaluationRepository,
                releaseApprovalRepository,
                rollbackRepository);
    }

    @Test
    void syncPlatformLifecycleLedgersPersistsImportedDeclarationsWithoutOverclaimingEmpiricalEval() {
        when(changeRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(any(), any(), any()))
                .thenReturn(Optional.empty());
        when(evaluationRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(any(), any(), any()))
                .thenReturn(Optional.empty());
        when(releaseApprovalRepository.findFirstByRegistryScopeAndPromptKeyAndTemplateKeyAndPromptVersionAndContractVersionOrderByUpdatedAtDesc(
                any(), any(), any(), any(), any()))
                .thenReturn(Optional.empty());
        when(changeRepository.save(any(PromptGovernanceChangeRecord.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(evaluationRepository.save(any(PromptGovernanceEvaluationRecord.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(releaseApprovalRepository.save(any(PromptGovernanceReleaseApprovalRecord.class))).thenAnswer(invocation -> invocation.getArgument(0));

        service.syncPlatformLifecycleLedgers();

        // One declaration row per bundle the build runs: the v19 bundle and the v20 bundle (W3-16).
        int bundles = PromptGovernanceRegistryService.platformStandardDescriptors().size();
        assertThat(bundles).isEqualTo(2);
        verify(promptGovernanceRegistryService).syncPlatformRegistry();
        verify(changeRepository, times(bundles)).save(any(PromptGovernanceChangeRecord.class));
        // N-GOV-2: a declaration row needs the scenario families its bundle's manifest declares, or the default ones.
        ArgumentCaptor<PromptGovernanceEvaluationRecord> evaluation =
                ArgumentCaptor.forClass(PromptGovernanceEvaluationRecord.class);
        verify(evaluationRepository, times(bundles)).save(evaluation.capture());
        for (PromptGovernanceEvaluationRecord row : evaluation.getAllValues()) {
            assertThat(row.getRequiredScenarioCount()).isEqualTo(PromptGovernanceEmpiricalEvalService
                    .requiredScenarioFamilies(PromptBundleCatalog.shared()
                            .find(row.getPromptKey(), row.getPromptVersion()).orElse(null)).size());
        }
        verify(releaseApprovalRepository, times(bundles)).save(any(PromptGovernanceReleaseApprovalRecord.class));
        // The v19 bundle declares no rollback target (its former target has no text), so it gets no rollback row. The
        // v20 bundle declares the v19 bundle of this build: its row records the declared target, not a ready rollback
        // (W1-18, PV-3).
        ArgumentCaptor<PromptGovernanceRollbackRecord> rollback = ArgumentCaptor.forClass(PromptGovernanceRollbackRecord.class);
        verify(rollbackRepository).save(rollback.capture());
        assertThat(rollback.getValue().getPromptVersion()).isEqualTo("2026.10.16-v20.24");
        assertThat(rollback.getValue().getRollbackTargetPromptVersion()).isEqualTo("2026.10.16-v19.20");
        assertThat(rollback.getValue().getRollbackState()).isEqualTo("TARGET_DECLARED");
        assertThat(rollback.getValue().getRollbackReadinessState()).isEqualTo("WORKFLOW_MISSING");
    }

    @Test
    void syncPlatformLifecycleLedgersLeavesRecordedLedgerRowsAsTheyAre() {
        PromptGovernanceEvaluationRecord recordedEvaluation = PromptGovernanceEvaluationRecord.builder()
                .evaluationState("PASSED")
                .empiricalEvidenceState("SATISFIED")
                .tevvGateState("READY_FOR_PRODUCTION")
                .registrationSource("PROMPT_EMPIRICAL_EVAL_WORKFLOW")
                .build();
        PromptGovernanceReleaseApprovalRecord recordedApproval = PromptGovernanceReleaseApprovalRecord.builder()
                .approvalState("APPROVED")
                .releaseStatus("ACTIVE")
                .registrationSource("PROMPT_RELEASE_GATE_WORKFLOW")
                .build();
        when(changeRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(any(), any(), any()))
                .thenReturn(Optional.of(PromptGovernanceChangeRecord.builder().changeState("APPROVED").build()));
        when(evaluationRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(any(), any(), any()))
                .thenReturn(Optional.of(recordedEvaluation));
        when(releaseApprovalRepository.findFirstByRegistryScopeAndPromptKeyAndTemplateKeyAndPromptVersionAndContractVersionOrderByUpdatedAtDesc(
                any(), any(), any(), any(), any()))
                .thenReturn(Optional.of(recordedApproval));

        service.syncPlatformLifecycleLedgers();

        // An evaluation recorded by the evaluation workflow is not rewritten to MISSING / NOT_READY, and an approval is
        // not rewritten to the imported declaration (version management PV-4, PV-5).
        verify(changeRepository, never()).save(any(PromptGovernanceChangeRecord.class));
        verify(evaluationRepository, never()).save(any(PromptGovernanceEvaluationRecord.class));
        verify(releaseApprovalRepository, never()).save(any(PromptGovernanceReleaseApprovalRecord.class));
        assertThat(recordedEvaluation.getEmpiricalEvidenceState()).isEqualTo("SATISFIED");
        assertThat(recordedEvaluation.getTevvGateState()).isEqualTo("READY_FOR_PRODUCTION");
        assertThat(recordedApproval.getApprovalState()).isEqualTo("APPROVED");
    }

    @Test
    void getSnapshotExposesEmpiricalEvalGapForProductionPrompt() {
        when(promptGovernanceRegistryService.getSnapshot(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE, 16))
                .thenReturn(new PromptGovernanceView.PromptGovernanceRegistrySnapshot(
                        PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                        1,
                        1,
                        1,
                        1,
                        1,
                        1,
                        "CONTROLLED_PRODUCTION",
                        List.of(new PromptGovernanceView.PromptGovernanceRegistryItem(
                                "cortex.security-decision",
                                "SecurityDecisionStandard",
                                "2026.04.04-e0.2",
                                "CORTEX_PROMPT_CONTRACT_V2",
                                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                                "PRODUCTION",
                                "contexa-cortex-core",
                                "P0-Preflight/E0-2",
                                "2026.03.26-e0.1",
                                "2026.03.26-e0.1",
                                true,
                                true,
                                true,
                                true,
                                List.of("STRICT_JSON_SCHEMA", "MODEL_COMPATIBLE_OPENAI_ANTHROPIC_GEMINI"),
                                "io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate",
                                "STANDARD_TEMPLATE_BOOTSTRAP",
                                LocalDateTime.of(2026, 3, 26, 11, 0),
                                List.of(),
                                "registry summary")),
                        LocalDateTime.of(2026, 3, 26, 11, 5)));
        when(changeRepository.findByRegistryScopeOrderByUpdatedAtDesc(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE))
                .thenReturn(List.of(PromptGovernanceChangeRecord.builder()
                        .registryScope(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE)
                        .promptKey("cortex.security-decision")
                        .promptVersion("2026.04.04-e0.2")
                        .contractVersion("CORTEX_PROMPT_CONTRACT_V2")
                        .changeReference("IMPORTED-CHANGE:2026.04.04-e0.2")
                        .changeType("PROMPT_GOVERNANCE_STANDARDIZATION")
                        .changeState("IMPORTED_DECLARATION")
                        .changeSummary("summary")
                        .changedBy("contexa-cortex-core")
                        .registrationSource("STANDARD_TEMPLATE_BOOTSTRAP")
                        .updatedAt(LocalDateTime.of(2026, 3, 26, 11, 10))
                        .build()));
        when(evaluationRepository.findByRegistryScopeOrderByUpdatedAtDesc(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE))
                .thenReturn(List.of(PromptGovernanceEvaluationRecord.builder()
                        .registryScope(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE)
                        .promptKey("cortex.security-decision")
                        .promptVersion("2026.04.04-e0.2")
                        .evaluationReference("2026.03.26-e0.1")
                        .evaluationMode("POLICY_BASELINE")
                        .evaluationState("BASELINE_DECLARED")
                        .empiricalEvidenceState("MISSING")
                        .promptInjectionState("NOT_VERIFIED")
                        .latencyGateState("NOT_VERIFIED")
                        .costGateState("NOT_VERIFIED")
                        .evaluationSummary("summary")
                        .evaluatedBy("contexa-cortex-core")
                        .registrationSource("STANDARD_TEMPLATE_BOOTSTRAP")
                        .updatedAt(LocalDateTime.of(2026, 3, 26, 11, 11))
                        .build()));
        when(releaseApprovalRepository.findByRegistryScopeOrderByUpdatedAtDesc(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE))
                .thenReturn(List.of(PromptGovernanceReleaseApprovalRecord.builder()
                        .registryScope(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE)
                        .promptKey("cortex.security-decision")
                        .promptVersion("2026.04.04-e0.2")
                        .releaseApprovalReference("P0-Preflight/E0-2")
                        .releaseStatus("PRODUCTION")
                        .approvalState("IMPORTED_DECLARATION")
                        .approvalChannel("STANDARD_TEMPLATE_BOOTSTRAP")
                        .approvedBy("contexa-cortex-core")
                        .approvalSummary("summary")
                        .registrationSource("STANDARD_TEMPLATE_BOOTSTRAP")
                        .updatedAt(LocalDateTime.of(2026, 3, 26, 11, 12))
                        .build()));
        when(rollbackRepository.findByRegistryScopeOrderByUpdatedAtDesc(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE))
                .thenReturn(List.of(PromptGovernanceRollbackRecord.builder()
                        .registryScope(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE)
                        .promptKey("cortex.security-decision")
                        .promptVersion("2026.04.04-e0.2")
                        .rollbackReference("IMPORTED-ROLLBACK:2026.04.04-e0.2")
                        .rollbackTargetPromptVersion("2026.03.26-e0.1")
                        .rollbackState("TARGET_DECLARED")
                        .rollbackReadinessState("WORKFLOW_MISSING")
                        .rollbackStrategy("VERSION_ROLLBACK")
                        .rollbackReason("summary")
                        .preparedBy("contexa-cortex-core")
                        .registrationSource("STANDARD_TEMPLATE_BOOTSTRAP")
                        .updatedAt(LocalDateTime.of(2026, 3, 26, 11, 13))
                        .build()));

        PromptGovernanceView.PromptGovernanceLifecycleLedgerSnapshot snapshot = service.getSnapshot(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                10);

        assertThat(snapshot.promptCount()).isEqualTo(1);
        assertThat(snapshot.changeRecordedCount()).isEqualTo(1);
        assertThat(snapshot.empiricalEvalSatisfiedCount()).isZero();
        assertThat(snapshot.releaseWorkflowControlledCount()).isZero();
        assertThat(snapshot.rollbackPreparedCount()).isZero();
        assertThat(snapshot.modelCompatibleCount()).isEqualTo(1);
        assertThat(snapshot.lifecycleState()).isEqualTo("EMPIRICAL_EVAL_GAP");
        assertThat(snapshot.lifecycleFacts()).anyMatch(fact -> fact.contains("lack empirical prompt evaluation evidence"));
        assertThat(snapshot.prompts()).hasSize(1);
        assertThat(snapshot.prompts().get(0).lifecycleItemState()).isEqualTo("EMPIRICAL_EVAL_GAP");
        assertThat(snapshot.prompts().get(0).empiricalEvalSatisfied()).isFalse();
        assertThat(snapshot.prompts().get(0).releaseWorkflowControlled()).isFalse();
        assertThat(snapshot.prompts().get(0).rollbackPrepared()).isFalse();
    }
}
