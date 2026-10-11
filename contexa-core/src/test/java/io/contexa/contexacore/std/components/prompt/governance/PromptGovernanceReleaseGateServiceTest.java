package io.contexa.contexacore.std.components.prompt.governance;

import io.contexa.contexacore.std.components.prompt.PromptReleaseStatus;
import io.contexa.contexacore.repository.prompt.PromptGovernanceBudgetProfileRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceChangeRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceEvaluationRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceModelCompatibilityRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRegistryRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseApprovalRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseWorkflowRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRollbackRecordRepository;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceChangeRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceBudgetProfileRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceEvaluationRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceModelCompatibilityRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceRegistryRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceReleaseApprovalRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceReleaseWorkflowRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceRollbackRecord;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PromptGovernanceReleaseGateServiceTest {

    @Mock
    private PromptGovernanceLifecycleLedgerService lifecycleLedgerService;
    @Mock
    private PromptGovernanceRegistryRepository registryRepository;
    @Mock
    private PromptGovernanceChangeRecordRepository changeRepository;
    @Mock
    private PromptGovernanceEvaluationRecordRepository evaluationRepository;
    @Mock
    private PromptGovernanceReleaseApprovalRepository releaseApprovalRepository;
    @Mock
    private PromptGovernanceRollbackRecordRepository rollbackRepository;
    @Mock
    private PromptGovernanceReleaseWorkflowRepository workflowRepository;
    @Mock
    private PromptGovernanceModelCompatibilityRepository modelCompatibilityRepository;
    @Mock
    private PromptGovernanceBudgetProfileRepository budgetProfileRepository;

    private PromptGovernanceReleaseGateService service;

    @BeforeEach
    void setUp() {
        service = new PromptGovernanceReleaseGateService(
                lifecycleLedgerService,
                registryRepository,
                changeRepository,
                evaluationRepository,
                releaseApprovalRepository,
                rollbackRepository,
                workflowRepository,
                modelCompatibilityRepository,
                budgetProfileRepository);
    }

    @Test
    void getSnapshotMarksImportedProductionAsUncontrolled() {
        when(lifecycleLedgerService.getSnapshot(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE, 10))
                .thenReturn(new PromptGovernanceView.PromptGovernanceLifecycleLedgerSnapshot(
                        PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                        1,
                        1,
                        0,
                        0,
                        0,
                        1,
                        "EMPIRICAL_EVAL_GAP",
                        List.of(),
                        List.of(new PromptGovernanceView.PromptGovernanceLifecycleLedgerItem(
                                "cortex.security-decision",
                                "SecurityDecisionStandard",
                                "2026.04.04-e0.2",
                                "CORTEX_PROMPT_CONTRACT_V2",
                                "PRODUCTION",
                                "IMPORTED-CHANGE:2026.04.04-e0.2",
                                "PROMPT_GOVERNANCE_STANDARDIZATION",
                                "IMPORTED_DECLARATION",
                                true,
                                "2026.03.26-e0.1",
                                "POLICY_BASELINE",
                                "BASELINE_DECLARED",
                                "MISSING",
                                "NOT_VERIFIED",
                                false,
                                "P0-Preflight/E0-2",
                                "IMPORTED_DECLARATION",
                                "STANDARD_TEMPLATE_BOOTSTRAP",
                                false,
                                "IMPORTED-ROLLBACK:2026.04.04-e0.2",
                                "2026.03.26-e0.1",
                                "TARGET_DECLARED",
                                "WORKFLOW_MISSING",
                                false,
                                true,
                                List.of("STRICT_JSON_SCHEMA"),
                                "EMPIRICAL_EVAL_GAP",
                                LocalDateTime.of(2026, 3, 26, 12, 0),
                                List.of(),
                                "summary")),
                        LocalDateTime.of(2026, 3, 26, 12, 5)));
        when(workflowRepository.findByRegistryScopeOrderByCreatedAtDesc(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE))
                .thenReturn(List.of());
        when(budgetProfileRepository.findByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                "cortex.security-decision",
                "2026.04.04-e0.2")).thenReturn(List.of(budgetProfileRecord()));

        PromptGovernanceView.PromptGovernanceReleaseGateSnapshot snapshot = service.getSnapshot(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                10);

        assertThat(snapshot.gateState()).isEqualTo("UNCONTROLLED_PRODUCTION");
        assertThat(snapshot.prompts()).hasSize(1);
        assertThat(snapshot.prompts().get(0).gateState()).isEqualTo("UNCONTROLLED_PRODUCTION");
        assertThat(snapshot.prompts().get(0).expectedNextReleaseStatus()).isEqualTo("CANARY");
        // Decision 1: the gate names the canonical states; ROLLED_BACK reads as DEPRECATED.
        assertThat(snapshot.prompts().get(0).allowedNextReleaseStatuses()).containsExactly("CANARY", "DEPRECATED", "RETIRED");
    }

    @Test
    void transitionPromptReleaseBlocksProductionWhenEmpiricalEvalIsMissing() {
        PromptGovernanceRegistryRecord registryRecord = registryRecord("CANARY");
        when(registryRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                "cortex.security-decision",
                "2026.04.04-e0.2")).thenReturn(Optional.of(registryRecord));
        when(modelCompatibilityRepository.findByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                "cortex.security-decision",
                "2026.04.04-e0.2")).thenReturn(List.of(compatibilityRecord()));
        when(budgetProfileRepository.findByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                "cortex.security-decision",
                "2026.04.04-e0.2")).thenReturn(List.of(budgetProfileRecord()));
        when(changeRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                "cortex.security-decision",
                "2026.04.04-e0.2")).thenReturn(Optional.of(PromptGovernanceChangeRecord.builder()
                .promptKey("cortex.security-decision")
                .promptVersion("2026.04.04-e0.2")
                .build()));
        when(evaluationRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                "cortex.security-decision",
                "2026.04.04-e0.2")).thenReturn(Optional.of(PromptGovernanceEvaluationRecord.builder()
                .evaluationState("BASELINE_DECLARED")
                .empiricalEvidenceState("MISSING")
                .build()));
        when(releaseApprovalRepository.findFirstByRegistryScopeAndPromptKeyAndTemplateKeyAndPromptVersionAndContractVersionOrderByUpdatedAtDesc(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                "cortex.security-decision",
                "SecurityDecisionStandard",
                "2026.04.04-e0.2",
                "CORTEX_PROMPT_CONTRACT_V2")).thenReturn(Optional.of(PromptGovernanceReleaseApprovalRecord.builder()
                .approvalState("APPROVED")
                .build()));
        when(rollbackRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                "cortex.security-decision",
                "2026.04.04-e0.2")).thenReturn(Optional.of(PromptGovernanceRollbackRecord.builder()
                .rollbackTargetPromptVersion("2026.03.26-e0.1")
                .rollbackReadinessState("READY")
                .build()));
        when(workflowRepository.save(any(PromptGovernanceReleaseWorkflowRecord.class))).thenAnswer(invocation -> {
            PromptGovernanceReleaseWorkflowRecord record = invocation.getArgument(0);
            record.setCreatedAt(LocalDateTime.of(2026, 3, 26, 13, 0));
            return record;
        });

        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = service.transitionPromptRelease(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                "cortex.security-decision",
                "2026.04.04-e0.2",
                PromptReleaseStatus.PRODUCTION,
                "platform-admin",
                "Attempt production release.",
                "ENTERPRISE_RELEASE_GATE");

        assertThat(receipt.applied()).isFalse();
        assertThat(receipt.gateState()).isEqualTo("BLOCKED_BY_EMPIRICAL_EVAL_GAP");
        assertThat(receipt.blockers()).anyMatch(blocker -> blocker.contains("EMPIRICAL_EVAL_MISSING"));
        verify(workflowRepository).save(any(PromptGovernanceReleaseWorkflowRecord.class));
    }

    @Test
    void transitionPromptReleaseCanDowngradeImportedProductionToControlledCanary() {
        PromptGovernanceRegistryRecord registryRecord = registryRecord("PRODUCTION");
        when(registryRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                "cortex.security-decision",
                "2026.04.04-e0.2")).thenReturn(Optional.of(registryRecord));
        when(modelCompatibilityRepository.findByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                "cortex.security-decision",
                "2026.04.04-e0.2")).thenReturn(List.of(compatibilityRecord()));
        when(budgetProfileRepository.findByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                "cortex.security-decision",
                "2026.04.04-e0.2")).thenReturn(List.of(budgetProfileRecord()));
        when(changeRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                "cortex.security-decision",
                "2026.04.04-e0.2")).thenReturn(Optional.of(PromptGovernanceChangeRecord.builder()
                .promptKey("cortex.security-decision")
                .promptVersion("2026.04.04-e0.2")
                .build()));
        when(evaluationRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                "cortex.security-decision",
                "2026.04.04-e0.2")).thenReturn(Optional.of(PromptGovernanceEvaluationRecord.builder()
                .evaluationState("BASELINE_DECLARED")
                .empiricalEvidenceState("MISSING")
                .build()));
        when(releaseApprovalRepository.findFirstByRegistryScopeAndPromptKeyAndTemplateKeyAndPromptVersionAndContractVersionOrderByUpdatedAtDesc(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                "cortex.security-decision",
                "SecurityDecisionStandard",
                "2026.04.04-e0.2",
                "CORTEX_PROMPT_CONTRACT_V2")).thenReturn(Optional.of(PromptGovernanceReleaseApprovalRecord.builder()
                .registryScope(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE)
                .promptKey("cortex.security-decision")
                .promptVersion("2026.04.04-e0.2")
                .approvalState("IMPORTED_DECLARATION")
                .build()));
        when(rollbackRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                "cortex.security-decision",
                "2026.04.04-e0.2")).thenReturn(Optional.of(PromptGovernanceRollbackRecord.builder()
                .registryScope(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE)
                .promptKey("cortex.security-decision")
                .promptVersion("2026.04.04-e0.2")
                .rollbackTargetPromptVersion("2026.03.26-e0.1")
                .rollbackReadinessState("WORKFLOW_MISSING")
                .build()));
        when(workflowRepository.save(any(PromptGovernanceReleaseWorkflowRecord.class))).thenAnswer(invocation -> {
            PromptGovernanceReleaseWorkflowRecord record = invocation.getArgument(0);
            record.setCreatedAt(LocalDateTime.of(2026, 3, 26, 13, 30));
            return record;
        });
        when(registryRepository.save(any(PromptGovernanceRegistryRecord.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(releaseApprovalRepository.save(any(PromptGovernanceReleaseApprovalRecord.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(rollbackRepository.save(any(PromptGovernanceRollbackRecord.class))).thenAnswer(invocation -> invocation.getArgument(0));

        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = service.transitionPromptRelease(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                "cortex.security-decision",
                "2026.04.04-e0.2",
                PromptReleaseStatus.CANARY,
                "platform-admin",
                "Re-enter controlled canary.",
                "ENTERPRISE_RELEASE_GATE");

        assertThat(receipt.applied()).isTrue();
        assertThat(receipt.gateState()).isEqualTo("DEGRADED_TO_CONTROLLED_CANARY");
        ArgumentCaptor<PromptGovernanceRegistryRecord> registryCaptor = ArgumentCaptor.forClass(PromptGovernanceRegistryRecord.class);
        verify(registryRepository).save(registryCaptor.capture());
        assertThat(registryCaptor.getValue().getReleaseStatus()).isEqualTo("CANARY");
        ArgumentCaptor<PromptGovernanceReleaseWorkflowRecord> workflowCaptor = ArgumentCaptor.forClass(PromptGovernanceReleaseWorkflowRecord.class);
        verify(workflowRepository).save(workflowCaptor.capture());
        assertThat(workflowCaptor.getValue().getCurrentReleaseStatus()).isEqualTo("ACTIVE");
        assertThat(workflowCaptor.getValue().getTargetReleaseStatus()).isEqualTo("CANARY");
        ArgumentCaptor<PromptGovernanceReleaseApprovalRecord> approvalCaptor = ArgumentCaptor.forClass(PromptGovernanceReleaseApprovalRecord.class);
        verify(releaseApprovalRepository).save(approvalCaptor.capture());
        assertThat(approvalCaptor.getValue().getApprovalState()).isEqualTo("APPROVED");
        assertThat(approvalCaptor.getValue().getTemplateKey()).isEqualTo("SecurityDecisionStandard");
        assertThat(approvalCaptor.getValue().getContractVersion()).isEqualTo("CORTEX_PROMPT_CONTRACT_V2");
        ArgumentCaptor<PromptGovernanceRollbackRecord> rollbackCaptor = ArgumentCaptor.forClass(PromptGovernanceRollbackRecord.class);
        verify(rollbackRepository).save(rollbackCaptor.capture());
        assertThat(rollbackCaptor.getValue().getRollbackReadinessState()).isEqualTo("READY");
    }

    @Test
    void transitionPromptReleaseReadsAStoredScopeStatusAsACanaryInsteadOfFailing() {
        PromptGovernanceRegistryRecord registryRecord = registryRecord("ACTIVE_FOR_SCOPE");
        when(registryRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                "cortex.security-decision",
                "2026.04.04-e0.2")).thenReturn(Optional.of(registryRecord));
        when(workflowRepository.save(any(PromptGovernanceReleaseWorkflowRecord.class))).thenAnswer(invocation -> {
            PromptGovernanceReleaseWorkflowRecord record = invocation.getArgument(0);
            record.setCreatedAt(LocalDateTime.of(2026, 3, 26, 14, 0));
            return record;
        });

        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = service.transitionPromptRelease(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                "cortex.security-decision",
                "2026.04.04-e0.2",
                PromptReleaseStatus.EVAL_ONLY,
                "platform-admin",
                "Back to evaluation.",
                "ENTERPRISE_RELEASE_GATE");

        assertThat(receipt.applied()).isFalse();
        assertThat(receipt.targetReleaseStatus()).isEqualTo("SHADOW");
        assertThat(receipt.blockers()).containsExactly("ILLEGAL_STATE_TRANSITION current=ACTIVE_FOR_SCOPE target=SHADOW.");
    }

    private PromptGovernanceRegistryRecord registryRecord(String releaseStatus) {
        return PromptGovernanceRegistryRecord.builder()
                .registryScope(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE)
                .promptKey("cortex.security-decision")
                .templateKey("SecurityDecisionStandard")
                .promptVersion("2026.04.04-e0.2")
                .contractVersion("CORTEX_PROMPT_CONTRACT_V2")
                .promptArtifactHashSha256("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .releaseStatus(releaseStatus)
                .owner("contexa-cortex-core")
                .releaseApprovalReference("P0-Preflight/E0-2")
                .evaluationBaselineReference("2026.03.26-e0.1")
                .rollbackPromptVersion("2026.03.26-e0.1")
                .changeSummary("summary")
                .templateClassName("io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate")
                .registrationSource("STANDARD_TEMPLATE_BOOTSTRAP")
                .supportedModelProfilesJson("[\"STRICT_JSON_SCHEMA\"]")
                .build();
    }

    private PromptGovernanceModelCompatibilityRecord compatibilityRecord() {
        return PromptGovernanceModelCompatibilityRecord.builder()
                .registryScope(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE)
                .promptKey("cortex.security-decision")
                .promptVersion("2026.04.04-e0.2")
                .modelProfileKey("MODEL_COMPATIBLE_OPENAI_ANTHROPIC_GEMINI")
                .profileCategory("PROVIDER_COMPATIBILITY")
                .providerScope("OPENAI|ANTHROPIC|GEMINI")
                .compatibilityState("DECLARED_NOT_VERIFIED")
                .tokenCountingPolicyKey("MODEL_AWARE_TOKEN_COUNTING_V1")
                .cachePolicyKey("STRUCTURED_PROMPT_CACHE_BY_REQUEST_AND_BUDGET_V1")
                .compactionPolicyKey("LOSSLESS_PROMPT_OPTIMIZATION_V1")
                .registrationSource("STANDARD_TEMPLATE_BOOTSTRAP")
                .build();
    }

    private PromptGovernanceBudgetProfileRecord budgetProfileRecord() {
        return PromptGovernanceBudgetProfileRecord.builder()
                .registryScope(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE)
                .promptKey("cortex.security-decision")
                .promptVersion("2026.04.04-e0.2")
                .budgetProfileKey("CORTEX_L1_INTERACTIVE_STRICT")
                .maxInputTokens(4200)
                .budgetState("DECLARED_IMPORTED")
                .tokenCountingPolicyKey("MODEL_AWARE_TOKEN_COUNTING_V1")
                .cachePolicyKey("STRUCTURED_PROMPT_CACHE_BY_REQUEST_AND_BUDGET_V1")
                .cachePolicyState("DECLARED")
                .compactionPolicyKey("LOSSLESS_PROMPT_OPTIMIZATION_V1")
                .compactionPolicyState("DECLARED")
                .registrationSource("STANDARD_TEMPLATE_BOOTSTRAP")
                .build();
    }
}
