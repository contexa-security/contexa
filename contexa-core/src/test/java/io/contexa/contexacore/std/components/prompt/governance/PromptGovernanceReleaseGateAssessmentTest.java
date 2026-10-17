package io.contexa.contexacore.std.components.prompt.governance;

import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceBudgetProfileRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceChangeRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceEvaluationRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceModelCompatibilityRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceRegistryRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceReleaseApprovalRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceReleaseWorkflowRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceRollbackRecord;
import io.contexa.contexacore.repository.prompt.PromptGovernanceBudgetProfileRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceChangeRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceEvaluationRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceModelCompatibilityRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRegistryRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseApprovalRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseWorkflowRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRollbackRecordRepository;
import io.contexa.contexacore.std.components.prompt.PromptReleaseStatus;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleState;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * W7-14 (PV-8): the version screen's 'ready' is the release gate's own answer. For every state a bundle may take
 * next, the assessment gives the blockers the transition would meet, read without writing, and the evidence the gate
 * reads; a state is ready exactly when a transition to it is applied.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PromptGovernanceReleaseGateAssessmentTest {

    private static final String SCOPE = PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE;
    private static final String KEY = "cortex.security-decision";
    private static final String VERSION = "2026.10.16-v20.22";
    private static final String CONTRACT = "CORTEX_PROMPT_CONTRACT_V3";
    private static final String ROLLBACK = "2026.10.16-v19.18";

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
        service = new PromptGovernanceReleaseGateService(lifecycleLedgerService, registryRepository, changeRepository,
                evaluationRepository, releaseApprovalRepository, rollbackRepository, workflowRepository,
                modelCompatibilityRepository, budgetProfileRepository);
        when(workflowRepository.save(any(PromptGovernanceReleaseWorkflowRecord.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }

    @Test
    void everyNextStateTheGateAllowsIsAssessedInOrderAndNothingIsWritten() {
        records("CANARY", PromptBundleCatalog.shared().find(KEY, VERSION).orElseThrow().bundleHash(), true);

        PromptGovernanceReleaseGateService.ReleaseGateAssessment assessment = service.assessPromptRelease(SCOPE, KEY,
                VERSION);

        assertThat(assessment.currentState()).isEqualTo(PromptBundleState.CANARY.name());
        assertThat(assessment.targets()).extracting(PromptGovernanceReleaseGateService.ReleaseGateTarget::targetState)
                .containsExactly("ACTIVE", "DEPRECATED", "RETIRED");
        verify(workflowRepository, never()).save(any(PromptGovernanceReleaseWorkflowRecord.class));
        verify(registryRepository, never()).save(any(PromptGovernanceRegistryRecord.class));
        verify(releaseApprovalRepository, never()).save(any(PromptGovernanceReleaseApprovalRecord.class));
        verify(rollbackRepository, never()).save(any(PromptGovernanceRollbackRecord.class));
    }

    @Test
    void aStateIsReadyExactlyWhenTheTransitionIsApplied() {
        records("CANARY", PromptBundleCatalog.shared().find(KEY, VERSION).orElseThrow().bundleHash(), true);

        PromptGovernanceReleaseGateService.ReleaseGateTarget active = target(service.assessPromptRelease(SCOPE, KEY,
                VERSION), "ACTIVE");
        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = transition(PromptReleaseStatus.PRODUCTION);

        assertThat(active.ready()).isTrue();
        assertThat(active.blockers()).isEmpty();
        assertThat(receipt.applied()).isTrue();
        assertThat(active.gateState()).isEqualTo(receipt.gateState());
    }

    @Test
    void aBlockedStateCarriesTheBlockersTheTransitionIsRefusedWith() {
        records("CANARY", "another-bundle-hash", false);

        PromptGovernanceReleaseGateService.ReleaseGateTarget active = target(service.assessPromptRelease(SCOPE, KEY,
                VERSION), "ACTIVE");
        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = transition(PromptReleaseStatus.PRODUCTION);

        assertThat(active.ready()).isFalse();
        assertThat(active.blockers()).isNotEmpty()
                .anyMatch(blocker -> blocker.startsWith("EVALUATION_NOT_FOR_BUNDLE_HASH"))
                .anyMatch(blocker -> blocker.startsWith("BUDGET_PROFILE_MISSING"));
        assertThat(receipt.applied()).isFalse();
        assertThat(active.blockers()).isEqualTo(receipt.blockers());
        assertThat(active.gateState()).isEqualTo(receipt.gateState());
    }

    @Test
    void theEvidenceIsWhatTheGateReads() {
        records("CANARY", "another-bundle-hash", true);

        PromptGovernanceReleaseGateService.ReleaseGateEvidence evidence = service.assessPromptRelease(SCOPE, KEY,
                VERSION).evidence();

        assertThat(evidence).isNotNull();
        assertThat(evidence.changeRecorded()).isTrue();
        assertThat(evidence.evaluationReference()).isEqualTo("P6-GATE-1");
        assertThat(evidence.evaluationState()).isEqualTo("PASSED");
        assertThat(evidence.tevvGateState()).isEqualTo("READY_FOR_PRODUCTION");
        assertThat(evidence.evaluationBundleHash()).isEqualTo("another-bundle-hash");
        assertThat(evidence.evaluationRunReference()).isEqualTo("protocol-4e311e2c");
        assertThat(evidence.evaluationForThisBundle()).isFalse();
        assertThat(evidence.approvalState()).isEqualTo("APPROVED");
        assertThat(evidence.approvedBy()).isEqualTo("operator-a");
        assertThat(evidence.rollbackTargetPromptVersion()).isEqualTo(ROLLBACK);
        assertThat(evidence.rollbackReadinessState()).isEqualTo("READY");
        assertThat(evidence.providerCompatibilityDeclared()).isTrue();
        assertThat(evidence.budgetProfileKeys()).containsExactly("CORTEX_L1_INTERACTIVE_STRICT");
        assertThat(evidence.tokenCountingPolicyDeclared()).isTrue();
    }

    /**
     * N-GOV-3: next to the covered and required counts, the evidence names the families the bundle requires (its
     * manifest's, else the default families: this version's manifest declares none), the families the evaluation
     * covered and the required ones it left uncovered.
     */
    @Test
    void theEvidenceNamesTheRequiredCoveredAndUncoveredScenarioFamilies() {
        records("CANARY", "another-bundle-hash", true);
        when(evaluationRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(SCOPE, KEY,
                VERSION)).thenReturn(Optional.of(PromptGovernanceEvaluationRecord.builder()
                .evaluationReference("P6-GATE-1").evaluationState("PARTIAL").coveredScenarioCount(1)
                .requiredScenarioCount(3).coveredScenarioFamiliesJson("[\"PROMPT_INJECTION\"]")
                .bundleHash("another-bundle-hash").build()));

        PromptGovernanceReleaseGateService.ReleaseGateEvidence evidence = service.assessPromptRelease(SCOPE, KEY,
                VERSION).evidence();

        assertThat(evidence.requiredScenarioFamilies())
                .containsExactly("PROMPT_INJECTION", "TOOL_MISUSE", "MEMORY_POISONING");
        assertThat(evidence.coveredScenarioFamilies()).containsExactly("PROMPT_INJECTION");
        assertThat(evidence.uncoveredScenarioFamilies()).containsExactly("TOOL_MISUSE", "MEMORY_POISONING");
    }

    @Test
    void aRetiredBundleHasNoNextState() {
        records("RETIRED", PromptBundleCatalog.shared().find(KEY, VERSION).orElseThrow().bundleHash(), true);

        PromptGovernanceReleaseGateService.ReleaseGateAssessment assessment = service.assessPromptRelease(SCOPE, KEY,
                VERSION);

        assertThat(assessment.currentState()).isEqualTo("RETIRED");
        assertThat(assessment.targets()).isEmpty();
    }

    private static PromptGovernanceReleaseGateService.ReleaseGateTarget target(
            PromptGovernanceReleaseGateService.ReleaseGateAssessment assessment, String state) {
        return assessment.targets().stream().filter(target -> state.equals(target.targetState())).findFirst()
                .orElseThrow();
    }

    private PromptGovernanceReleaseGateService.ReleaseTransitionReceipt transition(PromptReleaseStatus target) {
        return service.transitionPromptRelease(SCOPE, KEY, VERSION, target, "operator-b", "W7-14 test",
                "OSS_OPERATOR_API");
    }

    private void records(String releaseStatus, String evaluatedBundleHash, boolean budgetProfiles) {
        when(registryRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(SCOPE, KEY,
                VERSION)).thenReturn(Optional.of(PromptGovernanceRegistryRecord.builder().registryScope(SCOPE)
                .promptKey(KEY).templateKey("SecurityDecisionStandard").promptVersion(VERSION).contractVersion(CONTRACT)
                .promptArtifactHashSha256("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .releaseStatus(releaseStatus).owner("contexa-cortex-core").releaseApprovalReference("P6-GATE-1")
                .rollbackPromptVersion(ROLLBACK).changeSummary("summary")
                .templateClassName("SecurityDecisionStandardPromptTemplate").registrationSource("test").build()));
        when(modelCompatibilityRepository.findByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(SCOPE,
                KEY, VERSION)).thenReturn(List.of(PromptGovernanceModelCompatibilityRecord.builder().registryScope(SCOPE)
                .promptKey(KEY).promptVersion(VERSION).modelProfileKey("MODEL_COMPATIBLE_OPENAI_ANTHROPIC_GEMINI")
                .profileCategory("PROVIDER_COMPATIBILITY").providerScope("OPENAI|ANTHROPIC|GEMINI")
                .compatibilityState("DECLARED_NOT_VERIFIED").tokenCountingPolicyKey("MODEL_AWARE_TOKEN_COUNTING_V1")
                .cachePolicyKey("STRUCTURED_PROMPT_CACHE_BY_REQUEST_AND_BUDGET_V1")
                .compactionPolicyKey("LOSSLESS_PROMPT_OPTIMIZATION_V1").registrationSource("test").build()));
        when(budgetProfileRepository.findByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(SCOPE, KEY,
                VERSION)).thenReturn(budgetProfiles ? List.of(PromptGovernanceBudgetProfileRecord.builder()
                .registryScope(SCOPE).promptKey(KEY).promptVersion(VERSION)
                .budgetProfileKey("CORTEX_L1_INTERACTIVE_STRICT").maxInputTokens(4200).budgetState("DECLARED_IMPORTED")
                .tokenCountingPolicyKey("MODEL_AWARE_TOKEN_COUNTING_V1")
                .cachePolicyKey("STRUCTURED_PROMPT_CACHE_BY_REQUEST_AND_BUDGET_V1").cachePolicyState("DECLARED")
                .compactionPolicyKey("LOSSLESS_PROMPT_OPTIMIZATION_V1").compactionPolicyState("DECLARED")
                .registrationSource("test").build()) : List.of());
        when(changeRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(SCOPE, KEY,
                VERSION)).thenReturn(Optional.of(PromptGovernanceChangeRecord.builder().promptKey(KEY)
                .promptVersion(VERSION).build()));
        when(evaluationRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(SCOPE, KEY,
                VERSION)).thenReturn(Optional.of(PromptGovernanceEvaluationRecord.builder()
                .evaluationReference("P6-GATE-1").evaluationState("PASSED").empiricalEvidenceState("SATISFIED")
                .tevvGateState("READY_FOR_PRODUCTION").promptInjectionState("PASSED").latencyGateState("PASSED")
                .costGateState("PASSED").bundleHash(evaluatedBundleHash).runReference("protocol-4e311e2c").build()));
        when(releaseApprovalRepository
                .findFirstByRegistryScopeAndPromptKeyAndTemplateKeyAndPromptVersionAndContractVersionOrderByUpdatedAtDesc(
                        SCOPE, KEY, "SecurityDecisionStandard", VERSION, CONTRACT))
                .thenReturn(Optional.of(PromptGovernanceReleaseApprovalRecord.builder().approvalState("APPROVED")
                        .approvedBy("operator-a").build()));
        when(rollbackRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(SCOPE, KEY,
                VERSION)).thenReturn(Optional.of(PromptGovernanceRollbackRecord.builder()
                .rollbackTargetPromptVersion(ROLLBACK).rollbackReadinessState("READY").build()));
    }
}
