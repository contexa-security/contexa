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
import static org.mockito.Mockito.when;

/**
 * W6-8 (PV-5, PV-6): a bundle of this build is released only on an evaluation made with that bundle's
 * hash (PV-5, PV-6); an evaluation of another bundle hash under the same version name does not open the gate.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PromptGovernanceReleaseGateBundleHashTest {

    private static final String SCOPE = PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE;
    private static final String KEY = "cortex.security-decision";
    private static final String VERSION = "2026.10.16-v20.22";
    private static final String CONTRACT = "CORTEX_PROMPT_CONTRACT_V3";

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
    }

    @Test
    void anEvaluationOfAnotherBundleHashDoesNotOpenTheGate() {
        records("another-bundle-hash");

        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = release();

        assertThat(receipt.applied()).isFalse();
        assertThat(receipt.blockers()).anyMatch(blocker -> blocker.startsWith("EVALUATION_NOT_FOR_BUNDLE_HASH"));
    }

    @Test
    void anEvaluationOfThisBundleHashIsTheBundlesEvaluation() {
        records(PromptBundleCatalog.shared().find(KEY, VERSION).orElseThrow().bundleHash());

        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = release();

        assertThat(receipt.blockers()).noneMatch(blocker -> blocker.startsWith("EVALUATION_NOT_FOR_BUNDLE_HASH"));
    }

    private PromptGovernanceReleaseGateService.ReleaseTransitionReceipt release() {
        return service.transitionPromptRelease(SCOPE, KEY, VERSION, PromptReleaseStatus.PRODUCTION, "platform-admin",
                "Release the evaluated bundle.", "OSS_OPERATOR_API");
    }

    private void records(String evaluatedBundleHash) {
        when(registryRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(SCOPE, KEY,
                VERSION)).thenReturn(Optional.of(PromptGovernanceRegistryRecord.builder().registryScope(SCOPE)
                .promptKey(KEY).templateKey("SecurityDecisionStandard").promptVersion(VERSION).contractVersion(CONTRACT)
                .promptArtifactHashSha256("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .releaseStatus("CANARY").owner("contexa-cortex-core").releaseApprovalReference("P5-D6B-2026-10-16")
                .rollbackPromptVersion("2026.10.16-v19.18").changeSummary("summary")
                .templateClassName("SecurityDecisionStandardPromptTemplate").registrationSource("test").build()));
        when(modelCompatibilityRepository.findByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(SCOPE,
                KEY, VERSION)).thenReturn(List.of(PromptGovernanceModelCompatibilityRecord.builder().registryScope(SCOPE)
                .promptKey(KEY).promptVersion(VERSION).modelProfileKey("MODEL_COMPATIBLE_OPENAI_ANTHROPIC_GEMINI")
                .profileCategory("PROVIDER_COMPATIBILITY").providerScope("OPENAI|ANTHROPIC|GEMINI")
                .compatibilityState("DECLARED_NOT_VERIFIED").tokenCountingPolicyKey("MODEL_AWARE_TOKEN_COUNTING_V1")
                .cachePolicyKey("STRUCTURED_PROMPT_CACHE_BY_REQUEST_AND_BUDGET_V1")
                .compactionPolicyKey("LOSSLESS_PROMPT_OPTIMIZATION_V1").registrationSource("test").build()));
        when(budgetProfileRepository.findByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(SCOPE, KEY,
                VERSION)).thenReturn(List.of(PromptGovernanceBudgetProfileRecord.builder().registryScope(SCOPE)
                .promptKey(KEY).promptVersion(VERSION).budgetProfileKey("CORTEX_L1_INTERACTIVE_STRICT")
                .maxInputTokens(4200).budgetState("DECLARED_IMPORTED")
                .tokenCountingPolicyKey("MODEL_AWARE_TOKEN_COUNTING_V1")
                .cachePolicyKey("STRUCTURED_PROMPT_CACHE_BY_REQUEST_AND_BUDGET_V1").cachePolicyState("DECLARED")
                .compactionPolicyKey("LOSSLESS_PROMPT_OPTIMIZATION_V1").compactionPolicyState("DECLARED")
                .registrationSource("test").build()));
        when(changeRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(SCOPE, KEY,
                VERSION)).thenReturn(Optional.of(PromptGovernanceChangeRecord.builder().promptKey(KEY)
                .promptVersion(VERSION).build()));
        when(evaluationRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(SCOPE, KEY,
                VERSION)).thenReturn(Optional.of(PromptGovernanceEvaluationRecord.builder().evaluationState("PASSED")
                .empiricalEvidenceState("SATISFIED").tevvGateState("READY_FOR_PRODUCTION")
                .promptInjectionState("PASSED").latencyGateState("PASSED").costGateState("PASSED")
                .bundleHash(evaluatedBundleHash).runReference("protocol-4e311e2c").build()));
        when(releaseApprovalRepository
                .findFirstByRegistryScopeAndPromptKeyAndTemplateKeyAndPromptVersionAndContractVersionOrderByUpdatedAtDesc(
                        SCOPE, KEY, "SecurityDecisionStandard", VERSION, CONTRACT))
                .thenReturn(Optional.of(PromptGovernanceReleaseApprovalRecord.builder().approvalState("APPROVED").build()));
        when(rollbackRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(SCOPE, KEY,
                VERSION)).thenReturn(Optional.of(PromptGovernanceRollbackRecord.builder()
                .rollbackTargetPromptVersion("2026.10.16-v19.18").rollbackReadinessState("READY").build()));
        when(workflowRepository.save(any(PromptGovernanceReleaseWorkflowRecord.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }
}
