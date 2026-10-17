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
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleState;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * N-GOV-4 and N-GOV-5 (P8): the release gate's transitions in the canonical states (version management decision 1 and
 * section 8). A receipt names the previous state canonically, as its target. A bundle the gate activates is the one
 * active release of its scope, prompt key and template: the active releases it replaces become DEPRECATED, each with
 * its workflow record and without a rollback (DEPRECATED is entered when another bundle becomes ACTIVE). An explicit
 * deprecation needs another active release in the bundle's place and no rollback target of its own, and the only active
 * release is not deprecated; rolling back is the rollback service's (W6-10).
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PromptGovernanceReleaseGateStatesTest {

    private static final String SCOPE = PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE;
    private static final String KEY = "cortex.security-decision";
    private static final String TEMPLATE = "SecurityDecisionStandard";
    private static final String CONTRACT = "CORTEX_PROMPT_CONTRACT_V3";
    private static final String V20 = "2026.10.16-v20.22";
    private static final String V19 = "2026.10.16-v19.18";
    private static final String V19_OLDER = "2026.10.15-v19.17";

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
    void theReceiptNamesThePreviousStateInTheCanonicalVocabulary() {
        records("PRODUCTION", true);

        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = transition(V20,
                PromptBundleState.CANARY);

        // N-GOV-4: the receipt named the stored value (PRODUCTION here) beside a canonical target.
        assertThat(receipt.applied()).isTrue();
        assertThat(receipt.previousReleaseStatus()).isEqualTo("ACTIVE");
        assertThat(receipt.targetReleaseStatus()).isEqualTo("CANARY");
    }

    @Test
    void anActivationDeprecatesTheOtherActiveReleasesOfItsScopeKeyAndTemplate() {
        PromptGovernanceRegistryRecord activated = records("CANARY", true);
        PromptGovernanceRegistryRecord v19 = row(V19, "ACTIVE", TEMPLATE);
        PromptGovernanceRegistryRecord older = row(V19_OLDER, "PRODUCTION", TEMPLATE);
        PromptGovernanceRegistryRecord otherTemplate = row("2026.10.14-v19.13", "ACTIVE", "OtherTemplate");
        PromptGovernanceRegistryRecord deprecated = row("2026.10.13-v19.9", "DEPRECATED", TEMPLATE);
        scope(activated, v19, older, otherTemplate, deprecated);

        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = transition(V20,
                PromptBundleState.ACTIVE);

        assertThat(receipt.applied()).isTrue();
        assertThat(activated.getReleaseStatus()).isEqualTo("ACTIVE");
        assertThat(v19.getReleaseStatus()).isEqualTo("DEPRECATED");
        assertThat(older.getReleaseStatus()).isEqualTo("DEPRECATED");
        assertThat(otherTemplate.getReleaseStatus()).isEqualTo("ACTIVE");
        assertThat(deprecated.getReleaseStatus()).isEqualTo("DEPRECATED");
        verify(registryRepository).save(v19);
        verify(registryRepository).save(older);
        verify(registryRepository, never()).save(otherTemplate);
        verify(registryRepository, never()).save(deprecated);
        ArgumentCaptor<PromptGovernanceReleaseWorkflowRecord> workflows =
                ArgumentCaptor.forClass(PromptGovernanceReleaseWorkflowRecord.class);
        verify(workflowRepository, atLeastOnce()).save(workflows.capture());
        List<PromptGovernanceReleaseWorkflowRecord> superseded = workflows.getAllValues().stream()
                .filter(workflow -> !V20.equals(workflow.getPromptVersion())).toList();
        assertThat(superseded).extracting(PromptGovernanceReleaseWorkflowRecord::getPromptVersion,
                        PromptGovernanceReleaseWorkflowRecord::getCurrentReleaseStatus,
                        PromptGovernanceReleaseWorkflowRecord::getTargetReleaseStatus,
                        PromptGovernanceReleaseWorkflowRecord::getGateState)
                .containsExactlyInAnyOrder(tuple(V19, "ACTIVE", "DEPRECATED", "SUPERSEDED"),
                        tuple(V19_OLDER, "ACTIVE", "DEPRECATED", "SUPERSEDED"));
        assertThat(superseded).allMatch(workflow -> workflow.getRationale().contains(V20));
        // The replaced releases are not rolled back: only the activated release's own rollback state is written.
        verify(rollbackRepository, times(1)).save(any(PromptGovernanceRollbackRecord.class));
        verify(releaseApprovalRepository, times(1)).save(any(PromptGovernanceReleaseApprovalRecord.class));
    }

    @Test
    void aRefusedActivationDeprecatesNothing() {
        PromptGovernanceRegistryRecord activated = records("CANARY", false);
        PromptGovernanceRegistryRecord v19 = row(V19, "ACTIVE", TEMPLATE);
        scope(activated, v19);

        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = transition(V20,
                PromptBundleState.ACTIVE);

        assertThat(receipt.applied()).isFalse();
        assertThat(v19.getReleaseStatus()).isEqualTo("ACTIVE");
        verify(registryRepository, never()).save(any(PromptGovernanceRegistryRecord.class));
    }

    @Test
    void aBundleAnotherActiveReleaseReplacesIsDeprecatedWithoutARollbackTargetOfItsOwn() {
        PromptGovernanceRegistryRecord v19 = release(V19, "ACTIVE", null);
        PromptGovernanceRegistryRecord v20 = row(V20, "ACTIVE", TEMPLATE);
        scope(v19, v20);

        PromptGovernanceReleaseGateService.ReleaseGateTarget assessed = service.assessPromptRelease(SCOPE, KEY, V19)
                .targets().stream().filter(target -> "DEPRECATED".equals(target.targetState())).findFirst()
                .orElseThrow();
        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = transition(V19,
                PromptBundleState.DEPRECATED);

        // Before N-GOV-5 a deprecation was the bundle's own rollback execution: ROLLBACK_TARGET_MISSING without one.
        assertThat(assessed.ready()).isTrue();
        assertThat(receipt.applied()).isTrue();
        assertThat(receipt.blockers()).isEmpty();
        assertThat(receipt.gateState()).isEqualTo("SUPERSEDED").isEqualTo(assessed.gateState());
        assertThat(v19.getReleaseStatus()).isEqualTo("DEPRECATED");
        assertThat(v20.getReleaseStatus()).isEqualTo("ACTIVE");
        verify(rollbackRepository, never()).save(any(PromptGovernanceRollbackRecord.class));
        ArgumentCaptor<PromptGovernanceReleaseApprovalRecord> approval =
                ArgumentCaptor.forClass(PromptGovernanceReleaseApprovalRecord.class);
        verify(releaseApprovalRepository).save(approval.capture());
        assertThat(approval.getValue().getApprovalState()).isEqualTo("APPROVED");
        assertThat(approval.getValue().getReleaseStatus()).isEqualTo("DEPRECATED");
    }

    @Test
    void theOnlyActiveReleaseIsNotDeprecated() {
        PromptGovernanceRegistryRecord v19 = release(V19, "ACTIVE", V19_OLDER);
        scope(v19, row(V19_OLDER, "DEPRECATED", TEMPLATE), row("2026.10.14-v19.13", "ACTIVE", "OtherTemplate"));

        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = transition(V19,
                PromptBundleState.DEPRECATED);

        // Before N-GOV-5 a declared rollback target let the only active release go, and none was left to run.
        assertThat(receipt.applied()).isFalse();
        assertThat(receipt.blockers()).hasSize(1);
        assertThat(receipt.blockers().get(0)).startsWith("NO_OTHER_ACTIVE_RELEASE");
        assertThat(v19.getReleaseStatus()).isEqualTo("ACTIVE");
        verify(registryRepository, never()).save(any(PromptGovernanceRegistryRecord.class));
    }

    private PromptGovernanceReleaseGateService.ReleaseTransitionReceipt transition(String version,
                                                                                  PromptBundleState target) {
        return service.transitionPromptRelease(SCOPE, KEY, version, target, "operator-b", "N-GOV-5 test",
                "OSS_OPERATOR_API");
    }

    private void scope(PromptGovernanceRegistryRecord... rows) {
        when(registryRepository.findByRegistryScopeAndPromptKeyOrderByUpdatedAtDesc(SCOPE, KEY))
                .thenReturn(List.of(rows));
    }

    private static PromptGovernanceRegistryRecord row(String version, String releaseStatus, String templateKey) {
        return PromptGovernanceRegistryRecord.builder().registryScope(SCOPE).promptKey(KEY).templateKey(templateKey)
                .promptVersion(version).contractVersion(CONTRACT)
                .promptArtifactHashSha256("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .releaseStatus(releaseStatus).owner("contexa-cortex-core").changeSummary("summary")
                .templateClassName("SecurityDecisionStandardPromptTemplate").registrationSource("test").build();
    }

    /** A release with its change record only, and the rollback target its row declares (none when null). */
    private PromptGovernanceRegistryRecord release(String version, String releaseStatus, String rollbackTarget) {
        PromptGovernanceRegistryRecord record = row(version, releaseStatus, TEMPLATE);
        record.setRollbackPromptVersion(rollbackTarget);
        when(registryRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(SCOPE, KEY,
                version)).thenReturn(Optional.of(record));
        when(changeRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(SCOPE, KEY,
                version)).thenReturn(Optional.of(PromptGovernanceChangeRecord.builder().promptKey(KEY)
                .promptVersion(version).build()));
        return record;
    }

    /** The v20 release with the evidence a canary and an activation need (budget profiles when asked). */
    private PromptGovernanceRegistryRecord records(String releaseStatus, boolean budgetProfiles) {
        PromptGovernanceRegistryRecord record = release(V20, releaseStatus, V19);
        record.setReleaseApprovalReference("P8-GATE-1");
        when(modelCompatibilityRepository.findByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(SCOPE,
                KEY, V20)).thenReturn(List.of(PromptGovernanceModelCompatibilityRecord.builder().registryScope(SCOPE)
                .promptKey(KEY).promptVersion(V20).modelProfileKey("MODEL_COMPATIBLE_OPENAI_ANTHROPIC_GEMINI")
                .profileCategory("PROVIDER_COMPATIBILITY").providerScope("OPENAI|ANTHROPIC|GEMINI")
                .compatibilityState("DECLARED_NOT_VERIFIED").tokenCountingPolicyKey("MODEL_AWARE_TOKEN_COUNTING_V1")
                .cachePolicyKey("STRUCTURED_PROMPT_CACHE_BY_REQUEST_AND_BUDGET_V1")
                .compactionPolicyKey("LOSSLESS_PROMPT_OPTIMIZATION_V1").registrationSource("test").build()));
        when(budgetProfileRepository.findByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(SCOPE, KEY,
                V20)).thenReturn(budgetProfiles ? List.of(PromptGovernanceBudgetProfileRecord.builder()
                .registryScope(SCOPE).promptKey(KEY).promptVersion(V20)
                .budgetProfileKey("CORTEX_L1_INTERACTIVE_STRICT").maxInputTokens(4200).budgetState("DECLARED_IMPORTED")
                .tokenCountingPolicyKey("MODEL_AWARE_TOKEN_COUNTING_V1")
                .cachePolicyKey("STRUCTURED_PROMPT_CACHE_BY_REQUEST_AND_BUDGET_V1").cachePolicyState("DECLARED")
                .compactionPolicyKey("LOSSLESS_PROMPT_OPTIMIZATION_V1").compactionPolicyState("DECLARED")
                .registrationSource("test").build()) : List.of());
        when(evaluationRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(SCOPE, KEY,
                V20)).thenReturn(Optional.of(PromptGovernanceEvaluationRecord.builder()
                .evaluationReference("P8-GATE-1").evaluationState("PASSED").empiricalEvidenceState("SATISFIED")
                .tevvGateState("READY_FOR_PRODUCTION").promptInjectionState("PASSED").latencyGateState("PASSED")
                .costGateState("PASSED").bundleHash(PromptBundleCatalog.shared().find(KEY, V20).orElseThrow()
                        .bundleHash()).runReference("protocol-4e311e2c").build()));
        when(releaseApprovalRepository
                .findFirstByRegistryScopeAndPromptKeyAndTemplateKeyAndPromptVersionAndContractVersionOrderByUpdatedAtDesc(
                        SCOPE, KEY, TEMPLATE, V20, CONTRACT))
                .thenReturn(Optional.of(PromptGovernanceReleaseApprovalRecord.builder().approvalState("APPROVED")
                        .approvedBy("operator-a").build()));
        when(rollbackRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(SCOPE, KEY,
                V20)).thenReturn(Optional.of(PromptGovernanceRollbackRecord.builder()
                .rollbackTargetPromptVersion(V19).rollbackReadinessState("READY").build()));
        return record;
    }
}
