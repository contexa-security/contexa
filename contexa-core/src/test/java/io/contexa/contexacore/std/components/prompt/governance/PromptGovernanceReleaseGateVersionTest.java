/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.std.components.prompt.governance;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptDocument;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceEvaluationRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceRegistryRecord;
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
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleState;
import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionCatalog;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionDocument;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Plan 3.9: the release gate of the versions of the database ({@code v2.0}). Each of the 14 blockers of a bundle reads
 * as the version table says: the state rules of the labels keep blocking, the change record and the product policy
 * are always there, the evaluation is a trial the gate recommends with a warning instead of requiring, the injection
 * guard is read from the version, and the rollback target is the version deciding now. A version used for decisions
 * before another becomes AVAILABLE.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PromptGovernanceReleaseGateVersionTest {

    private static final String SCOPE = PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE;
    private static final String KEY = SecurityDecisionPromptDocument.PROMPT;
    /** A prompt whose product the build does not ship, so it declares no product policy. */
    private static final String OTHER = "cortex.unshipped";
    private static final String TEMPLATE = "SecurityDecisionStandard";
    private static final String CONTRACT = "CORTEX_PROMPT_CONTRACT_V5";

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

    private final Versions versions = new Versions();
    private final List<PromptGovernanceRegistryRecord> rows = new ArrayList<>();
    private PromptGovernanceReleaseGateService gate;

    @BeforeEach
    void setUp() {
        gate = new PromptGovernanceReleaseGateService(lifecycleLedgerService, registryRepository, changeRepository,
                evaluationRepository, releaseApprovalRepository, rollbackRepository, workflowRepository,
                modelCompatibilityRepository, budgetProfileRepository, versions);
        when(workflowRepository.save(any(PromptGovernanceReleaseWorkflowRecord.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(registryRepository.findByRegistryScopeAndPromptKeyOrderByUpdatedAtDesc(any(), any()))
                .thenAnswer(invocation -> rows.stream()
                        .filter(row -> row.getPromptKey().equals(invocation.getArgument(1))).toList());
        when(registryRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(any(), any(),
                any())).thenAnswer(invocation -> rows.stream()
                .filter(row -> row.getPromptKey().equals(invocation.getArgument(1))
                        && row.getPromptVersion().equals(invocation.getArgument(2))).findFirst());
    }

    // ----- ILLEGAL_STATE_TRANSITION: the state rules of the labels keep blocking -----

    @Test
    void aHiddenVersionIsNotUsedUsedFirstOrRunAlongside() {
        version(KEY, 1, "AVAILABLE", true);

        for (PromptBundleState target : List.of(PromptBundleState.ACTIVE, PromptBundleState.CANARY,
                PromptBundleState.SHADOW)) {
            assertThat(transition(KEY, "v1.0", target).blockers())
                    .singleElement().asString().startsWith("ILLEGAL_STATE_TRANSITION");
        }
    }

    @Test
    void aVersionTheVersionTableDoesNotHaveIsNotUsed() {
        row(KEY, "v7.0", "AVAILABLE", TEMPLATE);

        assertThat(transition(KEY, "v7.0", PromptBundleState.ACTIVE).blockers())
                .singleElement().asString().startsWith("ILLEGAL_STATE_TRANSITION");
    }

    @Test
    void aHiddenRowTakesNoStateAndAVersionUsedFirstOrAlongsideIsNotHidden() {
        version(KEY, 1, "RETIRED", true);
        version(KEY, 2, "CANARY", false);
        version(KEY, 3, "SHADOW", false);

        assertThat(transition(KEY, "v1.0", PromptBundleState.AVAILABLE).blockers())
                .singleElement().asString().startsWith("ILLEGAL_STATE_TRANSITION");
        assertThat(transition(KEY, "v2.0", PromptBundleState.RETIRED).blockers())
                .singleElement().asString().startsWith("ILLEGAL_STATE_TRANSITION");
        assertThat(transition(KEY, "v3.0", PromptBundleState.RETIRED).blockers())
                .singleElement().asString().startsWith("ILLEGAL_STATE_TRANSITION");
    }

    @Test
    void aVersionMovesBetweenTheLabelsOfTheScreens() {
        version(KEY, 1, "ACTIVE", false);
        version(KEY, 2, "AVAILABLE", false);
        version(KEY, 3, "AVAILABLE", false);
        version(KEY, 4, "AVAILABLE", false);
        versions.deciding = "v1.0";

        assertThat(transition(KEY, "v2.0", PromptBundleState.CANARY).applied()).isTrue();
        // A canary takes its state again to change its share, and stops by going back to AVAILABLE.
        assertThat(transition(KEY, "v2.0", PromptBundleState.CANARY).applied()).isTrue();
        assertThat(transition(KEY, "v2.0", PromptBundleState.AVAILABLE).applied()).isTrue();
        assertThat(transition(KEY, "v3.0", PromptBundleState.SHADOW).applied()).isTrue();
        assertThat(transition(KEY, "v3.0", PromptBundleState.AVAILABLE).applied()).isTrue();
        assertThat(transition(KEY, "v4.0", PromptBundleState.RETIRED).applied()).isTrue();
        assertThat(state(KEY, "v2.0")).isEqualTo("AVAILABLE");
        assertThat(state(KEY, "v3.0")).isEqualTo("AVAILABLE");
        assertThat(state(KEY, "v4.0")).isEqualTo("RETIRED");
    }

    // ----- NO_OTHER_ACTIVE_RELEASE: the version used for decisions is not hidden -----

    @Test
    void theVersionUsedForDecisionsIsNotHiddenNorLeftUnusedAlone() {
        version(KEY, 1, "ACTIVE", false);
        version(KEY, 2, "AVAILABLE", false);

        assertThat(transition(KEY, "v1.0", PromptBundleState.RETIRED).blockers())
                .singleElement().asString().startsWith("NO_OTHER_ACTIVE_RELEASE");
        assertThat(transition(KEY, "v1.0", PromptBundleState.AVAILABLE).blockers())
                .singleElement().asString().startsWith("NO_OTHER_ACTIVE_RELEASE");
        assertThat(state(KEY, "v1.0")).isEqualTo("ACTIVE");
    }

    // ----- CHANGE_LEDGER_MISSING, the product policy, NON_FUNCTIONAL and the evaluations: never blocking -----

    /**
     * A version without a change record, a compatibility or budget ledger row, an evaluation or a trial is used for
     * decisions: its description and parts are its change record, its product policy is inherited, its length was
     * checked before it was saved, and a trial is recommended with a warning.
     */
    @Test
    void aVersionWithoutLedgerRowsEvaluationsOrTrialsIsUsedWithAWarning() {
        version(KEY, 1, "ACTIVE", false);
        version(KEY, 2, "AVAILABLE", false);
        versions.deciding = "v1.0";

        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = transition(KEY, "v2.0",
                PromptBundleState.ACTIVE);

        assertThat(receipt.applied()).isTrue();
        assertThat(receipt.blockers()).isEmpty();
        assertThat(receipt.warnings()).singleElement().asString()
                .startsWith(PromptGovernanceReleaseGateService.TRIAL_RECOMMENDED);
        assertThat(state(KEY, "v2.0")).isEqualTo("ACTIVE");
    }

    @Test
    void anEvaluationOfAnotherHashOrThatFailedItsGatesDoesNotBlockAVersion() {
        version(KEY, 1, "AVAILABLE", false);
        when(evaluationRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(SCOPE, KEY,
                "v1.0")).thenReturn(Optional.of(PromptGovernanceEvaluationRecord.builder()
                .evaluationReference("old").evaluationState("FAILED").empiricalEvidenceState("MISSING")
                .tevvGateState("NON_FUNCTIONAL_BLOCK").promptInjectionState("FAILED").latencyGateState("FAILED")
                .costGateState("FAILED").bundleHash("another-hash").build()));

        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = transition(KEY, "v1.0",
                PromptBundleState.ACTIVE);

        assertThat(receipt.blockers()).isEmpty();
        assertThat(receipt.applied()).isTrue();
    }

    @Test
    void aFinishedTrialTakesTheWarningAway() {
        version(KEY, 1, "AVAILABLE", false);
        versions.trials.add(1);

        PromptGovernanceReleaseGateService.ReleaseGateAssessment assessment = gate.assessPromptRelease(SCOPE, KEY,
                "v1.0");

        assertThat(assessment.targets()).filteredOn(target -> "ACTIVE".equals(target.targetState())).singleElement()
                .satisfies(target -> {
                    assertThat(target.ready()).isTrue();
                    assertThat(target.warnings()).isEmpty();
                });
        assertThat(transition(KEY, "v1.0", PromptBundleState.ACTIVE).warnings()).isEmpty();
    }

    @Test
    void theAssessmentOfAVersionWithoutATrialIsReadyAndWarns() {
        version(KEY, 1, "AVAILABLE", false);

        PromptGovernanceReleaseGateService.ReleaseGateAssessment assessment = gate.assessPromptRelease(SCOPE, KEY,
                "v1.0");

        assertThat(assessment.targets()).extracting(PromptGovernanceReleaseGateService.ReleaseGateTarget::targetState)
                .containsExactly("ACTIVE", "CANARY", "SHADOW", "RETIRED");
        assertThat(assessment.targets()).filteredOn(target -> List.of("ACTIVE", "CANARY")
                .contains(target.targetState())).allSatisfy(target -> {
                    assertThat(target.ready()).isTrue();
                    assertThat(target.warnings()).singleElement().asString()
                            .startsWith(PromptGovernanceReleaseGateService.TRIAL_RECOMMENDED);
                });
        assertThat(assessment.targets()).filteredOn(target -> "SHADOW".equals(target.targetState())).singleElement()
                .satisfies(target -> assertThat(target.warnings()).isEmpty());
        assertThat(assessment.evidence().providerCompatibilityDeclared()).isTrue();
        assertThat(assessment.evidence().budgetProfileKeys()).isNotEmpty();
        assertThat(assessment.evidence().tokenCountingPolicyDeclared()).isTrue();
        assertThat(assessment.evidence().cachePolicyGoverned()).isTrue();
        assertThat(assessment.evidence().compactionPolicyGoverned()).isTrue();
    }

    /** The product policy blocks only a prompt whose product declares none (the start fails for a shipped one). */
    @Test
    void aPromptWithoutAProductPolicyIsBlockedByEachOfItsFiveGaps() {
        version(OTHER, 1, "AVAILABLE", false);

        assertThat(codes(transition(OTHER, "v1.0", PromptBundleState.ACTIVE).blockers())).containsExactlyInAnyOrder(
                "MODEL_COMPATIBILITY_MISSING", "BUDGET_PROFILE_MISSING", "TOKEN_COUNTING_POLICY_MISSING",
                "CACHE_POLICY_MISSING", "COMPACTION_POLICY_MISSING");
        assertThat(codes(transition(OTHER, "v1.0", PromptBundleState.CANARY).blockers())).containsExactlyInAnyOrder(
                "MODEL_COMPATIBILITY_MISSING", "BUDGET_PROFILE_MISSING");
        assertThat(transition(OTHER, "v1.0", PromptBundleState.SHADOW).blockers()).isEmpty();
    }

    // ----- PROMPT_INJECTION_GATE_FAILED: read from the version -----

    @Test
    void aVersionThatDoesNotKeepTheInjectionGuardDoesNotDecide() {
        version(KEY, 1, "ACTIVE", false);
        version(KEY, 2, "AVAILABLE", false);
        versions.deciding = "v1.0";
        versions.assembled.put(2, withoutLockedEvidenceReading());

        assertThat(codes(transition(KEY, "v2.0", PromptBundleState.ACTIVE).blockers()))
                .containsExactly("PROMPT_INJECTION_GATE_FAILED");
        assertThat(codes(transition(KEY, "v2.0", PromptBundleState.CANARY).blockers()))
                .containsExactly("PROMPT_INJECTION_GATE_FAILED");
        // Run alongside, nothing it answers is enforced.
        assertThat(transition(KEY, "v2.0", PromptBundleState.SHADOW).blockers()).isEmpty();
    }

    // ----- ROLLBACK_TARGET_MISSING: the version deciding now -----

    @Test
    void theRollbackTargetIsTheVersionDecidingNowAndTheLedgerKeepsIt() {
        version(KEY, 1, "AVAILABLE", false);
        version(KEY, 2, "AVAILABLE", false);
        versions.deciding = "v1.0";

        assertThat(transition(KEY, "v2.0", PromptBundleState.ACTIVE).applied()).isTrue();

        ArgumentCaptor<PromptGovernanceRollbackRecord> ledger = ArgumentCaptor.forClass(PromptGovernanceRollbackRecord.class);
        verify(rollbackRepository).save(ledger.capture());
        assertThat(ledger.getValue().getPromptVersion()).isEqualTo("v2.0");
        assertThat(ledger.getValue().getRollbackTargetPromptVersion()).isEqualTo("v1.0");
        assertThat(ledger.getValue().getRollbackReadinessState()).isEqualTo("READY");
    }

    @Test
    void theOneVersionOfAPromptAndTheVersionDecidingNowNeedNoRollbackTarget() {
        version(KEY, 1, "AVAILABLE", false);

        assertThat(transition(KEY, "v1.0", PromptBundleState.ACTIVE).blockers()).isEmpty();

        version(KEY, 2, "AVAILABLE", false);
        versions.deciding = "v2.0";
        assertThat(transition(KEY, "v2.0", PromptBundleState.ACTIVE).blockers()).isEmpty();
    }

    @Test
    void withoutAVersionDecidingNowASecondVersionHasNoRollbackTarget() {
        version(KEY, 1, "AVAILABLE", false);
        version(KEY, 2, "AVAILABLE", false);
        versions.deciding = null;

        assertThat(codes(transition(KEY, "v2.0", PromptBundleState.ACTIVE).blockers()))
                .containsExactly("ROLLBACK_TARGET_MISSING");
        assertThat(codes(transition(KEY, "v2.0", PromptBundleState.CANARY).blockers()))
                .containsExactly("ROLLBACK_TARGET_MISSING");
    }

    // ----- the version used before becomes AVAILABLE -----

    @Test
    void usingAVersionLeavesTheVersionUsedBeforeAvailableAndAnEarlierBundleDeprecated() {
        PromptGovernanceRegistryRecord before = version(KEY, 1, "ACTIVE", false);
        version(KEY, 2, "SHADOW", false);
        PromptGovernanceRegistryRecord bundle = row(KEY, "2026.11.16-v1.0", "ACTIVE", TEMPLATE);
        PromptGovernanceRegistryRecord otherTemplate = row(KEY, "v9.0", "ACTIVE", "OtherTemplate");
        versions.deciding = "v1.0";

        assertThat(transition(KEY, "v2.0", PromptBundleState.ACTIVE).applied()).isTrue();

        assertThat(state(KEY, "v2.0")).isEqualTo("ACTIVE");
        assertThat(before.getReleaseStatus()).isEqualTo("AVAILABLE");
        assertThat(bundle.getReleaseStatus()).isEqualTo("DEPRECATED");
        assertThat(otherTemplate.getReleaseStatus()).isEqualTo("ACTIVE");
        verify(registryRepository, never()).save(otherTemplate);
        ArgumentCaptor<PromptGovernanceReleaseWorkflowRecord> workflows =
                ArgumentCaptor.forClass(PromptGovernanceReleaseWorkflowRecord.class);
        verify(workflowRepository, atLeastOnce()).save(workflows.capture());
        assertThat(workflows.getAllValues()).filteredOn(workflow -> "SUPERSEDED".equals(workflow.getGateState()))
                .extracting(PromptGovernanceReleaseWorkflowRecord::getPromptVersion,
                        PromptGovernanceReleaseWorkflowRecord::getTargetReleaseStatus)
                .containsExactlyInAnyOrder(tuple("v1.0", "AVAILABLE"), tuple("2026.11.16-v1.0", "DEPRECATED"));
    }

    // ----- helpers -----

    private PromptGovernanceReleaseGateService.ReleaseTransitionReceipt transition(String prompt, String version,
                                                                                  PromptBundleState target) {
        return gate.transitionPromptRelease(SCOPE, prompt, version, target, "operator-a", "plan 3.9", "OSS_OPERATOR_API");
    }

    private PromptGovernanceRegistryRecord version(String prompt, int number, String state, boolean hidden) {
        versions.entries.put(prompt + "|" + number, new PromptVersionCatalog.Entry(SCOPE, prompt, number,
                "hash-" + number, number == 1 ? null : 1, number == 1 ? PromptVersionCatalog.CONTEXA : "ORGANIZATION",
                hidden));
        return row(prompt, "v" + number + ".0", state, TEMPLATE);
    }

    private PromptGovernanceRegistryRecord row(String prompt, String version, String state, String template) {
        PromptGovernanceRegistryRecord record = PromptGovernanceRegistryRecord.builder().registryScope(SCOPE)
                .promptKey(prompt).templateKey(template).promptVersion(version).contractVersion(CONTRACT)
                .promptArtifactHashSha256("hash").releaseStatus(state).owner("contexa-cortex-core")
                .changeSummary(version).templateClassName("SecurityDecisionStandardPromptTemplate")
                .registrationSource("PROMPT_VERSION_PRODUCT").build();
        rows.add(record);
        return record;
    }

    private String state(String prompt, String version) {
        return rows.stream().filter(row -> row.getPromptKey().equals(prompt) && row.getPromptVersion().equals(version))
                .findFirst().orElseThrow().getReleaseStatus();
    }

    private static List<String> codes(List<String> blockers) {
        return blockers.stream().map(blocker -> blocker.split(" ", 2)[0]).toList();
    }

    /** The product version with its evidence reading part left changeable, as no saved version can be. */
    private static AssembledPrompt withoutLockedEvidenceReading() {
        AssembledPrompt product = SecurityDecisionPromptDocument.product();
        List<PromptVersionDocument.Part> system = product.system().stream()
                .map(part -> !"evidence-reading".equals(part.key()) ? part
                        : new PromptVersionDocument.Part(part.key(), part.title(), false, part.join(), part.heading(),
                        part.group(), part.when(), part.prepared(), part.text(), part.whenText(), part.items(),
                        part.effects(), part.action(), part.addAfter()))
                .toList();
        return new AssembledPrompt(product.prompt(), product.release(), product.title(), system, product.user(),
                product.corrections(), true);
    }

    /** The version table of the test: its versions, their assembled prompts, the one deciding and the trials. */
    private static final class Versions implements PromptVersionCatalog {

        private final Map<String, Entry> entries = new LinkedHashMap<>();
        private final Map<Integer, AssembledPrompt> assembled = new LinkedHashMap<>();
        private final Set<Integer> trials = new HashSet<>();
        private String deciding;

        @Override
        public List<Entry> versions(String scope, String prompt) {
            return entries.values().stream().filter(entry -> entry.prompt().equals(prompt))
                    .sorted(Comparator.comparingInt(Entry::number).reversed()).toList();
        }

        @Override
        public Optional<AssembledPrompt> assembled(String scope, String prompt, String name) {
            return find(scope, prompt, name).map(entry -> assembled.getOrDefault(entry.number(),
                    SecurityDecisionPromptDocument.product()));
        }

        @Override
        public Optional<String> deciding(String scope, String prompt) {
            return Optional.ofNullable(deciding);
        }

        @Override
        public boolean trialFinished(String scope, String prompt, String name) {
            return find(scope, prompt, name).filter(entry -> trials.contains(entry.number())).isPresent();
        }
    }
}
