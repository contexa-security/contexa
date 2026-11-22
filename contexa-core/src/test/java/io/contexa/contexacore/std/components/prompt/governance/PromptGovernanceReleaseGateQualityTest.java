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
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceRegistryRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceReleaseWorkflowRecord;
import io.contexa.contexacore.repository.prompt.PromptGovernanceBudgetProfileRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceChangeRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceEvaluationRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceModelCompatibilityRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRegistryRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseApprovalRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseWorkflowRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRollbackRecordRepository;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleState;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateMode;
import io.contexa.contexacore.std.components.prompt.quality.QualityGatePolicy;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateReading;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSide;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateStatus;
import io.contexa.contexacore.std.components.prompt.quality.QualityMeasurementState;
import io.contexa.contexacore.std.components.prompt.version.AssembledPrompt;
import io.contexa.contexacore.std.components.prompt.version.PromptVersionCatalog;
import io.contexa.contexacore.std.components.prompt.version.VersionedPrompts;
import io.contexa.contexacore.std.rag.QueryTransformPrompt;
import io.contexa.contexacore.testsupport.QualityGateFixtures;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Plan 3.4, 5 step 5: the quality gate in the release gate. It applies to the security decision alone, when a version
 * is used for decisions or started as a canary; it blocks in the blocking mode and warns in the warning mode, keeping
 * the verdict; an operator overrides a blocking quality gate with a reason, which the workflow records, and a blank
 * reason is refused; the override passes over the quality gate alone; going back to a version the scope used for
 * decisions takes no quality condition, a canary does.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PromptGovernanceReleaseGateQualityTest {

    private static final String SCOPE = PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE;
    private static final String KEY = SecurityDecisionPromptDocument.PROMPT;
    /** A versioned prompt other than the security decision, whose product declares its policy (plan 3.11). */
    private static final String OTHER = QueryTransformPrompt.ALL.get(0).prompt();
    private static final String TEMPLATE = "SecurityDecisionStandard";

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
    private final QualityGateFixtures.Source source = QualityGateFixtures.source(
            QualityGateReading.measured(QualityGateFixtures.input(QualityGateFixtures.sound("v1.0"),
                    QualityGateFixtures.missesTheMustCatchCase("v2.0"))));

    @BeforeEach
    void setUp() {
        when(workflowRepository.save(any(PromptGovernanceReleaseWorkflowRecord.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(registryRepository.findByRegistryScopeAndPromptKeyOrderByUpdatedAtDesc(any(), any()))
                .thenAnswer(invocation -> rows.stream()
                        .filter(row -> row.getPromptKey().equals(invocation.getArgument(1))).toList());
        when(registryRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(any(), any(),
                any())).thenAnswer(invocation -> rows.stream()
                .filter(row -> row.getPromptKey().equals(invocation.getArgument(1))
                        && row.getPromptVersion().equals(invocation.getArgument(2))).findFirst());
        for (String prompt : List.of(KEY, OTHER)) {
            version(prompt, 1, "ACTIVE");
            version(prompt, 2, "AVAILABLE");
        }
        versions.deciding = "v1.0";
    }

    // ----- where it applies -----

    @Test
    void theQualityGateReadsTheSecurityDecisionAloneWhenAVersionIsUsedOrStartedAsACanary() {
        PromptGovernanceReleaseGateService gate = gate(QualityGateMode.BLOCK);

        PromptGovernanceReleaseGateService.ReleaseGateAssessment decision = gate.assessPromptRelease(SCOPE, KEY, "v2.0");
        PromptGovernanceReleaseGateService.ReleaseGateAssessment other = gate.assessPromptRelease(SCOPE, OTHER, "v2.0");

        assertThat(target(decision, "ACTIVE").quality()).isNotNull();
        assertThat(target(decision, "CANARY").quality()).isNotNull();
        assertThat(target(decision, "SHADOW").quality()).isNull();
        assertThat(target(decision, "RETIRED").quality()).isNull();
        assertThat(other.targets()).allSatisfy(target -> {
            assertThat(target.quality()).isNull();
            assertThat(target.ready()).isTrue();
        });
        // Read once for both targets, against the version deciding now.
        assertThat(source.reads()).containsExactly(SCOPE + " " + KEY + " v2.0 v1.0");
    }

    // ----- the modes -----

    @Test
    void inTheBlockingModeABlockedVersionIsNotUsedAndTheBlockerNamesTheConditions() {
        PromptGovernanceReleaseGateService gate = gate(QualityGateMode.BLOCK);

        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = gate.transitionPromptRelease(SCOPE, KEY,
                "v2.0", PromptBundleState.ACTIVE, "operator-a", "month end", "OSS_OPERATOR_API");

        assertThat(receipt.applied()).isFalse();
        assertThat(receipt.gateState()).isEqualTo("BLOCKED_BY_QUALITY_GATE");
        assertThat(receipt.blockers()).singleElement().asString()
                .startsWith(PromptGovernanceReleaseGateService.QUALITY_GATE_BLOCKED)
                .contains("MUST_CATCH_NEVER_ALLOWED");
        assertThat(receipt.quality().verdict()).isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(receipt.qualityOverridden()).isFalse();
        assertThat(state(KEY, "v2.0")).isEqualTo("AVAILABLE");
        PromptGovernanceReleaseGateService.ReleaseGateTarget active = target(gate.assessPromptRelease(SCOPE, KEY,
                "v2.0"), "ACTIVE");
        assertThat(active.ready()).isFalse();
        assertThat(active.overridable()).isTrue();
    }

    @Test
    void inTheWarningModeABlockedVerdictIsUsedWithAWarningAndTheVerdictIsKept() {
        PromptGovernanceReleaseGateService gate = gate(QualityGateMode.WARN);

        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = gate.transitionPromptRelease(SCOPE, KEY,
                "v2.0", PromptBundleState.ACTIVE, "operator-a", null, "OSS_OPERATOR_API");

        assertThat(receipt.applied()).isTrue();
        assertThat(receipt.blockers()).isEmpty();
        assertThat(receipt.quality().verdict()).isEqualTo(QualityGateStatus.BLOCKED);
        assertThat(receipt.quality().applied()).isEqualTo(QualityGateStatus.WARNING);
        assertThat(receipt.quality().mode()).isEqualTo(QualityGateMode.WARN);
        assertThat(state(KEY, "v2.0")).isEqualTo("ACTIVE");
    }

    /** Plan 3.4: the five states a source answers with, in the blocking mode. */
    @ParameterizedTest
    @EnumSource(QualityMeasurementState.class)
    void eachStateOfTheMeasurementsIsAppliedAsThePlanSays(QualityMeasurementState state) {
        source.answer(switch (state) {
            case MEASURED -> QualityGateReading.measured(QualityGateFixtures.input(QualityGateFixtures.sound("v1.0"),
                    QualityGateFixtures.sound("v2.0")));
            case MISSING -> QualityGateReading.missing(Set.of(QualityGateSide.CANDIDATE), null);
            case STALE -> QualityGateReading.stale(Set.of(QualityGateSide.CURRENT), QualityGateFixtures.input(
                    QualityGateFixtures.sound("v1.0"), QualityGateFixtures.sound("v2.0")));
            case UNMEASURABLE -> QualityGateReading.unmeasurable("NO_REPLAY");
            case BASELINE_PENDING -> QualityGateReading.baselinePending(QualityGateFixtures.input(null,
                    QualityGateFixtures.sound("v2.0")));
        });

        PromptGovernanceReleaseGateService.ReleaseGateTarget active = target(gate(QualityGateMode.BLOCK)
                .assessPromptRelease(SCOPE, KEY, "v2.0"), "ACTIVE");

        assertThat(active.quality().measurement()).isEqualTo(state);
        QualityGateStatus expected = switch (state) {
            case MEASURED -> QualityGateStatus.PASSED;
            case MISSING -> QualityGateStatus.BLOCKED;
            case STALE, UNMEASURABLE, BASELINE_PENDING -> QualityGateStatus.WARNING;
        };
        assertThat(active.quality().applied()).isEqualTo(expected);
        assertThat(active.ready()).isEqualTo(expected != QualityGateStatus.BLOCKED);
    }

    @Test
    void withoutAPolicyEveryVersionIsUsedWithTheWarningThatItCannotBeMeasured() {
        PromptGovernanceReleaseGateService gate = new PromptGovernanceReleaseGateService(lifecycleLedgerService,
                registryRepository, changeRepository, evaluationRepository, releaseApprovalRepository,
                rollbackRepository, workflowRepository, modelCompatibilityRepository, budgetProfileRepository, versions,
                null);

        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = gate.transitionPromptRelease(SCOPE, KEY,
                "v2.0", PromptBundleState.CANARY, "operator-a", null, "OSS_OPERATOR_API");

        assertThat(receipt.applied()).isTrue();
        assertThat(receipt.quality().measurement()).isEqualTo(QualityMeasurementState.UNMEASURABLE);
        assertThat(receipt.quality().applied()).isEqualTo(QualityGateStatus.WARNING);
        assertThat(gate.qualityMeasurement(SCOPE, KEY, "v1.0")).isEqualTo(QualityMeasurementState.UNMEASURABLE);
        assertThat(gate.qualityMeasurement(SCOPE, OTHER, "v1.0")).isNull();
    }

    // ----- the override -----

    @Test
    void anOperatorsReasonOverridesABlockingQualityGateAndTheWorkflowRecordsIt() {
        PromptGovernanceReleaseGateService gate = gate(QualityGateMode.BLOCK);

        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = gate.transitionPromptRelease(SCOPE, KEY,
                "v2.0", PromptBundleState.ACTIVE, "operator-a", "month end", "OSS_OPERATOR_API",
                "fixes the outage of the payroll run");

        assertThat(receipt.applied()).isTrue();
        assertThat(receipt.qualityOverridden()).isTrue();
        assertThat(receipt.gateState()).isEqualTo(PromptGovernanceReleaseGateService.QUALITY_GATE_OVERRIDDEN);
        assertThat(state(KEY, "v2.0")).isEqualTo("ACTIVE");
        ArgumentCaptor<PromptGovernanceReleaseWorkflowRecord> workflows =
                ArgumentCaptor.forClass(PromptGovernanceReleaseWorkflowRecord.class);
        verify(workflowRepository, atLeastOnce()).save(workflows.capture());
        PromptGovernanceReleaseWorkflowRecord applied = workflows.getAllValues().get(0);
        assertThat(applied.getGateState()).isEqualTo(PromptGovernanceReleaseGateService.QUALITY_GATE_OVERRIDDEN);
        assertThat(applied.getActor()).isEqualTo("operator-a");
        assertThat(applied.getRationale()).startsWith(PromptGovernanceReleaseGateService.QUALITY_GATE_OVERRIDDEN)
                .contains("MUST_CATCH_NEVER_ALLOWED", "fixes the outage of the payroll run", "month end");
    }

    @Test
    void anOverrideWithoutAReasonIsRefusedAndNothingIsRecorded() {
        PromptGovernanceReleaseGateService gate = gate(QualityGateMode.BLOCK);

        assertThatThrownBy(() -> gate.transitionPromptRelease(SCOPE, KEY, "v2.0", PromptBundleState.ACTIVE,
                "operator-a", null, "OSS_OPERATOR_API", "  ")).isInstanceOf(IllegalArgumentException.class);
        assertThat(state(KEY, "v2.0")).isEqualTo("AVAILABLE");
        verify(workflowRepository, never()).save(any(PromptGovernanceReleaseWorkflowRecord.class));
    }

    @Test
    void theOverridePassesOverTheQualityGateAloneAndTheOtherBlockersStillBlock() {
        // A version that does not keep the injection guard of its product.
        versions.assembled.put(2, new AssembledPrompt(KEY, "v2.0", "no guard", List.of(), List.of(), Map.of(), true));
        PromptGovernanceReleaseGateService gate = gate(QualityGateMode.BLOCK);

        PromptGovernanceReleaseGateService.ReleaseTransitionReceipt receipt = gate.transitionPromptRelease(SCOPE, KEY,
                "v2.0", PromptBundleState.ACTIVE, "operator-a", null, "OSS_OPERATOR_API", "urgent");

        assertThat(receipt.applied()).isFalse();
        assertThat(receipt.qualityOverridden()).isFalse();
        assertThat(codes(receipt.blockers())).containsExactly("PROMPT_INJECTION_GATE_FAILED",
                PromptGovernanceReleaseGateService.QUALITY_GATE_BLOCKED);
        assertThat(target(gate.assessPromptRelease(SCOPE, KEY, "v2.0"), "ACTIVE").overridable()).isFalse();
        assertThat(state(KEY, "v2.0")).isEqualTo("AVAILABLE");
    }

    // ----- going back -----

    @Test
    void goingBackToAVersionTheScopeUsedForDecisionsTakesNoQualityConditionButACanaryDoes() {
        versions.used.add(2);
        PromptGovernanceReleaseGateService gate = gate(QualityGateMode.BLOCK);

        PromptGovernanceReleaseGateService.ReleaseGateAssessment assessment = gate.assessPromptRelease(SCOPE, KEY,
                "v2.0");

        assertThat(target(assessment, "ACTIVE").quality().rollback()).isTrue();
        assertThat(target(assessment, "ACTIVE").ready()).isTrue();
        assertThat(target(assessment, "CANARY").quality().rollback()).isFalse();
        assertThat(target(assessment, "CANARY").ready()).isFalse();
        assertThat(gate.transitionPromptRelease(SCOPE, KEY, "v2.0", PromptBundleState.ACTIVE, "operator-a", null,
                "OSS_OPERATOR_API").applied()).isTrue();
    }

    @Test
    void theVersionDecidingNowTakesNoQualityCondition() {
        PromptGovernanceReleaseGateService gate = gate(QualityGateMode.BLOCK);

        PromptGovernanceReleaseGateService.ReleaseGateTarget active = target(gate.assessPromptRelease(SCOPE, KEY,
                "v1.0"), "ACTIVE");

        assertThat(active.quality().rollback()).isTrue();
        assertThat(active.ready()).isTrue();
        assertThat(source.reads()).isEmpty();
    }

    // ----- helpers -----

    private PromptGovernanceReleaseGateService gate(QualityGateMode mode) {
        return new PromptGovernanceReleaseGateService(lifecycleLedgerService, registryRepository, changeRepository,
                evaluationRepository, releaseApprovalRepository, rollbackRepository, workflowRepository,
                modelCompatibilityRepository, budgetProfileRepository, versions,
                new VersionedPrompts(List.copyOf(QueryTransformPrompt.ALL)),
                new QualityGatePolicy(source, mode, QualityGateFixtures.SETTINGS));
    }

    private static PromptGovernanceReleaseGateService.ReleaseGateTarget target(
            PromptGovernanceReleaseGateService.ReleaseGateAssessment assessment, String state) {
        return assessment.targets().stream().filter(target -> target.targetState().equals(state)).findFirst()
                .orElseThrow();
    }

    private void version(String prompt, int number, String state) {
        versions.entries.put(prompt + "|" + number, new PromptVersionCatalog.Entry(SCOPE, prompt, number,
                "hash-" + number, number == 1 ? null : 1, number == 1 ? PromptVersionCatalog.CONTEXA : "ORGANIZATION",
                false));
        rows.add(PromptGovernanceRegistryRecord.builder().registryScope(SCOPE).promptKey(prompt).templateKey(TEMPLATE)
                .promptVersion("v" + number + ".0").contractVersion("CORTEX_PROMPT_CONTRACT_V5")
                .promptArtifactHashSha256("hash").releaseStatus(state).owner("contexa-cortex-core")
                .changeSummary("v" + number + ".0").templateClassName("SecurityDecisionStandardPromptTemplate")
                .registrationSource("PROMPT_VERSION_PRODUCT").build());
    }

    private String state(String prompt, String version) {
        return rows.stream().filter(row -> row.getPromptKey().equals(prompt) && row.getPromptVersion().equals(version))
                .findFirst().orElseThrow().getReleaseStatus();
    }

    private static List<String> codes(List<String> blockers) {
        return blockers.stream().map(blocker -> blocker.split(" ", 2)[0]).toList();
    }

    /** The version table of the test: its versions, their assembled prompts, the one deciding and those used. */
    private static final class Versions implements PromptVersionCatalog {

        private final Map<String, Entry> entries = new LinkedHashMap<>();
        private final Map<Integer, AssembledPrompt> assembled = new LinkedHashMap<>();
        private final Set<Integer> used = new HashSet<>();
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
            return false;
        }

        @Override
        public boolean usedForDecisions(String scope, String prompt, String name) {
            return find(scope, prompt, name).filter(entry -> used.contains(entry.number())).isPresent();
        }
    }
}
