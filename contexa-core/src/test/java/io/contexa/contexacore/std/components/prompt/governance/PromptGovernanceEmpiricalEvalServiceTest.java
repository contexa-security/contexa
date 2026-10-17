package io.contexa.contexacore.std.components.prompt.governance;

import io.contexa.contexacore.repository.prompt.PromptGovernanceEvaluationRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRegistryRepository;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceEvaluationRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceRegistryRecord;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleElement;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleElementState;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleHashes;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleManifest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PromptGovernanceEmpiricalEvalServiceTest {

    @Mock
    private PromptGovernanceRegistryRepository registryRepository;
    @Mock
    private PromptGovernanceEvaluationRecordRepository evaluationRepository;

    private PromptGovernanceEmpiricalEvalService service;

    @BeforeEach
    void setUp() {
        service = new PromptGovernanceEmpiricalEvalService(registryRepository, evaluationRepository);
    }

    @Test
    void recordEvaluationMarksPromptReadyForProductionWhenAllRequiredScenariosAndGatesPass() {
        when(registryRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                "cortex.security-decision",
                "2026.04.04-e0.2")).thenReturn(Optional.of(registryRecord()));
        when(evaluationRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                "cortex.security-decision",
                "2026.04.04-e0.2")).thenReturn(Optional.empty());
        when(evaluationRepository.save(any(PromptGovernanceEvaluationRecord.class))).thenAnswer(invocation -> {
            PromptGovernanceEvaluationRecord record = invocation.getArgument(0);
            record.setUpdatedAt(LocalDateTime.of(2026, 3, 26, 14, 0));
            return record;
        });

        PromptGovernanceEmpiricalEvalService.EvalRegistrationReceipt receipt = service.recordEvaluation(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                "cortex.security-decision",
                "2026.04.04-e0.2",
                "PROMPT-TEVV-2026-03-26",
                "REPLAY_SUITE",
                List.of("PROMPT_INJECTION", "TOOL_MISUSE", "MEMORY_POISONING"),
                "PASSED",
                "PASSED",
                "PASSED",
                "platform-admin",
                "Full prompt TEVV passed.");

        assertThat(receipt.evaluationState()).isEqualTo("PASSED");
        assertThat(receipt.tevvGateState()).isEqualTo("READY_FOR_PRODUCTION");
        ArgumentCaptor<PromptGovernanceEvaluationRecord> captor = ArgumentCaptor.forClass(PromptGovernanceEvaluationRecord.class);
        verify(evaluationRepository).save(captor.capture());
        assertThat(captor.getValue().getScenarioCoverageState()).isEqualTo("COMPLETE");
        assertThat(captor.getValue().getCoveredScenarioCount()).isEqualTo(3);
        assertThat(captor.getValue().getTevvGateState()).isEqualTo("READY_FOR_PRODUCTION");
    }

    @Test
    void getSnapshotShowsCanaryOnlyWhenCoverageIsPartialButNoGateFailureExists() {
        when(registryRepository.findByRegistryScopeOrderByUpdatedAtDesc(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE))
                .thenReturn(List.of(registryRecord()));
        when(evaluationRepository.findByRegistryScopeOrderByUpdatedAtDesc(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE))
                .thenReturn(List.of(PromptGovernanceEvaluationRecord.builder()
                        .registryScope(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE)
                        .promptKey("cortex.security-decision")
                        .promptVersion("2026.04.04-e0.2")
                        .evaluationReference("PROMPT-TEVV-2026-03-26")
                        .evaluationMode("REPLAY_SUITE")
                        .evaluationState("CANARY_ONLY")
                        .empiricalEvidenceState("SATISFIED")
                        .promptInjectionState("PASSED")
                        .scenarioCoverageState("PARTIAL")
                        .coveredScenarioCount(2)
                        .requiredScenarioCount(3)
                        .coveredScenarioFamiliesJson("[\"PROMPT_INJECTION\",\"TOOL_MISUSE\"]")
                        .tevvGateState("READY_FOR_CANARY")
                        .qualityGateState("PASSED")
                        .latencyGateState("PASSED")
                        .costGateState("PASSED")
                        .evaluatedBy("platform-admin")
                        .evaluationSummary("Partial coverage; canary only.")
                        .updatedAt(LocalDateTime.of(2026, 3, 26, 14, 10))
                        .build()));

        PromptGovernanceView.PromptGovernanceEmpiricalEvalSnapshot snapshot = service.getSnapshot(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                10);

        assertThat(snapshot.evalPortfolioState()).isEqualTo("READY_FOR_CANARY");
        assertThat(snapshot.canaryReadyCount()).isEqualTo(1);
        assertThat(snapshot.prompts()).hasSize(1);
        assertThat(snapshot.prompts().get(0).tevvGateState()).isEqualTo("READY_FOR_CANARY");
        assertThat(snapshot.prompts().get(0).coveredScenarioCount()).isEqualTo(2);
        assertThat(snapshot.prompts().get(0).coveredScenarioFamilies()).containsExactly("PROMPT_INJECTION", "TOOL_MISUSE");
    }

    // N-GOV-2: a bundle whose manifest declares its evaluation scenario families needs those families only.
    @Test
    void aBundleThatDeclaresItsScenarioFamiliesIsReadyForProductionWhenItCoversThem() {
        PromptGovernanceEmpiricalEvalService declared = serviceWith(List.of("PROMPT_INJECTION", "MEMORY_POISONING"));
        stubRecording();

        PromptGovernanceEmpiricalEvalService.EvalRegistrationReceipt receipt = declared.recordEvaluation(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE, "cortex.security-decision", "2026.04.04-e0.2",
                "PROMPT-TEVV-2026-10-16", "REPLAY_SUITE", List.of("PROMPT_INJECTION", "MEMORY_POISONING"),
                "PASSED", "PASSED", "PASSED", "platform-admin", "The declared families passed.");

        assertThat(receipt.tevvGateState()).isEqualTo("READY_FOR_PRODUCTION");
        PromptGovernanceEvaluationRecord saved = savedRecord();
        assertThat(saved.getScenarioCoverageState()).isEqualTo("COMPLETE");
        assertThat(saved.getCoveredScenarioCount()).isEqualTo(2);
        assertThat(saved.getRequiredScenarioCount()).isEqualTo(2);
    }

    @Test
    void aFamilyTheBundleDoesNotDeclareIsNotCountedAsCovered() {
        PromptGovernanceEmpiricalEvalService declared = serviceWith(List.of("PROMPT_INJECTION", "MEMORY_POISONING"));
        stubRecording();

        declared.recordEvaluation(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE, "cortex.security-decision",
                "2026.04.04-e0.2", "PROMPT-TEVV-2026-10-16", "REPLAY_SUITE",
                List.of("PROMPT_INJECTION", "TOOL_MISUSE", "MEMORY_POISONING"), "PASSED", "PASSED", "PASSED",
                "platform-admin", "A family outside the declaration was reported.");

        PromptGovernanceEvaluationRecord saved = savedRecord();
        assertThat(saved.getCoveredScenarioFamiliesJson()).contains("MEMORY_POISONING", "PROMPT_INJECTION")
                .doesNotContain("TOOL_MISUSE");
        assertThat(saved.getCoveredScenarioCount()).isEqualTo(2);
        assertThat(saved.getRequiredScenarioCount()).isEqualTo(2);
    }

    @Test
    void aBundleThatDeclaresNoScenarioFamiliesNeedsTheDefaultFamilies() {
        PromptGovernanceEmpiricalEvalService undeclared = serviceWith(List.of());
        stubRecording();

        PromptGovernanceEmpiricalEvalService.EvalRegistrationReceipt receipt = undeclared.recordEvaluation(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE, "cortex.security-decision", "2026.04.04-e0.2",
                "PROMPT-TEVV-2026-10-16", "REPLAY_SUITE", List.of("PROMPT_INJECTION", "MEMORY_POISONING"),
                "PASSED", "PASSED", "PASSED", "platform-admin", "Two of the default families passed.");

        assertThat(receipt.tevvGateState()).isEqualTo("READY_FOR_CANARY");
        PromptGovernanceEvaluationRecord saved = savedRecord();
        assertThat(saved.getScenarioCoverageState()).isEqualTo("PARTIAL");
        assertThat(saved.getRequiredScenarioCount()).isEqualTo(3);
    }

    @Test
    void aVersionWithoutAnEvaluationShowsTheFamilyCountItsManifestDeclares() {
        when(registryRepository.findByRegistryScopeOrderByUpdatedAtDesc(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE))
                .thenReturn(List.of(registryRecord()));
        when(evaluationRepository.findByRegistryScopeOrderByUpdatedAtDesc(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE))
                .thenReturn(List.of());

        PromptGovernanceView.PromptGovernanceEmpiricalEvalSnapshot snapshot =
                serviceWith(List.of("PROMPT_INJECTION", "MEMORY_POISONING"))
                        .getSnapshot(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE, 10);

        assertThat(snapshot.prompts()).hasSize(1);
        assertThat(snapshot.prompts().get(0).scenarioCoverageState()).isEqualTo("NOT_RECORDED");
        assertThat(snapshot.prompts().get(0).requiredScenarioCount()).isEqualTo(2);
    }

    /**
     * N-GOV-3: the view names the families the bundle requires (its manifest declares them) and the required ones
     * the evaluation left uncovered; without an evaluation every required family is uncovered.
     */
    @Test
    void theViewNamesTheRequiredAndUncoveredScenarioFamilies() {
        when(registryRepository.findByRegistryScopeOrderByUpdatedAtDesc(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE))
                .thenReturn(List.of(registryRecord()));
        when(evaluationRepository.findByRegistryScopeOrderByUpdatedAtDesc(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE))
                .thenReturn(List.of(PromptGovernanceEvaluationRecord.builder()
                        .registryScope(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE)
                        .promptKey("cortex.security-decision")
                        .promptVersion("2026.04.04-e0.2")
                        .evaluationReference("PROMPT-TEVV-2026-10-17")
                        .evaluationState("CANARY_ONLY")
                        .scenarioCoverageState("PARTIAL")
                        .coveredScenarioCount(1)
                        .requiredScenarioCount(2)
                        .coveredScenarioFamiliesJson("[\"PROMPT_INJECTION\"]")
                        .updatedAt(LocalDateTime.of(2026, 10, 17, 9, 0))
                        .build()));
        PromptGovernanceEmpiricalEvalService declared = serviceWith(List.of("PROMPT_INJECTION", "MEMORY_POISONING"));

        PromptGovernanceView.PromptGovernanceEmpiricalEvalItem item = declared
                .getSnapshot(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE, 10).prompts().get(0);

        // The required names are normalised and sorted (N-GOV-2), so the uncovered ones follow that order.
        assertThat(item.requiredScenarioFamilies()).containsExactly("MEMORY_POISONING", "PROMPT_INJECTION");
        assertThat(item.coveredScenarioFamilies()).containsExactly("PROMPT_INJECTION");
        assertThat(item.uncoveredScenarioFamilies()).containsExactly("MEMORY_POISONING");

        when(evaluationRepository.findByRegistryScopeOrderByUpdatedAtDesc(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE))
                .thenReturn(List.of());
        PromptGovernanceView.PromptGovernanceEmpiricalEvalItem none = declared
                .getSnapshot(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE, 10).prompts().get(0);

        assertThat(none.requiredScenarioFamilies()).containsExactly("MEMORY_POISONING", "PROMPT_INJECTION");
        assertThat(none.uncoveredScenarioFamilies()).containsExactly("MEMORY_POISONING", "PROMPT_INJECTION");
    }

    @Test
    void theRequiredFamiliesAreTheDeclaredNamesOnceInUpperCaseOrElseTheDefaultFamilies() {
        assertThat(PromptGovernanceEmpiricalEvalService.requiredScenarioFamilies(
                manifest(List.of(" memory_poisoning", "PROMPT_INJECTION", "MEMORY_POISONING", " "))))
                .containsExactly("MEMORY_POISONING", "PROMPT_INJECTION");
        assertThat(PromptGovernanceEmpiricalEvalService.requiredScenarioFamilies(null))
                .containsExactlyInAnyOrder("PROMPT_INJECTION", "TOOL_MISUSE", "MEMORY_POISONING");
    }

    private PromptGovernanceEmpiricalEvalService serviceWith(List<String> evaluationScenarioFamilies) {
        return new PromptGovernanceEmpiricalEvalService(registryRepository, evaluationRepository,
                new PromptBundleCatalog(List.of(manifest(evaluationScenarioFamilies))));
    }

    private void stubRecording() {
        when(registryRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                "cortex.security-decision",
                "2026.04.04-e0.2")).thenReturn(Optional.of(registryRecord()));
        when(evaluationRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                "cortex.security-decision",
                "2026.04.04-e0.2")).thenReturn(Optional.empty());
        when(evaluationRepository.save(any(PromptGovernanceEvaluationRecord.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }

    private PromptGovernanceEvaluationRecord savedRecord() {
        ArgumentCaptor<PromptGovernanceEvaluationRecord> captor = ArgumentCaptor.forClass(PromptGovernanceEvaluationRecord.class);
        verify(evaluationRepository).save(captor.capture());
        return captor.getValue();
    }

    /** A manifest of the registry record's version that declares the given evaluation scenario families. */
    private static PromptBundleManifest manifest(List<String> evaluationScenarioFamilies) {
        List<PromptBundleElement> elements = new ArrayList<>();
        for (String id : PromptBundleHashes.ELEMENT_IDS) {
            elements.add("B1".equals(id)
                    ? PromptBundleHashes.present(id, "system text", "text")
                    : PromptBundleHashes.marker(id, PromptBundleElementState.ABSENT, "none"));
        }
        return new PromptBundleManifest("cortex.security-decision", "2026.04.04-e0.2",
                PromptBundleHashes.bundleHash(elements), elements, null, null, "summary", List.of(), "author",
                "2026-10-16", null, List.of(), List.of(), List.of(), evaluationScenarioFamilies);
    }

    private PromptGovernanceRegistryRecord registryRecord() {
        return PromptGovernanceRegistryRecord.builder()
                .registryScope(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE)
                .promptKey("cortex.security-decision")
                .templateKey("SecurityDecisionStandard")
                .promptVersion("2026.04.04-e0.2")
                .contractVersion("CORTEX_PROMPT_CONTRACT_V2")
                .promptArtifactHashSha256("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .releaseStatus("CANARY")
                .owner("contexa-cortex-core")
                .releaseApprovalReference("P0-Preflight/E0-2")
                .evaluationBaselineReference("2026.03.26-e0.1")
                .rollbackPromptVersion("2026.03.26-e0.1")
                .changeSummary("summary")
                .templateClassName("io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate")
                .registrationSource("STANDARD_TEMPLATE_BOOTSTRAP")
                .supportedModelProfilesJson("[\"STRICT_JSON_SCHEMA\"]")
                .updatedAt(LocalDateTime.of(2026, 3, 26, 13, 50))
                .build();
    }
}
