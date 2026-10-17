package io.contexa.contexacore.std.components.prompt.governance;

import io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionPromptBundles;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import io.contexa.contexacore.std.components.prompt.PromptReleaseStatus;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRegistryRepository;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceRegistryRecord;
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
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PromptGovernanceRegistryServiceTest {

    @Mock
    private PromptGovernanceRegistryRepository repository;

    private PromptGovernanceRegistryService service;

    @BeforeEach
    void setUp() {
        service = new PromptGovernanceRegistryService(repository);
    }

    @Test
    void registerPromptArtifactPersistsGovernedDescriptor() {
        PromptGovernanceDescriptor descriptor = descriptor();
        when(repository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                descriptor.promptKey(),
                descriptor.promptVersion())).thenReturn(Optional.empty());
        when(repository.save(any(PromptGovernanceRegistryRecord.class))).thenAnswer(invocation -> invocation.getArgument(0));

        PromptGovernanceRegistryService.PromptRegistrationReceipt receipt = service.registerPromptArtifact(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                descriptor,
                "STANDARD_TEMPLATE_BOOTSTRAP");

        assertThat(receipt.created()).isTrue();
        ArgumentCaptor<PromptGovernanceRegistryRecord> captor = ArgumentCaptor.forClass(PromptGovernanceRegistryRecord.class);
        verify(repository).save(captor.capture());
        PromptGovernanceRegistryRecord saved = captor.getValue();
        assertThat(saved.getPromptKey()).isEqualTo("cortex.security-decision");
        // A new row takes the declaration as its first value, in the canonical vocabulary (decision 1).
        assertThat(saved.getReleaseStatus()).isEqualTo("ACTIVE");
        assertThat(saved.getReleaseApprovalReference()).isEqualTo("P0-Preflight/E0-2");
        assertThat(saved.getPromptArtifactHashSha256()).hasSize(64);
        assertThat(saved.getSupportedModelProfilesJson()).contains("STRICT_JSON_SCHEMA");
        assertThat(saved.getRegistrationSource()).isEqualTo("STANDARD_TEMPLATE_BOOTSTRAP");
        assertThat(saved.getCreatedAt()).isNotNull();
        assertThat(saved.getUpdatedAt()).isNotNull();
    }

    @Test
    void syncOfAnExistingRowRefreshesCodeContentAndLeavesTheReleaseWorkflowFieldsAlone() {
        PromptGovernanceDescriptor descriptor = descriptor();
        LocalDateTime operatorUpdate = LocalDateTime.of(2026, 10, 1, 9, 0);
        PromptGovernanceRegistryRecord existing = PromptGovernanceRegistryRecord.builder()
                .id(7L)
                .registryScope(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE)
                .promptKey(descriptor.promptKey())
                .templateKey(descriptor.templateKey())
                .promptVersion(descriptor.promptVersion())
                .contractVersion(descriptor.contractVersion())
                .promptArtifactHashSha256("stale-hash")
                .releaseStatus("CANARY")
                .owner(descriptor.owner())
                .releaseApprovalReference("PROMPT-RELEASE-WORKFLOW:operator")
                .evaluationBaselineReference("eval-run-42")
                .rollbackPromptVersion(null)
                .changeSummary(descriptor.changeSummary())
                .templateClassName(descriptor.templateClassName())
                .registrationSource("PROMPT_RELEASE_GATE_WORKFLOW")
                .supportedModelProfilesJson("[\"STRICT_JSON_SCHEMA\",\"MODEL_COMPATIBLE_OPENAI_ANTHROPIC_GEMINI\"]")
                .createdAt(LocalDateTime.of(2026, 9, 1, 9, 0))
                .updatedAt(operatorUpdate)
                .build();
        when(repository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                descriptor.promptKey(),
                descriptor.promptVersion())).thenReturn(Optional.of(existing));
        when(repository.save(any(PromptGovernanceRegistryRecord.class))).thenAnswer(invocation -> invocation.getArgument(0));

        PromptGovernanceRegistryService.PromptRegistrationReceipt receipt = service.registerPromptArtifact(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                descriptor,
                "STANDARD_TEMPLATE_BOOTSTRAP");

        assertThat(receipt.created()).isFalse();
        assertThat(existing.getPromptArtifactHashSha256()).isEqualTo(descriptor.artifactHashSha256());
        assertThat(existing.getReleaseStatus()).isEqualTo("CANARY");
        assertThat(existing.getReleaseApprovalReference()).isEqualTo("PROMPT-RELEASE-WORKFLOW:operator");
        assertThat(existing.getEvaluationBaselineReference()).isEqualTo("eval-run-42");
        assertThat(existing.getRollbackPromptVersion()).isNull();
        assertThat(existing.getRegistrationSource()).isEqualTo("PROMPT_RELEASE_GATE_WORKFLOW");
        assertThat(existing.getUpdatedAt()).isAfter(operatorUpdate);
        verify(repository).save(existing);
    }

    @Test
    void syncOfAnUnchangedRowDoesNotWriteOrMoveItsUpdateTime() {
        PromptGovernanceDescriptor descriptor = descriptor();
        LocalDateTime operatorUpdate = LocalDateTime.of(2026, 10, 1, 9, 0);
        PromptGovernanceRegistryRecord existing = PromptGovernanceRegistryRecord.builder()
                .id(7L)
                .registryScope(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE)
                .promptKey(descriptor.promptKey())
                .templateKey(descriptor.templateKey())
                .promptVersion(descriptor.promptVersion())
                .contractVersion(descriptor.contractVersion())
                .promptArtifactHashSha256(descriptor.artifactHashSha256())
                .releaseStatus("DEPRECATED")
                .owner(descriptor.owner())
                .changeSummary(descriptor.changeSummary())
                .templateClassName(descriptor.templateClassName())
                .registrationSource("PROMPT_RELEASE_GATE_WORKFLOW")
                .supportedModelProfilesJson("[\"STRICT_JSON_SCHEMA\",\"MODEL_COMPATIBLE_OPENAI_ANTHROPIC_GEMINI\"]")
                .updatedAt(operatorUpdate)
                .build();
        when(repository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                descriptor.promptKey(),
                descriptor.promptVersion())).thenReturn(Optional.of(existing));

        PromptGovernanceRegistryService.PromptRegistrationReceipt receipt = service.registerPromptArtifact(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                descriptor,
                "STANDARD_TEMPLATE_BOOTSTRAP");

        assertThat(receipt.created()).isFalse();
        assertThat(receipt.releaseStatus()).isEqualTo("DEPRECATED");
        assertThat(existing.getUpdatedAt()).isEqualTo(operatorUpdate);
        verify(repository, never()).save(any(PromptGovernanceRegistryRecord.class));
    }

    @Test
    void getSnapshotSummarizesGovernanceReadiness() {
        when(repository.findByRegistryScopeOrderByUpdatedAtDesc(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE))
                .thenReturn(List.of(PromptGovernanceRegistryRecord.builder()
                        .registryScope(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE)
                        .promptKey("cortex.security-decision")
                        .templateKey("SecurityDecisionStandard")
                        .promptVersion("2026.04.04-e0.2")
                        .contractVersion("CORTEX_PROMPT_CONTRACT_V2")
                        .promptArtifactHashSha256("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                        .releaseStatus("PRODUCTION")
                        .owner("contexa-cortex-core")
                        .releaseApprovalReference("P0-Preflight/E0-2")
                        .evaluationBaselineReference("2026.03.26-e0.1")
                        .rollbackPromptVersion("2026.03.26-e0.1")
                        .changeSummary("Governed prompt rollout")
                        .templateClassName("io.contexa.SecurityDecisionStandardPromptTemplate")
                        .registrationSource("STANDARD_TEMPLATE_BOOTSTRAP")
                        .supportedModelProfilesJson("[\"STRICT_JSON_SCHEMA\",\"MODEL_COMPATIBLE_OPENAI_ANTHROPIC_GEMINI\"]")
                        .createdAt(LocalDateTime.of(2026, 3, 26, 10, 0))
                        .updatedAt(LocalDateTime.of(2026, 3, 26, 11, 0))
                        .build()));

        PromptGovernanceView.PromptGovernanceRegistrySnapshot snapshot = service.getSnapshot(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                10);

        assertThat(snapshot.promptCount()).isEqualTo(1);
        assertThat(snapshot.productionCount()).isEqualTo(1);
        assertThat(snapshot.approvalLinkedCount()).isEqualTo(1);
        assertThat(snapshot.evalLinkedCount()).isEqualTo(1);
        assertThat(snapshot.rollbackReadyCount()).isEqualTo(1);
        assertThat(snapshot.modelCompatibleCount()).isEqualTo(1);
        assertThat(snapshot.registryState()).isEqualTo("CONTROLLED_PRODUCTION");
        assertThat(snapshot.prompts()).hasSize(1);
        assertThat(snapshot.prompts().get(0).releaseApproved()).isTrue();
        assertThat(snapshot.prompts().get(0).evalLinked()).isTrue();
        assertThat(snapshot.prompts().get(0).rollbackReady()).isTrue();
        assertThat(snapshot.prompts().get(0).modelProfilesDeclared()).isTrue();
    }

    /**
     * N-GOV-6: a new version that declares production (the build default does) entered ACTIVE with the latest update
     * time and took the default selection from the release the gate activated. Beside an active release of a bundle
     * this build runs it enters AVAILABLE; the release it found keeps its state (PV-4).
     */
    @Test
    void aDeclaredProductionEntersAvailableBesideAnActiveReleaseOfABundleThisBuildRuns() {
        PromptGovernanceDescriptor descriptor = descriptor();
        PromptGovernanceRegistryRecord active = release(SecurityDecisionPromptBundles.V20.version(), "ACTIVE");
        when(repository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                descriptor.promptKey(),
                descriptor.promptVersion())).thenReturn(Optional.empty());
        lenient().when(repository.findByRegistryScopeAndPromptKeyOrderByUpdatedAtDesc(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE, descriptor.promptKey()))
                .thenReturn(List.of(active));
        when(repository.save(any(PromptGovernanceRegistryRecord.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        PromptGovernanceRegistryService.PromptRegistrationReceipt receipt = service.registerPromptArtifact(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                descriptor,
                "STANDARD_TEMPLATE_BOOTSTRAP");

        assertThat(receipt.created()).isTrue();
        assertThat(receipt.releaseStatus()).isEqualTo("AVAILABLE");
        assertThat(active.getReleaseStatus()).isEqualTo("ACTIVE");
        verify(repository, never()).save(active);
    }

    /**
     * N-GOV-6: an active release of a bundle this build no longer runs (an earlier version of the build default) does
     * not hold a new build default back: it enters as declared, so the registry selects a bundle the build can run.
     */
    @Test
    void aDeclaredProductionEntersAsDeclaredBesideAnActiveReleaseOfABundleThisBuildNoLongerRuns() {
        PromptGovernanceDescriptor descriptor = descriptor();
        PromptGovernanceRegistryRecord earlier = release("2026.03.26-e0.1", "PRODUCTION");
        when(repository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                descriptor.promptKey(),
                descriptor.promptVersion())).thenReturn(Optional.empty());
        lenient().when(repository.findByRegistryScopeAndPromptKeyOrderByUpdatedAtDesc(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE, descriptor.promptKey()))
                .thenReturn(List.of(earlier));
        when(repository.save(any(PromptGovernanceRegistryRecord.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        PromptGovernanceRegistryService.PromptRegistrationReceipt receipt = service.registerPromptArtifact(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                descriptor,
                "STANDARD_TEMPLATE_BOOTSTRAP");

        assertThat(receipt.releaseStatus()).isEqualTo("ACTIVE");
        assertThat(earlier.getReleaseStatus()).isEqualTo("PRODUCTION");
        verify(repository, never()).save(earlier);
    }

    private static PromptGovernanceRegistryRecord release(String version, String releaseStatus) {
        return PromptGovernanceRegistryRecord.builder()
                .id(11L)
                .registryScope(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE)
                .promptKey("cortex.security-decision")
                .templateKey("SecurityDecisionStandard")
                .promptVersion(version)
                .releaseStatus(releaseStatus)
                .updatedAt(LocalDateTime.of(2026, 10, 16, 9, 0))
                .build();
    }

    private PromptGovernanceDescriptor descriptor() {
        return new PromptGovernanceDescriptor(
                "cortex.security-decision",
                "SecurityDecisionStandard",
                "2026.04.04-e0.2",
                "CORTEX_PROMPT_CONTRACT_V2",
                PromptReleaseStatus.PRODUCTION,
                "contexa-cortex-core",
                "P0-Preflight/E0-2",
                "2026.03.26-e0.1",
                "2026.03.26-e0.1",
                "NIST/ISO aligned governed security decision prompt tightened high-critical allow thresholds, uncertainty routing, and compact-runtime parity",
                List.of("STRICT_JSON_SCHEMA", "MODEL_COMPATIBLE_OPENAI_ANTHROPIC_GEMINI"),
                "io.contexa.contexacore.autonomous.tiered.prompt.SecurityDecisionStandardPromptTemplate");
    }
}
