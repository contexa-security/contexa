package io.contexa.contexacore.std.components.prompt.governance;

import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceRegistryRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceReleaseApprovalRecord;
import io.contexa.contexacore.repository.prompt.PromptGovernanceChangeRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceEvaluationRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRegistryRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseApprovalRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseWorkflowRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRollbackRecordRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PromptGovernanceJpaLedgerWriterTest {

    private static final LocalDateTime NOW = LocalDateTime.of(2026, 10, 10, 13, 0);

    @Mock
    private PromptGovernanceRegistryRepository registryRepository;
    @Mock
    private PromptGovernanceChangeRecordRepository changeRepository;
    @Mock
    private PromptGovernanceEvaluationRecordRepository evaluationRepository;
    @Mock
    private PromptGovernanceReleaseApprovalRepository releaseApprovalRepository;
    @Mock
    private PromptGovernanceReleaseWorkflowRepository releaseWorkflowRepository;
    @Mock
    private PromptGovernanceRollbackRecordRepository rollbackRepository;

    private PromptGovernanceJpaLedgerWriter writer;

    @BeforeEach
    void setUp() {
        writer = new PromptGovernanceJpaLedgerWriter(
                registryRepository,
                changeRepository,
                evaluationRepository,
                releaseApprovalRepository,
                releaseWorkflowRepository,
                rollbackRepository);
    }

    @Test
    void releaseApprovalIsLookedUpAndWrittenWithTheFiveColumnIdentity() {
        when(releaseApprovalRepository.findFirstByRegistryScopeAndPromptKeyAndTemplateKeyAndPromptVersionAndContractVersionOrderByUpdatedAtDesc(
                "PLATFORM_GLOBAL",
                "cortex.security-decision",
                "SecurityDecisionStandard",
                "2026.04.04-e0.2",
                "CORTEX_PROMPT_CONTRACT_V2")).thenReturn(Optional.empty());

        writer.upsertReleaseApproval(
                "PLATFORM_GLOBAL",
                "cortex.security-decision",
                "SecurityDecisionStandard",
                "2026.04.04-e0.2",
                "CORTEX_PROMPT_CONTRACT_V2",
                "PQA-RELEASE:PLATFORM_GLOBAL:cortex.security-decision:2026.04.04-e0.2",
                "PRODUCTION",
                "APPROVED",
                "PQA_PROMPT_GOVERNANCE",
                "admin",
                "Release gates were revalidated before production approval.",
                "PQA_PROMPT_INTEGRATED_MANAGEMENT",
                NOW);

        ArgumentCaptor<PromptGovernanceReleaseApprovalRecord> captor =
                ArgumentCaptor.forClass(PromptGovernanceReleaseApprovalRecord.class);
        verify(releaseApprovalRepository).saveAndFlush(captor.capture());
        verify(releaseApprovalRepository, never()).save(any());
        PromptGovernanceReleaseApprovalRecord saved = captor.getValue();
        assertThat(saved.getTemplateKey()).isEqualTo("SecurityDecisionStandard");
        assertThat(saved.getContractVersion()).isEqualTo("CORTEX_PROMPT_CONTRACT_V2");
        assertThat(saved.getReleaseStatus()).isEqualTo("PRODUCTION");
        assertThat(saved.getApprovalState()).isEqualTo("APPROVED");
        assertThat(saved.getCreatedAt()).isEqualTo(NOW);
        assertThat(saved.getUpdatedAt()).isEqualTo(NOW);
    }

    @Test
    void existingReleaseApprovalOfTheSameIdentityIsUpdatedInPlace() {
        PromptGovernanceReleaseApprovalRecord existing = PromptGovernanceReleaseApprovalRecord.builder()
                .id(7L)
                .registryScope("PLATFORM_GLOBAL")
                .promptKey("cortex.security-decision")
                .templateKey("SecurityDecisionStandard")
                .promptVersion("2026.04.04-e0.2")
                .contractVersion("CORTEX_PROMPT_CONTRACT_V2")
                .approvalState("IMPORTED_DECLARATION")
                .createdAt(NOW.minusDays(1))
                .updatedAt(NOW.minusDays(1))
                .build();
        when(releaseApprovalRepository.findFirstByRegistryScopeAndPromptKeyAndTemplateKeyAndPromptVersionAndContractVersionOrderByUpdatedAtDesc(
                "PLATFORM_GLOBAL",
                "cortex.security-decision",
                "SecurityDecisionStandard",
                "2026.04.04-e0.2",
                "CORTEX_PROMPT_CONTRACT_V2")).thenReturn(Optional.of(existing));

        writer.upsertReleaseApproval(
                "PLATFORM_GLOBAL",
                "cortex.security-decision",
                "SecurityDecisionStandard",
                "2026.04.04-e0.2",
                "CORTEX_PROMPT_CONTRACT_V2",
                "pqa-rtg-release-1",
                "ACTIVE_FOR_SCOPE",
                "APPROVED",
                "PQA_RUNTIME_GOVERNANCE_ACTION",
                "operator",
                "Approved runtime governance rule is active for scoped prompt assembly.",
                "PQA_RUNTIME_GOVERNANCE",
                NOW);

        verify(releaseApprovalRepository).saveAndFlush(existing);
        assertThat(existing.getId()).isEqualTo(7L);
        assertThat(existing.getApprovalState()).isEqualTo("APPROVED");
        assertThat(existing.getCreatedAt()).isEqualTo(NOW.minusDays(1));
        assertThat(existing.getUpdatedAt()).isEqualTo(NOW);
    }

    @Test
    void registryActivationIsFlushedAndKeepsTheGivenRegistrationSource() {
        PromptGovernanceRegistryRecord registry = PromptGovernanceRegistryRecord.builder()
                .registryScope("PLATFORM_GLOBAL")
                .promptKey("cortex.security-decision")
                .promptVersion("2026.04.04-e0.2")
                .releaseStatus("CANARY")
                .registrationSource("STANDARD_TEMPLATE_BOOTSTRAP")
                .build();
        when(registryRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                "PLATFORM_GLOBAL",
                "cortex.security-decision",
                "2026.04.04-e0.2")).thenReturn(Optional.of(registry));

        writer.activateRegistryRelease(
                "PLATFORM_GLOBAL",
                "cortex.security-decision",
                "2026.04.04-e0.2",
                "PRODUCTION",
                "PQA-RELEASE:PLATFORM_GLOBAL:cortex.security-decision:2026.04.04-e0.2",
                "STANDARD_TEMPLATE_BOOTSTRAP",
                NOW);

        verify(registryRepository).saveAndFlush(registry);
        assertThat(registry.getReleaseStatus()).isEqualTo("PRODUCTION");
        assertThat(registry.getRegistrationSource()).isEqualTo("STANDARD_TEMPLATE_BOOTSTRAP");
        assertThat(registry.getUpdatedAt()).isEqualTo(NOW);
    }
}
