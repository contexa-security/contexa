package io.contexa.contexacore.std.components.prompt.governance;

import io.contexa.contexacore.repository.prompt.PromptGovernanceBudgetProfileRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceModelCompatibilityRepository;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceBudgetProfileRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceModelCompatibilityRecord;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.List;
import org.mockito.Mockito;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class PromptGovernanceModelCompatibilityRegistryServiceTest {

    @Mock
    private PromptGovernanceRegistryService promptGovernanceRegistryService;
    @Mock
    private PromptGovernanceModelCompatibilityRepository modelCompatibilityRepository;
    @Mock
    private PromptGovernanceBudgetProfileRepository budgetProfileRepository;

    private PromptGovernanceModelCompatibilityRegistryService service;

    @BeforeEach
    void setUp() {
        service = new PromptGovernanceModelCompatibilityRegistryService(
                promptGovernanceRegistryService,
                modelCompatibilityRepository,
                budgetProfileRepository);
    }

    @Test
    void getSnapshotShowsGovernedBudgetAndProviderCompatibility() {
        Mockito.when(modelCompatibilityRepository.findByRegistryScopeOrderByUpdatedAtDesc(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE))
                .thenReturn(List.of(PromptGovernanceModelCompatibilityRecord.builder()
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
                        .updatedAt(LocalDateTime.of(2026, 3, 26, 15, 0))
                        .build()));
        Mockito.when(budgetProfileRepository.findByRegistryScopeOrderByUpdatedAtDesc(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE))
                .thenReturn(List.of(PromptGovernanceBudgetProfileRecord.builder()
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
                        .updatedAt(LocalDateTime.of(2026, 3, 26, 15, 1))
                        .build()));

        PromptGovernanceView.PromptGovernanceModelCompatibilitySnapshot snapshot = service.getSnapshot(
                PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE,
                10);

        assertThat(snapshot.compatibilityRegistryState()).isEqualTo("DECLARED_GOVERNED");
        assertThat(snapshot.prompts()).hasSize(1);
        assertThat(snapshot.prompts().get(0).providerCompatibilityDeclared()).isTrue();
        assertThat(snapshot.prompts().get(0).budgetProfilesGoverned()).isTrue();
        assertThat(snapshot.prompts().get(0).budgetProfiles().get(0).budgetProfileKey())
                .isEqualTo("CORTEX_L1_INTERACTIVE_STRICT");
        assertThat(snapshot.prompts().get(0).budgetProfiles().get(0).maxInputTokens()).isEqualTo(4200);
        assertThat(snapshot.prompts().get(0).budgetProfiles().get(0).compactionPolicyKey())
                .isEqualTo("LOSSLESS_PROMPT_OPTIMIZATION_V1");
    }
}
