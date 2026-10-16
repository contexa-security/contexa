package io.contexa.autoconfigure.iam.admin;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.repository.prompt.PromptGovernanceBudgetProfileRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceChangeRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceEvaluationRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceModelCompatibilityRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRegistryRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseApprovalRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseWorkflowRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRollbackRecordRepository;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptorResolver;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleSelector;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceEmpiricalEvalService;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceJpaLedgerWriter;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceLifecycleLedgerService;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceModelCompatibilityRegistryService;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceRegistryService;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceReleaseGateService;
import io.contexa.contexaiam.admin.promptquality.governance.JdbcPromptReleaseQueryService;
import io.contexa.contexaiam.admin.promptquality.governance.PromptGovernanceRuntimeCacheInvalidationService;
import io.contexa.contexaiam.admin.promptquality.governance.PromptReleaseConsole;
import io.contexa.contexaiam.admin.promptquality.governance.PromptReleaseConsoleApiController;
import io.contexa.contexaiam.admin.promptquality.governance.PromptReleasePageController;
import io.contexa.contexaiam.admin.promptquality.official.application.PromptRuntimeGovernanceDescriptorVerifier;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import org.junit.jupiter.api.Test;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * W1-20 (c): one property turns prompt version management on and off as a whole, independent of the enterprise and
 * SaaS switches (decision 11, PV-22), and every bean of the set is registered, the release gate included (PV-24).
 */
class PromptGovernanceAutoConfigurationTest {

    private static final List<Class<?>> GOVERNANCE_TYPES = List.of(
            PromptGovernanceRuntimeCacheInvalidationService.class,
            PromptGovernanceDescriptorResolver.class,
            PromptGovernanceJpaLedgerWriter.class,
            JdbcPromptReleaseQueryService.class,
            PromptGovernanceRegistryService.class,
            PromptGovernanceModelCompatibilityRegistryService.class,
            PromptGovernanceLifecycleLedgerService.class,
            PromptGovernanceReleaseGateService.class,
            PromptGovernanceEmpiricalEvalService.class,
            PromptRuntimeGovernanceDescriptorVerifier.class,
            // W7-14: the version screens with their read API.
            PromptReleaseConsole.class,
            PromptReleaseConsoleApiController.class,
            PromptReleasePageController.class);

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(PromptGovernanceAutoConfiguration.class))
            .withBean("contexaJdbcTemplate", JdbcTemplate.class, () -> mock(JdbcTemplate.class))
            .withBean(ObjectMapper.class, ObjectMapper::new)
            .withBean(PromptQualityMessageResolver.class, () -> mock(PromptQualityMessageResolver.class))
            .withBean(PromptGovernanceRegistryRepository.class, () -> mock(PromptGovernanceRegistryRepository.class))
            .withBean(PromptGovernanceChangeRecordRepository.class, () -> mock(PromptGovernanceChangeRecordRepository.class))
            .withBean(PromptGovernanceEvaluationRecordRepository.class, () -> mock(PromptGovernanceEvaluationRecordRepository.class))
            .withBean(PromptGovernanceReleaseApprovalRepository.class, () -> mock(PromptGovernanceReleaseApprovalRepository.class))
            .withBean(PromptGovernanceReleaseWorkflowRepository.class, () -> mock(PromptGovernanceReleaseWorkflowRepository.class))
            .withBean(PromptGovernanceRollbackRecordRepository.class, () -> mock(PromptGovernanceRollbackRecordRepository.class))
            .withBean(PromptGovernanceModelCompatibilityRepository.class, () -> mock(PromptGovernanceModelCompatibilityRepository.class))
            .withBean(PromptGovernanceBudgetProfileRepository.class, () -> mock(PromptGovernanceBudgetProfileRepository.class));

    @Test
    void theWholeSetIsOnByDefaultWithoutTheEnterpriseOrSaasSwitches() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            for (Class<?> type : GOVERNANCE_TYPES) {
                assertThat(context).as(type.getSimpleName()).hasSingleBean(type);
            }
            assertThat(context).hasBean("promptGovernanceRegistryBootstrapRunner");
            assertThat(context.getBean("promptGovernanceRegistryBootstrapRunner")).isInstanceOf(ApplicationRunner.class);
        });
    }

    @Test
    void theEnterpriseAndSaasSwitchesNoLongerDecide() {
        runner.withPropertyValues("contexa.enterprise.enabled=false", "contexa.saas.enabled=false")
                .run(context -> {
                    assertThat(context).hasSingleBean(PromptGovernanceReleaseGateService.class);
                    assertThat(context).hasSingleBean(PromptRuntimeGovernanceDescriptorVerifier.class);
                    assertThat(context).hasBean("promptGovernanceRegistryBootstrapRunner");
                });
    }

    @Test
    void thePropertyTurnsTheWholeSetOff() {
        runner.withPropertyValues("contexa.prompt.governance.enabled=false")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    for (Class<?> type : GOVERNANCE_TYPES) {
                        assertThat(context).as(type.getSimpleName()).doesNotHaveBean(type);
                    }
                    assertThat(context).doesNotHaveBean("promptGovernanceRegistryBootstrapRunner");
                });
    }

    /** W3-16: the registry chooses the bundle only when the configuration says so; the OSS default is the configuration. */
    @Test
    void theRegistrySelectsTheBundleOnlyWhenTheConfigurationSaysSo() {
        runner.run(context -> assertThat(context).doesNotHaveBean(PromptBundleSelector.class));
        runner.withPropertyValues("contexa.security.tiered.prompt-bundle.selector=configuration")
                .run(context -> assertThat(context).doesNotHaveBean(PromptBundleSelector.class));
        runner.withPropertyValues("contexa.security.tiered.prompt-bundle.selector=registry")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(PromptBundleSelector.class);
                    assertThat(context).hasSingleBean(PromptGovernanceDescriptorResolver.class);
                });
    }

    @Test
    void withoutTheRegistryThereIsNoStartupRegistrationAndNoVerifier() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(PromptGovernanceAutoConfiguration.class))
                .withBean("contexaJdbcTemplate", JdbcTemplate.class, () -> mock(JdbcTemplate.class))
                .withBean(ObjectMapper.class, ObjectMapper::new)
                .withBean(PromptQualityMessageResolver.class, () -> mock(PromptQualityMessageResolver.class))
                .withBean(PromptGovernanceChangeRecordRepository.class, () -> mock(PromptGovernanceChangeRecordRepository.class))
                .withBean(PromptGovernanceEvaluationRecordRepository.class, () -> mock(PromptGovernanceEvaluationRecordRepository.class))
                .withBean(PromptGovernanceReleaseApprovalRepository.class, () -> mock(PromptGovernanceReleaseApprovalRepository.class))
                .withBean(PromptGovernanceReleaseWorkflowRepository.class, () -> mock(PromptGovernanceReleaseWorkflowRepository.class))
                .withBean(PromptGovernanceRollbackRecordRepository.class, () -> mock(PromptGovernanceRollbackRecordRepository.class))
                .run(context -> {
                    // The verifier would fail every judgment on an empty registry, so it is not registered (PV-22).
                    assertThat(context).doesNotHaveBean(PromptGovernanceRegistryService.class);
                    assertThat(context).doesNotHaveBean("promptGovernanceRegistryBootstrapRunner");
                    assertThat(context).doesNotHaveBean(PromptRuntimeGovernanceDescriptorVerifier.class);
                });
    }
}
