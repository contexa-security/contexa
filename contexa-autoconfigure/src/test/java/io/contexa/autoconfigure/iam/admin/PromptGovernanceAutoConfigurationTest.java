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
import io.contexa.contexacore.std.components.prompt.quality.QualityGateMode;
import io.contexa.contexacore.std.components.prompt.quality.QualityGatePolicy;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateReading;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSettings;
import io.contexa.contexacore.std.components.prompt.quality.QualityGateSource;
import io.contexa.contexacore.std.components.prompt.quality.QualityMeasurementState;
import io.contexa.contexaiam.admin.promptquality.governance.JdbcPromptReleaseQueryService;
import io.contexa.contexaiam.admin.promptquality.governance.PromptBundleRollbackService;
import io.contexa.contexaiam.admin.promptquality.governance.PromptGovernanceRuntimeCacheInvalidationService;
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
            PromptBundleRollbackService.class);

    /** Plan 6-6 (5): the release screens and their API, whose features the prompt version screens took over. */
    private static final List<String> RELEASE_SCREEN_BEANS = List.of(
            "contexaPromptReleaseApiController",
            "contexaPromptBundleRollbackApiController",
            "contexaPromptReleaseTransitionApiController",
            "contexaPromptReleaseConsole",
            "contexaPromptReleaseConsoleApiController",
            "contexaPromptReleasePageController");

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(PromptGovernanceAutoConfiguration.class))
            .withBean("contexaJdbcTemplate", JdbcTemplate.class, () -> mock(JdbcTemplate.class))
            .withBean("contexaObjectMapper", ObjectMapper.class, ObjectMapper::new)
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
            assertThat(context).hasBean("contexaPromptGovernanceRegistryBootstrapRunner");
            assertThat(context.getBean("contexaPromptGovernanceRegistryBootstrapRunner")).isInstanceOf(ApplicationRunner.class);
        });
    }

    @Test
    void theReleaseScreensAndTheirApiAreGone() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            for (String bean : RELEASE_SCREEN_BEANS) {
                assertThat(context).as(bean).doesNotHaveBean(bean);
            }
        });
    }

    @Test
    void theEnterpriseAndSaasSwitchesNoLongerDecide() {
        runner.withPropertyValues("contexa.enterprise.enabled=false", "contexa.saas.enabled=false")
                .run(context -> {
                    assertThat(context).hasSingleBean(PromptGovernanceReleaseGateService.class);
                    assertThat(context).hasBean("contexaPromptGovernanceRegistryBootstrapRunner");
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
                    assertThat(context).doesNotHaveBean("contexaPromptGovernanceRegistryBootstrapRunner");
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

    /**
     * Plan 3.4, 5 step 5: the quality gate goes in as a warning with the thresholds of the plan; an installation sets
     * the mode and the thresholds, the release gate reads the measurements of the store when there is one, and a
     * threshold outside its range stops the start.
     */
    @Test
    void theQualityGateIsAWarningByDefaultAndItsSettingsAndStoreAreRead() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            QualityGatePolicy defaults = context.getBean(PqaOssQualityGateProperties.class).policy(null);
            assertThat(defaults.mode()).isEqualTo(QualityGateMode.WARN);
            assertThat(defaults.settings()).isEqualTo(QualityGateSettings.defaults());
            assertThat(context.getBean(PromptGovernanceReleaseGateService.class)
                    .qualityMeasurement(null, "cortex.security-decision", "v1.0"))
                    .isEqualTo(QualityMeasurementState.UNMEASURABLE);
        });
        runner.withPropertyValues("contexa.pqa.oss.quality.gate.mode=block",
                        "contexa.pqa.oss.quality.gate.model-less-limit=0.02",
                        "contexa.pqa.oss.quality.gate.significance=0.1",
                        "contexa.pqa.oss.quality.gate.minimum-stop-roots=50",
                        "contexa.pqa.oss.quality.gate.minimum-allow-roots=60")
                .withBean(QualityGateSource.class, () -> (scope, prompt, candidate, current) ->
                        QualityGateReading.baselinePending(null))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    QualityGatePolicy policy = context.getBean(PqaOssQualityGateProperties.class).policy(null);
                    assertThat(policy.mode()).isEqualTo(QualityGateMode.BLOCK);
                    assertThat(policy.settings()).isEqualTo(new QualityGateSettings(0.02, 0.1, 50, 60));
                    assertThat(context.getBean(PromptGovernanceReleaseGateService.class)
                            .qualityMeasurement(null, "cortex.security-decision", "v1.0"))
                            .isEqualTo(QualityMeasurementState.BASELINE_PENDING);
                });
        runner.withPropertyValues("contexa.pqa.oss.quality.gate.significance=1.5")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void withoutTheRegistryThereIsNoStartupRegistration() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(PromptGovernanceAutoConfiguration.class))
                .withBean("contexaJdbcTemplate", JdbcTemplate.class, () -> mock(JdbcTemplate.class))
                .withBean("contexaObjectMapper", ObjectMapper.class, ObjectMapper::new)
                .withBean(PromptGovernanceChangeRecordRepository.class, () -> mock(PromptGovernanceChangeRecordRepository.class))
                .withBean(PromptGovernanceEvaluationRecordRepository.class, () -> mock(PromptGovernanceEvaluationRecordRepository.class))
                .withBean(PromptGovernanceReleaseApprovalRepository.class, () -> mock(PromptGovernanceReleaseApprovalRepository.class))
                .withBean(PromptGovernanceReleaseWorkflowRepository.class, () -> mock(PromptGovernanceReleaseWorkflowRepository.class))
                .withBean(PromptGovernanceRollbackRecordRepository.class, () -> mock(PromptGovernanceRollbackRecordRepository.class))
                .run(context -> {
                    assertThat(context).doesNotHaveBean(PromptGovernanceRegistryService.class);
                    assertThat(context).doesNotHaveBean("contexaPromptGovernanceRegistryBootstrapRunner");
                });
    }
}
