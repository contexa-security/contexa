package io.contexa.autoconfigure.iam.admin;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.company.CompanyRecordsFactSourceVerifier;
import io.contexa.contexacore.std.components.prompt.governance.PromptGovernanceRegistryService;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexacore.verification.inspection.PromptFactSourceVerifier;
import io.contexa.contexacore.verification.inspection.PromptInspectionCheck;
import io.contexa.contexacore.verification.inspection.PromptInspectionReinspection;
import io.contexa.contexacore.verification.inspection.PromptInspectionResultStore;
import io.contexa.contexacore.verification.inspection.PromptInspectionScheduler;
import io.contexa.contexacore.verification.inspection.PromptInspectionService;
import io.contexa.contexacore.verification.inspection.PromptInspector;
import io.contexa.contexaiam.admin.promptquality.inspection.BundleTraceCheck;
import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptInspectionQueries;
import io.contexa.contexaiam.admin.promptquality.inspection.JdbcPromptInspectionResultStore;
import io.contexa.contexaiam.admin.promptquality.inspection.PromptInspectionApiController;
import io.contexa.contexaiam.admin.promptquality.inspection.PromptInspectionConsole;
import io.contexa.contexaiam.admin.promptquality.inspection.PromptInspectionPageController;
import io.contexa.contexaiam.admin.promptquality.evidence.SealedEvidenceController;
import io.contexa.contexaiam.admin.promptquality.evidence.SealedEvidenceDetails;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;

import java.lang.reflect.Method;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * The OSS prompt inspection wiring: the inspector with the core checks (and the bundle trace when the release registry
 * verifier is there), the JDBC result store, the automatic round and the operator's re-inspection, all off while
 * Enterprise is enabled or the inspection is switched off.
 */
class PromptInspectionAutoConfigurationTest {

    /** The evidence audit (plan 2.1 of the prompt quality redesign). */
    private static final List<String> CHECKS = List.of("SEAL_INTEGRITY", "BUNDLE_TRACE", "SOURCE_TRUTH");

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(PromptInspectionAutoConfiguration.class))
            .withBean("contexaObjectMapper", ObjectMapper.class, ObjectMapper::new)
            .withBean(SealedEvidencePackageRepository.class, () -> mock(SealedEvidencePackageRepository.class))
            .withBean("contexaJdbcTemplate", JdbcTemplate.class, () -> mock(JdbcTemplate.class))
            .withBean("contexaTransactionManager", PlatformTransactionManager.class,
                    () -> mock(PlatformTransactionManager.class));

    @Test
    void theInspectorTheStoreTheRoundAndTheReinspectionAreWired() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(PromptInspector.class);
            assertThat(context.getBean(PromptInspectionResultStore.class))
                    .isInstanceOf(JdbcPromptInspectionResultStore.class);
            assertThat(context).hasSingleBean(PromptInspectionService.class);
            assertThat(context).hasSingleBean(PromptInspectionScheduler.class);
            assertThat(context).hasSingleBean(PromptInspectionReinspection.class);
            assertThat(context).doesNotHaveBean("promptInspectionReinspectionExecutor");
            assertThat(context).hasSingleBean(JdbcPromptInspectionQueries.class);
            assertThat(context).hasSingleBean(PromptInspectionConsole.class);
            assertThat(context).hasSingleBean(PromptInspectionApiController.class);
            assertThat(context).hasSingleBean(PromptInspectionPageController.class);
            // Quality plan 3.7, 3.8: the sealed evidence, which the sealed prompt screens' addresses open.
            assertThat(context).hasSingleBean(SealedEvidenceDetails.class);
            assertThat(context).hasSingleBean(SealedEvidenceController.class);
            assertThat(context.getBean(PromptInspector.class).checks()).extracting(PromptInspectionCheck::code)
                    .containsExactlyElementsOf(CHECKS);
            assertThat(bundleTrace(context.getBean(PromptInspector.class)).readsRegistry()).isFalse();
            // docs/agent OC-4: the source truth check reads Contexa's own records without a host verifier.
            assertThat(context.getBean(PromptFactSourceVerifier.class))
                    .isInstanceOf(CompanyRecordsFactSourceVerifier.class);
        });
    }

    /** docs/agent OC-4: an application's own verifier of its sources replaces Contexa's. */
    @Test
    void anApplicationsOwnSourceVerifierReplacesContexas() {
        PromptFactSourceVerifier own = subject -> List.of();
        runner.withBean(PromptFactSourceVerifier.class, () -> own).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(PromptFactSourceVerifier.class)).isSameAs(own);
        });
    }

    @Test
    void withThePromptVersionManagementTheBundleTraceReadsItsReleaseRegistry() {
        runner.withBean(PromptGovernanceRegistryService.class, () -> mock(PromptGovernanceRegistryService.class))
                .run(context -> {
                    assertThat(context.getBean(PromptInspector.class).checks()).extracting(PromptInspectionCheck::code)
                            .containsExactlyElementsOf(CHECKS);
                    assertThat(bundleTrace(context.getBean(PromptInspector.class)).readsRegistry()).isTrue();
                });
    }

    private static BundleTraceCheck bundleTrace(PromptInspector inspector) {
        return (BundleTraceCheck) inspector.checks().stream()
                .filter(check -> BundleTraceCheck.CODE.equals(check.code())).findFirst().orElseThrow();
    }

    @Test
    void withEnterpriseEnabledNothingIsWired() {
        runner.withPropertyValues("contexa.enterprise.enabled=true")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(PromptInspector.class);
                    assertThat(context).doesNotHaveBean(PromptInspectionScheduler.class);
                });
    }

    @Test
    void switchedOffNothingIsWired() {
        runner.withPropertyValues("contexa.prompt-inspection.enabled=false")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(PromptInspector.class);
                    assertThat(context).doesNotHaveBean(PromptInspectionScheduler.class);
                });
    }

    @Test
    void theSettingsAreTheDesignDefaultsAndCanBeChanged() {
        runner.run(context -> {
            PromptInspectionProperties properties = context.getBean(PromptInspectionProperties.class);
            assertThat(properties.getInterval()).isEqualTo(Duration.ofSeconds(30))
                    .isEqualTo(Duration.parse(PromptInspectionScheduler.DEFAULT_INTERVAL));
            assertThat(properties.getInitialDelay())
                    .isEqualTo(Duration.parse(PromptInspectionScheduler.DEFAULT_INITIAL_DELAY));
            assertThat(properties.getBatchSize()).isEqualTo(50);
            // R1b-6: a period's re-inspection is the round's work, so there is no page size of a re-inspection job.
            assertThat(Arrays.stream(PromptInspectionProperties.class.getMethods()).map(Method::getName))
                    .doesNotContain("getReinspectionPageSize");
            assertThat(properties.getSamplePercent()).isEqualTo(100);
        });
        runner.withPropertyValues("contexa.prompt-inspection.batch-size=7",
                        "contexa.prompt-inspection.sample-percent=40")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    PromptInspectionProperties properties = context.getBean(PromptInspectionProperties.class);
                    assertThat(properties.getBatchSize()).isEqualTo(7);
                    assertThat(properties.getSamplePercent()).isEqualTo(40);
                });
        runner.withPropertyValues("contexa.prompt-inspection.sample-percent=0")
                .run(context -> assertThat(context).hasFailed());
    }

    /**
     * What an inspection found plays no part in how long a sealed package is kept: the inspection wires no retention
     * of its own and its result store removes no package, whatever the earlier clean period is set to.
     */
    @Test
    void theInspectionRemovesNoSealedPackage() {
        runner.withPropertyValues("contexa.pqa.oss.sealed-evidence.retention.clean-period=0s")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(PromptInspectionScheduler.class);
                    assertThat(context).doesNotHaveBean("contexaPromptInspectionCleanPackageRetentionScheduler");
                    assertThat(context.getBeanNamesForType(Object.class)).noneMatch(name -> name.contains("Retention"));
                });
        assertThat(Arrays.stream(PromptInspectionResultStore.class.getMethods()).map(Method::getName))
                .doesNotContain("removeCleanPackagesCapturedBefore");
    }

    @Test
    void withoutTheContexaDatabaseThereIsNoStoreAndNoRound() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(PromptInspectionAutoConfiguration.class))
                .withBean("contexaObjectMapper", ObjectMapper.class, ObjectMapper::new)
                .withBean(SealedEvidencePackageRepository.class, () -> mock(SealedEvidencePackageRepository.class))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(PromptInspector.class);
                    assertThat(context).doesNotHaveBean(PromptInspectionResultStore.class);
                    assertThat(context).doesNotHaveBean(PromptInspectionScheduler.class);
                    assertThat(context).doesNotHaveBean(PromptInspectionApiController.class);
                    assertThat(context).doesNotHaveBean(PromptInspectionPageController.class);
                    assertThat(context).doesNotHaveBean(SealedEvidenceController.class);
                });
    }
}
