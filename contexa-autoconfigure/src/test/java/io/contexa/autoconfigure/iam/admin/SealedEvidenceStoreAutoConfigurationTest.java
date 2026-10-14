package io.contexa.autoconfigure.iam.admin;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.autoconfigure.core.CoreDataAutoConfiguration;
import io.contexa.contexacore.autonomous.handler.handler.SealedEvidenceCaptureHandler;
import io.contexa.contexacore.verification.evidence.CanonicalSecurityContextSerializer;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageIntegrity;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRepository;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackageRetentionScheduler;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.aop.AopAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

/**
 * R4a: the sealed evidence store, integrity and serializer beans live in their own auto-configuration, outside the
 * condition on the 12-metric runtime class, so capture, retention and the automatic inspection round keep their store
 * when the old official verification goes; the classes they need live outside the {@code official} package.
 */
class SealedEvidenceStoreAutoConfigurationTest {

    private static final String ENTERPRISE = "io.contexa.autoconfigure.enterprise.iam.IamEnterpriseAutoConfiguration";
    private static final String NEUTRAL_REPOSITORY =
            "io.contexa.contexaiam.admin.promptquality.evidence.JdbcSealedEvidencePackageRepository";
    private static final String NEUTRAL_TIMESTAMPS =
            "io.contexa.contexaiam.admin.promptquality.common.PromptQualityJdbcTimestamps";

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    AopAutoConfiguration.class,
                    SealedEvidenceStoreAutoConfiguration.class,
                    PqaSealedEvidenceAutoConfiguration.class))
            .withBean(ObjectMapper.class, ObjectMapper::new);

    @Test
    void captureAndRetentionHaveTheirStoreWithoutTheOfficialVerificationConfiguration() {
        runner.withBean("contexaJdbcTemplate", JdbcTemplate.class, () -> new JdbcTemplate(mock(DataSource.class)))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBeanNamesForType(SealedEvidencePackageRepository.class))
                            .containsExactly("pqaSealedEvidencePackageRepository");
                    assertThat(context.getBean(SealedEvidencePackageRepository.class).getClass().getName())
                            .isEqualTo(NEUTRAL_REPOSITORY);
                    assertThat(context.getBeanNamesForType(SealedEvidencePackageIntegrity.class))
                            .containsExactly("pqaSealedEvidencePackageIntegrity");
                    assertThat(context.getBeanNamesForType(CanonicalSecurityContextSerializer.class))
                            .containsExactly("pqaCanonicalSecurityContextSerializer");
                    assertThat(context).hasSingleBean(SealedEvidenceCaptureHandler.class);
                    assertThat(context).hasSingleBean(SealedEvidencePackageRetentionScheduler.class);
                });
    }

    @Test
    void withoutTheContexaJdbcTemplateThereIsNoStoreAndSoNoCapture() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean(SealedEvidencePackageRepository.class);
            assertThat(context).doesNotHaveBean(SealedEvidenceCaptureHandler.class);
            assertThat(context).doesNotHaveBean(SealedEvidencePackageRetentionScheduler.class);
        });
    }

    @Test
    void integrityAndSerializerAlreadyThereAreKept() {
        runner.withBean("contexaJdbcTemplate", JdbcTemplate.class, () -> new JdbcTemplate(mock(DataSource.class)))
                .withBean("ossSealedEvidencePackageIntegrity", SealedEvidencePackageIntegrity.class,
                        SealedEvidencePackageIntegrity::new)
                .withBean("ossCanonicalSecurityContextSerializer", CanonicalSecurityContextSerializer.class,
                        () -> new CanonicalSecurityContextSerializer(new ObjectMapper()))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBeanNamesForType(SealedEvidencePackageIntegrity.class))
                            .containsExactly("ossSealedEvidencePackageIntegrity");
                    assertThat(context.getBeanNamesForType(CanonicalSecurityContextSerializer.class))
                            .containsExactly("ossCanonicalSecurityContextSerializer");
                    assertThat(context).hasSingleBean(SealedEvidencePackageRepository.class);
                });
    }

    @Test
    void theStoreComesAfterTheDataAndEnterpriseConfigurationsAndBeforeItsConsumers() {
        AutoConfiguration store = SealedEvidenceStoreAutoConfiguration.class.getAnnotation(AutoConfiguration.class);
        assertThat(store.after()).contains(CoreDataAutoConfiguration.class);
        assertThat(store.afterName()).contains(ENTERPRISE);
        assertThat(PqaSealedEvidenceAutoConfiguration.class.getAnnotation(AutoConfiguration.class).after())
                .containsExactly(SealedEvidenceStoreAutoConfiguration.class);
        assertThat(PromptInspectionAutoConfiguration.class.getAnnotation(AutoConfiguration.class).after())
                .contains(SealedEvidenceStoreAutoConfiguration.class)
                .doesNotContain(PqaOfficialInspectionAutoConfiguration.class);
    }

    @Test
    void theOfficialVerificationConfigurationDeclaresNoStoreIntegrityOrSerializerBean() {
        List<Class<?>> moved = List.of(SealedEvidencePackageRepository.class, SealedEvidencePackageIntegrity.class,
                CanonicalSecurityContextSerializer.class);
        assertThat(Arrays.stream(PqaOfficialInspectionAutoConfiguration.class.getDeclaredMethods())
                .map(Method::getReturnType))
                .doesNotContainAnyElementsOf(moved);
    }

    @Test
    void theStoreAndTheTimestampHelperLiveOutsideTheOfficialPackage() throws ClassNotFoundException {
        assertThat(Class.forName(NEUTRAL_REPOSITORY)).isNotNull();
        assertThat(Class.forName(NEUTRAL_TIMESTAMPS)).isNotNull();
        assertThatThrownBy(() -> Class.forName(
                "io.contexa.contexaiam.admin.promptquality.official.persistence.JdbcSealedEvidencePackageRepository"))
                .isInstanceOf(ClassNotFoundException.class);
        assertThatThrownBy(() -> Class.forName(
                "io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityJdbcTimestamps"))
                .isInstanceOf(ClassNotFoundException.class);
    }
}
