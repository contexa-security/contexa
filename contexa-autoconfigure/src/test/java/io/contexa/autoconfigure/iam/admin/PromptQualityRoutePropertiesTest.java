package io.contexa.autoconfigure.iam.admin;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.ui.ExtendedModelMap;

import static org.assertj.core.api.Assertions.assertThat;

class PromptQualityRoutePropertiesTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(RoutePropertiesConfiguration.class);

    @Test
    void defaultsApplyWithoutHostApplicationYaml() {
        contextRunner.run(context -> {
            PromptQualityRouteProperties properties = context.getBean(PromptQualityRouteProperties.class);
            assertThat(properties.getOfficialApiRoot()).isEqualTo("/contexa/admin/api/prompt-quality");
            assertThat(properties.getEnterpriseApiRoot())
                    .isEqualTo("/contexa/admin/api/enterprise/prompt-quality");
            assertThat(properties.getEnterpriseVerificationRuntimeRunsPath())
                    .isEqualTo("/verification/runtime-runs");
            PromptQualityOfficialVerificationProperties executionProperties =
                    context.getBean(PromptQualityOfficialVerificationProperties.class);
            assertThat(executionProperties.getStaleExecutionTimeout()).isEqualTo(Duration.ofMinutes(15));
        });
    }

    @Test
    void explicitHostOverridesAreBoundAndNormalized() {
        contextRunner.withPropertyValues(
                        "contexa.pqa.routes.official-api-root=/tenant-a/contexa/admin/api/prompt-quality/",
                        "contexa.pqa.routes.enterprise-api-root=/tenant-a/contexa/admin/api/enterprise/prompt-quality/",
                        "contexa.pqa.routes.enterprise-verification-runtime-runs-path=/verification/runtime-runs/",
                        "contexa.pqa.official-verification.stale-execution-timeout=2m")
                .run(context -> {
                    PromptQualityRouteProperties properties = context.getBean(PromptQualityRouteProperties.class);
                    assertThat(properties.getOfficialApiRoot())
                            .isEqualTo("/tenant-a/contexa/admin/api/prompt-quality");
                    assertThat(properties.getEnterpriseApiRoot())
                            .isEqualTo("/tenant-a/contexa/admin/api/enterprise/prompt-quality");
                    assertThat(properties.getEnterpriseVerificationRuntimeRunsPath())
                            .isEqualTo("/verification/runtime-runs");
                    assertThat(context.getBean(PromptQualityOfficialVerificationProperties.class)
                            .getStaleExecutionTimeout()).isEqualTo(Duration.ofMinutes(2));
                });
    }

    @Test
    void modelAdvicePublishesBothCanonicalRoots() {
        PromptQualityRouteProperties properties = new PromptQualityRouteProperties();
        PromptQualityRouteModelAdvice advice = new PromptQualityRouteModelAdvice(properties);
        ExtendedModelMap model = new ExtendedModelMap();
        advice.addPromptQualityRoutes(model);
        assertThat(model)
                .containsEntry("pqaOfficialApiRoot", properties.getOfficialApiRoot())
                .containsEntry("pqaEnterpriseApiRoot", properties.getEnterpriseApiRoot());
    }

    @Test
    void pqaAutoConfigurationRegistersRoutePropertiesAndModelAdvice() throws NoSuchMethodException {
        EnableConfigurationProperties annotation = PqaOfficialInspectionAutoConfiguration.class
                .getAnnotation(EnableConfigurationProperties.class);
        assertThat(annotation.value()).contains(
                PromptQualityRouteProperties.class,
                PromptQualityOfficialVerificationProperties.class);
        assertThat(PqaOfficialInspectionAutoConfiguration.class
                .getDeclaredMethod("promptQualityRouteModelAdvice", PromptQualityRouteProperties.class)
                .getReturnType()).isEqualTo(PromptQualityRouteModelAdvice.class);
    }

    @Test
    void configurationMetadataDeclaresTheRuntimeDefaults() throws Exception {
        try (var stream = getClass().getClassLoader()
                .getResourceAsStream("META-INF/additional-spring-configuration-metadata.json")) {
            assertThat(stream).isNotNull();
            String metadata = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
            assertThat(metadata)
                    .contains("\"name\": \"contexa.pqa.routes.official-api-root\"")
                    .contains("\"defaultValue\": \"" + PromptQualityRouteProperties.DEFAULT_OFFICIAL_API_ROOT + "\"")
                    .contains("\"name\": \"contexa.pqa.routes.enterprise-api-root\"")
                    .contains("\"defaultValue\": \"" + PromptQualityRouteProperties.DEFAULT_ENTERPRISE_API_ROOT + "\"")
                    .contains("\"name\": \"contexa.pqa.routes.enterprise-verification-runtime-runs-path\"")
                    .contains("\"defaultValue\": \""
                            + PromptQualityRouteProperties.DEFAULT_ENTERPRISE_VERIFICATION_RUNTIME_RUNS_PATH
                            + "\"")
                    .contains("\"name\": \"contexa.pqa.official-verification.stale-execution-timeout\"")
                    .contains("\"defaultValue\": \"15m\"");
        }
    }
    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties({
            PromptQualityRouteProperties.class,
            PromptQualityOfficialVerificationProperties.class
    })
    static class RoutePropertiesConfiguration {
    }
}
