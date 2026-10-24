package io.contexa.autoconfigure.iam.access;

import io.contexa.contexacore.autonomous.access.AccessEvaluationService;
import io.contexa.contexacore.autonomous.event.publisher.ZeroTrustEventPublisher;
import io.contexa.contexacore.autonomous.service.SynchronousProtectableDecisionService;
import io.contexa.contexacore.properties.SecurityZeroTrustProperties;
import io.contexa.contexaiam.access.web.AccessEvaluationController;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/** docs/agent B4: the AuthZEN evaluation API exists only when it is turned on, on the engine's decision path. */
class AccessEvaluationAutoConfigurationTest {

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AccessEvaluationAutoConfiguration.class))
            .withUserConfiguration(DecisionPath.class);

    @Test
    void itIsOffByDefault() {
        runner.run(context -> {
            assertThat(context).doesNotHaveBean(AccessEvaluationService.class);
            assertThat(context).doesNotHaveBean(AccessEvaluationController.class);
        });
    }

    @Test
    void turnedOnItDecidesThroughTheEnginesPath() {
        runner.withPropertyValues("contexa.security.zerotrust.authzen.enabled=true",
                        "contexa.security.zerotrust.authzen.required-authority=SCOPE_gateway.pep")
                .run(context -> {
                    assertThat(context).hasSingleBean(AccessEvaluationService.class);
                    assertThat(context).hasSingleBean(AccessEvaluationController.class);
                    assertThat(context.getBean(SecurityZeroTrustProperties.class).getAuthzen().getRequiredAuthority())
                            .isEqualTo("SCOPE_gateway.pep");
                });
    }

    @Test
    void withoutTheEnginesDecisionPathItStaysOff() {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(AccessEvaluationAutoConfiguration.class))
                .withPropertyValues("contexa.security.zerotrust.authzen.enabled=true")
                .run(context -> assertThat(context).doesNotHaveBean(AccessEvaluationService.class));
    }

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(SecurityZeroTrustProperties.class)
    static class DecisionPath {

        @Bean
        ZeroTrustEventPublisher zeroTrustEventPublisher() {
            return mock(ZeroTrustEventPublisher.class);
        }

        @Bean
        SynchronousProtectableDecisionService synchronousProtectableDecisionService() {
            return mock(SynchronousProtectableDecisionService.class);
        }
    }
}
