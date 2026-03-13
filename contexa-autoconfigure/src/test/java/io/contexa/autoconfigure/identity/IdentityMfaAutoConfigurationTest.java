package io.contexa.autoconfigure.identity;

import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests the conditional activation gates of IdentityMfaAutoConfiguration.
 * Verifies @ConditionalOnBean(PlatformConfig) and @ConditionalOnProperty gates.
 */
@DisplayName("IdentityMfaAutoConfiguration")
class IdentityMfaAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(IdentityMfaAutoConfiguration.class));

    @Nested
    @DisplayName("Activation gates")
    class ActivationGates {

        @Test
        @DisplayName("Should not activate without PlatformConfig bean")
        void shouldNotActivateWithoutPlatformConfig() {
            contextRunner
                    .run(context -> {
                        assertThat(context).doesNotHaveBean(IdentityMfaAutoConfiguration.class);
                    });
        }

        @Test
        @DisplayName("Should not activate when contexa.identity.mfa.enabled=false")
        void shouldNotActivateWhenDisabled() {
            contextRunner
                    .withBean(PlatformConfig.class, () -> org.mockito.Mockito.mock(PlatformConfig.class))
                    .withPropertyValues("contexa.identity.mfa.enabled=false")
                    .run(context -> {
                        assertThat(context).doesNotHaveBean(IdentityMfaAutoConfiguration.class);
                    });
        }
    }
}
