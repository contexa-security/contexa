package io.contexa.autoconfigure.core.session;

import io.contexa.contexacore.infra.session.MfaSessionRepository;
import io.contexa.contexacore.infra.session.generator.SessionIdGenerator;
import io.contexa.contexacore.infra.session.generator.HttpSessionIdGenerator;
import io.contexa.contexacore.infra.session.impl.HttpSessionMfaRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("CoreSessionAutoConfiguration")
class CoreSessionAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(CoreSessionAutoConfiguration.class));

    @Nested
    @DisplayName("SessionIdGenerator")
    class SessionIdGeneratorTest {

        @Test
        @DisplayName("Should create HttpSessionIdGenerator by default")
        void shouldCreateHttpSessionIdGenerator() {
            contextRunner.run(context -> {
                assertThat(context).hasSingleBean(SessionIdGenerator.class);
                assertThat(context.getBean(SessionIdGenerator.class))
                        .isInstanceOf(HttpSessionIdGenerator.class);
            });
        }
    }

    @Nested
    @DisplayName("MfaSessionRepository fallback")
    class MfaSessionRepositoryTest {

        @Test
        @DisplayName("Should fallback to HttpSession when no Redis available")
        void shouldFallbackToHttpSession() {
            contextRunner.run(context -> {
                assertThat(context).hasSingleBean(MfaSessionRepository.class);
                assertThat(context.getBean(MfaSessionRepository.class))
                        .isInstanceOf(HttpSessionMfaRepository.class);
            });
        }
    }
}
