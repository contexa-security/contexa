package io.contexa.autoconfigure.ai;

import io.contexa.contexacore.security.AISessionSecurityContextRepository;
import io.contexa.contexaidentity.security.core.bootstrap.configurer.SessionSecurityContextRepositoryConfigurer;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class AiSecurityConfigurationTest {

    @Test
    void shouldRegisterSessionSecurityContextRepositoryConfigurerWhenUserProvidesPlatformConfig() {
        new ApplicationContextRunner()
                .withUserConfiguration(AiSecurityConfiguration.class)
                .withBean(PlatformConfig.class, () -> PlatformConfig.builder().build())
                .withBean(AISessionSecurityContextRepository.class,
                        () -> mock(AISessionSecurityContextRepository.class))
                .run(context -> {
                    assertThat(context).hasSingleBean(PlatformConfig.class);
                    assertThat(context).hasSingleBean(AISessionSecurityContextRepository.class);
                    assertThat(context).hasSingleBean(SessionSecurityContextRepositoryConfigurer.class);
                });
    }
}