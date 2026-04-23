package io.contexa.autoconfigure.iam.aiam;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexaidentity.security.core.config.PlatformConfig;
import io.contexa.contexaiam.aiam.service.DataIngestionServiceImpl;
import io.contexa.contexaiam.aiam.strategy.ConditionTemplateDiagnosisStrategy;
import io.contexa.contexaiam.aiam.strategy.PolicyGenerationDiagnosisStrategy;
import io.contexa.contexaiam.aiam.strategy.ResourceNamingDiagnosisStrategy;
import io.contexa.contexaiam.repository.PolicyRepository;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class IamAiamServiceStrategyAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(IamAiamServiceStrategyAutoConfiguration.class))
            .withBean(PlatformConfig.class, () -> mock(PlatformConfig.class))
            .withBean(PolicyRepository.class, () -> mock(PolicyRepository.class))
            .withBean(ObjectMapper.class, ObjectMapper::new)
            .withBean(AILabFactory.class, () -> mock(AILabFactory.class));

    @Test
    void shouldStartWithoutVectorStoreAndSkipDataIngestionService() {
        contextRunner.run(context -> {
            assertThat(context).doesNotHaveBean(DataIngestionServiceImpl.class);
            assertThat(context).hasSingleBean(ConditionTemplateDiagnosisStrategy.class);
            assertThat(context).hasSingleBean(PolicyGenerationDiagnosisStrategy.class);
            assertThat(context).hasSingleBean(ResourceNamingDiagnosisStrategy.class);
        });
    }
}
