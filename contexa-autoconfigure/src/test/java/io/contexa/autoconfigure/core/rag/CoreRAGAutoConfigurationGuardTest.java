package io.contexa.autoconfigure.core.rag;

import io.contexa.contexacore.infra.lock.DistributedLockService;
import io.contexa.contexacore.std.components.event.AuditLogger;
import io.contexa.contexacore.std.rag.service.UnifiedVectorService;
import io.contexa.contexacore.std.strategy.AIStrategyRegistry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class CoreRAGAutoConfigurationGuardTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(CoreRAGAutoConfiguration.class))
            .withBean(AIStrategyRegistry.class, () -> mock(AIStrategyRegistry.class))
            .withBean(AuditLogger.class, () -> mock(AuditLogger.class))
            .withBean(DistributedLockService.class, () -> mock(DistributedLockService.class));

    @Test
    @DisplayName("rag advisors and vector services back off without ChatClient.Builder and VectorStore")
    void ragBeansBackOffWithoutChatClientBuilderAndVectorStore() {
        contextRunner.run(context -> {
            assertThat(context).doesNotHaveBean("behaviorQueryTransformer");
            assertThat(context).doesNotHaveBean("riskQueryTransformer");
            assertThat(context).doesNotHaveBean("policyQueryTransformer");
            assertThat(context).doesNotHaveBean("behaviorAnalysisRagAdvisor");
            assertThat(context).doesNotHaveBean("riskAssessmentRagAdvisor");
            assertThat(context).doesNotHaveBean("policyGenerationRagAdvisor");
            assertThat(context).doesNotHaveBean(UnifiedVectorService.class);
        });
    }
}