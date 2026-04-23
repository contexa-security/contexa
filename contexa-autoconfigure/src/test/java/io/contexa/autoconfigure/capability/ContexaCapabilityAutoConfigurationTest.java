package io.contexa.autoconfigure.capability;

import io.contexa.contexacommon.autoconfigure.capability.CapabilityStatus;
import io.contexa.contexacommon.autoconfigure.capability.ContexaCapability;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class ContexaCapabilityAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(ContexaCapabilityAutoConfiguration.class));

    @Test
    @DisplayName("defaults to AUTO mode without verbose application properties")
    void defaultsToAutoMode() {
        contextRunner.run(context -> {
            ContexaCapabilityProperties properties = context.getBean(ContexaCapabilityProperties.class);

            assertThat(properties.getMode().name()).isEqualTo("AUTO");
            assertThat(properties.getRequired()).isEmpty();
        });
    }

    @Test
    @DisplayName("detects incomplete RAG vector chain when VectorStore exists but UnifiedVectorService is missing")
    void detectsIncompleteRagVectorChain() {
        contextRunner
                .withBean(VectorStore.class, () -> mock(VectorStore.class))
                .withPropertyValues(
                        "contexa.capability.mode=warn",
                        "contexa.capability.required.rag-vector=true")
                .run(context -> {
                    ContexaCapabilityRegistry registry = context.getBean(ContexaCapabilityRegistry.class);

                    assertThat(registry.lastResults())
                            .filteredOn(result -> result.capability() == ContexaCapability.RAG_VECTOR)
                            .singleElement()
                            .satisfies(result -> {
                                assertThat(result.status()).isEqualTo(CapabilityStatus.INACTIVE_UNEXPECTED);
                                assertThat(result.required()).isTrue();
                                assertThat(result.presentBeans()).contains("org.springframework.ai.vectorstore.VectorStore");
                                assertThat(result.missingBeans()).contains(
                                        "io.contexa.contexacore.autonomous.tiered.cache.VectorStoreCacheLayer",
                                        "io.contexa.contexacore.std.rag.service.UnifiedVectorService");
                            });
                });
    }

    @Test
    @DisplayName("fails fast when a required capability is incomplete")
    void failsFastWhenRequiredCapabilityIsIncomplete() {
        contextRunner
                .withBean(VectorStore.class, () -> mock(VectorStore.class))
                .withPropertyValues(
                        "contexa.capability.mode=fail-fast",
                        "contexa.capability.required.rag-vector=true")
                .run(context -> assertThat(context).hasFailed());
    }
}
