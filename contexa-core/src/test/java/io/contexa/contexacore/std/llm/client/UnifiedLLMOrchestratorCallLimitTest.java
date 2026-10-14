package io.contexa.contexacore.std.llm.client;

import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.concurrent.Callable;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * P3-EXTRA-9: the provider call waits on its own executor under the platform limit, lowered to the calling layer's model
 * call limit when the execution context carries one. Waiting on the pipeline cannot bound it, since the pipeline runs on
 * the calling thread.
 */
class UnifiedLLMOrchestratorCallLimitTest {

    @Test
    void theLayerCallLimitBoundsTheProviderCallBelowThePlatformLimit() {
        UnifiedLLMOrchestrator orchestrator = new UnifiedLLMOrchestrator(null, null, new TieredLLMProperties(),
                new AdvisorRegistry(), new SecurityPlaneProperties());
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));
        context.addMetadata(ExecutionContext.CALL_TIMEOUT_MS, 50L);
        Callable<String> slowCall = () -> {
            Thread.sleep(2000);
            return "late";
        };

        long started = System.currentTimeMillis();
        assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(orchestrator, "executeProviderCallWithinTimeout",
                context, null, slowCall)).isInstanceOf(RuntimeException.class)
                .satisfies(error -> assertThat(error.getClass().getSimpleName())
                        .isEqualTo("ProviderCallTimeoutException"));

        assertThat(System.currentTimeMillis() - started).isLessThan(1500);
        assertThat(context.getMetadata()).containsEntry("providerCallTimeoutMs", 50L);
    }

    @Test
    void withoutALayerLimitThePlatformLimitStays() {
        UnifiedLLMOrchestrator orchestrator = new UnifiedLLMOrchestrator(null, null, new TieredLLMProperties(),
                new AdvisorRegistry(), new SecurityPlaneProperties());
        ExecutionContext context = ExecutionContext.from(new Prompt("security prompt"));

        Object result = ReflectionTestUtils.invokeMethod(orchestrator, "executeProviderCallWithinTimeout", context, null,
                (Callable<String>) () -> "in time");

        assertThat(result).isEqualTo("in time");
        assertThat(context.getMetadata()).containsEntry("providerCallTimeoutMs", 60000L);
    }
}
