package io.contexa.autoconfigure.iam.aiam;

import io.contexa.autoconfigure.core.autonomous.CoreAutonomousEventAutoConfiguration;
import io.contexa.contexacore.autonomous.event.LlmAnalysisEventListener;
import io.contexa.contexaiam.aiam.event.ZeroTrustAnalysisEventListener;
import io.contexa.contexaiam.aiam.event.ZeroTrustSsePublisher;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

/**
 * AutoConfiguration for Zero Trust SSE event system.
 * Registers ZeroTrustAnalysisEventListener as @Primary decorator
 * that wraps the existing LlmAnalysisEventListener (e.g., LlmAnalysisEventListenerImpl)
 * while adding Zero Trust SSE event publishing for BLOCK/ESCALATE pages.
 */
@AutoConfiguration
@AutoConfigureBefore(CoreAutonomousEventAutoConfiguration.class)
public class IamAiamZeroTrustSseAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public ZeroTrustSsePublisher zeroTrustSsePublisher() {
        return new ZeroTrustSsePublisher();
    }

    @Bean
    @Primary
    public LlmAnalysisEventListener zeroTrustAnalysisEventListener(
            ZeroTrustSsePublisher zeroTrustSsePublisher,
            ObjectProvider<LlmAnalysisEventListener> existingListeners) {
        LlmAnalysisEventListener delegate = existingListeners.orderedStream()
                .filter(l -> !(l instanceof ZeroTrustAnalysisEventListener))
                .findFirst()
                .orElse(null);
        return new ZeroTrustAnalysisEventListener(zeroTrustSsePublisher, delegate);
    }
}
