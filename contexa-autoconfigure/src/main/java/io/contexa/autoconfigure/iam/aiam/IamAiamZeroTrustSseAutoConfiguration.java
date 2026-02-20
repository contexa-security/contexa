package io.contexa.autoconfigure.iam.aiam;

import io.contexa.autoconfigure.core.autonomous.CoreAutonomousEventAutoConfiguration;
import io.contexa.contexacore.autonomous.event.LlmAnalysisEventListener;
import io.contexa.contexaiam.aiam.event.ZeroTrustAnalysisEventListener;
import io.contexa.contexaiam.aiam.event.ZeroTrustSsePublisher;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/**
 * AutoConfiguration for Zero Trust SSE event system.
 * Must load before CoreAutonomousEventAutoConfiguration to override
 * the default no-op LlmAnalysisEventListener.
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
    @ConditionalOnMissingBean(LlmAnalysisEventListener.class)
    public LlmAnalysisEventListener zeroTrustAnalysisEventListener(
            ZeroTrustSsePublisher zeroTrustSsePublisher) {
        return new ZeroTrustAnalysisEventListener(zeroTrustSsePublisher);
    }
}
