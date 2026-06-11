/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.autoconfigure.iam.aiam;

import io.contexa.autoconfigure.core.autonomous.CoreAutonomousEventAutoConfiguration;
import io.contexa.contexacore.autonomous.event.LlmAnalysisEventListener;
import io.contexa.contexaiam.aiam.event.ZeroTrustAnalysisEventListener;
import io.contexa.contexaiam.aiam.event.ZeroTrustSsePublisher;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

/**
 * AutoConfiguration for Zero Trust SSE event system.
 * <p>
 * Registers ZeroTrustAnalysisEventListener as {@code @Primary} decorator
 * that wraps the default LlmAnalysisEventListener (no-op fallback from
 * {@link CoreAutonomousEventAutoConfiguration}) while adding Zero Trust
 * SSE event publishing for BLOCK/ESCALATE pages.
 * <p>
 * Must run AFTER CoreAutonomousEventAutoConfiguration so the default
 * {@code llmAnalysisEventListener} bean exists as delegate target.
 */
@AutoConfiguration
@AutoConfigureAfter(CoreAutonomousEventAutoConfiguration.class)
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
            @Qualifier("llmAnalysisEventListener") LlmAnalysisEventListener delegate) {
        return new ZeroTrustAnalysisEventListener(zeroTrustSsePublisher, delegate);
    }
}

