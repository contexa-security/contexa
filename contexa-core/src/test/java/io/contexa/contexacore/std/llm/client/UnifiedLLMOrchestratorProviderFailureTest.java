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
package io.contexa.contexacore.std.llm.client;

import io.contexa.contexacore.config.TieredLLMProperties;
import io.contexa.contexacore.properties.SecurityPlaneProperties;
import io.contexa.contexacore.std.advisor.core.AdvisorRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.ai.retry.NonTransientAiException;
import org.springframework.ai.retry.TransientAiException;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Which provider failures are sent again. Spring AI turns an HTTP 4xx into a NonTransientAiException and a 5xx into a
 * TransientAiException; a request the provider refused (a 400 for a setting the model does not take, a 401, a 404)
 * gets the same answer when it is sent again, while a timeout, a conflict, a rate limit and an overload may pass.
 */
class UnifiedLLMOrchestratorProviderFailureTest {

    private final UnifiedLLMOrchestrator orchestrator = new UnifiedLLMOrchestrator(null, null,
            new TieredLLMProperties(), new AdvisorRegistry(), new SecurityPlaneProperties());

    @Test
    void aRequestTheProviderRefusedIsNotSentAgain() {
        NonTransientAiException refused = new NonTransientAiException(
                "HTTP 400 - {\"type\":\"error\",\"error\":{\"type\":\"invalid_request_error\","
                        + "\"message\":\"`temperature` is deprecated for this model.\"}}");

        assertThat(retryable(refused)).isFalse();
        assertThat(retryable(new RuntimeException(refused))).isFalse();
        assertThat(retryable(new NonTransientAiException("HTTP 401 - invalid x-api-key"))).isFalse();
    }

    @Test
    void aTimeoutAConflictARateLimitAndAnOverloadAreSentAgain() {
        assertThat(retryable(new NonTransientAiException("HTTP 429 - rate_limit_error"))).isTrue();
        assertThat(retryable(new NonTransientAiException("HTTP 408 - request timeout"))).isTrue();
        assertThat(retryable(new NonTransientAiException("HTTP 409 - conflict"))).isTrue();
        assertThat(retryable(new TransientAiException("HTTP 529 - {\"type\":\"overloaded_error\"}"))).isTrue();
        assertThat(retryable(new TransientAiException("HTTP 500 - internal error"))).isTrue();
        assertThat(retryable(new IOException("connection reset"))).isTrue();
    }

    private boolean retryable(Throwable failure) {
        Boolean retryable = ReflectionTestUtils.invokeMethod(orchestrator, "isRetryableProviderFailure", failure);
        return Boolean.TRUE.equals(retryable);
    }
}
