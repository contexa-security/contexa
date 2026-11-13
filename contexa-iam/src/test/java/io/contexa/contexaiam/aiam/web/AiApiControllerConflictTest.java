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
package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacore.exception.AIOperationException;
import io.contexa.contexacore.exception.StrategicOperationConflictException;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.std.streaming.StandardStreamingService;
import io.contexa.contexaiam.aiam.protocol.context.PolicyContext;
import io.contexa.contexaiam.aiam.protocol.request.PolicyGenerationItem;
import io.contexa.contexaiam.aiam.protocol.response.PolicyResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** A policy generation refused for an identical running one answers 409, not the 500 of a failed generation. */
class AiApiControllerConflictTest {

    private AICoreOperations<PolicyContext> processor;
    private StandardStreamingService streaming;
    private AiApiController controller;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        processor = mock(AICoreOperations.class);
        streaming = mock(StandardStreamingService.class);
        controller = new AiApiController(processor, streaming);
    }

    @Test
    void anIdenticalRequestThatIsRunningAnswersConflict() {
        when(streaming.process(any(), eq(processor), eq(PolicyResponse.class)))
                .thenReturn(Mono.error(new StrategicOperationConflictException("Strategic operation conflict: strategy-x")));

        ResponseEntity<Object> response = controller.generatePolicyFromText(item()).block();

        assertThat(response).isNotNull();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    void anyOtherFailureStillAnswersInternalServerError() {
        when(streaming.process(any(), eq(processor), eq(PolicyResponse.class)))
                .thenReturn(Mono.error(new AIOperationException("Async strategic operation failed: strategy-x")));

        ResponseEntity<Object> response = controller.generatePolicyFromText(item()).block();

        assertThat(response).isNotNull();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    private static PolicyGenerationItem item() {
        return new PolicyGenerationItem("let auditors read settlement records", null);
    }
}
