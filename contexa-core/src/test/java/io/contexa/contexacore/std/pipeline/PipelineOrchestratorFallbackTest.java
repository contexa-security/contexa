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
package io.contexa.contexacore.std.pipeline;

import io.contexa.contexacommon.domain.DiagnosisType;
import io.contexa.contexacommon.domain.TemplateType;
import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacore.std.pipeline.executor.PipelineExecutor;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * K123: a pipeline whose model call ran past its limit answers with the fallback of the answer's type: made by the
 * type's no-argument constructor or by its (request id, status) one with a failure status, its error set; a type of
 * neither fails as before.
 */
class PipelineOrchestratorFallbackTest {

    private final PipelineOrchestrator orchestrator = new PipelineOrchestrator(List.of(new TimedOut()));

    @Test
    @DisplayName("K123: a type with a no-argument constructor answers a timed out call with its error set")
    void aNoArgumentTypeAnswersATimedOutCall() {
        NoArgument answer = orchestrator.execute(request(), PipelineConfiguration.createPipelineConfig(),
                NoArgument.class).block();

        assertThat(answer).isNotNull();
        assertThat(answer.getErrorMessage()).startsWith("Pipeline execution failed: ").contains("LLM_EXECUTION");
        assertThat(answer.getMetadata("errorType", String.class)).isEqualTo("TimeoutException");
    }

    @Test
    @DisplayName("K123: a type taking a request id and a status is made with them, a failure")
    void aRequestAndStatusTypeIsMadeWithAFailure() {
        AIRequest<Context> request = request();

        RequestAndStatus answer = orchestrator.execute(request, PipelineConfiguration.createPipelineConfig(),
                RequestAndStatus.class).block();

        assertThat(answer).isNotNull();
        assertThat(answer.requestId).isEqualTo(request.getRequestId());
        assertThat(answer.status).isEqualTo(AIResponse.ExecutionStatus.FAILURE);
        assertThat(answer.getErrorMessage()).startsWith("Pipeline execution failed: ");
    }

    @Test
    @DisplayName("K123: a type of neither constructor still fails, saying which it needs")
    void aTypeOfNeitherFails() {
        assertThatThrownBy(() -> orchestrator.execute(request(), PipelineConfiguration.createPipelineConfig(),
                Neither.class).block())
                .hasMessageContaining("Expected either () or (String, ExecutionStatus)");
    }

    private static AIRequest<Context> request() {
        return new AIRequest<>(new Context(), new TemplateType("ConditionTemplate"), new DiagnosisType("ConditionTemplate"));
    }

    static final class Context extends DomainContext {
        @Override
        public String getDomainType() {
            return "TEST";
        }
    }

    public static final class NoArgument extends AIResponse {
        public NoArgument() {
        }
    }

    public static final class RequestAndStatus extends AIResponse {
        final String requestId;
        final ExecutionStatus status;

        public RequestAndStatus(String requestId, ExecutionStatus status) {
            this.requestId = requestId;
            this.status = status;
        }
    }

    public static final class Neither extends AIResponse {
        public Neither(Object data) {
        }
    }

    /** An executor whose model call ran past its limit, as STEP 4 (LLM_EXECUTION) reports it. */
    static final class TimedOut implements PipelineExecutor {

        @Override
        public <T extends DomainContext, R extends AIResponse> Mono<R> execute(AIRequest<T> request,
                                                                             PipelineConfiguration configuration,
                                                                             Class<R> responseType) {
            return Mono.error(new TimeoutException("STEP 4 failed: LLM_EXECUTION (99184ms)"));
        }

        @Override
        public <T extends DomainContext> Flux<String> executeStream(AIRequest<T> request,
                                                                     PipelineConfiguration configuration) {
            return Flux.empty();
        }

        @Override
        public String getSupportedDomain() {
            return "TEST";
        }

        @Override
        public <T extends DomainContext> boolean supportsConfiguration(PipelineConfiguration configuration) {
            return true;
        }
    }
}
