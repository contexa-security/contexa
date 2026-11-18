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
package io.contexa.contexaiam.aiam.labs.condition;

import io.contexa.contexacommon.domain.context.DomainContext;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.domain.request.AIResponse;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexacore.std.pipeline.PipelineConfiguration;
import io.contexa.contexacore.std.pipeline.PipelineOrchestrator;
import io.contexa.contexacore.std.pipeline.executor.PipelineExecutor;
import io.contexa.contexaiam.aiam.protocol.context.ConditionTemplateContext;
import io.contexa.contexaiam.aiam.protocol.request.ConditionTemplateGenerationRequest;
import io.contexa.contexaiam.aiam.protocol.response.ConditionTemplateGenerationResponse;
import io.contexa.contexaiam.domain.entity.ConditionTemplate;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import io.contexa.contexaiam.resource.service.AutoConditionTemplateService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * K123: a condition template generation whose model call runs past its limit answers with the pipeline's fallback of
 * its answer (no template, the error set) instead of failing to make one; the generation keeps its own fallback
 * templates and ends without an exception.
 */
class ConditionTemplateGenerationTimeoutTest {

    private final ConditionTemplateGenerationLab lab = new ConditionTemplateGenerationLab(
            new PipelineOrchestrator(List.of(new TimedOut())));

    @Test
    @DisplayName("K123: the lab answers a timed out call with the pipeline's fallback, not its own failure")
    void theLabAnswersATimedOutCallWithThePipelinesFallback() {
        ConditionTemplateGenerationResponse answer = lab.processAsync(
                new ConditionTemplateGenerationRequest(ConditionTemplateContext.forUniversalTemplate())).block();

        assertThat(answer).isNotNull();
        assertThat(answer.getErrorMessage()).startsWith("Pipeline execution failed: ").contains("LLM_EXECUTION");
        assertThat(answer.getMetadata("errorType", String.class)).isEqualTo("TimeoutException");
        assertThat(answer.hasTemplates()).isFalse();
        assertThat(answer.getProcessingMetadata()).as("not the lab's own failure answer").doesNotContainKey("error");
    }

    @Test
    @DisplayName("K123: a generation whose every model call timed out keeps its fallback templates, no exception")
    void aGenerationOfTimedOutCallsKeepsItsFallbackTemplates() {
        ConditionTemplateRepository templates = mock(ConditionTemplateRepository.class);
        ManagedResourceRepository resources = mock(ManagedResourceRepository.class);
        when(resources.findByResourceType(ManagedResource.ResourceType.METHOD)).thenReturn(List.of(
                ManagedResource.builder().id(3L).resourceIdentifier("com.example.OrderService.cancel(java.lang.Long)")
                        .resourceType(ManagedResource.ResourceType.METHOD).parameterTypes("[java.lang.Long]")
                        .serviceOwner("orders").build()));
        when(templates.findAll()).thenReturn(List.of());
        when(templates.saveAll(anyList())).thenAnswer(call -> call.getArgument(0));
        AutoConditionTemplateService service = new AutoConditionTemplateService(templates, resources, new ThroughTheLab());

        List<ConditionTemplate> saved = service.generateConditionTemplates();

        assertThat(saved).isNotEmpty().allSatisfy(template -> assertThat(template.getTemplateType()).isEqualTo("fallback"));
    }

    /** The condition template prompt's operations, as the strategy hands a request to the lab. */
    private final class ThroughTheLab implements AICoreOperations<ConditionTemplateContext> {

        @Override
        @SuppressWarnings("unchecked")
        public <R extends AIResponse> Mono<R> process(AIRequest<ConditionTemplateContext> request, Class<R> responseType) {
            return (Mono<R>) lab.processAsync((ConditionTemplateGenerationRequest) request);
        }

        @Override
        public Flux<String> processStream(AIRequest<ConditionTemplateContext> request) {
            return Flux.empty();
        }
    }

    /** An executor whose model call ran past its limit, as STEP 4 (LLM_EXECUTION) reports it on the server. */
    private static final class TimedOut implements PipelineExecutor {

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
            return "ConditionTemplate";
        }

        @Override
        public <T extends DomainContext> boolean supportsConfiguration(PipelineConfiguration configuration) {
            return true;
        }
    }
}
