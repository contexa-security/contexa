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
package io.contexa.contexaiam.resource.service;

import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexacommon.entity.ManagedResource;
import io.contexa.contexacore.exception.StrategicOperationConflictException;
import io.contexa.contexacore.std.operations.AICoreOperations;
import io.contexa.contexaiam.aiam.protocol.context.ConditionTemplateContext;
import io.contexa.contexaiam.aiam.protocol.response.ConditionTemplateGenerationResponse;
import io.contexa.contexaiam.repository.ConditionTemplateRepository;
import io.contexa.contexaiam.repository.ManagedResourceRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import reactor.core.publisher.Mono;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A generation refused because an identical one is already running must not save defaults beside the real templates that
 * generation saves; any other failure still ends in the fallback templates.
 */
class AutoConditionTemplateServiceConflictTest {

    private ConditionTemplateRepository repository;
    private AICoreOperations<ConditionTemplateContext> processor;
    private AutoConditionTemplateService service;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        repository = mock(ConditionTemplateRepository.class);
        ManagedResourceRepository resources = mock(ManagedResourceRepository.class);
        processor = mock(AICoreOperations.class);
        service = new AutoConditionTemplateService(repository, resources, processor);
        ManagedResource method = ManagedResource.builder()
                .resourceIdentifier("com.example.OrderService.cancel(Long)")
                .resourceType(ManagedResource.ResourceType.METHOD)
                .serviceOwner("OrderService")
                .parameterTypes("[\"java.lang.Long\"]")
                .build();
        when(resources.findByResourceType(ManagedResource.ResourceType.METHOD)).thenReturn(List.of(method));
        when(repository.findAll()).thenReturn(List.of());
        when(repository.saveAll(anyList())).thenAnswer(inv -> inv.getArgument(0));
    }

    @Test
    void aRefusedUniversalGenerationSavesNothing() {
        when(processor.process(ArgumentMatchers.<AIRequest<ConditionTemplateContext>>any(), eq(ConditionTemplateGenerationResponse.class)))
                .thenReturn(Mono.error(new StrategicOperationConflictException("Strategic operation conflict: universal")));

        assertThatThrownBy(service::generateConditionTemplates).isInstanceOf(StrategicOperationConflictException.class);

        verify(repository, never()).saveAll(anyList());
    }

    @Test
    void aRefusedBatchGenerationSavesNothing() {
        ConditionTemplateGenerationResponse noTemplates = ConditionTemplateGenerationResponse.failure("batch", "none", "no templates");
        when(processor.process(ArgumentMatchers.<AIRequest<ConditionTemplateContext>>any(), eq(ConditionTemplateGenerationResponse.class)))
                .thenReturn(Mono.just(noTemplates), Mono.error(new StrategicOperationConflictException("Strategic operation conflict: batch")));

        assertThatThrownBy(service::generateConditionTemplates)
                .isInstanceOf(StrategicOperationConflictException.class)
                .hasMessage("Strategic operation conflict: batch");

        verify(repository, never()).saveAll(anyList());
    }

    @Test
    void anyOtherFailureStillEndsInTheFallbackTemplates() {
        when(processor.process(ArgumentMatchers.<AIRequest<ConditionTemplateContext>>any(), eq(ConditionTemplateGenerationResponse.class)))
                .thenReturn(Mono.error(new IllegalStateException("model unavailable")));

        assertThat(service.generateConditionTemplates()).isNotNull();

        verify(repository).saveAll(anyList());
    }
}
