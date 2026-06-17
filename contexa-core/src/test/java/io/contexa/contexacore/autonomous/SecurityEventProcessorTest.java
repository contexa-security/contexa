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
package io.contexa.contexacore.autonomous;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import io.contexa.contexacore.SecurityEvent;
import io.contexa.contexacore.SecurityEventContext;
import io.contexa.contexacore.autonomous.handler.SecurityEventHandler;

import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.Test;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.quality.Strictness;


@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SecurityEventProcessorTest {

    @Mock
    private SecurityEventHandler handler1;

    @Mock
    private SecurityEventHandler handler2;

    @Mock
    private SecurityEventHandler handler3;

    private SecurityEventProcessor processor;

    @BeforeEach
    void setUp() {
        when(handler1.getName()).thenReturn("handler1");
        when(handler2.getName()).thenReturn("handler2");
        when(handler3.getName()).thenReturn("handler3");

        when(handler1.canHandle(any())).thenReturn(true);
        when(handler2.canHandle(any())).thenReturn(true);
        when(handler3.canHandle(any())).thenReturn(true);

        when(handler1.handle(any())).thenReturn(true);
        when(handler2.handle(any())).thenReturn(true);
        when(handler3.handle(any())).thenReturn(true);
    }

    @Test
    @DisplayName("Handlers should be sorted by order: 50 -> 55 -> 60")
    void shouldSortHandlersByOrder() {
        // given
        when(handler1.getOrder()).thenReturn(60);
        when(handler2.getOrder()).thenReturn(50);
        when(handler3.getOrder()).thenReturn(55);

        List<SecurityEventHandler> handlers = List.of(handler1, handler2, handler3);
        processor = new SecurityEventProcessor(handlers);

        SecurityEvent event = SecurityEvent.builder().build();

        // when
        SecurityEventContext result = processor.process(event);

        // then
        assertThat(result).isNotNull();
        assertThat(result.getProcessingStatus()).isEqualTo(SecurityEventContext.ProcessingStatus.COMPLETED);

        var inOrder = Mockito.inOrder(handler2, handler3, handler1);
        inOrder.verify(handler2).handle(any());
        inOrder.verify(handler3).handle(any());
        inOrder.verify(handler1).handle(any());
    }

    @Test
    @DisplayName("Handler chain should execute sequentially")
    void shouldExecuteHandlerChainSequentially() {
        // given
        when(handler1.getOrder()).thenReturn(10);
        when(handler2.getOrder()).thenReturn(20);
        when(handler3.getOrder()).thenReturn(30);

        List<SecurityEventHandler> handlers = List.of(handler1, handler2, handler3);
        processor = new SecurityEventProcessor(handlers);

        SecurityEvent event = SecurityEvent.builder().build();

        // when
        SecurityEventContext result = processor.process(event);

        // then
        assertThat(result.getProcessingStatus()).isEqualTo(SecurityEventContext.ProcessingStatus.COMPLETED);
        verify(handler1).handle(any());
        verify(handler2).handle(any());
        verify(handler3).handle(any());
    }

    @Test
    @DisplayName("Chain should stop when handler returns false")
    void shouldStopChainWhenHandlerReturnsFalse() {
        // given
        when(handler1.getOrder()).thenReturn(10);
        when(handler2.getOrder()).thenReturn(20);
        when(handler3.getOrder()).thenReturn(30);
        when(handler2.handle(any())).thenReturn(false);

        List<SecurityEventHandler> handlers = List.of(handler1, handler2, handler3);
        processor = new SecurityEventProcessor(handlers);

        SecurityEvent event = SecurityEvent.builder().build();

        // when
        SecurityEventContext result = processor.process(event);

        // then
        verify(handler1).handle(any());
        verify(handler2).handle(any());
        verify(handler3, never()).handle(any());
    }

    @Test
    @DisplayName("Handler chain should stop before enforcement when event deadline is exceeded")
    void shouldStopChainWhenProcessingDeadlineIsExceeded() {
        // given
        when(handler1.getOrder()).thenReturn(10);
        when(handler2.getOrder()).thenReturn(20);
        when(handler1.handle(any())).thenAnswer(invocation -> {
            SecurityEventContext context = invocation.getArgument(0);
            context.getSecurityEvent().addMetadata(SecurityEventProcessor.PROCESSING_TIMED_OUT, true);
            return true;
        });

        List<SecurityEventHandler> handlers = List.of(handler1, handler2);
        processor = new SecurityEventProcessor(handlers);

        SecurityEvent event = SecurityEvent.builder().build();

        // when
        SecurityEventContext result = processor.process(event);

        // then
        verify(handler1).handle(any());
        verify(handler2, never()).handle(any());
        assertThat(result.getProcessingStatus()).isEqualTo(SecurityEventContext.ProcessingStatus.FAILED);
        assertThat(result.getMetadata())
                .containsEntry(SecurityEventProcessor.PROCESSING_DEADLINE_EXCEEDED, true)
                .containsEntry(SecurityEventProcessor.PROCESSING_DEADLINE_EXCEEDED_BEFORE_HANDLER, "handler2");
    }

    @Test
    @DisplayName("handleError should be called when handler throws exception")
    void shouldCallHandleErrorOnException() {
        // given
        when(handler1.getOrder()).thenReturn(10);
        when(handler2.getOrder()).thenReturn(20);

        RuntimeException exception = new RuntimeException("test error");
        when(handler1.handle(any())).thenThrow(exception);

        List<SecurityEventHandler> handlers = List.of(handler1, handler2);
        processor = new SecurityEventProcessor(handlers);

        SecurityEvent event = SecurityEvent.builder().build();

        // when
        SecurityEventContext result = processor.process(event);

        // then
        verify(handler1).handleError(any(SecurityEventContext.class), any(Exception.class));
        // After handleError, chain continues (executeHandler returns true on exception)
        verify(handler2).handle(any());
    }

    @Test
    @DisplayName("Empty handler list should complete without errors")
    void shouldHandleEmptyHandlerList() {
        // given
        List<SecurityEventHandler> handlers = Collections.emptyList();
        processor = new SecurityEventProcessor(handlers);

        SecurityEvent event = SecurityEvent.builder().build();

        // when
        SecurityEventContext result = processor.process(event);

        // then
        assertThat(result).isNotNull();
        assertThat(result.getProcessingStatus()).isEqualTo(SecurityEventContext.ProcessingStatus.COMPLETED);
        assertThat(result.getSecurityEvent()).isEqualTo(event);
    }
}
