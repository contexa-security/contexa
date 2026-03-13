package io.contexa.contexacore.autonomous;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacore.autonomous.handler.SecurityEventHandler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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

        var inOrder = org.mockito.Mockito.inOrder(handler2, handler3, handler1);
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
