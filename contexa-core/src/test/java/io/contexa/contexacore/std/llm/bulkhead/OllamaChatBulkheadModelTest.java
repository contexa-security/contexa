package io.contexa.contexacore.std.llm.bulkhead;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.telemetry.SecurityEventTelemetryContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.Prompt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OllamaChatBulkheadModelTest {

    @Mock
    private ChatModel delegate;

    @BeforeEach
    void resetBulkheadRegistry() {
        OllamaBulkheadRegistry.resetForTests();
    }

    @Test
    @DisplayName("Ollama chat busy 오류는 제한된 budget 내에서 재시도해야 한다")
    void shouldRetryBusyChatCall() {
        Prompt prompt = new Prompt(new UserMessage("hello"));
        ChatResponse response = new ChatResponse(java.util.List.of(new Generation(new AssistantMessage("ok"))));
        SecurityEvent event = SecurityEvent.builder().eventId("evt-chat").build();

        when(delegate.call(prompt))
                .thenThrow(new RuntimeException("maximum pending requests exceeded"))
                .thenReturn(response);

        OllamaChatBulkheadModel wrapper = new OllamaChatBulkheadModel(
                delegate,
                "qwen3:8b-retry",
                new OllamaBulkheadSettings(1, 1000, 1, 1, 2, 2000)
        );

        try (SecurityEventTelemetryContext.Scope ignored = SecurityEventTelemetryContext.open(event)) {
            assertThat(wrapper.call(prompt)).isEqualTo(response);
        }
        verify(delegate, times(2)).call(prompt);
        assertThat(event.getMetadata()).containsKey("chatAcquireMs");
        assertThat(event.getMetadata()).containsEntry("chatRetryCount", 1L);
    }

    @Test
    @DisplayName("busy 실패가 임계치를 넘으면 chat circuit 이 열리고 다음 호출을 즉시 차단해야 한다")
    void shouldOpenCircuitAfterRepeatedBusyFailures() {
        Prompt prompt = new Prompt(new UserMessage("hello"));
        SecurityEvent event = SecurityEvent.builder().eventId("evt-chat-circuit").build();

        when(delegate.call(prompt))
                .thenThrow(new RuntimeException("maximum pending requests exceeded"));

        OllamaChatBulkheadModel wrapper = new OllamaChatBulkheadModel(
                delegate,
                "qwen3:8b-circuit",
                new OllamaBulkheadSettings(1, 1000, 0, 0, 1, 2000)
        );

        try (SecurityEventTelemetryContext.Scope ignored = SecurityEventTelemetryContext.open(event)) {
            assertThatThrownBy(() -> wrapper.call(prompt))
                    .isInstanceOf(RuntimeException.class)
                    .hasMessageContaining("maximum pending requests exceeded");
            assertThatThrownBy(() -> wrapper.call(prompt))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("circuit open");
        }

        assertThat(event.getMetadata()).containsEntry("chatCircuitOpen", true);
    }
}
