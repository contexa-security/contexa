package io.contexa.contexacore.autonomous.event.listener;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.event.SecurityEventListener;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.Acknowledgment;

import java.util.concurrent.CompletableFuture;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class KafkaSecurityEventCollectorTest {

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private KafkaTemplate<String, Object> kafkaTemplate;

    @Mock
    private SecurityEventListener listener;

    @Mock
    private Acknowledgment acknowledgment;

    private KafkaSecurityEventCollector collector;

    @BeforeEach
    void setUp() {
        collector = new KafkaSecurityEventCollector(objectMapper, kafkaTemplate, new SecurityKafkaProperties());
        when(listener.getListenerName()).thenReturn("listener");
        when(listener.isActive()).thenReturn(true);
    }

    @Test
    @DisplayName("중복 listener 등록은 하나로 유지하고 active listener 에게만 이벤트를 전달해야 한다")
    void shouldPreventDuplicateRegistrationAndDispatchOnlyToActiveListeners() throws Exception {
        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder("evt")
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType("METHOD")
                .userId("user-1")
                .sessionId("session-1")
                .clientIp("127.0.0.1")
                .payload(Map.of("action", "ALLOW"))
                .build();

        collector.registerListener(listener);
        collector.registerListener(listener);
        when(objectMapper.readValue(eq("{json}"), eq(ZeroTrustSpringEvent.class))).thenReturn(event);

        collector.consumeZeroTrustEvents("{json}", "security.events.auth", 0, 10L, acknowledgment);

        assertThat(collector.getStatistics()).containsEntry("listener_count", 1);
        var inOrder = inOrder(listener, acknowledgment);
        inOrder.verify(listener).onSecurityEvent(any());
        inOrder.verify(acknowledgment).acknowledge();
    }

    @Test
    @DisplayName("shutdown 이후에는 consume 를 거부하고 ack 하지 않아야 한다")
    void shouldRejectConsumeWhenCollectorStopped() throws Exception {
        collector.shutdown();

        collector.consumeZeroTrustEvents("{json}", "security.events.auth", 0, 11L, acknowledgment);

        verify(objectMapper, never()).readValue(any(String.class), eq(ZeroTrustSpringEvent.class));
        verify(acknowledgment, never()).acknowledge();
    }

    @Test
    @DisplayName("리스너 실패 시 DLQ 전송은 비차단으로 시도하고 원본 ack 없이 재전달 경계로 남겨야 한다")
    void shouldRequestDlqAndAvoidAckWhenListenerFails() throws Exception {
        ZeroTrustSpringEvent event = ZeroTrustSpringEvent.builder("evt")
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType("METHOD")
                .userId("user-1")
                .sessionId("session-1")
                .clientIp("127.0.0.1")
                .payload(Map.of("action", "ALLOW"))
                .build();

        collector.registerListener(listener);
        when(objectMapper.readValue(eq("{json}"), eq(ZeroTrustSpringEvent.class))).thenReturn(event);
        doReturn(CompletableFuture.completedFuture(null))
                .when(kafkaTemplate).send(anyString(), any());
        org.mockito.Mockito.doThrow(new IllegalStateException("listener boom"))
                .when(listener).onSecurityEvent(any());

        assertThatThrownBy(() -> collector.consumeZeroTrustEvents("{json}", "security.events.auth", 1, 99L, acknowledgment))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("redelivery scheduled");

        verify(acknowledgment, never()).acknowledge();
        assertThat(collector.getStatistics())
                .containsEntry("redelivery_scheduled_count", 1L)
                .containsEntry("dlq_dispatch_requested_count", 1L)
                .containsEntry("dlq_dispatch_confirmed_count", 1L);
    }
}
