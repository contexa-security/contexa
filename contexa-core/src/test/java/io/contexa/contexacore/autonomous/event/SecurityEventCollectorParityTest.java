package io.contexa.contexacore.autonomous.event;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.listener.InMemorySecurityEventCollector;
import io.contexa.contexacore.autonomous.event.listener.KafkaSecurityEventCollector;
import io.contexa.contexacore.autonomous.event.publisher.InMemorySecurityEventPublisher;
import io.contexa.contexacore.properties.SecurityKafkaProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.kafka.core.KafkaTemplate;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SecurityEventCollectorParityTest {

    @Test
    @DisplayName("standalone와 distributed 경로는 같은 ZeroTrust 입력에 대해 같은 SecurityEvent shape를 만들어야 한다")
    void shouldProduceEquivalentSecurityEventsAcrossStandaloneAndDistributedPaths() throws Exception {
        ZeroTrustSpringEvent sourceEvent = ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType("METHOD")
                .userId("user-1")
                .sessionId("session-1")
                .clientIp("192.168.1.10")
                .userAgent("Mozilla/5.0")
                .payload(Map.of("action", "ALLOW", "resource", "/admin/api/security-test/sensitive/resource-001"))
                .build();

        AtomicReference<SecurityEvent> standaloneResult = new AtomicReference<>();
        InMemorySecurityEventCollector inMemoryCollector = new InMemorySecurityEventCollector();
        inMemoryCollector.registerListener(new CapturingListener(standaloneResult));
        new InMemorySecurityEventPublisher(inMemoryCollector).publishGenericSecurityEvent(sourceEvent);

        AtomicReference<SecurityEvent> kafkaResult = new AtomicReference<>();
        ObjectMapper objectMapper = mock(ObjectMapper.class);
        KafkaSecurityEventCollector kafkaCollector = new KafkaSecurityEventCollector(
                objectMapper,
                mock(KafkaTemplate.class),
                new SecurityKafkaProperties());
        kafkaCollector.registerListener(new CapturingListener(kafkaResult));
        when(objectMapper.readValue("{json}", ZeroTrustSpringEvent.class)).thenReturn(sourceEvent);
        kafkaCollector.consumeZeroTrustEvents("{json}",
                "security.events.authorization.method", 0, 1L, null);

        assertThat(kafkaResult.get()).isNotNull();
        assertThat(standaloneResult.get()).isNotNull();
        assertEquivalent(standaloneResult.get(), kafkaResult.get());
    }

    private void assertEquivalent(SecurityEvent standalone, SecurityEvent distributed) {
        assertThat(distributed.getUserId()).isEqualTo(standalone.getUserId());
        assertThat(distributed.getSessionId()).isEqualTo(standalone.getSessionId());
        assertThat(distributed.getSourceIp()).isEqualTo(standalone.getSourceIp());
        assertThat(distributed.getUserAgent()).isEqualTo(standalone.getUserAgent());
        assertThat(distributed.getSource()).isEqualTo(standalone.getSource());
        assertThat(distributed.getSeverity()).isEqualTo(standalone.getSeverity());
        assertThat(distributed.getDescription()).isEqualTo(standalone.getDescription());
        assertThat(distributed.getMetadata()).containsEntry("action", standalone.getMetadata().get("action"));
        assertThat(distributed.getMetadata()).containsEntry("resource", standalone.getMetadata().get("resource"));
        assertThat(distributed.getMetadata()).containsKey("ingestAt");
        assertThat(standalone.getMetadata()).containsKey("ingestAt");
        assertThat(distributed.getMetadata()).containsEntry("zerotrust.category", "AUTHORIZATION");
        assertThat(distributed.getMetadata()).containsEntry("zerotrust.eventType", "METHOD");
    }

    private static final class CapturingListener implements SecurityEventListener {
        private final AtomicReference<SecurityEvent> sink;

        private CapturingListener(AtomicReference<SecurityEvent> sink) {
            this.sink = sink;
        }

        @Override
        public void onSecurityEvent(SecurityEvent event) {
            sink.set(event);
        }

        @Override
        public String getListenerName() {
            return "capturing-listener";
        }
    }
}
