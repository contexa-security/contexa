package io.contexa.contexacommon.domain;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** QF-55: the copy of an event handed to another thread shares no metadata map with the event. */
class SecurityEventDetachedCopyTest {

    @Test
    void theCopyKeepsTheFieldsAndTheOrderOfTheMetadataInAMapOfItsOwn() {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("requestId", "request-1");
        metadata.put("httpMethod", "GET");
        metadata.put("requestPath", "/api/orders");
        SecurityEvent event = SecurityEvent.builder().eventId("evt-1").userId("alice").sessionId("session-1")
                .sourceIp("10.0.0.1").userAgent("agent").description("request").blocked(true)
                .metadata(Collections.synchronizedMap(metadata)).build();

        SecurityEvent copy = event.detachedCopy();
        copy.addMetadata("learnedBy", "MODEL_ALLOW");
        event.addMetadata("AuditingHandler_executionTime", 2L);

        assertThat(copy).isNotSameAs(event);
        assertThat(copy.getMetadata()).isNotSameAs(event.getMetadata());
        assertThat(copy.getMetadata().keySet()).containsExactly("requestId", "httpMethod", "requestPath", "learnedBy");
        assertThat(event.getMetadata()).doesNotContainKey("learnedBy");
        assertThat(copy.getEventId()).isEqualTo("evt-1");
        assertThat(copy.getUserId()).isEqualTo("alice");
        assertThat(copy.getSessionId()).isEqualTo("session-1");
        assertThat(copy.getSourceIp()).isEqualTo("10.0.0.1");
        assertThat(copy.getUserAgent()).isEqualTo("agent");
        assertThat(copy.getDescription()).isEqualTo("request");
        assertThat(copy.getTimestamp()).isEqualTo(event.getTimestamp());
        assertThat(copy.getSource()).isEqualTo(event.getSource());
        assertThat(copy.getSeverity()).isEqualTo(event.getSeverity());
        assertThat(copy.isBlocked()).isTrue();
    }

    @Test
    void anEventWithoutMetadataGivesACopyWithoutMetadata() {
        SecurityEvent event = SecurityEvent.builder().eventId("evt-2").metadata(null).build();

        assertThat(event.detachedCopy().getMetadata()).isNull();
    }
}
