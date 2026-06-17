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
package io.contexa.contexacore.autonomous.event.publisher;

import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustEventCategory;
import io.contexa.contexacore.autonomous.event.domain.ZeroTrustSpringEvent;
import io.contexa.contexacore.autonomous.event.listener.InMemorySecurityEventCollector;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class InMemorySecurityEventPublisherTest {

    @Mock
    private InMemorySecurityEventCollector eventCollector;

    private InMemorySecurityEventPublisher publisher;

    @BeforeEach
    void setUp() {
        publisher = new InMemorySecurityEventPublisher(eventCollector);
    }

    @Test
    @DisplayName("Should convert and dispatch event to collector")
    void shouldConvertAndDispatchEvent() {
        // given
        Map<String, Object> payload = new HashMap<>();
        payload.put("action", "ALLOW");

        ZeroTrustSpringEvent springEvent = ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHENTICATION)
                .eventType("SUCCESS")
                .userId("user1")
                .sessionId("session1")
                .clientIp("192.168.1.1")
                .userAgent("Mozilla/5.0")
                .payload(payload)
                .build();

        // when
        publisher.publishGenericSecurityEvent(springEvent);

        // then
        ArgumentCaptor<SecurityEvent> captor = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(eventCollector).dispatchEvent(captor.capture());

        SecurityEvent captured = captor.getValue();
        assertThat(captured.getUserId()).isEqualTo("user1");
        assertThat(captured.getSessionId()).isEqualTo("session1");
        assertThat(captured.getSourceIp()).isEqualTo("192.168.1.1");
        assertThat(captured.getUserAgent()).isEqualTo("Mozilla/5.0");
        assertThat(captured.getSource()).isEqualTo(SecurityEvent.EventSource.IAM);
        assertThat(captured.getDescription()).isEqualTo("AUTHENTICATION event: SUCCESS");
    }

    @Test
    @DisplayName("BLOCK action should map to CRITICAL severity")
    void shouldMapBlockToCritical() {
        // given
        Map<String, Object> payload = new HashMap<>();
        payload.put("action", "BLOCK");

        ZeroTrustSpringEvent springEvent = ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHENTICATION)
                .eventType("FAILURE")
                .payload(payload)
                .build();

        // when
        publisher.publishGenericSecurityEvent(springEvent);

        // then
        ArgumentCaptor<SecurityEvent> captor = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(eventCollector).dispatchEvent(captor.capture());
        assertThat(captor.getValue().getSeverity()).isEqualTo(SecurityEvent.Severity.CRITICAL);
    }

    @Test
    @DisplayName("ESCALATE action should map to HIGH severity")
    void shouldMapEscalateToHigh() {
        // given
        Map<String, Object> payload = new HashMap<>();
        payload.put("action", "ESCALATE");

        ZeroTrustSpringEvent springEvent = ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.THREAT)
                .eventType("DETECTED")
                .payload(payload)
                .build();

        // when
        publisher.publishGenericSecurityEvent(springEvent);

        // then
        ArgumentCaptor<SecurityEvent> captor = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(eventCollector).dispatchEvent(captor.capture());
        assertThat(captor.getValue().getSeverity()).isEqualTo(SecurityEvent.Severity.HIGH);
    }

    @Test
    @DisplayName("CHALLENGE action should map to MEDIUM severity")
    void shouldMapChallengeToMedium() {
        // given
        Map<String, Object> payload = new HashMap<>();
        payload.put("action", "CHALLENGE");

        ZeroTrustSpringEvent springEvent = ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHENTICATION)
                .eventType("MFA")
                .payload(payload)
                .build();

        // when
        publisher.publishGenericSecurityEvent(springEvent);

        // then
        ArgumentCaptor<SecurityEvent> captor = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(eventCollector).dispatchEvent(captor.capture());
        assertThat(captor.getValue().getSeverity()).isEqualTo(SecurityEvent.Severity.MEDIUM);
    }

    @Test
    @DisplayName("ALLOW action should map to LOW severity")
    void shouldMapAllowToLow() {
        // given
        Map<String, Object> payload = new HashMap<>();
        payload.put("action", "ALLOW");

        ZeroTrustSpringEvent springEvent = ZeroTrustSpringEvent.builder("test")
                .category(ZeroTrustEventCategory.AUTHORIZATION)
                .eventType("METHOD")
                .payload(payload)
                .build();

        // when
        publisher.publishGenericSecurityEvent(springEvent);

        // then
        ArgumentCaptor<SecurityEvent> captor = ArgumentCaptor.forClass(SecurityEvent.class);
        verify(eventCollector).dispatchEvent(captor.capture());
        assertThat(captor.getValue().getSeverity()).isEqualTo(SecurityEvent.Severity.LOW);
    }

    @Test
    @DisplayName("Null event should be silently ignored")
    void shouldIgnoreNullEvent() {
        // when
        publisher.publishGenericSecurityEvent(null);

        // then
        verify(eventCollector, never()).dispatchEvent(any());
    }
}
