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
package io.contexa.contexacore.autonomous.utils;

import io.contexa.contexacommon.domain.SecurityEvent;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SessionFingerprintUtilTest {

    @Mock
    private HttpServletRequest request;

    @Test
    @DisplayName("generateFingerprint for SecurityEvent should generate consistent hash")
    void testSecurityEventFingerprint() {
        SecurityEvent event = mock(SecurityEvent.class);
        when(event.getUserAgent()).thenReturn("Mozilla/5.0");
        when(event.getSourceIp()).thenReturn("192.168.0.1");
        when(event.getTimestamp()).thenReturn(LocalDateTime.of(2026, 6, 15, 14, 0));

        String fp1 = SessionFingerprintUtil.generateFingerprint(event);
        String fp2 = SessionFingerprintUtil.generateFingerprint(event);

        assertThat(fp1).isEqualTo(fp2);
        assertThat(fp1).isNotEqualTo("UNKNOWN");
    }

    @Test
    @DisplayName("generateFingerprint for null SecurityEvent returns UNKNOWN")
    void testSecurityEventFingerprintNull() {
        String fp = SessionFingerprintUtil.generateFingerprint((SecurityEvent) null);
        assertThat(fp).isEqualTo("UNKNOWN");
    }

    @Test
    @DisplayName("generateContextBindingHash returns consistent hash for same input")
    void testContextBindingHash() {
        String h1 = SessionFingerprintUtil.generateContextBindingHash("sess-1", "127.0.0.1", "Agent");
        String h2 = SessionFingerprintUtil.generateContextBindingHash("sess-1", "127.0.0.1", "Agent");

        assertThat(h1).isEqualTo(h2);
    }

    @Test
    @DisplayName("generateContextBindingHash returns different hash if IP changes")
    void testContextBindingHashDifferentIp() {
        String h1 = SessionFingerprintUtil.generateContextBindingHash("sess-1", "127.0.0.1", "Agent");
        String h2 = SessionFingerprintUtil.generateContextBindingHash("sess-1", "10.0.0.1", "Agent");

        assertThat(h1).isNotEqualTo(h2);
    }

    @Test
    @DisplayName("generateContextBindingHash for HttpServletRequest caches hash in attributes")
    void testContextBindingHashCaching() {
        when(request.getRequestedSessionId()).thenReturn("session-xyz");
        when(request.getRemoteAddr()).thenReturn("192.168.1.10");
        when(request.getHeader(anyString())).thenAnswer(invocation ->
                "User-Agent".equals(invocation.getArgument(0)) ? "Mozilla/5.0" : null);
        when(request.getAttribute("contexa.contextBindingHash")).thenReturn(null);

        String hash = SessionFingerprintUtil.generateContextBindingHash(request);

        assertThat(hash).isNotNull();
        verify(request).setAttribute("contexa.contextBindingHash", hash);
    }
}
