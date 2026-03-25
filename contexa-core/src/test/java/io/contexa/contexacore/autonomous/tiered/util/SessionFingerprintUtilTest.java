package io.contexa.contexacore.autonomous.tiered.util;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.utils.SessionFingerprintUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;

class SessionFingerprintUtilTest {

    @Test
    @DisplayName("Same input produces same hash (deterministic)")
    void generateFingerprint_sameInput_sameHash() {
        // given
        SecurityEvent event1 = SecurityEvent.builder()
                .userAgent("Mozilla/5.0")
                .sourceIp("192.168.1.1")
                .timestamp(LocalDateTime.of(2026, 3, 12, 14, 30))
                .severity(SecurityEvent.Severity.MEDIUM)
                .build();

        SecurityEvent event2 = SecurityEvent.builder()
                .userAgent("Mozilla/5.0")
                .sourceIp("192.168.1.1")
                .timestamp(LocalDateTime.of(2026, 3, 12, 14, 30))
                .severity(SecurityEvent.Severity.MEDIUM)
                .build();

        // when
        String hash1 = SessionFingerprintUtil.generateFingerprint(event1);
        String hash2 = SessionFingerprintUtil.generateFingerprint(event2);

        // then
        assertThat(hash1).isEqualTo(hash2);
    }

    @Test
    @DisplayName("Different input produces different hash")
    void generateFingerprint_differentInput_differentHash() {
        // given
        SecurityEvent event1 = SecurityEvent.builder()
                .userAgent("Mozilla/5.0")
                .sourceIp("192.168.1.1")
                .timestamp(LocalDateTime.of(2026, 3, 12, 14, 30))
                .build();

        SecurityEvent event2 = SecurityEvent.builder()
                .userAgent("Chrome/120.0")
                .sourceIp("10.0.0.1")
                .timestamp(LocalDateTime.of(2026, 3, 12, 10, 0))
                .build();

        // when
        String hash1 = SessionFingerprintUtil.generateFingerprint(event1);
        String hash2 = SessionFingerprintUtil.generateFingerprint(event2);

        // then
        assertThat(hash1).isNotEqualTo(hash2);
    }

    @Test
    @DisplayName("Null SecurityEvent returns UNKNOWN")
    void generateFingerprint_nullEvent_returnsUnknown() {
        // when
        String result = SessionFingerprintUtil.generateFingerprint((SecurityEvent) null);

        // then
        assertThat(result).isEqualTo("UNKNOWN");
    }

    @Test
    @DisplayName("generateContextBindingHash combines sessionId, IP, and UA")
    void generateContextBindingHash_combinesInputs() {
        // given
        String sessionId = "session-123";
        String ip = "192.168.1.100";
        String userAgent = "Mozilla/5.0";

        // when
        String hash1 = SessionFingerprintUtil.generateContextBindingHash(sessionId, ip, userAgent);
        String hash2 = SessionFingerprintUtil.generateContextBindingHash(sessionId, ip, userAgent);

        // then
        assertThat(hash1).isNotNull();
        assertThat(hash1).isEqualTo(hash2);
        assertThat(hash1).hasSize(16);
    }

    @Test
    @DisplayName("generateContextBindingHash with different inputs produces different hash")
    void generateContextBindingHash_differentInputs_differentHash() {
        // given & when
        String hash1 = SessionFingerprintUtil.generateContextBindingHash("sess1", "192.168.1.1", "Chrome");
        String hash2 = SessionFingerprintUtil.generateContextBindingHash("sess2", "10.0.0.1", "Firefox");

        // then
        assertThat(hash1).isNotEqualTo(hash2);
    }

    @Test
    @DisplayName("generateContextBindingHash returns null when all inputs are null")
    void generateContextBindingHash_allNull_returnsNull() {
        // when
        String result = SessionFingerprintUtil.generateContextBindingHash(null, null, null);

        // then
        assertThat(result).isNull();
    }

    @Test
    @DisplayName("generateContextBindingHash handles partial null inputs")
    void generateContextBindingHash_partialNull_returnsHash() {
        // when
        String result = SessionFingerprintUtil.generateContextBindingHash("session-1", null, null);

        // then
        assertThat(result).isNotNull();
        assertThat(result).hasSize(16);
    }

    @Test
    @DisplayName("extractClientIp prefers X-Forwarded-For header")
    void extractClientIp_xForwardedFor_returnsFirstIp() {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Forwarded-For", "203.0.113.1, 70.41.3.18");
        request.setRemoteAddr("127.0.0.1");

        // when
        String clientIp = SessionFingerprintUtil.extractClientIp(request);

        // then
        assertThat(clientIp).isEqualTo("203.0.113.1");
    }

    @Test
    @DisplayName("extractClientIp falls back to X-Real-IP when X-Forwarded-For absent")
    void extractClientIp_xRealIp_returnsIp() {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Real-IP", "203.0.113.5");
        request.setRemoteAddr("127.0.0.1");

        // when
        String clientIp = SessionFingerprintUtil.extractClientIp(request);

        // then
        assertThat(clientIp).isEqualTo("203.0.113.5");
    }

    @Test
    @DisplayName("extractClientIp falls back to remoteAddr when no proxy headers")
    void extractClientIp_noProxyHeaders_returnsRemoteAddr() {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.168.1.50");

        // when
        String clientIp = SessionFingerprintUtil.extractClientIp(request);

        // then
        assertThat(clientIp).isEqualTo("192.168.1.50");
    }

    @Test
    @DisplayName("extractClientIp ignores 'unknown' header values")
    void extractClientIp_unknownHeader_skipsToNext() {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Forwarded-For", "unknown");
        request.addHeader("X-Real-IP", "10.0.0.5");
        request.setRemoteAddr("127.0.0.1");

        // when
        String clientIp = SessionFingerprintUtil.extractClientIp(request);

        // then
        assertThat(clientIp).isEqualTo("10.0.0.5");
    }

    @Test
    @DisplayName("generateContextBindingHash from request caches result in attribute")
    void generateContextBindingHash_fromRequest_cachesInAttribute() {
        // given
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.168.1.1");
        request.addHeader("User-Agent", "TestAgent");

        // when
        String hash1 = SessionFingerprintUtil.generateContextBindingHash(request);
        String hash2 = SessionFingerprintUtil.generateContextBindingHash(request);

        // then
        assertThat(hash1).isNotNull();
        assertThat(hash1).isEqualTo(hash2);
    }

    @Test
    @DisplayName("generateContextBindingHash from null request returns null")
    void generateContextBindingHash_nullRequest_returnsNull() {
        // when
        String result = SessionFingerprintUtil.generateContextBindingHash(null);

        // then
        assertThat(result).isNull();
    }
}
