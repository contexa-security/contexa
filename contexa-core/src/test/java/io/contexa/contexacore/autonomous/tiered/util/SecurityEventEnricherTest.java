package io.contexa.contexacore.autonomous.tiered.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SecurityEventEnricherTest {

    // --- extractOSFromUserAgent tests ---

    @Test
    @DisplayName("extractOSFromUserAgent should detect Android")
    void shouldDetectAndroid() {
        String ua = "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36";
        assertThat(SecurityEventEnricher.extractOSFromUserAgent(ua)).isEqualTo("Android");
    }

    @Test
    @DisplayName("extractOSFromUserAgent should detect iOS from iPhone")
    void shouldDetectIos() {
        String ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148";
        assertThat(SecurityEventEnricher.extractOSFromUserAgent(ua)).isEqualTo("iOS");
    }

    @Test
    @DisplayName("extractOSFromUserAgent should detect Windows")
    void shouldDetectWindows() {
        String ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36";
        assertThat(SecurityEventEnricher.extractOSFromUserAgent(ua)).isEqualTo("Windows");
    }

    @Test
    @DisplayName("extractOSFromUserAgent should detect Mac")
    void shouldDetectMac() {
        String ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36";
        assertThat(SecurityEventEnricher.extractOSFromUserAgent(ua)).isEqualTo("Mac");
    }

    @Test
    @DisplayName("extractOSFromUserAgent should detect ChromeOS")
    void shouldDetectChromeOS() {
        String ua = "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36";
        assertThat(SecurityEventEnricher.extractOSFromUserAgent(ua)).isEqualTo("ChromeOS");
    }

    @Test
    @DisplayName("extractOSFromUserAgent should detect Linux")
    void shouldDetectLinux() {
        String ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36";
        assertThat(SecurityEventEnricher.extractOSFromUserAgent(ua)).isEqualTo("Linux");
    }

    @Test
    @DisplayName("extractOSFromUserAgent should return Desktop for unrecognized UA")
    void shouldReturnDesktopForUnrecognizedUA() {
        String ua = "CustomAgent/1.0";
        assertThat(SecurityEventEnricher.extractOSFromUserAgent(ua)).isEqualTo("Desktop");
    }

    // --- extractBrowserSignature tests ---

    @Test
    @DisplayName("extractBrowserSignature should detect Chrome")
    void shouldDetectChrome() {
        String ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        String result = SecurityEventEnricher.extractBrowserSignature(ua);
        assertThat(result).isNotNull();
        assertThat(result).startsWith("Chrome/");
    }

    @Test
    @DisplayName("extractBrowserSignature should detect Edge")
    void shouldDetectEdge() {
        String ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.91";
        String result = SecurityEventEnricher.extractBrowserSignature(ua);
        assertThat(result).isNotNull();
        assertThat(result).startsWith("Edge/");
    }

    @Test
    @DisplayName("extractBrowserSignature should detect Firefox")
    void shouldDetectFirefox() {
        String ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0";
        String result = SecurityEventEnricher.extractBrowserSignature(ua);
        assertThat(result).isNotNull();
        assertThat(result).startsWith("Firefox/");
    }

    @Test
    @DisplayName("extractBrowserSignature should detect Safari")
    void shouldDetectSafari() {
        String ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15";
        String result = SecurityEventEnricher.extractBrowserSignature(ua);
        assertThat(result).isNotNull();
        assertThat(result).startsWith("Safari/");
    }

    // --- URL decoding tests ---

    @Test
    @DisplayName("SecurityEventEnricher should handle URL-encoded strings via getDecodedPayload")
    void shouldDecodeUrlEncodedStrings() {
        // given
        SecurityEventEnricher enricher = new SecurityEventEnricher();
        io.contexa.contexacore.autonomous.domain.SecurityEvent event = io.contexa.contexacore.autonomous.domain.SecurityEvent.builder()
                .build();
        event.addMetadata("requestPayload", "hello%20world%21");

        // when
        var decoded = enricher.getDecodedPayload(event);

        // then
        assertThat(decoded).isPresent();
        assertThat(decoded.get()).isEqualTo("hello world!");
    }

    // --- Base64 detection and decoding tests ---

    @Test
    @DisplayName("SecurityEventEnricher should detect and decode Base64 with printable content")
    void shouldDetectAndDecodeBase64() {
        // given
        SecurityEventEnricher enricher = new SecurityEventEnricher();
        // "Hello World!" in Base64
        String base64Value = "SGVsbG8gV29ybGQh";
        io.contexa.contexacore.autonomous.domain.SecurityEvent event = io.contexa.contexacore.autonomous.domain.SecurityEvent.builder()
                .build();
        event.addMetadata("requestPayload", base64Value);

        // when
        var decoded = enricher.getDecodedPayload(event);

        // then
        assertThat(decoded).isPresent();
        assertThat(decoded.get()).isEqualTo("Hello World!");
    }

    // --- Null input handling ---

    @Test
    @DisplayName("extractOSFromUserAgent should return null for null input")
    void shouldReturnNullForNullUserAgent() {
        assertThat(SecurityEventEnricher.extractOSFromUserAgent(null)).isNull();
    }

    @Test
    @DisplayName("extractOSFromUserAgent should return null for empty input")
    void shouldReturnNullForEmptyUserAgent() {
        assertThat(SecurityEventEnricher.extractOSFromUserAgent("")).isNull();
    }

    @Test
    @DisplayName("extractBrowserSignature should return null for null input")
    void shouldReturnNullBrowserForNullInput() {
        assertThat(SecurityEventEnricher.extractBrowserSignature(null)).isNull();
    }

    @Test
    @DisplayName("extractBrowserSignature should return null for empty input")
    void shouldReturnNullBrowserForEmptyInput() {
        assertThat(SecurityEventEnricher.extractBrowserSignature("")).isNull();
    }

    @Test
    @DisplayName("getDecodedPayload should return empty for event without payload")
    void shouldReturnEmptyForNoPayload() {
        // given
        SecurityEventEnricher enricher = new SecurityEventEnricher();
        io.contexa.contexacore.autonomous.domain.SecurityEvent event = io.contexa.contexacore.autonomous.domain.SecurityEvent.builder()
                .build();

        // when
        var result = enricher.getDecodedPayload(event);

        // then
        assertThat(result).isEmpty();
    }
}
