package io.contexa.contexacommon.bridge;

import io.contexa.contexacommon.security.bridge.BridgeObjectExtractor;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class BridgeObjectExtractorTest {

    @Test
    void extractBooleanShouldNotPromoteAuthenticationMethodCollectionsIntoBooleanFacts() {
        Boolean extracted = BridgeObjectExtractor.extractBoolean(
                Map.of("amr", List.of("pwd", "mfa", "webauthn")),
                List.of("amr"));

        assertThat(extracted).isNull();
    }

    @Test
    void extractBooleanShouldParseOnlyExplicitBooleanRepresentations() {
        assertThat(BridgeObjectExtractor.extractBoolean(Map.of("flag", "true"), List.of("flag"))).isTrue();
        assertThat(BridgeObjectExtractor.extractBoolean(Map.of("flag", "no"), List.of("flag"))).isFalse();
        assertThat(BridgeObjectExtractor.extractBoolean(Map.of("flag", List.of("1")), List.of("flag"))).isTrue();
    }
}
