package io.contexa.contexacore.autonomous.saas.threat;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.security.processor.ProcessingResult;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

class ThreatSignalNormalizationServiceTest {

    private final ThreatSignalNormalizationService service = new ThreatSignalNormalizationService();

    @Test
    void normalizeUsesRawThreatCategoryWhenAvailable() {
        ThreatSignalNormalizationService.NormalizedThreatSignal signal = service.normalize(
                event("/login", Map.of("threatCategory", "ACCOUNT_TAKEOVER", "failedLoginAttempts", 5)),
                result("BLOCK", Map.of("threatCategory", "ACCOUNT_TAKEOVER"), List.of("token_replay")));

        assertThat(signal.rawThreatCategory()).isEqualTo("ACCOUNT_TAKEOVER");
        assertThat(signal.canonicalThreatClass()).isEqualTo("account_takeover");
        assertThat(signal.mitreTacticHints()).contains("Initial Access", "Credential Access");
        assertThat(signal.targetSurfaceCategory()).isEqualTo("authentication");
        assertThat(signal.signalTags()).contains("failed_login_burst", "surface_authentication", "session_takeover_risk");
    }

    @Test
    void normalizeFallsBackToBehaviorPatternsAndRequestPath() {
        ThreatSignalNormalizationService.NormalizedThreatSignal signal = service.normalize(
                event("/signin", Map.of("isImpossibleTravel", true, "isNewDevice", true)),
                result("BLOCK", Map.of("behaviorPatterns", List.of("IMPOSSIBLE_TRAVEL")), List.of("geo_velocity_anomaly")));

        assertThat(signal.rawThreatCategory()).isNull();
        assertThat(signal.canonicalThreatClass()).isEqualTo("impossible_travel");
        assertThat(signal.mitreTacticHints()).contains("Initial Access", "Credential Access");
        assertThat(signal.targetSurfaceCategory()).isEqualTo("authentication");
        assertThat(signal.signalTags()).contains("impossible_travel", "geo_velocity", "new_device");
    }

    private SecurityEvent event(String requestPath, Map<String, Object> additionalMetadata) {
        LinkedHashMap<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("requestPath", requestPath);
        metadata.putAll(additionalMetadata);
        return SecurityEvent.builder()
                .eventId("evt-001")
                .timestamp(LocalDateTime.of(2026, 3, 16, 13, 30))
                .source(SecurityEvent.EventSource.IAM)
                .severity(SecurityEvent.Severity.HIGH)
                .sourceIp("10.10.10.10")
                .metadata(Map.copyOf(metadata))
                .build();
    }

    private ProcessingResult result(String action, Map<String, Object> analysisData, List<String> indicators) {
        return ProcessingResult.builder()
                .success(true)
                .action(action)
                .confidence(0.83)
                .riskScore(0.91)
                .analysisData(analysisData)
                .threatIndicators(indicators)
                .build();
    }
}
