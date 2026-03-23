package io.contexa.contexacore.autonomous.saas.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.LocalDateTime;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record ThreatIntelligenceSnapshot(
        String tenantId,
        boolean featureEnabled,
        boolean sharingEnabled,
        List<ThreatSignalItem> signals,
        LocalDateTime generatedAt) {

    public ThreatIntelligenceSnapshot {
        signals = signals == null ? List.of() : List.copyOf(signals);
    }

    public static ThreatIntelligenceSnapshot empty() {
        return new ThreatIntelligenceSnapshot(null, false, false, List.of(), null);
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ThreatSignalItem(
            String signalKey,
            String status,
            String canonicalThreatClass,
            String geoCountry,
            List<String> mitreTacticHints,
            List<String> targetSurfaceHints,
            List<String> signalTags,
            int affectedTenantCount,
            int observationCount,
            LocalDateTime firstObservedAt,
            LocalDateTime lastObservedAt,
            LocalDateTime expiresAt,
            String summary) {

        public ThreatSignalItem {
            mitreTacticHints = mitreTacticHints == null ? List.of() : List.copyOf(mitreTacticHints);
            targetSurfaceHints = targetSurfaceHints == null ? List.of() : List.copyOf(targetSurfaceHints);
            signalTags = signalTags == null ? List.of() : List.copyOf(signalTags);
        }
    }
}
