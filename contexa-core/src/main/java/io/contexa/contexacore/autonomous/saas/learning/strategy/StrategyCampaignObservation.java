package io.contexa.contexacore.autonomous.saas.learning.strategy;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Campaign observation input used by strategy learning.
 */
public record StrategyCampaignObservation(
        String correlationId,
        String signalKey,
        String canonicalThreatClass,
        String geoCountry,
        List<String> facts,
        LocalDateTime observedAt) {

    public StrategyCampaignObservation {
        facts = facts == null ? List.of() : List.copyOf(facts);
    }
}
