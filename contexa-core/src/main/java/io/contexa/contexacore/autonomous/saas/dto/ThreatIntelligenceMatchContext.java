package io.contexa.contexacore.autonomous.saas.dto;

import java.util.List;

public record ThreatIntelligenceMatchContext(
        boolean applied,
        List<MatchedSignal> matchedSignals) {

    public ThreatIntelligenceMatchContext {
        matchedSignals = matchedSignals == null ? List.of() : List.copyOf(matchedSignals);
    }

    public static ThreatIntelligenceMatchContext empty() {
        return new ThreatIntelligenceMatchContext(false, List.of());
    }

    public boolean hasMatches() {
        return !matchedSignals.isEmpty();
    }

    public record MatchedSignal(
            ThreatIntelligenceSnapshot.ThreatSignalItem signal,
            List<String> matchedFacts) {

        public MatchedSignal {
            matchedFacts = matchedFacts == null ? List.of() : List.copyOf(matchedFacts);
        }
    }
}
