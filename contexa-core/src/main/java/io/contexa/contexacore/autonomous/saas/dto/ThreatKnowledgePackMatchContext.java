package io.contexa.contexacore.autonomous.saas.dto;

import java.util.List;

public record ThreatKnowledgePackMatchContext(
        boolean applied,
        List<MatchedKnowledgeCase> matchedCases) {

    public ThreatKnowledgePackMatchContext {
        matchedCases = matchedCases == null ? List.of() : List.copyOf(matchedCases);
    }

    public static ThreatKnowledgePackMatchContext empty() {
        return new ThreatKnowledgePackMatchContext(false, List.of());
    }

    public boolean hasMatches() {
        return !matchedCases.isEmpty();
    }

    public record MatchedKnowledgeCase(
            ThreatKnowledgePackSnapshot.KnowledgeCaseItem knowledgeCase,
            List<String> matchedFacts) {

        public MatchedKnowledgeCase {
            matchedFacts = matchedFacts == null ? List.of() : List.copyOf(matchedFacts);
        }
    }
}