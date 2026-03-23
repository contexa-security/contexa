package io.contexa.contexacore.std.security;

import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class PoisonedKnowledgeIncidentService {

    public KnowledgeIncident buildIncident(
            ContextProvenanceRecord provenanceRecord,
            String quarantineState,
            List<String> facts) {
        String artifactId = provenanceRecord != null && StringUtils.hasText(provenanceRecord.artifactId())
                ? provenanceRecord.artifactId()
                : "unknown-artifact";
        List<String> incidentFacts = new ArrayList<>();
        if (facts != null) {
            incidentFacts.addAll(facts);
        }
        if (provenanceRecord != null && StringUtils.hasText(provenanceRecord.summary())) {
            incidentFacts.add(provenanceRecord.summary());
        }
        String summary = String.format(
                Locale.ROOT,
                "Artifact %s entered %s state during runtime context authorization.",
                artifactId,
                StringUtils.hasText(quarantineState) ? quarantineState : "UNKNOWN");
        return new KnowledgeIncident(artifactId, quarantineState, summary, List.copyOf(incidentFacts));
    }

    public record KnowledgeIncident(
            String artifactId,
            String quarantineState,
            String summary,
            List<String> facts) {

        public KnowledgeIncident {
            facts = facts == null ? List.of() : List.copyOf(facts);
        }
    }
}