package io.contexa.contexacore.std.security;

import java.util.ArrayList;
import java.util.List;

public class KnowledgeQuarantineService {

    private final PoisonedKnowledgeIncidentService poisonedKnowledgeIncidentService;

    public KnowledgeQuarantineService(PoisonedKnowledgeIncidentService poisonedKnowledgeIncidentService) {
        this.poisonedKnowledgeIncidentService = poisonedKnowledgeIncidentService != null
                ? poisonedKnowledgeIncidentService
                : new PoisonedKnowledgeIncidentService();
    }

    public KnowledgeQuarantineDecision evaluate(
            ContextProvenanceRecord provenanceRecord,
            PromptInjectionDefenseService.PromptInjectionDefenseDecision promptDecision,
            MemoryQuarantineService.MemoryQuarantineDecision memoryDecision) {
        List<String> facts = new ArrayList<>();
        if (promptDecision != null) {
            facts.add(promptDecision.summary());
            facts.addAll(promptDecision.flags());
        }
        if (memoryDecision != null) {
            facts.addAll(memoryDecision.facts());
        }

        String quarantineState = "ACTIVE";
        boolean allowed = true;
        if (promptDecision != null && !promptDecision.allowed()) {
            quarantineState = "QUARANTINED";
            allowed = false;
        }
        else if (memoryDecision != null && !memoryDecision.allowed()) {
            quarantineState = memoryDecision.quarantineState();
            allowed = false;
        }
        else if (promptDecision != null && "REVIEW_REQUIRED".equals(promptDecision.quarantineState())) {
            quarantineState = "REVIEW_REQUIRED";
        }

        PoisonedKnowledgeIncidentService.KnowledgeIncident incident = poisonedKnowledgeIncidentService.buildIncident(
                provenanceRecord,
                quarantineState,
                facts);
        String decision = allowed ? "ALLOW" : "DENIED_KNOWLEDGE_QUARANTINE";
        return new KnowledgeQuarantineDecision(allowed, decision, quarantineState, incident.summary(), incident.facts());
    }

    public record KnowledgeQuarantineDecision(
            boolean allowed,
            String decision,
            String quarantineState,
            String incidentSummary,
            List<String> incidentFacts) {

        public KnowledgeQuarantineDecision {
            incidentFacts = incidentFacts == null ? List.of() : List.copyOf(incidentFacts);
        }
    }
}