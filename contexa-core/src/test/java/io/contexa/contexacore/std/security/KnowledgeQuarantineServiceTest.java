package io.contexa.contexacore.std.security;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class KnowledgeQuarantineServiceTest {

    private final KnowledgeQuarantineService service = new KnowledgeQuarantineService(new PoisonedKnowledgeIncidentService());

    @Test
    void evaluateBuildsQuarantineIncidentForDeniedPromptContext() {
        ContextProvenanceRecord provenanceRecord = new ContextProvenanceRecord(
                "artifact-1",
                "v1",
                "THREAT_KNOWLEDGE",
                "TENANT",
                true,
                "security_investigation",
                true,
                "source=THREAT_KNOWLEDGE");
        PromptInjectionDefenseService.PromptInjectionDefenseDecision promptDecision =
                new PromptInjectionDefenseService.PromptInjectionDefenseDecision(
                        false,
                        "DENIED_PROMPT_SAFETY",
                        "QUARANTINED",
                        null,
                        List.of("IGNORE_PREVIOUS_INSTRUCTIONS"),
                        "Prompt safety guard quarantined the context.");
        MemoryQuarantineService.MemoryQuarantineDecision memoryDecision =
                new MemoryQuarantineService.MemoryQuarantineDecision(
                        true,
                        "ALLOWED_MEMORY_PROMOTED",
                        "ACTIVE",
                        false,
                        List.of("Memory artifact is runtime safe."));

        KnowledgeQuarantineService.KnowledgeQuarantineDecision decision = service.evaluate(
                provenanceRecord,
                promptDecision,
                memoryDecision);

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.quarantineState()).isEqualTo("QUARANTINED");
        assertThat(decision.incidentSummary()).contains("artifact-1");
        assertThat(decision.incidentFacts()).contains("Prompt safety guard quarantined the context.");
    }
}
