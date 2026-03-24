package io.contexa.contexacore.std.security;

import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class MemoryQuarantineServiceTest {

    private final MemoryQuarantineService service = new MemoryQuarantineService(new MemoryReadPolicy());

    @Test
    void evaluateQuarantinesPoisonedKnowledge() {
        MemoryQuarantineService.MemoryQuarantineDecision decision = service.evaluate(new Document(
                "memory",
                Map.of(
                        "documentType", "memory_ltm",
                        "promotionState", "PROMOTED",
                        "knowledgePoisoned", true)));

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.decision()).isEqualTo("DENIED_POISONED_KNOWLEDGE");
        assertThat(decision.quarantineState()).isEqualTo("QUARANTINED");
        assertThat(decision.poisoned()).isTrue();
    }

    @Test
    void evaluateAllowsRuntimeSafeMemory() {
        MemoryQuarantineService.MemoryQuarantineDecision decision = service.evaluate(new Document(
                "memory",
                Map.of(
                        "documentType", "memory_ltm",
                        "runtimeSafe", true)));

        assertThat(decision.allowed()).isTrue();
        assertThat(decision.quarantineState()).isEqualTo("ACTIVE");
    }
}
