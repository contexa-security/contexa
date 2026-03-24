package io.contexa.contexacore.std.security;

import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class MemoryReadPolicyTest {

    private final MemoryReadPolicy policy = new MemoryReadPolicy();

    @Test
    void evaluateShouldAllowPromotedMemoryArtifact() {
        MemoryReadDecision decision = policy.evaluate(new Document(
                "Validated long-term memory.",
                Map.of("documentType", "memory_ltm", "promotionState", "PROMOTED")));

        assertThat(decision.allowed()).isTrue();
        assertThat(decision.decision()).isEqualTo("ALLOWED_MEMORY_PROMOTED");
    }

    @Test
    void evaluateShouldDenyUnpromotedMemoryArtifact() {
        MemoryReadDecision decision = policy.evaluate(new Document(
                "Unreviewed long-term memory.",
                Map.of("documentType", "memory_ltm")));

        assertThat(decision.allowed()).isFalse();
        assertThat(decision.decision()).isEqualTo("DENIED_MEMORY_PROMOTION");
    }
}