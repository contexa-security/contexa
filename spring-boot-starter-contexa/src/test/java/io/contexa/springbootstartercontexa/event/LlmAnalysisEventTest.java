package io.contexa.springbootstartercontexa.event;

import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LlmAnalysisEventTest {

    @Test
    void serializesCanonicalSecurityContextMetadataWithInstantField() {
        CanonicalSecurityContext canonicalContext = CanonicalSecurityContext.builder()
                .collectedAt(Instant.parse("2026-04-09T10:49:03Z"))
                .build();

        LlmAnalysisEvent event = LlmAnalysisEvent.contextCollected(
                "demo-user",
                "/api/test",
                Map.of("sealedEvidence.canonicalContext", canonicalContext));

        String json = event.toJson();

        assertNotEquals("{}", json);
        assertTrue(json.contains("\"type\":\"CONTEXT_COLLECTED\""));
        assertTrue(json.contains("\"sealedEvidence.canonicalContext\""));
        assertTrue(json.contains("\"collectedAt\":\"2026-04-09T10:49:03Z\""));
    }
}