package io.contexa.showcase.portal.spec;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** The specification of a run is built from what control D and the rule controls report, and hashes stably. */
class ExecutionSpecStoreTest {

    private final ObjectMapper json = new ObjectMapper();

    @Test
    void theRunSpecificationComesFromTheReportedConfiguration() throws Exception {
        JsonNode engine = json.readTree("""
                {"engineVersion":"0.1.0","codeCommit":"abc123def456-dirty","effectiveMode":"ENFORCE",
                 "chatModel":"gpt-5-nano","embeddingModel":"text-embedding-3-small","embeddingDimensions":1024,
                 "timeZone":"UTC","endpointProtection":{"POST /api/projects/*/exports":"sync",
                 "GET /api/documents/*":"async"}}""");
        JsonNode rules = json.readTree("{\"sha256\":\"" + "a".repeat(64) + "\"}");

        ExecutionSpec spec = ExecutionSpecStore.build(engine, rules, "tpl-eng-k-1", "b".repeat(64), null);

        assertThat(spec.effectiveMode()).isEqualTo("ENFORCE");
        assertThat(spec.endpointProtection()).containsEntry("POST /api/projects/*/exports", "sync");
        assertThat(spec.ruleVersion()).isEqualTo("a".repeat(64));
        assertThat(spec.codeCommit()).isEqualTo("abc123def456-dirty");
        assertThat(ExecutionSpecHasher.hash(spec))
                .isEqualTo(ExecutionSpecHasher.hash(ExecutionSpecStore.build(engine, rules, "tpl-eng-k-1",
                        "b".repeat(64), null)))
                .isNotEqualTo(ExecutionSpecHasher.hash(ExecutionSpecStore.build(engine, rules, "tpl-eng-k-2",
                        "b".repeat(64), null)));
    }
}
