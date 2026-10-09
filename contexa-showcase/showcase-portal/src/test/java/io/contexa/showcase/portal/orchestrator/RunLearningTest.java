package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What the engine learned during a run is copied from two snapshots (docs/showcase/데모-재설계.md R-32): counts as they
 * are, documents the template did not have by their text (a copied document gets new IDs), session identifiers masked.
 */
class RunLearningTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void countsAreCopiedAndOnlyTheDocumentsTheTemplateDidNotHaveAreListed() throws IOException {
        JsonNode template = JSON.readTree("""
                {"capturedAt":"2026-10-06T08:28:25Z","baselineUpdateCount":25,
                 "workProfileObservations":["a","b"],"roleScopeObservations":["r"],"permissionChangeObservations":[],
                 "behaviourDocuments":[{"content":"old","metadata":{"eventId":"e-1"}}]}""");
        JsonNode atEnd = JSON.readTree("""
                {"capturedAt":"2026-10-06T12:21:00Z","baselineUpdateCount":26,
                 "workProfileObservations":["a","b","c"],"roleScopeObservations":["r","r2"],
                 "permissionChangeObservations":[],
                 "behaviourDocuments":[
                   {"content":"old","metadata":{"eventId":"copied-with-a-new-id"},"embedding":"[0.1]"},
                   {"content":"User accessed /api/projects/GB-500/exports/stream session 0123456789ABCDEF0123456789ABCDEF",
                    "metadata":{"eventId":"e-2","requestPath":"/api/projects/GB-500/exports/stream","action":"CHALLENGE",
                                "riskScore":0.65,"sessionId":"0123456789ABCDEF0123456789ABCDEF"},
                    "embedding":"[0.2]"}]}""");

        JsonNode summary = RunLearning.summary(JSON, "tpl-1", template, atEnd);

        assertThat(summary.path("template").path("baselineUpdateCount").asLong()).isEqualTo(25);
        assertThat(summary.path("atRunEnd").path("baselineUpdateCount").asLong()).isEqualTo(26);
        assertThat(summary.path("atRunEnd").path("workProfileObservations").asInt()).isEqualTo(3);
        assertThat(summary.path("atRunEnd").path("roleScopeObservations").asInt()).isEqualTo(2);
        assertThat(summary.path("atRunEnd").path("behaviourDocuments").asInt()).isEqualTo(2);
        JsonNode added = summary.path("newBehaviourDocuments");
        assertThat(added).hasSize(1);
        assertThat(added.get(0).path("requestPath").asText()).isEqualTo("/api/projects/GB-500/exports/stream");
        assertThat(added.get(0).path("action").asText()).isEqualTo("CHALLENGE");
        assertThat(added.get(0).has("sessionId")).as("not a copied field").isFalse();
        assertThat(added.get(0).has("embedding")).isFalse();
        assertThat(added.get(0).path("content").asText()).contains("<SESSION>")
                .doesNotContainPattern("\\b[0-9A-F]{32}\\b");
        assertThat(summary.path("capturedAt").asText()).isEqualTo("2026-10-06T12:21:00Z");
    }
}
