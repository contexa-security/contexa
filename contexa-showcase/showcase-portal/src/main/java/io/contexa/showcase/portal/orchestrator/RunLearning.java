package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * What the engine learned during a run (docs/showcase/데모-재설계.md 10.2 R-32): the run principal's engine state read at
 * the run's end through the same public stores a template is read with, next to the template state the run started
 * from. Counts are copied from both snapshots; behaviour documents the template did not have are listed with the
 * fields the engine stored, and the HTTP session identifier is masked. A copied template document gets new IDs under
 * the run's keys but keeps its text, so a document is new when its text (session masked) is not among the template's,
 * counted as a multiset. Nothing is matched to a step: a document carries its own request path and time.
 */
public final class RunLearning {

    static final Pattern SESSION_ID = Pattern.compile("\\b[0-9A-F]{32}\\b");
    static final List<String> DOCUMENT_FIELDS = List.of("timestamp", "httpMethod", "requestPath",
            "action", "proposedAction", "autonomousAction", "riskScore", "confidence", "analysisDepth",
            "technicalFallbackApplied", "resourceSensitivity", "sourceIp", "userAgentBrowser", "userAgentOS");

    private RunLearning() {
    }

    /**
     * @param template the template snapshot the run started from (engine_template.snapshot)
     * @param atEnd    the run principal's snapshot at the run's end
     */
    public static ObjectNode summary(ObjectMapper json, String templateId, JsonNode template, JsonNode atEnd) {
        ObjectNode summary = json.createObjectNode();
        summary.put("templateId", templateId);
        summary.put("templateCapturedAt", text(template.path("capturedAt")));
        summary.put("capturedAt", text(atEnd.path("capturedAt")));
        summary.set("template", counts(json, template));
        summary.set("atRunEnd", counts(json, atEnd));
        Map<String, Integer> known = new HashMap<>();
        template.path("behaviourDocuments").forEach(document -> known.merge(masked(document), 1, Integer::sum));
        ArrayNode added = json.createArrayNode();
        for (JsonNode document : atEnd.path("behaviourDocuments")) {
            String content = masked(document);
            Integer left = known.get(content);
            if (left != null && left > 0) {
                known.put(content, left - 1);
                continue;
            }
            JsonNode metadata = document.path("metadata");
            ObjectNode entry = json.createObjectNode();
            for (String field : DOCUMENT_FIELDS) {
                if (metadata.has(field)) {
                    entry.set(field, metadata.get(field));
                }
            }
            entry.put("content", content);
            added.add(entry);
        }
        summary.set("newBehaviourDocuments", added);
        return summary;
    }

    private static String masked(JsonNode document) {
        return SESSION_ID.matcher(document.path("content").asText("")).replaceAll("<SESSION>");
    }

    private static ObjectNode counts(ObjectMapper json, JsonNode snapshot) {
        ObjectNode counts = json.createObjectNode();
        counts.put("baselineUpdateCount", snapshot.path("baselineUpdateCount").asLong());
        counts.put("workProfileObservations", snapshot.path("workProfileObservations").size());
        counts.put("roleScopeObservations", snapshot.path("roleScopeObservations").size());
        counts.put("permissionChangeObservations", snapshot.path("permissionChangeObservations").size());
        counts.put("behaviourDocuments", snapshot.path("behaviourDocuments").size());
        return counts;
    }

    private static String text(JsonNode node) {
        return node.isMissingNode() || node.isNull() ? null : node.asText();
    }
}
