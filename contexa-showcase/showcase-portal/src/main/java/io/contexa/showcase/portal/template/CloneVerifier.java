package io.contexa.showcase.portal.template;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.showcase.business.client.WorkloadClient.RunIdentity;
import io.contexa.showcase.portal.orchestrator.WorkloadAdmin;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * P1-BE-06: clones a READY template into fresh run principals and reads each clone back through the same public
 * stores, comparing field by field with the template. Owner and identity fields (user, organization, tenant,
 * document ids) and the wall-clock save time differ by design and are excluded; everything else must be equal.
 */
public class CloneVerifier {

    static final Set<String> OWNER_KEYS = Set.of("userId", "organizationId", "organization_id", "orgId", "tenantId",
            "tenant_id", "id", "artifactId", "eventId");

    private final WorkloadAdmin admin;
    private final TemplateStore templates;
    private final ObjectMapper json;
    private final SecureRandom random = new SecureRandom();

    public CloneVerifier(WorkloadAdmin admin, TemplateStore templates, ObjectMapper json) {
        this.admin = admin;
        this.templates = templates;
        this.json = json;
    }

    public record CloneCheck(int cloneNo, String username, boolean equal, List<String> differences) {
    }

    public List<CloneCheck> verify(String employeeKey, int clones) throws IOException {
        TemplateStore.ReadyTemplate template = templates.latestReady(employeeKey)
                .orElseThrow(() -> new IllegalStateException("No READY template for " + employeeKey));
        JsonNode employee = admin.employee(employeeKey);
        List<CloneCheck> checks = new ArrayList<>();
        for (int clone = 1; clone <= clones; clone++) {
            String hex = HexFormat.of().formatHex(bytes());
            String runId = "chk-run-" + hex;
            String username = "v" + hex + "-" + employeeKey;
            RunIdentity run = new RunIdentity(runId, "org-" + hex, "tenant-" + hex, null, null);
            try {
                admin.registerPlainPrincipal(run, username, "Check-" + UUID.randomUUID() + "-Aa1", employeeKey);
                Map<String, Object> principal = new LinkedHashMap<>();
                principal.put("username", username);
                principal.put("password", "Check-" + UUID.randomUUID() + "-Aa1");
                principal.put("employeeKey", employeeKey);
                principal.put("roleKey", employee.path("roleKey").asText());
                principal.put("displayName", employee.path("displayName").asText());
                principal.put("department", employee.path("department").asText());
                principal.put("organizationId", run.organization());
                principal.put("tenantId", run.tenant());
                principal.put("template", template.snapshot());
                admin.createEnginePrincipal(run, principal);
                JsonNode copy = admin.snapshot(username, employeeKey, run.organization(), run.tenant());
                List<String> differences = differences(template.snapshot(), copy);
                checks.add(new CloneCheck(clone, username, differences.isEmpty(), differences));
            } finally {
                admin.deleteEnginePrincipal(runId, username);
                admin.deletePlainRun(runId);
            }
        }
        return checks;
    }

    List<String> differences(JsonNode template, JsonNode copy) throws IOException {
        List<String> differences = new ArrayList<>();
        compare(differences, "baselineUpdateCount", template.path("baselineUpdateCount"), copy.path("baselineUpdateCount"));
        compare(differences, "userBaseline", baseline(template.path("userBaseline")), baseline(copy.path("userBaseline")));
        compare(differences, "organizationBaseline", baseline(template.path("organizationBaseline")),
                baseline(copy.path("organizationBaseline")));
        compare(differences, "workProfileObservations", template.path("workProfileObservations"),
                copy.path("workProfileObservations"));
        compare(differences, "authorizationState", template.path("authorizationState"), copy.path("authorizationState"));
        compare(differences, "scopeKey", template.path("scopeKey"), copy.path("scopeKey"));
        compare(differences, "roleScopeObservations", template.path("roleScopeObservations"),
                copy.path("roleScopeObservations"));
        compare(differences, "permissionChangeObservations", template.path("permissionChangeObservations"),
                copy.path("permissionChangeObservations"));
        compare(differences, "behaviourDocuments", documents(template.path("behaviourDocuments")),
                documents(copy.path("behaviourDocuments")));
        return differences;
    }

    /** The baseline without its owner and its wall-clock save time. */
    private JsonNode baseline(JsonNode text) throws IOException {
        if (text == null || text.isNull() || text.isMissingNode()) {
            return json.nullNode();
        }
        ObjectNode node = (ObjectNode) json.readTree(text.asText());
        node.remove("userId");
        node.remove("lastUpdated");
        return node;
    }

    /** Memory documents by content and stored embedding, without owner and identity metadata, in content order. */
    private JsonNode documents(JsonNode documents) {
        List<String> normalised = new ArrayList<>();
        for (JsonNode document : documents) {
            ObjectNode metadata = document.path("metadata").deepCopy();
            OWNER_KEYS.forEach(metadata::remove);
            normalised.add(document.path("content").asText() + " " + metadata + " "
                    + document.path("embedding").asText(""));
        }
        normalised.sort(String::compareTo);
        return json.valueToTree(normalised);
    }

    private static void compare(List<String> differences, String field, JsonNode expected, JsonNode actual) {
        if (expected.equals(actual)) {
            return;
        }
        if (expected.isArray() && actual.isArray() && expected.size() == actual.size()) {
            for (int i = 0; i < expected.size(); i++) {
                if (!expected.get(i).equals(actual.get(i))) {
                    String left = expected.get(i).isTextual() ? expected.get(i).asText() : expected.get(i).toString();
                    String right = actual.get(i).isTextual() ? actual.get(i).asText() : actual.get(i).toString();
                    int at = firstDifference(left, right);
                    differences.add(field + "[" + i + "] at " + at + ": template=" + around(left, at) + " clone="
                            + around(right, at));
                    return;
                }
            }
        }
        differences.add(field + ": template=" + abbreviate(expected.toString()) + " clone="
                + abbreviate(actual.toString()));
    }

    private static int firstDifference(String left, String right) {
        int limit = Math.min(left.length(), right.length());
        for (int i = 0; i < limit; i++) {
            if (left.charAt(i) != right.charAt(i)) {
                return i;
            }
        }
        return limit;
    }

    /** The text around a position, so a difference deep inside a long value can be read. */
    private static String around(String text, int at) {
        int from = Math.max(0, at - 120);
        int to = Math.min(text.length(), at + 180);
        return (from > 0 ? "..." : "") + text.substring(from, to) + (to < text.length() ? "..." : "");
    }

    private static String abbreviate(String text) {
        return text.length() <= 300 ? text : text.substring(0, 300) + "...";
    }

    private byte[] bytes() {
        byte[] bytes = new byte[6];
        random.nextBytes(bytes);
        return bytes;
    }
}
