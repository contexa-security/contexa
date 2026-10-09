package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.business.client.WorkloadClient;
import io.contexa.showcase.business.client.WorkloadClient.Response;
import io.contexa.showcase.business.client.WorkloadClient.RunIdentity;
import io.contexa.showcase.business.internal.InternalContextSigner;
import io.contexa.showcase.business.run.RunFacts;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Calls of the workload management APIs (docs/showcase/ADR.md ADR-24): the plain workload (instance B) owns the
 * business database and the run's plain accounts; control D owns the engine accounts, templates and decisions.
 */
public class WorkloadAdmin {

    private final ControlEndpoints endpoints;
    private final InternalContextSigner signer;
    private final ObjectMapper json;

    public WorkloadAdmin(ControlEndpoints endpoints, InternalContextSigner signer, ObjectMapper json) {
        this.endpoints = endpoints;
        this.signer = signer;
        this.json = json;
    }

    public JsonNode company() throws IOException {
        return read(plain("ops").get("/internal/company", null, null));
    }

    /** The rule controls' published configuration and hash (execution specification ruleVersion). */
    public JsonNode rules() throws IOException {
        return read(plain("ops").get("/internal/rules", null, null));
    }

    /**
     * The rule classes' decisions of recorded requests under the given settings (H-10); the plain workload evaluates
     * them from the recorded facts and changes nothing.
     */
    public JsonNode evaluateRules(Object evaluation) throws IOException {
        return read(plain("ops").postJson("/internal/rules/evaluate", null, null,
                json.writeValueAsString(evaluation)));
    }

    /** The lab's choices as the business database holds them (docs/showcase/데모-재설계.md 5A.1.1). */
    public JsonNode labOptions(List<String> employees) throws IOException {
        return read(plain("ops").get("/internal/company/lab-options?employees=" + String.join(",", employees), null,
                null));
    }

    /** The lab's choices for the protagonists (docs/showcase/데모-재설계.md 5A.1.2). */
    public JsonNode labOptions() throws IOException {
        return read(plain("ops").get("/internal/company/lab-options", null, null));
    }

    /** The employees whose normal work the business database scripts for the template learning, in key order. */
    public List<String> protagonists() throws IOException {
        List<String> keys = new ArrayList<>();
        read(plain("ops").get("/internal/company/protagonists", null, null)).forEach(key -> keys.add(key.asText()));
        return keys;
    }

    public JsonNode employee(String employeeKey) throws IOException {
        return read(plain("ops").get("/internal/company/employees/" + employeeKey, null, null));
    }

    public String document(String project, String type, int position) throws IOException {
        return read(plain("ops").get("/internal/company/documents/" + project + "/" + type + "/" + position, null,
                null)).path("documentKey").asText();
    }

    public void registerPlainPrincipal(RunIdentity run, String username, String password, String employeeKey)
            throws IOException {
        read(client(endpoints.b(), run).postJson("/internal/runs/" + run.runId() + "/principals", null, null,
                json.writeValueAsString(Map.of("username", username, "password", password, "employeeKey", employeeKey,
                        "organizationId", run.organization(), "tenantId", run.tenant()))));
    }

    public void addFacts(RunIdentity run, RunFacts facts) throws IOException {
        read(client(endpoints.b(), run).postJson("/internal/runs/" + run.runId() + "/facts", null, null,
                json.writeValueAsString(facts)));
    }

    public JsonNode plainEvidence(String runId) throws IOException {
        return read(plain(runId).get("/internal/runs/" + runId + "/evidence", null, null));
    }

    public JsonNode deletePlainRun(String runId) throws IOException {
        return read(plain(runId).delete("/internal/runs/" + runId, null));
    }

    public JsonNode createEnginePrincipal(RunIdentity run, Map<String, Object> request) throws IOException {
        return read(client(endpoints.d(), run).postJson("/internal/runs/" + run.runId() + "/principals", null, null,
                json.writeValueAsString(request)));
    }

    public JsonNode deleteEnginePrincipal(String runId, String username) throws IOException {
        return read(engine(runId).delete("/internal/runs/" + runId + "/principals/" + username, null));
    }

    public JsonNode snapshot(String username, String employeeKey, String organization, String tenant)
            throws IOException {
        return read(engine("ops").postJson("/internal/templates/snapshot", null, null, json.writeValueAsString(
                Map.of("username", username, "employeeKey", employeeKey, "organizationId", organization,
                        "tenantId", tenant))));
    }

    public Optional<String> inboxCode(String recipient) throws IOException {
        Response response = engine("ops").get("/internal/inbox/" + URLEncoder.encode(recipient, StandardCharsets.UTF_8),
                null, null);
        if (response.status() == 404) {
            return Optional.empty();
        }
        return Optional.of(read(response).path("code").asText());
    }

    public JsonNode decision(String requestId) throws IOException {
        return read(engine("ops").get("/internal/decisions/" + requestId, null, null));
    }

    /** Every model call control D kept for a decision: prompt, request options, provider response (W1-2). */
    public JsonNode exchanges(String requestId) throws IOException {
        return read(engine("ops").get("/internal/decisions/" + requestId + "/exchanges", null, null));
    }

    /** The normalised prompt control D saw for a decision, or empty when it no longer holds it. */
    public Optional<String> prompt(String requestId) throws IOException {
        Response response = engine("ops").get("/internal/decisions/" + requestId + "/prompt", null, null);
        if (response.status() == 404) {
            return Optional.empty();
        }
        return Optional.of(read(response).path("prompt").asText());
    }

    public JsonNode escalationProtection(String username) throws IOException {
        return read(engine("ops").get("/internal/users/" + username + "/escalation-protection", null, null));
    }

    public JsonNode embeddings(String username) throws IOException {
        return read(engine("ops").get("/internal/users/" + username + "/embeddings", null, null));
    }

    public JsonNode engine() throws IOException {
        return read(engine("ops").get("/internal/engine", null, null));
    }

    /** Development-only forced decision on control D; fails unless D runs with showcase.dev.forced-actions=true. */
    public void forceAction(String username, String action) throws IOException {
        read(engine("ops").postForm("/internal/dev/actions/" + URLEncoder.encode(username, StandardCharsets.UTF_8)
                + "?action=" + URLEncoder.encode(action, StandardCharsets.UTF_8), null, null, Map.of()));
    }

    private WorkloadClient plain(String runId) {
        return client(endpoints.b(), new RunIdentity(runId, null, null, null, null));
    }

    private WorkloadClient engine(String runId) {
        return client(endpoints.d(), new RunIdentity(runId, null, null, null, null));
    }

    private WorkloadClient client(URI base, RunIdentity run) {
        return new WorkloadClient(base, signer, run, endpoints.requestTimeout());
    }

    private JsonNode read(Response response) throws IOException {
        if (response.status() / 100 != 2) {
            throw new IOException("Management call failed: status=" + response.status() + ", body="
                    + abbreviate(response.text()));
        }
        return response.body().length == 0 ? json.createObjectNode() : json.readTree(response.body());
    }

    static String abbreviate(String text) {
        return text == null || text.length() <= 400 ? text : text.substring(0, 400) + "...";
    }
}
