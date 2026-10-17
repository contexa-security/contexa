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

    /**
     * W6-1 (P6-CHANGE-2): the sealed prompt of a decision as control D read it with the OSS prompt parser: its lines,
     * the bundle, the reason codes and the latest inspection; empty when the decision was not sealed.
     */
    public Optional<JsonNode> promptFacts(String requestId) throws IOException {
        Response response = engine("ops").get("/internal/decisions/" + requestId + "/prompt-facts", null, null);
        if (response.status() == 404) {
            return Optional.empty();
        }
        return Optional.of(read(response));
    }

    /**
     * N-SRC-3: control D inspects the decision's sealed package at once, while the run's records are still there;
     * empty while the package is not stored yet.
     */
    public Optional<JsonNode> inspectSealed(String requestId) throws IOException {
        Response response = engine("ops").postJson("/internal/decisions/" + requestId + "/inspection", null, null,
                "{}");
        if (response.status() == 404) {
            return Optional.empty();
        }
        return Optional.of(read(response));
    }

    /** A release transition's answer from control D: the HTTP status and the gate's receipt. */
    public record ReleaseTransition(int status, JsonNode receipt) {
    }

    /**
     * W6-9 (P6): a release transition of the security decision prompt on control D through its OSS release gate; the
     * receipt also when the gate refuses it (422).
     */
    public ReleaseTransition promptReleaseTransition(String promptVersion, String targetReleaseStatus,
                                                     String rationale) throws IOException {
        Response response = engine("ops").postJson("/internal/prompt-releases/transition", null, null,
                json.writeValueAsString(Map.of("promptVersion", promptVersion, "targetReleaseStatus",
                        targetReleaseStatus, "rationale", rationale)));
        if (response.status() == 422) {
            return new ReleaseTransition(422, json.readTree(response.body()));
        }
        return new ReleaseTransition(response.status(), read(response));
    }

    /**
     * W8-3 (P8 rollback rehearsal): a rollback of the security decision prompt's active bundle on control D through
     * its OSS rollback service; the service's result also when it refuses (422).
     */
    public ReleaseTransition promptRollback(String fromVersion, String toVersion, String reason, boolean emergency)
            throws IOException {
        Map<String, Object> request = Map.of("registryScope", "PLATFORM_GLOBAL", "promptKey",
                "cortex.security-decision", "fromVersion", fromVersion, "toVersion", toVersion, "reason", reason,
                "emergency", emergency);
        return answer(engine("ops").postJson("/internal/prompt-releases/rollback", null, null,
                json.writeValueAsString(request)));
    }

    /**
     * W8-3 (W6-8 design): the harness's evaluation of a bundle on control D through the OSS empirical evaluation
     * service, with the bundle hash and the runs it counted.
     */
    public ReleaseTransition promptEvaluation(JsonNode evaluation) throws IOException {
        return answer(engine("ops").postJson("/internal/prompt-releases/evaluation", null, null,
                json.writeValueAsString(evaluation)));
    }

    /** W8-3: the approval of a rollback that waits for one, by the harness's second actor on control D. */
    public ReleaseTransition promptRollbackApproval(String executionKey) throws IOException {
        return answer(engine("ops").postJson("/internal/prompt-releases/rollback/"
                + URLEncoder.encode(executionKey, StandardCharsets.UTF_8) + "/approve", null, null, "{}"));
    }

    private ReleaseTransition answer(Response response) throws IOException {
        if (response.status() == 422) {
            return new ReleaseTransition(422, json.readTree(response.body()));
        }
        return new ReleaseTransition(response.status(), read(response));
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
