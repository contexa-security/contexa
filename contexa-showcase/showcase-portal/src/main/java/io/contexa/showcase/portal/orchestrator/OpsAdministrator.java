package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.business.client.WorkloadClient;
import io.contexa.showcase.business.client.WorkloadClient.RunIdentity;
import io.contexa.showcase.business.internal.InternalContextSigner;
import io.contexa.showcase.portal.orchestrator.ControlEndpoints.Control;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * docs/agent OC-5: control D's security administrator for operations outside a run, as an operator signs in to the
 * admin console: the same IT administrator a run's approver plays, signed in to control D with the engine's
 * administrator role, used for replays of sealed decisions through Contexa's admin API, and removed when closed.
 */
public final class OpsAdministrator implements AutoCloseable {

    /** docs/agent B4: the scope control D's AuthZEN evaluation API requires by default. */
    static final String AUTHZEN_SCOPE = "contexa.authzen";

    private final WorkloadAdmin admin;
    private final RunIdentity identity;
    private final RunApprover approver;
    private final ControlEndpoints endpoints;
    private final InternalContextSigner signer;
    private final ObjectMapper json;
    private final Duration timeout;
    private final String hex;

    private OpsAdministrator(WorkloadAdmin admin, RunIdentity identity, RunApprover approver,
                             ControlEndpoints endpoints, InternalContextSigner signer, ObjectMapper json,
                             Duration timeout, String hex) {
        this.admin = admin;
        this.identity = identity;
        this.approver = approver;
        this.endpoints = endpoints;
        this.signer = signer;
        this.json = json;
        this.timeout = timeout;
        this.hex = hex;
    }

    static OpsAdministrator create(WorkloadAdmin admin, ControlEndpoints endpoints, InternalContextSigner signer,
                                   ObjectMapper json, Duration timeout) throws IOException {
        byte[] random = new byte[6];
        new SecureRandom().nextBytes(random);
        String hex = HexFormat.of().formatHex(random);
        String office = admin.employee(RunApprover.EMPLOYEE).path("officeNetwork").asText();
        RunIdentity identity = new RunIdentity("ops-" + hex, "org-ops-" + hex, "tenant-ops-" + hex,
                RunOrchestrator.hostIn(office, 250), "ShowcasePortalOps/1.0");
        RunApprover approver = new RunApprover(admin, identity, hex, Instant.now(), () -> new ControlSession(Control.D,
                new WorkloadClient(endpoints.of(Control.D), signer, identity, timeout), json));
        return new OpsAdministrator(admin, identity, approver, endpoints, signer, json, timeout, hex);
    }

    /** The sealed decision of the request replayed through Contexa's admin API; empty when it was not sealed. */
    public Optional<JsonNode> replay(String requestId, Map<String, Object> request) throws IOException {
        return approver.replaySealed(requestId, request);
    }

    /**
     * docs/agent B4: asks control D's OpenID AuthZEN evaluation API as an enforcement point does. A client registered
     * through Contexa's agent registration API with the scope the API requires takes a client credentials token,
     * reads the metadata and sends each call; the client is removed afterwards.
     *
     * @param calls each with {@code endpoint} ({@code evaluation} or {@code evaluations}), {@code body} and an
     *              optional {@code requestId}
     * @return the metadata answer and each call's status, echoed request identifier and body
     */
    public Map<String, Object> authzenCheck(String basePath, List<Map<String, Object>> calls) throws IOException {
        String pepId = "pep-" + hex;
        String clientId = pepId + "-client";
        Map<String, Object> registration = new LinkedHashMap<>();
        registration.put("agentId", pepId);
        registration.put("displayName", "AuthZEN check enforcement point");
        registration.put("agentType", "SHOWCASE_ENFORCEMENT_POINT");
        registration.put("sponsorId", approver.username());
        registration.put("clientId", clientId);
        registration.put("scopes", List.of(AUTHZEN_SCOPE));
        registration.put("ownToken", true);
        registration.put("actsForPeople", false);
        registration.put("tokenLifetimeMinutes", 10);
        registration.put("account", false);
        registration.put("accountGroups", List.of());
        JsonNode registered = approver.registerAgent(registration);
        try {
            String secret = registered.path("clientSecret").asText(null);
            if (secret == null || secret.isBlank()) {
                throw new IOException("The agent registration API gave no client secret for " + clientId);
            }
            WorkloadClient pep = new WorkloadClient(endpoints.of(Control.D), signer, identity, timeout);
            String basic = Base64.getEncoder().encodeToString((clientId + ":" + secret)
                    .getBytes(StandardCharsets.UTF_8));
            WorkloadClient.Response token = pep.postForm(RunAgent.TOKEN_ENDPOINT, UUID.randomUUID().toString(),
                    Instant.now(), Map.of("grant_type", "client_credentials", "scope", AUTHZEN_SCOPE),
                    Map.of("Authorization", "Basic " + basic));
            if (token.status() != 200) {
                throw new IOException("The enforcement point's token request failed: " + token.status());
            }
            WorkloadClient bearer = pep.withBearer(json.readTree(token.body()).path("access_token").asText());
            Map<String, Object> answers = new LinkedHashMap<>();
            WorkloadClient.Response metadata = bearer.get("/.well-known/authzen-configuration",
                    UUID.randomUUID().toString(), Instant.now());
            answers.put("metadata", answer(metadata, null));
            List<Map<String, Object>> results = new ArrayList<>();
            for (Map<String, Object> call : calls) {
                String endpoint = "evaluations".equals(call.get("endpoint")) ? "evaluations" : "evaluation";
                String requestId = call.get("requestId") != null ? call.get("requestId").toString() : null;
                Map<String, String> headers = requestId != null ? Map.of("X-Request-ID", requestId) : Map.of();
                WorkloadClient.Response response = bearer.postJson(basePath + "/access/v1/" + endpoint,
                        UUID.randomUUID().toString(), Instant.now(), json.writeValueAsString(call.get("body")),
                        headers);
                results.add(answer(response, endpoint));
            }
            answers.put("calls", results);
            return answers;
        } finally {
            approver.removeAgent(pepId);
        }
    }

    private Map<String, Object> answer(WorkloadClient.Response response, String endpoint) {
        Map<String, Object> answer = new LinkedHashMap<>();
        if (endpoint != null) {
            answer.put("endpoint", endpoint);
        }
        answer.put("status", response.status());
        answer.put("requestId", response.header("X-Request-ID").orElse(null));
        String text = response.text();
        try {
            answer.put("body", json.readTree(text));
        } catch (IOException | RuntimeException e) {
            answer.put("body", text);
        }
        return answer;
    }

    /** Removes the administrator when it was created. */
    @Override
    public void close() throws IOException {
        if (approver.created()) {
            admin.deleteEnginePrincipal(identity.runId(), approver.username());
        }
    }
}
