package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.business.client.WorkloadClient;
import io.contexa.showcase.business.client.WorkloadClient.Response;
import io.contexa.showcase.business.company.CompanyBlueprint;
import io.contexa.showcase.business.work.RbacPolicy;
import io.contexa.showcase.portal.orchestrator.ControlEndpoints.Control;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * The agent of a run in control D (docs/agent A7-0), the way an application's agent works with Contexa: its OAuth2
 * client and registration, and the three ways it sends a request.
 * <ul>
 *     <li>For the person: the person signs in to the agent workspace (D's agents' flow, with the person's one-time
 *     code) and the agent exchanges the person's token, presenting its own token as the actor token (RFC 8693).</li>
 *     <li>On its own: with its own client credentials token.</li>
 *     <li>With its own account in the people's session flow.</li>
 * </ul>
 */
final class RunAgent {

    /** The sign-in of D's agents' flow, under its URL prefix. */
    static final String WORKSPACE_LOGIN = "/agent/api/mfa/login";
    static final String WORKSPACE_CODE_REQUEST = "/agent/mfa/ott/generate-code";
    static final String WORKSPACE_CODE_VERIFY = "/agent/login/mfa-ott";
    static final String TOKEN_ENDPOINT = "/oauth2/token";
    static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

    /** The engine group of a company role (control D's RBAC seed names its groups so). */
    static final String ENGINE_GROUP_PREFIX = "SC_";

    private final String agentId;
    private final String clientId;
    private final boolean account;
    private final String scope;
    private final ScenarioDefinition.Agent definition;
    private String clientSecret;
    private String accountPassword;

    RunAgent(String runHex, ScenarioDefinition.Agent definition, boolean account) {
        this.definition = definition;
        this.agentId = agentId(runHex, definition.name());
        this.clientId = agentId + "-client";
        this.account = account;
        this.scope = RbacPolicy.agentScope(definition.roleKey());
    }

    /** The run's agent: named after the run and the case's agent name, so runs never share an agent. */
    static String agentId(String runHex, String name) {
        return "agt-" + runHex + "-" + name;
    }

    String agentId() {
        return agentId;
    }

    String clientId() {
        return clientId;
    }

    ScenarioDefinition.Agent definition() {
        return definition;
    }

    /**
     * docs/agent OC-3: the registration control D's administrator makes through the engine's agent registration API:
     * the client (its own token and token exchange), the registry entry with the person accountable and, for a session
     * agent, an account in the engine group of its role.
     */
    Map<String, Object> registration(String sponsor) {
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("agentId", agentId);
        request.put("displayName", definition.title() != null ? definition.title().getOrDefault("en", agentId)
                : agentId);
        request.put("agentType", "SHOWCASE_RUN_AGENT");
        request.put("sponsorId", sponsor);
        request.put("clientId", clientId);
        request.put("scopes", List.of(scope));
        request.put("ownToken", true);
        request.put("actsForPeople", true);
        request.put("tokenLifetimeMinutes", 30);
        request.put("account", account);
        request.put("accountGroups", account ? List.of(ENGINE_GROUP_PREFIX + definition.roleKey()) : List.of());
        return request;
    }

    /** docs/agent OC-3: the secrets the registration API gave once. */
    void credentials(JsonNode registered) {
        this.clientSecret = registered.path("clientSecret").asText(null);
        this.accountPassword = registered.path("accountPassword").asText(null);
        if (clientSecret == null || clientSecret.isBlank()) {
            throw new IllegalStateException("The agent registration API gave no client secret for " + agentId);
        }
        if (account && (accountPassword == null || accountPassword.isBlank())) {
            throw new IllegalStateException("The agent registration API gave no account password for " + agentId);
        }
    }

    /** The agent acting for the person: a token exchanged from the person's workspace token. */
    ControlSession delegated(WorkloadClient personClient, WorkloadClient agentClient, String username,
                             String password, Instant at, WorkloadAdmin admin, ObjectMapper json) throws IOException {
        String personToken = workspaceToken(personClient, username, password, at, admin, json);
        String actorToken = clientToken(agentClient, at, json);
        Response exchanged = agentClient.postForm(TOKEN_ENDPOINT, UUID.randomUUID().toString(), at, Map.of(
                "grant_type", TOKEN_EXCHANGE,
                "subject_token", personToken,
                "subject_token_type", ACCESS_TOKEN_TYPE,
                "actor_token", actorToken,
                "actor_token_type", ACCESS_TOKEN_TYPE,
                "scope", scope), basic());
        return new ControlSession(Control.D, agentClient.withBearer(accessToken(exchanged, "token exchange", json)),
                json);
    }

    /** The agent acting on its own: its client credentials token. */
    ControlSession autonomous(WorkloadClient agentClient, Instant at, ObjectMapper json) throws IOException {
        return new ControlSession(Control.D, agentClient.withBearer(clientToken(agentClient, at, json)), json);
    }

    /** The agent with its own account in the people's session flow. */
    ControlSession session(WorkloadClient agentClient, Instant at, WorkloadAdmin admin, ObjectMapper json)
            throws IOException {
        if (accountPassword == null) {
            throw new IllegalStateException("The agent " + agentId + " has no account");
        }
        ControlSession session = new ControlSession(Control.D, agentClient, json);
        session.signInEngine(agentId, accountPassword, agentId + "@" + CompanyBlueprint.EMAIL_DOMAIN, at, admin);
        return session;
    }

    /** The person's token from the agent workspace sign-in, the person's one-time code included. */
    static String workspaceToken(WorkloadClient personClient, String username, String password, Instant at,
                                 WorkloadAdmin admin, ObjectMapper json) throws IOException {
        Response login = personClient.postJson(WORKSPACE_LOGIN, UUID.randomUUID().toString(), at,
                json.writeValueAsString(Map.of("username", username, "password", password)));
        if (login.status() != 200) {
            throw new IOException("Agent workspace sign-in failed: " + login.status() + " " + login.text());
        }
        JsonNode body = json.readTree(login.body());
        if ("MFA_REQUIRED".equals(body.path("status").asText())) {
            Response generate = personClient.postForm(WORKSPACE_CODE_REQUEST, UUID.randomUUID().toString(), at,
                    Map.of("username", username));
            if (generate.status() != 200 && generate.status() != 302) {
                throw new IOException("Agent workspace code request failed: " + generate.status() + " "
                        + generate.text());
            }
            String code = admin.inboxCode(username + "@" + CompanyBlueprint.EMAIL_DOMAIN)
                    .orElseThrow(() -> new IOException("No one-time code in the demo inbox"));
            Response verify = personClient.postForm(WORKSPACE_CODE_VERIFY, UUID.randomUUID().toString(), at,
                    Map.of("token", code));
            if (verify.status() != 200) {
                throw new IOException("Agent workspace code verification failed: " + verify.status() + " "
                        + verify.text());
            }
            body = json.readTree(verify.body());
        }
        String token = body.path("accessToken").asText(null);
        if (token == null || token.isBlank()) {
            throw new IOException("The agent workspace sign-in returned no access token");
        }
        return token;
    }

    private String clientToken(WorkloadClient agentClient, Instant at, ObjectMapper json) throws IOException {
        Response token = agentClient.postForm(TOKEN_ENDPOINT, UUID.randomUUID().toString(), at,
                Map.of("grant_type", "client_credentials", "scope", scope), basic());
        return accessToken(token, "client credentials", json);
    }

    private Map<String, String> basic() {
        String credentials = clientId + ":" + clientSecret;
        return Map.of("Authorization", "Basic "
                + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8)));
    }

    private static String accessToken(Response response, String grant, ObjectMapper json) throws IOException {
        if (response.status() != 200) {
            throw new IOException("The agent's " + grant + " token request failed: " + response.status() + " "
                    + response.text());
        }
        String token = json.readTree(response.body()).path("access_token").asText(null);
        if (token == null || token.isBlank()) {
            throw new IOException("The agent's " + grant + " token response carries no access token");
        }
        return token;
    }
}
