package io.contexa.showcase.workload.contexa.probe;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.business.client.WorkloadClient;
import io.contexa.showcase.business.client.WorkloadClient.Response;
import io.contexa.showcase.business.company.CompanyBlueprint;
import io.contexa.showcase.business.company.CompanyCalendar;
import io.contexa.showcase.business.company.TimeSlot;
import io.contexa.showcase.business.internal.InternalContextSigner;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * docs/agent A1-12, A7-0 on the running control D (never in a build), with no business request and so no model call:
 * the person signs in to D's agents' flow (password, then the one-time code from the demo inbox) and receives an
 * access token from Contexa's internal client; the run's agent, holding its own client credentials token, exchanges
 * the person's token (RFC 8693). The exchanged token names the person as subject and the agent's client as actor and
 * client. Runs only when SHOWCASE_LIVE_D_URL names the running D; its secrets come from showcase.env, never printed.
 */
class LiveDelegationTokenTest {

    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();
    private static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

    @Test
    void theAgentExchangesThePersonsWorkspaceTokenForATokenActingForThePerson() throws Exception {
        String base = System.getenv("SHOWCASE_LIVE_D_URL");
        assumeTrue(base != null && !base.isBlank(), "SHOWCASE_LIVE_D_URL names no running control D");
        Instant at = CompanyCalendar.at(LocalDate.parse(System.getenv().getOrDefault("SHOWCASE_COMPANY_ANCHOR_DATE",
                "2026-09-30")), TimeSlot.AFTERNOON);
        String runHex = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        String runId = "run-" + runHex;
        String username = "v" + runHex + "-" + CompanyBlueprint.ENGINEER_K;
        String password = "Live-" + UUID.randomUUID() + "-Aa1";
        InternalContextSigner signer = new InternalContextSigner(System.getenv("SHOWCASE_INTERNAL_SIGNING_KEY"));
        WorkloadClient admin = new WorkloadClient(URI.create(base), signer, new WorkloadClient.RunIdentity(runId,
                "org-" + runHex, "tenant-" + runHex, "10.40.12.90", "LiveDelegationToken/1.0"), Duration.ofSeconds(60));
        WorkloadClient person = admin.freshSession(new WorkloadClient.RunIdentity(runId, "org-" + runHex,
                "tenant-" + runHex, "10.40.21.90", CompanyBlueprint.ENGINEER_K_DEVICE));
        WorkloadClient agentClient = admin.freshSession(new WorkloadClient.RunIdentity(runId, "org-" + runHex,
                "tenant-" + runHex, "10.60.1.32", "report-agent/1.0"));
        Map<String, Object> principal = new LinkedHashMap<>();
        principal.put("username", username);
        principal.put("password", password);
        principal.put("employeeKey", CompanyBlueprint.ENGINEER_K);
        principal.put("roleKey", CompanyBlueprint.ROLE_ENGINEER);
        principal.put("displayName", "Live delegation check");
        principal.put("department", "Agent live check");
        principal.put("organizationId", "org-" + runHex);
        principal.put("tenantId", "tenant-" + runHex);
        principal.put("template", null);
        assertThat(admin.postJson("/internal/runs/" + runId + "/principals", null, null,
                JSON.writeValueAsString(principal)).status()).isEqualTo(200);
        String agentId = "agt-" + runHex + "-report";
        String clientId = agentId + "-client";
        String secret = "Agt-" + UUID.randomUUID().toString().replace("-", "");
        Map<String, Object> agent = new LinkedHashMap<>();
        agent.put("agentId", agentId);
        agent.put("displayName", "Live delegation agent");
        agent.put("sponsor", username);
        agent.put("clientId", clientId);
        agent.put("clientSecret", secret);
        agent.put("scopes", List.of("sc.engineer"));
        try {
            Response registered = admin.postJson("/internal/runs/" + runId + "/agents", null, null,
                    JSON.writeValueAsString(agent));
            assertThat(registered.status()).as(registered.text()).isEqualTo(200);

            String personToken = workspaceToken(person, admin, username, password, at);
            Response actor = agentClient.postForm("/oauth2/token", UUID.randomUUID().toString(), at,
                    Map.of("grant_type", "client_credentials", "scope", "sc.engineer"), basic(clientId, secret));
            assertThat(actor.status()).as(actor.text()).isEqualTo(200);
            Response exchanged = agentClient.postForm("/oauth2/token", UUID.randomUUID().toString(), at, Map.of(
                    "grant_type", TOKEN_EXCHANGE,
                    "subject_token", personToken,
                    "subject_token_type", ACCESS_TOKEN_TYPE,
                    "actor_token", JSON.readTree(actor.body()).path("access_token").asText(),
                    "actor_token_type", ACCESS_TOKEN_TYPE,
                    "scope", "sc.engineer"), basic(clientId, secret));
            assertThat(exchanged.status()).as(exchanged.text()).isEqualTo(200);

            JsonNode person0 = claims(personToken);
            JsonNode delegated = claims(JSON.readTree(exchanged.body()).path("access_token").asText());
            assertThat(person0.path("sub").asText()).isEqualTo(username);
            assertThat(delegated.path("sub").asText()).isEqualTo(username);
            assertThat(delegated.path("act").path("sub").asText()).isEqualTo(clientId);
            assertThat(delegated.path("client_id").asText()).isEqualTo(clientId);
            assertThat(delegated.path("scope").toString()).contains("sc.engineer");
            System.out.println("LIVE personSub=" + person0.path("sub").asText() + " delegatedSub="
                    + delegated.path("sub").asText() + " act=" + delegated.path("act") + " client_id="
                    + delegated.path("client_id").asText() + " scope=" + delegated.path("scope"));
        } finally {
            admin.delete("/internal/runs/" + runId + "/agents/" + agentId + "?clientId=" + clientId, null);
            admin.delete("/internal/runs/" + runId + "/principals/" + username, null);
        }
    }

    /** The person's sign-in to D's agents' flow: password, then the one-time code read from D's demo inbox. */
    private static String workspaceToken(WorkloadClient person, WorkloadClient admin, String username, String password,
                                         Instant at) throws IOException {
        Response login = person.postJson("/agent/api/mfa/login", UUID.randomUUID().toString(), at,
                JSON.writeValueAsString(Map.of("username", username, "password", password)));
        assertThat(login.status()).as(login.text()).isEqualTo(200);
        assertThat(JSON.readTree(login.body()).path("status").asText()).as(login.text()).isEqualTo("MFA_REQUIRED");
        Response generate = person.postForm("/agent/mfa/ott/generate-code", UUID.randomUUID().toString(), at,
                Map.of("username", username));
        assertThat(generate.status()).as(generate.text()).isIn(200, 302);
        Response inbox = admin.get("/internal/inbox/" + username + "@" + CompanyBlueprint.EMAIL_DOMAIN, null, null);
        assertThat(inbox.status()).as(inbox.text()).isEqualTo(200);
        Response verify = person.postForm("/agent/login/mfa-ott", UUID.randomUUID().toString(), at,
                Map.of("token", JSON.readTree(inbox.body()).path("code").asText()));
        assertThat(verify.status()).as(verify.text()).isEqualTo(200);
        String token = JSON.readTree(verify.body()).path("accessToken").asText();
        assertThat(token).as(verify.text()).isNotBlank();
        return token;
    }

    private static Map<String, String> basic(String clientId, String secret) {
        return Map.of("Authorization", "Basic " + Base64.getEncoder().encodeToString(
                (URLEncoder.encode(clientId, StandardCharsets.UTF_8) + ":"
                        + URLEncoder.encode(secret, StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8)));
    }

    private static JsonNode claims(String jwt) throws IOException {
        return JSON.readTree(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]));
    }
}
