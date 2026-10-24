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
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
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
 * docs/agent A1 G-5, on the running control D (never in a build): the token requests Contexa refuses before deciding
 * them leave no decision of record. A forged token, the token of an agent removed after it was issued (A1-2, its
 * registration is gone), and the internal client's own client credentials token (A1-2) are refused with 401, and D
 * holds no decision for them. Runs only when SHOWCASE_LIVE_D_URL names the running D; its secrets come from the
 * environment the showcase scripts load (showcase.env) and are never printed.
 */
class LiveAgentRefusalsTest {

    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();

    @Test
    void tokensContexaRefusesReachNoDecision() throws Exception {
        String base = System.getenv("SHOWCASE_LIVE_D_URL");
        assumeTrue(base != null && !base.isBlank(), "SHOWCASE_LIVE_D_URL names no running control D");
        Instant at = CompanyCalendar.at(LocalDate.parse(System.getenv().getOrDefault("SHOWCASE_COMPANY_ANCHOR_DATE",
                "2026-09-30")), TimeSlot.AFTERNOON);
        String runHex = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        String runId = "run-" + runHex;
        String username = "v" + runHex + "-" + CompanyBlueprint.ENGINEER_K;
        InternalContextSigner signer = new InternalContextSigner(System.getenv("SHOWCASE_INTERNAL_SIGNING_KEY"));
        WorkloadClient admin = new WorkloadClient(URI.create(base), signer, new WorkloadClient.RunIdentity(runId,
                "org-" + runHex, "tenant-" + runHex, "10.40.12.90", "LiveAgentRefusals/1.0"), Duration.ofSeconds(60));
        WorkloadClient agentClient = admin.freshSession(new WorkloadClient.RunIdentity(runId, "org-" + runHex,
                "tenant-" + runHex, "10.60.1.30", "report-agent/1.0"));
        Map<String, Object> principal = new LinkedHashMap<>();
        principal.put("username", username);
        principal.put("password", "Live-" + UUID.randomUUID() + "-Aa1");
        principal.put("employeeKey", CompanyBlueprint.ENGINEER_K);
        principal.put("roleKey", CompanyBlueprint.ROLE_ENGINEER);
        principal.put("displayName", "Live refusal check");
        principal.put("department", "Agent live check");
        principal.put("organizationId", "org-" + runHex);
        principal.put("tenantId", "tenant-" + runHex);
        principal.put("template", null);
        Response created = admin.postJson("/internal/runs/" + runId + "/principals", null, null,
                JSON.writeValueAsString(principal));
        assertThat(created.status()).as(created.text()).isEqualTo(200);
        String agentId = "agt-" + runHex + "-live";
        String clientId = agentId + "-client";
        String secret = "Agt-" + UUID.randomUUID().toString().replace("-", "");
        Map<String, Object> agent = new LinkedHashMap<>();
        agent.put("agentId", agentId);
        agent.put("displayName", "Live refusal agent");
        agent.put("sponsor", username);
        agent.put("clientId", clientId);
        agent.put("clientSecret", secret);
        agent.put("scopes", List.of("sc.engineer"));
        try {
            Response registered = admin.postJson("/internal/runs/" + runId + "/agents", null, null,
                    JSON.writeValueAsString(agent));
            assertThat(registered.status()).as(registered.text()).isEqualTo(200);
            String document = document();
            String issuedBeforeRemoval = token(agentClient, at, clientId, secret);

            String forged = UUID.randomUUID().toString();
            Response forgedRead = agentClient.withBearer("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln")
                    .get("/api/documents/" + document, forged, at);
            assertThat(forgedRead.status()).as(forgedRead.text()).isEqualTo(401);
            assertNoDecision(admin, forged);

            Response removed = admin.delete("/internal/runs/" + runId + "/agents/" + agentId + "?clientId=" + clientId,
                    null);
            assertThat(removed.status()).as(removed.text()).isEqualTo(200);
            String afterRemoval = UUID.randomUUID().toString();
            Response removedRead = agentClient.withBearer(issuedBeforeRemoval)
                    .get("/api/documents/" + document, afterRemoval, at);
            assertThat(removedRead.status()).as(removedRead.text()).isEqualTo(401);
            assertNoDecision(admin, afterRemoval);
            System.out.println("LIVE forged=" + forgedRead.status() + " removedAgent=" + removedRead.status()
                    + " requestIds=" + forged + "," + afterRemoval);
        } finally {
            admin.delete("/internal/runs/" + runId + "/agents/" + agentId + "?clientId=" + clientId, null);
            admin.delete("/internal/runs/" + runId + "/principals/" + username, null);
        }
    }

    /** A1-2: the internal client may hold a client credentials token, which no API takes. */
    @Test
    void theInternalClientsOwnTokenReachesNoDecision() throws Exception {
        String base = System.getenv("SHOWCASE_LIVE_D_URL");
        assumeTrue(base != null && !base.isBlank(), "SHOWCASE_LIVE_D_URL names no running control D");
        Instant at = CompanyCalendar.at(LocalDate.parse(System.getenv().getOrDefault("SHOWCASE_COMPANY_ANCHOR_DATE",
                "2026-09-30")), TimeSlot.AFTERNOON);
        String runHex = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        WorkloadClient client = new WorkloadClient(URI.create(base),
                new InternalContextSigner(System.getenv("SHOWCASE_INTERNAL_SIGNING_KEY")),
                new WorkloadClient.RunIdentity("run-" + runHex, "org-" + runHex, "tenant-" + runHex, "10.60.1.31",
                        "internal-client-check/1.0"), Duration.ofSeconds(60));

        String internalToken = token(client, at, "default-client", System.getenv("SHOWCASE_OAUTH2_CLIENT_SECRET"));
        String internal = UUID.randomUUID().toString();
        Response internalRead = client.withBearer(internalToken).get("/api/documents/" + document(), internal, at);

        assertThat(internalRead.status()).as(internalRead.text()).isEqualTo(401);
        assertNoDecision(client, internal);
        System.out.println("LIVE internalClient=" + internalRead.status() + " requestId=" + internal);
    }

    private static String token(WorkloadClient client, Instant at, String clientId, String secret) throws IOException {
        String basic = Base64.getEncoder().encodeToString((URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + ":" + URLEncoder.encode(secret, StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8));
        Response token = client.postForm("/oauth2/token", UUID.randomUUID().toString(), at,
                Map.of("grant_type", "client_credentials"), Map.of("Authorization", "Basic " + basic));
        assertThat(token.status()).as(clientId + " " + token.text()).isEqualTo(200);
        return JSON.readTree(token.body()).path("access_token").asText();
    }

    private static void assertNoDecision(WorkloadClient admin, String requestId) throws IOException {
        Response decision = admin.get("/internal/decisions/" + requestId, null, null);
        assertThat(decision.status()).as(decision.text()).isEqualTo(200);
        JsonNode evidence = JSON.readTree(decision.body());
        assertThat(evidence.path("records").size()).as(decision.text()).isZero();
        assertThat(evidence.path("events").size()).as(decision.text()).isZero();
        assertThat(evidence.path("modelCalls").size()).as(decision.text()).isZero();
    }

    private static String document() throws Exception {
        String url = System.getenv().getOrDefault("SHOWCASE_WORK_DB_URL",
                "jdbc:postgresql://127.0.0.1:46432/showcase_work4");
        try (Connection connection = DriverManager.getConnection(url, System.getenv("SHOWCASE_DB_USER"),
                System.getenv("SHOWCASE_DB_PASSWORD"));
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery(
                     "select min(document_key) from document where project_key = 'HX-310'")) {
            rows.next();
            return rows.getString(1);
        }
    }
}
