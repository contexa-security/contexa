package io.contexa.showcase.workload.contexa.probe;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.repository.UserRepository;
import io.contexa.contexacore.autonomous.agent.AgentDelegationRequest;
import io.contexa.contexacore.autonomous.agent.DelegationRegistry;
import io.contexa.contexacore.autonomous.company.CompanyRecordSet;
import io.contexa.contexaiam.admin.web.agent.service.AgentProvisioning;
import io.contexa.contexaiam.admin.web.company.service.CompanyRecordsAdminService;
import io.contexa.showcase.business.client.WorkloadClient;
import io.contexa.showcase.business.client.WorkloadClient.Response;
import io.contexa.showcase.business.company.CompanyBlueprint;
import io.contexa.showcase.business.company.CompanyCalendar;
import io.contexa.showcase.business.company.TimeSlot;
import io.contexa.showcase.business.context.CompanyRecordsExport;
import io.contexa.showcase.business.internal.InternalContextSigner;
import io.contexa.showcase.business.run.RunFacts;
import io.contexa.showcase.business.run.RunRegistry;
import io.contexa.showcase.business.work.WorkDatabase;
import io.contexa.showcase.workload.contexa.ContexaWorkloadApplication;
import io.contexa.showcase.workload.contexa.inbox.DemoInboxEmailService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * docs/agent A7-0, control D side: a run's agent registered through D's internal API reaches the engine in each of the
 * three ways an application's agent works with Contexa, through Contexa's own OAuth2 and session flows: with its own
 * client credentials token, with a token exchanged from the person's agent workspace token (RFC 8693, the person's
 * one-time code included), and signed in with its own account in the people's session flow (A1-13). The engine decides
 * each request in place and states the agent to the model, and for the person's agent the run's delegation of record;
 * the agent goes with the run. Skipped without Docker.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(classes = {ContexaWorkloadApplication.class, ProbeEndpoints.class, AnalysisHandOffRecording.class},
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AgentPathsContractTest {

    private static final String SIGNING_KEY = ProbeDatabase.randomKey();
    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();
    private static final Instant AT = CompanyCalendar.at(ProbeDatabase.ANCHOR, TimeSlot.AFTERNOON);
    private static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        ProbeDatabase.register(registry, SIGNING_KEY);
        registry.add("spring.ai.openai.api-key", () -> "probe-key-never-used");
    }

    @LocalServerPort
    int port;

    @Autowired
    DemoInboxEmailService inbox;

    @Autowired
    RunRegistry runs;

    @Autowired
    DelegationRegistry delegations;

    @Autowired
    AgentProvisioning provisioning;

    @Autowired
    CompanyRecordsAdminService companyRecords;

    @Autowired
    WorkDatabase workDatabase;

    @Autowired
    UserRepository users;

    record Run(String runId, String runHex, String username, String password, WorkloadClient admin) {
    }

    record Agent(String agentId, String clientId, String clientSecret, String accountPassword) {

        Map<String, String> basic() {
            return Map.of("Authorization", "Basic " + Base64.getEncoder()
                    .encodeToString((clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8)));
        }
    }

    @Test
    void anAutonomousAgentReachesTheEngineWithItsOwnClientCredentialsToken() throws Exception {
        Run run = create();
        Agent agent = register(run, "solo", false);
        WorkloadClient agentClient = agentClient(run);

        String requestId = UUID.randomUUID().toString();
        Response read = agentClient.withBearer(clientToken(agentClient, agent))
                .get("/api/documents/" + document(), requestId, AT);

        String prompt = decidedInPlace(run, read, requestId);
        // The engine takes the agent's own token as an agent (A1-3). A2-4: the subject is the registered agent, with
        // the client it signed in as, its sponsor and its registration.
        assertThat(line(prompt, "Subject: ")).startsWith("Subject: " + agent.agentId() + " (AGENT_RUNTIME, ")
                .endsWith(", client " + agent.clientId() + ", sponsor " + run.username() + ", registration ACTIVE)");
        // A2-11: the client's own token, its times told against when D read it (the run's company clock is apart).
        assertThat(line(prompt, "Credential: ")).matches(".*Credential: client's own access token, grant"
                + " client_credentials, client " + Pattern.quote(agent.clientId()) + ", issued \\d+ min before this"
                + " request, expires \\d+ (min|h) after this request, not bound to a key");
        // A2-6: the agent acts on its own, so the coverage names no delegated objective missing.
        assertThat(line(prompt, "Coverage: ")).doesNotContain("Delegated objective");
        // A2-12: the company records are its sponsor's, and a line says so.
        assertSponsorsRecords(prompt, run);
        // A1-6, CF-13: the run's agent, registered without a tenant, is the registered agent in the run tenant's
        // request, and its sponsor (the run principal) answers for it.
        JsonNode metadata = decisionMetadata(run, requestId);
        assertThat(metadata.path("agentRegistrationStatus").asText()).as(metadata.toString()).isEqualTo("ACTIVE");
        assertThat(metadata.path("agentAccountableId").asText()).as(metadata.toString()).isEqualTo(run.username());
        remove(run, agent);
    }

    @Test
    void anAgentActingForThePersonReachesTheEngineWithTheTokenExchangedFromTheWorkspaceSignIn() throws Exception {
        Run run = create();
        Agent agent = register(run, "report", false);
        String delegationId = delegate(run, agent);
        WorkloadClient agentClient = agentClient(run);
        WorkloadClient person = run.admin().freshSession(new WorkloadClient.RunIdentity(run.runId(),
                "org-" + run.runHex(), "tenant-" + run.runHex(), "10.40.21.90", CompanyBlueprint.ENGINEER_K_DEVICE));

        String personToken = workspaceToken(person, run);
        Response exchanged = agentClient.postForm("/oauth2/token", UUID.randomUUID().toString(), AT, Map.of(
                "grant_type", TOKEN_EXCHANGE,
                "subject_token", personToken,
                "subject_token_type", ACCESS_TOKEN_TYPE,
                "actor_token", clientToken(agentClient, agent),
                "actor_token_type", ACCESS_TOKEN_TYPE,
                "scope", "sc.engineer"), agent.basic());
        assertThat(exchanged.status()).as(exchanged.text()).isEqualTo(200);
        String requestId = UUID.randomUUID().toString();
        Response read = agentClient.withBearer(JSON.readTree(exchanged.body()).path("access_token").asText())
                .get("/api/documents/" + document(), requestId, AT);

        // The objective's summary is in no token: it reaches the model from the run's delegation of record, as an
        // untrusted text (A2-5); the delegation line states the delegation by its fields (A2-4).
        String prompt = decidedInPlace(run, read, requestId);
        assertThat(line(prompt, "Subject: ")).startsWith("Subject: " + run.username() + " (HUMAN_USER, ")
                .endsWith(", through agent " + agent.agentId() + ", agent sponsor " + run.username()
                        + ", agent registration ACTIVE)");
        assertThat(line(prompt, "Credential: ")).contains("Credential: delegated access token, grant token-exchange,")
                .contains(", actor chain depth 1, not bound to a key");
        assertThat(line(prompt, "Delegation: ")).matches(".*Delegation: agent " + Pattern.quote(agent.agentId())
                + " for " + Pattern.quote(run.username()) + ", chain depth 1, objective REPORTING, allowed DOCUMENT_READ"
                + " on HX-310, expires 3 h after this request, proof [a-z ]+, drift no \\(.+\\)")
                .doesNotContain("Prepare the weekly");
        assertThat(line(prompt, "RecordProvenance: ")).endsWith("RecordProvenance: delegation " + delegationId
                + " recorded by " + run.username() + " (the delegator) 1 h before this request");
        assertThat(prompt).contains("source=delegation objective (host text); \"Prepare the weekly HX-310 drawing"
                + " report\"");
        // A2-6: the delegation the records completed is not named missing.
        assertThat(line(prompt, "Coverage: ")).doesNotContain("Bridge missing context: DELEGATION");
        // A2-12: the exchanged token's subject is the person, whose records are the request's own: no holder line.
        assertThat(prompt).doesNotContain("RecordsHolder: ").contains("Assignment: ");
        remove(run, agent);
    }

    @Test
    void anAgentSignsInWithItsOwnAccountWithoutThePeoplesFactorsAndIsKnownAsTheAgent() throws Exception {
        Run run = create();
        Agent agent = register(run, "desk", true);
        WorkloadClient agentClient = agentClient(run);

        Response login = agentClient.postJson("/api/mfa/login", UUID.randomUUID().toString(), AT,
                JSON.writeValueAsString(Map.of("username", agent.agentId(), "password", agent.accountPassword())));
        assertThat(login.status()).as(login.text()).isEqualTo(200);
        assertThat(JSON.readTree(login.body()).path("status").asText()).as(login.text()).isNotEqualTo("MFA_REQUIRED");
        String requestId = UUID.randomUUID().toString();
        Response read = agentClient.get("/api/documents/" + document(), requestId, AT);

        // A1-13: the approved agent's own account is an agent, not a person.
        String prompt = decidedInPlace(run, read, requestId);
        assertThat(line(prompt, "Subject: ")).startsWith("Subject: " + agent.agentId() + " (AGENT_RUNTIME, ")
                .contains(", the agent's own account, sponsor " + run.username() + ", registration ACTIVE)");
        assertSponsorsRecords(prompt, run);
        remove(run, agent);
        assertThat(users.findByUsername(agent.agentId())).isEmpty();
    }

    @Test
    void aRemovedAgentGetsNoToken() throws Exception {
        Run run = create();
        Agent agent = register(run, "gone", false);
        WorkloadClient agentClient = agentClient(run);
        clientToken(agentClient, agent);

        remove(run, agent);

        Response refused = agentClient.postForm("/oauth2/token", UUID.randomUUID().toString(), AT,
                Map.of("grant_type", "client_credentials", "scope", "sc.engineer"), agent.basic());
        assertThat(refused.status()).as(refused.text()).isEqualTo(401);
    }

    private Run create() throws Exception {
        String runHex = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        String runId = "run-" + runHex;
        String username = "v" + runHex + "-" + CompanyBlueprint.ENGINEER_K;
        String password = "Agent-" + UUID.randomUUID() + "-Aa1";
        WorkloadClient admin = new WorkloadClient(URI.create("http://127.0.0.1:" + port + "/"),
                new InternalContextSigner(SIGNING_KEY), new WorkloadClient.RunIdentity(runId, "org-" + runHex,
                "tenant-" + runHex, "10.40.12.90", "AgentPathsContract/1.0"), Duration.ofSeconds(30));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("username", username);
        body.put("password", password);
        body.put("employeeKey", CompanyBlueprint.ENGINEER_K);
        body.put("roleKey", CompanyBlueprint.ROLE_ENGINEER);
        body.put("displayName", "Agent contract " + CompanyBlueprint.ENGINEER_K);
        body.put("department", "Agent contract test");
        body.put("organizationId", "org-" + runHex);
        body.put("tenantId", "tenant-" + runHex);
        body.put("template", null);
        Response created = admin.postJson("/internal/runs/" + runId + "/principals", null, null,
                JSON.writeValueAsString(body));
        assertThat(created.status()).as(created.text()).isEqualTo(200);
        // docs/agent OC-2: the company's integration puts the employee's records into Contexa, as the portal does for
        // every run; Contexa judges the person's and their agents' requests with them.
        companyRecords.put("probe", null, JSON.convertValue(new CompanyRecordsExport(workDatabase)
                .export(username, CompanyBlueprint.ENGINEER_K, runId), CompanyRecordSet.class));
        return new Run(runId, runHex, username, password, admin);
    }

    /**
     * docs/agent OC-3: the agent registered through Contexa's agent registration, as an application's administrator
     * registers it: the client, the registry entry with the person accountable and, for a session agent, its account.
     */
    private Agent register(Run run, String name, boolean account) {
        String agentId = "agt-" + run.runHex() + "-" + name;
        AgentProvisioning.Credentials credentials = asAdministrator(() -> provisioning.register(
                new AgentProvisioning.Registration(null, agentId, "Agent " + name, "SHOWCASE_RUN_AGENT",
                        run.username(), agentId + "-client", List.of("sc.engineer"), true, true, null, account,
                        account ? List.of("SC_" + CompanyBlueprint.ROLE_ENGINEER) : List.of()), "probe"));
        return new Agent(agentId, credentials.clientId(), credentials.clientSecret(), credentials.accountPassword());
    }

    /** The registration API and the console act for a signed-in administrator; the probe acts as one. */
    private static <T> T asAdministrator(Supplier<T> action) {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("probe", null,
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))));
        try {
            return action.get();
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    /**
     * docs/agent OC-1: the delegation the person gave the agent, kept by Contexa as an integration imports it from the
     * company's records (who wrote it and when, the period in the company's time); its identifier.
     */
    private String delegate(Run run, Agent agent) {
        return delegations.record(new AgentDelegationRequest("tenant-" + run.runHex(), run.username(),
                agent.agentId(), "DLG-" + run.runHex() + "-1", "REPORTING", "Prepare the weekly HX-310 drawing report",
                List.of("DOCUMENT_READ"), List.of("HX-310"), false, null, null, AT.minus(Duration.ofHours(1)),
                AT.plus(Duration.ofHours(3)), run.username(), AT.minus(Duration.ofHours(1)))).delegationId();
    }

    /** docs/agent OC-3: the agent, its client, its tokens and its account are removed through Contexa. */
    private void remove(Run run, Agent agent) {
        asAdministrator(() -> provisioning.remove(null, agent.agentId(), "probe"));
    }

    private WorkloadClient agentClient(Run run) {
        return new WorkloadClient(URI.create("http://127.0.0.1:" + port + "/"), new InternalContextSigner(SIGNING_KEY),
                new WorkloadClient.RunIdentity(run.runId(), "org-" + run.runHex(), "tenant-" + run.runHex(),
                        "10.60.1.20", "report-agent/1.0"), Duration.ofSeconds(30));
    }

    private static String clientToken(WorkloadClient agentClient, Agent agent) throws IOException {
        Response token = agentClient.postForm("/oauth2/token", UUID.randomUUID().toString(), AT,
                Map.of("grant_type", "client_credentials", "scope", "sc.engineer"), agent.basic());
        assertThat(token.status()).as(token.text()).isEqualTo(200);
        return JSON.readTree(token.body()).path("access_token").asText();
    }

    /** The person's sign-in to D's agents' flow: password, then the one-time code from the person's mailbox. */
    private String workspaceToken(WorkloadClient person, Run run) throws IOException {
        Response login = person.postJson("/agent/api/mfa/login", UUID.randomUUID().toString(), AT,
                JSON.writeValueAsString(Map.of("username", run.username(), "password", run.password())));
        assertThat(login.status()).as(login.text()).isEqualTo(200);
        assertThat(JSON.readTree(login.body()).path("status").asText()).as(login.text()).isEqualTo("MFA_REQUIRED");
        Response generate = person.postForm("/agent/mfa/ott/generate-code", UUID.randomUUID().toString(), AT,
                Map.of("username", run.username()));
        assertThat(generate.status()).as(generate.text()).isIn(200, 302);
        String code = inbox.take(run.username() + "@" + CompanyBlueprint.EMAIL_DOMAIN).orElseThrow().code();
        Response verify = person.postForm("/agent/login/mfa-ott", UUID.randomUUID().toString(), AT,
                Map.of("token", code));
        assertThat(verify.status()).as(verify.text()).isEqualTo(200);
        JsonNode body = JSON.readTree(verify.body());
        String token = body.path("accessToken").asText();
        assertThat(token).as(verify.text()).isNotBlank();
        return token;
    }

    /**
     * An agent's request with no decision on record is decided in the request (A1-5). These tests run without a model
     * (its key is never valid), so the decision falls closed to the additional check; the prompt the engine built for
     * the model is the request as the engine saw it.
     */
    private String decidedInPlace(Run run, Response read, String requestId) throws IOException {
        assertThat(read.status()).as(read.text()).isEqualTo(401);
        assertThat(JSON.readTree(read.body()).path("code").asText()).as(read.text()).isEqualTo("ZERO_TRUST_CHALLENGE");
        Response exchanges = run.admin().get("/internal/decisions/" + requestId + "/exchanges", null, null);
        assertThat(exchanges.status()).as(exchanges.text()).isEqualTo(200);
        StringBuilder prompts = new StringBuilder();
        for (JsonNode exchange : JSON.readTree(exchanges.body())) {
            prompts.append(exchange.path("systemPrompt").asText()).append('\n')
                    .append(exchange.path("userPrompt").asText()).append('\n');
        }
        assertThat(prompts.toString()).as("the model exchanges of " + requestId).isNotBlank();
        return prompts.toString();
    }

    /** A2-12: an agent's request is judged with its sponsor's company records, and a line says whose they are. */
    private static void assertSponsorsRecords(String prompt, Run run) {
        assertThat(line(prompt, "RecordsHolder: ")).endsWith("RecordsHolder: " + run.username()
                + " (the agent's sponsor)");
        assertThat(line(prompt, "Assignment: ")).contains("HX-310");
        assertThat(line(prompt, "Unknown: ")).doesNotContain("Assignment").doesNotContain("Policy");
    }

    /** The first line of the prompt with the text, as it was drawn. */
    /**
     * The line of the prompt that holds the text: one that starts with it before one that only contains it, since the
     * baseline block has lines of its own ("BaselineSubject: ...") that contain the label of another line.
     */
    private static String line(String prompt, String text) {
        return prompt.lines().filter(candidate -> candidate.startsWith(text)).findFirst()
                .or(() -> prompt.lines().filter(candidate -> candidate.contains(text)).findFirst())
                .orElseThrow(() -> new AssertionError("no line with " + text + " in\n" + prompt));
    }

    /** The facts the engine recorded with its decision of the request. */
    private JsonNode decisionMetadata(Run run, String requestId) throws IOException {
        Response decision = run.admin().get("/internal/decisions/" + requestId, null, null);
        assertThat(decision.status()).as(decision.text()).isEqualTo(200);
        JsonNode records = JSON.readTree(decision.body()).path("records");
        assertThat(records.size()).as(decision.text()).isPositive();
        JsonNode metadata = records.get(0).path("metadataJson");
        return metadata.isTextual() ? JSON.readTree(metadata.asText()) : metadata;
    }

    private String document() {
        return workDatabase.jdbc().getJdbcTemplate().queryForObject(
                "select min(document_key) from document where project_key = 'HX-310'", String.class);
    }
}
