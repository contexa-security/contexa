package io.contexa.showcase.workload.contexa.probe;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.domain.SecurityEvent;
import io.contexa.contexacommon.security.baseline.BaselineVector;
import io.contexa.contexacore.autonomous.baseline.store.BaselineDataStore;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import io.contexa.contexacore.security.UnifiedUserDetailsService;
import io.contexa.contexaiam.security.xacml.pep.CustomDynamicAuthorizationManager;
import io.contexa.showcase.business.client.WorkloadClient;
import io.contexa.showcase.business.client.WorkloadClient.Response;
import io.contexa.showcase.business.company.CompanyBlueprint;
import io.contexa.showcase.business.company.CompanyCalendar;
import io.contexa.showcase.business.company.TimeSlot;
import io.contexa.showcase.business.context.BusinessContextLookup;
import io.contexa.showcase.business.context.LookupPlan;
import io.contexa.showcase.business.context.RecordingBusinessContextLookup;
import io.contexa.showcase.business.internal.InternalContextSigner;
import io.contexa.showcase.business.run.RunRegistry;
import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.business.work.RbacParityCases;
import io.contexa.showcase.business.work.WorkDatabase;
import io.contexa.showcase.workload.contexa.ContexaWorkloadApplication;
import io.contexa.showcase.workload.contexa.context.BusinessFrictionProvider;
import io.contexa.showcase.workload.contexa.inbox.DemoInboxEmailService;
import io.contexa.showcase.workload.contexa.internal.DevForcedActionController;
import io.contexa.showcase.workload.contexa.internal.EndpointProtection;
import io.contexa.showcase.workload.contexa.observation.UsageLedger;
import io.contexa.showcase.workload.contexa.principal.OrphanPrincipalSweeper;
import io.contexa.showcase.workload.contexa.principal.SharedAccountGuard;
import io.contexa.showcase.workload.contexa.template.TemplateSnapshot;
import io.contexa.contexacommon.repository.UserRepository;
import io.micrometer.observation.ObservationRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.ai.embedding.EmbeddingModel;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.net.URI;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Control D's own contracts on the real engine (P1): the engine policies give the shared RBAC table's static decision
 * for every role-by-endpoint case (P1-BE-02), run principals are created with their employee's role and fully removed,
 * a template snapshot written under a run principal reads back identically, the business context provider states the
 * company facts, and the protection mode of each endpoint is read from the code. Skipped without Docker.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(classes = {ContexaWorkloadApplication.class, ProbeEndpoints.class, AnalysisHandOffRecording.class},
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ControlDContractTest {

    private static final String SIGNING_KEY = ProbeDatabase.randomKey();
    private static final ObjectMapper JSON = new ObjectMapper().findAndRegisterModules();

    private static final Map<String, String> EMPLOYEE_OF_ROLE = Map.of(
            CompanyBlueprint.ROLE_ENGINEER, CompanyBlueprint.ENGINEER_K,
            CompanyBlueprint.ROLE_SALES, "sal-01",
            CompanyBlueprint.ROLE_PM, "pm-01",
            CompanyBlueprint.ROLE_PARTNER, "prt-01",
            CompanyBlueprint.ROLE_FINANCE, "fin-01",
            CompanyBlueprint.ROLE_ADMIN, CompanyBlueprint.ADMIN_A);

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        ProbeDatabase.register(registry, SIGNING_KEY);
        registry.add("spring.ai.openai.api-key", () -> "probe-key-never-used");
    }

    @LocalServerPort
    int port;

    @Autowired
    private ObjectProvider<DevForcedActionController> forcedActions;

    @Autowired
    CustomDynamicAuthorizationManager authorization;

    @Autowired
    UnifiedUserDetailsService userDetails;

    @Autowired
    UserRepository users;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    DemoInboxEmailService inbox;

    @Autowired
    BaselineDataStore baselines;

    @Autowired
    SecurityContextDataStore contexts;

    @Autowired
    BusinessFrictionProvider frictionProvider;

    @Autowired
    RunRegistry runs;

    @Autowired
    JdbcTemplate vectorDatabase;

    @Autowired
    OrphanPrincipalSweeper orphanSweeper;

    @Autowired
    EmbeddingModel embeddingModel;

    @Autowired
    UsageLedger usageLedger;

    @Autowired
    ObjectProvider<ObservationRegistry> observationRegistries;

    record Created(String runId, String username, String password, String organization, String tenant,
                   WorkloadClient admin) {
    }

    private Created create(String employeeKey, String roleKey, TemplateSnapshot template) throws Exception {
        String runHex = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        String runId = "run-" + runHex;
        String username = "v" + runHex + "-" + employeeKey;
        String password = "Contract-" + UUID.randomUUID() + "-Aa1";
        WorkloadClient admin = new WorkloadClient(URI.create("http://127.0.0.1:" + port + "/"),
                new InternalContextSigner(SIGNING_KEY),
                new WorkloadClient.RunIdentity(runId, "org-" + runHex, "tenant-" + runHex, "10.40.12.90",
                        "ControlDContract/1.0"), Duration.ofSeconds(30));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("username", username);
        body.put("password", password);
        body.put("employeeKey", employeeKey);
        body.put("roleKey", roleKey);
        body.put("displayName", "Contract " + employeeKey);
        body.put("department", "Contract test");
        body.put("organizationId", "org-" + runHex);
        body.put("tenantId", "tenant-" + runHex);
        body.put("template", template);
        Response created = admin.postJson("/internal/runs/" + runId + "/principals", null, null,
                JSON.writeValueAsString(body));
        assertThat(created.status()).as(created.text()).isEqualTo(200);
        return new Created(runId, username, password, "org-" + runHex, "tenant-" + runHex, admin);
    }

    /** P1-BE-02, control D side. */
    @Autowired
    private SharedAccountGuard sharedAccounts;

    @Autowired
    @Qualifier("contexaJdbcTemplate")
    private JdbcTemplate engineDatabase;

    /** P5-SEC-01: the engine's seeded sample accounts exist but none of them can sign in. */
    @Test
    void noSharedAccountCanSignInAfterStart() {
        assertThat(sharedAccounts.usableSharedAccounts()).isEmpty();
        assertThat(engineDatabase.queryForObject("select count(*) from users where username = 'admin' and not enabled "
                + "and account_locked", Integer.class)).isEqualTo(1);
    }

    /** Forced decisions exist only on a development stack that sets the flag; visitors never see one. */
    @Test
    void forcedDecisionsDoNotExistUnlessTheDevelopmentFlagIsSet() {
        assertThat(forcedActions.getIfAvailable()).isNull();
    }

    @Test
    void enginePoliciesGiveTheSharedRbacTableDecisionForEveryCase() throws Exception {
        Map<String, UserDetails> principals = new HashMap<>();
        for (Map.Entry<String, String> entry : EMPLOYEE_OF_ROLE.entrySet()) {
            Created created = create(entry.getValue(), entry.getKey(), null);
            UserDetails loaded = userDetails.loadUserByUsername(created.username());
            assertThat(loaded.getAuthorities()).extracting(GrantedAuthority::getAuthority)
                    .as("the engine loads the employee's role through its group")
                    .contains("ROLE_SC_" + entry.getKey());
            principals.put(entry.getKey(), loaded);
        }
        List<RbacParityCases.Case> cases = RbacParityCases.all();
        assertThat(cases).hasSizeGreaterThanOrEqualTo(30);
        for (RbacParityCases.Case parity : cases) {
            UserDetails user = principals.get(parity.roleKey());
            MockHttpServletRequest request = new MockHttpServletRequest(parity.method(), parity.path());
            request.setRequestURI(parity.path());
            UsernamePasswordAuthenticationToken authentication = UsernamePasswordAuthenticationToken.authenticated(
                    user, null, user.getAuthorities());
            boolean granted = authorization.check(() -> authentication, new RequestAuthorizationContext(request))
                    .isGranted();
            assertThat(granted).as(parity.toString()).isEqualTo(parity.allowed());
        }
    }

    @Test
    void aRunPrincipalSignsInWithTheEngineFlowAndIsFullyRemoved() throws Exception {
        Created created = create(CompanyBlueprint.ENGINEER_K, CompanyBlueprint.ROLE_ENGINEER, null);
        ProbeClient client = new ProbeClient(URI.create("http://127.0.0.1:" + port), new InternalContextSigner(SIGNING_KEY),
                new ProbeClient.RunIdentity(created.runId(), created.username(), created.password(),
                        created.username() + "@showcase.invalid", created.organization(), created.tenant(),
                        "10.40.21.90", CompanyBlueprint.ENGINEER_K_DEVICE));
        new ProbeRuns(users, passwordEncoder, inbox, new InternalContextSigner(SIGNING_KEY), port).signIn(client);

        Response deleted = created.admin().delete("/internal/runs/" + created.runId() + "/principals/"
                + created.username(), null);

        assertThat(deleted.status()).as(deleted.text()).isEqualTo(200);
        assertThat(JSON.readTree(deleted.body()).path("failedSteps").size()).isZero();
        assertThat(users.findByUsername(created.username())).isEmpty();
    }

    /** P1-OPS-01: every embedding call of the engine reaches the usage meter, attributed to the principal it names. */
    @Test
    void embeddingCallsReachTheUsageMeter() {
        assertThat(observationRegistries.stream().count()).as("one observation registry").isEqualTo(1);
        String principal = "v" + UUID.randomUUID().toString().replace("-", "").substring(0, 12) + "-eng-k";
        try {
            embeddingModel.embed("user: " + principal + ", action: READ");
        } catch (RuntimeException expected) {
            // The probe context has no model key; the failed call is still observed.
        }

        assertThat(usageLedger.callsOf("user:" + principal)).extracting(UsageLedger.ModelCall::kind)
                .containsExactly("EMBEDDING");
    }

    /** A memory document written after its principal was removed is purged; a live principal's is kept (T8). */
    @Test
    void theSweeperPurgesMemoryOfRemovedPrincipalsOnly() throws Exception {
        Created live = create(CompanyBlueprint.ENGINEER_K, CompanyBlueprint.ROLE_ENGINEER, null);
        String removed = "v" + UUID.randomUUID().toString().replace("-", "").substring(0, 12) + "-eng-k";
        insertMemory(live.username());
        insertMemory(removed);

        orphanSweeper.sweep();

        assertThat(memoryOf(removed)).as("the removed principal's late document").isZero();
        assertThat(memoryOf(live.username())).as("the live principal's document").isEqualTo(1);
        assertThat(orphanSweeper.state().purgedPrincipals()).isPositive();
    }

    private void insertMemory(String username) {
        String embedding = "[" + String.join(",", Collections.nCopies(1024, "0.01")) + "]";
        vectorDatabase.update("insert into vector_store (id, content, metadata, embedding) "
                        + "values (?, 'memory', cast(? as json), cast(? as vector))", UUID.randomUUID(),
                "{\"userId\":\"" + username + "\",\"documentType\":\"behavior\"}", embedding);
    }

    private int memoryOf(String username) {
        Integer count = vectorDatabase.queryForObject(
                "select count(*) from vector_store where metadata::jsonb ->> 'userId' = ?", Integer.class, username);
        return count == null ? 0 : count;
    }

    @Test
    void aTemplateSnapshotReadsBackIdenticallyUnderTheRunPrincipal() throws Exception {
        Created template = create(CompanyBlueprint.ENGINEER_K, CompanyBlueprint.ROLE_ENGINEER, null);
        BaselineVector baseline = BaselineVector.builder()
                .userId(template.username())
                .normalAccessHours(new Integer[]{9, 10, 14})
                .normalUserAgents(new String[]{"Edge-Windows"})
                .updateCount(24L)
                .build();
        baselines.saveUserBaseline(template.username(), baseline);
        baselines.saveOrganizationBaseline(template.organization(), BaselineVector.builder()
                .userId("org:" + template.organization()).updateCount(24L).build());
        contexts.addWorkProfileObservation(template.tenant(), template.username(), "observation-1");
        contexts.addWorkProfileObservation(template.tenant(), template.username(), "observation-2");
        contexts.addPermissionChangeObservation(template.tenant(), template.username(), "change-1");

        Response exported = template.admin().postJson("/internal/templates/snapshot", null, null,
                JSON.writeValueAsString(Map.of("username", template.username(), "employeeKey",
                        CompanyBlueprint.ENGINEER_K, "organizationId", template.organization(),
                        "tenantId", template.tenant())));
        assertThat(exported.status()).as(exported.text()).isEqualTo(200);
        TemplateSnapshot snapshot = JSON.readValue(exported.body(), TemplateSnapshot.class);
        assertThat(snapshot.baselineUpdateCount()).isEqualTo(24L);
        assertThat(snapshot.workProfileObservations()).containsExactly("observation-1", "observation-2");

        Created run = create(CompanyBlueprint.ENGINEER_K, CompanyBlueprint.ROLE_ENGINEER, snapshot);

        BaselineVector copied = baselines.getUserBaseline(run.username());
        assertThat(copied.getUserId()).isEqualTo(run.username());
        assertThat(copied.getUpdateCount()).isEqualTo(24L);
        assertThat(copied.getNormalAccessHours()).containsExactly(9, 10, 14);
        assertThat(baselines.getOrganizationBaseline(run.organization()).getUserId())
                .isEqualTo("org:" + run.organization());
        assertThat(contexts.getRecentWorkProfileObservations(run.tenant(), run.username(), 10))
                .containsExactly("observation-1", "observation-2");
        assertThat(contexts.getRecentPermissionChangeObservations(run.tenant(), run.username(), 10))
                .containsExactly("change-1");
        assertThat(contexts.getRecentWorkProfileObservations(template.tenant(), run.username(), 10))
                .as("nothing is written under the template tenant").isEmpty();
    }

    @Test
    void theBusinessContextProviderStatesTheCompanyFactsOfTheRequest() {
        String username = "v" + UUID.randomUUID().toString().replace("-", "").substring(0, 12) + "-adm-a";
        runs.registerPrincipal(username, "run-provider", CompanyBlueprint.ADMIN_A, "org-provider", "tenant-provider");
        SecurityEvent event = SecurityEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .userId(username)
                .timestamp(LocalDateTime.ofInstant(CompanyCalendar.at(ProbeDatabase.ANCHOR, TimeSlot.DAWN), ZoneOffset.UTC))
                .build();
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("requestPath", "/api/projects/" + CompanyBlueprint.A3_TARGET + "/exports");
        metadata.put("httpMethod", "POST");
        metadata.put("queryString", "items=4831");
        event.setMetadata(metadata);
        CanonicalSecurityContext context = new CanonicalSecurityContext();

        frictionProvider.enrich(event, context);

        assertThat(context.getFrictionProfile()).isNotNull();
        assertThat(context.getFrictionProfile().getApprovalGranted()).isFalse();
        assertThat(context.getFrictionProfile().getApprovalLineage())
                .anySatisfy(line -> assertThat(line).contains("assigned to project GB-500: no"))
                .anySatisfy(line -> assertThat(line).contains("no approval"))
                .anySatisfy(line -> assertThat(line).contains("no ITSM ticket"))
                .anySatisfy(line -> assertThat(line).contains("not on call"))
                .anySatisfy(line -> assertThat(line).contains("in the last 30 days: 0"))
                .allSatisfy(line -> assertThat(line).doesNotContainIgnoringCase("required"));
    }

    @Autowired
    BusinessContextLookup lookup;

    @Autowired
    WorkDatabase workDatabase;

    /** P1-BE-04, control D side: the provider looks up exactly the facts of the shared plan for every operation. */
    @Test
    void theContextProviderReadsExactlyThePlannedFacts() {
        String username = "v" + UUID.randomUUID().toString().replace("-", "").substring(0, 12) + "-adm-a";
        runs.registerPrincipal(username, "run-plan", CompanyBlueprint.ADMIN_A, "org-plan", "tenant-plan");
        Map<String, String[]> requests = new LinkedHashMap<>();
        requests.put("EXPORT", new String[]{"POST", "/api/projects/GB-500/exports", "items=4831"});
        requests.put("EXPORT claimed", new String[]{"POST", "/api/projects/GB-500/exports",
                "items=300&claimedTicket=INC-7781"});
        requests.put("DOCUMENT_READ", new String[]{"GET", "/api/documents/" + workDatabase.jdbc()
                .getJdbcTemplate().queryForObject("select min(document_key) from document where project_key = 'GB-500'",
                        String.class), null});
        requests.put("CUSTOMER_READ", new String[]{"GET", "/api/customers/CUS-0001", null});
        requests.put("ROLE_GRANT", new String[]{"POST", "/api/admin/role-grants",
                "project=GB-500&grantee=eng-k&responsibility=REVIEW"});
        for (Map.Entry<String, String[]> request : requests.entrySet()) {
            RecordingBusinessContextLookup recording = new RecordingBusinessContextLookup(lookup);
            SecurityEvent event = SecurityEvent.builder().userId(username)
                    .timestamp(LocalDateTime.ofInstant(CompanyCalendar.at(ProbeDatabase.ANCHOR, TimeSlot.AFTERNOON),
                            ZoneOffset.UTC))
                    .build();
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("httpMethod", request.getValue()[0]);
            metadata.put("requestPath", request.getValue()[1]);
            if (request.getValue()[2] != null) {
                metadata.put("queryString", request.getValue()[2]);
            }
            event.setMetadata(metadata);
            CanonicalSecurityContext context = new CanonicalSecurityContext();
            new BusinessFrictionProvider(recording, workDatabase).enrich(event, context);
            BusinessOperation operation = BusinessOperation.valueOf(request.getKey().split(" ")[0]);
            boolean claimed = request.getKey().endsWith("claimed");
            assertThat(recording.called()).as(request.getKey())
                    .isEqualTo(LookupPlan.forRequest(operation, claimed));
            if (claimed) {
                assertThat(context.getFrictionProfile().getApprovalLineage())
                        .anyMatch(line -> line.startsWith("Requester claim in the request (not verified): ticket INC-7781"))
                        .anyMatch(line -> line.contains("the claimed ticket INC-7781 does not exist"));
            }
        }
    }

    @Test
    void theProtectionOfEachEndpointIsReadFromTheCode() throws Exception {
        assertThat(EndpointProtection.describe()).containsEntry("POST /api/projects/*/exports", "sync")
                .containsEntry("POST /api/admin/role-grants", "sync")
                .containsEntry("GET /api/documents/*", "async")
                .containsEntry("GET /api/projects/*/exports/stream", "async")
                .containsEntry("GET /api/projects", "none");
        WorkloadClient admin = create(CompanyBlueprint.ADMIN_A, CompanyBlueprint.ROLE_ADMIN, null).admin();
        JsonNode engine = JSON.readTree(admin.get("/internal/engine", null, null).body());
        assertThat(engine.path("effectiveMode").asText()).isEqualTo("ENFORCE");
        assertThat(engine.path("timeZone").asText()).isIn("UTC", "Etc/UTC", "Z");
    }
}
