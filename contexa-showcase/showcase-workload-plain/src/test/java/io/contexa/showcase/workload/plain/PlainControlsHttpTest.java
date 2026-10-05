package io.contexa.showcase.workload.plain;

import io.contexa.showcase.business.client.WorkloadClient;
import io.contexa.showcase.business.client.WorkloadClient.Response;
import io.contexa.showcase.business.company.CompanyBlueprint;
import io.contexa.showcase.business.company.TimeSlot;
import io.contexa.showcase.business.run.RunFacts;
import io.contexa.showcase.business.work.RbacParityCases;
import io.contexa.showcase.workload.plain.security.ControlAuthorizationManager;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.test.context.TestPropertySource;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The three plain controls over real HTTP: the shared role-based policy (B), the threshold rules (C1) and the
 * context lookup rules (C2) decide as their published configuration says, record every decision, and refuse the
 * management API without the internal signature. Scene A3 (administrator A exports 4,831 documents of a project
 * not assigned to them at 03:17) is the representative case of the deck's table (p.1, p.10).
 */
class PlainControlsHttpTest {

    static final String A3_EXPORT = "/api/projects/" + CompanyBlueprint.A3_TARGET + "/exports?items=4831";

    @Nested
    @SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
    @TestPropertySource(properties = "showcase.control=B")
    class ControlB extends PlainControlTestSupport {

        @Test
        void roleBasedAccessDeliversTheRepresentativeBulkExport() throws Exception {
            WorkloadClient adminA = signedIn(CompanyBlueprint.ADMIN_A);
            String requestId = UUID.randomUUID().toString();
            Response export = adminA.postJson(A3_EXPORT, requestId, at(TimeSlot.DAWN), null);

            assertThat(export.status()).as(export.text()).isEqualTo(200);
            assertThat(json(export).path("deliveredItems").asInt()).isEqualTo(4831);
            assertThat(jdbc.queryForObject("select status from export_job where request_id = ?", String.class, requestId))
                    .isEqualTo("COMPLETED");
            assertThat(jdbc.queryForObject("select rule_id from rule_decision_log where request_id = ?", String.class,
                    requestId)).isEqualTo("RBAC");
        }

        @Test
        void rolesOutsideThePolicyAreRefusedWithTheRule() throws Exception {
            Response partnerExport = signedIn("prt-01").postJson("/api/projects/HX-200/exports?items=5",
                    UUID.randomUUID().toString(), at(TimeSlot.AFTERNOON), null);
            Response salesDocument = signedIn("sal-01").get("/api/documents/" + drawingOf("HX-310"),
                    UUID.randomUUID().toString(), at(TimeSlot.AFTERNOON));

            assertThat(partnerExport.status()).isEqualTo(403);
            assertThat(json(partnerExport).path("rule").asText()).isEqualTo("RBAC");
            assertThat(salesDocument.status()).isEqualTo(403);
            assertThat(json(salesDocument).path("rule").asText()).isEqualTo("RBAC");
        }

        @Autowired
        ControlAuthorizationManager authorization;

        /** P1-BE-02, control B side: the static decision of every role-by-endpoint case matches the shared policy. */
        @Test
        void staticDecisionsMatchTheSharedRbacTable() {
            List<RbacParityCases.Case> cases = RbacParityCases.all();
            assertThat(cases).hasSizeGreaterThanOrEqualTo(30);
            for (RbacParityCases.Case parity : cases) {
                MockHttpServletRequest request = new MockHttpServletRequest(parity.method(), parity.path());
                request.setRequestURI(parity.path());
                TestingAuthenticationToken user = new TestingAuthenticationToken("parity-" + parity.roleKey(), null,
                        "ROLE_" + parity.roleKey());
                boolean granted = authorization.check(() -> user, new RequestAuthorizationContext(request)).isGranted();
                assertThat(granted).as(parity.toString()).isEqualTo(parity.allowed());
            }
        }

        @Test
        void theManagementApiNeedsTheInternalSignatureAndTheBusinessApiNeedsASession() throws Exception {
            HttpClient raw = HttpClient.newHttpClient();
            HttpResponse<String> unsigned = raw.send(HttpRequest.newBuilder(
                            URI.create("http://127.0.0.1:" + port + "/internal/runs/x/evidence")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());
            HttpResponse<String> anonymous = raw.send(HttpRequest.newBuilder(
                            URI.create("http://127.0.0.1:" + port + "/api/projects")).GET().build(),
                    HttpResponse.BodyHandlers.ofString());

            assertThat(unsigned.statusCode()).isEqualTo(403);
            assertThat(unsigned.body()).contains("INTERNAL_SIGNATURE_REQUIRED");
            assertThat(anonymous.statusCode()).isEqualTo(401);
        }

        /**
         * P5-SEC-01 (deck p.37): the plain controls have no shared account. Every sign-in account belongs to a run
         * principal and goes with it; the usual administrator names do not sign in.
         */
        @Test
        void noSharedAccountExistsAndAnAccountCannotOutliveItsRunPrincipal() throws Exception {
            assertThat(jdbc.queryForObject("select count(*) from plain_user where username !~ '^v[0-9a-f]{12}-'",
                    Integer.class)).isZero();
            assertThatThrownBy(() -> jdbc.update("insert into plain_user (username, password_hash) values (?, ?)",
                    "admin", "{noop}admin")).isInstanceOf(DataIntegrityViolationException.class);

            HttpClient raw = HttpClient.newHttpClient();
            for (String name : new String[]{"admin", "administrator", "root", "manager", "user"}) {
                HttpResponse<String> login = raw.send(HttpRequest.newBuilder(
                                URI.create("http://127.0.0.1:" + port + "/api/login"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(
                                JSON.writeValueAsString(Map.of("username", name, "password", name))))
                        .build(), HttpResponse.BodyHandlers.ofString());
                assertThat(login.statusCode()).as(name).isEqualTo(401);
            }
        }
    }

    @Nested
    @SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
    @TestPropertySource(properties = "showcase.control=C1")
    class ControlC1 extends PlainControlTestSupport {

        @Test
        void thresholdsStopTheRepresentativeExportAndTheVolumeButNotNormalWork() throws Exception {
            Response a3 = signedIn(CompanyBlueprint.ADMIN_A).postJson(A3_EXPORT, UUID.randomUUID().toString(),
                    at(TimeSlot.DAWN), null);
            WorkloadClient engineerK = signedIn(CompanyBlueprint.ENGINEER_K);
            Response small = engineerK.postJson("/api/projects/" + CompanyBlueprint.K_PROJECT + "/exports?items=20",
                    UUID.randomUUID().toString(), at(TimeSlot.AFTERNOON), null);
            Response large = engineerK.postJson("/api/projects/" + CompanyBlueprint.K_PROJECT + "/exports?items=600",
                    UUID.randomUUID().toString(), at(TimeSlot.AFTERNOON), null);
            Response dormant = engineerK.get("/api/documents/" + drawingOf("GB-500"), UUID.randomUUID().toString(),
                    at(TimeSlot.AFTERNOON));

            assertThat(a3.status()).isEqualTo(403);
            assertThat(json(a3).path("rule").asText()).isEqualTo("C1-NIGHT");
            assertThat(small.status()).as(small.text()).isEqualTo(200);
            assertThat(json(large).path("rule").asText()).isEqualTo("C1-VOLUME");
            assertThat(dormant.status()).isEqualTo(403);
            assertThat(json(dormant).path("rule").asText()).isEqualTo("C1-DORMANT");
        }
    }

    @Nested
    @SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
    @TestPropertySource(properties = "showcase.control=C2")
    class ControlC2 extends PlainControlTestSupport {

        @Test
        void contextLookupsStopTheRepresentativeExportAndAllowItWithAnApproval() throws Exception {
            String deniedId = UUID.randomUUID().toString();
            Response denied = signedIn(CompanyBlueprint.ADMIN_A).postJson(A3_EXPORT, deniedId, at(TimeSlot.DAWN), null);
            RunFacts approved = new RunFacts(List.of(), List.of(new RunFacts.Approval("APR-" + UUID.randomUUID(),
                    CompanyBlueprint.ADMIN_A, "pm-11", CompanyBlueprint.A3_TARGET, "PROJECT_TRANSFER", 5_000,
                    at(TimeSlot.DAWN).minus(Duration.ofDays(1)), at(TimeSlot.DAWN).plus(Duration.ofDays(1)),
                    "APPROVED")), List.of());
            Response allowed = signedIn(CompanyBlueprint.ADMIN_A, approved).postJson(A3_EXPORT,
                    UUID.randomUUID().toString(), at(TimeSlot.DAWN), null);

            assertThat(denied.status()).isEqualTo(403);
            assertThat(json(denied).path("rule").asText()).isEqualTo("C2-NO-CONTEXT");
            assertThat(jdbc.queryForObject("select facts::text from rule_decision_log where request_id = ?",
                    String.class, deniedId)).contains("NO_APPROVAL").contains("NO_TICKET");
            assertThat(allowed.status()).as(allowed.text()).isEqualTo(200);
            assertThat(json(allowed).path("deliveredItems").asInt()).isEqualTo(4831);
        }

        /** Deck A8: a ticket named in the request counts only when the business database confirms it. */
        @Test
        void aClaimedTicketIsCheckedAndAFalseClaimIsRefused() throws Exception {
            String ticketKey = "TCK-" + UUID.randomUUID().toString().substring(0, 8);
            RunFacts incident = new RunFacts(List.of(new RunFacts.Ticket(ticketKey, "INCIDENT", CompanyBlueprint.ADMIN_A,
                    "pm-11", CompanyBlueprint.A3_TARGET, "INCIDENT_RECOVERY", "Recovery of GB-500 records",
                    at(TimeSlot.DAWN).minus(Duration.ofHours(1)), at(TimeSlot.DAWN).plus(Duration.ofHours(4)), "OPEN")),
                    List.of(), List.of(new RunFacts.Oncall("ONC-" + ticketKey, CompanyBlueprint.ADMIN_A, "PLATFORM",
                    at(TimeSlot.DAWN).minus(Duration.ofHours(2)), at(TimeSlot.DAWN).plus(Duration.ofHours(6)))));
            Response falseClaim = signedIn(CompanyBlueprint.ADMIN_A).postJson(A3_EXPORT + "&claimedTicket=INC-7781",
                    UUID.randomUUID().toString(), at(TimeSlot.DAWN), null);
            Response trueClaim = signedIn(CompanyBlueprint.ADMIN_A, incident).postJson(A3_EXPORT + "&claimedTicket="
                    + ticketKey, UUID.randomUUID().toString(), at(TimeSlot.DAWN), null);

            assertThat(falseClaim.status()).isEqualTo(403);
            assertThat(json(falseClaim).path("rule").asText()).isEqualTo("C2-FALSE-CLAIM");
            assertThat(trueClaim.status()).as(trueClaim.text()).isEqualTo(200);
        }

        /** Deck A5: a role is given only under an approved change ticket for that project. */
        @Test
        void aRoleGrantNeedsAnApprovedChangeTicket() throws Exception {
            String grant = "/api/admin/role-grants?project=" + CompanyBlueprint.A3_TARGET + "&grantee="
                    + CompanyBlueprint.ENGINEER_K + "&responsibility=REVIEW";
            RunFacts change = new RunFacts(List.of(new RunFacts.Ticket("TCK-" + UUID.randomUUID().toString()
                    .substring(0, 8), "CHANGE", CompanyBlueprint.ADMIN_A, "pm-11", CompanyBlueprint.A3_TARGET,
                    "ACCESS_GRANT", "Review access to GB-500", at(TimeSlot.AFTERNOON).minus(Duration.ofHours(2)),
                    at(TimeSlot.AFTERNOON).plus(Duration.ofHours(6)), "APPROVED")), List.of(), List.of());
            Response unapproved = signedIn(CompanyBlueprint.ADMIN_A).postJson(grant, UUID.randomUUID().toString(),
                    at(TimeSlot.AFTERNOON), null);
            Response approved = signedIn(CompanyBlueprint.ADMIN_A, change).postJson(grant, UUID.randomUUID().toString(),
                    at(TimeSlot.AFTERNOON), null);

            assertThat(unapproved.status()).isEqualTo(403);
            assertThat(json(unapproved).path("rule").asText()).isEqualTo("C2-NO-CHANGE-TICKET");
            assertThat(approved.status()).as(approved.text()).isEqualTo(200);
            assertThat(json(approved).path("grantee").asText()).isEqualTo(CompanyBlueprint.ENGINEER_K);
        }

        /** Deck A1: company data is used from a company office or a registered business trip only. */
        @Test
        void anExternalNetworkIsRefusedAndARegisteredTripIsNot() throws Exception {
            String document = "/api/documents/" + drawingOf(CompanyBlueprint.K_PROJECT);
            RunFacts trip = new RunFacts(List.of(), List.of(), List.of(), List.of(new RunFacts.TravelPlan(
                    "TRV-" + UUID.randomUUID().toString().substring(0, 8), CompanyBlueprint.ENGINEER_K, "Singapore",
                    "SG", "198.51.100.0/24", at(TimeSlot.AFTERNOON).minus(Duration.ofDays(2)),
                    at(TimeSlot.AFTERNOON).plus(Duration.ofDays(3)))));
            Response external = signedIn(CompanyBlueprint.ENGINEER_K, RunFacts.none(), "203.0.113.9")
                    .get(document, UUID.randomUUID().toString(), at(TimeSlot.AFTERNOON));
            Response travelling = signedIn(CompanyBlueprint.ENGINEER_K, trip, "198.51.100.9")
                    .get(document, UUID.randomUUID().toString(), at(TimeSlot.AFTERNOON));

            assertThat(external.status()).isEqualTo(403);
            assertThat(json(external).path("rule").asText()).isEqualTo("C2-EXTERNAL-NETWORK");
            assertThat(travelling.status()).as(travelling.text()).isEqualTo(200);
        }

        @Test
        void singleDocumentsNeedAnAssignmentATicketOrRecentWork() throws Exception {
            WorkloadClient engineerK = signedIn(CompanyBlueprint.ENGINEER_K);
            Response own = engineerK.get("/api/documents/" + drawingOf(CompanyBlueprint.K_PROJECT), UUID.randomUUID().toString(),
                    at(TimeSlot.AFTERNOON));
            Response foreign = engineerK.get("/api/documents/" + drawingOf("GB-500"), UUID.randomUUID().toString(),
                    at(TimeSlot.AFTERNOON));

            assertThat(own.status()).as(own.text()).isEqualTo(200);
            assertThat(json(own).path("projectKey").asText()).isEqualTo(CompanyBlueprint.K_PROJECT);
            assertThat(foreign.status()).isEqualTo(403);
            assertThat(json(foreign).path("rule").asText()).isEqualTo("C2-NO-CONTEXT");
        }
    }
}
