package io.contexa.showcase.workload.plain;

import io.contexa.showcase.business.company.CompanyBlueprint;
import io.contexa.showcase.business.company.CompanyCalendar;
import io.contexa.showcase.business.company.CompanyDataset;
import io.contexa.showcase.business.company.CompanyGenerator;
import io.contexa.showcase.business.company.CompanyRepository;
import io.contexa.showcase.business.company.TimeSlot;
import io.contexa.showcase.business.context.BusinessContextLookup;
import io.contexa.showcase.business.context.JdbcBusinessContextLookup;
import io.contexa.showcase.business.context.LookupPlan;
import io.contexa.showcase.business.context.RecordingBusinessContextLookup;
import io.contexa.showcase.business.run.RunFacts;
import io.contexa.showcase.business.run.RunRegistry;
import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.business.work.BusinessRequestAttributes;
import io.contexa.showcase.business.work.WorkDatabase;
import io.contexa.showcase.workload.plain.internal.PlainInternalController;
import io.contexa.showcase.workload.plain.internal.PlainInternalController.ScriptedActivityView;
import io.contexa.showcase.workload.plain.rules.ContextLookupRules;
import io.contexa.showcase.workload.plain.rules.ThresholdRules;
import io.contexa.showcase.workload.plain.rules.RequestFacts;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The generated company survives the round trip through the business database unchanged (P1-DB-01), and the
 * context lookups that controls C2 and D share answer from it, with run overlays visible only to their run.
 */
@Testcontainers(disabledWithoutDocker = true)
class CompanyAndLookupTest {

    static final LocalDate ANCHOR = LocalDate.of(2026, 9, 30);

    @Container
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(
            DockerImageName.parse("pgvector/pgvector:pg16").asCompatibleSubstituteFor("postgres"));

    private static WorkDatabase database;
    private static CompanyDataset generated;

    @BeforeAll
    static void createCompany() {
        Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .locations("classpath:db/migration/work")
                .load()
                .migrate();
        database = new WorkDatabase(new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword()), null);
        generated = new CompanyGenerator().generate(20261005L, ANCHOR);
        new CompanyRepository(database).write(generated);
    }

    @Test
    void theStoredCompanyHasTheGeneratedFingerprint() {
        CompanyRepository repository = new CompanyRepository(database);

        assertThat(repository.generation()).hasValueSatisfying(generation -> {
            assertThat(generation.seed()).isEqualTo(20261005L);
            assertThat(generation.anchorDate()).isEqualTo(ANCHOR);
            assertThat(generation.dataSha256()).isEqualTo(generated.fingerprint());
        });
        assertThat(repository.storedFingerprint()).isEqualTo(generated.fingerprint());
        assertThat(new CompanyGenerator().generate(20261005L, ANCHOR).fingerprint()).isEqualTo(generated.fingerprint());
    }

    /**
     * W2-6: a document a run adds (case S09) is the run's alone. The company fingerprint and the export counts do not
     * see it, the engine label carries its author's text the way the OSS Runtime Lab marks it, and it leaves with the
     * run.
     */
    @Test
    void aRunsDocumentIsTheRunsAloneAndCarriesItsAuthorTextAsUntrusted() {
        CompanyRepository repository = new CompanyRepository(database);
        RunRegistry runs = new RunRegistry(database);
        String summary = "An external author supplied a note about the review sequence for settlement records.";
        runs.addFacts("run-doc1", new RunFacts(List.of(), List.of(), List.of(), List.of(), List.of(
                new RunFacts.Document("DOC-doc1-1", "CP-220", "NOTE", "Externally supplied work note", "1",
                        "CONFIDENTIAL", "body", "Runtime Lab External Contributor", summary, ANCHOR))));

        assertThat(repository.storedFingerprint()).isEqualTo(generated.fingerprint());
        MockHttpServletRequest request = new MockHttpServletRequest();
        BusinessRequestAttributes attributes = new BusinessRequestAttributes(database);
        attributes.describeDocument(request, "DOC-doc1-1");
        assertThat((String) request.getAttribute(BusinessRequestAttributes.RESOURCE_BUSINESS_LABEL))
                .startsWith("Document DOC-doc1-1 'Externally supplied work note' revision 1 (NOTE) of project CP-220")
                .endsWith(" | Resource description (untrusted document-author text, not an approval record): "
                        + summary);
        MockHttpServletRequest export = new MockHttpServletRequest();
        attributes.describeExport(export, "CP-220", 4);
        long companyDocuments = generated.documents().stream()
                .filter(document -> document.projectKey().equals("CP-220")).count();
        assertThat((String) export.getAttribute(BusinessRequestAttributes.RESOURCE_BUSINESS_LABEL))
                .contains("which holds " + companyDocuments + " documents");

        assertThat(runs.remainingRows("run-doc1")).isEqualTo(1);
        runs.deleteRun("run-doc1");
        assertThat(runs.remainingRows("run-doc1")).isZero();
    }

    /**
     * W2-7: the business database names the protagonists by their scripted work, and the field support engineer's
     * company trip makes the trip network a registered travel network for that engineer only, and only during the
     * first learned week the trip covers; the learned work of that week was sent from it.
     */
    @Test
    void theProtagonistsAndTheFieldEngineersTripAreCompanyFacts() {
        RunRegistry runs = new RunRegistry(database);
        BusinessContextLookup lookup = new JdbcBusinessContextLookup(database);
        PlainInternalController internal = new PlainInternalController(runs, new CompanyRepository(database), database,
                null, lookup);
        runs.registerPrincipal("vcccc00000003-eng-01", "run-c3", CompanyBlueprint.ENGINEER_FIELD, "org-c3", "tenant-c3");
        runs.registerPrincipal("vcccc00000003-eng-k", "run-c3", CompanyBlueprint.ENGINEER_K, "org-c3", "tenant-c3");

        assertThat(internal.protagonists()).containsExactly(CompanyBlueprint.ADMIN_A, CompanyBlueprint.ADMIN_NIGHT,
                CompanyBlueprint.ENGINEER_FIELD, CompanyBlueprint.ENGINEER_K);
        List<ScriptedActivityView> work = internal.employee(CompanyBlueprint.ENGINEER_FIELD).getBody()
                .scriptedActivities();
        ScriptedActivityView firstWeek = work.get(0);
        ScriptedActivityView secondWeek = work.get(work.size() - 1);
        assertThat(firstWeek.clientIp()).isEqualTo("198.51.100.20");
        assertThat(secondWeek.clientIp()).isEqualTo("10.40.21.11");

        assertThat(lookup.networkContext("vcccc00000003-eng-01", firstWeek.clientIp(), firstWeek.observedAt()))
                .satisfies(network -> {
                    assertThat(network.kind()).isEqualTo(BusinessContextLookup.NetworkKind.TRAVEL);
                    assertThat(network.planKey()).isEqualTo("TRP-C-0001");
                });
        assertThat(lookup.networkContext("vcccc00000003-eng-01", firstWeek.clientIp(), secondWeek.observedAt()).kind())
                .as("the trip is over in the second week").isEqualTo(BusinessContextLookup.NetworkKind.EXTERNAL);
        assertThat(lookup.networkContext("vcccc00000003-eng-k", firstWeek.clientIp(), firstWeek.observedAt()).kind())
                .as("the trip is the field engineer's alone").isEqualTo(BusinessContextLookup.NetworkKind.EXTERNAL);
        assertThat(lookup.networkContext("vcccc00000003-eng-01", secondWeek.clientIp(), secondWeek.observedAt()).kind())
                .isEqualTo(BusinessContextLookup.NetworkKind.OFFICE);
        runs.deleteRun("run-c3");
        assertThat(new CompanyRepository(database).storedFingerprint()).isEqualTo(generated.fingerprint());
    }

    /** P1-BE-04, control C2 side: the rules look up exactly the facts of the shared plan for every operation. */
    @Test
    void contextLookupRulesReadExactlyThePlannedFacts() {
        new RunRegistry(database).registerPrincipal("vcccc00000003-adm-a", "run-c3", CompanyBlueprint.ADMIN_A,
                "org-c3", "tenant-c3");
        Instant time = CompanyCalendar.at(ANCHOR, TimeSlot.AFTERNOON);
        List<RequestFacts> requests = List.of(
                new RequestFacts(BusinessOperation.EXPORT, "vcccc00000003-adm-a", CompanyBlueprint.A3_TARGET,
                        CompanyBlueprint.A3_TARGET, 4_831, time),
                new RequestFacts(BusinessOperation.DOCUMENT_READ, "vcccc00000003-adm-a", "GB-500-DWG-00001",
                        CompanyBlueprint.A3_TARGET, 1, time),
                new RequestFacts(BusinessOperation.CUSTOMER_READ, "vcccc00000003-adm-a", "CUS-0001", "HX-200", 1, time),
                new RequestFacts(BusinessOperation.EXPORT, "vcccc00000003-adm-a", CompanyBlueprint.A3_TARGET,
                        CompanyBlueprint.A3_TARGET, 300, time, "TCK-NOT-THERE", "203.0.113.7"),
                new RequestFacts(BusinessOperation.ROLE_GRANT, "vcccc00000003-adm-a", CompanyBlueprint.ENGINEER_K,
                        CompanyBlueprint.A3_TARGET, 1, time, null, "10.40.12.9"));
        for (RequestFacts request : requests) {
            RecordingBusinessContextLookup recording = new RecordingBusinessContextLookup(
                    new JdbcBusinessContextLookup(database));
            new ContextLookupRules(recording).evaluate(request);
            assertThat(recording.called()).as(request.operation().name())
                    .isEqualTo(LookupPlan.forRequest(request.operation(), request.claimedTicket() != null));
        }
    }

    /** Survey L2: an export without a valid item count is refused by both rule controls, and nothing is looked up. */
    @Test
    void anExportWithoutAValidItemCountIsRefusedWithoutLookingAnythingUp() {
        new RunRegistry(database).registerPrincipal("vcccc00000004-adm-a", "run-c4", CompanyBlueprint.ADMIN_A,
                "org-c4", "tenant-c4");
        Instant time = CompanyCalendar.at(ANCHOR, TimeSlot.AFTERNOON);
        RequestFacts unknown = new RequestFacts(BusinessOperation.EXPORT, "vcccc00000004-adm-a",
                CompanyBlueprint.A3_TARGET, CompanyBlueprint.A3_TARGET, null, time, null, "10.40.12.9");
        RecordingBusinessContextLookup recording = new RecordingBusinessContextLookup(
                new JdbcBusinessContextLookup(database));

        assertThat(new ContextLookupRules(recording).evaluate(unknown).ruleId()).isEqualTo("C2-ITEMS-UNKNOWN");
        assertThat(recording.called()).isEmpty();
        assertThat(new ThresholdRules(new JdbcBusinessContextLookup(database)).evaluate(unknown).ruleId())
                .isEqualTo("C1-ITEMS-UNKNOWN");
    }

    @Test
    void lookupsAnswerFromTheCompanyAndOnlyTheRunSeesItsOverlay() {
        RunRegistry runs = new RunRegistry(database);
        BusinessContextLookup lookup = new JdbcBusinessContextLookup(database);
        runs.registerPrincipal("vaaaa00000001-adm-a", "run-a1", CompanyBlueprint.ADMIN_A, "org-a1", "tenant-a1");
        runs.registerPrincipal("vbbbb00000002-adm-a", "run-b2", CompanyBlueprint.ADMIN_A, "org-b2", "tenant-b2");
        runs.registerPrincipal("vaaaa00000001-eng-k", "run-a1", CompanyBlueprint.ENGINEER_K, "org-a1", "tenant-a1");
        Instant dawn = CompanyCalendar.at(ANCHOR, TimeSlot.DAWN);
        runs.addFacts("run-a1", new RunFacts(
                List.of(new RunFacts.Ticket("TCK-RUNA1-1", "INCIDENT", CompanyBlueprint.ADMIN_A, "pm-11",
                                CompanyBlueprint.A3_TARGET, "PROJECT_TRANSFER", "Transfer of GB-500 records",
                                dawn.minus(Duration.ofHours(1)), dawn.plus(Duration.ofHours(4)), "APPROVED"),
                        new RunFacts.Ticket("TCK-RUNA1-2", "INCIDENT", CompanyBlueprint.ADMIN_A, "pm-11", "GB-400",
                                "INCIDENT_RECOVERY", "Expired ticket", dawn.minus(Duration.ofHours(6)),
                                dawn.minus(Duration.ofHours(2)), "APPROVED")),
                List.of(new RunFacts.Approval("APR-RUNA1-1", CompanyBlueprint.ADMIN_A, "pm-11",
                        CompanyBlueprint.A3_TARGET, "PROJECT_TRANSFER", 5_000, dawn.minus(Duration.ofDays(1)),
                        dawn.plus(Duration.ofDays(1)), "APPROVED")),
                List.of()));

        assertThat(lookup.ticketCovers("vaaaa00000001-adm-a", CompanyBlueprint.A3_TARGET, BusinessOperation.EXPORT, dawn)
                .covered()).isTrue();
        assertThat(lookup.ticketCovers("vaaaa00000001-adm-a", "GB-400", BusinessOperation.EXPORT, dawn).mismatches())
                .containsExactly("VALIDITY");
        assertThat(lookup.ticketCovers("vbbbb00000002-adm-a", CompanyBlueprint.A3_TARGET, BusinessOperation.EXPORT, dawn)
                .covered()).as("another run never sees this run's ticket").isFalse();
        assertThat(lookup.approvalExists("vaaaa00000001-adm-a", CompanyBlueprint.A3_TARGET, 4_831, dawn).covered())
                .isTrue();
        assertThat(lookup.approvalExists("vaaaa00000001-adm-a", CompanyBlueprint.A3_TARGET, 5_400, dawn).mismatches())
                .containsExactly("ITEMS");
        assertThat(lookup.projectAssigned("vaaaa00000001-adm-a", CompanyBlueprint.A3_TARGET, dawn).assigned()).isFalse();
        assertThat(lookup.projectAssigned("vaaaa00000001-adm-a", CompanyBlueprint.PLM_OPERATIONS, dawn).assigned())
                .isTrue();
        assertThat(lookup.historyDays("vaaaa00000001-adm-a", CompanyBlueprint.A3_TARGET, dawn, 30).days()).isZero();
        assertThat(lookup.historyDays("vaaaa00000001-eng-k", CompanyBlueprint.K_PROJECT, dawn, 30).days())
                .isGreaterThanOrEqualTo(4);
        assertThat(lookup.oncallHas("vaaaa00000001-eng-k", dawn).onCall()).isTrue();
        assertThat(lookup.oncallHas("vaaaa00000001-adm-a", dawn).onCall()).isFalse();
        assertThat(lookup.customerOwner("vaaaa00000001-adm-a", "CUS-0001").owner()).isFalse();

        runs.deleteRun("run-a1");
        assertThat(runs.remainingRows("run-a1")).isZero();
        assertThat(runs.remainingRows("run-b2")).isEqualTo(1);
        assertThat(new CompanyRepository(database).storedFingerprint())
                .as("run rows never change the company").isEqualTo(generated.fingerprint());
    }
}
