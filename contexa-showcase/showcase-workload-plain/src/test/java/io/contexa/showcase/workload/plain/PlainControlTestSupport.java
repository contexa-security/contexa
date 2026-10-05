package io.contexa.showcase.workload.plain;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.business.client.WorkloadClient;
import io.contexa.showcase.business.client.WorkloadClient.Response;
import io.contexa.showcase.business.client.WorkloadClient.RunIdentity;
import io.contexa.showcase.business.company.CompanyCalendar;
import io.contexa.showcase.business.company.TimeSlot;
import io.contexa.showcase.business.internal.InternalContextSigner;
import io.contexa.showcase.business.run.RunFacts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Shared setup of the plain control tests: one PostgreSQL per test class, the company generated at a fixed anchor
 * date, and run principals created through the signed management API the orchestrator uses.
 */
abstract class PlainControlTestSupport {

    static final String SIGNING_KEY = "c2hvd2Nhc2UtdGVzdC1zaWduaW5nLWtleS0zMi1ieXRlcyEh";
    static final LocalDate ANCHOR = LocalDate.of(2026, 9, 30);
    static final ObjectMapper JSON = new ObjectMapper();

    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(
            DockerImageName.parse("pgvector/pgvector:pg16").asCompatibleSubstituteFor("postgres"));

    static {
        POSTGRES.start();
    }

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("showcase.internal.signing-key", () -> SIGNING_KEY);
        registry.add("showcase.company.anchor-date", ANCHOR::toString);
        registry.add("server.address", () -> "127.0.0.1");
    }

    @LocalServerPort
    int port;

    @Autowired
    JdbcTemplate jdbc;

    /** First drawing of the project; document keys are generated, so tests look them up. */
    String drawingOf(String projectKey) {
        return jdbc.queryForObject("select min(document_key) from document where project_key = ? "
                + "and document_type = 'DRAWING'", String.class, projectKey);
    }

    static Instant at(TimeSlot slot) {
        return CompanyCalendar.at(ANCHOR, slot);
    }

    /** A fresh run principal playing the employee, signed in to this control. */
    WorkloadClient signedIn(String employeeKey) throws Exception {
        return signedIn(employeeKey, RunFacts.none());
    }

    WorkloadClient signedIn(String employeeKey, RunFacts facts) throws Exception {
        return signedIn(employeeKey, facts, "10.40.12.77");
    }

    /** As {@link #signedIn(String, RunFacts)}, connecting from the given address. */
    WorkloadClient signedIn(String employeeKey, RunFacts facts, String clientIp) throws Exception {
        String runHex = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        String runId = "run-" + runHex;
        String username = "v" + runHex + "-" + employeeKey;
        String password = "Plain-" + UUID.randomUUID();
        WorkloadClient client = new WorkloadClient(URI.create("http://127.0.0.1:" + port + "/"),
                new InternalContextSigner(SIGNING_KEY),
                new RunIdentity(runId, "org-" + runHex, "tenant-" + runHex, clientIp, "PlainControlTest/1.0"),
                Duration.ofSeconds(30));
        Response registered = client.postJson("/internal/runs/" + runId + "/principals", null, null,
                JSON.writeValueAsString(Map.of("username", username, "password", password, "employeeKey", employeeKey,
                        "organizationId", "org-" + runHex, "tenantId", "tenant-" + runHex)));
        assertThat(registered.status()).as(registered.text()).isEqualTo(200);
        if (!facts.equals(RunFacts.none())) {
            Response added = client.postJson("/internal/runs/" + runId + "/facts", null, null,
                    JSON.findAndRegisterModules().writeValueAsString(facts));
            assertThat(added.status()).as(added.text()).isEqualTo(200);
        }
        Response login = client.postJson("/api/login", UUID.randomUUID().toString(), at(TimeSlot.MORNING),
                JSON.writeValueAsString(Map.of("username", username, "password", password)));
        assertThat(login.status()).as(login.text()).isEqualTo(200);
        return client;
    }

    static JsonNode json(Response response) throws Exception {
        return JSON.readTree(response.body());
    }
}
