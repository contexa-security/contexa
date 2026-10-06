package io.contexa.showcase.portal.live;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.combination.Combination;
import io.contexa.showcase.portal.combination.CombinationService;
import io.contexa.showcase.portal.combination.CombinationStore;
import io.contexa.showcase.portal.orchestrator.Measurements;
import io.contexa.showcase.portal.orchestrator.RunOrchestrator.RunSummary;
import io.contexa.showcase.portal.template.TemplateCurrency;
import io.contexa.showcase.portal.template.TemplateStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.net.URI;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Deck p.28 on the gate in front of new live runs (P4-BE-03, docs/showcase/체험우선-설계.md): every press runs live,
 * a failed human check or a spent allotment refuses before any count is taken and carries the cell's record, and a run
 * that fails gives its count back.
 */
@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest
class LiveGateIntegrationTest {

    @Container
    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(
            DockerImageName.parse("pgvector/pgvector:pg16").asCompatibleSubstituteFor("postgres"));

    private static final String SIGNING_KEY = randomKey();
    private static final String ADDRESS = "198.51.100.9";

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("showcase.internal.signing-key", () -> SIGNING_KEY);
    }

    @Autowired
    NamedParameterJdbcTemplate jdbc;

    private final CountDownLatch release = new CountDownLatch(1);
    private final List<String> kept = new CopyOnWriteArrayList<>();
    private final List<String> runStatus = new ArrayList<>(List.of("COMPLETED"));
    private LiveRuns live;
    private final AtomicBoolean templateCurrent = new AtomicBoolean(true);
    private final LiveGateWatch watch = new LiveGateWatch(1000, Clock.systemUTC());

    @AfterEach
    void close() {
        release.countDown();
        if (live != null) {
            live.close();
        }
    }

    @Test
    void everyPressRunsLiveEvenWhenTheCellHasARecord() throws Exception {
        LiveQuota quota = quota(2);
        LiveGate gate = gate(cells(Optional.of("run-stored")), turnstileOff(), allotment(30), quota);

        LiveGate.Outcome outcome = gate.combination("v1", ADDRESS, cell(), null);

        assertThat(outcome).isInstanceOf(LiveGate.Started.class);
        assertThat(quota.remaining("v1")).isEqualTo(1);
        assertThat(watch.status().outcomes()).isEqualTo(Map.of("STARTED", 1L));
    }

    @Test
    void aRefusedCellCarriesItsRecordToBeShownAsARecord() throws Exception {
        LiveQuota quota = quota(2);
        LiveGate gate = gate(cells(Optional.of("run-stored")), turnstileOff(), allotment(0), quota);

        LiveGate.Outcome outcome = gate.combination("v1", ADDRESS, cell(), null);

        assertThat(outcome).isInstanceOf(LiveGate.Refused.class);
        LiveGate.Refused refused = (LiveGate.Refused) outcome;
        assertThat(refused.reason()).isEqualTo("ALLOTMENT");
        assertThat(refused.fallback().runId()).isEqualTo("run-stored");
        assertThat(quota.remaining("v1")).isEqualTo(2);
        assertThat(live.running()).isZero();
    }

    @Test
    void aFailedHumanCheckOrASpentAllotmentRefusesBeforeAnyCount() throws Exception {
        LiveQuota quota = quota(2);
        TurnstileVerifier unreachable = new TurnstileVerifier(true, "site", "real-secret", Set.of("demo.ctxa.ai"),
                URI.create("http://127.0.0.1:1/siteverify"), false, new ObjectMapper());

        LiveGate.Outcome check = gate(cells(Optional.empty()), unreachable, allotment(30), quota)
                .combination("v1", ADDRESS, cell(), "token");
        live.close();
        LiveGate.Outcome spent = gate(cells(Optional.empty()), turnstileOff(), allotment(0), quota)
                .combination("v1", ADDRESS, cell(), null);

        assertThat(check).isEqualTo(new LiveGate.Refused("TURNSTILE_UNAVAILABLE", null));
        assertThat(spent).isEqualTo(new LiveGate.Refused("ALLOTMENT", null));
        assertThat(quota.remaining("v1")).isEqualTo(2);
        assertThat(watch.status().refusalsThisHour()).isEqualTo(Map.of("TURNSTILE_UNAVAILABLE", 1L, "ALLOTMENT", 1L));
    }

    @Test
    void aNewCellRunsOnceKeepsItsRecordAndCountsOnce() throws Exception {
        LiveQuota quota = quota(1);
        LiveGate gate = gate(cells(Optional.empty()), turnstileOff(), allotment(30), quota);

        LiveGate.Outcome first = gate.combination("v1", ADDRESS, cell(), null);
        LiveGate.Outcome again = gate.combination("v1", ADDRESS, cell(), null);
        LiveGate.Outcome other = gate.combination("v2", "192.0.2.1", cell(), null);

        assertThat(first).isInstanceOf(LiveGate.Started.class);
        assertThat(again).as("the visitor's run in progress").isInstanceOf(LiveGate.Started.class);
        assertThat(((LiveGate.Started) again).run()).isSameAs(((LiveGate.Started) first).run());
        assertThat(quota.remaining("v1")).isZero();
        assertThat(other).isInstanceOf(LiveGate.Started.class);
        release.countDown();
        await(() -> kept.size() == 2);
        assertThat(kept).containsOnly("run-" + cell().key());
        assertThat(gate.combination("v1", ADDRESS, Combination.parse("eng-k.DAWN.40.NONE.USUAL"), null))
                .isEqualTo(new LiveGate.Refused("VISITOR_LIMIT", null));
        assertThat(watch.status().outcomes()).isEqualTo(Map.of("STARTED", 2L, "RESUMED", 1L, "VISITOR_LIMIT", 1L));
    }

    @Test
    void noRunStartsWithoutATemplateLearnedUnderTheVersionsInForce() throws Exception {
        templateCurrent.set(false);
        LiveQuota quota = quota(1);
        LiveGate gate = gate(cells(Optional.empty()), turnstileOff(), allotment(30), quota);

        assertThat(gate.combination("v1", ADDRESS, cell(), null)).isEqualTo(new LiveGate.Refused("TEMPLATE", null));
        assertThat(quota.remaining("v1")).as("a refusal takes nothing").isEqualTo(1);
        assertThat(live.running()).isZero();
        assertThat(watch.status().outcomes()).isEqualTo(Map.of("TEMPLATE", 1L));
    }

    @Test
    void finishedRunsAreCountedWithTheirUnresolvedDecisions() throws Exception {
        LiveGate gate = gate(cells(Optional.empty()), turnstileOff(), allotment(30), quota(5));

        assertThat(gate.combination("v1", ADDRESS, cell(), null)).isInstanceOf(LiveGate.Started.class);
        release.countDown();
        await(() -> watch.status().finishedThisHour() == 1);
        assertThat(watch.status().unresolvedThisHour()).isZero();
    }

    @Test
    void aRunThatFailsGivesItsCountBack() throws Exception {
        runStatus.set(0, "FAILED");
        LiveQuota quota = quota(1);
        LiveGate gate = gate(cells(Optional.empty()), turnstileOff(), allotment(30), quota);

        assertThat(gate.combination("v1", ADDRESS, cell(), null)).isInstanceOf(LiveGate.Started.class);
        release.countDown();
        await(() -> quota.remaining("v1") == 1);
        assertThat(kept).isEmpty();
    }

    private LiveGate gate(CombinationService cells, TurnstileVerifier turnstile, LiveAllotment allotment,
                          LiveQuota quota) {
        live = new LiveRuns((scenario, forced, responder, listener) -> {
            listener.runStarted("run-" + scenario.key());
            try {
                release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return new RunSummary("run-" + scenario.key(), scenario.key(), "u", "org", runStatus.get(0), null,
                    List.of());
        }, new LiveRuns.Settings(5, 5, 0, Duration.ofMinutes(30), Duration.ofMinutes(15), List.of(), null),
                Clock.systemUTC());
        return new LiveGate(cells, turnstile, allotment, quota, live, watch, templates());
    }

    /** The current template of any employee, or none when {@link #templateCurrent} is false. */
    private TemplateCurrency templates() {
        return new TemplateCurrency(null, null, Clock.systemUTC()) {
            @Override
            public Optional<TemplateStore.ReadyTemplate> current(String employeeKey) {
                return templateCurrent.get()
                        ? Optional.of(new TemplateStore.ReadyTemplate("tpl-" + employeeKey, employeeKey, null,
                        Instant.now()))
                        : Optional.empty();
            }
        };
    }

    /** The grid's stored runs without control D: the version key is fixed and a kept run is only noted. */
    private CombinationService cells(Optional<String> storedRun) {
        return new CombinationService(null, null, null, new CombinationStore(jdbc), null, null, Clock.systemUTC()) {
            @Override
            public String versionKey(String employee) {
                return "k".repeat(64);
            }

            @Override
            public Optional<CombinationStore.RecordRow> record(Combination combination) {
                return storedRun.map(run -> new CombinationStore.RecordRow(combination.key(), 1, "k".repeat(64), run,
                        null, Instant.now()));
            }

            @Override
            public CombinationView view(Combination combination) {
                return new CombinationView(combination.key(), combination.employee(), combination.slot(),
                        combination.items(), combination.ticket(), combination.device(), true, Instant.now(),
                        storedRun.orElse(null), null);
            }

            @Override
            public boolean keep(Combination combination, String versionKey, String runId, String visitorHash) {
                kept.add(runId);
                return true;
            }
        };
    }

    private LiveQuota quota(int visitorDaily) {
        jdbc.getJdbcTemplate().update("delete from live_quota");
        return new LiveQuota(jdbc, SIGNING_KEY, visitorDaily, 30, Clock.systemUTC());
    }

    private LiveAllotment allotment(double monthlyBudget) {
        return new LiveAllotment(jdbc, new Measurements.Prices(0.05, 0.40, 0.02, "test"), monthlyBudget,
                Clock.systemUTC());
    }

    private static TurnstileVerifier turnstileOff() {
        return new TurnstileVerifier(false, "", "", Set.of(), TurnstileVerifier.SITEVERIFY, false, new ObjectMapper());
    }

    private static Combination cell() {
        return Combination.parse("adm-a.DAWN.4831.MATCH.USUAL");
    }

    private static void await(BooleanSupplier condition) throws InterruptedException {
        long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (System.nanoTime() < until) {
            if (condition.getAsBoolean()) {
                return;
            }
            Thread.sleep(10);
        }
        throw new AssertionError("condition not reached");
    }

    private static String randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
