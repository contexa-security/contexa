package io.contexa.showcase.portal.ops;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.contexa.showcase.portal.benchmark.BenchmarkService;
import io.contexa.showcase.portal.benchmark.BenchmarkView;
import io.contexa.showcase.portal.benchmark.DecisionQuality;
import io.contexa.showcase.portal.reactivity.InjectionEvaluator;
import io.contexa.showcase.portal.reactivity.InvarianceEvaluator;
import io.contexa.showcase.portal.reactivity.PromptQualityController;
import io.contexa.showcase.portal.reactivity.PromptQualityPublications;
import io.contexa.showcase.portal.reactivity.PromptQualityView;
import io.contexa.showcase.portal.reactivity.ReactionEvaluator;
import io.contexa.showcase.portal.reactivity.ReactivityService;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * N-PQ-1 (P8): the operator's publication of the prompt quality takes each harness figure from the batch it was
 * measured in (delivery, reaction and injection in batches of their own, plan 8.4, 8.5, 8.7), refuses a batch of
 * another setting naming its figure, dates the publication by the latest of its sources, keeps what the one-batch call
 * published, stores the raw data (U6-5), and the visitor API answers the view as it was published: the screen's read
 * without the raw data, the raw data address with it.
 */
class PromptQualityOpsControllerTest {

    private static final String SETTING = "f".repeat(64);
    private static final String PROTOCOL = "proto-1";
    private static final BenchmarkView.Rate DELIVERED = BenchmarkService.rate(10, 11);
    /** The delivery the lab runs of the reaction batch give (the w72 publication's 93/348). */
    private static final BenchmarkView.Rate LAB_DELIVERED = BenchmarkService.rate(93, 348);
    private static final BenchmarkView.Rate DIRECTION = BenchmarkService.rate(110, 116);
    private static final BenchmarkView.Rate OTHER_DIRECTION = BenchmarkService.rate(1, 4);
    private static final BenchmarkView.Rate KEPT = BenchmarkService.rate(60, 60);
    private static final BenchmarkView.Rate UNCHANGED = BenchmarkService.rate(5, 6);
    private static final BenchmarkView.Rate FEW_INJECTED = BenchmarkService.rate(1, 3);
    private static final BenchmarkView.Rate FIRST_STEP = BenchmarkService.rate(25, 26);
    private static final BenchmarkView.Rate DECISIONS = BenchmarkService.rate(12, 13);
    private static final DecisionQuality QUALITY = new DecisionQuality(BenchmarkService.rate(30, 39),
            BenchmarkService.rate(11, 13), BenchmarkService.rate(35, 36), 0);
    private static final Instant MEASURED = Instant.parse("2026-10-17T03:00:00Z");
    private static final PromptQualityView.Batches BATCHES = PromptQualityView.Batches.of(null, "p8v20-delivery",
            "p8v20-reaction", "p8v20-injection");
    private static final PromptQualityView.Comparison COMPARISON = new PromptQualityView.Comparison("protocol-v19",
            "2026.10.16-v19.20", "2026.10.16-v20.24", BenchmarkService.rate(67, 90), BenchmarkService.rate(80, 80),
            BenchmarkService.rate(8, 66), BenchmarkService.rate(2, 75));

    @Test
    void eachHarnessFigureIsReadFromTheReportOfItsOwnBatch() throws Exception {
        Reports reports = new Reports();

        PromptQualityView view = PromptQualityOpsController.view(reports, MEASURED, SETTING, BATCHES, PROTOCOL,
                QUALITY, COMPARISON);

        assertThat(view.delivery()).as("the delivery batch, not the lab runs of the reaction batch")
                .isEqualTo(DELIVERED);
        assertThat(view.reaction().direction()).isEqualTo(DIRECTION);
        assertThat(view.injection().unchanged()).isEqualTo(UNCHANGED);
        assertThat(view.invariance().firstStepFacts()).as("the protocol's repetitions").isEqualTo(FIRST_STEP);
        assertThat(view.raw().delivery().delivered()).as("U6-5: the raw data of the same sources").isEqualTo(DELIVERED);
        assertThat(view.raw().injection().unchanged()).isEqualTo(UNCHANGED);
        assertThat(view.comparison()).isEqualTo(COMPARISON);
        assertThat(reports.asked).containsExactly("p8v20-delivery|null", "p8v20-reaction|null",
                "p8v20-injection|null", "null|proto-1");
    }

    @Test
    void theOneBatchCallPublishesTheFiguresItPublishedBefore() throws Exception {
        PromptQualityView.Batches one = PromptQualityView.Batches.of("w7-2", null, null, null);

        PromptQualityView view = PromptQualityOpsController.view(new Reports(), MEASURED, SETTING, one, PROTOCOL,
                QUALITY, null);
        PromptQualityView before = PromptQualityView.of(MEASURED, SETTING, "w7-2", PROTOCOL,
                new Reports().report("w7-2", PROTOCOL), QUALITY);

        assertThat(view.batch()).isEqualTo("w7-2");
        assertThat(List.of(view.delivery(), view.reaction(), view.invariance(), view.injection(), view.accuracy()))
                .isEqualTo(List.of(before.delivery(), before.reaction(), before.invariance(), before.injection(),
                        before.accuracy()));
    }

    @Test
    void aBatchOfAnotherSettingIsRefusedNamingItsFigure() {
        PromptQualityPublications refusing = new Publications(Map.of("p8v20-injection",
                PromptQualityPublications.BATCH_NOT_IN_SETTING), null, Map.of());

        assertThat(refusing.refusal(SETTING, BATCHES, PROTOCOL)).contains(new PromptQualityPublications.Refusal(
                PromptQualityPublications.BATCH_NOT_IN_SETTING, "injection", "p8v20-injection"));
        assertThat(new Publications(Map.of(), PromptQualityPublications.PROTOCOL_UNFINISHED, Map.of())
                .refusal(SETTING, BATCHES, PROTOCOL)).as("a protocol reason names no figure")
                .contains(new PromptQualityPublications.Refusal(PromptQualityPublications.PROTOCOL_UNFINISHED,
                        null, null));
        assertThat(new Publications(Map.of(), null, Map.of()).refusal(SETTING, BATCHES, PROTOCOL)).isEmpty();
    }

    @Test
    void thePublicationIsDatedByTheLatestOfItsSources() {
        Publications publications = new Publications(Map.of(), null, Map.of(
                "p8v20-delivery", Instant.parse("2026-10-17T02:10:00Z"),
                "p8v20-reaction", Instant.parse("2026-10-17T02:00:00Z"),
                "p8v20-injection", Instant.parse("2026-10-17T01:50:00Z")));

        assertThat(publications.measuredAt(BATCHES, PROTOCOL)).isEqualTo(Instant.parse("2026-10-17T02:10:00Z"));
    }

    @Test
    void visitorsReadTheViewAsItWasPublished() throws Exception {
        ObjectMapper json = new ObjectMapper().findAndRegisterModules();
        Publications publications = new Publications(Map.of(), null, Map.of());
        PromptQualityView view = PromptQualityOpsController.view(new Reports(), MEASURED, SETTING, BATCHES, PROTOCOL,
                QUALITY, COMPARISON);
        publications.publish(SETTING, BATCHES.reaction(), PROTOCOL, json.writeValueAsString(view), MEASURED);

        PromptQualityController visitors = new PromptQualityController(publications, json);
        JsonNode download = visitors.promptQuality(SETTING, true).getBody();
        JsonNode screen = visitors.promptQuality(SETTING, false).getBody();

        JsonNode stored = json.readTree(json.writeValueAsString(view));
        assertThat(download).as("U6-5: the raw data address gives the record as published").isEqualTo(stored);
        assertThat(download.path("raw").path("reaction").path("direction").path("hits").asInt()).isEqualTo(110);
        assertThat(screen.has("raw")).as("U6-5: the screen's read carries no raw data").isFalse();
        ((ObjectNode) stored).remove("raw");
        assertThat(screen).as("the screen's read is the published view without its raw data").isEqualTo(stored);
        assertThat(screen.path("batches").path("injection").asText()).isEqualTo("p8v20-injection");
        assertThat(screen.path("delivery").path("total").asInt()).isEqualTo(11);
        assertThat(screen.path("comparison").path("attackBefore").path("hits").asInt()).isEqualTo(67);
    }

    /**
     * The reports of the batches, each holding figures of every kind (the reaction batch's lab runs give a delivery
     * too), and the protocol's repetitions; the calls are kept in order.
     */
    private static final class Reports extends ReactivityService {

        private final List<String> asked = new ArrayList<>();

        Reports() {
            super(null, null, null, null, null, null);
        }

        @Override
        public Report report(String batchId, String protocolId) {
            asked.add(batchId + "|" + protocolId);
            InvarianceEvaluator.Invariance repeated = protocolId == null ? null : new InvarianceEvaluator.Invariance(
                    FIRST_STEP, FIRST_STEP, Map.of(), DECISIONS, 0, List.of());
            if (batchId == null) {
                return new Report(null, protocolId, null, null, repeated, null);
            }
            boolean all = batchId.startsWith("w7");
            boolean delivery = all || batchId.contains("delivery");
            boolean reaction = all || batchId.contains("reaction");
            boolean injection = all || batchId.contains("injection");
            return new Report(batchId, protocolId,
                    new BatchDelivery(delivery ? DELIVERED : LAB_DELIVERED, Map.of(), 0, List.of()),
                    new ReactionEvaluator.Summary(4, 0, KEPT, reaction ? DIRECTION : OTHER_DIRECTION, KEPT, List.of(),
                            List.of(), List.of(), List.of()),
                    repeated, new InjectionEvaluator.Summary(6, 0, injection ? UNCHANGED : FEW_INJECTED, List.of()));
        }
    }

    /** The publications without a database: single-batch refusals and dates as given, the stored views in a map. */
    private static final class Publications extends PromptQualityPublications {

        private final Map<String, String> batchRefusals;
        private final String protocolRefusal;
        private final Map<String, Instant> batchDates;
        private final Map<String, String> stored = new HashMap<>();

        Publications(Map<String, String> batchRefusals, String protocolRefusal, Map<String, Instant> batchDates) {
            super(null);
            // Copies that answer a batch not given (null) with nothing, as the database does.
            this.batchRefusals = new HashMap<>(batchRefusals);
            this.protocolRefusal = protocolRefusal;
            this.batchDates = new HashMap<>(batchDates);
        }

        @Override
        public Optional<String> refusal(String setting, String batch, String protocol) {
            return protocolRefusal != null ? Optional.of(protocolRefusal)
                    : Optional.ofNullable(batchRefusals.get(batch));
        }

        @Override
        public Instant measuredAt(String batch, String protocol) {
            return batchDates.get(batch);
        }

        @Override
        public void publish(String setting, String batch, String protocol, String quality, Instant at) {
            stored.put(setting, quality);
        }

        /** The record as stored, raw data included: the visitor API must leave it out of the screen's read itself. */
        @Override
        public Optional<String> published(String setting) {
            return Optional.ofNullable(stored.get(setting));
        }

        @Override
        public Optional<String> publishedWithRaw(String setting) {
            return Optional.ofNullable(stored.get(setting));
        }
    }
}
