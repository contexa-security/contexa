package io.contexa.showcase.portal.ops;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.benchmark.BenchmarkController;
import io.contexa.showcase.portal.benchmark.DecisionQuality;
import io.contexa.showcase.portal.benchmark.DecisionQualityService;
import io.contexa.showcase.portal.orchestrator.WorkloadAdmin;
import io.contexa.showcase.portal.reactivity.PromptQualityPublications;
import io.contexa.showcase.portal.reactivity.PromptQualityView;
import io.contexa.showcase.portal.reactivity.ReactivityService;
import io.contexa.showcase.portal.reactivity.RunLevelReaction;
import io.contexa.showcase.portal.scenario.ScenarioCatalog;
import io.contexa.showcase.portal.scenario.ScenarioDefinition;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

/**
 * W7-13: the operator publishes what the benchmark's prompt quality tab shows for a measurement setting, on the
 * operator port: the harness batches and the measurement protocol, counted now with the harness metrics (W6-1) and
 * the decision quality (W6-2) and stored; visitors see nothing until then. Both read the sealed prompts through
 * control D, so it answers only where the portal has control D. N-PQ-1: each harness figure has its batch
 * (deliveryBatch, reactionBatch, injectionBatch; batch is the default of each, the one-batch call as before), an
 * earlier measurement (baselineProtocol) gives the U6-4 comparison, and the raw data is stored with the view (U6-5).
 */
@RestController
@ConditionalOnProperty(prefix = "showcase.portal.ops", name = "port")
public class PromptQualityOpsController {

    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectProvider<WorkloadAdmin> admin;
    private final ObjectProvider<ReactivityService> reactivity;
    private final PromptQualityPublications publications;
    private final ObjectMapper json;
    private final ObjectProvider<ScenarioCatalog> catalog;

    public PromptQualityOpsController(NamedParameterJdbcTemplate jdbc, ObjectProvider<WorkloadAdmin> admin,
                                      ObjectProvider<ReactivityService> reactivity,
                                      PromptQualityPublications publications, ObjectMapper json,
                                      ObjectProvider<ScenarioCatalog> catalog) {
        this.jdbc = jdbc;
        this.admin = admin;
        this.reactivity = reactivity;
        this.publications = publications;
        this.json = json;
        this.catalog = catalog;
    }

    @PostMapping("/ops/prompt-quality")
    public ResponseEntity<Object> publish(@RequestParam("setting") String setting,
                                          @RequestParam(name = "batch", required = false) String batch,
                                          @RequestParam(name = "deliveryBatch", required = false)
                                          String deliveryBatch,
                                          @RequestParam(name = "reactionBatch", required = false)
                                          String reactionBatch,
                                          @RequestParam(name = "injectionBatch", required = false)
                                          String injectionBatch,
                                          @RequestParam("protocol") String protocol,
                                          @RequestParam(name = "baselineProtocol", required = false)
                                          String baselineProtocol) throws IOException {
        ReactivityService service = reactivity.getIfAvailable();
        WorkloadAdmin workloadAdmin = admin.getIfAvailable();
        ScenarioCatalog cases = catalog.getIfAvailable();
        if (service == null || workloadAdmin == null || (baselineProtocol != null && cases == null)) {
            return ResponseEntity.notFound().build();
        }
        if (!BenchmarkController.SETTING.matcher(setting).matches()) {
            return ResponseEntity.badRequest().body(Map.of("reason", PromptQualityPublications.UNKNOWN_SETTING));
        }
        PromptQualityView.Batches batches = PromptQualityView.Batches.of(batch, deliveryBatch, reactionBatch,
                injectionBatch);
        if (batches.missing() != null) {
            return ResponseEntity.badRequest().body(Map.of("reason", PromptQualityPublications.MISSING_BATCH,
                    "metric", batches.missing()));
        }
        Optional<PromptQualityPublications.Refusal> refused = publications.refusal(setting, batches, protocol)
                .or(() -> baselineProtocol == null ? Optional.empty() : publications.baselineRefusal(baselineProtocol));
        if (refused.isPresent()) {
            return ResponseEntity.badRequest().body(body(refused.get()));
        }
        PromptQualityView.Comparison comparison = null;
        if (baselineProtocol != null) {
            Function<String, String> classOf = key -> cases.find(key).map(ScenarioDefinition::oracle)
                    .map(ScenarioDefinition.Oracle::classification).orElse(null);
            comparison = PromptQualityView.Comparison.of(baselineProtocol,
                    RunLevelReaction.bundle(jdbc, baselineProtocol), RunLevelReaction.bundle(jdbc, protocol),
                    RunLevelReaction.count(RunLevelReaction.steps(jdbc, baselineProtocol), classOf),
                    RunLevelReaction.count(RunLevelReaction.steps(jdbc, protocol), classOf));
        }
        PromptQualityView view = view(service, publications.measuredAt(batches, protocol), setting, batches, protocol,
                new DecisionQualityService(jdbc, workloadAdmin, json).of(protocol), comparison);
        // The stored view names every batch and holds the raw data; the row's batch_id keeps the reaction batch.
        publications.publish(setting, batches.reaction(), protocol, json.writeValueAsString(view), Instant.now());
        return ResponseEntity.ok(view);
    }

    /**
     * N-PQ-1: each harness figure from its own batch's report, invariance from the protocol's repetitions, with the
     * U6-4 comparison and the U6-5 raw data.
     */
    static PromptQualityView view(ReactivityService service, Instant measuredAt, String setting,
                                  PromptQualityView.Batches batches, String protocol, DecisionQuality quality,
                                  PromptQualityView.Comparison comparison) throws IOException {
        Map<String, ReactivityService.Report> reports = new HashMap<>();
        for (String batch : batches.byMetric().values()) {
            if (!reports.containsKey(batch)) {
                reports.put(batch, service.report(batch, null));
            }
        }
        return PromptQualityView.of(measuredAt, setting, batches, protocol, reports.get(batches.delivery()),
                reports.get(batches.reaction()), reports.get(batches.injection()), service.report(null, protocol),
                quality, comparison);
    }

    /** The refusal as the operator reads it: the reason, and for a source the figure and the source. */
    private static Map<String, Object> body(PromptQualityPublications.Refusal refusal) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("reason", refusal.reason());
        if (refusal.metric() != null) {
            body.put("metric", refusal.metric());
            body.put("source", refusal.source());
        }
        return body;
    }
}
