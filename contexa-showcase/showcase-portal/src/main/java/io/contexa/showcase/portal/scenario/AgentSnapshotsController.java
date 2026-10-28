package io.contexa.showcase.portal.scenario;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * docs/agent Agent중심-화면 AC-5 (D-6): the reference agent runs frozen as files under {@code agent-runs/}, which the
 * screens show as stored real runs without any model call. Each file is the portal's own answer for the run and its
 * case, read once from a running portal ({@code web/scripts/snapshot-agent-runs.mjs}); the files and their index are
 * the only things this serves, so the database may be cleaned and a screen still has a real run to show.
 */
@RestController
public class AgentSnapshotsController {

    private static final Pattern LABEL = Pattern.compile("[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*");

    private final ObjectMapper json;
    private final List<Map<String, Object>> index;
    private final Set<String> labels;

    public AgentSnapshotsController(ObjectMapper json) {
        this.json = json;
        this.index = read("/agent-runs/index.json", new TypeReference<List<Map<String, Object>>>() {
        });
        this.labels = index.stream().map(entry -> (String) entry.get("label")).collect(Collectors.toUnmodifiableSet());
    }

    /** The frozen runs: label, run, case, kind and why it was chosen. */
    @GetMapping("/api/agent-snapshots")
    public List<Map<String, Object>> index() {
        return index;
    }

    /** One frozen run, as it was read. */
    @GetMapping("/api/agent-snapshots/{label}")
    public ResponseEntity<Map<String, Object>> snapshot(@PathVariable("label") String label) {
        if (!LABEL.matcher(label).matches()) {
            return ResponseEntity.badRequest().build();
        }
        if (!labels.contains(label)) {
            return ResponseEntity.notFound().build();
        }
        Map<String, Object> snapshot = new LinkedHashMap<>(read("/agent-runs/" + label + ".json",
                new TypeReference<Map<String, Object>>() {
                }));
        snapshot.put("summary", summary(json.valueToTree(snapshot.get("run"))));
        return ResponseEntity.ok(snapshot);
    }

    /**
     * What the run's requests did at control D, counted from the stored steps (docs/agent Agent중심-화면 AS-10): the
     * requests, those delivered and refused, the refusals that only said the analysis was busy, the requests with a
     * verdict of their own, the model calls the verdicts made, the step control D first stopped the work at, and what
     * it still delivered after that step.
     */
    static Map<String, Object> summary(JsonNode run) {
        int requests = 0;
        int delivered = 0;
        int busy = 0;
        int withVerdict = 0;
        int modelCalls = 0;
        JsonNode first = run.path("proof").path("controls").path("D").path("firstStopStep");
        Integer firstStop = first.isNumber() ? first.asInt() : null;
        int deliveredAfter = 0;
        for (JsonNode step : run.path("steps")) {
            requests++;
            JsonNode outcome = step.path("outcomes").path("D");
            boolean passed = "DELIVERED".equals(outcome.path("outcome").asText());
            if (passed) {
                delivered++;
                if (firstStop != null && step.path("stepNo").asInt() > firstStop) {
                    deliveredAfter++;
                }
            }
            if ("ZERO_TRUST_ANALYSIS_BUSY".equals(outcome.path("rule").asText())) {
                busy++;
            }
            JsonNode decision = step.path("decision");
            if (decision.hasNonNull("final_action")) {
                withVerdict++;
            }
            modelCalls += decision.path("model_calls").asInt(0);
        }
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("requests", requests);
        summary.put("delivered", delivered);
        summary.put("refused", requests - delivered);
        summary.put("busy", busy);
        summary.put("withVerdict", withVerdict);
        summary.put("modelCalls", modelCalls);
        summary.put("firstStopStep", firstStop);
        summary.put("deliveredAfterFirstStop", deliveredAfter);
        return summary;
    }

    private <T> T read(String resource, TypeReference<T> type) {
        try (InputStream stream = AgentSnapshotsController.class.getResourceAsStream(resource)) {
            if (stream == null) {
                throw new IllegalStateException("Missing agent snapshot resource " + resource);
            }
            return json.readValue(stream, type);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
