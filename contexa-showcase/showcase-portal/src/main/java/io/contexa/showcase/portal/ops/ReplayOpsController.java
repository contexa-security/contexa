package io.contexa.showcase.portal.ops;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.orchestrator.WorkloadAdmin;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

/**
 * V-2.2 of the v21 plan: the replays of recorded decisions with a chosen bundle (operator port). For each run step the
 * portal finds the decision's request, the template the run cloned and the decision it recorded; control D draws the
 * decision's sealed prompt again with the bundle and asks once. The rows put the recorded decision next to the
 * replayed one. Nothing is applied, recorded for a run or learned. Like the other operator controllers it answers only
 * on the operator port, and only where the portal has control D.
 */
@RestController
@ConditionalOnProperty(prefix = "showcase.portal.ops", name = "port")
public class ReplayOpsController {

    private static final Pattern RUN_ID = Pattern.compile("run-[0-9a-f]{12}");
    private static final Pattern BUNDLE = Pattern.compile("[0-9]{4}\\.[0-9]{2}\\.[0-9]{2}-v[0-9.]+");
    private static final int MAX_STEPS = 80;

    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectProvider<WorkloadAdmin> admin;
    private final ObjectMapper json;
    private final ExecutorService executor = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "showcase-replays");
        thread.setDaemon(true);
        return thread;
    });
    private final Map<String, ReplayJob> jobs = new ConcurrentHashMap<>();

    public ReplayOpsController(NamedParameterJdbcTemplate jdbc, ObjectProvider<WorkloadAdmin> admin,
                               ObjectMapper json) {
        this.jdbc = jdbc;
        this.admin = admin;
        this.json = json;
    }

    /** One run step to replay. */
    public record Step(String runId, int stepNo) {
    }

    /**
     * The bundle to draw with and the run steps to replay, in their order, and the models to ask the second pass with
     * when a replay answers ESCALATE (판정층 7절; none asks no second pass).
     */
    public record ReplayBatch(String bundleVersion, List<Step> steps, List<String> secondPassModels) {
    }

    private static final Pattern MODEL = Pattern.compile("[a-z0-9][a-z0-9.\\-]{0,63}");
    private static final int MAX_SECOND_PASS_MODELS = 3;

    /** A replay job: its rows so far and whether it ended. */
    public record ReplayJob(String jobId, String bundleVersion, int steps, String status, Instant startedAt,
                            Instant finishedAt, List<Map<String, Object>> rows) {
    }

    @PostMapping("/ops/replays")
    public ResponseEntity<ReplayJob> replay(@RequestBody ReplayBatch batch) {
        if (batch == null || batch.bundleVersion() == null || !BUNDLE.matcher(batch.bundleVersion()).matches()
                || batch.steps() == null || batch.steps().isEmpty() || batch.steps().size() > MAX_STEPS
                || batch.steps().stream().anyMatch(step -> step == null || step.runId() == null
                || !RUN_ID.matcher(step.runId()).matches() || step.stepNo() < 1)
                || batch.secondPassModels() != null && (batch.secondPassModels().size() > MAX_SECOND_PASS_MODELS
                || batch.secondPassModels().stream().anyMatch(model -> model == null || !MODEL.matcher(model).matches()))) {
            return ResponseEntity.badRequest().build();
        }
        WorkloadAdmin workloadAdmin = admin.getIfAvailable();
        if (workloadAdmin == null) {
            return ResponseEntity.notFound().build();
        }
        String jobId = "replay-job-" + UUID.randomUUID();
        List<Map<String, Object>> rows = Collections.synchronizedList(new ArrayList<>());
        jobs.put(jobId, new ReplayJob(jobId, batch.bundleVersion(), batch.steps().size(), "RUNNING", Instant.now(), null,
                rows));
        executor.submit(() -> {
            for (Step step : batch.steps()) {
                rows.add(row(workloadAdmin, step, batch.bundleVersion(), batch.secondPassModels()));
            }
            jobs.computeIfPresent(jobId, (id, job) -> new ReplayJob(id, job.bundleVersion(), job.steps(), "DONE",
                    job.startedAt(), Instant.now(), job.rows()));
        });
        return ResponseEntity.ok(jobs.get(jobId));
    }

    @GetMapping("/ops/replays/{jobId}")
    public ResponseEntity<ReplayJob> job(@PathVariable("jobId") String jobId) {
        ReplayJob job = jobs.get(jobId);
        return job == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(job);
    }

    /** The replay of one run step next to the decision the run recorded. */
    private Map<String, Object> row(WorkloadAdmin workload, Step step, String bundleVersion,
                                    List<String> secondPassModels) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("runId", step.runId());
        row.put("stepNo", step.stepNo());
        try {
            List<Map<String, Object>> found = jdbc.queryForList("""
                            select rd.request_id::text as request_id, r.scenario_key, rd.final_action, rd.reasoning,
                                   r.template_id, t.snapshot::text as snapshot
                              from run_decision rd
                              join run r on r.run_id = rd.run_id
                              left join engine_template t on t.template_id = r.template_id
                             where rd.run_id = :run and rd.step_no = :step
                            """,
                    new MapSqlParameterSource("run", step.runId()).addValue("step", step.stepNo()));
            if (found.isEmpty()) {
                row.put("failure", "NO_RECORDED_DECISION");
                return row;
            }
            Map<String, Object> recorded = found.get(0);
            row.put("scenarioKey", recorded.get("scenario_key"));
            row.put("requestId", recorded.get("request_id"));
            row.put("recordedAction", recorded.get("final_action"));
            row.put("recordedReason", recorded.get("reasoning"));
            row.put("templateId", recorded.get("template_id"));
            JsonNode snapshot = recorded.get("snapshot") instanceof String text ? json.readTree(text) : null;
            if (snapshot == null) {
                row.put("failure", "NO_TEMPLATE_SNAPSHOT");
                return row;
            }
            Map<String, Object> request = new LinkedHashMap<>();
            request.put("bundleVersion", bundleVersion);
            request.put("userBaseline", text(snapshot.path("userBaseline")));
            request.put("organizationBaseline", text(snapshot.path("organizationBaseline")));
            if (secondPassModels != null && !secondPassModels.isEmpty()) {
                request.put("secondPassModels", secondPassModels);
            }
            Optional<JsonNode> replayed = workload.replay(String.valueOf(recorded.get("request_id")), request);
            if (replayed.isEmpty()) {
                row.put("failure", "NOT_SEALED");
                return row;
            }
            row.put("replay", json.convertValue(replayed.get(), Object.class));
        }
        catch (IOException | RuntimeException exception) {
            row.put("failure", exception.getClass().getSimpleName() + ": " + exception.getMessage());
        }
        return row;
    }

    private static String text(JsonNode node) {
        return node == null || node.isMissingNode() || node.isNull() ? null : node.asText();
    }
}
