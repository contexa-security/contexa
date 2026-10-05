package io.contexa.showcase.portal.orchestrator;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Repeats the clean-up of runs whose principal may still exist (plan section 8: a failed clean-up step is detected and
 * retried; docs/showcase/계획대조-검수.md N-6). A finished run whose engine or business clean-up failed is cleaned
 * again, up to {@link #MAX_RETRIES} times; a run still RUNNING an hour after its start was abandoned by a stopped
 * portal, so its principal is cleaned and the run is closed as FAILED. Both clean-up calls delete by name and run id,
 * so repeating them is safe.
 */
public class CleanupRetrier {

    private static final Logger log = LoggerFactory.getLogger(CleanupRetrier.class);

    static final Duration ABANDONED_AFTER = Duration.ofHours(1);
    static final int MAX_RETRIES = 5;
    static final int BATCH = 50;
    static final String ABANDONED = "Abandoned: no result an hour after the start (portal stopped during the run)";

    /** What one pass did: runs it tried, runs now clean, runs still failing. */
    public record Pass(int tried, int cleaned, int stillFailing) {
    }

    private final RunStore runs;
    private final WorkloadAdmin admin;
    private final ObjectMapper json;
    private final Clock clock;

    public CleanupRetrier(RunStore runs, WorkloadAdmin admin, ObjectMapper json, Clock clock) {
        this.runs = runs;
        this.admin = admin;
        this.json = json;
        this.clock = clock;
    }

    public synchronized Pass run() {
        Instant now = clock.instant();
        int cleaned = 0;
        int failing = 0;
        List<RunStore.CleanupCandidate> candidates =
                runs.cleanupCandidates(now.minus(ABANDONED_AFTER), MAX_RETRIES, BATCH);
        for (RunStore.CleanupCandidate candidate : candidates) {
            boolean abandoned = "RUNNING".equals(candidate.status());
            Map<String, Object> cleanup = read(candidate.cleanup());
            boolean ok = true;
            if (abandoned || cleanup.containsKey("engineError")) {
                try {
                    cleanup.put("engine", admin.deleteEnginePrincipal(candidate.runId(), candidate.principal()));
                    cleanup.remove("engineError");
                } catch (IOException | RuntimeException e) {
                    log.error("Engine clean-up retry failed: runId={}", candidate.runId(), e);
                    cleanup.put("engineError", e.getMessage());
                    ok = false;
                }
            }
            if (abandoned || cleanup.containsKey("businessError")) {
                try {
                    cleanup.put("business", admin.deletePlainRun(candidate.runId()));
                    cleanup.remove("businessError");
                } catch (IOException | RuntimeException e) {
                    log.error("Business clean-up retry failed: runId={}", candidate.runId(), e);
                    cleanup.put("businessError", e.getMessage());
                    ok = false;
                }
            }
            cleanup.put("retries", ((Number) cleanup.getOrDefault("retries", 0)).intValue() + 1);
            cleanup.put("retriedAt", now.toString());
            runs.cleanupRetried(candidate.runId(), cleanup, abandoned ? ABANDONED : null);
            if (ok) {
                cleaned++;
            } else {
                failing++;
            }
        }
        return new Pass(candidates.size(), cleaned, failing);
    }

    private Map<String, Object> read(String text) {
        if (text == null || text.isBlank()) {
            return new LinkedHashMap<>();
        }
        try {
            return json.readValue(text, new TypeReference<LinkedHashMap<String, Object>>() {
            });
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unreadable clean-up record", e);
        }
    }
}
