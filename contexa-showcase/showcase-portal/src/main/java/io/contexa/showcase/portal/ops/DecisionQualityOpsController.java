package io.contexa.showcase.portal.ops;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.benchmark.BenchmarkController;
import io.contexa.showcase.portal.benchmark.DecisionQuality;
import io.contexa.showcase.portal.benchmark.DecisionQualityPublications;
import io.contexa.showcase.portal.benchmark.DecisionQualityService;
import io.contexa.showcase.portal.orchestrator.WorkloadAdmin;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

/**
 * BM-S8 of docs/showcase/벤치마크-구현계획.md: the operator publishes the decision quality of a finished measurement
 * protocol for its setting, on the operator port (G5 of the v21 plan: each decision's reason codes against the facts
 * they cite, read from control D's latest inspections when published). The prompt quality publication needs harness
 * batches too; this one needs the protocol only.
 */
@RestController
@ConditionalOnProperty(prefix = "showcase.portal.ops", name = "port")
public class DecisionQualityOpsController {

    /** What the benchmark reads for a setting: the protocol, when it was published, and the decision quality. */
    public record Publication(String setting, String protocol, Instant publishedAt, DecisionQuality quality) {
    }

    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectProvider<WorkloadAdmin> admin;
    private final DecisionQualityPublications publications;
    private final ObjectMapper json;

    public DecisionQualityOpsController(NamedParameterJdbcTemplate jdbc, ObjectProvider<WorkloadAdmin> admin,
                                        DecisionQualityPublications publications, ObjectMapper json) {
        this.jdbc = jdbc;
        this.admin = admin;
        this.publications = publications;
        this.json = json;
    }

    @PostMapping("/ops/decision-quality")
    public ResponseEntity<Object> publish(@RequestParam("setting") String setting,
                                          @RequestParam("protocol") String protocol) throws IOException {
        WorkloadAdmin workloadAdmin = admin.getIfAvailable();
        if (workloadAdmin == null) {
            return ResponseEntity.notFound().build();
        }
        if (!BenchmarkController.SETTING.matcher(setting).matches()) {
            return ResponseEntity.badRequest().body(Map.of("reason", "UNKNOWN_SETTING"));
        }
        Optional<String> refused = publications.refusal(setting, protocol);
        if (refused.isPresent()) {
            return ResponseEntity.badRequest().body(Map.of("reason", refused.get(), "protocol", protocol));
        }
        Publication publication = new Publication(setting, protocol, Instant.now(),
                new DecisionQualityService(jdbc, workloadAdmin, json).of(protocol));
        publications.publish(setting, protocol, json.writeValueAsString(publication), publication.publishedAt());
        return ResponseEntity.ok(publication);
    }
}
