package io.contexa.showcase.portal.ops;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.benchmark.BenchmarkController;
import io.contexa.showcase.portal.benchmark.DecisionQualityService;
import io.contexa.showcase.portal.orchestrator.WorkloadAdmin;
import io.contexa.showcase.portal.reactivity.PromptQualityPublications;
import io.contexa.showcase.portal.reactivity.PromptQualityView;
import io.contexa.showcase.portal.reactivity.ReactivityService;
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
 * W7-13: the operator publishes what the benchmark's prompt quality tab shows for a measurement setting, on the
 * operator port: the harness batch and the measurement protocol, counted now with the harness metrics (W6-1) and the
 * decision quality (W6-2) and stored; visitors see nothing until then. Both read the sealed prompts through control D,
 * so it answers only where the portal has control D.
 */
@RestController
@ConditionalOnProperty(prefix = "showcase.portal.ops", name = "port")
public class PromptQualityOpsController {

    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectProvider<WorkloadAdmin> admin;
    private final ObjectProvider<ReactivityService> reactivity;
    private final PromptQualityPublications publications;
    private final ObjectMapper json;

    public PromptQualityOpsController(NamedParameterJdbcTemplate jdbc, ObjectProvider<WorkloadAdmin> admin,
                                      ObjectProvider<ReactivityService> reactivity,
                                      PromptQualityPublications publications, ObjectMapper json) {
        this.jdbc = jdbc;
        this.admin = admin;
        this.reactivity = reactivity;
        this.publications = publications;
        this.json = json;
    }

    @PostMapping("/ops/prompt-quality")
    public ResponseEntity<Object> publish(@RequestParam("setting") String setting, @RequestParam("batch") String batch,
                                          @RequestParam("protocol") String protocol) throws IOException {
        ReactivityService service = reactivity.getIfAvailable();
        WorkloadAdmin workloadAdmin = admin.getIfAvailable();
        if (service == null || workloadAdmin == null) {
            return ResponseEntity.notFound().build();
        }
        Optional<String> refused = BenchmarkController.SETTING.matcher(setting).matches()
                ? publications.refusal(setting, batch, protocol)
                : Optional.of(PromptQualityPublications.UNKNOWN_SETTING);
        if (refused.isPresent()) {
            return ResponseEntity.badRequest().body(Map.of("reason", refused.get()));
        }
        PromptQualityView view = PromptQualityView.of(publications.measuredAt(batch, protocol), setting, batch,
                protocol, service.report(batch, protocol),
                new DecisionQualityService(jdbc, workloadAdmin, json).of(protocol));
        publications.publish(setting, batch, protocol, json.writeValueAsString(view), Instant.now());
        return ResponseEntity.ok(view);
    }
}
