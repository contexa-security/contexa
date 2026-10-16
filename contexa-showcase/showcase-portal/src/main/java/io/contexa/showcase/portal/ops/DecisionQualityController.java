package io.contexa.showcase.portal.ops;

import io.contexa.showcase.portal.benchmark.DecisionQuality;
import io.contexa.showcase.portal.benchmark.DecisionQualityService;
import io.contexa.showcase.portal.orchestrator.WorkloadAdmin;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

/**
 * W6-2 (P6-CHANGE-3): the decision quality of a measurement protocol, on the operator port. It reads the sealed
 * prompts through control D, so it answers only where the portal has control D.
 */
@RestController
@ConditionalOnProperty(prefix = "showcase.portal.ops", name = "port")
public class DecisionQualityController {

    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectProvider<WorkloadAdmin> admin;
    private final ObjectMapper json;

    public DecisionQualityController(NamedParameterJdbcTemplate jdbc, ObjectProvider<WorkloadAdmin> admin,
                                     ObjectMapper json) {
        this.jdbc = jdbc;
        this.admin = admin;
        this.json = json;
    }

    @GetMapping("/ops/decision-quality")
    public ResponseEntity<DecisionQuality> decisionQuality(@RequestParam("protocol") String protocolId)
            throws IOException {
        WorkloadAdmin workloadAdmin = admin.getIfAvailable();
        if (workloadAdmin == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(new DecisionQualityService(jdbc, workloadAdmin, json).of(protocolId));
    }
}
