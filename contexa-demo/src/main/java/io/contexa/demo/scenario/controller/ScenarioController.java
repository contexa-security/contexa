package io.contexa.demo.scenario.controller;

import io.contexa.demo.scenario.dto.ScenarioEvaluation;
import io.contexa.demo.scenario.dto.ScenarioSummary;
import io.contexa.demo.scenario.dto.StoredScenario;
import io.contexa.demo.scenario.service.ScenarioCatalog;
import io.contexa.demo.shared.web.AbstractQueryController;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@Profile("portal")
@RequestMapping("/api/lab/scenarios")
public class ScenarioController extends AbstractQueryController {

    private final ScenarioCatalog catalog;

    public ScenarioController(ScenarioCatalog catalog) {
        this.catalog = catalog;
    }

    @GetMapping
    public ResponseEntity<List<ScenarioSummary>> list() {
        return result(catalog.list());
    }

    @GetMapping("/{id}")
    public ResponseEntity<StoredScenario> get(@PathVariable UUID id) {
        var value = catalog.find(id);
        return value == null ? ResponseEntity.notFound().build() : result(value);
    }

    @GetMapping("/{id}/criteria")
    public ResponseEntity<ScenarioEvaluation> criteria(@PathVariable UUID id) {
        var value = catalog.evaluation(id);
        return value == null ? ResponseEntity.notFound().build() : result(value);
    }
}
