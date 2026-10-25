package io.contexa.showcase.workload.contexa.internal;

import io.contexa.showcase.workload.contexa.observation.ModelOutage;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.TreeSet;

/**
 * Development-only outage of the judging model for named runs (docs/agent A6-R10). It exists only with
 * {@code showcase.dev.model-outage=true}, and a production start with that flag is refused like one with the forced
 * decisions. The portal switches it on for the run of an agent case that measures the engine without its model and off
 * again when the run ends. Like every {@code /internal} route it needs the internal signature.
 */
@RestController
@ConditionalOnProperty(name = "showcase.dev.model-outage", havingValue = "true")
public class ModelOutageController {

    private final ModelOutage outage;

    public ModelOutageController(ModelOutage outage) {
        this.outage = outage;
    }

    @PostMapping("/internal/dev/model-outage/{run}")
    public Map<String, Object> begin(@PathVariable("run") String run) {
        outage.begin(run);
        return state();
    }

    @DeleteMapping("/internal/dev/model-outage/{run}")
    public Map<String, Object> end(@PathVariable("run") String run) {
        outage.end(run);
        return state();
    }

    @GetMapping("/internal/dev/model-outage")
    public Map<String, Object> state() {
        return Map.of("runs", new TreeSet<>(outage.runs()), "refusedCalls", outage.refusedCalls());
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> refused(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
    }
}
