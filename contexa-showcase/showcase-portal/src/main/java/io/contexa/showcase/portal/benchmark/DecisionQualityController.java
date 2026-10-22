package io.contexa.showcase.portal.benchmark;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.Optional;

/**
 * BM-S8 of docs/showcase/벤치마크-구현계획.md: the visitor API of a setting's published decision quality (G5 of the v21
 * plan); 404 until one is published. Stored values only: nothing is counted and control D is not read here.
 */
// The operator port has its own DecisionQualityController (W6-2, counted on demand); this one reads publications.
@RestController("benchmarkDecisionQualityController")
public class DecisionQualityController {

    private final DecisionQualityPublications publications;
    private final ObjectMapper json;

    public DecisionQualityController(DecisionQualityPublications publications, ObjectMapper json) {
        this.publications = publications;
        this.json = json;
    }

    @GetMapping("/api/benchmark/decision-quality")
    public ResponseEntity<JsonNode> decisionQuality(@RequestParam("setting") String setting) throws IOException {
        if (!BenchmarkController.SETTING.matcher(setting).matches()) {
            return ResponseEntity.notFound().build();
        }
        Optional<String> published = publications.published(setting);
        if (published.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(json.readTree(published.get()));
    }
}
