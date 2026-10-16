package io.contexa.showcase.portal.reactivity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.portal.benchmark.BenchmarkController;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.Optional;

/**
 * W7-13: visitor API of the benchmark's prompt quality tab (docs/showcase/화면설계-프롬프트신뢰-보강안.md 3.5, 5): the
 * view an operator published for a measurement setting, the latest published one when none is named; 404 until one
 * is published. Stored values only: nothing is counted and control D is not read here.
 */
@RestController
public class PromptQualityController {

    private final PromptQualityPublications publications;
    private final ObjectMapper json;

    public PromptQualityController(PromptQualityPublications publications, ObjectMapper json) {
        this.publications = publications;
        this.json = json;
    }

    @GetMapping("/api/benchmark/prompt-quality")
    public ResponseEntity<JsonNode> promptQuality(@RequestParam(name = "setting", required = false) String setting)
            throws IOException {
        if (setting != null && !BenchmarkController.SETTING.matcher(setting).matches()) {
            return ResponseEntity.notFound().build();
        }
        Optional<String> published = publications.published(setting);
        if (published.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(json.readTree(published.get()));
    }
}
