package io.contexa.showcase.portal.benchmark;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.regex.Pattern;

/**
 * Visitor API of the benchmark (docs/showcase/데모-재설계.md 5A.2): the scores of a measurement setting from its
 * protocol runs, the latest setting when none is named. Counted from stored runs; cached for a minute.
 */
@RestController
public class BenchmarkController {

    static final Pattern SETTING = Pattern.compile("[0-9a-f]{64}");

    private final BenchmarkService benchmark;

    public BenchmarkController(BenchmarkService benchmark) {
        this.benchmark = benchmark;
    }

    @GetMapping("/api/benchmark")
    public ResponseEntity<BenchmarkView> benchmark(@RequestParam(name = "setting", required = false) String setting) {
        if (setting != null && !SETTING.matcher(setting).matches()) {
            return ResponseEntity.notFound().build();
        }
        return benchmark.view(setting).map(ResponseEntity::ok).orElse(ResponseEntity.notFound().build());
    }

    /** Every counted protocol run of the setting with its score: the raw data the summary offers to download. */
    @GetMapping("/api/benchmark/runs")
    public ResponseEntity<BenchmarkService.Raw> runs(@RequestParam(name = "setting", required = false) String setting) {
        if (setting != null && !SETTING.matcher(setting).matches()) {
            return ResponseEntity.notFound().build();
        }
        return benchmark.raw(setting).map(ResponseEntity::ok).orElse(ResponseEntity.notFound().build());
    }
}
