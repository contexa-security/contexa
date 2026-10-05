package io.contexa.showcase.portal.replay;

import io.contexa.showcase.portal.spec.ExecutionSpec;
import io.contexa.showcase.portal.spec.ExecutionSpecStore;
import io.contexa.showcase.portal.spec.ScoringContract;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Visitor API of recorded replays and the execution specification behind them (deck p.24: a replay shows its source
 * and version). Only published, consistent recordings are served.
 */
@RestController
public class ReplayController {

    private static final Pattern HASH = Pattern.compile("[0-9a-f]{64}");

    private final ReplayViews views;
    private final ExecutionSpecStore specs;
    private final ReplayGuard guard;
    private final ScoringContract contract;

    public ReplayController(ReplayViews views, ExecutionSpecStore specs, ReplayGuard guard, ScoringContract contract) {
        this.views = views;
        this.specs = specs;
        this.guard = guard;
        this.contract = contract;
    }

    /** The scoring contract and its version, as every run records it (deck p.33: published before measuring). */
    @GetMapping("/api/contract")
    public Map<String, Object> contract() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("contractVersion", contract.version());
        body.put("status", contract.status());
        body.put("contract", contract.document());
        return body;
    }

    @GetMapping("/api/pairs")
    public List<ReplayView.PairSummary> pairs() {
        return views.summaries();
    }

    @GetMapping("/api/replays/{pairKey}")
    public ResponseEntity<ReplayView.Pair> replay(@PathVariable("pairKey") String pairKey) {
        return views.published(pairKey)
                .filter(pair -> pair.scenes().stream().noneMatch(scene -> guard.blocked(scene.recordId())))
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping("/api/specs/{specHash}")
    public ResponseEntity<Map<String, Object>> spec(@PathVariable("specHash") String specHash) {
        if (!HASH.matcher(specHash).matches()) {
            return ResponseEntity.notFound().build();
        }
        return specs.find(specHash).map(spec -> ResponseEntity.ok(body(specHash, spec)))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    private static Map<String, Object> body(String specHash, ExecutionSpec spec) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("specHash", specHash);
        body.put("spec", spec);
        return body;
    }
}
