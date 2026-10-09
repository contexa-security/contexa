package io.contexa.showcase.workload.plain.internal;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.showcase.workload.plain.rules.RecordedRuleEvaluation;
import io.contexa.showcase.workload.plain.rules.RuleSettings;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * The rules scene's evaluation (docs/showcase/데모-재설계.md H-10): the rule classes decide recorded requests again under
 * a visitor's settings. Part of the workload management API, so only a verified internal caller (the portal) reaches
 * it; it reads no database and changes nothing.
 */
@RestController
public class RuleEvaluationController {

    /** Most requests one evaluation may carry: the recorded cases of the rules scene with all their steps. */
    static final int MAX_STEPS = 500;

    public record Evaluation(RuleSettings settings, List<RecordedRuleEvaluation.Step> steps) {
    }

    private final ObjectMapper json;

    public RuleEvaluationController(ObjectMapper json) {
        this.json = json;
    }

    @PostMapping("/internal/rules/evaluate")
    public ResponseEntity<List<RecordedRuleEvaluation.Result>> evaluate(@RequestBody Evaluation evaluation) {
        if (evaluation == null || evaluation.settings() == null || evaluation.steps() == null
                || evaluation.steps().size() > MAX_STEPS || evaluation.settings().nightStart() == null
                || evaluation.settings().nightEnd() == null || evaluation.settings().volumeLimit() < 0) {
            return ResponseEntity.badRequest().build();
        }
        return ResponseEntity.ok(evaluation.steps().stream()
                .map(step -> RecordedRuleEvaluation.evaluate(step, evaluation.settings(), json))
                .toList());
    }
}
