package io.contexa.showcase.portal.rules;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * Visitor API of the rule-limits scene: its cases, counted from the stored real runs and cached for a minute, the
 * values the rule controls run with, and the rule classes' decisions of those cases under a visitor's settings (H-10).
 */
@RestController
public class RuleCasesController {

    private static final Logger log = LoggerFactory.getLogger(RuleCasesController.class);

    /**
     * @param defaults     the values the rule controls run with; null when the plain workload could not be asked or the
     *                     portal has no control addresses
     * @param recordedFrom the earliest end of the cases' runs, the start of the records' period (the source mark's
     *                     recorded time); null without cases
     * @param recordedTo   the latest end of the cases' runs; null without cases
     */
    public record CasesView(Instant computedAt, RuleEvaluation.Defaults defaults, List<RuleCases.Case> cases,
                            Instant recordedFrom, Instant recordedTo) {
    }

    private final RuleCases cases;
    private final RuleEvaluation evaluation;

    /** @param evaluation absent in a portal without control addresses, which only shows the stored runs */
    public RuleCasesController(RuleCases cases, ObjectProvider<RuleEvaluation> evaluation) {
        this.cases = cases;
        this.evaluation = evaluation.getIfAvailable();
    }

    @GetMapping("/api/rules/cases")
    public CasesView cases() {
        RuleCases.View view = cases.view();
        RuleEvaluation.Defaults defaults = null;
        try {
            defaults = evaluation == null ? null : evaluation.defaults();
        } catch (IOException e) {
            log.error("Rule control values could not be read", e);
        }
        List<Instant> ends = view.cases().stream().map(RuleCases.Case::finishedAt).filter(Objects::nonNull).sorted()
                .toList();
        return new CasesView(view.computedAt(), defaults, view.cases(), ends.isEmpty() ? null : ends.get(0),
                ends.isEmpty() ? null : ends.get(ends.size() - 1));
    }

    @PostMapping("/api/rules/evaluate")
    public ResponseEntity<RuleEvaluation.Result> evaluate(@RequestBody RuleEvaluation.Settings settings) {
        if (settings == null || !settings.valid()) {
            return ResponseEntity.badRequest().build();
        }
        if (evaluation == null) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        }
        try {
            return ResponseEntity.ok(evaluation.evaluate(settings));
        } catch (IOException e) {
            log.error("Rule evaluation failed", e);
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        }
    }
}
