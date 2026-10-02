package io.contexa.demo.experience.factor.service.impl;

import io.contexa.demo.comparison.variation.service.RunVariationQuery;
import io.contexa.demo.experience.factor.dto.ComparisonFactor;
import io.contexa.demo.experience.factor.dto.FactorComparison;
import io.contexa.demo.experience.factor.dto.FactorPair;
import io.contexa.demo.experience.factor.service.FactorComparisonQuery;
import io.contexa.demo.experience.report.dto.StoredReport;
import io.contexa.demo.experience.report.repository.ReportRepository;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

@Component
@Profile("portal")
public class StoredFactorComparisonQuery implements FactorComparisonQuery {

    private final ReportRepository reports;
    private final RunVariationQuery variations;

    public StoredFactorComparisonQuery(ReportRepository reports, RunVariationQuery variations) {
        this.reports = reports;
        this.variations = variations;
    }

    @Override
    public FactorComparison compare(UUID visitorId, ComparisonFactor factor, List<UUID> before, List<UUID> after) {
        if (before.size() != 3 || after.size() != 3 || Stream.concat(before.stream(), after.stream()).distinct().count() != 6) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "SIX_DISTINCT_REPORTS_REQUIRED");
        }
        var originals = Stream.concat(before.stream(), after.stream()).map(id -> owned(visitorId, id)).toList();
        if (originals.stream().map(StoredReport::runId).distinct().count() != 6) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "SIX_DISTINCT_RUNS_REQUIRED");
        }
        List<FactorPair> pairs = new ArrayList<>();
        for (int index = 0; index < 3; index++) {
            var left = originals.get(index);
            var right = originals.get(index + 3);
            var rightManifest = right.payload().execution().run().manifest();
            var conditions = variations.capture(visitorId, rightManifest.plan().withParent(left.runId()),
                    rightManifest.initialConditions());
            pairs.add(new FactorPair(index + 1, left, right, conditions));
        }
        return new FactorComparison("FACTOR_COMPARISON_V1", factor, Instant.now(), List.copyOf(pairs),
                "REQUIRES_REVIEW_OF_ACTUAL_INPUTS_AND_EFFECTS",
                List.of("INTENDED_FACTOR_IS_NOT_VERIFIED_ISOLATION", "MULTIPLE_CHANGED_CONDITIONS_ARE_CONFOUNDED",
                        "NO_DIFFERENCE_AND_FAILURES_REMAIN_VISIBLE", "PRIOR_ACTION_REUSE_IS_NOT_NEW_MODEL_ANALYSIS",
                        "SIX_COMPARISONS_ARE_NOT_GENERALIZED_EFFECTIVENESS", "NO_MODEL_CALL_OR_STATE_CHANGE_FROM_THIS_VIEW"));
    }

    private StoredReport owned(UUID visitorId, UUID id) {
        var report = reports.find(visitorId, id);
        if (report == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        if (report.payload().execution().steps().stream().anyMatch(step -> step.requestId() == null)) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "FACTOR_REQUIRES_DISPATCHED_WORK");
        }
        return report;
    }
}
