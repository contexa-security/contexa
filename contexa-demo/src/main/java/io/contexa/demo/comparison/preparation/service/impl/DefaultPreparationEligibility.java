package io.contexa.demo.comparison.preparation.service.impl;

import io.contexa.demo.comparison.preparation.dto.PreparationBlocker;
import io.contexa.demo.comparison.preparation.service.PreparationEligibility;
import io.contexa.demo.readiness.dto.ReadinessReport;
import io.contexa.demo.readiness.dto.WorkerReadiness;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Component
@Profile("portal")
public class DefaultPreparationEligibility implements PreparationEligibility {

    private static final Set<String> BLOCKING_STATES = Set.of("MISSING", "UNAVAILABLE", "INVALID_CONFIGURATION",
            "ENFORCEMENT_DISABLED", "NOT_IMPLEMENTED", "PARTIALLY_IMPLEMENTED");

    @Override
    public List<PreparationBlocker> inspect(ReadinessReport report, boolean documentsMatch) {
        List<PreparationBlocker> blockers = new ArrayList<>();
        append(blockers, report);
        for (WorkerReadiness worker : report.workers()) {
            if (!"REACHABLE".equals(worker.state()) || worker.report() == null) {
                blockers.add(new PreparationBlocker(worker.role(), "worker", worker.state()));
            } else {
                append(blockers, worker.report());
            }
        }
        if (!documentsMatch) {
            blockers.add(new PreparationBlocker("comparison", "documents", "NOT_MATCHED"));
        }
        blockers.add(new PreparationBlocker("comparison", "authenticated-sessions", "NOT_OBSERVED"));
        blockers.add(new PreparationBlocker("comparison", "complete-manifest", "PARTIALLY_IMPLEMENTED"));
        return List.copyOf(blockers);
    }

    private void append(List<PreparationBlocker> blockers, ReadinessReport report) {
        report.checks().stream().filter(check -> BLOCKING_STATES.contains(check.state()))
                .forEach(check -> blockers.add(new PreparationBlocker(report.role(), check.component(), check.state())));
        if (!report.experimentReady()) {
            blockers.add(new PreparationBlocker(report.role(), "execution-readiness", "NOT_READY"));
        }
    }
}
