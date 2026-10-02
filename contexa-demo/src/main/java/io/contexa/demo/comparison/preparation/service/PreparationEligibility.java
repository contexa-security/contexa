package io.contexa.demo.comparison.preparation.service;

import io.contexa.demo.comparison.preparation.dto.PreparationBlocker;
import io.contexa.demo.readiness.dto.ReadinessReport;

import java.util.List;

public interface PreparationEligibility {

    List<PreparationBlocker> inspect(ReadinessReport report, boolean documentsMatch);
}
