package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageDetail;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunAuditSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunFailureCause;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageListItem;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageSummary;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunTechnicalLedger;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialActualPromptProblem;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationMetricTrace;

import java.util.List;

public interface PromptQualityOfficialRunDetailService {

    default List<OfficialRunPackageListItem> listRecentRunSummaries(int limit) {
        return List.of();
    }

    OfficialRunPackageDetail findPackageDetail(String packageId);

    default OfficialRunPackageDetail findPackageDetail(String packageId, String aggregateRunId) {
        return findPackageDetail(packageId);
    }

    default OfficialRunTechnicalLedger findTechnicalLedger(String packageId, String aggregateRunId) {
        OfficialRunPackageDetail detail = findPackageDetail(packageId, aggregateRunId);
        return new OfficialRunTechnicalLedger(
                detail.packageId(),
                detail.aggregateRunId(),
                detail.totalRunCount(),
                false,
                List.of());
    }

    default OfficialRunPackageSummary findPackageSummary(String packageId, String aggregateRunId) {
        return OfficialRunPackageSummary.fromDetail(findPackageDetail(packageId, aggregateRunId));
    }

    default List<OfficialRunFailureCause> findFailureDetails(String packageId, String aggregateRunId) {
        OfficialRunPackageSummary summary = findPackageSummary(packageId, aggregateRunId);
        return summary == null ? List.of() : summary.failureCauses();
    }

    default List<OfficialRunAuditSnapshot> findAuditPayloads(String packageId, String aggregateRunId) {
        return findPackageDetail(packageId, aggregateRunId).auditSnapshots();
    }

    default List<OfficialActualPromptProblem> findActualPromptProblems(String packageId, String aggregateRunId) {
        return findPackageDetail(packageId, aggregateRunId).actualPromptProblems();
    }

    OfficialVerificationMetricTrace findRunDetail(String runId);
}
