package io.contexa.contexaiam.admin.promptquality.official.model;

import java.util.List;

public record OfficialRunRemediationGroup(
        String groupId,
        String rootCauseKey,
        String remediationOwner,
        String operatorTitle,
        String operatorReason,
        String nextAction,
        String reverifyCriterion,
        List<String> affectedMetricCodes,
        List<String> affectedCheckCodes,
        int findingCount,
        String relatedProcessStep) {

    public OfficialRunRemediationGroup {
        affectedMetricCodes = affectedMetricCodes == null ? List.of() : List.copyOf(affectedMetricCodes);
        affectedCheckCodes = affectedCheckCodes == null ? List.of() : List.copyOf(affectedCheckCodes);
    }
}

