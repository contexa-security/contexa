package io.contexa.contexaiam.admin.promptquality.official.application;

import java.util.Optional;
import java.util.Set;

public interface OfficialVerificationContractLinkIntegrityRepository {
    void assertActualPromptProblemLedgerReferences(String aggregateRunId);
    Set<String> registeredMetricCodes();
    Set<String> registeredMetricCheckCodes();
    Optional<CheckDefinitionLink> findMetricCheckDefinition(String metricCode, String checkCode);
    Optional<CheckDefinitionLink> findActualPromptProblemLink(
            String aggregateRunId, String problemId, String issueKey, String contractIssueKey, String source);

    record CheckDefinitionLink(String fieldKey, String promptLocation, String relatedProcessStep) {
    }
}