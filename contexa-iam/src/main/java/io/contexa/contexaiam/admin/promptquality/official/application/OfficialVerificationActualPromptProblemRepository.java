package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.model.OfficialActualPromptProblem;

import java.util.List;

public interface OfficialVerificationActualPromptProblemRepository {
    List<OfficialActualPromptProblem> findByAggregateRunId(String aggregateRunId);
    List<OfficialActualPromptProblem> findByAggregateRunIds(List<String> aggregateRunIds);
}