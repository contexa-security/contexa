package io.contexa.demo.comparison.submission.repository;

import io.contexa.demo.comparison.run.dto.RunCommand;
import io.contexa.demo.comparison.submission.dto.RunSubmission;

import java.util.List;
import java.util.UUID;

public interface RunSubmissionRepository {

    UUID begin(UUID visitorId, RunCommand command);

    void finish(UUID submissionId, String state, UUID runId, Integer httpStatus, String reason);

    List<RunSubmission> find(UUID visitorId, UUID preparationId);
}
