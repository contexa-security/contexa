package io.contexa.demo.comparison.submission.service;

import io.contexa.demo.comparison.run.dto.RunCommand;
import io.contexa.demo.comparison.run.dto.RunView;
import io.contexa.demo.comparison.submission.dto.RunSubmission;

import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;

public interface RunSubmissionService {

    RunView track(UUID visitorId, RunCommand command, Supplier<RunView> operation);

    List<RunSubmission> find(UUID visitorId, UUID preparationId);
}
