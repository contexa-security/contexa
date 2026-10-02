package io.contexa.demo.comparison.run.service;

import io.contexa.demo.comparison.run.dto.RunCommand;
import io.contexa.demo.comparison.run.dto.RunView;
import io.contexa.demo.comparison.run.dto.RunSummary;
import java.util.List;
import java.util.UUID;

public interface ComparisonRunService {

    List<RunSummary> recent(UUID visitorId);

    RunView create(UUID visitorId, RunCommand command);

    RunView find(UUID visitorId, UUID runId);

    RunView cancel(UUID visitorId, UUID runId);
}
