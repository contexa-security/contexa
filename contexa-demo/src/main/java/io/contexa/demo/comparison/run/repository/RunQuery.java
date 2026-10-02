package io.contexa.demo.comparison.run.repository;

import io.contexa.demo.comparison.run.dto.RunRecord;
import io.contexa.demo.comparison.run.dto.RunSummary;
import io.contexa.demo.comparison.run.dto.RunStep;
import io.contexa.demo.comparison.run.dto.RunEvent;
import java.util.List;
import java.util.UUID;

public interface RunQuery {

    List<RunSummary> recent(UUID visitorId);

    RunRecord find(UUID visitorId, UUID runId);

    RunRecord findCommand(UUID visitorId, UUID commandId);

    List<RunStep> steps(UUID runId);

    List<RunEvent> events(UUID runId);
}
