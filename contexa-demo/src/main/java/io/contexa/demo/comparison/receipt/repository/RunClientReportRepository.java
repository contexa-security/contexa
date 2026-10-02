package io.contexa.demo.comparison.receipt.repository;

import io.contexa.demo.comparison.receipt.dto.RunClientReport;
import io.contexa.demo.comparison.receipt.dto.RunClientReportInput;
import java.util.List;
import java.util.UUID;

public interface RunClientReportRepository {

    RunClientReport save(UUID visitorId, UUID runId, RunClientReportInput input);

    List<RunClientReport> find(UUID visitorId, UUID runId);
}
