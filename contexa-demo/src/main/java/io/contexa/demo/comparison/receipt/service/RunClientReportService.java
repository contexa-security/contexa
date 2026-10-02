package io.contexa.demo.comparison.receipt.service;

import io.contexa.demo.comparison.receipt.dto.RunClientReport;
import io.contexa.demo.comparison.receipt.dto.RunClientReportInput;
import java.util.UUID;

public interface RunClientReportService {

    RunClientReport record(UUID visitorId, UUID runId, RunClientReportInput input);
}
