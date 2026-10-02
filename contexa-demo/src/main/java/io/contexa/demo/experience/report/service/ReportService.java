package io.contexa.demo.experience.report.service;

import io.contexa.demo.experience.report.dto.ReportCommand;
import io.contexa.demo.experience.report.dto.ReportSummary;
import io.contexa.demo.experience.report.dto.StoredReport;
import java.util.List;
import java.util.UUID;

public interface ReportService {

    StoredReport capture(UUID visitorId, UUID runId, ReportCommand command);

    StoredReport find(UUID visitorId, UUID reportId);

    List<ReportSummary> list(UUID visitorId, UUID runId);
}
