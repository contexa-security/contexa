package io.contexa.demo.experience.report.repository;

import io.contexa.demo.experience.report.dto.ReportSummary;
import io.contexa.demo.experience.report.dto.StoredReport;
import java.util.List;
import java.util.UUID;

public interface ReportRepository {

    StoredReport find(UUID visitorId, UUID reportId);

    StoredReport findCommand(UUID visitorId, UUID commandId);

    List<ReportSummary> list(UUID visitorId, UUID runId);

    StoredReport save(UUID visitorId, UUID commandId, StoredReport report);
}
