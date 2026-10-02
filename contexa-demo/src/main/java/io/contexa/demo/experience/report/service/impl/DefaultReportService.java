package io.contexa.demo.experience.report.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import io.contexa.demo.comparison.run.repository.RunQuery;
import io.contexa.demo.comparison.run.service.ComparisonRunService;
import io.contexa.demo.experience.report.dto.ReportCommand;
import io.contexa.demo.experience.report.dto.ReportPayload;
import io.contexa.demo.experience.report.dto.ReportSource;
import io.contexa.demo.experience.report.dto.ReportSummary;
import io.contexa.demo.experience.report.dto.StoredReport;
import io.contexa.demo.experience.report.repository.ReportRepository;
import io.contexa.demo.experience.report.service.ReportService;
import io.contexa.demo.observation.request.service.WorkspaceEvidenceQuery;
import io.contexa.demo.shared.document.DocumentCodec;
import org.springframework.context.annotation.Profile;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
@Profile("portal")
public class DefaultReportService implements ReportService {

    private final RunQuery runs;
    private final ComparisonRunService executions;
    private final WorkspaceEvidenceQuery evidence;
    private final ReportRepository reports;
    private final DocumentCodec documents;

    public DefaultReportService(RunQuery runs, ComparisonRunService executions, WorkspaceEvidenceQuery evidence,
            ReportRepository reports, DocumentCodec documents) {
        this.runs = runs;
        this.executions = executions;
        this.evidence = evidence;
        this.reports = reports;
        this.documents = documents;
    }

    @Override
    public StoredReport capture(UUID visitorId, UUID runId, ReportCommand command) {
        requireRun(visitorId, runId);
        StoredReport previous = reports.findCommand(visitorId, command.commandId());
        if (previous != null) {
            return sameRun(previous, runId);
        }
        var execution = executions.find(visitorId, runId);
        List<ReportSource> sources = new ArrayList<>();
        List<String> limitations = new ArrayList<>(List.of("POINT_IN_TIME_NOT_ATOMIC",
                "LATE_RESULTS_REQUIRE_NEW_REPORT", "CLIENT_MEASUREMENTS_ARE_SELF_REPORTED",
                "REPRESENTATIVE_EXECUTION_NOT_GENERALIZED_EFFECTIVENESS"));
        if (!"RESPONDED".equals(execution.run().state())) {
            limitations.add("EXECUTION_NOT_COMPLETED");
        }
        if (execution.moreEventsAvailable()) {
            limitations.add("EXECUTION_EVENTS_TRUNCATED");
        }
        if (execution.clientReports().size() < execution.steps().size()) {
            limitations.add("CLIENT_MEASUREMENTS_INCOMPLETE");
        }
        for (var step : execution.steps()) {
            ReportSource source = source(visitorId, step.arm(), step.requestId());
            sources.add(source);
            if (!"CAPTURED".equals(source.state())) {
                limitations.add("SOURCE_" + source.state() + "_" + step.arm());
            }
        }
        Instant now = Instant.now();
        var payload = new ReportPayload("RUNTIME_LAB_REPORT_V1", now, execution, List.copyOf(sources),
                List.copyOf(limitations), "NOT_REVIEWED",
                "CREATE_NEW_RUN_RECHECK_CURRENT_SESSIONS_DATA_POLICY_MODEL_AND_NATIVE_HISTORY_NO_STATE_RESTORE");
        var candidate = new StoredReport(UUID.randomUUID(), runId, now,
                documents.hash(documents.write(payload)), "PRESERVED_JSON_V2", payload);
        return sameRun(reports.save(visitorId, command.commandId(), candidate), runId);
    }

    @Override
    public StoredReport find(UUID visitorId, UUID reportId) {
        StoredReport report = reports.find(visitorId, reportId);
        if (report == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        return report;
    }

    @Override
    public List<ReportSummary> list(UUID visitorId, UUID runId) {
        requireRun(visitorId, runId);
        return reports.list(visitorId, runId);
    }

    private void requireRun(UUID visitorId, UUID runId) {
        if (runs.find(visitorId, runId) == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
    }

    private StoredReport sameRun(StoredReport report, UUID runId) {
        if (!runId.equals(report.runId())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "REPORT_COMMAND_ALREADY_USED");
        }
        return report;
    }

    private ReportSource source(UUID visitorId, String arm, UUID requestId) {
        if (requestId == null) {
            return new ReportSource(arm, null, "NOT_DISPATCHED", Instant.now(), null, null);
        }
        try {
            var value = evidence.find(arm, requestId, visitorId);
            String encoded = documents.write(value);
            return new ReportSource(arm, requestId, "CAPTURED", Instant.now(),
                    documents.hash(encoded), documents.read(encoded, JsonNode.class));
        } catch (DataAccessException unavailable) {
            return new ReportSource(arm, requestId, "UNAVAILABLE", Instant.now(), null, null);
        } catch (ResponseStatusException missing) {
            if (missing.getStatusCode().value() != 404) {
                throw missing;
            }
            return new ReportSource(arm, requestId, "NOT_COLLECTED", Instant.now(), null, null);
        }
    }
}
