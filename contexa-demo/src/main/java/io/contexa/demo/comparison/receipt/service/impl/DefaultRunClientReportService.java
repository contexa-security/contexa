package io.contexa.demo.comparison.receipt.service.impl;

import io.contexa.demo.comparison.receipt.dto.RunClientReport;
import io.contexa.demo.comparison.receipt.dto.RunClientReportInput;
import io.contexa.demo.comparison.receipt.repository.RunClientReportRepository;
import io.contexa.demo.comparison.receipt.service.RunClientReportService;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import java.time.Duration;
import java.util.UUID;

@Service
@Profile("portal")
public class DefaultRunClientReportService implements RunClientReportService {

    private final RunClientReportRepository repository;

    public DefaultRunClientReportService(RunClientReportRepository repository) {
        this.repository = repository;
    }

    @Override
    public RunClientReport record(UUID visitorId, UUID runId, RunClientReportInput input) {
        boolean started = "STARTED".equals(input.stage());
        boolean inconsistentStart = started && (!"UNCONFIRMED".equals(input.outcome())
                || !"PREPARATION".equals(input.phase()) || input.httpStatus() != null || input.responseBytes() != null);
        boolean inconsistentFinish = !started && "UNCONFIRMED".equals(input.outcome());
        boolean receivedWithoutStatus = "RESPONSE_RECEIVED".equals(input.outcome())
                && (input.httpStatus() == null || input.responseBytes() == null || !"BUSINESS".equals(input.phase()));
        Duration duration = Duration.between(input.startedAt(), input.observedAt());
        if (inconsistentStart || inconsistentFinish || receivedWithoutStatus
                || duration.isNegative() || duration.compareTo(Duration.ofDays(1)) > 0) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "INVALID_CLIENT_REPORT");
        }
        return repository.save(visitorId, runId, input);
    }
}
