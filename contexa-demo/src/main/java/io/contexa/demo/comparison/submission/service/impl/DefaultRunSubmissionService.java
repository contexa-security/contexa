package io.contexa.demo.comparison.submission.service.impl;

import io.contexa.demo.comparison.preparation.service.ComparisonPreparationService;
import io.contexa.demo.comparison.run.dto.RunCommand;
import io.contexa.demo.comparison.run.dto.RunView;
import io.contexa.demo.comparison.submission.dto.RunSubmission;
import io.contexa.demo.comparison.submission.repository.RunSubmissionRepository;
import io.contexa.demo.comparison.submission.service.RunSubmissionService;
import io.contexa.demo.comparison.support.AbstractRunFailureSupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;

@Service
@Profile("portal")
public class DefaultRunSubmissionService extends AbstractRunFailureSupport implements RunSubmissionService {

    private static final Logger log = LoggerFactory.getLogger(DefaultRunSubmissionService.class);
    private final RunSubmissionRepository repository;
    private final ComparisonPreparationService preparations;

    public DefaultRunSubmissionService(RunSubmissionRepository repository, ComparisonPreparationService preparations) {
        this.repository = repository;
        this.preparations = preparations;
    }

    @Override
    public RunView track(UUID visitorId, RunCommand command, Supplier<RunView> operation) {
        UUID id = repository.begin(visitorId, command);
        try {
            RunView view = operation.get();
            finish(id, "RUN_AVAILABLE", view.run().id(), 200, null);
            return view;
        } catch (ResponseStatusException rejected) {
            finish(id, "REJECTED", null, rejected.getStatusCode().value(),
                    publicReason(rejected.getReason()));
            throw rejected;
        } catch (RuntimeException failed) {
            finish(id, "FAILED", null, null, "CREATION_FAILED");
            throw failed;
        }
    }

    @Override
    public List<RunSubmission> find(UUID visitorId, UUID preparationId) {
        preparations.find(visitorId, preparationId);
        return repository.find(visitorId, preparationId);
    }

    private void finish(UUID id, String state, UUID runId, Integer httpStatus, String reason) {
        try {
            repository.finish(id, state, runId, httpStatus, reason);
        } catch (RuntimeException unavailable) {
            log.warn("Run submission completion missing: {}", unavailable.getClass().getSimpleName());
        }
    }
}
