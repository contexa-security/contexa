package io.contexa.demo.comparison.run.service.impl;

import io.contexa.demo.comparison.attestation.service.AttestationPairQuery;
import io.contexa.demo.comparison.manifest.evaluation.source.ReviewContractQuery;
import io.contexa.demo.comparison.preparation.service.ComparisonPreparationService;
import io.contexa.demo.comparison.receipt.repository.RunClientReportRepository;
import io.contexa.demo.comparison.run.dto.RequestSchedule;
import io.contexa.demo.comparison.run.dto.RunCommand;
import io.contexa.demo.comparison.run.dto.RunManifest;
import io.contexa.demo.comparison.run.dto.RunRecord;
import io.contexa.demo.comparison.run.dto.RunView;
import io.contexa.demo.comparison.run.dto.RunSummary;
import io.contexa.demo.comparison.variation.service.RunVariationQuery;
import io.contexa.demo.comparison.run.repository.RunCreationRepository;
import io.contexa.demo.comparison.run.repository.RunLifecycleRepository;
import io.contexa.demo.comparison.run.repository.RunQuery;
import io.contexa.demo.comparison.run.service.ComparisonRunService;
import io.contexa.demo.comparison.submission.service.RunSubmissionService;
import io.contexa.demo.readiness.service.ReadinessService;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.workspace.service.WorkspaceService;
import io.contexa.demo.experience.journey.service.JourneyStepQuery;
import io.contexa.demo.experience.history.service.HistoryReferenceQuery;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.annotation.Profile;
import org.springframework.context.event.EventListener;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
@Profile("portal")
public class DefaultComparisonRunService implements ComparisonRunService {

    private final UUID instanceId = UUID.randomUUID();
    private final ComparisonPreparationService preparations;
    private final AttestationPairQuery conditions;
    private final ReadinessService readiness;
    private final WorkspaceService workspaces;
    private final RunQuery query;
    private final RunCreationRepository creations;
    private final RunLifecycleRepository lifecycle;
    private final DocumentCodec documents;
    private final RunClientReportRepository clientReports;
    private final RunSubmissionService submissions;
    private final ReviewContractQuery reviewContracts;
    private final RunVariationQuery variations;
    private final JourneyStepQuery journeySteps;
    private final HistoryReferenceQuery historyReferences;

    public DefaultComparisonRunService(ComparisonPreparationService preparations, AttestationPairQuery conditions,
            ReadinessService readiness, WorkspaceService workspaces, RunQuery query, RunCreationRepository creations,
            RunLifecycleRepository lifecycle, DocumentCodec documents, RunClientReportRepository clientReports,
            RunSubmissionService submissions, ReviewContractQuery reviewContracts, RunVariationQuery variations,
            JourneyStepQuery journeySteps, HistoryReferenceQuery historyReferences) {
        this.preparations = preparations;
        this.conditions = conditions;
        this.readiness = readiness;
        this.workspaces = workspaces;
        this.query = query;
        this.creations = creations;
        this.lifecycle = lifecycle;
        this.documents = documents;
        this.clientReports = clientReports;
        this.submissions = submissions;
        this.reviewContracts = reviewContracts;
        this.variations = variations;
        this.journeySteps = journeySteps;
        this.historyReferences = historyReferences;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void recover() {
        lifecycle.interruptPreviousCoordinator(instanceId);
    }

    @Override
    public List<RunSummary> recent(UUID visitorId) {
        return query.recent(visitorId);
    }

    @Override
    public RunView create(UUID visitorId, RunCommand command) {
        return submissions.track(visitorId, command, () -> createObserved(visitorId, command));
    }

    private RunView createObserved(UUID visitorId, RunCommand command) {
        String inputHash = documents.hash(documents.write(command));
        if (query.findCommand(visitorId, command.commandId()) != null) {
            return find(visitorId, creations.reuse(visitorId, command.commandId(), inputHash).id());
        }
        var prepared = preparations.find(visitorId, command.preparationId());
        var workspace = workspaces.current(visitorId);
        if (workspace == null || !workspace.id().equals(prepared.workspaceId())
                || !workspace.expiresAt().isAfter(Instant.now())) {
            throw new ResponseStatusException(HttpStatus.GONE, "WORKSPACE_EXPIRED");
        }
        var pair = conditions.inspect(visitorId, prepared.id(), command.baselineAttestationId(),
                command.contexaAttestationId());
        if (!pair.initialConditionsMatch()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "INITIAL_CONDITIONS_NOT_MATCHED");
        }
        var currentReadiness = readiness.inspect(false, true);
        if (!currentReadiness.foundationReady() || currentReadiness.workers().size() != 2) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "EXECUTION_FOUNDATION_UNAVAILABLE");
        }
        var plan = prepared.snapshot().requestPlan();
        if (!Set.of("DOCUMENT_READ_PAIR", "CUSTOMER_READ_PAIR", "DOCUMENT_DOWNLOAD_PAIR", "BUSINESS_EXPORT_PAIR").contains(plan.kind()) || plan.requestsPerArm() != 1) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "UNSUPPORTED_REQUEST_PLAN");
        }
        var schedule = new RequestSchedule(1, 2, Duration.ZERO, Duration.ofSeconds(60),
                Duration.ofMinutes(2), "ONE_DISPATCH_PER_ARM_OR_CANCEL_OR_DEADLINE", false);
        var manifest = new RunManifest(plan.kind() + "_V1", prepared.id(), prepared.snapshotSha256(), plan,
                pair.attestations(), schedule, "OBSERVE_HTTP_AND_NATIVE_EVIDENCE_SEPARATELY_NO_MODEL_SCORE",
                List.of("NATIVE_HISTORY_READS_NOT_ATOMIC_EMPTY_LIST_NOT_ABSENCE_PROOF",
                        "PER_REQUEST_OPTIONS_AND_DYNAMIC_PROMPT_LINKED_AFTER_DISPATCH",
                        "SECURITY_EFFECTIVENESS_REQUIRES_SEPARATE_SCENARIO_REVIEW"),
                currentReadiness, reviewContracts.capture(plan.kind()), variations.capture(visitorId, plan, pair.attestations()),
                journeySteps.capture(visitorId, plan), historyReferences.capture(visitorId, plan, pair.attestations()));
        Instant createdAt = Instant.now();
        Instant deadline = createdAt.plus(schedule.dispatchWindow());
        if (workspace.expiresAt().isBefore(deadline)) {
            deadline = workspace.expiresAt();
        }
        var candidate = new RunRecord(UUID.randomUUID(), visitorId, workspace.id(), command.commandId(), instanceId,
                createdAt, deadline, inputHash, documents.hash(documents.write(manifest)), manifest, "READY");
        return find(visitorId, creations.save(candidate).id());
    }

    @Override
    public RunView find(UUID visitorId, UUID runId) {
        if (query.find(visitorId, runId) == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        lifecycle.expire(visitorId, runId);
        var events = query.events(runId);
        return new RunView(query.find(visitorId, runId), query.steps(runId),
                events.stream().limit(500).toList(), 500, events.size() > 500, clientReports.find(visitorId, runId));
    }

    @Override
    public RunView cancel(UUID visitorId, UUID runId) {
        find(visitorId, runId);
        lifecycle.cancel(visitorId, runId);
        return find(visitorId, runId);
    }
}
