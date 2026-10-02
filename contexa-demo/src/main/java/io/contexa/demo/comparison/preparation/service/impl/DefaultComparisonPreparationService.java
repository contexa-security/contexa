package io.contexa.demo.comparison.preparation.service.impl;

import io.contexa.demo.comparison.preparation.dto.ArmDocumentFingerprint;
import io.contexa.demo.comparison.preparation.dto.ArmCustomerFingerprint;
import io.contexa.demo.comparison.preparation.dto.ComparisonResourceFingerprint;
import io.contexa.demo.comparison.preparation.dto.ComparisonPreparationSnapshot;
import io.contexa.demo.comparison.preparation.dto.ComparisonRequestPlan;
import io.contexa.demo.comparison.preparation.dto.ComparisonFileRequest;
import io.contexa.demo.comparison.preparation.dto.PreparationBlocker;
import io.contexa.demo.comparison.preparation.dto.PreparationCommand;
import io.contexa.demo.comparison.preparation.dto.PreparedComparison;
import io.contexa.demo.comparison.preparation.repository.ComparisonPreparationRepository;
import io.contexa.demo.comparison.preparation.service.ComparisonPreparationService;
import io.contexa.demo.comparison.preparation.service.PreparationEligibility;
import io.contexa.demo.comparison.variation.service.RunVariationQuery;
import io.contexa.demo.comparison.batch.dto.ArmBatchFingerprint;
import io.contexa.demo.comparison.batch.dto.ComparisonExportSelection;
import io.contexa.demo.comparison.batch.source.ComparisonBatchSource;
import io.contexa.demo.comparison.preparation.source.ComparisonDocumentSource;
import io.contexa.demo.comparison.preparation.source.ComparisonCustomerSource;
import io.contexa.demo.readiness.dto.ReadinessReport;
import io.contexa.demo.readiness.service.ReadinessService;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.workspace.dto.WorkspaceView;
import io.contexa.demo.workspace.service.WorkspaceService;
import io.contexa.demo.experience.journey.service.JourneyStepQuery;
import io.contexa.demo.experience.history.service.HistoryReferenceQuery;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
@Profile("portal")
public class DefaultComparisonPreparationService implements ComparisonPreparationService {

    private final WorkspaceService workspaces;
    private final ComparisonPreparationRepository repository;
    private final List<ComparisonDocumentSource> sources;
    private final List<ComparisonCustomerSource> customers;
    private final ReadinessService readiness;
    private final PreparationEligibility eligibility;
    private final DocumentCodec documents;
    private final RunVariationQuery variations;
    private final ComparisonBatchSource batches;
    private final JourneyStepQuery journeySteps;
    private final HistoryReferenceQuery historyReferences;

    public DefaultComparisonPreparationService(WorkspaceService workspaces, ComparisonPreparationRepository repository,
            List<ComparisonDocumentSource> sources, ReadinessService readiness, PreparationEligibility eligibility,
            DocumentCodec documents, List<ComparisonCustomerSource> customers, RunVariationQuery variations,
            ComparisonBatchSource batches, JourneyStepQuery journeySteps, HistoryReferenceQuery historyReferences) {
        this.workspaces = workspaces;
        this.repository = repository;
        this.sources = sources;
        this.readiness = readiness;
        this.eligibility = eligibility;
        this.documents = documents;
        this.customers = List.copyOf(customers);
        this.variations = variations;
        this.batches = batches;
        this.journeySteps = journeySteps;
        this.historyReferences = historyReferences;
    }

    @Override
    public PreparedComparison prepare(UUID visitorId, PreparationCommand command) {
        WorkspaceView workspace = workspaces.current(visitorId);
        if (workspace == null || !workspace.expiresAt().isAfter(Instant.now())) {
            throw new ResponseStatusException(HttpStatus.GONE, "WORKSPACE_EXPIRED");
        }
        if (!workspace.allowedAccounts().contains(command.requestedAccount())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "ACCOUNT_NOT_ASSIGNED");
        }
        boolean customer = command.customerId() != null;
        boolean batch = command.exportSelection() != null;
        variations.requireParent(visitorId, command.parentRunId(), command.requestedAccount());
        boolean download = "DOWNLOAD".equals(command.operation()) || batch;
        String kind = batch ? "BUSINESS_EXPORT_PAIR" : customer ? "CUSTOMER_READ_PAIR" : download ? "DOCUMENT_DOWNLOAD_PAIR" : "DOCUMENT_READ_PAIR";
        ComparisonFileRequest fileRequest = download ? new ComparisonFileRequest(command.commandId(), command.language()) : null;
        var selection = command.exportSelection();
        ComparisonExportSelection export = !batch ? null : new ComparisonExportSelection(selection.resourceType(),
                selection.targetIds().stream().sorted().toList(), selection.baselineApprovalId(), selection.contexaApprovalId());
        ComparisonRequestPlan plan = new ComparisonRequestPlan(kind, "POST",
                batch ? "/api/work/exports/download" : customer ? "/api/work/customers/" + command.customerId() + "/read"
                        : "/api/work/documents/" + command.documentId() + (download ? "/download" : "/read"),
                command.requestedAccount(), command.purpose(), 1, fileRequest, command.parentRunId(), export,
                command.journeyStep(), command.approvalReferences(), command.historyReportId());
        journeySteps.capture(visitorId, plan);
        historyReferences.capture(visitorId, plan, List.of());
        String inputHash = documents.hash(documents.write(plan));
        PreparedComparison previous = repository.findCommand(visitorId, command.commandId());
        if (previous != null) {
            return repository.save(previous, inputHash, workspace.id());
        }
        List<ArmDocumentFingerprint> captured = customer || batch ? List.of() : sources.stream().map(source -> source.capture(command.documentId()))
                .sorted((first, second) -> first.arm().compareTo(second.arm())).toList();
        List<ArmCustomerFingerprint> customerSources = customer ? customers.stream()
                .map(source -> source.capture(command.customerId()))
                .sorted((first, second) -> first.arm().compareTo(second.arm())).toList() : null;
        List<ArmBatchFingerprint> batchSources = batch ? List.of(batches.capture("baseline", export), batches.capture("contexa", export)) : null;
        List<? extends ComparisonResourceFingerprint> resources = batch ? batchSources : customer ? customerSources : captured;
        boolean matched = resources.size() == 2 && resources.stream().allMatch(value -> "CAPTURED".equals(value.state()))
                && resources.get(0).sourceSha256().equals(resources.get(1).sourceSha256());
        ReadinessReport report = readiness.inspect(false, true);
        List<PreparationBlocker> blockers = eligibility.inspect(report, matched);
        ComparisonPreparationSnapshot snapshot = new ComparisonPreparationSnapshot(plan, captured, !customer && !batch && matched, report,
                blockers, blockers.isEmpty(), customerSources, customer ? matched : null, batchSources, batch ? matched : null);
        PreparedComparison candidate = new PreparedComparison(UUID.randomUUID(), visitorId, workspace.id(),
                command.commandId(), Instant.now(), inputHash, documents.hash(documents.write(snapshot)), snapshot);
        return repository.save(candidate, inputHash, workspace.id());
    }

    @Override
    public PreparedComparison find(UUID visitorId, UUID id) {
        PreparedComparison stored = repository.find(visitorId, id);
        if (stored == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        return stored;
    }
}
