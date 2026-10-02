package io.contexa.demo.experience.history.service.impl;

import io.contexa.demo.comparison.attestation.dto.ArmAttestation;
import io.contexa.demo.comparison.preparation.dto.ComparisonRequestPlan;
import io.contexa.demo.experience.history.dto.FrozenHistoryReference;
import io.contexa.demo.experience.history.dto.HistoryOrigin;
import io.contexa.demo.experience.history.service.HistoryReferenceQuery;
import io.contexa.demo.experience.report.repository.ReportRepository;
import io.contexa.demo.shared.document.DocumentCodec;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Component
@Profile("portal")
public class StoredHistoryReferenceQuery implements HistoryReferenceQuery {

    private final ReportRepository reports;
    private final DocumentCodec documents;

    public StoredHistoryReferenceQuery(ReportRepository reports, DocumentCodec documents) {
        this.reports = reports;
        this.documents = documents;
    }

    @Override
    public FrozenHistoryReference capture(UUID visitorId, ComparisonRequestPlan plan, List<ArmAttestation> current) {
        if (plan.historyReportId() == null) {
            return null;
        }
        var report = reports.find(visitorId, plan.historyReportId());
        if (report == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        var sourceRun = report.payload().execution().run();
        if (!Objects.equals(sourceRun.id(), plan.parentRunId())
                || !sourceRun.manifest().plan().requestedAccount().equals(plan.requestedAccount())) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "HISTORY_SOURCE_MISMATCH");
        }
        if (!"PRESERVED_JSON_V2".equals(report.archiveState())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "HISTORY_SOURCE_ENCODING_UNVERIFIED");
        }
        List<HistoryOrigin> origins = new ArrayList<>();
        for (var source : report.payload().sources()) {
            if (!"contexa".equals(source.arm()) || !"CAPTURED".equals(source.state()) || source.evidence() == null) {
                continue;
            }
            for (var event : source.evidence().path("analysisEvents")) {
                String kind = event.path("kind").asText();
                boolean observed = "BASELINE_WRITE".equals(kind) && event.path("payload").path("sameValueObserved").asBoolean()
                        || "RAG_WRITE".equals(kind) && event.path("payload").path("matchingDocumentObserved").asBoolean();
                if (observed) {
                    origins.add(new HistoryOrigin(event.path("id").asText(), source.requestId().toString(), kind,
                            documents.hash(documents.write(event))));
                }
            }
        }
        if (origins.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "HISTORY_WRITE_NOT_OBSERVED");
        }
        var before = sourceRun.manifest().initialConditions().stream()
                .filter(value -> "contexa".equals(value.arm())).findFirst().orElse(null);
        var now = current.stream().filter(value -> "contexa".equals(value.arm())).findFirst().orElse(null);
        String compatibility = before == null || now == null ? "NOT_CHECKED"
                : Objects.equals(before.snapshot().environment().applicationSha256(), now.snapshot().environment().applicationSha256())
                        ? "SAME_APPLICATION" : "DIFFERENT_APPLICATION";
        return new FrozenHistoryReference(report.id(), report.contentSha256(), sourceRun.id(), sourceRun.manifestSha256(),
                report.createdAt(), plan.requestedAccount(), List.copyOf(origins), compatibility,
                now == null ? "NOT_CHECKED" : now.snapshot().history().state(),
                List.of("ACTUAL_PRIOR_WRITES_NOT_SYNTHETIC_BASELINE", "CURRENT_HISTORY_RECHECKED_NO_STATE_RESTORE",
                        "REFERENCE_DOES_NOT_PROVE_CURRENT_RETRIEVAL_OR_CAUSAL_USE",
                        "OLD_SESSION_AND_SECURITY_ACTION_NOT_RESTORED", "MODEL_POLICY_DATA_COMPATIBILITY_IN_RUN_VARIATION"));
    }
}
