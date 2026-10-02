package io.contexa.demo.comparison.variation.service.impl;

import io.contexa.demo.comparison.attestation.dto.ArmAttestation;
import io.contexa.demo.comparison.attestation.dto.AttestationSnapshot;
import io.contexa.demo.comparison.preparation.dto.ComparisonRequestPlan;
import io.contexa.demo.comparison.run.dto.RunRecord;
import io.contexa.demo.comparison.run.repository.RunQuery;
import io.contexa.demo.comparison.variation.dto.ConditionDelta;
import io.contexa.demo.comparison.variation.dto.RunVariation;
import io.contexa.demo.comparison.variation.service.RunVariationQuery;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.work.approval.dto.ApprovalEvidence;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.TreeMap;

@Component
@Profile("portal")
public class StoredRunVariationQuery implements RunVariationQuery {

    private final RunQuery runs;
    private final DocumentCodec documents;

    public StoredRunVariationQuery(RunQuery runs, DocumentCodec documents) {
        this.runs = runs;
        this.documents = documents;
    }

    @Override
    public void requireParent(UUID visitorId, UUID parentRunId, String account) {
        if (parentRunId != null) {
            parent(visitorId, parentRunId, account);
        }
    }

    @Override
    public RunVariation capture(UUID visitorId, ComparisonRequestPlan plan, List<ArmAttestation> current) {
        if (plan.parentRunId() == null) {
            return null;
        }
        var previous = parent(visitorId, plan.parentRunId(), plan.requestedAccount());
        var priorPlan = previous.manifest().plan();
        List<ConditionDelta> changes = new ArrayList<>();
        add(changes, "both", "PURPOSE", "USER_DECLARED_PURPOSE", priorPlan.purpose(), plan.purpose());
        add(changes, "both", "RESOURCE", "REQUEST_PLAN", priorPlan.path(), plan.path());
        add(changes, "both", "OPERATION", "REQUEST_PLAN", priorPlan.kind(), plan.kind());
        add(changes, "both", "LANGUAGE", "REQUEST_PLAN",
                priorPlan.fileRequest() == null ? "NOT_APPLICABLE" : priorPlan.fileRequest().language(),
                plan.fileRequest() == null ? "NOT_APPLICABLE" : plan.fileRequest().language());
        for (var now : current) {
            var before = previous.manifest().initialConditions().stream()
                    .filter(value -> value.arm().equals(now.arm())).findFirst().orElse(null);
            if (before == null) {
                add(changes, now.arm(), "INITIAL_SOURCES", "OBSERVATION", null, now.snapshotSha256());
            } else {
                compare(changes, now.arm(), before.snapshot(), now.snapshot());
            }
        }
        String interpretation = changes.stream().anyMatch(value -> "UNKNOWN".equals(value.state()))
                ? "INCOMPLETE_CONDITIONS_NO_CAUSAL_CLAIM" : "OBSERVED_DIFFERENCES_NO_CAUSAL_CLAIM";
        return new RunVariation(previous.id(), previous.manifestSha256(), List.copyOf(changes), interpretation,
                "REAL_BUSINESS_RECORDS_AND_OBSERVED_HISTORY_NO_INJECTED_SECURITY_INPUT");
    }

    private RunRecord parent(UUID visitorId, UUID id, String account) {
        RunRecord value = runs.find(visitorId, id);
        if (value == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        if (!Objects.equals(value.manifest().plan().requestedAccount(), account)) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "VARIATION_ACCOUNT_MUST_MATCH");
        }
        return value;
    }

    private void compare(List<ConditionDelta> target, String arm, AttestationSnapshot before, AttestationSnapshot now) {
        add(target, arm, "PERMISSIONS", "AUTHENTICATION", before.identity().accountAuthorities(), now.identity().accountAuthorities());
        add(target, arm, "STATIC_POLICY", "CONFIGURATION", before.identity().staticPolicySha256(), now.identity().staticPolicySha256());
        add(target, arm, "SESSION", "AUTHENTICATION", before.sessionSha256(), now.sessionSha256());
        add(target, arm, "ASSIGNMENTS", "BUSINESS_RECORD", before.assignedProjects(), now.assignedProjects());
        add(target, arm, "BUSINESS_DATA", "BUSINESS_RECORD", before.resource().sourceSha256(), now.resource().sourceSha256());
        add(target, arm, "BUSINESS_APPROVAL", "BUSINESS_RECORD",
                approvalFacts(before.approval()), approvalFacts(now.approval()));
        add(target, arm, "APPLICATION", "CONFIGURATION", before.environment().applicationSha256(), now.environment().applicationSha256());
        add(target, arm, "RUNTIME_CONFIGURATION", "CONFIGURATION",
                new TreeMap<>(before.environment().effectiveConfiguration()), new TreeMap<>(now.environment().effectiveConfiguration()));
        add(target, arm, "BASELINE", "OBSERVED_HISTORY", before.history().baselineSha256(), now.history().baselineSha256());
        add(target, arm, "PRIOR_ACTION", "OBSERVED_HISTORY", before.history().analysisSha256(), now.history().analysisSha256());
        if ("contexa".equals(arm)) {
            add(target, arm, "MODEL_AND_POLICY", "CONFIGURATION",
                    before.environment().nativeConfiguration() == null ? null : before.environment().nativeConfiguration().configurationSha256(),
                    now.environment().nativeConfiguration() == null ? null : now.environment().nativeConfiguration().configurationSha256());
            add(target, arm, "RAG_INVENTORY", "OBSERVED_HISTORY",
                    before.environment().ragInventory() == null ? null : before.environment().ragInventory().inventorySha256(),
                    now.environment().ragInventory() == null ? null : now.environment().ragInventory().inventorySha256());
        }
    }

    private ApprovalEvidence approvalFacts(ApprovalEvidence evidence) {
        if (evidence == null) {
            return null;
        }
        return new ApprovalEvidence(evidence.approvalId(), evidence.decisionId(), evidence.required(),
                evidence.status(), evidence.requester(), evidence.reviewer(), evidence.purpose(), evidence.targets(),
                evidence.decidedAt(), evidence.expiresAt(), null, evidence.source());
    }

    private void add(List<ConditionDelta> target, String arm, String condition, String provenance, Object before, Object now) {
        String previousHash = before == null ? null : documents.hash(documents.write(before));
        String currentHash = now == null ? null : documents.hash(documents.write(now));
        String state = before == null || now == null ? "UNKNOWN" : Objects.equals(before, now) ? "FIXED" : "CHANGED";
        target.add(new ConditionDelta(arm, condition, provenance, state, previousHash, currentHash));
    }
}
