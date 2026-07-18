package io.contexa.contexaiam.admin.promptquality.official.model;

import java.util.List;

public record OfficialVerificationVerdict(
        String packageId,
        String aggregateRunId,
        Status status,
        List<OfficialVerificationGateDecision> gates,
        List<OfficialVerificationGateFailure> failures,
        List<String> findings,
        List<String> nextActions,
        String decidedAt) {

    public enum Status {
        ELIGIBLE,
        INELIGIBLE
    }

    public OfficialVerificationVerdict {
        packageId = value(packageId);
        aggregateRunId = value(aggregateRunId);
        status = status == null ? Status.INELIGIBLE : status;
        gates = gates == null ? List.of() : List.copyOf(gates);
        failures = failures == null ? List.of() : List.copyOf(failures);
        findings = findings == null ? List.of() : List.copyOf(findings);
        nextActions = nextActions == null ? List.of() : List.copyOf(nextActions);
        decidedAt = value(decidedAt);
        if (status == Status.ELIGIBLE && (!failures.isEmpty() || gates.stream().anyMatch(gate -> !gate.passed()))) {
            throw new IllegalArgumentException("An eligible official verification verdict cannot contain failed gates.");
        }
    }

    public boolean eligible() {
        return status == Status.ELIGIBLE;
    }

    private static String value(String value) {
        return value == null ? "" : value.trim();
    }
}
