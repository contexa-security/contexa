package io.contexa.contexaiam.admin.promptquality.official.application;

import java.util.Objects;

import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationGateCode;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationGateDecision;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationGateFailure;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationVerdict;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceCheckResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceGateResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePromptConsistencyResult;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

public final class OfficialVerificationVerdictFactory {

    public OfficialVerificationVerdict create(
            String packageId,
            String aggregateRunId,
            String decidedAt,
            RuntimeEvidenceGateResult policyResult,
            RuntimeEvidencePromptConsistencyResult promptConsistency) {
        if (policyResult == null) {
            throw new IllegalArgumentException("The certification policy result is required.");
        }

        List<OfficialVerificationGateDecision> gates = new ArrayList<>();
        safeChecks(policyResult.checks()).stream()
                .map(this::decision)
                .forEach(gates::add);

        RuntimeEvidencePromptConsistencyResult consistency = promptConsistency == null
                ? RuntimeEvidencePromptConsistencyResult.empty()
                : promptConsistency;
        safeChecks(consistency.checks()).stream()
                .map(check -> decision(check.withGateCode(OfficialVerificationGateCode.PROMPT_CONSISTENCY)))
                .forEach(gates::add);

        if (!policyResult.passed() && gates.stream().allMatch(OfficialVerificationGateDecision::passed)) {
            gates.add(contractFailure(
                    OfficialVerificationGateCode.POLICY_CONTRACT,
                    "CERTIFICATION_POLICY_RESULT",
                    "certificationPolicy",
                    "passed=true",
                    "passed=false",
                    "The certification policy returned failed without a failed check."));
        }
        if (!consistency.passed()
                && gates.stream()
                .filter(gate -> gate.gateCode() == OfficialVerificationGateCode.PROMPT_CONSISTENCY)
                .allMatch(OfficialVerificationGateDecision::passed)) {
            gates.add(contractFailure(
                    OfficialVerificationGateCode.PROMPT_CONSISTENCY,
                    "PROMPT_CONSISTENCY_RESULT",
                    "promptConsistencyGate",
                    "passed=true",
                    "passed=false",
                    "Prompt consistency failed without a failed check."));
        }

        List<OfficialVerificationGateFailure> failures = gates.stream()
                .filter(gate -> !gate.passed())
                .map(OfficialVerificationGateFailure::from)
                .toList();
        boolean eligible = policyResult.passed() && consistency.passed() && failures.isEmpty();
        return new OfficialVerificationVerdict(
                packageId,
                aggregateRunId,
                eligible ? OfficialVerificationVerdict.Status.ELIGIBLE : OfficialVerificationVerdict.Status.INELIGIBLE,
                gates,
                failures,
                distinct(policyResult.findings(), consistency.findings()),
                distinct(policyResult.nextActions(), consistency.nextActions()),
                decidedAt);
    }

    private OfficialVerificationGateDecision decision(RuntimeEvidenceCheckResult check) {
        OfficialVerificationGateCode gateCode = check.gateCode() == null
                ? OfficialVerificationGateCode.UNCLASSIFIED
                : check.gateCode();
        String message = hasText(check.operatorReason()) ? check.operatorReason() : check.label();
        return new OfficialVerificationGateDecision(
                gateCode,
                check.metricCode(),
                check.checkCode(),
                check.source(),
                check.expectedValue(),
                check.actualValue(),
                check.pass(),
                gateCode.messageKey(),
                message,
                check.nextAction());
    }

    private OfficialVerificationGateDecision contractFailure(
            OfficialVerificationGateCode gateCode,
            String checkCode,
            String source,
            String expected,
            String actual,
            String message) {
        return new OfficialVerificationGateDecision(
                gateCode,
                "",
                checkCode,
                source,
                expected,
                actual,
                false,
                gateCode.messageKey(),
                message,
                "Inspect the gate implementation and produce an explicit failed check.");
    }

    private List<RuntimeEvidenceCheckResult> safeChecks(List<RuntimeEvidenceCheckResult> checks) {
        return checks == null ? List.of() : checks.stream().filter(Objects::nonNull).toList();
    }

    @SafeVarargs
    private final List<String> distinct(List<String>... values) {
        LinkedHashSet<String> result = new LinkedHashSet<>();
        if (values != null) {
            for (List<String> list : values) {
                if (list == null) {
                    continue;
                }
                list.stream().filter(this::hasText).map(String::trim).forEach(result::add);
            }
        }
        return List.copyOf(result);
    }

    private boolean hasText(String value) {
        return value != null && !value.trim().isEmpty();
    }
}
