package io.contexa.contexaiam.admin.promptquality.official.state;

import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Locale;

public class NoopPromptQualityStateCatalog implements PromptQualityStateCatalog {

    @Override
    public List<PromptQualityStateDescriptor> descriptors() {
        return List.of();
    }

    @Override
    public PromptQualityStateDescriptor describe(PromptQualityStateDimension dimension, String code) {
        if (PromptQualityStateDimension.EXECUTION_STATE.equals(dimension)) {
            String normalized = normalize(code);
            return descriptor(dimension, "QUALITY_PROCESS_HOME", normalized, normalized, "neutral", normalized, List.of(), "", 0);
        }
        if (PromptQualityStateDimension.PROCESS_STAGE.equals(dimension)) {
            String normalized = normalize(code);
            return descriptor(dimension, normalized, normalized, normalized, "neutral", "PROCESS", List.of(), "", 0);
        }
        if (PromptQualityStateDimension.RESOURCE_OPERATIONAL.equals(dimension)) {
            return resourceOperational(code);
        }
        return unknown(dimension, code);
    }

    @Override
    public PromptQualityStateDescriptor resourceRequestObservation(boolean evidenceObserved, boolean decisionRecorded) {
        if (decisionRecorded) {
            return descriptor(PromptQualityStateDimension.RESOURCE_REQUEST_OBSERVATION, "OFFICIAL_VERIFICATION",
                    "RUNTIME_DECISION_RECORDED", "RUNTIME_DECISION_RECORDED", "reverify", "DECISION_RECORDED",
                    List.of("RUN_OFFICIAL_VERIFICATION"), "", 0);
        }
        if (evidenceObserved) {
            return descriptor(PromptQualityStateDimension.RESOURCE_REQUEST_OBSERVATION, "RUNTIME_EVIDENCE",
                    "RUNTIME_EVIDENCE_RECORDED", "RUNTIME_EVIDENCE_RECORDED", "pending", "OBSERVED",
                    List.of("OPEN_RUNTIME_EVIDENCE"), "", 0);
        }
        return descriptor(PromptQualityStateDimension.RESOURCE_REQUEST_OBSERVATION, "PROTECTABLE_RESOURCES",
                "REQUEST_NOT_OBSERVED", "REQUEST_NOT_OBSERVED", "neutral", "NOT_OBSERVED",
                List.of(), "", 0);
    }

    @Override
    public PromptQualityStateDescriptor runtimeEvidence(boolean sealed, boolean integrityValid, boolean warningSignals) {
        if (!sealed) {
            return unknown(PromptQualityStateDimension.RUNTIME_EVIDENCE, "UNSEALED");
        }
        if (!integrityValid) {
            return unknown(PromptQualityStateDimension.RUNTIME_EVIDENCE, "INTEGRITY_ERROR");
        }
        if (warningSignals) {
            return unknown(PromptQualityStateDimension.RUNTIME_EVIDENCE, "WARNING_SIGNALS");
        }
        return unknown(PromptQualityStateDimension.RUNTIME_EVIDENCE, "READY_FOR_INSPECTION");
    }

    @Override
    public List<String> resourceOperationalActions(String operationalState, boolean promotable) {
        if (promotable) {
            return List.of("ENABLE_ZERO_TRUST", "REQUEST_REVERIFY", "BLOCK_RESOURCE", "SUSPEND");
        }
        return resourceOperational(operationalState).allowedActions();
    }

    private PromptQualityStateDescriptor unknown(PromptQualityStateDimension dimension, String code) {
        String normalized = normalize(code);
        return descriptor(dimension, "UNKNOWN", normalized, normalized, "neutral", "UNKNOWN", List.of(), "", 0);
    }

    private PromptQualityStateDescriptor resourceOperational(String code) {
        String normalized = normalize(code);
        return switch (normalized) {
            case "ZERO_TRUST_ENABLED" -> descriptor(
                    PromptQualityStateDimension.RESOURCE_OPERATIONAL,
                    "MONITORING",
                    normalized,
                    normalized,
                    "ready",
                    "READY",
                    List.of("DISABLE_ZERO_TRUST", "REQUEST_REVERIFY", "SUSPEND", "BLOCK_RESOURCE"),
                    "",
                    0);
            case "CERTIFIED" -> descriptor(
                    PromptQualityStateDimension.RESOURCE_OPERATIONAL,
                    "CERTIFICATES_PROMOTION",
                    normalized,
                    normalized,
                    "ready",
                    "READY",
                    List.of("ENABLE_ZERO_TRUST", "REQUEST_REVERIFY", "BLOCK_RESOURCE", "SUSPEND"),
                    "",
                    0);
            case "PENDING_VERIFICATION" -> descriptor(
                    PromptQualityStateDimension.RESOURCE_OPERATIONAL,
                    "OFFICIAL_VERIFICATION",
                    normalized,
                    normalized,
                    "reverify",
                    "REVERIFY",
                    List.of("RUN_OFFICIAL_VERIFICATION", "REQUEST_REVERIFY"),
                    "",
                    0);
            case "BLOCKED" -> descriptor(
                    PromptQualityStateDimension.RESOURCE_OPERATIONAL,
                    "REMEDIATION",
                    normalized,
                    normalized,
                    "blocked",
                    "BLOCKED",
                    List.of("REQUEST_REVERIFY", "RETIRE"),
                    "",
                    0);
            case "SUSPENDED", "EXPIRED" -> descriptor(
                    PromptQualityStateDimension.RESOURCE_OPERATIONAL,
                    "REMEDIATION",
                    normalized,
                    normalized,
                    "reverify",
                    "BLOCKED",
                    List.of("REQUEST_REVERIFY", "RETIRE"),
                    "",
                    0);
            default -> descriptor(
                    PromptQualityStateDimension.RESOURCE_OPERATIONAL,
                    "PROTECTABLE_RESOURCES",
                    normalized,
                    normalized,
                    "pending",
                    "PENDING",
                    List.of("RUN_OFFICIAL_VERIFICATION", "REQUEST_REVERIFY"),
                    "",
                    0);
        };
    }

    private PromptQualityStateDescriptor descriptor(
            PromptQualityStateDimension dimension,
            String processStage,
            String code,
            String label,
            String tone,
            String aggregateGroup,
            List<String> allowedActions,
            String nextAction,
            int order) {
        return new PromptQualityStateDescriptor(
                dimension == null ? "UNKNOWN" : dimension.name(),
                processStage,
                code,
                label,
                tone,
                aggregateGroup,
                allowedActions,
                nextAction,
                order);
    }

    private String normalize(String value) {
        return StringUtils.hasText(value) ? value.trim().toUpperCase(Locale.ROOT) : "UNKNOWN";
    }
}
