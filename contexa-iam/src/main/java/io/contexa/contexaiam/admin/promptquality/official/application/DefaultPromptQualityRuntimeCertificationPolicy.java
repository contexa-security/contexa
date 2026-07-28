package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.adjudication.ScorecardResult;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.replay.DeterministicReplayResult;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationGateCode;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceCheckResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceGateResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeGovernanceDescriptorVerificationResult;
import io.contexa.contexaiam.admin.promptquality.official.application.support.AbstractPromptQualityRuntimeEvidenceSupport;
import org.springframework.util.StringUtils;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class DefaultPromptQualityRuntimeCertificationPolicy
        extends AbstractPromptQualityRuntimeEvidenceSupport
        implements PromptQualityRuntimeCertificationPolicy {

    private static final int PROMPT_QUALITY_METRIC_COUNT = 12;
    private static final Set<String> PROMPT_QUALITY_METRIC_CODES = Set.of(
            "EIR", "CCR", "CCSR", "PFR", "MTR", "COR",
            "RAP", "RPI", "BMA", "USNS", "BSR", "PRE");
    private static final Set<String> PASS_STATES = Set.of("SUCCESS", "PASS", "PASSED", "VERIFIED", "COMPLETED");

    private final PromptRuntimeGovernanceDescriptorVerifier governanceDescriptorVerifier;

    public DefaultPromptQualityRuntimeCertificationPolicy(
            ObjectMapper objectMapper,
            PromptRuntimeGovernanceDescriptorVerifier governanceDescriptorVerifier,
            PromptQualityMessageResolver messageResolver) {
        super(
                Objects.requireNonNull(objectMapper, "objectMapper"),
                Objects.requireNonNull(messageResolver, "messageResolver"));
        this.governanceDescriptorVerifier = Objects.requireNonNull(
                governanceDescriptorVerifier,
                "governanceDescriptorVerifier");
    }

    @Override
    public RuntimeEvidenceGateResult evaluate(
            SealedEvidencePackage evidencePackage,
            boolean integrityValid,
            ScorecardResult scorecard,
            DeterministicReplayResult replay,
            List<? extends OfficialVerificationRunView> metrics) {
        List<RuntimeEvidenceCheckResult> checks = new ArrayList<>();
        List<String> findings = new ArrayList<>();
        List<String> actions = new ArrayList<>();
        Map<String, Object> requestFacts = parseJson(evidencePackage.getRequestFactsJson());
        Map<String, Object> promptMetadata = parsePromptExecutionMetadataHeader(evidencePackage.getPromptExecutionMetadataJson());
        String requestPath = requestPath(evidencePackage, requestFacts);
        String resourceId = firstNonBlank(
                text(requestFacts, "resourceId"),
                text(requestFacts, "endpointKey"),
                text(promptMetadata, "resourceId"),
                text(promptMetadata, "endpointKey"));
        String method = firstNonBlank(text(requestFacts, "httpMethod"), text(requestFacts, "method"));

        add(checks, OfficialVerificationGateCode.PACKAGE_ID, "PRE", "sealed evidence packageId exists", "packageId",
                evidencePackage.getPackageId(), StringUtils.hasText(evidencePackage.getPackageId()), "sealedEvidence");
        add(checks, OfficialVerificationGateCode.SEALED_EVIDENCE, "PRE", "sealed evidence is locked", "sealed=true",
                String.valueOf(evidencePackage.isSealed()), evidencePackage.isSealed(), "sealedEvidence");
        add(checks, OfficialVerificationGateCode.EVIDENCE_INTEGRITY, "PRE", "sealed evidence integrity is valid", "integrity pass",
                integrityValid ? "pass" : "fail", integrityValid, "sealedEvidence");
        add(checks, OfficialVerificationGateCode.RESOURCE_PATH, "PRE", "request resource path exists", "request URL exists",
                firstNonBlank(requestPath, "missing"), StringUtils.hasText(requestPath), "resourceScope");
        add(checks, OfficialVerificationGateCode.RESOURCE_ID, "PRE", "resource id exists", "resource id exists",
                firstNonBlank(resourceId, "missing"), StringUtils.hasText(resourceId), "resourceScope");
        add(checks, OfficialVerificationGateCode.HTTP_METHOD, "PRE", "HTTP method exists", "GET/POST or request method exists",
                firstNonBlank(method, "missing"), StringUtils.hasText(method), "resourceScope");
        add(checks, OfficialVerificationGateCode.RAW_SYSTEM_PROMPT, "PFR", "raw system prompt captured", "captured",
                hasText(evidencePackage.getRawSystemPrompt()) ? "captured" : "missing",
                hasText(evidencePackage.getRawSystemPrompt()), "promptCapture");
        add(checks, OfficialVerificationGateCode.RAW_USER_PROMPT, "PFR", "raw user prompt captured", "captured",
                hasText(evidencePackage.getRawUserPrompt()) ? "captured" : "missing",
                hasText(evidencePackage.getRawUserPrompt()), "promptCapture");
        add(checks, OfficialVerificationGateCode.FINAL_LLM_PROMPT, "PFR", "LLM prompt captured", "captured",
                hasText(evidencePackage.getSystemPromptText()) && hasText(evidencePackage.getUserPromptText()) ? "captured" : "missing",
                hasText(evidencePackage.getSystemPromptText()) && hasText(evidencePackage.getUserPromptText()), "promptCapture");
        add(checks, OfficialVerificationGateCode.PROMPT_HASH, "PFR", "prompt hash exists", "promptHash exists",
                firstNonBlank(evidencePackage.getPromptHash(), "missing"),
                hasText(evidencePackage.getPromptHash()), "promptCapture");
        add(checks, OfficialVerificationGateCode.REPLAY_HASH, "PFR", "prompt hash matches deterministic replay", "raw hash matches replay hash",
                replayHashLabel(evidencePackage, replay),
                replayHashMatches(evidencePackage, replay), "deterministicReplay");

        RuntimeGovernanceDescriptorVerificationResult governanceResult = governanceDescriptorVerifier.verify(
                evidencePackage,
                promptMetadata);
        governanceResult.checks().stream()
                .map(check -> check.withGateCode(OfficialVerificationGateCode.GOVERNANCE_DESCRIPTOR))
                .forEach(checks::add);
        checks.addAll(promptEvidenceManifestChecks(evidencePackage));

        // The legacy structural scorecard remains diagnostic input only. The authoritative
        // prompt-quality certification gate is the non-overlapping 12-metric set below.

        boolean replayPassed = replay != null
                && replay.checksRun() > 0
                && replay.checksPassed() >= replay.checksRun();
        add(checks, OfficialVerificationGateCode.DETERMINISTIC_REPLAY, "MTR", "deterministic replay matches sealed evidence", "all replay checks pass",
                replay == null ? "not executed" : replay.checksPassed() + "/" + replay.checksRun(),
                replayPassed, "deterministicReplay");

        Set<String> actualPromptMetricCodes = metrics == null
                ? Set.of()
                : metrics.stream()
                        .map(OfficialVerificationRunView::endpointKey)
                        .filter(StringUtils::hasText)
                        .map(code -> code.trim().toUpperCase(Locale.ROOT))
                        .filter(PROMPT_QUALITY_METRIC_CODES::contains)
                        .collect(Collectors.toUnmodifiableSet());
        boolean allMetricsPresent = actualPromptMetricCodes.containsAll(PROMPT_QUALITY_METRIC_CODES);
        long failedOfficialMetrics = metrics == null
                ? PROMPT_QUALITY_METRIC_COUNT
                : metrics.stream()
                        .filter(run -> run != null && StringUtils.hasText(run.endpointKey()))
                        .filter(run -> PROMPT_QUALITY_METRIC_CODES.contains(
                                run.endpointKey().trim().toUpperCase(Locale.ROOT)))
                        .filter(run -> !officialRunPassed(run))
                        .count();
        add(checks, OfficialVerificationGateCode.REQUIRED_METRICS, "PRE", "12 prompt quality metric results exist", String.valueOf(PROMPT_QUALITY_METRIC_COUNT),
                String.valueOf(actualPromptMetricCodes.size()), allMetricsPresent, "coreOfficialRuntime");
        add(checks, OfficialVerificationGateCode.METRIC_RESULTS, "PRE", "prompt quality metrics passed", "all prompt quality metric runs pass",
                failedOfficialMetrics == 0 ? "all pass" : failedOfficialMetrics + " failed",
                allMetricsPresent && failedOfficialMetrics == 0, "coreOfficialRuntime");

        checks.stream().filter(check -> !check.pass()).forEach(check -> {
            findings.add(message("enterprise.pqa.consistency.gate.issue",
                    metricName(check.metricCode()), gateLabel(check.label()), operatorValue(check.actualValue())));
            actions.add(actionFor(check.metricCode()));
        });
        findings.addAll(governanceResult.findings());
        actions.addAll(governanceResult.nextActions());
        boolean passed = checks.stream().allMatch(RuntimeEvidenceCheckResult::pass);
        return new RuntimeEvidenceGateResult(
                passed,
                List.copyOf(checks),
                findings.stream().distinct().toList(),
                actions.stream().distinct().toList());
    }

    private void add(
            List<RuntimeEvidenceCheckResult> checks,
            OfficialVerificationGateCode gateCode,
            String metricCode,
            String label,
            String expected,
            String actual,
            boolean pass,
            String source) {
        checks.add(new RuntimeEvidenceCheckResult(metricCode, label, expected, actual, pass, source).withGateCode(gateCode));
    }

    private List<RuntimeEvidenceCheckResult> promptEvidenceManifestChecks(SealedEvidencePackage evidencePackage) {
        Map<String, Object> manifest = parseJson(evidencePackage == null ? null : evidencePackage.getPromptEvidenceManifestJson());
        Object fields = manifest.get("fields");
        if (!(fields instanceof List<?> rows) || rows.isEmpty()) {
            return List.of();
        }
        List<RuntimeEvidenceCheckResult> checks = new ArrayList<>();
        for (Object row : rows) {
            if (!(row instanceof Map<?, ?> field) || !booleanValue(field.get("blocking"))) {
                continue;
            }
            String fieldKey = stringValue(field.get("fieldKey"));
            String displayName = firstNonBlank(stringValue(field.get("displayName")), fieldKey, message("enterprise.pqa.consistency.gate.fieldRequired"));
            List<String> metricCodes = metricCodes(field.get("metricCodes"));
            String evidenceSection = firstNonBlank(stringValue(field.get("evidenceSection")), "sealedEvidence");
            String evidencePath = firstNonBlank(stringValue(field.get("evidencePath")), fieldKey);
            String source = "sealedEvidence." + evidenceSection + "." + evidencePath;
            for (String metricCode : metricCodes) {
                checks.add(new RuntimeEvidenceCheckResult(
                        metricCode,
                        "PROMPT_MANIFEST_FIELD_" + normalizeCheckKey(fieldKey),
                        message("enterprise.pqa.consistency.gate.reflectionCheck", displayName),
                        message("enterprise.pqa.consistency.gate.reflectionDesc", displayName),
                        promptProjectionActual(field),
                        false,
                        source,
                        "BLOCKING",
                        "PROMPT_EVIDENCE_PROJECTION_MISMATCH",
                        stringValue(field.get("producer")),
                        message("enterprise.pqa.consistency.gate.reflectionFailure", displayName),
                        message("enterprise.pqa.consistency.gate.remediationAction", firstNonBlank(stringValue(field.get("producer")), message("enterprise.pqa.consistency.gate.reverifyContextProducer")), displayName),
                        message("enterprise.pqa.consistency.gate.reverifyCriterion", displayName)).withGateCode(OfficialVerificationGateCode.PROMPT_EVIDENCE_MANIFEST));
            }
        }
        return checks;
    }

    private List<String> metricCodes(Object metricCodes) {
        Set<String> result = new LinkedHashSet<>();
        if (metricCodes instanceof List<?> rows) {
            for (Object row : rows) {
                String value = stringValue(row);
                if (StringUtils.hasText(value)) {
                    result.add(value.trim().toUpperCase(Locale.ROOT));
                }
            }
            if (result.isEmpty()) {
                result.add("CCR");
            }
            return List.copyOf(result);
        }
        String value = stringValue(metricCodes);
        if (StringUtils.hasText(value)) {
            for (String token : value.split(",")) {
                if (StringUtils.hasText(token)) {
                    result.add(token.trim().toUpperCase(Locale.ROOT));
                }
            }
        }
        if (result.isEmpty()) {
            result.add("CCR");
        }
        return List.copyOf(result);
    }

    private String promptProjectionActual(Map<?, ?> field) {
        String state = stringValue(field.get("projectionState"));
        String evidenceValue = stringValue(field.get("evidenceValue"));
        String promptValue = stringValue(field.get("promptValue"));
        if (!StringUtils.hasText(promptValue) && StringUtils.hasText(evidenceValue)) {
            return message("enterprise.pqa.consistency.gate.evidenceValueMismatch", evidenceValue);
        }
        return message("enterprise.pqa.consistency.gate.reflectionState", firstNonBlank(state, message("enterprise.pqa.consistency.gate.notEvaluated")));
    }

    private boolean booleanValue(Object value) {
        if (value instanceof Boolean bool) {
            return bool;
        }
        return value != null && "true".equalsIgnoreCase(String.valueOf(value).trim());
    }

    private String stringValue(Object value) {
        if (value == null) {
            return null;
        }
        String normalized = String.valueOf(value).trim();
        return normalized.isEmpty() ? null : normalized;
    }

    private String normalizeCheckKey(String value) {
        if (!StringUtils.hasText(value)) {
            return "FIELD";
        }
        String normalized = value.trim()
                .replaceAll("([a-z])([A-Z])", "$1_$2")
                .replaceAll("[^A-Za-z0-9]+", "_")
                .replaceAll("^_+|_+$", "")
                .toUpperCase(Locale.ROOT);
        return normalized.isBlank() ? "FIELD" : normalized;
    }

    private boolean officialRunPassed(OfficialVerificationRunView run) {
        if (run == null) {
            return false;
        }
        String normalized = run.state() == null ? "" : run.state().trim().toUpperCase(Locale.ROOT);
        return PASS_STATES.contains(normalized) || normalized.contains("THRESHOLD PASSED");
    }

    private boolean replayHashMatches(SealedEvidencePackage evidencePackage, DeterministicReplayResult replay) {
        return hasText(evidencePackage.getPromptHash())
                && replay != null
                && hasText(replay.originalPromptHash())
                && evidencePackage.getPromptHash().equals(replay.originalPromptHash());
    }

    private String replayHashLabel(SealedEvidencePackage evidencePackage, DeterministicReplayResult replay) {
        if (!hasText(evidencePackage.getPromptHash())) {
            return message("enterprise.pqa.consistency.gate.hashMissing");
        }
        if (replay == null || !hasText(replay.originalPromptHash())) {
            return message("enterprise.pqa.consistency.gate.replayHashMissing");
        }
        return evidencePackage.getPromptHash().equals(replay.originalPromptHash())
                ? message("enterprise.pqa.consistency.gate.hashMatch")
                : message("enterprise.pqa.consistency.gate.hashMismatch");
    }

    private String actionFor(String metricCode) {
        return switch (metricCode) {
            case "PFR" -> message("enterprise.pqa.consistency.gate.remediationHint.pfr");
            case "MTR" -> message("enterprise.pqa.consistency.gate.remediationHint.mtr");
            default -> message("enterprise.pqa.consistency.gate.remediationHint.default");
        };
    }

    private String metricName(String metricCode) {
        return switch (metricCode == null ? "" : metricCode.trim().toUpperCase(Locale.ROOT)) {
            case "PRE" -> message("enterprise.pqa.consistency.gate.dimension.pre");
            case "PFR" -> message("enterprise.pqa.consistency.gate.dimension.pfr");
            case "MTR" -> message("enterprise.pqa.consistency.gate.dimension.mtr");
            default -> message("enterprise.pqa.consistency.gate.dimension.default");
        };
    }

    private String gateLabel(String label) {
        String normalized = label == null ? "" : label.trim().toLowerCase(Locale.ROOT);
        if (normalized.contains("packageid")) return message("enterprise.pqa.consistency.gate.label.packageId");
        if (normalized.contains("sealed evidence is locked")) return message("enterprise.pqa.consistency.gate.label.sealed");
        if (normalized.contains("integrity")) return message("enterprise.pqa.consistency.gate.label.integrity");
        if (normalized.contains("request resource path")) return message("enterprise.pqa.consistency.gate.label.requestPath");
        if (normalized.contains("resource id")) return message("enterprise.pqa.consistency.gate.label.resourceId");
        if (normalized.contains("http method")) return message("enterprise.pqa.consistency.gate.label.method");
        if (normalized.contains("system prompt")) return message("enterprise.pqa.consistency.gate.label.systemPrompt");
        if (normalized.contains("user prompt")) return message("enterprise.pqa.consistency.gate.label.userPrompt");
        if (normalized.contains("llm prompt")) return message("enterprise.pqa.consistency.gate.label.llmPrompt");
        if (normalized.contains("prompt hash")) return message("enterprise.pqa.consistency.gate.label.promptHash");
        if (normalized.contains("scorecard")) return message("enterprise.pqa.consistency.gate.label.scorecard");
        if (normalized.contains("replay")) return message("enterprise.pqa.consistency.gate.label.replay");
        if (normalized.contains("12 prompt quality")) return message("enterprise.pqa.consistency.gate.label.twelveMetrics");
        if (normalized.contains("prompt quality metrics")) return message("enterprise.pqa.consistency.gate.label.metricChecks");
        return message("enterprise.pqa.consistency.gate.label.defaultGate");
    }

    private String operatorValue(String value) {
        if (!StringUtils.hasText(value)) {
            return message("enterprise.pqa.consistency.gate.notEvaluated");
        }
        return switch (value.trim().toLowerCase(Locale.ROOT)) {
            case "present", "captured", "pass", "all pass" -> message("enterprise.pqa.consistency.gate.state.present");
            case "missing" -> message("enterprise.pqa.consistency.gate.state.missing");
            case "fail" -> message("enterprise.pqa.consistency.gate.state.fail");
            default -> value.trim();
        };
    }
}
