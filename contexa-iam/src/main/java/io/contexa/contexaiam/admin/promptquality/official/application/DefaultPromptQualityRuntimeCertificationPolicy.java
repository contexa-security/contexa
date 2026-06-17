package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.adjudication.ScorecardResult;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.replay.DeterministicReplayResult;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceCheckResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceGateResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeGovernanceDescriptorVerificationResult;
import io.contexa.contexaiam.admin.promptquality.official.application.support.AbstractPromptQualityRuntimeEvidenceSupport;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class DefaultPromptQualityRuntimeCertificationPolicy
        extends AbstractPromptQualityRuntimeEvidenceSupport
        implements PromptQualityRuntimeCertificationPolicy {

    private static final int PROMPT_QUALITY_METRIC_COUNT = 12;
    private static final double SCORECARD_PASS_RATE = 95.0d;
    private static final Set<String> PASS_STATES = Set.of("SUCCESS", "PASS", "PASSED", "VERIFIED", "COMPLETED");

    private final PromptRuntimeGovernanceDescriptorVerifier governanceDescriptorVerifier;

    public DefaultPromptQualityRuntimeCertificationPolicy(ObjectMapper objectMapper) {
        this(objectMapper, null);
    }

    public DefaultPromptQualityRuntimeCertificationPolicy(
            ObjectMapper objectMapper,
            PromptRuntimeGovernanceDescriptorVerifier governanceDescriptorVerifier) {
        super(objectMapper);
        this.governanceDescriptorVerifier = governanceDescriptorVerifier;
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
        Map<String, Object> promptMetadata = parseJson(evidencePackage.getPromptExecutionMetadataJson());
        String requestPath = requestPath(evidencePackage, requestFacts);
        String resourceId = firstNonBlank(
                text(requestFacts, "resourceId"),
                text(requestFacts, "endpointKey"),
                text(promptMetadata, "resourceId"),
                text(promptMetadata, "endpointKey"));
        String method = firstNonBlank(text(requestFacts, "httpMethod"), text(requestFacts, "method"));

        add(checks, "PRE", "sealed evidence packageId exists", "packageId",
                evidencePackage.getPackageId(), StringUtils.hasText(evidencePackage.getPackageId()), "sealedEvidence");
        add(checks, "PRE", "sealed evidence is locked", "sealed=true",
                String.valueOf(evidencePackage.isSealed()), evidencePackage.isSealed(), "sealedEvidence");
        add(checks, "PRE", "sealed evidence integrity is valid", "integrity pass",
                integrityValid ? "pass" : "fail", integrityValid, "sealedEvidence");
        add(checks, "PRE", "request resource path exists", "request URL exists",
                firstNonBlank(requestPath, "missing"), StringUtils.hasText(requestPath), "resourceScope");
        add(checks, "PRE", "resource id exists", "resource id exists",
                firstNonBlank(resourceId, "missing"), StringUtils.hasText(resourceId), "resourceScope");
        add(checks, "PRE", "HTTP method exists", "GET/POST or request method exists",
                firstNonBlank(method, "missing"), StringUtils.hasText(method), "resourceScope");
        add(checks, "PFR", "raw system prompt captured", "captured",
                hasText(evidencePackage.getRawSystemPrompt()) ? "captured" : "missing",
                hasText(evidencePackage.getRawSystemPrompt()), "promptCapture");
        add(checks, "PFR", "raw user prompt captured", "captured",
                hasText(evidencePackage.getRawUserPrompt()) ? "captured" : "missing",
                hasText(evidencePackage.getRawUserPrompt()), "promptCapture");
        add(checks, "PFR", "LLM prompt captured", "captured",
                hasText(evidencePackage.getSystemPromptText()) && hasText(evidencePackage.getUserPromptText()) ? "captured" : "missing",
                hasText(evidencePackage.getSystemPromptText()) && hasText(evidencePackage.getUserPromptText()), "promptCapture");
        add(checks, "PFR", "prompt hash exists", "promptHash exists",
                firstNonBlank(evidencePackage.getPromptHash(), "missing"),
                hasText(evidencePackage.getPromptHash()), "promptCapture");
        add(checks, "PFR", "prompt hash matches deterministic replay", "raw hash matches replay hash",
                replayHashLabel(evidencePackage, replay),
                replayHashMatches(evidencePackage, replay), "deterministicReplay");

        RuntimeGovernanceDescriptorVerificationResult governanceResult = governanceDescriptorVerifier == null
                ? RuntimeGovernanceDescriptorVerificationResult.empty()
                : governanceDescriptorVerifier.verify(evidencePackage, promptMetadata);
        checks.addAll(governanceResult.checks());
        checks.addAll(promptEvidenceManifestChecks(evidencePackage));

        boolean scorecardPassed = scorecard != null
                && scorecard.checksRun() > 0
                && scorecard.passRatePercent() >= SCORECARD_PASS_RATE;
        add(checks, "MTR", "prompt structure scorecard passed", SCORECARD_PASS_RATE + "% or higher",
                scorecard == null ? "not executed" : scorecard.passRatePercent() + "%",
                scorecardPassed, "promptScorecard");

        boolean replayPassed = replay != null
                && replay.checksRun() > 0
                && replay.checksPassed() >= replay.checksRun();
        add(checks, "MTR", "deterministic replay matches sealed evidence", "all replay checks pass",
                replay == null ? "not executed" : replay.checksPassed() + "/" + replay.checksRun(),
                replayPassed, "deterministicReplay");

        boolean allMetricsPresent = metrics != null && metrics.size() >= PROMPT_QUALITY_METRIC_COUNT;
        long failedOfficialMetrics = metrics == null
                ? PROMPT_QUALITY_METRIC_COUNT
                : metrics.stream().filter(run -> !officialRunPassed(run)).count();
        add(checks, "PRE", "12 prompt quality metric results exist", String.valueOf(PROMPT_QUALITY_METRIC_COUNT),
                metrics == null ? "0" : String.valueOf(metrics.size()), allMetricsPresent, "coreOfficialRuntime");
        add(checks, "PRE", "prompt quality metrics passed", "all prompt quality metric runs pass",
                failedOfficialMetrics == 0 ? "all pass" : failedOfficialMetrics + " failed",
                allMetricsPresent && failedOfficialMetrics == 0, "coreOfficialRuntime");

        checks.stream().filter(check -> !check.pass()).forEach(check -> {
            findings.add("보증 전 관문 문제: " + metricName(check.metricCode())
                    + " 기준에서 " + gateLabel(check.label())
                    + " 항목이 충족되지 않았습니다. 확인 결과는 "
                    + operatorValue(check.actualValue()) + "입니다.");
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
            String metricCode,
            String label,
            String expected,
            String actual,
            boolean pass,
            String source) {
        checks.add(new RuntimeEvidenceCheckResult(metricCode, label, expected, actual, pass, source));
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
            String displayName = firstNonBlank(stringValue(field.get("displayName")), fieldKey, "필수 프롬프트 항목");
            List<String> metricCodes = metricCodes(field.get("metricCodes"));
            String evidenceSection = firstNonBlank(stringValue(field.get("evidenceSection")), "sealedEvidence");
            String evidencePath = firstNonBlank(stringValue(field.get("evidencePath")), fieldKey);
            String source = "sealedEvidence." + evidenceSection + "." + evidencePath;
            for (String metricCode : metricCodes) {
                checks.add(new RuntimeEvidenceCheckResult(
                        metricCode,
                        "PROMPT_MANIFEST_FIELD_" + normalizeCheckKey(fieldKey),
                        displayName + " 프롬프트 반영 확인",
                        displayName + " 값이 봉인 증거와 최종 사용자 프롬프트에 같은 의미로 존재해야 합니다.",
                        promptProjectionActual(field),
                        false,
                        source,
                        "BLOCKING",
                        "PROMPT_EVIDENCE_PROJECTION_MISMATCH",
                        stringValue(field.get("producer")),
                        "문제: " + displayName + " 항목이 최종 사용자 프롬프트에 반영되지 않았습니다. 원인: 봉인 증거에는 값이 있으나 LLM이 보는 프롬프트에는 같은 값이 없습니다.",
                        "조치: " + firstNonBlank(stringValue(field.get("producer")), "해당 컨텍스트 생산자")
                                + "에서 " + displayName + " 값을 생성, 저장, 프롬프트 조립까지 같은 이름과 의미로 전달하십시오.",
                        "재검증 기준: 같은 요청 흐름으로 새 증거를 만들고 공식 검사를 다시 실행했을 때 "
                                + displayName + " 항목이 기준 충족으로 저장되어야 합니다."));
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
            return "봉인 증거 값은 '" + evidenceValue + "'이지만 최종 프롬프트에서는 확인되지 않았습니다.";
        }
        return "프롬프트 반영 상태: " + firstNonBlank(state, "확인 불가");
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
            return "프롬프트 해시 없음";
        }
        if (replay == null || !hasText(replay.originalPromptHash())) {
            return "재현 실행 해시 없음";
        }
        return evidencePackage.getPromptHash().equals(replay.originalPromptHash()) ? "일치" : "불일치";
    }

    private String actionFor(String metricCode) {
        return switch (metricCode) {
            case "PFR" -> "프롬프트 캡처 설정을 확인한 뒤 보호 리소스를 다시 요청하여 새 봉인 증거를 생성하십시오.";
            case "MTR" -> "재현 실행 또는 추적성 불일치를 수정한 뒤 같은 보호 리소스를 다시 요청하고 새 증거 번호로 재검증하십시오.";
            default -> "보호 리소스를 다시 요청한 뒤 코어 공식검사에서 새 봉인 증거를 재검증하십시오.";
        };
    }

    private String metricName(String metricCode) {
        return switch (metricCode == null ? "" : metricCode.trim().toUpperCase(Locale.ROOT)) {
            case "PRE" -> "보호 리소스 적격성";
            case "PFR" -> "프롬프트 충실성";
            case "MTR" -> "검사 추적성";
            default -> "공식 검사";
        };
    }

    private String gateLabel(String label) {
        String normalized = label == null ? "" : label.trim().toLowerCase(Locale.ROOT);
        if (normalized.contains("packageid")) return "봉인 증거 번호";
        if (normalized.contains("sealed evidence is locked")) return "봉인 상태";
        if (normalized.contains("integrity")) return "증거 무결성";
        if (normalized.contains("request resource path")) return "요청 리소스 경로";
        if (normalized.contains("resource id")) return "리소스 식별자";
        if (normalized.contains("http method")) return "HTTP 메서드";
        if (normalized.contains("system prompt")) return "시스템 프롬프트 캡처";
        if (normalized.contains("user prompt")) return "사용자 프롬프트 캡처";
        if (normalized.contains("llm prompt")) return "최종 LLM 프롬프트 캡처";
        if (normalized.contains("prompt hash")) return "프롬프트 해시";
        if (normalized.contains("scorecard")) return "프롬프트 구조 점검";
        if (normalized.contains("replay")) return "결정적 재현 실행";
        if (normalized.contains("12 prompt quality")) return "12개 프롬프트 품질 지표";
        if (normalized.contains("prompt quality metrics")) return "프롬프트 품질 지표 통과";
        return "공식 검사 관문";
    }

    private String operatorValue(String value) {
        if (!StringUtils.hasText(value)) {
            return "확인 불가";
        }
        return switch (value.trim().toLowerCase(Locale.ROOT)) {
            case "present", "captured", "pass", "all pass" -> "기준 충족";
            case "missing" -> "값 없음";
            case "fail" -> "실패";
            default -> value.trim();
        };
    }
}
