package io.contexa.sandbox.fullstack.prompt;

import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * scorecard/metric 실패를 책임 영역별 결함으로 분류한다.
 *
 * 분류 원칙:
 * - 필드 누락, 값 불일치, 섹션 누락, prompt trace 누락은 구현 결함
 * - foreign document, contamination, artifact mismatch는 데이터 품질 결함
 * - 얇은 baseline, ambiguity, provisional evidence는 LLM 해석 영역
 * - trace/telemetry 부재는 관측 결함
 */
public final class SandboxPromptDefectClassifier {

    private SandboxPromptDefectClassifier() {
    }

    public static List<SandboxPromptDefectFinding> classifyScorecardFailures(
            String benchmarkRunId,
            String username,
            SandboxPromptQualityScorecard scorecard) {
        List<SandboxPromptDefectFinding> findings = new ArrayList<>();
        if (scorecard == null) {
            return List.of();
        }
        for (SandboxPromptQualityScorecard.CheckResult failedCheck : scorecard.failedChecks()) {
            findings.add(new SandboxPromptDefectFinding(
                    benchmarkRunId,
                    username,
                    scorecard.label(),
                    normalizeCode(failedCheck.label()),
                    classify(failedCheck.label(), failedCheck.detail()),
                    failedCheck.label(),
                    failedCheck.detail()));
        }
        return List.copyOf(findings);
    }

    public static SandboxPromptDefectFinding classifyArtifactMismatch(
            String benchmarkRunId,
            String username,
            String source,
            String code,
            String summary,
            String detail) {
        return new SandboxPromptDefectFinding(
                benchmarkRunId,
                username,
                source,
                normalizeCode(code),
                SandboxPromptDefectCategory.DATA_QUALITY_DEFECT,
                summary,
                detail);
    }

    private static SandboxPromptDefectCategory classify(String label, String detail) {
        String corpus = (safe(label) + " " + safe(detail)).toLowerCase(Locale.ROOT);

        if (containsAny(corpus,
                "provisional",
                "thin",
                "fallback",
                "ambiguous",
                "baseline",
                "novelty",
                "scope limitation")) {
            return SandboxPromptDefectCategory.LLM_EVALUABLE_GAP;
        }

        if (containsAny(corpus,
                "relateddocuments",
                "contamination",
                "retrieval",
                "artifact",
                "user scope",
                "foreign",
                "denied",
                "riskscore",
                "confidence",
                "retrievalpurpose")) {
            return SandboxPromptDefectCategory.DATA_QUALITY_DEFECT;
        }

        if (containsAny(corpus,
                "promptexecutionmetadata",
                "promptversion",
                "trace",
                "requestid",
                "systemprompt",
                "userprompt",
                "metadata hashes",
                "missing bridge section",
                "missing",
                "mismatch",
                "unknown",
                "effectivepermissions",
                "effectiveroles",
                "authorizationeffect",
                "clientip",
                "requestpath")) {
            return SandboxPromptDefectCategory.IMPLEMENTATION_DEFECT;
        }

        return SandboxPromptDefectCategory.OBSERVABILITY_DEFECT;
    }

    private static boolean containsAny(String text, String... candidates) {
        if (!StringUtils.hasText(text) || candidates == null) {
            return false;
        }
        for (String candidate : candidates) {
            if (StringUtils.hasText(candidate) && text.contains(candidate)) {
                return true;
            }
        }
        return false;
    }

    private static String normalizeCode(String input) {
        if (!StringUtils.hasText(input)) {
            return "UNKNOWN_DEFECT";
        }
        return input.toUpperCase(Locale.ROOT)
                .replaceAll("[^A-Z0-9]+", "_")
                .replaceAll("_+", "_")
                .replaceAll("^_|_$", "");
    }

    private static String safe(String value) {
        return value == null ? "" : value;
    }
}
