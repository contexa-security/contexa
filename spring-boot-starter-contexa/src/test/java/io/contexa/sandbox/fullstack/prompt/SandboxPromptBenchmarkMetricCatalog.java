package io.contexa.sandbox.fullstack.prompt;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * CONTEXA sandbox official benchmark metric catalog.
 *
 * 목적:
 * - 보고서에 실리는 지표가 단순 문자열 나열이 아니라 공식 코드/카테고리/임계값을 가진 계약이 되도록 고정한다.
 * - 현재 컨텍스트/프롬프트 단계에서 계산 가능한 공식 지표와, 향후 LLM 책임 구간에서 열릴 공식 지표를 분리한다.
 */
public enum SandboxPromptBenchmarkMetricCatalog {

    EVENT_INTEGRITY_RATE("EIR", "Event Integrity Rate", "IMPLEMENTATION_ALIGNMENT", true, 95.0d, true, true),
    CONTEXT_COMPLETENESS_RATE("CCR", "Context Completeness Rate", "IMPLEMENTATION_ALIGNMENT", true, 95.0d, true, true),
    CONTEXT_CONSISTENCY_RATE("CCSR", "Context Consistency Rate", "IMPLEMENTATION_ALIGNMENT", true, 95.0d, true, true),
    PROMPT_FIDELITY_RATE("PFR", "Prompt Fidelity Rate", "IMPLEMENTATION_ALIGNMENT", true, 95.0d, true, true),
    METADATA_TRACEABILITY_RATE("MTR", "Metadata Traceability Rate", "IMPLEMENTATION_ALIGNMENT", true, 95.0d, true, true),
    CONTEXT_CONTAMINATION_RATE("CoR", "Context Contamination Rate", "IMPLEMENTATION_ALIGNMENT", true, 0.0d, false, true),
    RAG_AUTHORIZATION_PRECISION("RAP", "RAG Authorization Precision", "RAG_AND_BASELINE", true, 95.0d, true, true),
    ROUND_PROGRESSION_INTEGRITY("RPI", "Round Progression Integrity", "RAG_AND_BASELINE", true, 95.0d, true, true),
    BASELINE_MATURITY_ACCURACY("BMA", "Baseline Maturity Accuracy", "RAG_AND_BASELINE", true, 95.0d, true, true),
    USER_SPECIFIC_NOVELTY_SENSITIVITY("USNS", "User-Specific Novelty Sensitivity", "BEHAVIORAL_CONTEXT", true, 95.0d, true, true),
    BEHAVIORAL_SURPRISE_RESOLUTION("BSR", "Behavioral Surprise Resolution", "BEHAVIORAL_CONTEXT", true, 95.0d, true, true),
    CONTEXT_TO_DECISION_CALIBRATION("CDC", "Context-to-Decision Calibration", "LLM_DECISION", true, 95.0d, true, true),
    EVIDENCE_REASON_ALIGNMENT("ERA", "Evidence-Reason Alignment", "LLM_DECISION", true, 95.0d, true, true),
    SAFE_UNCERTAINTY_HANDLING_RATE("SUHR", "Safe-Uncertainty Handling Rate", "LLM_DECISION", true, 95.0d, true, true),

    MEMORY_TRACE_RECALL("MTRC", "Memory Trace Recall", "SUPPLEMENTARY", false, 95.0d, true, true),
    MEMORY_ARTIFACT_INTEGRITY("MAI", "Memory Artifact Integrity", "SUPPLEMENTARY", false, 95.0d, true, true),
    CONTEXT_NOISE_EXCLUSION_RATE("CNER", "Context Noise Exclusion Rate", "SUPPLEMENTARY", false, 95.0d, true, true),
    PROGRESSION_SCORE("PS", "Progression Score", "SUPPLEMENTARY", false, 95.0d, true, true);

    private static final Map<String, SandboxPromptBenchmarkMetricCatalog> BY_NAME = Arrays.stream(values())
            .collect(Collectors.toMap(
                    SandboxPromptBenchmarkMetricCatalog::metricName,
                    Function.identity(),
                    (left, right) -> left));

    private final String metricCode;
    private final String metricName;
    private final String category;
    private final boolean official;
    private final double successThreshold;
    private final boolean higherIsBetter;
    private final boolean implemented;

    SandboxPromptBenchmarkMetricCatalog(
            String metricCode,
            String metricName,
            String category,
            boolean official,
            double successThreshold,
            boolean higherIsBetter,
            boolean implemented) {
        this.metricCode = metricCode;
        this.metricName = metricName;
        this.category = category;
        this.official = official;
        this.successThreshold = successThreshold;
        this.higherIsBetter = higherIsBetter;
        this.implemented = implemented;
    }

    public String metricCode() {
        return metricCode;
    }

    public String metricName() {
        return metricName;
    }

    public String category() {
        return category;
    }

    public boolean official() {
        return official;
    }

    public double successThreshold() {
        return successThreshold;
    }

    public boolean higherIsBetter() {
        return higherIsBetter;
    }

    public boolean implemented() {
        return implemented;
    }

    public static Optional<SandboxPromptBenchmarkMetricCatalog> findByMetricName(String metricName) {
        if (metricName == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(BY_NAME.get(metricName));
    }

    public static List<SandboxPromptBenchmarkMetricCatalog> officialMetrics() {
        return Arrays.stream(values())
                .filter(SandboxPromptBenchmarkMetricCatalog::official)
                .toList();
    }

    public static List<SandboxPromptBenchmarkMetricCatalog> implementedOfficialMetrics() {
        return officialMetrics().stream()
                .filter(SandboxPromptBenchmarkMetricCatalog::implemented)
                .toList();
    }

    public static List<SandboxPromptBenchmarkMetricCatalog> pendingOfficialMetrics() {
        return officialMetrics().stream()
                .filter(metric -> !metric.implemented())
                .toList();
    }

    public Map<String, Object> toMap() {
        return Map.of(
                "metricCode", metricCode,
                "metricName", metricName,
                "category", category,
                "official", official,
                "successThreshold", successThreshold,
                "higherIsBetter", higherIsBetter,
                "implemented", implemented);
    }

    @Override
    public String toString() {
        return String.format(Locale.ROOT, "%s(%s)", metricCode, metricName);
    }
}
