package io.contexa.contexacore.verification.runtime.prompt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.metric.OfficialMetricEvaluationResult;
import io.contexa.contexacore.verification.runtime.OfficialVerificationMessageResolver;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

public class FinalPromptMetricEvaluationSuite {

    private final FinalPromptParser parser;
    private final ObjectMapper objectMapper;
    private final FinalPromptPreflightService preflightService;
    private final FinalPromptMetricContractCatalog contractCatalog;
    private final Map<String, FinalPromptMetricEvaluator> evaluators;
    private final OfficialVerificationMessageResolver messageResolver;

    public FinalPromptMetricEvaluationSuite(ObjectMapper objectMapper) {
        this(objectMapper, OfficialVerificationMessageResolver.classpath(Locale.KOREAN));
    }

    public FinalPromptMetricEvaluationSuite(
            ObjectMapper objectMapper,
            OfficialVerificationMessageResolver messageResolver) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
        this.messageResolver = Objects.requireNonNull(messageResolver, "messageResolver");
        this.preflightService = new FinalPromptPreflightService(this.objectMapper, this.messageResolver);
        this.contractCatalog = FinalPromptMetricContractCatalog.load(this.objectMapper);
        this.parser = new FinalPromptParser(contractCatalog);
        this.evaluators = buildEvaluators(contractCatalog);
    }

    public Map<String, OfficialMetricEvaluationResult> evaluatePromptQuality(
            SealedEvidencePackage evidencePackage) {
        FinalPromptPreflightResult preflight = preflightService.verify(evidencePackage);
        if (!preflight.ready()) {
            preflightService.assertReady(evidencePackage);
        }
        FinalPromptEvaluationInput input = FinalPromptEvaluationInput.from(evidencePackage, parser, preflight, objectMapper);
        FinalPromptMetricEvaluationContext context = new FinalPromptMetricEvaluationContext(input);
        Map<String, OfficialMetricEvaluationResult> results = new LinkedHashMap<>();
        for (String metricCode : contractCatalog.metricCodesInOrder()) {
            FinalPromptMetricEvaluator evaluator = evaluators.get(metricCode);
            if (evaluator == null) {
                throw new IllegalStateException("Final prompt metric evaluator is missing: " + metricCode);
            }
            FinalPromptMetricResult result;
            try {
                result = evaluator.evaluate(context);
            }
            catch (RuntimeException exception) {
                result = engineContractErrorResult(metricCode, exception);
            }
            if (result == null) {
                result = engineContractErrorResult(
                        metricCode,
                        new IllegalStateException("Final prompt metric evaluator returned null."));
            }
            results.put(metricCode, result.toOfficialMetricResult());
        }
        return Map.copyOf(results);
    }

    public FinalPromptPreflightResult verifyPreflight(SealedEvidencePackage evidencePackage) {
        return preflightService.verify(evidencePackage);
    }

    private Map<String, FinalPromptMetricEvaluator> buildEvaluators(FinalPromptMetricContractCatalog catalog) {
        Map<String, FinalPromptMetricEvaluator> result = new LinkedHashMap<>();
        FinalPromptMetricRuleEngine ruleEngine = new FinalPromptMetricRuleEngine();
        for (String metricCode : catalog.metricCodesInOrder()) {
            FinalPromptMetricEvaluator evaluator =
                    new ContractBackedFinalPromptMetricEvaluator(
                            catalog.metric(metricCode), ruleEngine, catalog, messageResolver);
            result.put(evaluator.metricCode(), evaluator);
        }
        return Map.copyOf(result);
    }

    private static FinalPromptMetricResult engineContractErrorResult(String metricCode, RuntimeException exception) {
        String normalizedMetricCode = metricCode == null || metricCode.isBlank() ? "UNKNOWN" : metricCode.trim();
        String cause = exception == null
                ? "unknown runtime error"
                : exception.getClass().getSimpleName() + ": " + nullSafeMessage(exception);
        String detectedSignalsJson = "[{\"signalKey\":\"Metric engine contract error\","
                + "\"evidenceValue\":\"The metric evaluator failed before producing a trustworthy result.\","
                + "\"runtimeFacts\":\"Cause: " + jsonEscape(cause) + "\","
                + "\"contextItems\":\"metricCode, engineContract\"}]";
        FinalPromptMetricCheck check = new FinalPromptMetricCheck(
                normalizedMetricCode,
                normalizedMetricCode + "_ENGINE_CONTRACT_ERROR",
                "Metric engine contract error",
                "The official PQA engine must evaluate every registered metric from the final prompt contract.",
                "The metric evaluator failed before producing a trustworthy result. Cause: " + cause,
                false,
                "internalGate.metricEngine." + normalizedMetricCode,
                "BLOCKING",
                "ENGINE_CONTRACT_ERROR",
                "PQA metric engine",
                "This is not a final prompt quality issue. It is an evaluator or contract execution error.",
                "Fix the metric evaluator or final-prompt-metric-contracts.json, then rerun official PQA for the same packageId.",
                "Rerunning official PQA with the same final prompt must produce a normal metric result without ENGINE_CONTRACT_ERROR.",
                "internalGate.metricEngine." + normalizedMetricCode,
                false,
                "INTERNAL_EXECUTION_GATE",
                "",
                "READY",
                "ENGINE_CONTRACT_ERROR",
                detectedSignalsJson,
                "[{\"metricCode\":\"" + normalizedMetricCode + "\",\"purposeResult\":\"ENGINE_CONTRACT_ERROR\"}]",
                "Engine contract must execute the metric purpose contract.",
                "A metric engine error means the official PQA result cannot be trusted until the evaluator runs normally.");
        return new FinalPromptMetricResult(
                normalizedMetricCode,
                0.0d,
                0,
                1,
                "threshold_failed",
                List.of(check));
    }

    private static String jsonEscape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder escaped = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '"' -> escaped.append("\\\"");
                case '\\' -> escaped.append("\\\\");
                case '\b' -> escaped.append("\\b");
                case '\f' -> escaped.append("\\f");
                case '\n' -> escaped.append("\\n");
                case '\r' -> escaped.append("\\r");
                case '\t' -> escaped.append("\\t");
                default -> {
                    if (ch < 0x20) {
                        escaped.append(String.format("\\u%04x", (int) ch));
                    } else {
                        escaped.append(ch);
                    }
                }
            }
        }
        return escaped.toString();
    }

    private static String nullSafeMessage(Throwable exception) {
        if (exception == null || exception.getMessage() == null || exception.getMessage().isBlank()) {
            return "no message";
        }
        return exception.getMessage().trim();
    }
}
