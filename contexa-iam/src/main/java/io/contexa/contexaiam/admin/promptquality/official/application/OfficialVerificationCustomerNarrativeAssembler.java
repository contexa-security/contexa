package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.metric.OfficialVerificationMetricDefinition;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityCustomerSentencePolicy;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialActualPromptProblem;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceMetricResult;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

public final class OfficialVerificationCustomerNarrativeAssembler {

    private final PromptQualityOfficialMetricCatalog metricCatalog;
    private final PromptQualityMessageResolver messageResolver;

    public OfficialVerificationCustomerNarrativeAssembler(
            PromptQualityOfficialMetricCatalog metricCatalog,
            PromptQualityMessageResolver messageResolver) {
        this.metricCatalog = Objects.requireNonNull(metricCatalog, "metricCatalog");
        this.messageResolver = Objects.requireNonNull(messageResolver, "messageResolver");
    }

    public List<String> customerSentences(List<String> values, boolean blockingFinding) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        return values.stream()
                .filter(StringUtils::hasText)
                .map(value -> customerSentence(value, blockingFinding))
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
    }

    public List<String> merge(List<String> left, List<String> right) {
        List<String> merged = new ArrayList<>();
        if (left != null) {
            merged.addAll(left);
        }
        if (right != null) {
            merged.addAll(right);
        }
        return merged.stream()
                .filter(StringUtils::hasText)
                .map(String::trim)
                .distinct()
                .toList();
    }

    public List<String> problemFindings(List<OfficialActualPromptProblem> problems) {
        if (problems == null || problems.isEmpty()) {
            return List.of();
        }
        return customerSentences(problems.stream()
                .filter(this::blocking)
                .map(problem -> {
                    String title = firstNonBlank(
                            problem.promptLabel(),
                            message("enterprise.pqa.diagnostic.promptProblemFound"));
                    String reason = firstNonBlank(
                            problem.whyItMatters(), problem.actualState(), problem.problemType());
                    return StringUtils.hasText(reason) ? title + ". " + reason : title;
                })
                .toList(), true);
    }

    public List<String> problemNextActions(List<OfficialActualPromptProblem> problems) {
        if (problems == null || problems.isEmpty()) {
            return List.of();
        }
        return customerSentences(problems.stream()
                .filter(this::blocking)
                .map(problem -> firstNonBlank(problem.fixAction(), problem.reverifyCriterionDetail()))
                .filter(StringUtils::hasText)
                .toList(), false);
    }

    public int passedMetricCount(List<RuntimeEvidenceMetricResult> metrics) {
        return metrics == null ? 0 : (int) metrics.stream()
                .filter(OfficialVerificationMetricClassifier::metricPassed)
                .count();
    }

    public int failedMetricCount(List<RuntimeEvidenceMetricResult> metrics) {
        return metrics == null ? 0 : (int) metrics.stream()
                .filter(metric -> metric != null
                        && !OfficialVerificationMetricClassifier.metricPassed(metric)
                        && !OfficialVerificationMetricClassifier.metricNotApplicable(metric))
                .count();
    }

    private boolean blocking(OfficialActualPromptProblem problem) {
        return problem != null && "BLOCKING".equalsIgnoreCase(firstNonBlank(problem.severity(), ""));
    }

    private String customerSentence(String value, boolean blockingFinding) {
        String metricName = customerMetricName(value == null ? "" : value.trim());
        if (!PromptQualityCustomerSentencePolicy.isCustomerSentence(metricName)) {
            metricName = message("enterprise.pqa.runtimeVerification.customerSentence.metricFallback");
        }
        String sentence = message(blockingFinding
                ? "enterprise.pqa.runtimeVerification.customerSentence.blockingTpl"
                : "enterprise.pqa.runtimeVerification.customerSentence.followUpTpl",
                metricName);
        return PromptQualityCustomerSentencePolicy.requireCustomerSentence(
                blockingFinding ? "runtime.blockingFinding" : "runtime.nextAction",
                sentence);
    }

    private String customerMetricName(String value) {
        if (StringUtils.hasText(value)) {
            for (OfficialVerificationMetricDefinition metric : metricCatalog.promptQualityMetrics()) {
                if (containsMetricCode(value, metric.code())) {
                    String code = normalized(metric.code());
                    return StringUtils.hasText(code)
                            ? message("enterprise.pqa.runtimeVerification.customerSentence.metricWithCode", code)
                            : message("enterprise.pqa.runtimeVerification.customerSentence.genericMetric");
                }
            }
            String normalizedValue = value.toLowerCase(Locale.ROOT);
            if (normalizedValue.contains("prompt")) {
                return message("enterprise.pqa.runtimeVerification.customerSentence.promptAlignment");
            }
            if (value.contains("@Protectable") || normalizedValue.contains("protectable")) {
                return message("enterprise.pqa.runtimeVerification.customerSentence.protectedResourceEligibility");
            }
        }
        return message("enterprise.pqa.runtimeVerification.customerSentence.metricFallback");
    }

    private boolean containsMetricCode(String value, String metricCode) {
        return StringUtils.hasText(value)
                && StringUtils.hasText(metricCode)
                && Pattern.compile("\\b" + Pattern.quote(metricCode.trim()) + "\\b", Pattern.CASE_INSENSITIVE)
                .matcher(value)
                .find();
    }

    private String firstNonBlank(String... values) {
        if (values != null) {
            for (String value : values) {
                if (StringUtils.hasText(value)) {
                    return value.trim();
                }
            }
        }
        return "";
    }

    private String normalized(String value) {
        return StringUtils.hasText(value) ? value.trim().toUpperCase(Locale.ROOT) : "";
    }

    private String message(String key, Object... args) {
        String resolved = messageResolver.resolve(key, args);
        if (!StringUtils.hasText(resolved) || key.equals(resolved)) {
            throw new IllegalStateException("Missing prompt-quality message key: " + key);
        }
        return resolved;
    }
}