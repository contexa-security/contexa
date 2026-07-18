package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.metric.OfficialVerificationMetricDefinition;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexacore.verification.runtime.sealed.OfficialSealedEvidenceVerificationRuntime;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationGateCode;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceCheckResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceGateResult;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public final class OfficialVerificationMetricContract {

    private final PromptQualityOfficialMetricCatalog metricCatalog;
    private final OfficialSealedEvidenceVerificationRuntime runtime;

    public OfficialVerificationMetricContract(
            PromptQualityOfficialMetricCatalog metricCatalog,
            OfficialSealedEvidenceVerificationRuntime runtime) {
        this.metricCatalog = Objects.requireNonNull(metricCatalog, "metricCatalog");
        this.runtime = Objects.requireNonNull(runtime, "runtime");
    }

    public RuntimeEvidenceGateResult withoutMetricExecutionChecks(RuntimeEvidenceGateResult result) {
        if (result == null) {
            throw new IllegalArgumentException("The preliminary certification policy result is required.");
        }
        List<RuntimeEvidenceCheckResult> checks = result.checks() == null
                ? List.of()
                : result.checks().stream()
                .filter(check -> check != null
                        && check.gateCode() != OfficialVerificationGateCode.REQUIRED_METRICS
                        && check.gateCode() != OfficialVerificationGateCode.METRIC_RESULTS)
                .toList();
        return new RuntimeEvidenceGateResult(
                checks.stream().allMatch(RuntimeEvidenceCheckResult::pass),
                checks,
                immutable(result.findings()),
                immutable(result.nextActions()));
    }

    public String metricSetVersion() {
        String material = metricCatalog.promptQualityMetrics().stream()
                .map(metric -> safe(metric.code()) + ":" + safe(metric.metricName()) + ":" + safe(metric.category())
                        + ":" + metric.benchmarkSuccessThreshold() + ":" + metric.official())
                .collect(Collectors.joining("|"));
        return "PQA12-" + sha256(material).substring(0, 16);
    }

    public String engineVersion() {
        Package runtimePackage = runtime.getClass().getPackage();
        String implementationVersion = runtimePackage == null ? null : runtimePackage.getImplementationVersion();
        return StringUtils.hasText(implementationVersion)
                ? implementationVersion.trim()
                : runtime.getClass().getName();
    }

    public List<String> expectedMetricCodes() {
        return metricCatalog.promptQualityMetrics().stream()
                .filter(metric -> !"LLM_DECISION".equalsIgnoreCase(metric.category()))
                .map(OfficialVerificationMetricDefinition::code)
                .filter(StringUtils::hasText)
                .map(code -> code.trim().toUpperCase(Locale.ROOT))
                .distinct()
                .toList();
    }

    public void assertComplete(List<? extends OfficialVerificationRunView> runs) {
        Set<String> expected = new LinkedHashSet<>(expectedMetricCodes());
        Set<String> actual = runs == null
                ? Set.of()
                : runs.stream()
                .filter(run -> run != null && StringUtils.hasText(run.endpointKey()))
                .map(run -> run.endpointKey().trim().toUpperCase(Locale.ROOT))
                .collect(Collectors.toCollection(LinkedHashSet::new));
        List<String> missing = expected.stream().filter(code -> !actual.contains(code)).toList();
        if (!missing.isEmpty()) {
            throw new IllegalStateException(
                    "Official metric runtime did not produce all configured prompt quality metrics. missingMetricCodes="
                            + String.join(",", missing));
        }
    }

    private String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is not available.", exception);
        }
    }

    private String safe(String value) {
        return StringUtils.hasText(value) ? value.trim() : "";
    }

    private <T> List<T> immutable(List<T> values) {
        return values == null ? List.of() : List.copyOf(values);
    }
}