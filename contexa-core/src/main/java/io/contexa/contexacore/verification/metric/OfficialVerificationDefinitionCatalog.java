package io.contexa.contexacore.verification.metric;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricContractCatalog;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;

/**
 * Versioned OSS persistence view derived from the canonical final-prompt
 * metric contract.  This class is not an independent metric/check catalog.
 */
public final class OfficialVerificationDefinitionCatalog {

    private static final FinalPromptMetricContractCatalog CANONICAL_CATALOG =
            FinalPromptMetricContractCatalog.load(new ObjectMapper());

    public static final String VERSION = CANONICAL_CATALOG.contractVersion();

    private static final List<MetricSeed> METRICS = CANONICAL_CATALOG.metrics().stream()
            .map(metric -> new MetricSeed(
                    metric.metricCode(),
                    metric.metricName(),
                    metric.metricGroup(),
                    metric.purpose(),
                    metric.qualityQuestion(),
                    metric.metricRole()))
            .toList();

    private static final List<CheckSeed> CHECKS = CANONICAL_CATALOG.metrics().stream()
            .flatMap(metric -> metric.checks().stream())
            .map(check -> new CheckSeed(
                    check.metricCode(),
                    check.checkName(),
                    check.qualityQuestion(),
                    check.expectedMessage(),
                    check.source(),
                    check.severity(),
                    check.remediationOwner()))
            .toList();

    private OfficialVerificationDefinitionCatalog() {
    }

    public static List<MetricSeed> metrics() {
        return METRICS;
    }

    public static List<CheckSeed> checks() {
        return CHECKS;
    }

    public static String checksum() {
        StringBuilder canonical = new StringBuilder(VERSION).append('\n');
        METRICS.forEach(metric -> canonical.append("M|").append(metric.canonical()).append('\n'));
        CHECKS.forEach(check -> canonical.append("C|").append(check.canonical()).append('\n'));
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(canonical.toString().getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required", exception);
        }
    }

    public record MetricSeed(
            String code,
            String name,
            String group,
            String purpose,
            String evidenceContract,
            String blockingScope) {

        private String canonical() {
            return String.join("|", code, name, group, purpose, evidenceContract, blockingScope);
        }
    }

    public record CheckSeed(
            String metricCode,
            String checkCode,
            String label,
            String expectedValue,
            String evidenceSource,
            String severity,
            String remediationOwner) {

        private String canonical() {
            return String.join("|", metricCode, checkCode, label, expectedValue,
                    evidenceSource, severity, remediationOwner);
        }
    }
}
