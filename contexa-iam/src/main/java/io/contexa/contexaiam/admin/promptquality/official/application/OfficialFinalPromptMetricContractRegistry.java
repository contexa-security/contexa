package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricCheckContract;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricContract;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricContractCatalog;
import io.contexa.contexaiam.admin.promptquality.official.common.OfficialMetricPurposeContractWriter;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceCheckResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceMetricResult;
import org.springframework.util.StringUtils;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

final class OfficialFinalPromptMetricContractRegistry {

    private final OfficialMetricPurposeContractWriter writer;
    private final OfficialVerificationSnapshotQueryService queryService;
    private final FinalPromptMetricContractCatalog catalog;

    OfficialFinalPromptMetricContractRegistry(
            ObjectMapper objectMapper,
            OfficialMetricPurposeContractWriter writer,
            OfficialVerificationSnapshotQueryService queryService) {
        this.writer = writer;
        this.queryService = queryService;
        this.catalog = FinalPromptMetricContractCatalog.load(objectMapper);
    }

    FinalPromptMetricContractCatalog catalog() {
        return catalog;
    }

    FinalPromptMetricContract metric(String metricCode) {
        return catalog.metric(metricCode);
    }

    FinalPromptMetricContract metricOrNull(String metricCode) {
        try {
            return metric(metricCode);
        }
        catch (IllegalStateException ignored) {
            return null;
        }
    }

    FinalPromptMetricCheckContract check(String metricCode, RuntimeEvidenceCheckResult check) {
        if (check == null || !StringUtils.hasText(check.checkCode())) {
            throw new IllegalStateException(
                    "Metric check code is required for contract lookup. metricCode=" + normalize(metricCode));
        }
        return catalog.check(metricCode, check.checkCode());
    }

    FinalPromptMetricCheckContract checkOrNull(String metricCode, RuntimeEvidenceCheckResult check) {
        try {
            return check(metricCode, check);
        }
        catch (IllegalStateException ignored) {
            return null;
        }
    }

    String canonicalCheckCode(String metricCode, RuntimeEvidenceCheckResult check) {
        if (check != null && "LLM_DECISION_QUALITY".equalsIgnoreCase(check.readinessScope())) {
            return normalize(check.checkCode());
        }
        return check == null ? "" : canonicalCheckCode(metricCode, check.checkCode());
    }

    String canonicalCheckCode(String metricCode, String checkCode) {
        String normalizedMetric = normalize(metricCode);
        String normalizedCheck = normalize(checkCode);
        if (!StringUtils.hasText(normalizedCheck)) {
            return "";
        }
        if (StringUtils.hasText(normalizedMetric)) {
            try {
                return catalog.check(normalizedMetric, normalizedCheck).checkName();
            }
            catch (IllegalStateException ignored) {
                String prefix = normalizedMetric + "_";
                if (normalizedCheck.startsWith(prefix) && normalizedCheck.length() > prefix.length()) {
                    return normalizedCheck.substring(prefix.length());
                }
            }
        }
        return normalizedCheck;
    }

    boolean customerDisplayEligible(FinalPromptMetricCheckContract checkContract) {
        return checkContract != null && checkContract.customerVisible();
    }

    List<Map<String, String>> evidenceBindings(FinalPromptMetricCheckContract checkContract) {
        return checkContract == null || checkContract.evidenceBindings() == null
                ? List.of() : checkContract.evidenceBindings();
    }

    void upsertRuntime(List<RuntimeEvidenceMetricResult> metrics) {
        writer.upsertRuntimeMetricContractCatalog(metrics);
    }

    void upsertFull() {
        writer.upsertFullMetricContractCatalog();
    }

    void assertFullPersisted() {
        writer.assertFullMetricContractCatalogPersisted();
    }
    void assertCustomerDisplayComplete(String aggregateRunId) {
        queryService.assertCustomerDisplayPayloadComplete(aggregateRunId);
    }

    void assertCustomerDisplayRole(
            String purposeVersion,
            String metricCode,
            String checkCode,
            String displayRole) {
        queryService.assertCustomerDisplayContractRole(
                purposeVersion, metricCode, checkCode, displayRole);
    }
    void assertDefinitionsRegistered(List<RuntimeEvidenceMetricResult> metrics) {
        DefinitionKeys keys = definitionKeys(metrics);
        writer.upsertFullMetricContractCatalog();
        writer.upsertRuntimeMetricContractCatalog(metrics);
        writer.assertFullMetricContractCatalogPersisted();
        assertRegistered("metric", keys.metrics(), queryService.registeredMetricCodes());
        assertRegistered("check", keys.checks(), queryService.registeredMetricCheckCodes());
    }

    private DefinitionKeys definitionKeys(List<RuntimeEvidenceMetricResult> metrics) {
        Set<String> metricCodes = new LinkedHashSet<>();
        Set<String> checkCodes = new LinkedHashSet<>();
        for (RuntimeEvidenceMetricResult metric : safeList(metrics)) {
            if (metric == null || !StringUtils.hasText(metric.metricCode())) {
                continue;
            }
            String metricCode = normalize(metric.metricCode());
            metricCodes.add(metricCode);
            for (RuntimeEvidenceCheckResult check : safeList(metric.checks())) {
                if (check != null && StringUtils.hasText(check.purposeVersion())) {
                    String checkCode = canonicalCheckCode(metricCode, check);
                    if (StringUtils.hasText(checkCode)) {
                        checkCodes.add(metricCode + "|" + normalize(checkCode));
                    }
                }
            }
        }
        return new DefinitionKeys(Set.copyOf(metricCodes), Set.copyOf(checkCodes));
    }

    private void assertRegistered(String type, Set<String> required, Set<String> registered) {
        List<String> missing = required.stream().filter(code -> !registered.contains(code)).toList();
        if (!missing.isEmpty()) {
            throw new IllegalStateException("Official verification " + type + " definitions are not registered: "
                    + String.join(", ", missing));
        }
    }

    private <T> List<T> safeList(List<T> values) {
        return values == null ? List.of() : values;
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private record DefinitionKeys(Set<String> metrics, Set<String> checks) {
    }
}
