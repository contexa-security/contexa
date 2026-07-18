package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.metric.OfficialPromptQualityNarrativeCatalog;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricCheckContract;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceCheckResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceMetricResult;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;

final class OfficialMetricPurposeLedgerRecorder {

    private final ObjectMapper objectMapper;
    private final OfficialVerificationMetricPurposeWriter purposeWriter;
    private final OfficialVerificationMetricPurposeEvidenceWriter evidenceWriter;
    private final OfficialFinalPromptMetricContractRegistry contractRegistry;
    private final OfficialMetricPurposeNarrative narrative;
    private final OfficialCustomerPurposeEvidenceParser evidenceParser;
    private final OfficialCustomerPurposeEvidenceValidator evidenceValidator;
    private final OfficialRuntimeEvidenceCheckInterpreter checkInterpreter;
    private final OfficialPromptSignalLedgerRecorder promptSignalRecorder;
    private final OfficialPromptQualityNarrativeCatalog narrativeCatalog = new OfficialPromptQualityNarrativeCatalog();

    OfficialMetricPurposeLedgerRecorder(
            ObjectMapper objectMapper,
            OfficialVerificationLedgerWriters writers,
            OfficialFinalPromptMetricContractRegistry contractRegistry,
            OfficialMetricPurposeNarrative narrative,
            OfficialCustomerPurposeEvidenceParser evidenceParser,
            OfficialCustomerPurposeEvidenceValidator evidenceValidator,
            OfficialRuntimeEvidenceCheckInterpreter checkInterpreter,
            OfficialPromptSignalLedgerRecorder promptSignalRecorder) {
        this.objectMapper = objectMapper;
        this.purposeWriter = writers.metricPurpose();
        this.evidenceWriter = writers.metricPurposeEvidence();
        this.contractRegistry = contractRegistry;
        this.narrative = narrative;
        this.evidenceParser = evidenceParser;
        this.evidenceValidator = evidenceValidator;
        this.checkInterpreter = checkInterpreter;
        this.promptSignalRecorder = promptSignalRecorder;
    }

    void record(String aggregateRunId, String packageId, List<RuntimeEvidenceMetricResult> metrics) {
        if (!StringUtils.hasText(aggregateRunId) || !StringUtils.hasText(packageId) || metrics == null) {
            return;
        }
        contractRegistry.upsertFull();
        contractRegistry.assertFullPersisted();
        metrics.forEach(metric -> recordMetric(aggregateRunId, packageId, metric));
    }

    void assertCustomerDisplayComplete(String aggregateRunId) {
        contractRegistry.assertCustomerDisplayComplete(aggregateRunId);
    }

    private void recordMetric(
            String aggregateRunId,
            String packageId,
            RuntimeEvidenceMetricResult metric) {
        if (metric == null || metric.checks() == null) {
            return;
        }
        metric.checks().stream().filter(check -> check != null)
                .forEach(check -> recordCheck(aggregateRunId, packageId, metric, check));
    }

    private void recordCheck(
            String aggregateRunId,
            String packageId,
            RuntimeEvidenceMetricResult metric,
            RuntimeEvidenceCheckResult check) {
        PurposeContext context = purposeContext(metric, check);
        recordPurposeHeaders(aggregateRunId, packageId, check, context);
        recordCustomerDisplay(aggregateRunId, packageId, check, context);
        recordPurposeEvidence(aggregateRunId, packageId, check, context);
        promptSignalRecorder.recordDetected(
                aggregateRunId, packageId, context.metricCode(), context.checkCode(), check, context.detectedSignals());
    }

    private PurposeContext purposeContext(
            RuntimeEvidenceMetricResult metric,
            RuntimeEvidenceCheckResult check) {
        String metricCode = normalize(metric.metricCode());
        String runtimeCheckCode = firstNonBlank(check.checkCode(), check.label(), "CHECK");
        FinalPromptMetricCheckContract contract = StringUtils.hasText(check.purposeVersion())
                ? contractRegistry.checkOrNull(metricCode, check) : null;
        boolean customerVisible = contractRegistry.customerDisplayEligible(contract)
                && !checkInterpreter.inputNotReady(check)
                && !(metricPassed(metric) && !check.pass());
        String readinessScope = checkInterpreter.inputNotReady(check)
                ? "INPUT_READINESS" : firstNonBlank(check.readinessScope(), "CUSTOMER_PROMPT_QUALITY");
        String checkCode = firstNonBlank(contract == null ? null : contract.checkName(), runtimeCheckCode);
        String issueKey = firstNonBlank(
                check.issueKey(), contract == null ? null : contract.issueKey(), check.source(), checkCode);
        CustomerDisplayPayloadFactory.Payload payload = customerVisible && StringUtils.hasText(check.purposeVersion())
                ? narrative.customerDisplayPayload(check, contract) : null;
        return new PurposeContext(
                metricCode, checkCode, check.purposeVersion(), issueKey, customerVisible,
                readinessScope, checkInterpreter.detectedSignals(check), contract, payload);
    }

    private void recordPurposeHeaders(
            String aggregateRunId,
            String packageId,
            RuntimeEvidenceCheckResult check,
            PurposeContext context) {
        List<String> presentInputs = prefixedValues(context.detectedSignals(), "present:");
        List<String> missingInputs = prefixedValues(context.detectedSignals(), "missing:");
        purposeWriter.insertReadiness(new OfficialVerificationMetricPurposeWriter.ReadinessCommand(
                fit(packageId, 128), fit(aggregateRunId, 256), fit(context.metricCode(), 32),
                fit(context.checkCode(), 128), fit(context.purposeVersion(), 128),
                fit(checkInterpreter.inputReadinessState(check), 128),
                writeJson(presentInputs.isEmpty() ? context.detectedSignals() : presentInputs),
                writeJson(missingInputs), fit(context.readinessScope(), 128), context.customerVisible()));
        purposeWriter.insertPurpose(purposeCommand(aggregateRunId, packageId, check, context));
    }

    private OfficialVerificationMetricPurposeWriter.PurposeCommand purposeCommand(
            String aggregateRunId,
            String packageId,
            RuntimeEvidenceCheckResult check,
            PurposeContext context) {
        return new OfficialVerificationMetricPurposeWriter.PurposeCommand(
                fit(packageId, 128), fit(aggregateRunId, 256), fit(context.metricCode(), 32),
                fit(context.checkCode(), 128), fit(context.purposeVersion(), 128),
                narrativeCatalog.metricPurpose(context.metricCode()),
                narrative.decisionUtility(check, context.customerVisible(), context.contract()),
                fit(checkInterpreter.purposeResult(check), 128), fit(context.issueKey(), 512),
                context.customerVisible(), fit(context.readinessScope(), 128),
                validJsonArray(check.detectedSignalsJson()), validJsonArray(check.interpretationLinksJson()),
                narrative.expectedValue(check, context.customerVisible(), context.contract()),
                narrative.actualValue(check, context.customerVisible(), context.contract()),
                fit(check.remediationOwner(), 128),
                narrative.nextAction(check, context.customerVisible(), context.contract()),
                narrative.reverifyCriterion(check, context.customerVisible(), context.contract()));
    }

    private void recordCustomerDisplay(
            String aggregateRunId,
            String packageId,
            RuntimeEvidenceCheckResult check,
            PurposeContext context) {
        if (context.payload() == null || !StringUtils.hasText(context.purposeVersion())) {
            return;
        }
        for (CustomerDisplayPayloadFactory.RolePayload role : context.payload().rolePayloads()) {
            contractRegistry.assertCustomerDisplayRole(
                    context.purposeVersion(), context.metricCode(), context.checkCode(), role.displayRole());
            purposeWriter.insertCustomerDisplay(new OfficialVerificationMetricPurposeWriter.CustomerDisplayCommand(
                    fit(packageId, 128), fit(aggregateRunId, 256), fit(context.metricCode(), 32),
                    fit(context.checkCode(), 128), fit(context.purposeVersion(), 128), fit(role.displayRole(), 64),
                    fit(role.title(), 512), fit(role.summary(), 1200), role.evidenceText(), role.whyItMatters(),
                    role.resolutionAction(), role.reverifyCondition(), writeJson(displayContextItems(context.contract())),
                    validJsonArray(check.detectedSignalsJson()),
                    fit(firstNonBlank(check.source(), check.issueKey(), context.checkCode()), 512)));
        }
    }

    private void recordPurposeEvidence(
            String aggregateRunId,
            String packageId,
            RuntimeEvidenceCheckResult check,
            PurposeContext purposeContext) {
        EvidenceContext evidenceContext = evidenceContext(check, purposeContext);
        for (String signal : evidenceContext.signals()) {
            recordEvidenceSignal(
                    aggregateRunId, packageId, check, purposeContext, evidenceContext, signal);
        }
    }

    private EvidenceContext evidenceContext(
            RuntimeEvidenceCheckResult check,
            PurposeContext context) {
        List<String> signals = context.customerVisible()
                ? evidenceParser.visibleSignals(context.detectedSignals(), check, true)
                : context.detectedSignals().stream().filter(StringUtils::hasText).distinct().toList();
        boolean contractBacked = context.customerVisible() && StringUtils.hasText(check.purposeVersion());
        if (signals.isEmpty() && contractBacked) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Customer-visible metric purpose evidence is missing. "
                    + "metricCode=" + context.metricCode() + ", checkCode=" + context.checkCode());
        }
        if (signals.isEmpty()) {
            signals = List.of(firstNonBlank(
                    context.customerVisible() ? check.label() : check.issueKey(),
                    check.source(), context.checkCode()));
        }
        String interpretation = contractBacked
                ? narrative.customerDisplayPayload(check, context.contract()).whyItMatters()
                : firstNonBlank(check.decisionUtility(), check.whyItMatters(), check.expectedValue(), check.actualValue());
        if (!StringUtils.hasText(interpretation)) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Metric purpose evidence requires contract interpretation."
                    + " metricCode=" + context.metricCode() + ", checkCode=" + context.checkCode());
        }
        return new EvidenceContext(
                signals, interpretation, checkInterpreter.purposeResult(check),
                firstNonBlank(context.readinessScope(), "CUSTOMER_PROMPT_QUALITY"),
                firstNonBlank(check.source(), check.issueKey()));
    }

    private void recordEvidenceSignal(
            String aggregateRunId,
            String packageId,
            RuntimeEvidenceCheckResult check,
            PurposeContext context,
            EvidenceContext evidenceContext,
            String signal) {
        CustomerPurposeEvidenceDisplay display = context.customerVisible() || evidenceParser.structuredSignal(signal)
                ? evidenceParser.display(signal, check, context.contract()) : null;
        if (display == null) {
            display = new CustomerPurposeEvidenceDisplay(
                    firstNonBlank(signal, context.checkCode()),
                    firstNonBlank(signal, check.actualValue(), check.expectedValue()));
        }
        if (context.customerVisible()) {
            evidenceValidator.validate(display, check, context.contract());
        }
        List<String> runtimeFacts = context.customerVisible()
                ? evidenceParser.scopedRuntimeFacts(display) : display.runtimeFacts();
        evidenceWriter.insert(new OfficialVerificationMetricPurposeEvidenceWriter.Command(
                fit(packageId, 128), fit(aggregateRunId, 256), context.metricCode(), fit(context.checkCode(), 128),
                fit(context.purposeVersion(), 128), fit(display.signalKey(), 512),
                fit(evidenceContext.promptLocation(), 512), display.evidenceValue(),
                sha256(display.evidenceValue()), evidenceContext.interpretation(),
                fit(evidenceContext.purposeResult(), 128), context.customerVisible(),
                fit(evidenceContext.readinessScope(), 128), writeJson(runtimeFacts), writeJson(display.contextItems())));
    }

    private List<String> displayContextItems(FinalPromptMetricCheckContract contract) {
        List<String> items = new ArrayList<>();
        for (Map<String, String> binding : contractRegistry.evidenceBindings(contract)) {
            if (binding == null) {
                continue;
            }
            appendDelimited(items, binding.get("customerVisibleContextItems"));
            appendDelimited(items, binding.get("customerVisiblePromptItems"));
        }
        return List.copyOf(items);
    }

    private List<String> prefixedValues(List<String> values, String prefix) {
        return values.stream().filter(value -> value.startsWith(prefix))
                .map(value -> value.substring(prefix.length())).toList();
    }

    private void appendDelimited(List<String> items, String value) {
        if (!StringUtils.hasText(value)) {
            return;
        }
        for (String token : value.split("[,|]")) {
            String item = token.trim();
            if (StringUtils.hasText(item) && !items.contains(item)) {
                items.add(item);
            }
        }
    }

    private String validJsonArray(String value) {
        if (!StringUtils.hasText(value)) {
            return "[]";
        }
        try {
            JsonNode node = objectMapper.readTree(value);
            return node != null && node.isArray() ? objectMapper.writeValueAsString(node) : "[]";
        }
        catch (Exception ignored) {
            return "[]";
        }
    }

    private String writeJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        }
        catch (Exception ex) {
            throw new IllegalStateException("Official metric purpose JSON serialization failed.", ex);
        }
    }

    private String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(safe(value).getBytes(StandardCharsets.UTF_8));
            return "sha256:" + HexFormat.of().formatHex(digest);
        }
        catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is not available.", ex);
        }
    }

    private boolean metricPassed(RuntimeEvidenceMetricResult metric) {
        String state = normalize(metric == null ? null : metric.state());
        return List.of("SUCCESS", "PASS", "PASSED", "VERIFIED", "COMPLETED").contains(state);
    }

    private String fit(String value, int maxLength) {
        return !StringUtils.hasText(value) || value.length() <= maxLength ? value : value.substring(0, maxLength);
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return "";
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private String safe(String value) {
        return value == null ? "" : value.trim();
    }

    private record PurposeContext(
            String metricCode,
            String checkCode,
            String purposeVersion,
            String issueKey,
            boolean customerVisible,
            String readinessScope,
            List<String> detectedSignals,
            FinalPromptMetricCheckContract contract,
            CustomerDisplayPayloadFactory.Payload payload) {
    }

    private record EvidenceContext(
            List<String> signals,
            String interpretation,
            String purposeResult,
            String readinessScope,
            String promptLocation) {
    }
}
