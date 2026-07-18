package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptMetricContractCatalog;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptParser;
import io.contexa.contexacore.verification.runtime.prompt.FinalPromptSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceCheckResult;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

public final class OfficialPromptSignalLedgerRecorder {

    private final OfficialVerificationPromptSignalWriter writer;

    public OfficialPromptSignalLedgerRecorder(OfficialVerificationPromptSignalWriter writer) {
        this.writer = Objects.requireNonNull(writer, "writer");
    }

    public void recordParsed(
            String aggregateRunId,
            String packageId,
            SealedEvidencePackage evidencePackage,
            FinalPromptMetricContractCatalog catalog) {
        if (!StringUtils.hasText(aggregateRunId)
                || !StringUtils.hasText(packageId)
                || evidencePackage == null
                || !StringUtils.hasText(evidencePackage.getUserPromptText())) {
            return;
        }
        FinalPromptSnapshot snapshot = new FinalPromptParser(catalog).parse(evidencePackage.getUserPromptText());
        snapshot.sections().forEach(section -> insert(
                aggregateRunId, packageId, "PROMPT", "SECTION", "section:" + section.name(),
                "finalUserPrompt.section", section.name(), "", section.name(), section.lineNumber(), "PROMPT_SECTION"));
        snapshot.fields().stream().filter(field -> field.mappedToContract()).forEach(field -> insert(
                aggregateRunId, packageId, "PROMPT", "FIELD", field.semanticKey(), field.promptLocation(),
                field.section(), field.label(), field.value(), field.lineNumber(),
                firstNonBlank(field.attackSignalRole(), field.securityRelevance(), "PROMPT_FIELD")));
        snapshot.bullets().forEach(bullet -> insert(
                aggregateRunId, packageId, "PROMPT", "BULLET", bullet.semanticKey(), bullet.promptLocation(),
                bullet.section(), firstNonBlank(bullet.parentGroup(), "bullet"), bullet.text(), bullet.lineNumber(),
                firstNonBlank(bullet.attackSignalRole(), "PROMPT_BULLET")));
        snapshot.narrativeLines().forEach(line -> insert(
                aggregateRunId, packageId, "PROMPT", "NARRATIVE", line.semanticKey(), line.promptLocation(),
                line.section(), "narrative", line.text(), line.lineNumber(),
                firstNonBlank(line.attackSignalRole(), "PROMPT_NARRATIVE")));
        snapshot.semanticGroups().forEach(group -> insert(
                aggregateRunId, packageId, "PROMPT", "SEMANTIC_GROUP", group.groupKey(), group.groupKey(),
                group.section(), group.groupLabel(), groupValue(
                        group.fieldLabels().size(), group.bulletTexts().size(), group.narrativeTexts().size()),
                group.startLineNumber(),
                firstNonBlank(group.attackSignalRole(), group.securityRelevance(), "PROMPT_SEMANTIC_GROUP")));
        snapshot.unmappedFacts().forEach(fact -> insert(
                aggregateRunId, packageId, "INTERNAL", "UNMAPPED_PROMPT_FACT",
                fact.errorCode() + ":" + fact.section() + ":" + fact.label(),
                "internalGate.unmappedPromptFact", fact.section(), fact.label(), fact.value(), fact.lineNumber(),
                "INTERNAL_GATE"));
    }

    public void recordDetected(
            String aggregateRunId,
            String packageId,
            String metricCode,
            String checkCode,
            RuntimeEvidenceCheckResult check,
            List<String> detectedSignals) {
        if (detectedSignals == null || detectedSignals.isEmpty()) {
            return;
        }
        int lineNumber = 0;
        for (String signal : detectedSignals) {
            if (StringUtils.hasText(signal)) {
                String value = signal.trim();
                writer.insert(new OfficialVerificationPromptSignalWriter.Command(
                        fit(packageId, 128), fit(aggregateRunId, 256), fit(metricCode, 32), fit(checkCode, 128),
                        fit(value, 512), fit(firstNonBlank(check.source(), check.issueKey()), 512), "",
                        fit(check.label(), 256), preview(value, 400), null, ++lineNumber,
                        fit(firstNonBlank(check.readinessScope(), "CUSTOMER_PROMPT_QUALITY"), 128)));
            }
        }
    }

    private void insert(
            String aggregateRunId,
            String packageId,
            String metricCode,
            String checkCode,
            String signalKey,
            String promptLocation,
            String sectionName,
            String labelName,
            String value,
            Integer lineNumber,
            String signalRole) {
        if (!StringUtils.hasText(signalKey)) {
            throw new IllegalStateException("Prompt signal ledger row requires a contract signal key.");
        }
        writer.insert(new OfficialVerificationPromptSignalWriter.Command(
                fit(packageId, 128), fit(aggregateRunId, 256), fit(metricCode, 32), fit(checkCode, 128),
                fit(signalKey, 512), fit(promptLocation, 512), fit(sectionName, 256), fit(labelName, 256),
                preview(value, 400), sha256Prefixed(value), lineNumber, fit(signalRole, 128)));
    }

    private String groupValue(int fieldCount, int bulletCount, int narrativeCount) {
        return "fields=" + fieldCount + "; bullets=" + bulletCount + "; narratives=" + narrativeCount;
    }

    private String sha256Prefixed(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(safe(value).getBytes(StandardCharsets.UTF_8));
            return "sha256:" + HexFormat.of().formatHex(digest);
        }
        catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is not available", ex);
        }
    }

    private String preview(String value, int maxLength) {
        String safeValue = safe(value);
        return safeValue.length() <= maxLength ? safeValue : safeValue.substring(0, maxLength);
    }

    private String fit(String value, int maxLength) {
        return StringUtils.hasText(value) && value.length() > maxLength ? value.substring(0, maxLength) : value;
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return "";
    }

    private String safe(String value) {
        return value == null ? "" : value;
    }
}