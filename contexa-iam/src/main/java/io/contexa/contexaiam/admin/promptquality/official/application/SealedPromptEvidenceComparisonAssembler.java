package io.contexa.contexaiam.admin.promptquality.official.application;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexaiam.admin.promptquality.official.application.support.AbstractPromptQualityRuntimeEvidenceSupport;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationPromptComparison;
import org.springframework.util.StringUtils;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

public final class SealedPromptEvidenceComparisonAssembler extends AbstractPromptQualityRuntimeEvidenceSupport {

    private final PromptComparisonValueInterpreter values;

    public SealedPromptEvidenceComparisonAssembler(
            ObjectMapper objectMapper,
            PromptQualityMessageResolver messageResolver,
            PromptComparisonValueInterpreter values) {
        super(objectMapper, messageResolver);
        this.values = Objects.requireNonNull(values, "values");
    }

    public List<OfficialVerificationPromptComparison> assemble(SealedEvidencePackage evidencePackage) {
        Map<String, Object> manifest = parseJson(
                evidencePackage == null ? null : evidencePackage.getPromptEvidenceManifestJson());
        Map<String, OfficialVerificationPromptComparison> comparisons = new LinkedHashMap<>();
        appendManifestFields(comparisons, manifest.get("fields"));
        appendFieldStateLedger(comparisons, manifest.get("fieldStateLedger"));
        appendPromptExecutionMetadata(comparisons, evidencePackage);
        return List.copyOf(comparisons.values());
    }

    private void appendManifestFields(
            Map<String, OfficialVerificationPromptComparison> comparisons,
            Object fieldRows) {
        if (!(fieldRows instanceof List<?> rows)) {
            return;
        }
        for (Object row : rows) {
            if (!(row instanceof Map<?, ?> field)) {
                continue;
            }
            String fieldKey = values.value(field.get("fieldKey"));
            if (!StringUtils.hasText(fieldKey)) {
                continue;
            }
            String promptValue = values.value(field.get("promptValue"));
            String evidenceValue = values.value(field.get("evidenceValue"));
            String state = values.projectionState(
                    values.value(field.get("projectionState")),
                    values.value(field.get("requiredLevel")));
            put(comparisons, new OfficialVerificationPromptComparison(
                    fieldKey,
                    firstNonBlank(values.value(field.get("displayName")), values.fieldLabel(fieldKey, fieldKey)),
                    evidenceValue,
                    promptValue,
                    evidenceValue,
                    state,
                    values.stateLabel(state),
                    values.meaning(state),
                    values.stringList(field.get("metricCodes")),
                    List.of(), List.of(), List.of(), List.of(),
                    values.promptLocation(field),
                    values.evidenceSource(field),
                    values.value(field.get("producer")),
                    "USER_PROMPT_EVIDENCE_MANIFEST"));
        }
    }

    private void appendFieldStateLedger(
            Map<String, OfficialVerificationPromptComparison> comparisons,
            Object fieldRows) {
        if (!(fieldRows instanceof List<?> rows)) {
            return;
        }
        for (Object row : rows) {
            if (!(row instanceof Map<?, ?> field)) {
                continue;
            }
            String fieldKey = values.value(field.get("fieldKey"));
            if (!StringUtils.hasText(fieldKey)) {
                continue;
            }
            boolean finalUserPromptField = "FINAL_USER_PROMPT_FIELD".equals(values.value(field.get("sourceType")));
            boolean blockingCandidate = Boolean.TRUE.equals(field.get("blockingCandidate"));
            if (!finalUserPromptField && !blockingCandidate) {
                continue;
            }
            String label = firstNonBlank(
                    values.value(field.get("promptLabel")),
                    values.value(field.get("sourceFieldPath")),
                    fieldKey);
            String fieldValue = values.value(field.get("valuePreview"));
            String state = blockingCandidate ? values.promptProblemState(field) : "MATCH";
            put(comparisons, new OfficialVerificationPromptComparison(
                    fieldKey,
                    values.fieldLabel(fieldKey, label),
                    fieldValue,
                    fieldValue,
                    fieldValue,
                    state,
                    values.stateLabel(state),
                    firstNonBlank(values.value(field.get("absenceReasonText")), values.meaning(state)),
                    values.metricCodes(field),
                    List.of(), List.of(), List.of(), List.of(),
                    firstNonBlank(values.value(field.get("promptSection")), values.value(field.get("promptPresenceState"))),
                    values.value(field.get("sourceFieldPath")),
                    firstNonBlank(values.value(field.get("remediationOwner")), "PROMPT_ASSEMBLER"),
                    "PROMPT_FIELD_STATE_LEDGER"));
        }
    }

    private void appendPromptExecutionMetadata(
            Map<String, OfficialVerificationPromptComparison> comparisons,
            SealedEvidencePackage evidencePackage) {
        Map<String, Object> metadata = parseJson(
                evidencePackage == null ? null : evidencePackage.getPromptExecutionMetadataJson());
        appendFinalUserFieldProblems(comparisons, metadata.get("promptFinalUserFieldLedger"));
        appendUserFieldDiffProblems(comparisons, metadata.get("promptUserFieldDiffLedger"));
    }

    private void appendFinalUserFieldProblems(
            Map<String, OfficialVerificationPromptComparison> comparisons,
            Object ledger) {
        if (!(ledger instanceof List<?> rows)) {
            return;
        }
        for (Object row : rows) {
            if (!(row instanceof Map<?, ?> field)) {
                continue;
            }
            String fieldKey = values.value(field.get("fieldKey"));
            String state = values.promptProblemState(field);
            if (!StringUtils.hasText(fieldKey) || !values.actualProblemState(state)) {
                continue;
            }
            String fieldValue = values.value(field.get("valuePreview"));
            put(comparisons, new OfficialVerificationPromptComparison(
                    fieldKey,
                    values.fieldLabel(fieldKey, firstNonBlank(values.value(field.get("label")), fieldKey)),
                    fieldValue,
                    fieldValue,
                    fieldValue,
                    state,
                    values.stateLabel(state),
                    firstNonBlank(values.value(field.get("absenceReasonText")), values.meaning(state)),
                    values.metricCodes(field),
                    List.of(), List.of(), List.of(), List.of(),
                    firstNonBlank(values.value(field.get("sectionTitle")), values.value(field.get("promptSection"))),
                    values.value(field.get("sourceFieldPath")),
                    firstNonBlank(values.value(field.get("remediationOwner")), "PROMPT_ASSEMBLER"),
                    "PROMPT_FINAL_USER_FIELD_LEDGER"));
        }
    }

    private void appendUserFieldDiffProblems(
            Map<String, OfficialVerificationPromptComparison> comparisons,
            Object ledger) {
        if (!(ledger instanceof List<?> rows)) {
            return;
        }
        for (Object row : rows) {
            if (!(row instanceof Map<?, ?> field)
                    || !Boolean.TRUE.equals(field.get("officialBlockingCandidate"))) {
                continue;
            }
            String fieldKey = values.value(field.get("fieldKey"));
            String diffType = values.value(field.get("diffType")).toUpperCase(Locale.ROOT);
            String state = firstNonBlank(
                    values.value(field.get("problemType")),
                    "VALUE_CHANGED".equals(diffType) ? "CONTRACT_MISMATCH" : "PROMPT_MISSING");
            if (!StringUtils.hasText(fieldKey) || !values.actualProblemState(state)) {
                continue;
            }
            state = state.toUpperCase(Locale.ROOT);
            put(comparisons, new OfficialVerificationPromptComparison(
                    fieldKey,
                    values.fieldLabel(fieldKey, firstNonBlank(values.value(field.get("label")), fieldKey)),
                    values.value(field.get("rawValuePreview")),
                    values.value(field.get("finalValuePreview")),
                    values.value(field.get("finalValuePreview")),
                    state,
                    values.stateLabel(state),
                    firstNonBlank(values.value(field.get("reason")), values.meaning(state)),
                    values.metricCodes(field),
                    List.of(), List.of(), List.of(), List.of(),
                    firstNonBlank(values.value(field.get("sectionTitle")), "PROMPT METADATA"),
                    values.value(field.get("sourceFieldPath")),
                    firstNonBlank(values.value(field.get("remediationOwner")), "PROMPT_ASSEMBLER"),
                    "PROMPT_USER_FIELD_DIFF_LEDGER"));
        }
    }

    private void put(
            Map<String, OfficialVerificationPromptComparison> comparisons,
            OfficialVerificationPromptComparison candidate) {
        if (candidate == null || !StringUtils.hasText(candidate.fieldKey())) {
            return;
        }
        String key = values.dedupeKey(candidate.fieldKey(), candidate.state());
        OfficialVerificationPromptComparison existing = comparisons.get(key);
        if (existing == null
                || (!OfficialVerificationMetricClassifier.blockingPromptComparison(existing)
                && OfficialVerificationMetricClassifier.blockingPromptComparison(candidate))) {
            comparisons.put(key, candidate);
        }
    }
}