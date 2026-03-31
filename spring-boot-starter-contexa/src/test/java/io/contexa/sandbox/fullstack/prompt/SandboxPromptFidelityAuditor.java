package io.contexa.sandbox.fullstack.prompt;

import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceSupport;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 실제 prompt 원본과 prompt metadata를 전수 대조하는 fidelity 감사기.
 *
 * 이 감사는 단순히 "섹션 문자열이 있나"만 보는 것이 아니다.
 * - prompt 본문
 * - metadata
 * - promptExecutionMetadata
 * - sectionSet / omittedSections / omissionLedger
 * - hash / length
 * 가 서로 같은 사실을 말하는지 검증한다.
 */
public final class SandboxPromptFidelityAuditor {

    private static final List<SectionRule> SECTION_RULES = List.of(
            new SectionRule("SYSTEM_INSTRUCTION", PromptKind.SYSTEM, true, List.of("You are a Zero Trust security analyst AI.")),
            new SectionRule("DECISION_CONTRACT", PromptKind.SYSTEM, true, List.of("=== DECISION ===", "<output_format>")),
            new SectionRule("CURRENT_REQUEST_AND_EVENT", PromptKind.USER, true, List.of("=== CURRENT REQUEST AND EVENT ===")),
            new SectionRule("BRIDGE_AND_COVERAGE", PromptKind.USER, false, List.of(
                    "=== BRIDGE RESOLUTION CONTEXT ===",
                    "=== CONTEXT COVERAGE ===")),
            new SectionRule("IDENTITY_AND_ROLE", PromptKind.USER, false, List.of(
                    "=== IDENTITY AND ROLE CONTEXT ===",
                    "=== AUTHENTICATION AND ASSURANCE CONTEXT ===")),
            new SectionRule("RESOURCE_AND_ACTION", PromptKind.USER, true, List.of("=== RESOURCE AND ACTION CONTEXT ===")),
            new SectionRule("SESSION_NARRATIVE", PromptKind.USER, true, List.of("=== SESSION NARRATIVE CONTEXT ===")),
            new SectionRule("OBSERVED_AND_PERSONAL_WORK_PATTERN", PromptKind.USER, false, List.of(
                    "=== OBSERVED WORK PATTERN CONTEXT ===",
                    "=== PERSONAL WORK PROFILE ===")),
            new SectionRule("ROLE_SCOPE", PromptKind.USER, false, List.of(
                    "=== ROLE AND WORK SCOPE CONTEXT ===",
                    "=== PEER COHORT DELTA ===")),
            new SectionRule("FRICTION_AND_APPROVAL", PromptKind.USER, true, List.of("=== FRICTION AND APPROVAL HISTORY ===")),
            new SectionRule("DELEGATED_OBJECTIVE", PromptKind.USER, true, List.of("=== DELEGATED OBJECTIVE CONTEXT ===")),
            new SectionRule("THREAT_LEARNING_AND_MEMORY", PromptKind.USER, true, List.of("=== OUTCOME AND REASONING MEMORY ===")),
            new SectionRule("EXPLICIT_MISSING_KNOWLEDGE", PromptKind.USER, true, List.of("=== EXPLICIT MISSING KNOWLEDGE ==="))
    );

    private SandboxPromptFidelityAuditor() {
    }

    public static SandboxPromptFidelityAssessment audit(
            String benchmarkRunId,
            String username,
            String source,
            SandboxPromptTraceSnapshot snapshot) {
        List<SandboxPromptDefectFinding> findings = new ArrayList<>();
        Map<String, Object> metadata = snapshot != null && snapshot.metadata() != null
                ? new LinkedHashMap<>(snapshot.metadata())
                : Map.of();
        PromptExecutionMetadata promptExecutionMetadata = snapshot != null ? snapshot.promptExecutionMetadata() : null;

        List<String> metadataSectionKeys = castStringList(metadata.get("promptSectionSet"));
        List<String> executionSectionKeys = promptExecutionMetadata != null ? promptExecutionMetadata.sectionSet() : List.of();
        List<String> metadataOmittedSections = castStringList(metadata.get("omittedSections"));
        List<String> executionOmittedSections = promptExecutionMetadata != null ? promptExecutionMetadata.omittedSections() : List.of();
        List<Map<String, Object>> metadataOmissionLedger = castMapList(metadata.get("omissionLedger"));
        int omissionLedgerCount = promptExecutionMetadata != null ? promptExecutionMetadata.omissionLedger().size() : 0;

        String systemPrompt = snapshot != null ? snapshot.systemPrompt() : null;
        String userPrompt = snapshot != null ? snapshot.userPrompt() : null;

        int total = 0;
        int passed = 0;

        total += 1;
        passed += check(findings, benchmarkRunId, username, source,
                "PROMPT_METADATA_SECTION_SET_PRESENT",
                !metadataSectionKeys.isEmpty(),
                "metadata.promptSectionSet=" + metadataSectionKeys);

        total += 1;
        passed += check(findings, benchmarkRunId, username, source,
                "PROMPT_EXECUTION_SECTION_SET_PRESENT",
                !executionSectionKeys.isEmpty(),
                "promptExecutionMetadata.sectionSet=" + executionSectionKeys);

        total += 1;
        passed += check(findings, benchmarkRunId, username, source,
                "PROMPT_SECTION_SET_MATCH",
                metadataSectionKeys.equals(executionSectionKeys),
                "metadata.promptSectionSet=" + metadataSectionKeys
                        + ", promptExecutionMetadata.sectionSet=" + executionSectionKeys);

        total += 1;
        passed += check(findings, benchmarkRunId, username, source,
                "PROMPT_OMITTED_SECTIONS_MATCH",
                metadataOmittedSections.equals(executionOmittedSections),
                "metadata.omittedSections=" + metadataOmittedSections
                        + ", promptExecutionMetadata.omittedSections=" + executionOmittedSections);

        total += 1;
        passed += check(findings, benchmarkRunId, username, source,
                "PROMPT_OMISSION_LEDGER_COUNT_MATCH",
                asInt(metadata.get("promptOmissionCount")) == omissionLedgerCount
                        && metadataOmissionLedger.size() == omissionLedgerCount,
                "metadata.promptOmissionCount=" + metadata.get("promptOmissionCount")
                        + ", metadata.omissionLedger.size=" + metadataOmissionLedger.size()
                        + ", promptExecutionMetadata.omissionLedger.size=" + omissionLedgerCount);

        total += 1;
        passed += check(findings, benchmarkRunId, username, source,
                "PROMPT_EVIDENCE_COMPLETENESS_MATCH",
                safeEquals(text(metadata.get("promptEvidenceCompleteness")),
                        promptExecutionMetadata != null && promptExecutionMetadata.promptEvidenceCompleteness() != null
                                ? promptExecutionMetadata.promptEvidenceCompleteness().name()
                                : null),
                "metadata.promptEvidenceCompleteness=" + text(metadata.get("promptEvidenceCompleteness"))
                        + ", promptExecutionMetadata.promptEvidenceCompleteness="
                        + (promptExecutionMetadata != null ? promptExecutionMetadata.promptEvidenceCompleteness() : null));

        total += 1;
        passed += check(findings, benchmarkRunId, username, source,
                "PROMPT_HASH_MATCH",
                safeEquals(text(metadata.get("promptHash")), promptExecutionMetadata != null ? promptExecutionMetadata.promptHash() : null)
                        && safeEquals(text(metadata.get("promptHash")), PromptGovernanceSupport.sha256(normalize(systemPrompt) + "\n---\n" + normalize(userPrompt))),
                "metadata.promptHash=" + text(metadata.get("promptHash"))
                        + ", promptExecutionMetadata.promptHash=" + (promptExecutionMetadata != null ? promptExecutionMetadata.promptHash() : null));

        total += 1;
        passed += check(findings, benchmarkRunId, username, source,
                "SYSTEM_PROMPT_HASH_MATCH",
                safeEquals(text(metadata.get("systemPromptHash")), promptExecutionMetadata != null ? promptExecutionMetadata.systemPromptHash() : null)
                        && safeEquals(text(metadata.get("systemPromptHash")), PromptGovernanceSupport.sha256(normalize(systemPrompt))),
                "metadata.systemPromptHash=" + text(metadata.get("systemPromptHash"))
                        + ", promptExecutionMetadata.systemPromptHash="
                        + (promptExecutionMetadata != null ? promptExecutionMetadata.systemPromptHash() : null));

        total += 1;
        passed += check(findings, benchmarkRunId, username, source,
                "USER_PROMPT_HASH_MATCH",
                safeEquals(text(metadata.get("userPromptHash")), promptExecutionMetadata != null ? promptExecutionMetadata.userPromptHash() : null)
                        && safeEquals(text(metadata.get("userPromptHash")), PromptGovernanceSupport.sha256(normalize(userPrompt))),
                "metadata.userPromptHash=" + text(metadata.get("userPromptHash"))
                        + ", promptExecutionMetadata.userPromptHash="
                        + (promptExecutionMetadata != null ? promptExecutionMetadata.userPromptHash() : null));

        total += 1;
        passed += check(findings, benchmarkRunId, username, source,
                "PROMPT_LENGTH_MATCH",
                asInt(metadata.get("systemPromptLength")) == length(systemPrompt)
                        && asInt(metadata.get("userPromptLength")) == length(userPrompt)
                        && asInt(metadata.get("totalPromptLength")) == (length(systemPrompt) + length(userPrompt)),
                "metadata.lengths=[system=" + metadata.get("systemPromptLength")
                        + ", user=" + metadata.get("userPromptLength")
                        + ", total=" + metadata.get("totalPromptLength")
                        + "], actual=[system=" + length(systemPrompt)
                        + ", user=" + length(userPrompt)
                        + ", total=" + (length(systemPrompt) + length(userPrompt)) + "]");

        total += 1;
        passed += check(findings, benchmarkRunId, username, source,
                "PROMPT_EXECUTION_LENGTH_MATCH",
                promptExecutionMetadata != null
                        && promptExecutionMetadata.systemPromptLength() == length(systemPrompt)
                        && promptExecutionMetadata.userPromptLength() == length(userPrompt)
                        && promptExecutionMetadata.totalPromptLength() == (length(systemPrompt) + length(userPrompt)),
                "promptExecutionMetadata.lengths="
                        + (promptExecutionMetadata != null
                        ? "[system=" + promptExecutionMetadata.systemPromptLength()
                        + ", user=" + promptExecutionMetadata.userPromptLength()
                        + ", total=" + promptExecutionMetadata.totalPromptLength() + "]"
                        : null));

        total += 1;
        passed += check(findings, benchmarkRunId, username, source,
                "PROMPT_SECTION_AND_OMISSION_DISJOINT",
                executionSectionKeys.stream().noneMatch(executionOmittedSections::contains),
                "sectionSet=" + executionSectionKeys + ", omittedSections=" + executionOmittedSections);

        for (SectionRule rule : SECTION_RULES) {
            boolean rendered = executionSectionKeys.contains(rule.sectionKey());
            boolean omitted = executionOmittedSections.contains(rule.sectionKey());
            boolean bodyContainsMarkers = rule.matches(systemPrompt, userPrompt);

            total += 1;
            passed += check(findings, benchmarkRunId, username, source,
                    "PROMPT_SECTION_" + rule.sectionKey() + "_RENDERED_MATCH",
                    rendered == bodyContainsMarkers || (!rendered && omitted && !bodyContainsMarkers),
                    "sectionKey=" + rule.sectionKey()
                            + ", rendered=" + rendered
                            + ", omitted=" + omitted
                            + ", bodyContainsMarkers=" + bodyContainsMarkers);
        }

        double fidelityRate = total <= 0 ? 0.0d : (passed * 100.0d) / total;
        return new SandboxPromptFidelityAssessment(
                source,
                fidelityRate,
                metadataSectionKeys,
                executionSectionKeys,
                executionOmittedSections,
                omissionLedgerCount,
                findings);
    }

    private static int check(
            List<SandboxPromptDefectFinding> findings,
            String benchmarkRunId,
            String username,
            String source,
            String code,
            boolean passed,
            String detail) {
        if (!passed) {
            findings.add(new SandboxPromptDefectFinding(
                    benchmarkRunId,
                    username,
                    source,
                    code,
                    SandboxPromptDefectCategory.IMPLEMENTATION_DEFECT,
                    code.replace('_', ' ').toLowerCase(Locale.ROOT),
                    detail));
        }
        return passed ? 1 : 0;
    }

    private static List<String> castStringList(Object value) {
        if (!(value instanceof List<?> list)) {
            return List.of();
        }
        List<String> casted = new ArrayList<>(list.size());
        for (Object item : list) {
            if (item != null) {
                casted.add(String.valueOf(item));
            }
        }
        return List.copyOf(casted);
    }

    private static List<Map<String, Object>> castMapList(Object value) {
        if (!(value instanceof List<?> list)) {
            return List.of();
        }
        List<Map<String, Object>> casted = new ArrayList<>(list.size());
        for (Object item : list) {
            if (item instanceof Map<?, ?> map) {
                Map<String, Object> normalized = new LinkedHashMap<>();
                map.forEach((key, entryValue) -> normalized.put(String.valueOf(key), entryValue));
                casted.add(normalized);
            }
        }
        return List.copyOf(casted);
    }

    private static int asInt(Object value) {
        if (value instanceof Number number) {
            return number.intValue();
        }
        if (value instanceof String text && text.matches("-?\\d+")) {
            return Integer.parseInt(text);
        }
        return -1;
    }

    private static int length(String value) {
        return value == null ? 0 : value.length();
    }

    private static String normalize(String value) {
        return value == null ? "" : value;
    }

    private static String text(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private static boolean safeEquals(String left, String right) {
        return left == null ? right == null : left.equals(right);
    }

    private enum PromptKind {
        SYSTEM,
        USER
    }

    private record SectionRule(
            String sectionKey,
            PromptKind promptKind,
            boolean requireAllMarkers,
            List<String> markers) {

        private boolean matches(String systemPrompt, String userPrompt) {
            String prompt = promptKind == PromptKind.SYSTEM ? normalize(systemPrompt) : normalize(userPrompt);
            if (!StringUtils.hasText(prompt)) {
                return false;
            }
            if (requireAllMarkers) {
                return markers.stream().allMatch(prompt::contains);
            }
            return markers.stream().anyMatch(prompt::contains);
        }
    }
}
