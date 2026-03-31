package io.contexa.sandbox.fullstack.prompt;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.std.components.prompt.PromptExecutionMetadata;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * requestId 기준 trace 계약 준수 검사기.
 *
 * 여기서 실패하는 항목은 LLM 판단 영역이 아니라 replay/trace 수집 계약 결함으로 본다.
 * 즉 이 감사에서 깨지면 benchmark 입력 자체가 성립하지 않는다.
 */
public final class SandboxPromptTraceContractValidator {

    private SandboxPromptTraceContractValidator() {
    }

    public static SandboxPromptTraceContractAssessment audit(
            String benchmarkRunId,
            String username,
            String source,
            SandboxPromptTraceSnapshot snapshot) {
        List<SandboxPromptDefectFinding> findings = new ArrayList<>();
        int total = 23;
        int passed = 0;

        passed += required(findings, benchmarkRunId, username, source, "TRACE_REQUEST_ID",
                "trace.requestId가 비어 있으면 안 된다",
                StringUtils.hasText(snapshot != null ? snapshot.requestId() : null),
                "trace.requestId=" + (snapshot != null ? snapshot.requestId() : null));
        passed += required(findings, benchmarkRunId, username, source, "TRACE_EVENT",
                "trace.event는 반드시 존재해야 한다",
                snapshot != null && snapshot.event() != null,
                "trace.event=" + (snapshot != null ? snapshot.event() : null));
        passed += required(findings, benchmarkRunId, username, source, "TRACE_SESSION_CTX",
                "trace.sessionCtx는 반드시 존재해야 한다",
                snapshot != null && snapshot.sessionContext() != null,
                "trace.sessionCtx=" + (snapshot != null ? snapshot.sessionContext() : null));
        passed += required(findings, benchmarkRunId, username, source, "TRACE_BEHAVIOR_CTX",
                "trace.behaviorCtx는 반드시 존재해야 한다",
                snapshot != null && snapshot.behaviorAnalysis() != null,
                "trace.behaviorCtx=" + (snapshot != null ? snapshot.behaviorAnalysis() : null));
        passed += required(findings, benchmarkRunId, username, source, "TRACE_RELATED_DOCS",
                "trace.relatedDocuments 자체는 null이면 안 된다",
                snapshot != null && snapshot.relatedDocuments() != null,
                "trace.relatedDocuments=" + (snapshot != null ? snapshot.relatedDocuments() : null));
        passed += required(findings, benchmarkRunId, username, source, "TRACE_SYSTEM_PROMPT",
                "trace.systemPrompt가 비어 있으면 안 된다",
                snapshot != null && StringUtils.hasText(snapshot.systemPrompt()),
                "trace.systemPrompt.blank=" + (snapshot == null || !StringUtils.hasText(snapshot.systemPrompt())));
        passed += required(findings, benchmarkRunId, username, source, "TRACE_USER_PROMPT",
                "trace.userPrompt가 비어 있으면 안 된다",
                snapshot != null && StringUtils.hasText(snapshot.userPrompt()),
                "trace.userPrompt.blank=" + (snapshot == null || !StringUtils.hasText(snapshot.userPrompt())));
        passed += required(findings, benchmarkRunId, username, source, "TRACE_METADATA",
                "trace.metadata는 반드시 존재해야 한다",
                snapshot != null && snapshot.metadata() != null,
                "trace.metadata=" + (snapshot != null ? snapshot.metadata() : null));
        passed += required(findings, benchmarkRunId, username, source, "TRACE_PROMPT_EXECUTION_METADATA",
                "trace.promptExecutionMetadata는 반드시 존재해야 한다",
                snapshot != null && snapshot.promptExecutionMetadata() != null,
                "trace.promptExecutionMetadata=" + (snapshot != null ? snapshot.promptExecutionMetadata() : null));

        Map<String, Object> eventMetadata = eventMetadata(snapshot);
        Map<String, Object> metadata = metadata(snapshot);
        PromptExecutionMetadata promptExecutionMetadata = snapshot != null ? snapshot.promptExecutionMetadata() : null;

        passed += required(findings, benchmarkRunId, username, source, "TRACE_EVENT_REQUEST_ID",
                "event.metadata.requestId가 비어 있으면 안 된다",
                StringUtils.hasText(text(eventMetadata.get("requestId"))),
                "event.metadata.requestId=" + text(eventMetadata.get("requestId")));
        passed += required(findings, benchmarkRunId, username, source, "TRACE_PROMPT_VERSION",
                "metadata.promptVersion이 비어 있으면 안 된다",
                StringUtils.hasText(text(metadata.get("promptVersion"))),
                "metadata.promptVersion=" + text(metadata.get("promptVersion")));
        passed += required(findings, benchmarkRunId, username, source, "TRACE_PROMPT_HASH",
                "metadata.promptHash가 비어 있으면 안 된다",
                StringUtils.hasText(text(metadata.get("promptHash"))),
                "metadata.promptHash=" + text(metadata.get("promptHash")));
        passed += required(findings, benchmarkRunId, username, source, "TRACE_SYSTEM_PROMPT_HASH",
                "metadata.systemPromptHash가 비어 있으면 안 된다",
                StringUtils.hasText(text(metadata.get("systemPromptHash"))),
                "metadata.systemPromptHash=" + text(metadata.get("systemPromptHash")));
        passed += required(findings, benchmarkRunId, username, source, "TRACE_USER_PROMPT_HASH",
                "metadata.userPromptHash가 비어 있으면 안 된다",
                StringUtils.hasText(text(metadata.get("userPromptHash"))),
                "metadata.userPromptHash=" + text(metadata.get("userPromptHash")));
        passed += required(findings, benchmarkRunId, username, source, "TRACE_PROMPT_SECTION_SET",
                "metadata.promptSectionSet은 비어 있으면 안 된다",
                !castStringList(metadata.get("promptSectionSet")).isEmpty(),
                "metadata.promptSectionSet=" + metadata.get("promptSectionSet"));
        passed += required(findings, benchmarkRunId, username, source, "TRACE_PROMPT_OMITTED_SECTIONS",
                "metadata.omittedSections는 반드시 존재해야 한다",
                metadata.containsKey("omittedSections"),
                "metadata.omittedSections=" + metadata.get("omittedSections"));
        passed += required(findings, benchmarkRunId, username, source, "TRACE_PROMPT_OMISSION_LEDGER",
                "metadata.omissionLedger는 반드시 존재해야 한다",
                metadata.containsKey("omissionLedger"),
                "metadata.omissionLedger=" + metadata.get("omissionLedger"));
        passed += required(findings, benchmarkRunId, username, source, "TRACE_PROMPT_SECTION_SET_MATCH",
                "metadata.promptSectionSet과 promptExecutionMetadata.sectionSet이 일치해야 한다",
                castStringList(metadata.get("promptSectionSet"))
                        .equals(promptExecutionMetadata != null ? promptExecutionMetadata.sectionSet() : List.of()),
                "metadata.promptSectionSet=" + metadata.get("promptSectionSet")
                        + ", promptExecutionMetadata.sectionSet=" + (promptExecutionMetadata != null ? promptExecutionMetadata.sectionSet() : null));
        passed += required(findings, benchmarkRunId, username, source, "TRACE_PROMPT_OMITTED_SECTIONS_MATCH",
                "metadata.omittedSections와 promptExecutionMetadata.omittedSections가 일치해야 한다",
                castStringList(metadata.get("omittedSections"))
                        .equals(promptExecutionMetadata != null ? promptExecutionMetadata.omittedSections() : List.of()),
                "metadata.omittedSections=" + metadata.get("omittedSections")
                        + ", promptExecutionMetadata.omittedSections=" + (promptExecutionMetadata != null ? promptExecutionMetadata.omittedSections() : null));
        passed += required(findings, benchmarkRunId, username, source, "TRACE_GOVERNANCE_TEMPLATE",
                "promptExecutionMetadata.governanceDescriptor.templateKey는 SecurityDecisionStandard여야 한다",
                "SecurityDecisionStandard".equals(governanceTemplateKey(snapshot)),
                "promptExecutionMetadata.governanceDescriptor.templateKey=" + governanceTemplateKey(snapshot));
        passed += required(findings, benchmarkRunId, username, source, "TRACE_EVIDENCE_COMPLETENESS",
                "promptExecutionMetadata.promptEvidenceCompleteness가 비어 있으면 안 된다",
                promptEvidenceCompleteness(snapshot) != null,
                "promptExecutionMetadata.promptEvidenceCompleteness=" + promptEvidenceCompleteness(snapshot));
        passed += required(findings, benchmarkRunId, username, source, "TRACE_EVIDENCE_COMPLETENESS_MATCH",
                "metadata.promptEvidenceCompleteness와 promptExecutionMetadata.promptEvidenceCompleteness가 일치해야 한다",
                text(metadata.get("promptEvidenceCompleteness")).equals(promptEvidenceCompleteness(snapshot)),
                "metadata.promptEvidenceCompleteness=" + text(metadata.get("promptEvidenceCompleteness"))
                        + ", promptExecutionMetadata.promptEvidenceCompleteness=" + promptEvidenceCompleteness(snapshot));
        passed += required(findings, benchmarkRunId, username, source, "TRACE_PROMPT_LENGTH_FIELDS",
                "prompt 길이 메타데이터가 비어 있으면 안 된다",
                metadata.containsKey("systemPromptLength")
                        && metadata.containsKey("userPromptLength")
                        && metadata.containsKey("totalPromptLength"),
                "metadata.lengths=[system=" + metadata.get("systemPromptLength")
                        + ", user=" + metadata.get("userPromptLength")
                        + ", total=" + metadata.get("totalPromptLength") + "]");

        return new SandboxPromptTraceContractAssessment(source, ratio(passed, total), findings);
    }

    private static int required(
            List<SandboxPromptDefectFinding> findings,
            String benchmarkRunId,
            String username,
            String source,
            String code,
            String summary,
            boolean passed,
            String detail) {
        if (!passed) {
            findings.add(new SandboxPromptDefectFinding(
                    benchmarkRunId,
                    username,
                    source,
                    code,
                    SandboxPromptDefectCategory.IMPLEMENTATION_DEFECT,
                    summary,
                    detail));
            return 0;
        }
        return 1;
    }

    private static double ratio(int passed, int total) {
        return total <= 0 ? 0.0d : (passed * 100.0d) / total;
    }

    private static Map<String, Object> eventMetadata(SandboxPromptTraceSnapshot snapshot) {
        SecurityEvent event = snapshot != null ? snapshot.event() : null;
        Map<String, Object> metadata = event != null && event.getMetadata() != null
                ? event.getMetadata()
                : Map.of();
        return new LinkedHashMap<>(metadata);
    }

    private static Map<String, Object> metadata(SandboxPromptTraceSnapshot snapshot) {
        return snapshot != null && snapshot.metadata() != null
                ? new LinkedHashMap<>(snapshot.metadata())
                : Map.of();
    }

    private static String governanceTemplateKey(SandboxPromptTraceSnapshot snapshot) {
        PromptExecutionMetadata promptExecutionMetadata = snapshot != null ? snapshot.promptExecutionMetadata() : null;
        PromptGovernanceDescriptor governanceDescriptor =
                promptExecutionMetadata != null ? promptExecutionMetadata.governanceDescriptor() : null;
        return governanceDescriptor != null ? governanceDescriptor.templateKey() : null;
    }

    private static String promptEvidenceCompleteness(SandboxPromptTraceSnapshot snapshot) {
        PromptExecutionMetadata promptExecutionMetadata = snapshot != null ? snapshot.promptExecutionMetadata() : null;
        return promptExecutionMetadata != null && promptExecutionMetadata.promptEvidenceCompleteness() != null
                ? promptExecutionMetadata.promptEvidenceCompleteness().name()
                : null;
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

    private static String text(Object value) {
        return value == null ? null : String.valueOf(value);
    }
}
