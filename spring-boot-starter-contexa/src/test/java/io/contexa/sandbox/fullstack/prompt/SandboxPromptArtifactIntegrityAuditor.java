package io.contexa.sandbox.fullstack.prompt;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import org.springframework.ai.document.Document;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * relatedDocuments의 text/metadata/current event를 함께 비교하는 무결성 감사기.
 *
 * 목적:
 * - vector memory 문서가 자기 자신과 모순되는지 잡아낸다.
 * - retrieval은 됐지만 저장된 artifact가 틀린 경우를 별도 결함으로 남긴다.
 */
public final class SandboxPromptArtifactIntegrityAuditor {

    private SandboxPromptArtifactIntegrityAuditor() {
    }

    public static SandboxPromptArtifactIntegrityAssessment audit(
            String benchmarkRunId,
            String username,
            String source,
            SecurityEvent currentEvent,
            List<Document> relatedDocuments) {
        if (relatedDocuments == null || relatedDocuments.isEmpty()) {
            return new SandboxPromptArtifactIntegrityAssessment(100.0d, List.of());
        }

        List<SandboxPromptDefectFinding> findings = new ArrayList<>();
        int total = 0;
        int passed = 0;
        String expectedUserId = currentEvent != null ? currentEvent.getUserId() : username;
        for (int index = 0; index < relatedDocuments.size(); index++) {
            Document document = relatedDocuments.get(index);
            if (document == null) {
                continue;
            }
            String documentSource = source + "#relatedDocument[" + index + "]";
            String text = document.getText();
            Map<String, Object> metadata = document.getMetadata() != null ? document.getMetadata() : Map.of();

            total += 1;
            passed += check(
                    benchmarkRunId,
                    username,
                    documentSource,
                    findings,
                    "DOCUMENT_TYPE_PRESENT",
                    StringUtils.hasText(text(metadata.get("documentType"))),
                    "document.metadata.documentType=" + text(metadata.get("documentType")));

            total += 1;
            passed += check(
                    benchmarkRunId,
                    username,
                    documentSource,
                    findings,
                    "USER_ID_PRESENT_AND_MATCHED",
                    StringUtils.hasText(text(metadata.get("userId")))
                            && safeEquals(expectedUserId, text(metadata.get("userId"))),
                    "expectedUserId=" + expectedUserId + ", document.userId=" + text(metadata.get("userId")));

            total += 1;
            passed += check(
                    benchmarkRunId,
                    username,
                    documentSource,
                    findings,
                    "RETRIEVAL_PURPOSE_PRESENT",
                    "security_investigation".equals(text(metadata.get("retrievalPurpose"))),
                    "document.retrievalPurpose=" + text(metadata.get("retrievalPurpose")));

            total += 1;
            passed += check(
                    benchmarkRunId,
                    username,
                    documentSource,
                    findings,
                    "REQUEST_PATH_PRESENT_AND_TEXT_MATCHED",
                    StringUtils.hasText(text(metadata.get("requestPath")))
                            && contains(text, text(metadata.get("requestPath"))),
                    "currentEvent.requestPath=" + extractEventMetadata(currentEvent, "requestPath")
                            + ", document.requestPath=" + text(metadata.get("requestPath")));

            total += 1;
            passed += check(
                    benchmarkRunId,
                    username,
                    documentSource,
                    findings,
                    "PROPOSED_ACTION_TEXT_MATCH",
                    matchesDecisionText(text, "proposedAction", text(metadata.get("proposedAction"))),
                    "document.proposedAction=" + text(metadata.get("proposedAction")) + ", text=" + abbreviate(text));

            total += 1;
            passed += check(
                    benchmarkRunId,
                    username,
                    documentSource,
                    findings,
                    "AUTONOMOUS_ACTION_TEXT_MATCH",
                    matchesDecisionText(text, "autonomousAction", text(metadata.get("autonomousAction"))),
                    "document.autonomousAction=" + text(metadata.get("autonomousAction")) + ", text=" + abbreviate(text));

            total += 1;
            passed += check(
                    benchmarkRunId,
                    username,
                    documentSource,
                    findings,
                    "RISK_SCORE_TEXT_MATCH",
                    matchesNumericDecisionText(text, "riskScore", metadata.get("riskScore")),
                    "document.riskScore=" + metadata.get("riskScore") + ", text=" + abbreviate(text));

            total += 1;
            passed += check(
                    benchmarkRunId,
                    username,
                    documentSource,
                    findings,
                    "CONFIDENCE_TEXT_MATCH",
                    matchesNumericDecisionText(text, "confidence", metadata.get("confidence")),
                    "document.confidence=" + metadata.get("confidence") + ", text=" + abbreviate(text));

            Object auditRisk = metadata.get("llmAuditRiskScore");
            if (auditRisk != null) {
                total += 1;
                passed += check(
                        benchmarkRunId,
                        username,
                        documentSource,
                        findings,
                        "LLM_AUDIT_RISK_SCORE_TEXT_MATCH",
                        matchesNumericDecisionText(text, "llmAuditRiskScore", auditRisk),
                        "document.llmAuditRiskScore=" + auditRisk + ", text=" + abbreviate(text));
            }

            Object auditConfidence = metadata.get("llmAuditConfidence");
            if (auditConfidence != null) {
                total += 1;
                passed += check(
                        benchmarkRunId,
                        username,
                        documentSource,
                        findings,
                        "LLM_AUDIT_CONFIDENCE_TEXT_MATCH",
                        matchesNumericDecisionText(text, "llmAuditConfidence", auditConfidence),
                        "document.llmAuditConfidence=" + auditConfidence + ", text=" + abbreviate(text));
            }
        }

        double integrityRate = total <= 0 ? 100.0d : (passed * 100.0d) / total;
        return new SandboxPromptArtifactIntegrityAssessment(integrityRate, findings);
    }

    private static int check(
            String benchmarkRunId,
            String username,
            String source,
            List<SandboxPromptDefectFinding> findings,
            String code,
            boolean passed,
            String detail) {
        if (!passed) {
            findings.add(SandboxPromptDefectClassifier.classifyArtifactMismatch(
                    benchmarkRunId,
                    username,
                    source,
                    code,
                    code.replace('_', ' '),
                    detail));
        }
        return passed ? 1 : 0;
    }

    private static boolean matchesDecisionText(String text, String key, String expectedValue) {
        if (!StringUtils.hasText(expectedValue)) {
            return true;
        }
        return contains(text, key + "=" + expectedValue);
    }

    private static boolean matchesNumericDecisionText(String text, String key, Object value) {
        Double numeric = asDouble(value);
        if (numeric == null) {
            return !StringUtils.hasText(text) || !text.contains(key + "=");
        }
        if (numeric < 0.0d) {
            return contains(text, key + "=N/A");
        }
        return contains(text, key + "=" + String.format(Locale.ROOT, "%.2f", numeric));
    }

    private static Double asDouble(Object value) {
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        if (value instanceof String text && !text.isBlank()) {
            try {
                return Double.parseDouble(text.trim());
            } catch (NumberFormatException ignored) {
                return null;
            }
        }
        return null;
    }

    private static String extractEventMetadata(SecurityEvent event, String key) {
        if (event == null || event.getMetadata() == null || !event.getMetadata().containsKey(key)) {
            return null;
        }
        return text(event.getMetadata().get(key));
    }

    private static boolean contains(String text, String expected) {
        return StringUtils.hasText(text) && StringUtils.hasText(expected) && text.contains(expected);
    }

    private static String abbreviate(String text) {
        if (!StringUtils.hasText(text)) {
            return null;
        }
        return text.length() > 220 ? text.substring(0, 220) + "..." : text;
    }

    private static boolean safeEquals(String expected, String actual) {
        return expected == null ? actual == null : expected.equals(actual);
    }

    private static String text(Object value) {
        return value == null ? null : String.valueOf(value);
    }
}
