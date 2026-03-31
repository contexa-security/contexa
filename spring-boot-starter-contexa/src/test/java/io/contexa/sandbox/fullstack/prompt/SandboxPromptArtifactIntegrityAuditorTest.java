package io.contexa.sandbox.fullstack.prompt;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.ai.document.Document;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SandboxPromptArtifactIntegrityAuditorTest {

    @Test
    @DisplayName("메모리 문서 text와 metadata가 같은 사실을 말하면 무결성 점수는 100이어야 한다")
    void shouldReturnPerfectIntegrityWhenDocumentTextMatchesMetadata() {
        SecurityEvent event = SecurityEvent.builder()
                .userId("alice@example.com")
                .build();
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");

        Document document = new Document(
                "User accessed /admin/api/security-test/sensitive/resource-001 via GET from 192.168.1.100 using Chrome/120 on Windows at 11:30 (Mon)\n"
                        + "Decision: proposedAction=ALLOW, autonomousAction=ALLOW, riskScore=0.10, confidence=0.70, llmAuditRiskScore=0.10, llmAuditConfidence=0.70, analysisLayer=1\n",
                Map.of(
                        "documentType", "behavior",
                        "userId", "alice@example.com",
                        "retrievalPurpose", "security_investigation",
                        "requestPath", "/admin/api/security-test/sensitive/resource-001",
                        "proposedAction", "ALLOW",
                        "autonomousAction", "ALLOW",
                        "riskScore", 0.10,
                        "confidence", 0.70,
                        "llmAuditRiskScore", 0.10,
                        "llmAuditConfidence", 0.70
                ));

        SandboxPromptArtifactIntegrityAssessment assessment = SandboxPromptArtifactIntegrityAuditor.audit(
                "benchmark-run-1",
                "alice@example.com",
                "2차 relatedDocuments",
                event,
                List.of(document));

        assertThat(assessment.integrityRate()).isEqualTo(100.0d);
        assertThat(assessment.findings()).isEmpty();
    }

    @Test
    @DisplayName("메모리 문서 text와 metadata가 서로 다르면 데이터 품질 결함으로 분류되어야 한다")
    void shouldEmitDataQualityDefectWhenDocumentTextContradictsMetadata() {
        SecurityEvent event = SecurityEvent.builder()
                .userId("alice@example.com")
                .timestamp(LocalDateTime.now())
                .build();
        event.addMetadata("requestPath", "/admin/api/security-test/sensitive/resource-001");

        Document document = new Document(
                "User accessed /admin/api/security-test/sensitive/resource-001 via GET from 192.168.1.100 using Chrome/120 on Windows at 11:30 (Mon)\n"
                        + "Decision: proposedAction=ALLOW, autonomousAction=ALLOW, riskScore=N/A, confidence=0.70, llmAuditConfidence=0.70, analysisLayer=1\n",
                Map.of(
                        "documentType", "behavior",
                        "userId", "alice@example.com",
                        "retrievalPurpose", "security_investigation",
                        "requestPath", "/admin/api/security-test/sensitive/resource-001",
                        "proposedAction", "ALLOW",
                        "autonomousAction", "ALLOW",
                        "riskScore", 0.10,
                        "confidence", 0.70,
                        "llmAuditRiskScore", 0.10,
                        "llmAuditConfidence", 0.70
                ));

        SandboxPromptArtifactIntegrityAssessment assessment = SandboxPromptArtifactIntegrityAuditor.audit(
                "benchmark-run-1",
                "alice@example.com",
                "2차 relatedDocuments",
                event,
                List.of(document));

        assertThat(assessment.integrityRate()).isLessThan(100.0d);
        assertThat(assessment.findings()).isNotEmpty();
        assertThat(assessment.findings())
                .allMatch(finding -> finding.category() == SandboxPromptDefectCategory.DATA_QUALITY_DEFECT);
        assertThat(assessment.findings())
                .anyMatch(finding -> "RISK_SCORE_TEXT_MATCH".equals(finding.code()));
    }
}
