package io.contexa.contexacore.autonomous.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.repository.AuditLogRepository;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.security.processor.ProcessingResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class SecurityPlaneAuditLoggerTest {

    @Mock
    private AuditLogRepository auditLogRepository;

    @Test
    void auditSecurityDecisionPersistsLlmAuditScoresInDetails() {
        SecurityPlaneAuditLogger logger = new SecurityPlaneAuditLogger(auditLogRepository, new ObjectMapper());
        SecurityEvent event = SecurityEvent.builder()
                .eventId("event-1")
                .userId("alice")
                .sessionId("session-1")
                .sourceIp("203.0.113.10")
                .timestamp(LocalDateTime.of(2026, 3, 23, 12, 40))
                .build();
        ProcessingResult result = ProcessingResult.builder()
                .success(true)
                .action("BLOCK")
                .reasoning("Suspicious delegated action")
                .aiAnalysisLevel(2)
                .llmAuditRiskScore(0.91)
                .llmAuditConfidence(0.87)
                .build();

        logger.auditSecurityDecision(event, result, 128L);

        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogRepository).save(captor.capture());
        AuditLog saved = captor.getValue();
        assertThat(saved.getDetails()).contains("\"llmAuditRiskScore\":0.91");
        assertThat(saved.getDetails()).contains("\"llmAuditConfidence\":0.87");
    }
}
