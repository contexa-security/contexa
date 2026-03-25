package io.contexa.contexacore.autonomous.saas.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PromptContextAuditPayload {

    private String auditId;
    private String correlationId;
    private String tenantExternalRef;
    private String executionId;
    private String retrievalPurpose;
    private String contextFingerprint;
    private int requestedDocumentCount;
    private int allowedDocumentCount;
    private int deniedDocumentCount;
    private List<String> deniedReasons;
    private List<ContextItem> contexts;
    private LocalDateTime forwardedAt;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ContextItem {

        private String contextType;
        private String sourceType;
        private String artifactId;
        private String artifactVersion;
        private String authorizationDecision;
        private boolean purposeMatch;
        private String provenanceSummary;
        private boolean includedInPrompt;
        private String promptSafetyDecision;
        private String memoryReadDecision;
        private String accessScope;
        private boolean tenantBound;
        private Double similarityScore;
    }
}
