/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.contexa.contexacore.autonomous.saas.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

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
    private String promptKey;
    private String templateKey;
    private String promptVersion;
    private String promptHash;
    private String systemPromptHash;
    private String userPromptHash;
    private String systemPrompt;
    private String userPrompt;
    private String resourceId;
    private String requestPath;
    private Boolean promptRuntimeTelemetryLinked;
    private String promptRuntimeTelemetryLayer;
    private Map<String, Object> promptRuntimeTelemetry;
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
        private String userId;
        private String retrievalPurpose;
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
