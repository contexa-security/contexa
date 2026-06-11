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
package io.contexa.contexacore.autonomous.audit;

import io.contexa.contexacommon.entity.AuditLog;
import io.contexa.contexacommon.enums.AuditEventCategory;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * Immutable audit record DTO based on 5W1H principle.
 * Who, When, Where, What, How, Why - all captured in a single record.
 */
@Getter
@Builder
public class AuditRecord {

    private final String principalName;
    private final String eventSource;

    @Builder.Default
    private final LocalDateTime timestamp = LocalDateTime.now();

    private final String clientIp;
    private final String sessionId;
    private final String userAgent;

    private final String resourceIdentifier;
    private final String resourceUri;
    private final String requestUri;

    private final String action;
    private final String httpMethod;
    private final AuditEventCategory eventCategory;

    private final String decision;
    private final String reason;
    private final String outcome;
    private final Double riskScore;
    private final Map<String, Object> details;

    private final String correlationId;

    /**
     * Convert this record to a persistent AuditLog entity.
     */
    public AuditLog toAuditLog(String detailsJson) {
        return AuditLog.builder()
                .timestamp(timestamp)
                .principalName(principalName != null ? principalName : "UNKNOWN")
                .resourceIdentifier(resourceIdentifier != null ? resourceIdentifier : "UNKNOWN")
                .action(action)
                .decision(decision != null ? decision : "UNKNOWN")
                .reason(truncate(reason, 1024))
                .outcome(outcome)
                .resourceUri(resourceUri)
                .clientIp(clientIp)
                .sessionId(sessionId)
                .details(detailsJson)
                .eventCategory(eventCategory != null ? eventCategory.name() : null)
                .userAgent(truncate(userAgent, 512))
                .httpMethod(httpMethod)
                .requestUri(truncate(requestUri, 2048))
                .riskScore(riskScore)
                .eventSource(eventSource)
                .correlationId(correlationId)
                .build();
    }

    private static String truncate(String value, int maxLength) {
        if (value == null) {
            return null;
        }
        return value.length() <= maxLength ? value : value.substring(0, maxLength);
    }
}
