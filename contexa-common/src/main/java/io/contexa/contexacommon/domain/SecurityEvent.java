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
package io.contexa.contexacommon.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import io.contexa.contexacommon.enums.ZeroTrustAction;

import java.time.LocalDateTime;
import java.util.UUID;
import java.util.HashMap;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityEvent {

    @Builder.Default
    private String eventId = UUID.randomUUID().toString();

    @Builder.Default
    private EventSource source = EventSource.UNKNOWN;

    @Builder.Default
    private LocalDateTime timestamp = LocalDateTime.now();

    @Builder.Default
    private Severity severity = Severity.MEDIUM;

    @Builder.Default
    private String description = "Security event";

    private String sourceIp;

    private String userId;
    private String userName;
    private String sessionId;
    private String userAgent;

    @Builder.Default
    private Map<String, Object> metadata = new HashMap<>();

    private boolean blocked;

    public enum EventSource {
        IDS("Intrusion Detection System"),
        IPS("Intrusion Prevention System"),
        SIEM("Security Information and Event Management"),
        FIREWALL("Firewall"),
        WAF("Web Application Firewall"),
        ENDPOINT("Endpoint Protection"),
        IAM("Identity and Access Management"),
        MANUAL("Manual Entry"),
        THREAT_INTEL("Threat Intelligence"),
        KAFKA("Kafka Stream"),
        REDIS("Redis Stream"),
        API("API Gateway"),
        UNKNOWN("Unknown Source");

        private final String description;

        EventSource(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }

    public enum Severity {
        CRITICAL("Critical", 10),
        HIGH("High", 8),
        MEDIUM("Medium", 5),
        LOW("Low", 3),
        INFO("Info", 1);

        private final String displayName;
        private final int score;

        Severity(String displayName, int score) {
            this.displayName = displayName;
            this.score = score;
        }

        public String getDisplayName() {
            return displayName;
        }

        public int getScore() {
            return score;
        }
    }

    public void addMetadata(String key, Object value) {
        if (this.metadata == null) {
            this.metadata = new HashMap<>();
        }
        this.metadata.put(key, value);
    }

    public void addMetadata(String key, String value) {
        addMetadata(key, (Object) value);
    }

    public boolean isHighRiskByAction(ZeroTrustAction action) {
        return action == ZeroTrustAction.BLOCK ||
               action == ZeroTrustAction.ESCALATE;
    }

    public boolean isBlockable() {
        return !blocked;
    }

    public boolean hasUserId() {
        return userId != null && !userId.trim().isEmpty();
    }

    public String getUserContextKey() {
        if (!hasUserId()) {
            throw new IllegalStateException("UserId is required for Zero Trust context");
        }
        return "security:user:context:" + userId;
    }

    public String getSessionMappingKey() {
        if (sessionId == null || sessionId.trim().isEmpty()) {
            return null;
        }
        return "security:session:user:" + sessionId;
    }
}
