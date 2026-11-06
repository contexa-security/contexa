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
import io.contexa.contexacommon.store.ApplicationNamespace;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.UUID;
import java.util.HashMap;
import java.util.LinkedHashMap;
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

    /** When the event happened: the request's observed time, else the time it was raised. */
    @Builder.Default
    private Instant timestamp = Instant.now();

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

    /** The event time as a wall-clock time in the company time zone, for its hour, minute and day. */
    public LocalDateTime getLocalTimestamp() {
        return EventTimeZone.toLocal(timestamp);
    }

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

    /**
     * A copy of the event with a metadata map of its own, for work handed to another thread (QF-55): what that work
     * writes on the copy never reaches this event, and what is written on this event afterwards never reaches the copy.
     * The entries keep their order and a synchronized map is read under its lock; the values themselves are shared.
     */
    public SecurityEvent detachedCopy() {
        Map<String, Object> current = metadata;
        Map<String, Object> copied = null;
        if (current != null) {
            synchronized (current) {
                copied = new LinkedHashMap<>(current);
            }
        }
        return SecurityEvent.builder()
                .eventId(eventId)
                .source(source)
                .timestamp(timestamp)
                .severity(severity)
                .description(description)
                .sourceIp(sourceIp)
                .userId(userId)
                .userName(userName)
                .sessionId(sessionId)
                .userAgent(userAgent)
                .metadata(copied)
                .blocked(blocked)
                .build();
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
        return ApplicationNamespace.key("security:user:context:" + userId);
    }

    public String getSessionMappingKey() {
        if (sessionId == null || sessionId.trim().isEmpty()) {
            return null;
        }
        return ApplicationNamespace.key("security:session:user:" + sessionId);
    }
}
