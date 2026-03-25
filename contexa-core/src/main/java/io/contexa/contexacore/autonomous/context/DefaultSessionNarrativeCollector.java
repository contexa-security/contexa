package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.store.SecurityContextDataStore;
import org.springframework.util.StringUtils;

import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.StringJoiner;

public class DefaultSessionNarrativeCollector implements SessionNarrativeCollector {

    private static final int MAX_SEQUENCE_SIZE = 10;
    private static final int BURST_PROTECTABLE_THRESHOLD = 3;
    private static final long BURST_INTERVAL_THRESHOLD_MS = 2_000L;

    private final SecurityContextDataStore dataStore;

    public DefaultSessionNarrativeCollector(SecurityContextDataStore dataStore) {
        this.dataStore = dataStore;
    }

    @Override
    public Optional<SessionNarrativeSnapshot> collect(SecurityEvent event) {
        if (event == null || !StringUtils.hasText(event.getSessionId())) {
            return Optional.empty();
        }

        String sessionId = event.getSessionId().trim();
        long currentTimestamp = resolveTimestamp(event);
        Long sessionStartedAt = dataStore.getSessionStartedAt(sessionId);
        if (sessionStartedAt == null) {
            sessionStartedAt = currentTimestamp;
            dataStore.setSessionStartedAt(sessionId, currentTimestamp);
        }

        Long previousRequestTimestamp = dataStore.getSessionLastRequestTime(sessionId);
        String previousPath = dataStore.getSessionPreviousPath(sessionId);
        String currentPath = resolveRequestPath(event);
        String currentActionFamily = resolveActionFamily(event);
        boolean protectableRequest = isProtectableRequest(event);

        if (StringUtils.hasText(currentActionFamily)) {
            dataStore.addSessionNarrativeActionFamily(sessionId, currentActionFamily);
        }
        if (protectableRequest && StringUtils.hasText(currentPath)) {
            dataStore.addSessionProtectableAccess(sessionId, currentPath);
        }

        Long lastRequestIntervalMs = null;
        if (previousRequestTimestamp != null && currentTimestamp >= previousRequestTimestamp) {
            lastRequestIntervalMs = currentTimestamp - previousRequestTimestamp;
            dataStore.addSessionRequestInterval(sessionId, lastRequestIntervalMs);
        }

        dataStore.setSessionLastRequestTime(sessionId, currentTimestamp);
        if (StringUtils.hasText(currentPath)) {
            dataStore.setSessionPreviousPath(sessionId, currentPath);
        }

        List<String> actionSequence = dataStore.getRecentSessionNarrativeActionFamilies(sessionId, MAX_SEQUENCE_SIZE);
        List<String> protectableSequence = dataStore.getRecentSessionProtectableAccesses(sessionId, MAX_SEQUENCE_SIZE);
        List<Long> recentIntervals = dataStore.getRecentSessionRequestIntervals(sessionId, BURST_PROTECTABLE_THRESHOLD);
        boolean burstPattern = detectBurst(protectableSequence, recentIntervals);
        int sessionAgeMinutes = Math.max(0, (int) ((currentTimestamp - sessionStartedAt) / 60_000L));
        String previousActionFamily = actionSequence.size() >= 2 ? actionSequence.get(actionSequence.size() - 2) : null;

        return Optional.of(SessionNarrativeSnapshot.builder()
                .sessionId(sessionId)
                .sessionAgeMinutes(sessionAgeMinutes)
                .previousPath(previousPath)
                .previousActionFamily(previousActionFamily)
                .lastRequestIntervalMs(lastRequestIntervalMs)
                .sessionActionSequence(actionSequence)
                .sessionProtectableSequence(protectableSequence)
                .burstPattern(burstPattern)
                .summary(buildSummary(sessionAgeMinutes, previousPath, previousActionFamily, lastRequestIntervalMs, actionSequence, burstPattern))
                .build());
    }

    private boolean detectBurst(List<String> protectableSequence, List<Long> recentIntervals) {
        if (protectableSequence == null || protectableSequence.size() < BURST_PROTECTABLE_THRESHOLD) {
            return false;
        }
        if (recentIntervals == null || recentIntervals.size() < BURST_PROTECTABLE_THRESHOLD - 1) {
            return false;
        }
        return recentIntervals.stream()
                .skip(Math.max(0, recentIntervals.size() - (BURST_PROTECTABLE_THRESHOLD - 1)))
                .allMatch(interval -> interval != null && interval <= BURST_INTERVAL_THRESHOLD_MS);
    }

    private String buildSummary(int sessionAgeMinutes,
                                String previousPath,
                                String previousActionFamily,
                                Long lastRequestIntervalMs,
                                List<String> actionSequence,
                                boolean burstPattern) {
        StringJoiner joiner = new StringJoiner(" | ");
        joiner.add("Session age " + sessionAgeMinutes + "m");
        if (StringUtils.hasText(previousPath)) {
            joiner.add("Previous path " + previousPath);
        }
        if (StringUtils.hasText(previousActionFamily)) {
            joiner.add("Previous action " + previousActionFamily);
        }
        if (lastRequestIntervalMs != null) {
            joiner.add("Inter-request gap " + lastRequestIntervalMs + "ms");
        }
        if (actionSequence != null && !actionSequence.isEmpty()) {
            joiner.add("Recent actions " + String.join(" -> ", actionSequence));
        }
        if (burstPattern) {
            joiner.add("Burst pacing detected");
        }
        return joiner.toString();
    }

    private long resolveTimestamp(SecurityEvent event) {
        if (event.getTimestamp() != null) {
            return event.getTimestamp().atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
        }
        return System.currentTimeMillis();
    }

    private String resolveRequestPath(SecurityEvent event) {
        Map<String, Object> metadata = event.getMetadata();
        if (metadata == null || metadata.isEmpty()) {
            return null;
        }
        Object requestPath = metadata.get("requestPath");
        if (requestPath == null) {
            requestPath = metadata.get("targetResource");
        }
        if (requestPath == null) {
            requestPath = metadata.get("protectableResource");
        }
        if (requestPath == null) {
            return null;
        }
        String normalized = requestPath.toString().trim();
        return StringUtils.hasText(normalized) ? normalized : null;
    }

    private String resolveActionFamily(SecurityEvent event) {
        Map<String, Object> metadata = event.getMetadata();
        if (metadata != null && !metadata.isEmpty()) {
            Object explicitAction = metadata.get("actionFamily");
            if (explicitAction == null) {
                explicitAction = metadata.get("operation");
            }
            if (explicitAction != null && StringUtils.hasText(explicitAction.toString())) {
                return explicitAction.toString().trim().toUpperCase();
            }
            Object httpMethod = metadata.get("httpMethod");
            if (httpMethod != null && StringUtils.hasText(httpMethod.toString())) {
                return switch (httpMethod.toString().trim().toUpperCase()) {
                    case "GET", "HEAD" -> "READ";
                    case "POST" -> "CREATE";
                    case "PUT", "PATCH" -> "UPDATE";
                    case "DELETE" -> "DELETE";
                    default -> "UNKNOWN";
                };
            }
        }
        return StringUtils.hasText(event.getDescription()) ? event.getDescription().trim().toUpperCase() : "UNKNOWN";
    }

    private boolean isProtectableRequest(SecurityEvent event) {
        Map<String, Object> metadata = event.getMetadata();
        if (metadata == null || metadata.isEmpty()) {
            return false;
        }

        Boolean explicitFlag = resolveBoolean(
                metadata.get("isProtectable"),
                metadata.get("protectable"),
                metadata.get("protectableRequest"));
        if (explicitFlag != null) {
            return explicitFlag;
        }

        if (metadata.get("protectableResource") != null) {
            return true;
        }

        if (metadata.containsKey("granted")
                && (metadata.containsKey("className") || metadata.containsKey("methodName"))) {
            return true;
        }

        return Boolean.TRUE.equals(resolveBoolean(
                metadata.get("isSensitiveResource"),
                metadata.get("privileged"),
                metadata.get("exportSensitive")));
    }

    private Boolean resolveBoolean(Object... candidates) {
        if (candidates == null) {
            return null;
        }
        for (Object candidate : candidates) {
            if (candidate == null) {
                continue;
            }
            if (candidate instanceof Boolean booleanValue) {
                return booleanValue;
            }
            String text = candidate.toString().trim();
            if (!StringUtils.hasText(text)) {
                continue;
            }
            if ("true".equalsIgnoreCase(text) || "false".equalsIgnoreCase(text)) {
                return Boolean.parseBoolean(text);
            }
        }
        return null;
    }
}
