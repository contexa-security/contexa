package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.domain.AuthorizationDecisionEvent;
import org.springframework.util.StringUtils;

import java.util.*;
import java.util.stream.Collectors;

public class MetadataObservedScopeInferenceService implements ObservedScopeInferenceService {

    private static final int TOP_LIMIT = 3;

    @Override
    public Optional<CanonicalSecurityContext.ObservedScope> infer(SecurityEvent event, CanonicalSecurityContext context) {
        if (event == null) {
            return Optional.empty();
        }

        Map<String, Object> metadata = event.getMetadata() != null ? event.getMetadata() : Map.of();
        List<ObservedAccessRecord> history = extractHistory(metadata);

        Integer accessCount = resolveInteger(metadata.get("protectableAccessCount"));
        if (accessCount == null && !history.isEmpty()) {
            accessCount = history.size();
        }

        Integer deniedCount = resolveInteger(metadata.get("recentDeniedAccessCount"), metadata.get("recentAccessDeniedCount"));
        if (deniedCount == null && !history.isEmpty()) {
            deniedCount = (int) history.stream().filter(ObservedAccessRecord::denied).count();
        }

        Integer sensitiveAccessCount = resolveInteger(metadata.get("recentSensitiveAccessCount"), metadata.get("recentSensitiveResourceCount"));
        if (sensitiveAccessCount == null && !history.isEmpty()) {
            sensitiveAccessCount = (int) history.stream().filter(ObservedAccessRecord::sensitive).count();
        }

        List<String> frequentResources = resolveStringList(
                metadata.get("frequentResources"),
                metadata.get("observedResources"),
                metadata.get("topResources"));
        if (frequentResources.isEmpty() && !history.isEmpty()) {
            frequentResources = topValues(history.stream()
                    .map(ObservedAccessRecord::resourceId)
                    .filter(StringUtils::hasText)
                    .toList());
        }

        List<String> frequentActionFamilies = resolveStringList(
                metadata.get("frequentActionFamilies"),
                metadata.get("observedActionFamilies"),
                metadata.get("topActionFamilies"));
        if (frequentActionFamilies.isEmpty() && !history.isEmpty()) {
            frequentActionFamilies = topValues(history.stream()
                    .map(ObservedAccessRecord::actionFamily)
                    .filter(StringUtils::hasText)
                    .toList());
        }

        String currentResource = extractCurrentResource(context, metadata);
        String currentActionFamily = extractCurrentActionFamily(context, metadata);
        Boolean rareCurrentResource = inferRareCurrentResource(frequentResources, currentResource, accessCount);
        Boolean rareCurrentActionFamily = inferRareCurrentActionFamily(frequentActionFamilies, currentActionFamily, accessCount);

        if (accessCount == null
                && deniedCount == null
                && sensitiveAccessCount == null
                && frequentResources.isEmpty()
                && frequentActionFamilies.isEmpty()
                && rareCurrentResource == null
                && rareCurrentActionFamily == null) {
            return Optional.empty();
        }

        String summary = buildSummary(accessCount, deniedCount, sensitiveAccessCount, rareCurrentResource, rareCurrentActionFamily);

        return Optional.of(CanonicalSecurityContext.ObservedScope.builder()
                .profileSource(!history.isEmpty() ? "PROTECTABLE_ACCESS_HISTORY" : "EVENT_METADATA")
                .summary(summary)
                .recentProtectableAccessCount(accessCount)
                .recentDeniedAccessCount(deniedCount)
                .recentSensitiveAccessCount(sensitiveAccessCount)
                .frequentResources(frequentResources)
                .frequentActionFamilies(frequentActionFamilies)
                .rareCurrentResource(rareCurrentResource)
                .rareCurrentActionFamily(rareCurrentActionFamily)
                .build());
    }

    private List<ObservedAccessRecord> extractHistory(Map<String, Object> metadata) {
        Object rawHistory = firstNonNull(
                metadata.get("protectableAccessHistory"),
                metadata.get("observedProtectableAccessHistory"),
                metadata.get("authorizationHistory"));
        if (!(rawHistory instanceof Collection<?> collection) || collection.isEmpty()) {
            return List.of();
        }

        List<ObservedAccessRecord> records = new ArrayList<>();
        for (Object item : collection) {
            ObservedAccessRecord record = toObservedAccessRecord(item);
            if (record != null) {
                records.add(record);
            }
        }
        return List.copyOf(records);
    }

    private ObservedAccessRecord toObservedAccessRecord(Object raw) {
        if (raw instanceof AuthorizationDecisionEvent event) {
            String resourceId = firstText(event.getResource(), extractMetadata(event.getMetadata(), "resourceId", "requestPath"));
            String actionFamily = firstText(event.getAction(), event.getHttpMethod());
            boolean sensitive = resolveBoolean(extractMetadata(event.getMetadata(), "isSensitiveResource", "sensitiveResource", "resourceSensitive"));
            boolean denied = event.getResult() == AuthorizationDecisionEvent.AuthorizationResult.DENIED;
            return new ObservedAccessRecord(resourceId, normalizeActionFamily(actionFamily), sensitive, denied);
        }
        if (raw instanceof Map<?, ?> rawMap) {
            Map<String, Object> map = new LinkedHashMap<>();
            rawMap.forEach((key, value) -> map.put(String.valueOf(key), value));
            String resourceId = firstText(map.get("resourceId"), map.get("resource"), map.get("requestPath"), map.get("httpUri"));
            String actionFamily = firstText(map.get("actionFamily"), map.get("action"), map.get("httpMethod"), map.get("method"));
            boolean sensitive = resolveBoolean(firstNonNull(map.get("isSensitiveResource"), map.get("sensitiveResource"), map.get("resourceSensitive")));
            boolean denied = "DENIED".equalsIgnoreCase(firstText(map.get("result"), map.get("authorizationResult")));
            return new ObservedAccessRecord(resourceId, normalizeActionFamily(actionFamily), sensitive, denied);
        }
        return null;
    }

    private String extractCurrentResource(CanonicalSecurityContext context, Map<String, Object> metadata) {
        if (context != null && context.getResource() != null) {
            return firstText(context.getResource().getResourceId(), context.getResource().getRequestPath());
        }
        return firstText(metadata.get("resourceId"), metadata.get("requestPath"), metadata.get("httpUri"));
    }

    private String extractCurrentActionFamily(CanonicalSecurityContext context, Map<String, Object> metadata) {
        if (context != null && context.getResource() != null) {
            return normalizeActionFamily(firstText(context.getResource().getActionFamily(), context.getResource().getHttpMethod()));
        }
        return normalizeActionFamily(firstText(metadata.get("actionFamily"), metadata.get("httpMethod"), metadata.get("method")));
    }

    private Boolean inferRareCurrentResource(List<String> frequentResources, String currentResource, Integer accessCount) {
        if (!StringUtils.hasText(currentResource) || accessCount == null || accessCount < 3 || frequentResources.isEmpty()) {
            return null;
        }
        return frequentResources.stream().noneMatch(currentResource::equalsIgnoreCase);
    }

    private Boolean inferRareCurrentActionFamily(List<String> frequentActionFamilies, String currentActionFamily, Integer accessCount) {
        if (!StringUtils.hasText(currentActionFamily) || accessCount == null || accessCount < 3 || frequentActionFamilies.isEmpty()) {
            return null;
        }
        return frequentActionFamilies.stream().noneMatch(currentActionFamily::equalsIgnoreCase);
    }

    private List<String> topValues(List<String> rawValues) {
        if (rawValues == null || rawValues.isEmpty()) {
            return List.of();
        }
        return rawValues.stream()
                .filter(StringUtils::hasText)
                .collect(Collectors.groupingBy(value -> value, LinkedHashMap::new, Collectors.counting()))
                .entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue(Comparator.reverseOrder()))
                .limit(TOP_LIMIT)
                .map(Map.Entry::getKey)
                .toList();
    }

    private List<String> resolveStringList(Object... rawValues) {
        List<String> values = new ArrayList<>();
        for (Object rawValue : rawValues) {
            if (rawValue == null) {
                continue;
            }
            if (rawValue instanceof Collection<?> collection) {
                for (Object item : collection) {
                    addString(values, item);
                }
                continue;
            }
            if (rawValue.toString().contains(",")) {
                for (String token : rawValue.toString().split(",")) {
                    addString(values, token);
                }
                continue;
            }
            addString(values, rawValue);
        }
        return values.stream().distinct().limit(TOP_LIMIT).toList();
    }

    private void addString(List<String> values, Object rawValue) {
        if (rawValue == null) {
            return;
        }
        String text = rawValue.toString().trim();
        if (!text.isBlank()) {
            values.add(text);
        }
    }

    private Integer resolveInteger(Object... values) {
        for (Object value : values) {
            if (value instanceof Number number) {
                return number.intValue();
            }
            if (value instanceof String stringValue && !stringValue.isBlank()) {
                try {
                    return Integer.parseInt(stringValue.trim());
                } catch (NumberFormatException ignored) {
                    return null;
                }
            }
        }
        return null;
    }

    private boolean resolveBoolean(Object value) {
        if (value instanceof Boolean booleanValue) {
            return booleanValue;
        }
        if (value instanceof String stringValue && !stringValue.isBlank()) {
            return Boolean.parseBoolean(stringValue);
        }
        return false;
    }

    private String extractMetadata(Map<String, Object> metadata, String... keys) {
        if (metadata == null || metadata.isEmpty()) {
            return null;
        }
        for (String key : keys) {
            Object value = metadata.get(key);
            if (value != null && StringUtils.hasText(value.toString())) {
                return value.toString();
            }
        }
        return null;
    }

    private Object firstNonNull(Object... values) {
        for (Object value : values) {
            if (value != null) {
                return value;
            }
        }
        return null;
    }

    private String firstText(Object... values) {
        for (Object value : values) {
            if (value == null) {
                continue;
            }
            String text = value.toString();
            if (!text.isBlank()) {
                return text;
            }
        }
        return null;
    }

    private String normalizeActionFamily(String actionFamily) {
        if (!StringUtils.hasText(actionFamily)) {
            return null;
        }
        String normalized = actionFamily.trim().toUpperCase(Locale.ROOT);
        return switch (normalized) {
            case "GET", "HEAD", "READ" -> "READ";
            case "POST", "CREATE" -> "CREATE";
            case "PUT", "PATCH", "UPDATE", "WRITE" -> "UPDATE";
            case "DELETE", "REMOVE" -> "DELETE";
            case "EXPORT", "DOWNLOAD" -> "EXPORT";
            case "APPROVE" -> "APPROVE";
            default -> normalized;
        };
    }

    private String buildSummary(
            Integer accessCount,
            Integer deniedCount,
            Integer sensitiveAccessCount,
            Boolean rareCurrentResource,
            Boolean rareCurrentActionFamily) {
        List<String> clauses = new ArrayList<>();
        if (accessCount != null) {
            clauses.add("Observed protectable history count is " + accessCount + ".");
        }
        if (deniedCount != null && deniedCount > 0) {
            clauses.add("Recent denied protectable attempts count is " + deniedCount + ".");
        }
        if (sensitiveAccessCount != null && sensitiveAccessCount > 0) {
            clauses.add("Sensitive protectable access count is " + sensitiveAccessCount + ".");
        }
        if (Boolean.TRUE.equals(rareCurrentResource)) {
            clauses.add("Current resource is not present in the top observed work-history resources.");
        }
        if (Boolean.TRUE.equals(rareCurrentActionFamily)) {
            clauses.add("Current action family is not present in the top observed work-history actions.");
        }
        if (clauses.isEmpty()) {
            return "Observed work-pattern history is limited.";
        }
        return String.join(" ", clauses);
    }

    private record ObservedAccessRecord(
            String resourceId,
            String actionFamily,
            boolean sensitive,
            boolean denied) {
    }
}
