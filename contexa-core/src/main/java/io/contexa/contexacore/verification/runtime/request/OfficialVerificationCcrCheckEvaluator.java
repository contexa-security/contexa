package io.contexa.contexacore.verification.runtime.request;

import io.contexa.contexacore.autonomous.tiered.util.SecurityEventEnricher;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationCcrExecutionService.CcrCheckResult;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationCcrExecutionService.EndpointDefinition;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class OfficialVerificationCcrCheckEvaluator {

    List<CcrCheckResult> evaluate(
            EndpointDefinition endpoint,
            Map<String, Object> eventMetadata,
            Map<String, Object> sessionMetadata,
            Map<String, Object> behaviorMetadata,
            Map<String, Object> promptExecutionMetadata
    ) {
        CheckContext context = prepareContext(
                endpoint, eventMetadata, sessionMetadata, behaviorMetadata, promptExecutionMetadata
        );
        List<CcrCheckResult> checks = new ArrayList<>();
        addEventChecks(checks, context);
        addContextChecks(checks, context);
        return List.copyOf(checks);
    }

    private CheckContext prepareContext(
            EndpointDefinition endpoint,
            Map<String, Object> eventMetadata,
            Map<String, Object> sessionMetadata,
            Map<String, Object> behaviorMetadata,
            Map<String, Object> promptExecutionMetadata
    ) {
        Map<String, Object> sessionSource = firstPresent(sessionMetadata, eventMetadata);
        Map<String, Object> behaviorSource = firstPresent(behaviorMetadata, eventMetadata);
        String requestPath = endpoint != null ? endpoint.path() : null;
        String currentUserAgent = text(behaviorSource, "currentUserAgent", "userAgent");
        if (!StringUtils.hasText(currentUserAgent)) {
            currentUserAgent = text(eventMetadata, "userAgent");
        }
        return new CheckContext(
                eventMetadata,
                sessionSource,
                expectedSensitivity(requestPath),
                String.valueOf(expectedSensitiveResource(requestPath)),
                resolveCurrentUserAgentOs(behaviorSource, currentUserAgent),
                resolveCurrentUserAgentBrowser(behaviorSource, currentUserAgent),
                promptExecutionMetadata
        );
    }

    private void addEventChecks(List<CcrCheckResult> checks, CheckContext context) {
        Map<String, Object> event = context.eventMetadata();
        checks.add(check("event metadata authMethod is populated", "present", text(event, "authMethod"),
                StringUtils.hasText(text(event, "authMethod")), "event.metadata.authMethod"));
        checks.add(check("event metadata authorizationEffect is populated", "present", text(event, "authorizationEffect"),
                StringUtils.hasText(text(event, "authorizationEffect")), "event.metadata.authorizationEffect"));
        checks.add(check("event metadata resourceSensitivity is populated", value(context.expectedSensitivity()),
                text(event, "resourceSensitivity"), sameValue(context.expectedSensitivity(), text(event, "resourceSensitivity")),
                "event.metadata.resourceSensitivity"));
        checks.add(check("event metadata isSensitiveResource is populated", context.expectedSensitiveResource(),
                text(event, "isSensitiveResource"), sameValue(context.expectedSensitiveResource(), text(event, "isSensitiveResource")),
                "event.metadata.isSensitiveResource"));
        checks.add(check("event metadata effectiveRoles is populated", "1+", joinList(event.get("effectiveRoles")),
                !castList(event.get("effectiveRoles")).isEmpty(), "event.metadata.effectiveRoles"));
        checks.add(check("event metadata effectivePermissions is populated", "1+", joinList(event.get("effectivePermissions")),
                !castList(event.get("effectivePermissions")).isEmpty(), "event.metadata.effectivePermissions"));
    }

    private void addContextChecks(List<CcrCheckResult> checks, CheckContext context) {
        Map<String, Object> session = context.sessionSource();
        checks.add(check("sessionCtx.userId is populated", "present", text(session, "userId"),
                StringUtils.hasText(text(session, "userId")), "sessionCtx.userId"));
        checks.add(check("sessionCtx.authMethod is populated", "present", text(session, "authMethod"),
                StringUtils.hasText(text(session, "authMethod")), "sessionCtx.authMethod"));
        checks.add(check("sessionCtx.requestCount is populated", "1+", text(session, "requestCount", "recentRequestCount"),
                integer(session, "requestCount", "recentRequestCount") > 0, "sessionCtx.requestCount"));
        checks.add(check("behaviorCtx.currentUserAgentOS is populated", "present", context.currentUserAgentOs(),
                StringUtils.hasText(context.currentUserAgentOs()), "behaviorCtx.currentUserAgentOS"));
        checks.add(check("behaviorCtx.currentUserAgentBrowser is populated", "present", context.currentUserAgentBrowser(),
                StringUtils.hasText(context.currentUserAgentBrowser()), "behaviorCtx.currentUserAgentBrowser"));
        Map<String, Object> prompt = context.promptExecutionMetadata();
        checks.add(check("promptExecutionMetadata is captured", "present", prompt.isEmpty() ? "absent" : "present",
                !prompt.isEmpty(), "promptExecutionMetadata"));
    }

    private CcrCheckResult check(String label, String expected, String actual, boolean pass, String source) {
        return new CcrCheckResult(label, value(expected), value(actual), pass, source);
    }

    private String resolveCurrentUserAgentOs(Map<String, Object> behaviorSource, String rawUserAgent) {
        String explicit = text(behaviorSource, "currentUserAgentOS");
        return StringUtils.hasText(explicit) ? explicit : SecurityEventEnricher.extractOSFromUserAgent(rawUserAgent);
    }

    private String resolveCurrentUserAgentBrowser(Map<String, Object> behaviorSource, String rawUserAgent) {
        String explicit = text(behaviorSource, "currentUserAgentBrowser");
        return StringUtils.hasText(explicit) ? explicit : SecurityEventEnricher.extractBrowserSignature(rawUserAgent);
    }

    private String expectedSensitivity(String requestPath) {
        if (requestPath != null && requestPath.contains("/critical/")) {
            return "CRITICAL";
        }
        if (requestPath != null && requestPath.contains("/sensitive/")) {
            return "HIGH";
        }
        if (requestPath != null && requestPath.contains("/normal/")) {
            return "STANDARD";
        }
        return "UNKNOWN";
    }

    private boolean expectedSensitiveResource(String requestPath) {
        return requestPath != null && (requestPath.contains("/critical/") || requestPath.contains("/sensitive/"));
    }

    private Map<String, Object> firstPresent(Map<String, Object>... sources) {
        for (Map<String, Object> source : sources) {
            if (source != null && !source.isEmpty()) {
                return source;
            }
        }
        return Map.of();
    }

    private boolean sameValue(String left, String right) {
        return StringUtils.hasText(left) && StringUtils.hasText(right) && left.trim().equalsIgnoreCase(right.trim());
    }

    private List<String> castList(Object value) {
        if (value instanceof List<?> items) {
            return items.stream()
                    .filter(item -> item != null && StringUtils.hasText(String.valueOf(item)))
                    .map(String::valueOf)
                    .toList();
        }
        if (value == null || !StringUtils.hasText(String.valueOf(value).trim())) {
            return List.of();
        }
        return List.of(String.valueOf(value).trim());
    }

    private String joinList(Object value) {
        List<String> items = castList(value);
        return items.isEmpty() ? null : String.join(", ", items);
    }

    private int integer(Map<String, Object> source, String... keys) {
        if (source == null) {
            return 0;
        }
        for (String key : keys) {
            Object candidate = source.get(key);
            if (candidate instanceof Number number) {
                return number.intValue();
            }
            if (candidate instanceof String textValue) {
                try {
                    return Integer.parseInt(textValue.trim());
                }
                catch (NumberFormatException ignored) {
                }
            }
        }
        return 0;
    }

    private String text(Map<String, Object> source, String... keys) {
        if (source == null) {
            return null;
        }
        for (String key : keys) {
            Object candidate = source.get(key);
            if (candidate != null && StringUtils.hasText(String.valueOf(candidate).trim())) {
                return String.valueOf(candidate).trim();
            }
        }
        return null;
    }

    private String value(String input) {
        return StringUtils.hasText(input) ? input : "absent";
    }

    private record CheckContext(
            Map<String, Object> eventMetadata,
            Map<String, Object> sessionSource,
            String expectedSensitivity,
            String expectedSensitiveResource,
            String currentUserAgentOs,
            String currentUserAgentBrowser,
            Map<String, Object> promptExecutionMetadata
    ) {
    }
}