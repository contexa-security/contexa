package io.contexa.contexacore.verification.runtime.request;

import io.contexa.contexacore.verification.runtime.request.OfficialVerificationCcsrExecutionService.CcsrCheckResult;
import io.contexa.contexacore.verification.runtime.request.OfficialVerificationCcsrExecutionService.EndpointDefinition;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

final class OfficialVerificationCcsrCheckEvaluator {

    List<CcsrCheckResult> evaluate(
            EndpointDefinition endpoint,
            Map<String, Object> invocation,
            Map<String, Object> eventMetadata,
            Map<String, Object> promptPayload
    ) {
        CheckContext context = context(endpoint, invocation, eventMetadata, promptPayload);
        List<CcsrCheckResult> checks = new ArrayList<>();
        addRequestAndClientChecks(checks, context);
        addSecurityAndPhaseChecks(checks, context);
        return List.copyOf(checks);
    }

    private CheckContext context(
            EndpointDefinition endpoint,
            Map<String, Object> invocation,
            Map<String, Object> eventMetadata,
            Map<String, Object> promptPayload
    ) {
        String userPrompt = text(promptPayload, "userPrompt");
        String eventRequestPath = text(eventMetadata, "requestPath", "requestUri", "servletPath");
        String eventClientIp = text(eventMetadata, "clientIp");
        boolean eventMfaVerified = Boolean.parseBoolean(value(text(eventMetadata, "mfaVerified")));
        String eventResourceSensitivity = text(eventMetadata, "resourceSensitivity");
        String expectedSensitivity = expectedSensitivity(endpoint.path());
        String eventAuthorizationEffect = text(eventMetadata, "authorizationEffect");
        return new CheckContext(
                userPrompt, eventRequestPath, eventClientIp, eventMfaVerified, eventResourceSensitivity,
                expectedSensitivity, eventAuthorizationEffect, text(invocation, "demoPhase"),
                text(eventMetadata, "demoPhase")
        );
    }

    private void addRequestAndClientChecks(List<CcsrCheckResult> checks, CheckContext context) {
        boolean pathReflected = hasReflectedValue(context.userPrompt(), context.eventRequestPath());
        boolean clientReflected = hasReflectedValue(context.userPrompt(), context.eventClientIp());
        checks.add(check("requestPath is reflected in user prompt", value(context.eventRequestPath()),
                pair(context.eventRequestPath(), boolText(pathReflected)), pathReflected,
                "analysis.events.metadata.requestPath -> promptAuditOutbox.payload.userPrompt"));
        checks.add(check("clientIp is reflected in user prompt", value(context.eventClientIp()),
                pair(context.eventClientIp(), boolText(clientReflected)), clientReflected,
                "analysis.events.metadata.clientIp -> promptAuditOutbox.payload.userPrompt"));
    }

    private void addSecurityAndPhaseChecks(List<CcsrCheckResult> checks, CheckContext context) {
        boolean promptMfa = containsText(context.userPrompt(), "MfaVerified: true");
        boolean promptSensitivity = containsText(
                context.userPrompt(), "Sensitivity: " + context.expectedSensitivity()
        );
        boolean promptAllow = containsText(context.userPrompt(), "AuthorizationEffect: ALLOW");
        checks.add(check("mfaVerified state matches user prompt", boolText(context.eventMfaVerified()),
                pair(boolText(context.eventMfaVerified()), boolText(promptMfa)),
                context.eventMfaVerified() == promptMfa,
                "analysis.events.metadata.mfaVerified -> promptAuditOutbox.payload.userPrompt"));
        checks.add(check("resourceSensitivity matches user prompt", context.expectedSensitivity(),
                pair(value(context.eventResourceSensitivity()), boolText(promptSensitivity)),
                context.expectedSensitivity().equalsIgnoreCase(value(context.eventResourceSensitivity())) == promptSensitivity,
                "analysis.events.metadata.resourceSensitivity -> promptAuditOutbox.payload.userPrompt"));
        checks.add(check("authorizationEffect matches user prompt", value(context.eventAuthorizationEffect()),
                pair(value(context.eventAuthorizationEffect()), boolText(promptAllow)),
                "ALLOW".equalsIgnoreCase(context.eventAuthorizationEffect()) == promptAllow,
                "analysis.events.metadata.authorizationEffect -> promptAuditOutbox.payload.userPrompt"));
        checks.add(check("demoPhase matches event metadata", value(context.responseDemoPhase()),
                pair(context.responseDemoPhase(), context.eventDemoPhase()),
                sameNullableValue(context.responseDemoPhase(), context.eventDemoPhase()),
                "invocation.demoPhase -> analysis.events.metadata.demoPhase"));
    }

    private boolean hasReflectedValue(String prompt, String value) {
        return StringUtils.hasText(value) && containsText(prompt, value);
    }

    private CcsrCheckResult check(String label, String expected, String actual, boolean pass, String source) {
        return new CcsrCheckResult(label, value(expected), value(actual), pass, source);
    }

    private boolean containsText(String source, String fragment) {
        return StringUtils.hasText(source) && StringUtils.hasText(fragment) && source.contains(fragment);
    }

    private String boolText(boolean value) {
        return Boolean.toString(value);
    }

    private boolean sameNullableValue(String left, String right) {
        if (!StringUtils.hasText(left) && !StringUtils.hasText(right)) {
            return true;
        }
        return StringUtils.hasText(left) && left.equals(right);
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

    private String pair(String left, String right) {
        return value(left) + " / " + value(right);
    }

    private record CheckContext(
            String userPrompt,
            String eventRequestPath,
            String eventClientIp,
            boolean eventMfaVerified,
            String eventResourceSensitivity,
            String expectedSensitivity,
            String eventAuthorizationEffect,
            String responseDemoPhase,
            String eventDemoPhase
    ) {
    }
}